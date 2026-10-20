//! `nzbd import <dir>` (T115, `docs/v3/MIGRATION.md` section 1): fills a library from a directory of NZB files (a 2.x
//! `data/store/`, an original `.nzb` collection) through the ingest pipeline with the configured parser limits,
//! workers, byte budget and commit groups. Host-only (a CLI command, never a web route).
//!
//! * The source is read only (`nzb_ingest::import`): copied into the store, never moved or deleted; symbolic links
//!   and special files are skipped and reported; names are display data.
//! * Refused while the library is restore-pending, superseded or foreign (the `serve` gate without writing the
//!   anchor), and when the directory overlaps a directory nzbd manages.
//! * SQLite: refused while `serve` runs (it takes `serve.lock`): SQLite has one writer and its locking between
//!   processes is not fair, so a bulk import next to a running server could make logins wait (review 34 L5).
//!   PostgreSQL: runs next to `serve` (parallel writers; the server's indexer picks the new releases up).
//! * Audited as actor `cli` (`library_import`, start and end with the counts; no path, no name).
//! * Exit codes: 0 everything imported or already there, 1 error, 2 something was skipped, failed, cut by
//!   `--max-entries` or interrupted (run the same command again: nothing is imported twice).

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Args;
use nzb_ingest::import::{
    DEFAULT_IMPORT_DEPTH, DEFAULT_IMPORT_ENTRIES, MAX_IMPORT_DEPTH, MAX_IMPORT_ENTRIES,
};
use nzb_ingest::{ImportLimits, ImportReport};
use nzb_store::prelude::*;

use crate::config::Config;

/// Progress lines on stderr at most this often.
const PROGRESS_EVERY: Duration = Duration::from_secs(5);
/// Jobs one import keeps in flight at most (each holds an open file).
const MAX_IN_FLIGHT: usize = 256;

/// `nzbd import <DIR>`.
#[derive(Args)]
pub struct ImportArgs {
    /// Directory of `.nzb` files to import (read only: files are copied, never moved or deleted). A 2.x
    /// `data/store/` works as it is.
    pub dir: PathBuf,
    /// Deepest sub-directory level that is entered (the directory's own files are level 0; a 2.x store needs 2).
    #[arg(long, default_value_t = DEFAULT_IMPORT_DEPTH)]
    pub max_depth: usize,
    /// Directory entries looked at before the import stops (run again with a higher value to continue).
    #[arg(long, default_value_t = DEFAULT_IMPORT_ENTRIES)]
    pub max_entries: u64,
    /// Also bring back releases that were deleted from the library (their digest is in the trash). Without it they
    /// are skipped and reported as `TRASHED`.
    #[arg(long)]
    pub include_deleted: bool,
    /// Run although the process is root (files it creates in the store would be root-owned and unreadable for
    /// `serve`; the documented `docker compose run` already runs as the service user).
    #[arg(long)]
    pub allow_root: bool,
}

/// Runs `nzbd import`.
///
/// # Errors
/// Configuration, overlap, lock, database and directory refusals (exit code 1).
pub fn run(cfg: &Config, args: &ImportArgs) -> Result<ExitCode, String> {
    for w in cfg.validate().map_err(|e| e.to_string())? {
        eprintln!("warning: {w}");
    }
    if args.max_depth > MAX_IMPORT_DEPTH
        || args.max_entries == 0
        || args.max_entries > MAX_IMPORT_ENTRIES
    {
        return Err(format!(
            "--max-depth must be 0..={MAX_IMPORT_DEPTH} and --max-entries 1..={MAX_IMPORT_ENTRIES}"
        ));
    }
    // Review 38 L3: like the db and audit commands, never create root-owned store files by accident.
    refuse_root(crate::dbcheck::running_as_root(), args.allow_root)?;
    // Review 38 L2: decided on the identity of the opened directory, again by the walk itself.
    nzb_ingest::check_root(&args.dir, &guard(cfg)).map_err(|e| e.to_string())?;
    // SQLite: the single writer is the import's alone (see the module docs).
    let _serve_lock = match cfg.db.backend {
        nzb_store::DbBackend::Sqlite => Some(crate::library::lock_serve(cfg).map_err(|e| {
            if e.starts_with("SERVE_LOCKED") {
                "SERVE_RUNNING: stop `nzbd serve` before importing into a SQLite library \
                 (on PostgreSQL the import can run next to the server)"
                    .to_owned()
            } else {
                e
            }
        })?),
        nzb_store::DbBackend::Postgres => None,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(import(cfg, args))
}

/// The directories nzbd manages: importing from (or into a parent of) one of them is refused.
fn managed_dirs(cfg: &Config) -> Vec<PathBuf> {
    let p = &cfg.paths;
    let mut v = vec![
        p.watch.clone(),
        p.store.clone(),
        p.failed.clone(),
        p.duplicates.clone(),
        p.tmp.clone(),
        p.backups.clone(),
        cfg.index_dir(),
        cfg.state_dir(),
    ];
    if cfg.db.backend == nzb_store::DbBackend::Sqlite
        && let Some(d) = p.db.parent()
    {
        v.push(d.to_path_buf());
    }
    v
}

/// Review 38 L3: refuses a root process (`as_root`, the effective uid is 0) unless `--allow-root`.
fn refuse_root(as_root: bool, allow_root: bool) -> Result<(), String> {
    if !allow_root && as_root {
        return Err(
            "refusing to run as root: the NZB files it writes would be root-owned and unreadable for `serve`. Run it \
             as the service user (`docker compose run` does), or pass --allow-root"
                .to_owned(),
        );
    }
    Ok(())
}

/// The refusal rules of the import: the managed directories (identity-checked by `nzb_ingest::check_root`).
fn guard(cfg: &Config) -> nzb_ingest::ImportGuard {
    nzb_ingest::ImportGuard {
        managed: managed_dirs(cfg),
        ..nzb_ingest::ImportGuard::default()
    }
}

/// PostgreSQL next to a running `serve` (it holds `serve.lock`): wait on the same SEC-092 lag gate as its scanner
/// (review 38 L4). Without a server nobody drains the outbox, so there is nothing to wait for.
fn lag_gate(cfg: &Config, db: &nzb_store::Store) -> Option<nzb_ingest::LagGate> {
    if cfg.db.backend != nzb_store::DbBackend::Postgres {
        return None;
    }
    match crate::library::lock_serve(cfg) {
        // Nobody serves: the probe lock is released at once.
        Ok(_probe) => None,
        Err(e) if e.starts_with("SERVE_LOCKED") => Some(nzb_ingest::LagGate::for_store(
            db.clone(),
            cfg.search.lag_pause_rows,
        )),
        Err(_) => None,
    }
}

async fn audit(db: &nzb_store::Store, detail: &str) {
    let entry = nzb_store::AuditEntry {
        who: nzb_store::AuditActor::cli(),
        event: "library_import",
        detail: Some(detail),
        ip: None,
        target_id: None,
    };
    if let Err(e) = db.audit_entry(&entry, crate::now_unix()).await {
        eprintln!("warning: audit row not written ({e})");
    }
}

fn counts(r: &ImportReport) -> String {
    format!(
        "files={} imported={} duplicates={} trashed={} failed={} skipped={} interrupted={} limit={}",
        r.files,
        r.imported,
        r.duplicates,
        r.trashed,
        r.failed_total(),
        r.skipped_total(),
        r.interrupted,
        r.entry_limit_hit
    )
}

#[allow(clippy::too_many_lines)] // one linear sequence: open, check, run, report
async fn import(cfg: &Config, args: &ImportArgs) -> Result<ExitCode, String> {
    let db = crate::ops::open_db(cfg).await?;
    if let Err(e) = crate::library::verify_identity(cfg, &db).await {
        db.close().await;
        return Err(e);
    }
    // Passive: never cleans the store's `.tmp/`, which belongs to a running `serve` (Postgres).
    let fs =
        nzb_store::FsStore::open_passive(&cfg.paths.store).map_err(|e| format!("store: {e}"))?;
    let store = Arc::new(crate::ops::fs_store(cfg, fs));
    let pipeline = nzb_ingest::Pipeline::new_import(
        nzb_ingest::PipelineConfig {
            limits: crate::parser_limits(cfg),
            watch_dir: cfg.paths.watch.clone(),
            failed_dir: cfg.paths.failed.clone(),
            duplicates_dir: cfg.paths.duplicates.clone(),
            duplicates_action: nzb_ingest::DuplicatesAction::Move,
            category_from_subfolder: false,
            failed_uploads_max_files: 0,
            failed_uploads_max_bytes: 0,
        },
        db.clone(),
        store,
        Arc::new(nzb_ingest::SystemWallClock),
    )
    .map_err(|e| format!("ingest: {e}"))?;
    let settings = cfg.ingest.settings();
    let (handle, workers) = pipeline.spawn(settings);
    audit(&db, "phase=start").await;

    let cancel = Arc::new(AtomicBool::new(false));
    let signals = {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            if let (Ok(mut t), Ok(mut i)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) {
                tokio::select! { _ = t.recv() => {}, _ = i.recv() => {} }
                eprintln!("import: stopping after the files in flight (run again to continue)");
                cancel.store(true, Ordering::SeqCst);
            }
        })
    };
    let guard = nzb_ingest::ImportGuard {
        lag_gate: lag_gate(cfg, &db),
        ..guard(cfg)
    };
    let limits = ImportLimits {
        include_deleted: args.include_deleted,
        max_depth: args.max_depth,
        max_entries: args.max_entries,
        max_file_bytes: cfg.limits.max_file_bytes,
        max_in_flight: settings.queue_cap.min(MAX_IN_FLIGHT),
    };
    let result = nzb_ingest::import_dir(
        &args.dir,
        limits,
        &handle,
        cancel,
        &guard,
        PROGRESS_EVERY,
        &|r| {
            if r.waiting_for_index {
                eprintln!(
                    "import: {}; waiting for the search index to catch up",
                    counts(r)
                );
            } else {
                eprintln!("import: {}", counts(r));
            }
        },
    )
    .await;
    signals.abort();
    drop(handle);
    for w in workers {
        let _ = w.await;
    }
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            let code = match e {
                nzb_ingest::ImportError::Overlap => "IMPORT_DIR_OVERLAP",
                nzb_ingest::ImportError::Root(_) => "IMPORT_DIR_UNUSABLE",
            };
            audit(&db, &format!("phase=end refused={code}")).await;
            db.close().await;
            return Err(e.to_string());
        }
    };
    audit(&db, &format!("phase=end {}", counts(&report))).await;
    db.close().await;
    print!("{}", render(&report));
    Ok(if report.has_problems() || report.interrupted {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn by_code<K: std::fmt::Debug>(
    m: impl Iterator<Item = (K, u64)>,
    code: impl Fn(&K) -> String,
) -> String {
    let parts: Vec<String> = m.map(|(k, n)| format!("{} {n}", code(&k))).collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

/// The final summary (stdout). Names are Debug-escaped by the importer; codes are fixed identifiers.
#[must_use]
pub fn render(r: &ImportReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "files       {}", r.files);
    let _ = writeln!(out, "imported    {}", r.imported);
    let _ = writeln!(out, "duplicates  {} (already in the library)", r.duplicates);
    let _ = writeln!(
        out,
        "trashed     {} (deleted from the library; not brought back without --include-deleted)",
        r.trashed
    );
    let _ = writeln!(
        out,
        "failed      {}{}",
        r.failed_total(),
        by_code(r.failed.iter().map(|(k, n)| (*k, *n)), |k| (*k).to_owned())
    );
    let _ = writeln!(
        out,
        "skipped     {}{}",
        r.skipped_total(),
        by_code(r.skipped.iter().map(|(k, n)| (*k, *n)), |k| k
            .code()
            .to_owned())
    );
    let _ = writeln!(
        out,
        "ignored     {} (hidden entries and files not ending in .nzb)",
        r.ignored
    );
    if r.entry_limit_hit {
        let _ = writeln!(
            out,
            "LIMIT: the walk stopped at --max-entries; run again with a higher value (nothing is imported twice)"
        );
    }
    if r.index_waits > 0 {
        let _ = writeln!(
            out,
            "waited {} time(s) for the search index of the running server to catch up",
            r.index_waits
        );
    }
    if r.interrupted {
        let _ = writeln!(
            out,
            "INTERRUPTED: run the same command again to continue (nothing is imported twice)"
        );
    }
    if !r.problems.is_empty() {
        let _ = writeln!(
            out,
            "problems (first {}):",
            nzb_ingest::import::MAX_REPORTED
        );
        for (name, code) in &r.problems {
            let _ = writeln!(out, "  {code:<22} {name}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t115_import_refuses_root_unless_allowed() {
        let e = refuse_root(true, false).unwrap_err();
        assert!(e.starts_with("refusing to run as root"), "{e}");
        assert!(refuse_root(true, true).is_ok());
        assert!(refuse_root(false, false).is_ok());
    }
}
