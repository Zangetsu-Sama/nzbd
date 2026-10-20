//! Startup recovery (T032, `INGEST_SPEC` §Crash safety, SEC-008).
//!
//! [`recover`] reconciles whatever a crash left behind, before the scanner and the upload
//! endpoint start. It is **idempotent** (a second run changes nothing) and **never deletes a
//! user's NZB**: leftovers that hold user content are moved, not removed. Phases, in order
//! (the fault-injection hook can "kill" the process after any of them):
//!
//! 0. stale generated `.part` copies in `failed/` and `duplicates/` (exact generated shape
//!    only); files named `nzbd-upload-*` in the upload staging directory (nothing can be in
//!    flight before the server starts, and an unacknowledged upload is re-sendable by its
//!    client). Any other file in the staging directory is left alone, and `Config::validate`
//!    refuses a staging directory that overlaps a data directory;
//! 1. a crash inside a hard-link move (`failed/` or `duplicates/` name + `watch/` name of one
//!    inode): drop the destination name, the watch name stays and is simply reprocessed;
//! 2. `.nzbd-trash.*` leftovers (watch, `failed/`, `duplicates/`) of an interrupted verified
//!    unlink (at most [`MAX_TRASH_PER_START`] per start): a second name of a shared
//!    inode is unlinked; a sole copy whose content is already indexed goes to `duplicates/`,
//!    anything else is restored into the watch folder under a visible `restored-` name;
//! 3. `failed/` consistency: orphan `reason.json`, files without one, files already indexed;
//! 4. store: releases whose blob is missing are **reported** (a duplicate re-`put` heals them),
//!    orphan blobs are **counted** (dry run). Startup never removes blobs: after a database
//!    restore from backup, blobs newer than the backup are the only copy of the user's NZBs;
//!    reclaiming them is the explicit `nzbd store gc`;
//!
//! Retention of `failed/` (D12) is **not** part of recovery: it hashes files, so the caller runs
//! [`crate::apply_retention`] in the background once the HTTP listener is up.

use nzb_store::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nzb_core::Sha256;
use nzb_store::{BlobMaintenance, GcCandidate, GcReport, Store, StoreError, VerifyReport};

use crate::failure::{self, Hook, no_faults};
use crate::fsops::{self, move_no_clobber};
use crate::pipeline::CrashPoint;
use crate::timefmt::utc_stamp;

/// Walk depth below the watch root in recursive mode (same bound as the scanner).
const MAX_DEPTH: usize = 4;
/// Safety bound on files visited per directory walk.
const MAX_FILES: usize = 100_000;
/// Missing blobs listed individually in the report.
const MAX_LISTED: usize = 100;
/// Trash files handled per start; the rest is left for the next start (bounded startup time).
pub const MAX_TRASH_PER_START: usize = 1000;
/// Reserved prefix of the files the upload handler stages in `paths.tmp`. Startup recovery
/// removes only files with this prefix; the upload handler (T051) must create its staging
/// files with [`staging_name`].
pub const STAGING_PREFIX: &str = "nzbd-upload-";
/// A blob whose ctime is this much newer than its mtime was restored with its old timestamps
/// (`cp -p`, rsync -a): see [`GcPlan::suspicious`].
const RESTORE_SKEW_SECS: i64 = 86_400;
/// Default safety grace of `store gc` (24 h): a blob younger than this is never reclaimed.
pub const DEFAULT_GC_GRACE_SECS: u64 = 24 * 3600;

/// Directories and limits for [`recover`].
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Watch folder.
    pub watch_dir: PathBuf,
    /// Quarantine directory.
    pub failed_dir: PathBuf,
    /// Duplicates directory.
    pub duplicates_dir: PathBuf,
    /// Upload staging directory (`paths.tmp`); `None` skips its cleanup.
    pub tmp_dir: Option<PathBuf>,
    /// Whether the watch folder is scanned recursively (trash can sit in sub-folders).
    pub recursive: bool,
    /// Size cap for reading a leftover (same as the pipeline).
    pub max_file_bytes: u64,
}

/// What [`recover`] found and did. All counts are 0 on a clean start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Stale `.part` copies removed from `failed/` and `duplicates/`.
    pub stale_parts_removed: usize,
    /// Files removed from the upload staging directory.
    pub tmp_removed: usize,
    /// Destination names of interrupted hard-link moves dropped (the watch name remains).
    pub split_links_healed: usize,
    /// Trash files that shared an inode with another name: the extra name was unlinked.
    pub trash_unlinked: usize,
    /// Trash files of already indexed content moved to `duplicates/`.
    pub trash_to_duplicates: usize,
    /// Trash files restored into the watch folder (content not indexed).
    pub trash_restored: usize,
    /// Interrupted NFO sidecar removals (`.nzbd-trash.nfo.*`, T141) moved to `failed/` as `.nfo`.
    pub nfo_trash_to_failed: usize,
    /// Trash files left alone (unreadable, too large, I/O error).
    pub trash_left: usize,
    /// Sidecars removed because their failed file is gone.
    pub orphan_sidecars_removed: u32,
    /// Failed files without a valid `reason.json`.
    pub failed_without_reason: u32,
    /// Failed files whose digest is already indexed (informational).
    pub failed_already_indexed: usize,
    /// Releases whose blob is missing from the store (first [`MAX_LISTED`]).
    pub missing_blobs: Vec<Sha256>,
    /// Total number of releases whose blob is missing.
    pub missing_total: usize,
    /// Unreferenced blobs a `store gc` with the default grace would reclaim.
    pub orphan_blobs: usize,
    /// Recoverable errors (each logged).
    pub errors: usize,
}

/// Runs startup recovery. Never fails: problems are counted in [`RecoveryReport::errors`].
pub async fn recover<S: BlobMaintenance + ?Sized>(
    cfg: &RecoveryConfig,
    db: &Store,
    store: &S,
    now: i64,
) -> RecoveryReport {
    recover_with(cfg, db, store, now, &no_faults).await
}

/// One regular file seen by a walk.
struct Seen {
    path: PathBuf,
    dev: u64,
    ino: u64,
    nlink: u64,
}

/// Regular files (never following symlinks) under `root`; `recursive` descends up to
/// [`MAX_DEPTH`] levels. Hidden files are included.
fn walk_files(root: &Path, recursive: bool) -> Vec<Seen> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            if out.len() >= MAX_FILES {
                return out;
            }
            let Ok(t) = e.file_type() else { continue };
            if t.is_file() {
                if let Ok(m) = e.metadata() {
                    out.push(Seen {
                        path: e.path(),
                        dev: m.dev(),
                        ino: m.ino(),
                        nlink: m.nlink(),
                    });
                }
            } else if t.is_dir() && recursive && depth < MAX_DEPTH {
                stack.push((e.path(), depth.saturating_add(1)));
            }
        }
    }
    out
}

fn is_trash(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(".nzbd-trash."))
}

/// A fresh staging file name: reserved prefix plus a unique tag. Never derived from input.
#[must_use]
pub fn staging_name() -> String {
    format!("{STAGING_PREFIX}{}", fsops::unique_tag())
}

/// Phase 0b: generated staging files (files and symlinks with the reserved prefix, directly
/// inside the staging directory) are leftovers of an unacknowledged upload. Regular files named
/// `.nzbd-trash.*` directly inside it are leftovers of a crash between the rename and the unlink
/// of `fsops::remove_if_unchanged` for an already ingested upload (the content is stored, so they
/// are never the only copy; `SECURITY_REVIEW` T051 L4). Everything else in the directory is not
/// ours and stays (`SECURITY_REVIEW` T032 M1).
fn clean_staging(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut n = 0usize;
    for e in rd.flatten().take(MAX_FILES) {
        let Ok(t) = e.file_type() else { continue };
        let name = e.file_name();
        let name = name.to_str().unwrap_or_default();
        let staged = name.starts_with(STAGING_PREFIX) && (t.is_file() || t.is_symlink());
        let trash = name.starts_with(".nzbd-trash.") && t.is_file();
        if (staged || trash) && fs::remove_file(e.path()).is_ok() {
            n = n.saturating_add(1);
        }
    }
    n
}

/// Phase 1. See module docs.
fn heal_split_links(cfg: &RecoveryConfig) -> usize {
    let shared: HashSet<(u64, u64)> = walk_files(&cfg.watch_dir, cfg.recursive)
        .iter()
        // A hidden trash name is resolved in phase 2 (its other name wins instead).
        .filter(|f| f.nlink > 1 && !is_trash(&f.path))
        .map(|f| (f.dev, f.ino))
        .collect();
    if shared.is_empty() {
        return 0;
    }
    let mut healed = 0usize;
    for dir in [&cfg.failed_dir, &cfg.duplicates_dir] {
        for f in walk_files(dir, false) {
            if f.nlink > 1 && shared.contains(&(f.dev, f.ino)) && fs::remove_file(&f.path).is_ok() {
                tracing::warn!(
                    file = ?f.path.file_name().unwrap_or_default(),
                    "dropped the destination name of an interrupted move; the watch copy remains"
                );
                healed = healed.saturating_add(1);
            }
        }
        fsops::fsync_dir(dir);
    }
    healed
}

fn is_nfo_trash(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(fsops::NFO_TRASH_PREFIX))
}

/// Phase 2 for the sole name of an interrupted NFO sidecar removal (T141, review 54 L2): it is an NFO, never an NZB,
/// so it goes to `failed/<stamp>-<sha8 of its bytes>.nfo` (move, don't delete), never back into the watch folder.
async fn recover_nfo_trash(cfg: &RecoveryConfig, now: i64, f: Seen, rep: &mut RecoveryReport) {
    let failed = cfg.failed_dir.clone();
    let path = f.path.clone();
    let moved = tokio::task::spawn_blocking(move || {
        let cap = u64::try_from(nzb_core::MAX_NFO_BYTES).unwrap_or(u64::MAX);
        let loaded = fsops::read_source(&path, cap, None, None).ok()?;
        let stem = format!("{}-{}", utc_stamp(now), loaded.sha.short());
        let naming = fsops::Naming {
            ext: "nfo",
            exact: false,
        };
        fsops::move_named(
            &path,
            &failed,
            &stem,
            naming,
            loaded.ident.as_ref(),
            Some(cap),
        )
        .ok()
    })
    .await
    .ok()
    .flatten();
    if let Some(dest) = moved {
        tracing::warn!(
            file = ?dest.file_name().unwrap_or_default(),
            "moved an interrupted NFO sidecar removal to failed/"
        );
        rep.nfo_trash_to_failed = rep.nfo_trash_to_failed.saturating_add(1);
    } else {
        tracing::warn!(
            file = ?f.path.file_name().unwrap_or_default(),
            "cannot recover a leftover NFO trash file; left in place"
        );
        rep.trash_left = rep.trash_left.saturating_add(1);
    }
}

/// Phase 2 for one trash file.
async fn recover_trash<S: BlobMaintenance + ?Sized>(
    cfg: &RecoveryConfig,
    db: &Store,
    store: &S,
    now: i64,
    f: Seen,
    rep: &mut RecoveryReport,
) {
    if f.nlink > 1 {
        // Another name keeps the inode alive: removing this hidden name loses nothing.
        if fs::remove_file(&f.path).is_ok() {
            rep.trash_unlinked = rep.trash_unlinked.saturating_add(1);
        } else {
            rep.trash_left = rep.trash_left.saturating_add(1);
        }
        return;
    }
    if is_nfo_trash(&f.path) {
        recover_nfo_trash(cfg, now, f, rep).await;
        return;
    }
    let path = f.path.clone();
    let max = cfg.max_file_bytes;
    let loaded = tokio::task::spawn_blocking(move || fsops::read_source(&path, max, None, None))
        .await
        .ok()
        .and_then(Result::ok);
    let Some(loaded) = loaded else {
        tracing::warn!(
            file = ?f.path.file_name().unwrap_or_default(),
            "cannot read leftover trash file; left in place"
        );
        rep.trash_left = rep.trash_left.saturating_add(1);
        return;
    };
    let Ok(row) = db.get_release_by_sha(&loaded.sha.to_hex()).await else {
        rep.errors = rep.errors.saturating_add(1);
        rep.trash_left = rep.trash_left.saturating_add(1);
        return;
    };
    let indexed = row.is_some();
    let stem = format!("{}-{}", utc_stamp(now), loaded.sha.short());
    let (dest_dir, stem) = if indexed {
        // Heal the blob first (idempotent): the move below is then never the last copy.
        if store.put(loaded.sha, &loaded.bytes).await.is_err() {
            rep.errors = rep.errors.saturating_add(1);
            rep.trash_left = rep.trash_left.saturating_add(1);
            return;
        }
        (cfg.duplicates_dir.clone(), stem)
    } else {
        // Back where it was, under a name the scanner (watch) or `failed list` understands.
        let dir = f
            .path
            .parent()
            .map_or_else(|| cfg.watch_dir.clone(), Path::to_path_buf);
        let in_watch = dir != cfg.failed_dir && dir != cfg.duplicates_dir;
        let stem = if in_watch {
            format!("restored-{stem}")
        } else {
            stem
        };
        (dir, stem)
    };
    let (src, ident) = (f.path.clone(), loaded.ident);
    let moved = tokio::task::spawn_blocking(move || {
        move_no_clobber(&src, &dest_dir, &stem, ident.as_ref())
    })
    .await;
    match moved {
        Ok(Ok(_)) if indexed => rep.trash_to_duplicates = rep.trash_to_duplicates.saturating_add(1),
        Ok(Ok(_)) => rep.trash_restored = rep.trash_restored.saturating_add(1),
        _ => {
            rep.errors = rep.errors.saturating_add(1);
            rep.trash_left = rep.trash_left.saturating_add(1);
        }
    }
}

#[allow(clippy::too_many_lines)] // a flat list of phases reads better than helpers
pub(crate) async fn recover_with<S: BlobMaintenance + ?Sized>(
    cfg: &RecoveryConfig,
    db: &Store,
    store: &S,
    now: i64,
    hook: Hook<'_>,
) -> RecoveryReport {
    let mut rep = RecoveryReport::default();

    // Phase 0.
    for dir in [&cfg.failed_dir, &cfg.duplicates_dir] {
        rep.stale_parts_removed = rep
            .stale_parts_removed
            .saturating_add(fsops::clean_stale_parts(dir));
    }
    if let Some(tmp) = &cfg.tmp_dir {
        rep.tmp_removed = clean_staging(tmp);
    }
    if hook(CrashPoint::RecoveryPhase(0)) {
        return rep;
    }

    // Phase 1.
    let c = cfg.clone();
    rep.split_links_healed = tokio::task::spawn_blocking(move || heal_split_links(&c))
        .await
        .unwrap_or(0);
    if hook(CrashPoint::RecoveryPhase(1)) {
        return rep;
    }

    // Phase 2.
    let c = cfg.clone();
    let trash: Vec<Seen> = tokio::task::spawn_blocking(move || {
        // `failed retry` unlinks inside failed/, so its trash lives there.
        let mut all = walk_files(&c.watch_dir, c.recursive);
        all.extend(walk_files(&c.failed_dir, false));
        all.extend(walk_files(&c.duplicates_dir, false));
        all.retain(|f| is_trash(&f.path));
        all
    })
    .await
    .unwrap_or_default();
    if trash.len() > MAX_TRASH_PER_START {
        tracing::warn!(
            found = trash.len(),
            handled = MAX_TRASH_PER_START,
            "many leftover trash files; the rest is handled at the next start"
        );
    }
    for f in trash.into_iter().take(MAX_TRASH_PER_START) {
        recover_trash(cfg, db, store, now, f, &mut rep).await;
    }
    if hook(CrashPoint::RecoveryPhase(2)) {
        return rep;
    }

    // Phase 3.
    let failed = cfg.failed_dir.clone();
    let (orphans, listing) = tokio::task::spawn_blocking(move || {
        let o = failure::remove_orphan_sidecars(&failed);
        (o, failure::list_failed(&failed).unwrap_or_default())
    })
    .await
    .unwrap_or_default();
    rep.orphan_sidecars_removed = orphans;
    rep.failed_without_reason =
        u32::try_from(listing.iter().filter(|e| e.reason.is_none()).count()).unwrap_or(u32::MAX);
    for e in &listing {
        if let Some(sha) = e.reason.as_ref().and_then(|r| r.sha256.as_deref())
            && matches!(db.get_release_by_sha(sha).await, Ok(Some(_)))
        {
            rep.failed_already_indexed = rep.failed_already_indexed.saturating_add(1);
        }
    }
    if hook(CrashPoint::RecoveryPhase(3)) {
        return rep;
    }

    // Phase 4.
    match check_store(db, store, true).await {
        Ok(c) => {
            rep.missing_total = c.missing.len();
            for sha in c.missing.iter().take(MAX_LISTED) {
                tracing::warn!(sha256 = %sha.to_hex(), "release blob is missing from the store");
            }
            rep.missing_blobs = c.missing.into_iter().take(MAX_LISTED).collect();
        }
        Err(e) => {
            tracing::error!(error = %e, "store check failed");
            rep.errors = rep.errors.saturating_add(1);
        }
    }
    match gc_orphans(db, store, now, DEFAULT_GC_GRACE_SECS, true).await {
        Ok(g) => rep.orphan_blobs = g.removed.len(),
        Err(e) => {
            tracing::error!(error = %e, "orphan blob scan failed");
            rep.errors = rep.errors.saturating_add(1);
        }
    }
    if hook(CrashPoint::RecoveryPhase(4)) {
        return rep;
    }

    tracing::info!(
        parts = rep.stale_parts_removed,
        staged = rep.tmp_removed,
        split_links = rep.split_links_healed,
        trash_restored = rep.trash_restored,
        trash_to_duplicates = rep.trash_to_duplicates,
        trash_unlinked = rep.trash_unlinked,
        missing_blobs = rep.missing_total,
        orphan_blobs = rep.orphan_blobs,
        failed_without_reason = rep.failed_without_reason,
        errors = rep.errors,
        "startup recovery finished"
    );
    rep
}

/// Result of [`check_store`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoreCheck {
    /// Number of release rows.
    pub rows: usize,
    /// Rows whose blob is missing.
    pub missing: Vec<Sha256>,
    /// Full walk result (`None` for a quick check).
    pub full: Option<VerifyReport>,
}

/// `store verify`: every release row must have its blob (`quick`); a full check additionally
/// re-hashes every blob. Read-only.
///
/// # Errors
/// Database or I/O errors.
pub async fn check_store<S: BlobMaintenance + ?Sized>(
    db: &Store,
    store: &S,
    quick: bool,
) -> Result<StoreCheck, StoreError> {
    let shas = db.list_shas().await?;
    let rows = shas.len();
    let all: Vec<Sha256> = shas.into_iter().collect();
    let mut missing = store.missing(all).await?;
    missing.sort_by_key(Sha256::to_hex);
    let full = if quick {
        None
    } else {
        Some(store.verify(None).await?)
    };
    Ok(StoreCheck {
        rows,
        missing,
        full,
    })
}

/// What `store gc` would do, with the stale-database signals (`SECURITY_REVIEW` T032 M2).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcPlan {
    /// Unreferenced blobs older than the grace.
    pub candidates: Vec<GcCandidate>,
    /// Their total size.
    pub bytes: u64,
    /// `ingested_at` of the newest release row.
    pub newest_row: Option<i64>,
    /// Candidates that look like the only copy of NZBs a stale database does not know:
    /// newer than the newest release row (the database predates them), or restored with old
    /// timestamps (ctime much newer than mtime). Running gc needs `--force` if non-empty.
    pub suspicious: Vec<(Sha256, &'static str)>,
}

/// Computes the [`GcPlan`]. Read-only.
///
/// # Errors
/// Database or I/O errors.
pub async fn gc_plan<S: BlobMaintenance + ?Sized>(
    db: &Store,
    store: &S,
    now: i64,
    grace_secs: u64,
) -> Result<GcPlan, StoreError> {
    let referenced = db.list_shas().await?;
    let newest_row = db.newest_ingested_at().await?;
    let cutoff = gc_cutoff(now, grace_secs);
    let candidates = store.gc_candidates(&referenced, cutoff).await?;
    let mut suspicious = Vec::new();
    for c in &candidates {
        if newest_row.is_none_or(|n| c.mtime > n) {
            suspicious.push((c.sha, "newer than the newest release row (stale database?)"));
        } else if c.ctime.saturating_sub(c.mtime) > RESTORE_SKEW_SECS {
            suspicious.push((c.sha, "timestamps look restored from a copy or backup"));
        }
    }
    let bytes = candidates
        .iter()
        .fold(0u64, |a, c| a.saturating_add(c.size));
    Ok(GcPlan {
        candidates,
        bytes,
        newest_row,
        suspicious,
    })
}

fn gc_cutoff(now: i64, grace_secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(now).unwrap_or(0).saturating_sub(grace_secs))
}

/// `store gc`: quarantines blobs that no release references and that are older than
/// `grace_secs`. The grace protects a blob whose row is about to be committed (`put` happens
/// before the row). The closure re-queries the database for every blob right before removal
/// and fails closed (a database error keeps the blob). **After restoring the database from
/// a backup, blobs newer than the backup are unreferenced although they are the only copy of
/// the user's NZBs; do not run this until the restore is verified.** For that reason blobs
/// are moved to the store's `.gc-trash/` quarantine and not unlinked (see
/// [`BlobMaintenance::purge_gc_trash`]), and the CLI refuses suspicious plans without `--force`.
///
/// # Errors
/// Database or I/O errors.
pub async fn gc_orphans<S: BlobMaintenance + ?Sized>(
    db: &Store,
    store: &S,
    now: i64,
    grace_secs: u64,
    dry_run: bool,
) -> Result<GcReport, StoreError> {
    store
        .gc_orphans(db, gc_cutoff(now, grace_secs), dry_run)
        .await
}
