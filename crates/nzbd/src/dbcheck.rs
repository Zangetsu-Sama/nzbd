//! `nzbd db check [--quick|--full]`: on-demand database integrity checks (T088), and the
//! mapping of [`nzb_store::OpenEvent`] to log lines used by `serve`.
//!
//! Startup only runs the bounded `fast` check by default (the full check reads the whole file,
//! 107 s cold at 1,000,000 releases); this is the explicit way to run the strong checks, e.g. from
//! the nightly/upgrade drill or before a risky operation. It opens the file read-only, so it
//! never modifies the database and is safe next to a running server.

use nzb_store::prelude::*;
use std::process::ExitCode;
use std::time::Instant;

use clap::Subcommand;
use nzb_store::{OpenEvent, StartupCheck, StoreError};

use crate::config::Config;

/// `nzbd db <action>`.
#[derive(Subcommand)]
pub enum DbAction {
    /// Check the database file (read-only). Exit code 0 = ok, 2 = damaged, 1 = could not run.
    Check {
        /// `PRAGMA integrity_check` + `foreign_key_check`: reads the whole file (minutes on a
        /// library of a million NZBs).
        #[arg(long, conflicts_with = "quick")]
        full: bool,
        /// `PRAGMA quick_check` over the whole file (no index or foreign-key cross-checks).
        #[arg(long)]
        quick: bool,
        /// Run even as root. Opening a WAL database creates `-wal`/`-shm` files owned by the
        /// invoking user when none exist; as root they would be unwritable for the service
        /// user. Use `docker compose exec nzbd /nzbd db check` instead.
        #[arg(long)]
        allow_root: bool,
    },
    /// Finish a restore from a backup (offline, host only; stop `nzbd serve` first): in ONE
    /// transaction delete every session, open invitation, MFA recovery code, staged credential
    /// and throttle row, revoke ALL API keys and write one audit row; then list every account
    /// with role and state, the audit chain anchor and the next steps. A restored file silently
    /// undoes revocations made after the snapshot; this is the hygiene step. Idempotent.
    RestoreFinish {
        /// Skip the typed confirmation (required when stdin is not a terminal).
        #[arg(long)]
        yes: bool,
        /// Print what would be removed and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Run even as root (the database files would become root-owned; see `db check`).
        #[arg(long)]
        allow_root: bool,
    },
    /// Write the log retention policy (days; floors: audit 90, account events 365, ingest log 1). Audited.
    SetRetention {
        /// Audit rows other than account events, days (>= 90).
        #[arg(long)]
        log_days: u32,
        /// Account-lifecycle audit rows, days (>= 365).
        #[arg(long)]
        account_days: u32,
        /// Ingest log rows, days (>= 1).
        #[arg(long)]
        ingest_days: u32,
        /// Never purge anything.
        #[arg(long)]
        keep_all: bool,
        /// Never purge account-lifecycle audit rows.
        #[arg(long)]
        account_keep_all: bool,
        /// Owner role (Postgres; default `nzbd_owner`).
        #[arg(long)]
        owner_user: Option<String>,
        /// Owner password file (Postgres; default `/run/setup-secrets/nzbd_db_owner_password`).
        #[arg(long)]
        owner_password_file: Option<std::path::PathBuf>,
    },
    /// Apply pending schema migrations. PostgreSQL: with the OWNER role, from the one-shot `setup` compose service
    /// only (`serve` never migrates); prints the plan, `--yes` applies it. SQLite: opens (creates) the library,
    /// which migrates itself.
    Migrate {
        /// Apply the plan (without it nothing is changed).
        #[arg(long)]
        yes: bool,
        /// Apply although app-role sessions are connected (normally a running `serve`: stop it first).
        #[arg(long)]
        force: bool,
        /// Run even as root (a SQLite library created as root would be refused by `serve`).
        #[arg(long)]
        allow_root: bool,
        /// PostgreSQL owner role.
        #[arg(long, default_value = crate::dbsetup::OWNER_USER)]
        owner_user: String,
        /// File holding the owner role's password (0400, owned by the process uid; only the `setup` service
        /// mounts it).
        #[arg(long, default_value = nzb_store::pg::config::OWNER_SECRET_PATH)]
        owner_password_file: std::path::PathBuf,
    },
    /// PostgreSQL: load an `nzbd backup` snapshot into an EMPTY, migrated database (OWNER role, `setup` service),
    /// verified against its manifest; the database stays restore-pending until `db restore-finish`. SQLite
    /// libraries are restored by copying the backup file (docs/RUNBOOK.md).
    Restore {
        /// The backup file (`nzbd-pg-...` or `...enc`).
        file: std::path::PathBuf,
        /// Accept a plaintext backup although `maintenance.backup_encryption_key_file` is set.
        #[arg(long)]
        allow_unencrypted: bool,
        /// Restore although app-role sessions are connected (normally a running `serve`: stop it first).
        #[arg(long)]
        force: bool,
        /// Run even as root.
        #[arg(long)]
        allow_root: bool,
        /// PostgreSQL owner role.
        #[arg(long, default_value = crate::dbsetup::OWNER_USER)]
        owner_user: String,
        /// File holding the owner role's password.
        #[arg(long, default_value = nzb_store::pg::config::OWNER_SECRET_PATH)]
        owner_password_file: std::path::PathBuf,
    },
}

/// Word the operator types to confirm `restore-finish` on a terminal.
const CONFIRM_WORD: &str = "restore-finish";

/// Runs an `nzbd db` action.
///
/// # Errors
/// The database cannot be opened or the runtime cannot start.
pub fn run_db(cfg: &Config, action: &DbAction) -> Result<ExitCode, String> {
    let (full, quick, allow_root) = match action {
        DbAction::Check {
            full,
            quick,
            allow_root,
        } => (full, quick, allow_root),
        DbAction::RestoreFinish {
            yes,
            dry_run,
            allow_root,
        } => return run_restore_finish(cfg, *yes, *dry_run, *allow_root),
        DbAction::SetRetention { .. } => {
            return crate::dbadmin::run_set_retention_action(cfg, action);
        }
        DbAction::Migrate {
            yes,
            force,
            allow_root,
            owner_user,
            owner_password_file,
        } => {
            refuse_root(*allow_root)?;
            return crate::dbsetup::run_migrate(cfg, *yes, *force, owner_user, owner_password_file);
        }
        DbAction::Restore {
            file,
            allow_unencrypted,
            force,
            allow_root,
            owner_user,
            owner_password_file,
        } => {
            refuse_root(*allow_root)?;
            return crate::dbsetup::run_restore(
                cfg,
                file,
                *allow_unencrypted,
                *force,
                owner_user,
                owner_password_file,
            );
        }
    };
    if !*allow_root && running_as_root() {
        return Err(root_refusal());
    }
    let mode = if *full {
        StartupCheck::Full
    } else if *quick {
        StartupCheck::Quick
    } else {
        StartupCheck::Fast
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = match crate::dbopen::open_read_only(cfg).await {
            Ok(db) => db,
            // Not a database / malformed header: the same verdict as a failed check.
            Err(crate::dbopen::OpenError::Store(StoreError::Integrity(why))) => {
                println!("database check ({}) FAILED: {why}", mode.as_str());
                return Ok(ExitCode::from(2));
            }
            Err(e) => return Err(format!("database: {e}")),
        };
        let started = Instant::now();
        let res = match &db {
            nzb_store::Store::Sqlite(s) => s.check(mode).await,
            nzb_store::Store::Postgres(_) => Ok(()),
        };
        let secs = started.elapsed().as_secs_f64();
        db.close().await;
        match res {
            Ok(()) => {
                println!("database check ({}) ok in {secs:.1} s", mode.as_str());
                Ok(ExitCode::SUCCESS)
            }
            Err(StoreError::Integrity(why)) => {
                println!("database check ({}) FAILED: {why}", mode.as_str());
                Ok(ExitCode::from(2))
            }
            Err(e) => Err(format!("database: {e}")),
        }
    })
}

/// The confirmation gate of `restore-finish`: `--yes` or `--dry-run` pass; otherwise a terminal
/// must be attached and the operator must type [`CONFIRM_WORD`]. `read_line` supplies the typed
/// line (injected so the gate is testable without a terminal).
fn confirm(
    yes: bool,
    dry_run: bool,
    tty: bool,
    read_line: &mut dyn FnMut() -> Result<String, String>,
) -> Result<(), String> {
    if yes || dry_run {
        return Ok(());
    }
    if !tty {
        return Err(
            "`db restore-finish` changes the database: pass --yes (or run it on a \
                    terminal and type the confirmation word); --dry-run shows the counts"
                .to_owned(),
        );
    }
    println!(
        "This revokes ALL API keys and deletes every session, open invitation, recovery \
         code and throttle row. Stop nzbd first. Type `{CONFIRM_WORD}` to continue:"
    );
    if read_line()?.trim() != CONFIRM_WORD {
        return Err("not confirmed; nothing was changed".to_owned());
    }
    Ok(())
}

/// `nzbd db restore-finish`.
fn run_restore_finish(
    cfg: &Config,
    yes: bool,
    dry_run: bool,
    allow_root: bool,
) -> Result<ExitCode, String> {
    use std::io::IsTerminal as _;
    if !allow_root && running_as_root() {
        return Err(
            "refusing to run `db restore-finish` as root: the database files would become \
             root-owned and the service user could not write them. Run it as the service user, \
             e.g. `docker compose run --rm --no-deps nzbd /nzbd db restore-finish`, or pass \
             --allow-root"
                .to_owned(),
        );
    }
    if !crate::dbopen::exists(cfg) {
        return Err(format!(
            "database {} does not exist",
            cfg.paths.db.display()
        ));
    }
    confirm(yes, dry_run, std::io::stdin().is_terminal(), &mut || {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("stdin: {e}"))?;
        Ok(line)
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before 1970".to_owned())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_owned()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        // A dry run is write-free: read-only handle, no migration, no category seeding, no chain
        // bootstrap. A real run opens read-write like every other operator command.
        let db = if dry_run {
            crate::dbopen::open_read_only(cfg).await
        } else {
            crate::dbopen::open_allow_restore_pending(cfg).await
        }
        .map_err(|e| format!("database: {e}"))?;
        let mut out = std::io::stdout().lock();
        let mut res = restore_finish_to(&db, now, dry_run, &mut out).await;
        // The finished database becomes the anchored one (restore detection, SEC-094); another library is never
        // adopted (SEC-101).
        if res.is_ok() && !dry_run {
            res = crate::library::accept_restored(cfg, &db).await;
        }
        db.close().await;
        res.map(|()| ExitCode::SUCCESS)
    })
}

/// The testable core of `restore-finish`: runs the store operation and prints the report, the
/// accounts, the audit anchor and the next steps. Only counts, ids, login names, roles and state
/// are printed (login names pass through `sanitize_text` so a hostile name cannot inject control
/// characters into the terminal).
///
/// # Errors
/// Database or output errors.
pub async fn restore_finish_to(
    db: &nzb_store::Store,
    now: i64,
    dry_run: bool,
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    let e = |e: StoreError| format!("database: {e}");
    let w = |r: std::io::Result<()>| r.map_err(|e| format!("output: {e}"));
    let rep = db.restore_finish(now, dry_run).await.map_err(|err| {
        let msg = err.to_string();
        if msg.contains("locked") || msg.contains("busy") {
            format!(
                "database: {msg} (the database is in use: is nzbd still running? \
                 stop it first: `docker compose stop nzbd`)"
            )
        } else {
            format!("database: {msg}")
        }
    })?;
    let (verb, keys_verb) = if dry_run {
        ("would remove", "would revoke")
    } else {
        ("removed", "revoked")
    };
    w(writeln!(
        out,
        "{verb}: {} session(s), {} staged credential(s), {} open invitation/recovery code(s), \
         {} MFA recovery code(s), {} login lock(s), {} account throttle(s), {} known address(es), \
         {} pending enrollment token(s)",
        rep.sessions,
        rep.credential_staging,
        rep.open_invites,
        rep.recovery_codes,
        rep.login_locks,
        rep.account_throttles,
        rep.known_ips,
        rep.enroll_tokens
    ))?;
    w(writeln!(
        out,
        "{keys_verb}: {} API key(s)",
        rep.api_keys_revoked
    ))?;
    w(writeln!(out, "accounts as the restored file has them:"))?;
    for a in db.restore_finish_accounts().await.map_err(e)? {
        let state = if a.deleted {
            "deleted"
        } else if a.disabled {
            "DISABLED"
        } else {
            "enabled"
        };
        w(writeln!(
            out,
            "  id={} name={} role={} state={} mfa={}",
            a.id,
            nzb_core::sanitize_text(&a.username, 64),
            a.role,
            state,
            if a.totp_enabled { "yes" } else { "no" }
        ))?;
    }
    match db.audit_anchor().await {
        Ok(a) => w(writeln!(out, "audit chain anchor: {}", a.line()))?,
        Err(err) => w(writeln!(out, "audit chain anchor unavailable: {err}"))?,
    }
    if dry_run {
        w(writeln!(out, "dry run: nothing was changed"))?;
    } else {
        w(writeln!(
            out,
            "next: (1) compare the accounts above with what you expect: roles, disabled state and \
             password hashes are exactly as the snapshot had them; `nzbd user ...` fixes them; \
             (2) re-issue the API keys you still need (`nzbd apikey create`); (3) re-invite \
             accounts created after the snapshot and re-issue their recovery codes; (4) compare \
             the anchor above with the logged anchors from before the restore; (5) run \
             `nzbd store verify`, then start nzbd"
        ))?;
    }
    Ok(())
}

/// Review 36 I3: `db migrate` / `db restore` refuse root like `db check` (files they create would be root-owned).
fn refuse_root(allow_root: bool) -> Result<(), String> {
    if !allow_root && running_as_root() {
        return Err(
            "refusing to run as root: files created now would be root-owned and refused by `serve`. Run it as the \
             service user (the `setup` service does), or pass --allow-root"
                .to_owned(),
        );
    }
    Ok(())
}

/// True when the effective uid is 0, the effective gid is 0, or group 0 is among the supplementary groups
/// (review 44 L1, SEC-040: a `user: "1000:0"` process is in the root group and creates root-group files).
/// `geteuid`/`getegid` cannot fail; a failing `getgroups` counts as root, so there is no "could not tell" path
/// that lets root through (review 39 L2: the earlier `/proc/self/status` parse treated an unreadable file as
/// "not root").
pub(crate) fn running_as_root() -> bool {
    let groups: Option<Vec<u32>> = rustix::process::getgroups()
        .ok()
        .map(|g| g.iter().map(|x| x.as_raw()).collect());
    is_root_identity(
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        groups.as_deref(),
    )
}

/// The rule of [`running_as_root`] on plain ids (`groups` = `None`: the supplementary groups are unknown).
fn is_root_identity(user: u32, group: u32, groups: Option<&[u32]>) -> bool {
    user == 0 || group == 0 || groups.is_none_or(|g| g.contains(&0))
}

/// Why `db check` will not run as root.
fn root_refusal() -> String {
    // A read-only SQLite open of a cleanly closed WAL database creates `-wal` and `-shm`
    // (SQLite offers no way to avoid it that is also safe next to a running server: `immutable=1`
    // would read a database the server is changing). Owned by root they would lock the service
    // user (uid 10001) out of its own WAL files (T088 review L1).
    "refusing to run `db check` as root: opening the database can create root-owned \
     -wal/-shm files the service user cannot write. Run it as the service user, e.g. \
     `docker compose exec nzbd /nzbd db check`, or pass --allow-root if you know the \
     server is stopped and will not be run as another user"
        .to_owned()
}

/// Logs one open/migration progress event. Only version numbers, compiled-in migration names
/// and durations are logged; nothing read from the database content.
pub fn log_open_event(ev: &OpenEvent) {
    match ev {
        OpenEvent::CheckStarted { mode, escalated } => {
            tracing::info!(
                mode = mode.as_str(),
                escalated = *escalated,
                "database check started{}",
                if *escalated {
                    " (full check forced: migrations are pending)"
                } else {
                    ""
                }
            );
        }
        OpenEvent::CheckFinished { mode, secs } => {
            tracing::info!(mode = mode.as_str(), secs = *secs, "database check passed");
        }
        OpenEvent::MigrationsPending { total, first, last } => {
            tracing::info!(
                pending = *total,
                first = *first,
                last = *last,
                "database migrations pending; the listener answers 503 until they finish"
            );
        }
        OpenEvent::MigrationStarted {
            version,
            description,
            index,
            total,
        } => {
            tracing::info!(
                version = *version,
                name = %description,
                step = *index,
                of = *total,
                "migration started"
            );
        }
        OpenEvent::MigrationRunning {
            version,
            elapsed_secs,
        } => {
            tracing::info!(
                version = *version,
                elapsed_secs = *elapsed_secs,
                "migration still running"
            );
        }
        OpenEvent::MigrationFinished { version, secs } => {
            tracing::info!(version = *version, secs = *secs, "migration finished");
        }
        OpenEvent::FileModeFixed { suffix, mode } => {
            tracing::warn!(
                file = %format!("paths.db{suffix}"),
                old_mode = %format!("{mode:o}"),
                "SEC-102: the database file was readable by group or other; set to 0600"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn cfg(dir: &std::path::Path) -> Config {
        let mut c = Config::default();
        c.paths.db = dir.join("nzbd.sqlite");
        c
    }

    fn check(c: &Config, full: bool, quick: bool) -> Result<String, String> {
        // `allow_root`: the test may run as root; the guard itself is tested below.
        run_db(
            c,
            &DbAction::Check {
                full,
                quick,
                allow_root: true,
            },
        )
        .map(|code| format!("{code:?}"))
    }

    #[test]
    fn t090_root_is_detected_from_the_effective_uid() {
        if rustix::process::geteuid().as_raw() == 0 {
            assert!(running_as_root());
        }
        assert!(root_refusal().contains("--allow-root"));
    }

    #[test]
    fn sec_040_root_group_counts_as_root() {
        // Review 44 L1: uid 0, gid 0 or group 0 among the supplementary groups are all refused.
        assert!(is_root_identity(0, 1000, Some(&[1000])));
        assert!(is_root_identity(1000, 0, Some(&[])));
        assert!(is_root_identity(1000, 1000, Some(&[1000, 0])));
        assert!(!is_root_identity(1000, 1000, Some(&[1000])));
        assert!(!is_root_identity(10001, 10001, Some(&[])));
        // Unknown supplementary groups fail closed.
        assert!(is_root_identity(1000, 1000, None));
        // The live process agrees with the rule on its own ids.
        let groups: Vec<u32> = rustix::process::getgroups()
            .unwrap()
            .iter()
            .map(|x| x.as_raw())
            .collect();
        assert_eq!(
            running_as_root(),
            is_root_identity(
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
                Some(&groups)
            )
        );
    }

    #[test]
    fn t090_the_refusal_applies_without_allow_root_only_when_root() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        let r = run_db(
            &c,
            &DbAction::Check {
                full: false,
                quick: false,
                allow_root: false,
            },
        );
        let as_root = running_as_root();
        // The file does not exist, so the non-root path is "could not run" too; only the
        // message tells them apart.
        let msg = r.unwrap_err();
        assert_eq!(msg.contains("--allow-root"), as_root, "{msg}");
    }

    #[test]
    fn t088_db_check_exit_codes_for_every_mode() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            nzb_store::Store::open_sqlite(&nzb_store::DbConfig {
                path: c.paths.db.clone(),
            })
            .await
            .unwrap()
            .close()
            .await;
        });
        let ok = format!("{:?}", ExitCode::SUCCESS);
        for (full, quick) in [(false, false), (false, true), (true, false)] {
            assert_eq!(check(&c, full, quick), Ok(ok.clone()));
        }
        // A missing file is "could not run" (error), not "damaged".
        let missing = cfg(&d.path().join("nope"));
        assert!(check(&missing, false, false).is_err());
        // Garbage: reported as damaged (exit 2) in every mode, and left untouched.
        let bad = d.path().join("bad");
        std::fs::create_dir(&bad).unwrap();
        let badc = cfg(&bad);
        std::fs::write(&badc.paths.db, vec![0x41_u8; 8192]).unwrap();
        let two = format!("{:?}", ExitCode::from(2));
        for (full, quick) in [(false, false), (false, true), (true, false)] {
            assert_eq!(check(&badc, full, quick), Ok(two.clone()));
        }
        assert_eq!(std::fs::read(&badc.paths.db).unwrap(), vec![0x41_u8; 8192]);
    }

    /// The leg's library (`NZBD_TEST_BACKEND`; SQLite at `paths.db`) with one API key.
    async fn db_with_key(c: &Config) -> (nzb_store::test_backend::TestStore, String) {
        let ts = nzb_store::test_backend::TestStore::open_file(&c.paths.db).await;
        let mut buf: Vec<u8> = Vec::new();
        crate::apikeys::create(&ts.store, "k", None, None, &mut buf)
            .await
            .unwrap();
        (ts, String::from_utf8(buf).unwrap())
    }

    #[tokio::test]
    async fn sec_068_restore_finish_cli_prints_counts_accounts_anchor_and_next_steps() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        let (ts, created) = db_with_key(&c).await;
        let db = ts.store.clone();
        let mut out: Vec<u8> = Vec::new();
        restore_finish_to(&db, 1_000, false, &mut out)
            .await
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("revoked: 1 API key(s)"), "{text}");
        assert!(
            text.contains("accounts as the restored file has them"),
            "{text}"
        );
        assert!(text.contains("audit chain anchor: head_log="), "{text}");
        assert!(text.contains("nzbd store verify"), "{text}");
        assert_eq!(db.count_active_api_keys().await.unwrap(), 0);
        // No secret is ever printed: the one-time key text of `create` is not in the report.
        for tok in created.split_whitespace().filter(|t| t.len() >= 32) {
            assert!(!text.contains(tok), "secret printed");
        }
        // Idempotent.
        let mut again: Vec<u8> = Vec::new();
        restore_finish_to(&db, 2_000, false, &mut again)
            .await
            .unwrap();
        assert!(
            String::from_utf8(again)
                .unwrap()
                .contains("revoked: 0 API key(s)")
        );
        assert!(db.audit_walk(None, &mut |_| {}).await.unwrap().is_ok());
        db.close().await;
    }

    #[tokio::test]
    async fn sec_068_restore_finish_dry_run_cli_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        let (ts, _) = db_with_key(&c).await;
        let db = ts.store.clone();
        let mut out: Vec<u8> = Vec::new();
        restore_finish_to(&db, 1_000, true, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("would revoke: 1 API key(s)"), "{text}");
        assert!(text.contains("nothing was changed"), "{text}");
        assert_eq!(db.count_active_api_keys().await.unwrap(), 1);
        db.close().await;
    }

    #[test]
    fn sec_068_restore_finish_refuses_without_yes_when_stdin_is_not_a_terminal() {
        let mut never = || -> Result<String, String> { panic!("must not read stdin") };
        let e = confirm(false, false, false, &mut never).unwrap_err();
        assert!(e.contains("--yes"), "{e}");
        // --yes and --dry-run pass without a terminal.
        assert!(confirm(true, false, false, &mut never).is_ok());
        assert!(confirm(false, true, false, &mut never).is_ok());
        // On a terminal the exact word is required.
        let mut wrong = || Ok("yes\n".to_owned());
        assert!(confirm(false, false, true, &mut wrong).is_err());
        let mut right = || Ok("restore-finish\n".to_owned());
        assert!(confirm(false, false, true, &mut right).is_ok());
    }

    #[test]
    fn sec_068_restore_finish_refuses_a_2x_database_and_leaves_it_untouched() {
        // Fresh start (owner decision 2026-10-15): v3 never migrates or writes a 2.x file, not even through
        // `restore-finish`; both the dry run and the real run fail and the bytes stay identical.
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        // The production bundle contains the old migrations, but no binary test fixtures.
        // Build the real legacy schema locally so this regression works from a fresh checkout.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use sqlx::Connection as _;
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&c.paths.db)
                .create_if_missing(true);
            let mut conn = sqlx::SqliteConnection::connect_with(&options)
                .await
                .unwrap();
            sqlx::migrate!("../../migrations")
                .run(&mut conn)
                .await
                .unwrap();
            conn.close().await.unwrap();
        });
        drop(rt);
        let before = std::fs::read(&c.paths.db).unwrap();
        for (yes, dry_run) in [(false, true), (true, false)] {
            let r = run_db(
                &c,
                &DbAction::RestoreFinish {
                    yes,
                    dry_run,
                    allow_root: true,
                },
            );
            assert!(r.is_err(), "dry_run={dry_run}");
            assert_eq!(std::fs::read(&c.paths.db).unwrap(), before);
        }
    }
}
