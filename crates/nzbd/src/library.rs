//! One `serve` per library, the library identity and restore detection at start (ARCHITECTURE v3 10 and 13.5;
//! SEC-094, SEC-101, SEC-102). Both backends.
//!
//! * `paths.state/serve.lock`: an exclusive lock held for the life of `serve` (std's safe `File::try_lock`); a second
//!   `serve` on the same state directory is refused (`SERVE_LOCKED`).
//! * `paths.state/db-anchor.json` (`nzb_store::DbAnchor`): written at the first start, refreshed every 10 s while the
//!   database changes and by `nzbd db restore-finish`. At start a database with another identity is refused
//!   (`LIBRARY_MISMATCH`, or `BACKEND_MISMATCH` when the configured database is still empty), one behind the anchor
//!   with `RESTORE_DETECTED`, a restored one (`db_state.restore_pending`) with `RESTORE_PENDING`. Adopting another
//!   library is not offered in 3.0 (the SQLite -> PostgreSQL move is deferred, owner decision 2026-10-15).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nzb_store::prelude::*;
use nzb_store::{AnchorVerdict, Store, read_anchor, write_anchor};

use crate::config::Config;

/// Name of the anchor file inside `paths.state`.
pub const ANCHOR_FILE: &str = "db-anchor.json";
/// Name of the lock file inside `paths.state`.
pub const LOCK_FILE: &str = "serve.lock";
/// How often `serve` refreshes the anchor (the documented residual: changes of the last <= 10 s).
pub const ANCHOR_EVERY: Duration = Duration::from_secs(10);

/// The held `serve.lock` (released when dropped, also when the process dies).
#[derive(Debug)]
pub struct ServeLock {
    _file: File,
}

/// Creates `paths.state` (0700) when missing.
///
/// # Errors
/// Filesystem errors (fixed text).
pub fn state_dir(cfg: &Config) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = cfg.state_dir();
    if !dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("paths.state: cannot create ({:?})", e.kind()))?;
    }
    Ok(dir)
}

/// Takes the exclusive `serve.lock`.
///
/// # Errors
/// `SERVE_LOCKED` when another `serve` holds it; filesystem errors.
pub fn lock_serve(cfg: &Config) -> Result<ServeLock, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = state_dir(cfg)?.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc_o_nofollow())
        .open(&path)
        .map_err(|e| format!("paths.state/serve.lock: cannot open ({:?})", e.kind()))?;
    match file.try_lock() {
        Ok(()) => Ok(ServeLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(
            "SERVE_LOCKED: another `nzbd serve` holds this library (paths.state/serve.lock)"
                .to_owned(),
        ),
        Err(std::fs::TryLockError::Error(e)) => Err(format!(
            "paths.state/serve.lock: cannot lock ({:?})",
            e.kind()
        )),
    }
}

/// `O_NOFOLLOW` (the lock file is never followed through a symbolic link).
const fn libc_o_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits().cast_signed()
}

fn anchor_path(cfg: &Config) -> Result<PathBuf, String> {
    Ok(state_dir(cfg)?.join(ANCHOR_FILE))
}

/// The start-up gate of `serve` (see the module docs). Writes the anchor when the database is admitted.
///
/// # Errors
/// `RESTORE_PENDING`, `LIBRARY_MISMATCH`, `BACKEND_MISMATCH`, `RESTORE_DETECTED`, `ANCHOR_UNREADABLE`, database
/// errors.
pub async fn admit(cfg: &Config, store: &Store) -> Result<(), String> {
    verify_identity(cfg, store).await?;
    write_now(cfg, store).await
}

/// The checks of [`admit`] without writing the anchor: operator commands that write to the library (`nzbd
/// import`) refuse a restored, superseded or foreign library exactly like `serve`, and leave the anchor to `serve`.
///
/// # Errors
/// As [`admit`].
pub async fn verify_identity(cfg: &Config, store: &Store) -> Result<(), String> {
    if store
        .restore_pending()
        .await
        .map_err(|e| format!("database: {e}"))?
    {
        return Err(
            "RESTORE_PENDING: this database was restored from a backup; run `nzbd db restore-finish` first".to_owned(),
        );
    }
    let path = anchor_path(cfg)?;
    let anchored = read_anchor(&path).map_err(|_| {
        "ANCHOR_UNREADABLE: paths.state/db-anchor.json is not a valid anchor file".to_owned()
    })?;
    if let Some(a) = anchored {
        match store
            .check_anchor(&a)
            .await
            .map_err(|e| format!("database: {e}"))?
        {
            AnchorVerdict::Consistent => {}
            AnchorVerdict::LibraryMismatch => return Err(mismatch(store, &a.backend).await),
            AnchorVerdict::RestoreDetected(why) => {
                return Err(format!(
                    "RESTORE_DETECTED: the database is behind paths.state/db-anchor.json ({why}); if it was \
                     restored on purpose, run `nzbd db restore-finish`"
                ));
            }
        }
    }
    Ok(())
}

async fn mismatch(store: &Store, anchored_backend: &str) -> String {
    if store.library_is_empty().await.unwrap_or(false) {
        format!(
            "BACKEND_MISMATCH: paths.state names a {anchored_backend} library but the configured {} database is \
             empty; check db.backend and the database settings",
            store.backend()
        )
    } else {
        format!(
            "LIBRARY_MISMATCH: the configured {} database is another library than the one paths.state was written \
             for; check db.backend, paths.db and the database settings (adopting another library is not offered \
             in 3.0)",
            store.backend()
        )
    }
}

/// Captures and writes the anchor now.
///
/// # Errors
/// Database or filesystem errors (fixed text).
pub async fn write_now(cfg: &Config, store: &Store) -> Result<(), String> {
    let a = store
        .capture_anchor()
        .await
        .map_err(|e| format!("anchor: {e}"))?;
    write_anchor(&anchor_path(cfg)?, &a)
        .map_err(|_| "anchor: cannot write paths.state/db-anchor.json".to_owned())
}

/// `restore-finish`: the restored database becomes the anchored one, unless it is another library (never adopted
/// in 3.0).
///
/// # Errors
/// `LIBRARY_MISMATCH`; database or filesystem errors.
pub async fn accept_restored(cfg: &Config, store: &Store) -> Result<(), String> {
    let path = anchor_path(cfg)?;
    if let Ok(Some(a)) = read_anchor(&path)
        && store
            .check_anchor(&a)
            .await
            .map_err(|e| format!("database: {e}"))?
            == AnchorVerdict::LibraryMismatch
        && !store
            .library_is_empty()
            .await
            .map_err(|e| format!("database: {e}"))?
    {
        return Err(mismatch(store, &a.backend).await);
    }
    write_now(cfg, store).await
}

/// Refreshes the anchor every [`ANCHOR_EVERY`] while `serve` runs (only when it changed). Ends with `stop`.
pub fn spawn_anchor_writer(
    cfg: &Config,
    store: Store,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let path = anchor_path(cfg);
    tokio::spawn(async move {
        let Ok(path) = path else { return };
        let mut last = None;
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => break,
                () = tokio::time::sleep(ANCHOR_EVERY) => {}
            }
            match store.capture_anchor().await {
                Ok(a) if last.as_ref() != Some(&a) => {
                    if write_anchor(&path, &a).is_ok() {
                        last = Some(a);
                    } else {
                        tracing::warn!("anchor: cannot write paths.state/db-anchor.json");
                    }
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("anchor: database not readable"),
            }
        }
    })
}

/// `paths.state` and the database file on one filesystem (SQLite): a snapshot of that filesystem rolls both back, so
/// restore detection cannot fire (review 34 M3, health WARN `ANCHOR_SAME_FILESYSTEM`).
#[must_use]
pub fn anchor_shares_filesystem(cfg: &Config) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    if cfg.db.backend != nzb_store::DbBackend::Sqlite {
        return false;
    }
    let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev()).ok();
    let db_dir = cfg.paths.db.parent().map(Path::to_path_buf);
    match (dev(&cfg.state_dir()), db_dir.as_deref().and_then(dev)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{admit, lock_serve};
    use crate::config::{Config, Paths};
    use nzb_store::prelude::*;
    use nzb_store::{DbBackend, Store};

    fn sqlite_cfg(dir: &std::path::Path, db: &str, state: &std::path::Path) -> Config {
        Config {
            paths: Paths {
                db: dir.join(db),
                state: Some(state.to_path_buf()),
                ..Paths::default()
            },
            ..Config::default()
        }
    }

    async fn sqlite(cfg: &Config) -> Store {
        crate::dbopen::open(cfg).await.unwrap()
    }

    async fn non_empty(store: &Store) {
        store
            .create_account_operator(
                &nzb_store::NewAccount {
                    username: "root",
                    password_hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
                    role: Some(nzb_store::Role::Admin),
                },
                nzb_store::AccountPolicy {
                    multi_user: true,
                    max_accounts: 10,
                    registration_enabled: true,
                },
                1,
            )
            .await
            .unwrap();
    }

    fn code(r: Result<(), String>) -> String {
        r.unwrap_err()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn sec_101_backend_is_recorded_in_db_state_and_anchor() {
        let d = tempfile::tempdir().unwrap();
        let cfg = sqlite_cfg(d.path(), "a.sqlite", &d.path().join("state"));
        let a = sqlite(&cfg).await;
        admit(&cfg, &a).await.unwrap();
        let anchored = nzb_store::read_anchor(&cfg.state_dir().join(super::ANCHOR_FILE))
            .unwrap()
            .unwrap();
        let now = a.capture_anchor().await.unwrap();
        assert_eq!(anchored.backend, "sqlite");
        assert_eq!(anchored.instance_id, now.instance_id);
        assert_eq!(anchored.instance_id.len(), 32);
        // The Postgres library records its own identity the same way.
        let t = nzb_store::pg::testing::TestDb::new().await;
        let pg = Store::Postgres(t.db.clone());
        let p = pg.capture_anchor().await.unwrap();
        assert_eq!(p.backend, "postgres");
        assert_eq!(p.instance_id.len(), 32);
        assert_ne!(p.instance_id, anchored.instance_id);
    }

    /// A configuration that points `serve` at another library than the anchored one is refused: another non-empty
    /// SQLite file (a changed `paths.db`), a non-empty Postgres database, and the superseded library after a switch.
    #[tokio::test]
    async fn sec_101_switching_back_to_a_superseded_library_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let cfg_a = sqlite_cfg(d.path(), "a.sqlite", &state);
        let a = sqlite(&cfg_a).await;
        non_empty(&a).await;
        admit(&cfg_a, &a).await.unwrap();
        // Another non-empty SQLite library under the same state directory.
        let cfg_b = sqlite_cfg(d.path(), "b.sqlite", &state);
        let b = sqlite(&cfg_b).await;
        non_empty(&b).await;
        assert_eq!(code(admit(&cfg_b, &b).await), "LIBRARY_MISMATCH");
        // A non-empty Postgres library: refused while the anchor names the SQLite one.
        let t = nzb_store::pg::testing::TestDb::new().await;
        let pg = Store::Postgres(t.db.clone());
        non_empty(&pg).await;
        let mut cfg_pg = cfg_a.clone();
        cfg_pg.db.backend = DbBackend::Postgres;
        assert_eq!(code(admit(&cfg_pg, &pg).await), "LIBRARY_MISMATCH");
        // Once the state names the Postgres library (as after a completed switch), going back is refused.
        std::fs::remove_file(state.join(super::ANCHOR_FILE)).unwrap();
        admit(&cfg_pg, &pg).await.unwrap();
        assert_eq!(code(admit(&cfg_a, &a).await), "LIBRARY_MISMATCH");
        // restore-finish never adopts another library either.
        assert_eq!(
            code(super::accept_restored(&cfg_a, &a).await),
            "LIBRARY_MISMATCH"
        );
        // The anchored library itself is admitted again.
        admit(&cfg_pg, &pg).await.unwrap();
    }

    /// An empty database of the configured backend while the anchor names a library: `BACKEND_MISMATCH`.
    #[tokio::test]
    async fn sec_101_backend_mismatch_refuses_to_start() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let cfg_a = sqlite_cfg(d.path(), "a.sqlite", &state);
        let a = sqlite(&cfg_a).await;
        non_empty(&a).await;
        admit(&cfg_a, &a).await.unwrap();
        let t = nzb_store::pg::testing::TestDb::new().await;
        let pg = Store::Postgres(t.db.clone());
        let mut cfg_pg = cfg_a.clone();
        cfg_pg.db.backend = DbBackend::Postgres;
        assert_eq!(code(admit(&cfg_pg, &pg).await), "BACKEND_MISMATCH");
        // A new empty SQLite file under the same state: the same refusal.
        let cfg_c = sqlite_cfg(d.path(), "c.sqlite", &state);
        let c = sqlite(&cfg_c).await;
        assert_eq!(code(admit(&cfg_c, &c).await), "BACKEND_MISMATCH");
    }

    #[tokio::test]
    async fn sec_102_second_serve_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let cfg = sqlite_cfg(d.path(), "a.sqlite", &d.path().join("state"));
        let first = lock_serve(&cfg).unwrap();
        let e = lock_serve(&cfg).unwrap_err();
        assert!(e.starts_with("SERVE_LOCKED"), "{e}");
        drop(first);
        lock_serve(&cfg).unwrap();
    }

    /// Review 34 M3: every SQLite backup copy carries `restore_pending = 1`, so a copy put back by any means is refused
    /// until `restore-finish`, which clears it, rotates the index epoch and re-anchors.
    #[tokio::test]
    async fn sec_068_restored_sqlite_file_is_refused_until_restore_finish() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let cfg = sqlite_cfg(d.path(), "a.sqlite", &state);
        let a = sqlite(&cfg).await;
        non_empty(&a).await;
        admit(&cfg, &a).await.unwrap();
        let backups = d.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let rep = a.backup(&backups, 1_700_000_000, 3, None).await.unwrap();
        let epoch_before = a.search_epoch().await.unwrap();
        a.close().await;
        // The manual path: the operator copies the backup over the database file.
        for suffix in ["-wal", "-shm"] {
            let mut p = cfg.paths.db.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(p);
        }
        std::fs::copy(&rep.path, &cfg.paths.db).unwrap();
        // Operator commands refuse it like Postgres does (review 35 L6); restore-finish's opener accepts it.
        let e = crate::dbopen::open(&cfg).await.unwrap_err().to_string();
        assert!(e.starts_with("RESTORE_PENDING"), "{e}");
        let restored = crate::dbopen::open_allow_restore_pending(&cfg)
            .await
            .unwrap();
        assert!(restored.restore_pending().await.unwrap());
        assert_eq!(code(admit(&cfg, &restored).await), "RESTORE_PENDING");
        restored.restore_finish(1_700_000_100, false).await.unwrap();
        assert!(!restored.restore_pending().await.unwrap());
        assert_ne!(restored.search_epoch().await.unwrap(), epoch_before);
        super::accept_restored(&cfg, &restored).await.unwrap();
        admit(&cfg, &restored).await.unwrap();
    }
}
