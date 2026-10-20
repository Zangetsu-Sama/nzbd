//! In-process maintenance task of `serve` (T061 L-3): the daily database backup (keep-N rotation)
//! plus PostgreSQL partition upkeep and the log and API-key purges, so a plain `docker compose up` does not accumulate log rows
//! forever and the health dashboard's "Database backups" row has something to report.
//!
//! It reuses the store functions the `nzbd backup` CLI uses. Everything is async (sqlx runs the SQL
//! on its own threads), so the request runtime is never blocked. Nothing here logs secrets: only
//! counts and the backup file name.

use nzb_store::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Delay after startup before the first run, so the listener and ingest recovery are not competing.
pub const FIRST_RUN_DELAY: Duration = Duration::from_secs(60);
/// Revoked API keys are kept this long (for the account page history), then purged.
pub const REVOKED_KEY_RETENTION_DAYS: u32 = 90;

/// Settings of one maintenance task.
#[derive(Debug, Clone)]
pub struct Params {
    /// Delay before the first run.
    pub first_delay: Duration,
    /// Time between runs.
    pub interval: Duration,
    /// Directory receiving the backups.
    pub backups_dir: PathBuf,
    /// Backups to keep.
    pub keep: usize,
    /// Encrypt snapshots at rest with this key (T104); `None` writes plain snapshots.
    pub backup_key: Option<Arc<nzb_store::BackupKey>>,
}

/// What one run did. Errors are strings without secrets (store errors never contain any).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// File name of the backup written, when it succeeded.
    pub backup_file: Option<String>,
    /// Old backups removed by rotation.
    pub rotated: usize,
    /// Expired sessions removed.
    pub sessions: u64,
    /// Audit rows removed.
    pub audit_rows: u64,
    /// Ingest-log rows removed.
    pub ingest_rows: u64,
    /// Audit rows stamped more than a day in the future (clock problem; they were treated as aged).
    pub future_audit_rows: u64,
    /// Revoked API keys removed.
    pub revoked_keys: u64,
    /// Rows removed from the account tables (spent codes, staged swaps, throttle, locks, addresses).
    pub account_rows: u64,
    /// Steps that failed (each step is attempted regardless of the others).
    pub errors: Vec<String>,
}

/// Runs PostgreSQL partition upkeep, backup and the purges once, at unix time `now`.
/// Partition months and retention cutoffs use the database clock, not `now`.
pub async fn run_once(db: &nzb_store::Store, p: &Params, now: i64) -> Report {
    let mut r = Report::default();
    if let nzb_store::Store::Postgres(pg) = db
        && let Err(e) = pg.partition_upkeep().await
    {
        r.errors.push(format!("partition upkeep: {e}"));
    }
    match db
        .backup(&p.backups_dir, now, p.keep, p.backup_key.as_deref())
        .await
    {
        Ok(b) => {
            r.backup_file = b.path.file_name().map(|n| n.to_string_lossy().into_owned());
            r.rotated = b.rotated;
            crate::audit::log_anchor(db, "after_backup").await;
        }
        Err(e) => r.errors.push(format!("backup: {e}")),
    }
    match db.purge_expired_sessions(now).await {
        Ok(n) => r.sessions = n,
        Err(e) => r.errors.push(format!("session purge: {e}")),
    }
    // v3: the retention policy lives in the database (`nzbd db set-retention`, floors 90/365/1 days) and the cutoffs
    // come from the database clock on both backends.
    match db.purge_logs().await {
        Ok(n) => {
            r.audit_rows = n.audit;
            r.ingest_rows = n.ingest;
            r.future_audit_rows = n.future_rows;
            crate::audit::log_anchor(db, "after_purge").await;
        }
        Err(e) => r.errors.push(format!("log purge: {e}")),
    }
    match db
        .purge_revoked_api_keys(now, REVOKED_KEY_RETENTION_DAYS)
        .await
    {
        Ok(n) => r.revoked_keys = n,
        Err(e) => r.errors.push(format!("api key purge: {e}")),
    }
    match db.purge_account_state(now).await {
        Ok(n) => {
            r.account_rows = n
                .invites
                .saturating_add(n.staging)
                .saturating_add(n.throttle)
                .saturating_add(n.locks)
                .saturating_add(n.known_ips);
        }
        Err(e) => r.errors.push(format!("account state purge: {e}")),
    }
    r
}

fn log_report(r: &Report) {
    if r.future_audit_rows > 0 {
        tracing::warn!(
            rows = r.future_audit_rows,
            "audit rows are stamped more than a day in the future; check the system clock"
        );
    }
    if r.errors.is_empty() {
        tracing::info!(
            backup = r.backup_file.as_deref().unwrap_or("-"),
            rotated = r.rotated,
            sessions = r.sessions,
            audit_rows = r.audit_rows,
            ingest_rows = r.ingest_rows,
            revoked_keys = r.revoked_keys,
            account_rows = r.account_rows,
            "maintenance finished"
        );
    } else {
        tracing::warn!(
            errors = %r.errors.join("; "),
            backup = r.backup_file.as_deref().unwrap_or("-"),
            "maintenance finished with errors"
        );
    }
}

/// Spawns the periodic task: first run after `first_delay`, then every `interval`, until `stop`
/// turns true. `clock` supplies unix seconds (a fake in tests). A zero `interval` is refused by
/// the caller (config `backup_interval_hours = 0` means "do not spawn").
pub fn spawn(
    db: nzb_store::Store,
    p: Params,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let first = tokio::time::Instant::now() + p.first_delay;
        let mut tick = tokio::time::interval_at(first, p.interval.max(Duration::from_millis(1)));
        // A long stall must not trigger a burst of catch-up runs.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => log_report(&run_once(&db, &p, clock()).await),
                () = async { let _ = stop.wait_for(|v| *v).await; } => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    const DAY: i64 = 86_400;

    /// The leg's library (`NZBD_TEST_BACKEND`).
    async fn open(dir: &tempfile::TempDir) -> nzb_store::test_backend::TestStore {
        nzb_store::test_backend::TestStore::open(dir.path()).await
    }

    /// Finished backups only. An in-progress run leaves `.<name>.tmp` (and SQLite's transient
    /// `-journal` next to it during `VACUUM INTO`); counting those made the scheduler test flaky.
    fn backups(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                !e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.')
            })
            .count()
    }

    #[tokio::test]
    async fn run_once_backs_up_rotates_and_purges_old_logs() {
        let dir = tempfile::tempdir().unwrap();
        let ts = open(&dir).await;
        let db = ts.store.clone();
        let bdir = dir.path().join("backups");
        std::fs::create_dir(&bdir).unwrap();
        // v3: purge cutoffs come from the database clock and the retention policy (90 days by default), so the rows
        // are aged relative to the real clock.
        let t0 = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        db.audit_event(t0 - 100 * DAY, Some("u"), "login_ok", None, None)
            .await
            .unwrap();
        db.audit_event(t0 - DAY, Some("u"), "login_ok", None, None)
            .await
            .unwrap();
        let p = Params {
            first_delay: Duration::ZERO,
            interval: Duration::from_secs(DAY.unsigned_abs()),
            backups_dir: bdir.clone(),
            keep: 2,
            backup_key: None,
        };
        let r = run_once(&db, &p, t0).await;
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(r.backup_file.is_some());
        assert_eq!(r.audit_rows, 1, "only the 100-day-old row is purged");
        for i in 1..=3 {
            let r = run_once(&db, &p, t0 + i * DAY).await;
            assert!(r.errors.is_empty(), "{:?}", r.errors);
        }
        assert_eq!(backups(&bdir), 2, "keep-N rotation");
    }

    #[tokio::test]
    async fn sec_052_scheduled_backup_is_encrypted_when_a_key_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let ts = open(&dir).await;
        let db = ts.store.clone();
        let bdir = dir.path().join("backups");
        std::fs::create_dir(&bdir).unwrap();
        let p = Params {
            first_delay: Duration::ZERO,
            interval: Duration::from_secs(DAY.unsigned_abs()),
            backups_dir: bdir.clone(),
            keep: 3,
            backup_key: Some(Arc::new(
                nzb_store::BackupKey::from_slice(&[9; 32]).unwrap(),
            )),
        };
        let r = run_once(&db, &p, 1_800_000_000).await;
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let name = r.backup_file.unwrap();
        // The backend's own format: a SQLite file copy or a Postgres snapshot, sealed either way.
        assert!(
            name.ends_with(".sqlite.enc") || name.ends_with(".nzbdpg.enc"),
            "{name}"
        );
        assert!(nzb_store::looks_encrypted(&bdir.join(&name)));
        // The health row still sees it (encrypted names parse like plain ones).
        assert_eq!(
            crate::health::parse_backup_ts(&name),
            Some(1_800_000_000),
            "{name}"
        );
    }

    #[tokio::test]
    async fn spawned_task_runs_repeatedly_on_a_fake_clock_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let ts = open(&dir).await;
        let db = ts.store.clone();
        let bdir = dir.path().join("backups");
        std::fs::create_dir(&bdir).unwrap();
        let p = Params {
            first_delay: Duration::from_millis(20),
            interval: Duration::from_millis(60),
            backups_dir: bdir.clone(),
            keep: 14,
            backup_key: None,
        };
        // Each call is one fake day later, so same-second backup names never collide.
        let fake = Arc::new(AtomicI64::new(1_800_000_000));
        let clock: Arc<dyn Fn() -> i64 + Send + Sync> =
            Arc::new(move || fake.fetch_add(DAY, Ordering::SeqCst));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let h = spawn(db.clone(), p, clock, stop_rx);
        let mut waited = 0;
        while backups(&bdir) < 3 && waited < 200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        }
        assert!(
            backups(&bdir) >= 3,
            "at least three scheduled runs happened"
        );
        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("task stops on shutdown")
            .unwrap();
    }
}

#[cfg(test)]
mod upkeep_regressions {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use nzb_store::pg::testing::TestDb;

    const DAY: i64 = 86_400;
    // 2027-03-15 12:00:00 UTC.
    const NOW: i64 = 1_805_112_000;

    fn params(dir: &std::path::Path) -> Params {
        let backups_dir = dir.join("backups");
        std::fs::create_dir(&backups_dir).unwrap();
        Params {
            first_delay: Duration::ZERO,
            interval: Duration::from_hours(24),
            backups_dir,
            keep: 2,
            backup_key: None,
        }
    }

    async fn partitions(t: &TestDb) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
             WHERE i.inhparent = 'nzbd.ingest_log'::regclass ORDER BY 1",
        )
        .fetch_all(&mut t.app_conn().await)
        .await
        .unwrap()
    }

    async fn insert_target(t: &TestDb, ts: i64) -> String {
        sqlx::query_scalar(
            "INSERT INTO ingest_log (ts, source, outcome) VALUES ($1, 'watch', 'ok') \
             RETURNING tableoid::regclass::text",
        )
        .bind(ts)
        .fetch_one(&mut t.app_conn().await)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn run_once_prepares_log_partitions_and_tracks_database_months() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path());
        let db = nzb_store::Store::Postgres(t.db.clone());
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);

        // Deliberately use a different caller clock: partition ranges belong to the database clock.
        let first = run_once(&db, &p, NOW - 10 * DAY).await;
        assert!(first.errors.is_empty(), "{:?}", first.errors);
        assert!(first.backup_file.is_some());
        assert_eq!(
            partitions(&t).await,
            [
                "ingest_log_default",
                "ingest_log_y2027m03",
                "ingest_log_y2027m04",
                "ingest_log_y2027m05"
            ],
            "daily maintenance must prepare the database's current and next two log months"
        );
        assert_eq!(insert_target(&t, NOW).await, "ingest_log_y2027m03");

        // 92 days later is June 15: a subsequent real maintenance run prepares June-August.
        let june = NOW + 92 * DAY;
        t.set_db_clock(june).await;
        let second = run_once(&db, &p, NOW - 10 * DAY + 1).await;
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        assert!(second.backup_file.is_some());
        let names = partitions(&t).await;
        for month in [
            "ingest_log_y2027m06",
            "ingest_log_y2027m07",
            "ingest_log_y2027m08",
        ] {
            assert!(names.iter().any(|name| name == month), "missing {month}");
        }
        assert_eq!(insert_target(&t, june).await, "ingest_log_y2027m06");
        assert_eq!(
            second.ingest_rows, 1,
            "ordinary retention still removes the aged March row"
        );
    }

    #[tokio::test]
    async fn upkeep_failure_is_reported_without_skipping_backup_or_purges() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        let dir = tempfile::tempdir().unwrap();
        let db = nzb_store::Store::Postgres(t.db.clone());
        db.audit_event(NOW - 100 * DAY, None, "login_ok", None, None)
            .await
            .unwrap();
        sqlx::query("REVOKE EXECUTE ON FUNCTION nzbd.ensure_log_partitions() FROM nzbd_app")
            .execute(&mut t.owner_conn().await)
            .await
            .unwrap();

        let report = run_once(&db, &params(dir.path()), NOW).await;
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.starts_with("partition upkeep:")),
            "partition upkeep failure must be reported by maintenance"
        );
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(
            report.backup_file.is_some(),
            "backup remains independent of upkeep"
        );
        assert_eq!(report.audit_rows, 1, "purges still run after failed upkeep");
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
        assert_eq!(insert_target(&t, NOW).await, "ingest_log_default");
    }
}
