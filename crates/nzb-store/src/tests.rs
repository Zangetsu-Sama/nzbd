//! Bootstrap tests: migrate from scratch, pragmas, seed, corrupt-DB fail-fast.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crate::{DbConfig, SqliteDb, StoreError, seed_rows};

fn cfg(dir: &tempfile::TempDir) -> DbConfig {
    DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    }
}

#[tokio::test]
async fn migrates_from_scratch_and_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.readers())
            .await
            .unwrap();
    for t in [
        "category",
        "release",
        "nzb_file",
        "account",
        "recovery_code",
        "session",
        "api_key",
        "ingest_log",
        "audit_log",
    ] {
        assert!(tables.iter().any(|n| n == t), "missing table {t}");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM category")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(usize::try_from(n).unwrap(), seed_rows().unwrap().len());
    let parent: Option<i64> = sqlx::query_scalar("SELECT parent_id FROM category WHERE id = 5040")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(parent, Some(5000));
    db.integrity_check().await.unwrap();
}

#[tokio::test]
async fn reopen_is_idempotent_and_reasserts_seed() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    sqlx::query("UPDATE category SET name = 'x' WHERE id = 8010")
        .execute(db.writer())
        .await
        .unwrap();
    db.close().await;
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM category")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(usize::try_from(n).unwrap(), seed_rows().unwrap().len());
    let name: String = sqlx::query_scalar("SELECT name FROM category WHERE id = 8010")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(name, "Other/Misc");
}

/// T146: a library seeded with the older taxonomy gets the new categories (and their totals rows) on the next open.
#[tokio::test]
async fn t146_old_library_gets_new_categories_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    for q in [
        "DELETE FROM category_stats WHERE category_id IN (1010, 1020, 1030, 4010, 4020, 4500, 4510, 4520, 7040)",
        "DELETE FROM category WHERE id IN (1010, 1020, 1030, 4010, 4020, 4500, 4510, 4520, 7040)",
    ] {
        sqlx::query(q).execute(db.writer()).await.unwrap();
    }
    db.close().await;
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let rows: Vec<(i64, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, parent_id, name FROM category WHERE id IN (1010, 1020, 1030, 4010, 4020, 4500, 4510, 4520, 7040) ORDER BY id",
    )
    .fetch_all(db.readers())
    .await
    .unwrap();
    assert_eq!(rows.len(), 9);
    assert_eq!(rows[4], (4020, Some(4000), "PC/Games".to_owned()));
    assert_eq!(rows[8], (7040, Some(7000), "Books/Mangas".to_owned()));
    let stats: i64 = sqlx::query_scalar("SELECT count(*) FROM category_stats")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(usize::try_from(stats).unwrap(), seed_rows().unwrap().len());
}

#[tokio::test]
async fn pragmas_are_applied() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    for pool in [db.writer(), db.readers()] {
        let jm: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(jm, "wal");
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(fk, 1);
        let bt: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(bt, 5000);
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(sync, 2, "FULL (D36 c: no knob)");
        // T087-H1: 2 = MEMORY; temp files would land on the 16 MiB /tmp tmpfs of the container.
        let temp: i64 = sqlx::query_scalar("PRAGMA temp_store")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(temp, 2, "MEMORY");
    }
    assert_eq!(db.writer().options().get_max_connections(), 1);
    assert_eq!(db.readers().options().get_max_connections(), 4);
    assert!(
        sqlx::query("DELETE FROM category")
            .execute(db.readers())
            .await
            .is_err(),
        "readers are read-only"
    );
}

#[tokio::test]
async fn synchronous_is_always_full() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(db.writer())
        .await
        .unwrap();
    assert_eq!(sync, 2);
}

#[tokio::test]
async fn foreign_keys_work() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let bad = sqlx::query(
        "INSERT INTO release (sha256, title, category_id, ingested_at, total_bytes, file_count, segment_count, nzb_size_bytes) \
         VALUES (zeroblob(32), 't', 999999, 0, 0, 0, 0, 0)",
    )
    .execute(db.writer())
    .await;
    assert!(bad.is_err(), "FK to category enforced");
}

#[tokio::test]
async fn garbage_file_fails_fast_and_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    std::fs::write(&c.path, vec![0x41u8; 8192]).unwrap();
    let err = SqliteDb::open(&c).await.unwrap_err();
    assert!(matches!(err, StoreError::Integrity(_)), "{err:?}");
    assert_eq!(std::fs::read(&c.path).unwrap(), vec![0x41u8; 8192]);
}

#[tokio::test]
async fn damaged_pages_fail_fast() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let db = SqliteDb::open(&c).await.unwrap();
    // Everything must be in the main file before it is damaged: a close under load can leave pages in the WAL.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(db.writer())
        .await
        .unwrap();
    db.close().await;
    let mut bytes = std::fs::read(&c.path).unwrap();
    assert!(bytes.len() > 4096 * 4);
    for b in bytes.iter_mut().skip(4096 * 2) {
        *b = 0xFF;
    }
    std::fs::write(&c.path, &bytes).unwrap();
    let err = SqliteDb::open(&c).await.unwrap_err();
    assert!(matches!(err, StoreError::Integrity(_)), "{err:?}");
}

#[tokio::test]
async fn foreign_key_violation_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let db = SqliteDb::open(&c).await.unwrap();
    let mut conn = db.writer().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO nzb_file (release_id, idx, subject, kind, bytes, segment_count) VALUES (42, 0, 's', 'other', 0, 0)",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(matches!(
        db.integrity_check().await,
        Err(StoreError::Integrity(_))
    ));
    db.close().await;
    // The default (fast) open does not look at foreign keys any more (T088); the full mode does.
    assert!(matches!(
        SqliteDb::open_with(&c, crate::StartupCheck::Full, &|_| {}).await,
        Err(StoreError::Integrity(_))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn db_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let _db = SqliteDb::open(&c).await.unwrap();
    assert_eq!(
        std::fs::metadata(&c.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// T061 L-2: the WAL and shared-memory sidecars hold the same rows as the main file and must be
/// 0600 too, both on a fresh database and when an older release left them 0644.
#[cfg(unix)]
#[tokio::test]
async fn t061_l2_wal_and_shm_sidecars_are_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let side = |suffix: &str| {
        let mut o = c.path.as_os_str().to_owned();
        o.push(suffix);
        std::path::PathBuf::from(o)
    };
    let db = SqliteDb::open(&c).await.unwrap();
    sqlx::query("UPDATE category SET name = name WHERE id = (SELECT min(id) FROM category)")
        .execute(db.writer())
        .await
        .unwrap();
    assert!(
        side("-wal").exists() && side("-shm").exists(),
        "WAL mode sidecars exist"
    );
    for p in [c.path.clone(), side("-wal"), side("-shm")] {
        assert_eq!(mode(&p), 0o600, "{}", p.display());
    }
    // Simulate a database written by an older release, then reopen.
    for suffix in ["-wal", "-shm"] {
        std::fs::set_permissions(side(suffix), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _second = SqliteDb::open(&c).await.unwrap();
    for suffix in ["-wal", "-shm"] {
        assert_eq!(mode(&side(suffix)), 0o600, "{suffix} repaired on open");
    }
}

/// SEC-081 / review 35 L8, the SQLite counterpart of `pg_tests::sec_081_purge_runs_in_bounded_batches`: the purge
/// runs in write transactions of at most `batch` rows (so the single writer is released between batches), removes
/// the same rows as one big purge would, and leaves the chain verifiable.
#[tokio::test]
async fn sec_081_purge_runs_in_bounded_batches() {
    const DAY: i64 = 86_400;
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let now = 1_700_000_000 + 1000 * DAY;
    for i in 0..10 {
        db.audit_event(
            now - (400 - i) * DAY,
            Some("user:1"),
            "download",
            None,
            None,
        )
        .await
        .unwrap();
    }
    for _ in 0..2 {
        db.audit_event(now - 5 * DAY, Some("user:1"), "download", None, None)
            .await
            .unwrap();
    }
    // Ingest rows to purge in batches as well.
    for i in 0..7 {
        sqlx::query("INSERT INTO ingest_log (ts, source, outcome) VALUES (?1, 'watch', 'failed')")
            .bind(now - (300 - i) * DAY)
            .execute(db.writer())
            .await
            .unwrap();
    }
    let r = db.purge_logs_batched(now, 90, 365, 90, 3).await.unwrap();
    assert_eq!((r.audit, r.ingest), (10, 7));
    let mut rows = 0;
    let rep = db.audit_walk(None, &mut |_| rows += 1).await.unwrap();
    assert!(rep.is_ok(), "{rep:?}");
    assert_eq!(rows, 2);
    assert!(db.audit_chain_quick().await.unwrap().consistent);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM ingest_log")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Review 34 L5 / SEC-095: a reader statement that runs past the deadline is interrupted (a busy error, so the web
/// layer answers the uniform 503), and the connection keeps working for the next statement.
#[tokio::test]
async fn sec_095_reader_statements_have_a_deadline() {
    let dir = tempfile::tempdir().unwrap();
    SqliteDb::open(&cfg(&dir)).await.unwrap().close().await;
    let pool = crate::db::reader_pool(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("nzbd.sqlite"))
            .read_only(true),
        std::time::Duration::from_millis(200),
    )
    .await
    .unwrap();
    let started = std::time::Instant::now();
    let e = sqlx::query_scalar::<_, i64>(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT count(*) FROM n",
    )
    .fetch_one(&pool)
    .await
    .unwrap_err();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(StoreError::Db(e).is_busy());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM category")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(n > 0);
}

/// SEC-095 on SQLite (the counterpart of `pg_tests::sec_095_no_long_work_under_account_lock`): the single writer is
/// the account-domain lock here, so no function that opens a write transaction (`begin_immediate()`) touches the
/// filesystem, spawns blocking work, sleeps or hashes a password; it only runs SQL. (Backups and the trash, whose
/// file work is the point, keep their file steps outside the transaction and are checked the same way.)
#[test]
fn sec_095_no_long_work_under_account_lock() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&src_dir).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.extension().is_none_or(|x| x != "rs")
            || name.ends_with("_tests.rs")
            || name == "tests.rs"
            || name.ends_with("testkit.rs")
            || name == "test_backend.rs"
        {
            continue;
        }
        let src = std::fs::read_to_string(&p).unwrap();
        let src = src
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default();
        for body in src.split("async fn ").skip(1) {
            // The function's own text: up to the next item at the impl level.
            let body = body.split("\n    pub ").next().unwrap_or(body);
            let body = body.split("\n    async fn ").next().unwrap_or(body);
            let Some(at) = body.find("begin_immediate()") else {
                continue;
            };
            checked += 1;
            let locked = &body[at..];
            for slow in [
                "std::fs",
                "File::",
                "spawn_blocking",
                "sleep(",
                "argon2",
                "fsync",
                "rename(",
            ] {
                assert!(
                    !locked.contains(slow),
                    "{slow} after begin_immediate() in {name}"
                );
            }
        }
    }
    assert!(checked > 30, "only {checked} write transactions found");
}
