//! The 3.x SQLite line (migrations 0015+, T122; `DATA_MODEL` v3 section 8, ARCHITECTURE v3 13.2-13.4): the blob refusal
//! before any v3 migration (D36 a, review 34 L6), the post-migration checks (M1 b), the outbox and totals triggers, the
//! retention floors (SEC-103), the library identity row and `synchronous = FULL`. SQLite-only (one-line reason each).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Connection, SqliteConnection};

use crate::acct_testkit::{T0, analysis};
use crate::{
    CategorySource, DbConfig, NewRelease, RetentionPolicy, SceneColumns, SqliteDb, StoreError,
};

const DAY: i64 = 86_400;

async fn conn(path: &Path, fk: bool) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(fk);
    SqliteConnection::connect_with(&options).await.unwrap()
}

/// A 2.x database (the 2.x migration chain, `migrations/0001`..`0014`) with a category and an account.
async fn db_2x(dir: &Path) -> PathBuf {
    let path = dir.join("old.sqlite");
    let mut c = conn(&path, true).await;
    sqlx::migrate!("../../migrations")
        .run(&mut c)
        .await
        .unwrap();
    sqlx::raw_sql(
        "INSERT INTO category (id, parent_id, name) VALUES (8000, NULL, 'Other'), (8010, 8000, 'Misc'); \
         INSERT INTO user (id, username, password_hash, created_at, password_changed_at, role) \
           VALUES (1, 'alice', 'x', 1, 1, 'admin');",
    )
    .execute(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();
    path
}

async fn table_exists(path: &Path, name: &str) -> bool {
    let mut c = conn(path, true).await;
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(name)
            .fetch_one(&mut c)
            .await
            .unwrap();
    c.close().await.unwrap();
    n > 0
}

fn variant(e: &StoreError) -> String {
    match e {
        StoreError::Refused(code) => format!("Refused({code})"),
        other => format!("{other:?}"),
    }
}

/// Fresh start (owner decision 2026-10-15): a database written by 2.x is refused with `LEGACY_DATABASE` before
/// anything is created or migrated, and the file is byte-identical afterwards (also its `-wal`).
#[tokio::test]
async fn legacy_2x_database_is_refused_and_never_modified() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_2x(dir.path()).await;
    let before = std::fs::read(&path).unwrap();
    for _ in 0..2 {
        let e = SqliteDb::open(&DbConfig { path: path.clone() })
            .await
            .unwrap_err();
        assert_eq!(variant(&e), "Refused(LEGACY_DATABASE)");
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the 2.x file is untouched"
    );
    assert!(!table_exists(&path, "db_state").await);
    // Any other non-empty database that is not a 3.x SQLite library is refused the same way.
    let other = dir.path().join("other.sqlite");
    let mut c = conn(&other, true).await;
    sqlx::query("CREATE TABLE t (x INTEGER)")
        .execute(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    let e = SqliteDb::open(&DbConfig { path: other }).await.unwrap_err();
    assert_eq!(variant(&e), "Refused(LEGACY_DATABASE)");
}

async fn open(dir: &tempfile::TempDir) -> SqliteDb {
    SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap()
}

async fn insert(db: &SqliteDb, n: u8, cat: u32) -> i64 {
    let a = analysis(n);
    db.insert_release(&NewRelease {
        analysis: &a,
        nzb_size_bytes: 1,
        source_name: None,
        source_label: None,
        category_id: cat,
        category_source: CategorySource::Fallback,
        meta_json: None,
        scene: SceneColumns::default(),
        ingested_at: T0,
    })
    .await
    .unwrap()
}

async fn stats(db: &SqliteDb, cat: i64) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT releases, files, segments, bytes FROM category_stats WHERE category_id = ?1",
    )
    .bind(cat)
    .fetch_one(db.readers())
    .await
    .unwrap()
}

/// Every release change writes its outbox row and its `category_stats` delta in the same transaction (triggers),
/// and the totals equal a recount.
#[tokio::test]
async fn release_changes_write_outbox_rows_and_exact_totals() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let a = insert(&db, 1, 8010).await;
    let b = insert(&db, 2, 8010).await;
    assert_eq!(stats(&db, 8010).await, (2, 0, 0, 2));
    db.set_category(b, 5040).await.unwrap();
    assert_eq!(stats(&db, 8010).await.0, 1);
    assert_eq!(stats(&db, 5040).await.0, 1);
    db.delete_release(a).await.unwrap();
    assert_eq!(stats(&db, 8010).await, (0, 0, 0, 0));
    let out: Vec<i64> = db
        .search_outbox_read(100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.release_id)
        .collect();
    assert_eq!(out, [a, b, b, a]);
    let recount: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT category_id, count(*) FROM release GROUP BY category_id ORDER BY category_id",
    )
    .fetch_all(db.readers())
    .await
    .unwrap();
    let kept: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT category_id, releases FROM category_stats WHERE releases > 0 ORDER BY category_id",
    )
    .fetch_all(db.readers())
    .await
    .unwrap();
    assert_eq!(recount, kept);
    // Every seeded category has a totals row.
    let missing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM category c WHERE NOT EXISTS (SELECT 1 FROM category_stats s WHERE s.category_id = c.id)",
    )
    .fetch_one(db.readers())
    .await
    .unwrap();
    assert_eq!(missing, 0);
}

/// The library identity (review 34 M2): one `db_state` row, backend `sqlite`, a random 16-byte instance id.
#[tokio::test]
async fn sec_101_backend_is_recorded_in_db_state_and_anchor() {
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let (a, b) = (open(&d1).await, open(&d2).await);
    let id = |db: SqliteDb| async move {
        sqlx::query_as::<_, (String, Vec<u8>, i64)>(
            "SELECT backend, instance_id, restore_pending FROM db_state WHERE id = 1",
        )
        .fetch_one(db.readers())
        .await
        .unwrap()
    };
    let (ba, ia, pa) = id(a.clone()).await;
    let (_, ib, _) = id(b.clone()).await;
    assert_eq!(ba, "sqlite");
    assert_eq!(ia.len(), 16);
    assert_ne!(ia, ib, "every library gets its own identity");
    assert_eq!(pa, 0);
    // A second backend name cannot be written (CHECK).
    assert!(
        sqlx::query("UPDATE db_state SET backend = 'postgres' WHERE id = 1")
            .execute(a.writer())
            .await
            .is_err()
    );
}

/// SEC-103: deleting an audit row younger than its class floor (database clock) is refused by the trigger; older
/// rows and rows stamped more than a day ahead (they never pin the purge) can go.
#[tokio::test]
async fn sec_103_sqlite_floor_trigger_refuses_young_audit_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(db.readers())
        .await
        .unwrap();
    for (age, event) in [
        (10, "download"),
        (100, "download"),
        (200, "user.create"),
        (400, "user.create"),
        (-3, "download"),
    ] {
        db.audit_event(now - age * DAY, Some("cli"), event, None, None)
            .await
            .unwrap();
    }
    let rows: Vec<(i64, i64)> = sqlx::query_as("SELECT id, ts FROM audit_log ORDER BY id")
        .fetch_all(db.readers())
        .await
        .unwrap();
    let del = |id: i64| {
        let db = db.clone();
        async move {
            sqlx::query("DELETE FROM audit_log WHERE id = ?1")
                .bind(id)
                .execute(db.writer())
                .await
        }
    };
    // Review 35 L2: no column of a row can be updated, the chain columns included; moving a 200-day-old account row
    // into class 0 (90-day floor) would otherwise make it deletable.
    for sql in [
        "UPDATE audit_log SET chain_class = 0 WHERE id = ?1",
        "UPDATE audit_log SET chain_hash = zeroblob(32) WHERE id = ?1",
        "UPDATE audit_log SET chain_prev = zeroblob(32) WHERE id = ?1",
        "UPDATE audit_log SET ts = 0 WHERE id = ?1",
        "UPDATE audit_log SET detail = 'x' WHERE id = ?1",
    ] {
        let e = sqlx::query(sql)
            .bind(rows[2].0)
            .execute(db.writer())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("immutable"), "{sql}: {e}");
    }
    let young_log = del(rows[0].0).await.unwrap_err();
    assert!(young_log.to_string().contains("AUDIT_RETENTION_FLOOR"));
    let young_account = del(rows[2].0).await.unwrap_err();
    assert!(young_account.to_string().contains("AUDIT_RETENTION_FLOOR"));
    del(rows[1].0).await.unwrap();
    del(rows[3].0).await.unwrap();
    del(rows[4].0).await.unwrap();
}

/// SEC-103: the policy floors hold (Rust check first, then the table CHECKs), and `purge_logs()` follows the policy
/// with the database clock.
#[tokio::test]
async fn sec_103_retention_policy_floors_hold_on_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    assert_eq!(
        db.retention_policy().await.unwrap(),
        RetentionPolicy::default()
    );
    for bad in [
        RetentionPolicy {
            log_days: 89,
            ..RetentionPolicy::default()
        },
        RetentionPolicy {
            account_days: 364,
            ..RetentionPolicy::default()
        },
        RetentionPolicy {
            ingest_days: 0,
            ..RetentionPolicy::default()
        },
    ] {
        let e = db.set_retention_policy(bad).await.unwrap_err();
        assert!(matches!(e, StoreError::OutOfRange(_)), "{e:?}");
    }
    for sql in [
        "UPDATE retention_policy SET log_days = 30 WHERE id = 1",
        "UPDATE retention_policy SET account_days = 90 WHERE id = 1",
        "UPDATE retention_policy SET ingest_days = 0 WHERE id = 1",
    ] {
        assert!(
            sqlx::query(sql).execute(db.writer()).await.is_err(),
            "{sql}"
        );
    }
    let longer = RetentionPolicy {
        log_days: 120,
        ..RetentionPolicy::default()
    };
    db.set_retention_policy(longer).await.unwrap();
    assert_eq!(db.retention_policy().await.unwrap(), longer);
    // purge_logs(): 150-day-old log row goes, 100-day-old stays (policy 120 days).
    let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(db.readers())
        .await
        .unwrap();
    for age in [150, 100] {
        db.audit_event(now - age * DAY, Some("cli"), "download", None, None)
            .await
            .unwrap();
    }
    let r = db.purge_logs().await.unwrap();
    assert_eq!(r.audit, 1);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(left, 1);
    let keep = RetentionPolicy {
        keep_all: true,
        ..longer
    };
    db.set_retention_policy(keep).await.unwrap();
    assert_eq!(db.purge_logs().await.unwrap().audit, 0);
}

/// SEC-085 (D32) on the v3 baseline: the email CHECK refuses control characters, spaces and markup characters and
/// accepts everything the normaliser can emit.
#[tokio::test]
async fn sec_085_email_check_refuses_control_characters_and_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    sqlx::query(
        "INSERT INTO account (id, username, password_hash, created_at, password_changed_at, role) \
         VALUES (2, 'bob', 'x', 1, 1, 'uploader')",
    )
    .execute(db.writer())
    .await
    .unwrap();
    for bad in [
        "a\u{1b}[2j@x.org",
        "a\tb@x.org",
        "a\nb@x.org",
        "a b@x.org",
        "a\"b@x.org",
        "a<b@x.org",
        "a;b@x.org",
    ] {
        let r = sqlx::query("UPDATE account SET email = ?1 WHERE id = 2")
            .bind(bad)
            .execute(db.writer())
            .await;
        assert!(r.is_err(), "email {bad:?}");
    }
    let ok =
        sqlx::query("UPDATE account SET email = 'x.y_z%w+v-u9@sub-d.example.org' WHERE id = 2")
            .execute(db.writer())
            .await;
    assert!(ok.is_ok(), "{ok:?}");
}

/// Ids are never handed out twice (AUTOINCREMENT on `release`, `release_trash`, `audit_log`, `account`, outbox),
/// also after the newest release was deleted.
#[tokio::test]
async fn release_ids_are_never_reissued() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let a = insert(&db, 1, 8010).await;
    let b = insert(&db, 2, 8010).await;
    db.delete_release(b).await.unwrap();
    db.delete_release(a).await.unwrap();
    let c = insert(&db, 3, 8010).await;
    assert!(c > b, "{c} reissued an id");
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn refused(e: &StoreError) -> &'static str {
    match e {
        StoreError::Refused(code) => code.split(':').next().unwrap_or_default(),
        other => panic!("not a refusal: {other:?}"),
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut o = path.as_os_str().to_owned();
    o.push(suffix);
    PathBuf::from(o)
}

/// SEC-102: a new library's file and sidecars are 0600; a symbolic link (the file or a sidecar), a non-regular
/// file or a group/other-writable directory are refused with `DB_FILE_MODE` before anything reads them, also by the
/// read-only open. SQLite-only: the files are the backend.
#[tokio::test]
async fn sec_102_sqlite_files_are_0600_and_not_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.sqlite");
    let db = SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap();
    for f in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
        if f.exists() {
            assert_eq!(mode_of(&f), 0o600, "{}", f.display());
        }
    }
    db.close().await;
    // The configured path is a symbolic link to a real library.
    let link = dir.path().join("link.sqlite");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let e = SqliteDb::open(&DbConfig { path: link.clone() })
        .await
        .unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    let e = SqliteDb::open_read_only(&link).await.unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    // A sidecar that is a symbolic link (SQLite would write the WAL through it).
    let wal = sidecar(&path, "-wal");
    let _ = std::fs::remove_file(&wal);
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), &wal).unwrap();
    let e = SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    std::fs::remove_file(&wal).unwrap();
    // A second name of the database (hard link), e.g. in a directory others can read.
    let second = dir.path().join("second-name");
    std::fs::hard_link(&path, &second).unwrap();
    let e = SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    std::fs::remove_file(&second).unwrap();
    // Not a regular file.
    let fifo_like = dir.path().join("d.sqlite");
    std::fs::create_dir(&fifo_like).unwrap();
    let e = SqliteDb::open(&DbConfig { path: fifo_like })
        .await
        .unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    // A database directory others can write to (they could swap the file).
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    set_mode(&shared, 0o777);
    let e = SqliteDb::open(&DbConfig {
        path: shared.join("t.sqlite"),
    })
    .await
    .unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    assert!(!shared.join("t.sqlite").exists(), "nothing was created");
    // The real library still opens.
    SqliteDb::open(&DbConfig { path })
        .await
        .unwrap()
        .close()
        .await;
}

/// SEC-102: an operator copy without `chmod` (owned by the service uid, readable by group/other) is set to 0600 and
/// reported (the nzbd logs it as a warning); the read-only open reports nothing and changes nothing.
#[tokio::test]
async fn sec_102_group_readable_database_is_fixed_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.sqlite");
    SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap()
        .close()
        .await;
    set_mode(&path, 0o644);
    SqliteDb::open_read_only(&path).await.unwrap().close().await;
    assert_eq!(mode_of(&path), 0o644, "a read-only open changes nothing");
    let events = std::sync::Mutex::new(Vec::new());
    let db = SqliteDb::open_with(
        &DbConfig { path: path.clone() },
        crate::StartupCheck::Fast,
        &|ev| {
            if let crate::OpenEvent::FileModeFixed { suffix, mode } = ev {
                events.lock().unwrap().push((suffix, mode));
            }
        },
    )
    .await
    .unwrap();
    // The read-only open left `-wal`/`-shm` with the main file's mode (SQLite copies it): all three are fixed.
    let ev = events.lock().unwrap().clone();
    assert!(ev.contains(&("", 0o644)), "{ev:?}");
    assert!(ev.iter().all(|(_, m)| *m == 0o644), "{ev:?}");
    for f in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
        if f.exists() {
            assert_eq!(mode_of(&f), 0o600, "{}", f.display());
        }
    }
    db.close().await;
}

/// SEC-102: a database file owned by another uid than the service's is refused (`DB_FILE_MODE`), never "fixed";
/// root (uid 0) may open any file. The uid is a parameter here: the test cannot `chown` without privileges.
#[tokio::test]
async fn sec_102_foreign_owned_database_is_refused() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.sqlite");
    SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap()
        .close()
        .await;
    set_mode(&path, 0o644);
    let own = std::fs::metadata(&path).unwrap().uid();
    let other = if own == 1 { 2 } else { 1 };
    let fixed = std::sync::atomic::AtomicBool::new(false);
    let report = |_: crate::OpenEvent| fixed.store(true, std::sync::atomic::Ordering::SeqCst);
    let e = crate::db::check_db_files(&path, Some(other), Some(&report)).unwrap_err();
    assert_eq!(refused(&e), "DB_FILE_MODE");
    assert!(!fixed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(mode_of(&path), 0o644, "a foreign file is never modified");
    crate::db::check_db_files(&path, Some(own), None).unwrap();
    crate::db::check_db_files(&path, Some(0), None).unwrap();
}

/// Review 35 L1: the SQLite baseline refuses what Postgres refuses for the display data of a release: a title of 0 or
/// more than 512 bytes or with a NUL byte, and a scene family outside the closed set. The byte length counts bytes,
/// not characters (170 three-byte characters fit, 171 do not).
#[tokio::test]
async fn release_checks_match_postgres() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let try_insert = |n: u8, title: String, family: Option<&'static str>| {
        let db = db.clone();
        async move {
            let mut a = analysis(n);
            a.title = title;
            db.insert_release(&NewRelease {
                analysis: &a,
                nzb_size_bytes: 1,
                source_name: None,
                source_label: None,
                category_id: 8010,
                category_source: CategorySource::Fallback,
                meta_json: None,
                scene: SceneColumns {
                    family: family.map(str::to_owned),
                    ..SceneColumns::default()
                },
                ingested_at: T0,
            })
            .await
        }
    };
    try_insert(1, "a".repeat(512), None).await.unwrap();
    try_insert(2, "\u{65e5}".repeat(170), Some("tv"))
        .await
        .unwrap();
    for (n, bad) in [
        (3, "a".repeat(513)),
        (4, "\u{65e5}".repeat(171)),
        (5, String::new()),
        (6, "\0".to_owned()),
        (7, "a\0b".to_owned()),
    ] {
        assert!(try_insert(n, bad.clone(), None).await.is_err(), "{bad:?}");
    }
    // A byte sequence whose hex spells "00" across a boundary (C2 A0 0B) is not a NUL (no hex() GLOB test).
    try_insert(8, "\u{a0}\u{b}".to_owned(), None).await.unwrap();
    assert!(
        try_insert(9, "x".to_owned(), Some("<b>fam</b>"))
            .await
            .is_err()
    );
}

/// T134 review I3/I4: the roles migration (`v3-sqlite/0004_roles`) refuses a library that already holds an account, or
/// only an audit chain head (an audit log purged down to zero rows), with `FRESH_DATA_REQUIRED`; an empty 3.4 library
/// migrates. Postgres twin: `pg_tests::t134_roles_migration_refuses_a_filled_library`.
#[tokio::test]
async fn t134_roles_migration_refuses_a_filled_library() {
    for case in ["account", "chain_head", "empty"] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DbConfig {
            path: dir.path().join("r.sqlite"),
        };
        let old = SqliteDb::open_at_version(&cfg, 3).await.unwrap();
        match case {
            "account" => {
                sqlx::query(
                    "INSERT INTO account (username, password_hash, created_at, password_changed_at, role) \
                     VALUES ('alice', 'x', 1, 1, 'admin')",
                )
                .execute(old.writer())
                .await
                .unwrap();
            }
            "chain_head" => {
                sqlx::query("UPDATE audit_chain_state SET head_hash = randomblob(32), floor_hash = randomblob(32)")
                    .execute(old.writer())
                    .await
                    .unwrap();
            }
            _ => {}
        }
        old.close().await;
        let r = SqliteDb::open(&cfg).await;
        if case == "empty" {
            let db = r.unwrap();
            db.close().await;
        } else {
            let Err(e) = r else {
                unreachable!("{case}: a filled library must be refused")
            };
            assert!(e.to_string().contains("FRESH_DATA_REQUIRED"), "{case}: {e}");
        }
    }
}
