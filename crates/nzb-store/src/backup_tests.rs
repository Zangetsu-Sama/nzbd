//! Backup/maintenance tests: restore, permissions, rotation safety, purges (SEC-044).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::backup::{backup_file, backup_name, is_backup_name};
use crate::{DbConfig, SqliteDb};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

async fn open(dir: &tempfile::TempDir) -> SqliteDb {
    SqliteDb::open(&DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    })
    .await
    .unwrap()
}

#[test]
fn names_are_generated_and_recognised() {
    assert_eq!(backup_name(0), "nzbd-19700101T000000Z.sqlite");
    assert_eq!(backup_name(1_709_210_096), "nzbd-20240229T123456Z.sqlite");
    assert!(is_backup_name(&backup_name(1_700_000_000)));
    for bad in [
        "nzbd-20240229T123456Z.sqlite.bak",
        "nzbd-2024022T1234567Z.sqlite",
        "x-20240229T123456Z.sqlite",
        "nzbd-20240229X123456Z.sqlite",
        "nzbd-20240229T12345aZ.sqlite",
        "../nzbd-20240229T123456Z.sqlite",
        ".nzbd-20240229T123456Z.sqlite",
        "nzbd.sqlite",
    ] {
        assert!(!is_backup_name(bad), "{bad}");
    }
}

#[tokio::test]
async fn sec_044_backup_restores_opens_and_queries() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    sqlx::query("INSERT INTO audit_log (ts, event) VALUES (1, 'marker')")
        .execute(db.writer())
        .await
        .unwrap();
    // Saved searches are part of the file like every account table (T127).
    let uid = db
        .create_user("alice", crate::acct_testkit::PHC, 1)
        .await
        .unwrap();
    db.create_saved_search(uid, "Mine", r#"{"q":"x"}"#, 1)
        .await
        .unwrap();
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let rep = db.backup(&backups, 1_700_000_000, 14).await.unwrap();
    assert_eq!(rep.path.parent().unwrap(), backups);
    let mode = fs::metadata(&rep.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // No temp leftovers.
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 1);
    db.close().await;

    // Restore: copy to a fresh location and open through the normal bootstrap.
    let restored = dir.path().join("restored.sqlite");
    fs::copy(&rep.path, &restored).unwrap();
    let r = SqliteDb::open(&DbConfig { path: restored }).await.unwrap();
    r.integrity_check().await.unwrap();
    let ev: String = sqlx::query_scalar("SELECT event FROM audit_log")
        .fetch_one(r.readers())
        .await
        .unwrap();
    assert_eq!(ev, "marker");
    let saved = r.saved_searches(uid).await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "Mine");
}

#[tokio::test]
async fn backup_file_works_offline_and_rejects_missing_source() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).await.close().await;
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let rep = backup_file(&dir.path().join("nzbd.sqlite"), &backups, 5, 14)
        .await
        .unwrap();
    assert!(rep.path.ends_with("nzbd-19700101T000005Z.sqlite"));
    assert!(
        backup_file(&dir.path().join("nope.sqlite"), &backups, 6, 14)
            .await
            .is_err()
    );
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 1);
}

#[tokio::test]
async fn same_second_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    db.backup(&b, 100, 14).await.unwrap();
    assert!(db.backup(&b, 100, 14).await.is_err());
}

#[tokio::test]
async fn sec_044_rotation_keeps_newest_and_only_deletes_generated_names() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    let foreign = [
        "notes.txt",
        "nzbd-20240101T000000Z.sqlite.bak",
        "nzbd.sqlite",
    ];
    for f in foreign {
        fs::write(b.join(f), b"keep").unwrap();
    }
    // A directory with a matching name must be left alone.
    fs::create_dir(b.join("nzbd-20000101T000000Z.sqlite")).unwrap();
    let base = 1_700_000_000;
    let mut rotated = 0;
    for i in 0..5 {
        rotated += db.backup(&b, base + i * 60, 3).await.unwrap().rotated;
    }
    assert_eq!(rotated, 2);
    let mut kept: Vec<String> = fs::read_dir(&b)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.file_name().into_string().unwrap())
        .filter(|n| is_backup_name(n))
        .collect();
    kept.sort();
    assert_eq!(kept, [2, 3, 4].map(|i| backup_name(base + i * 60)).to_vec());
    for f in foreign {
        assert!(b.join(f).exists(), "{f}");
    }
    assert!(b.join("nzbd-20000101T000000Z.sqlite").is_dir());
}

#[tokio::test]
async fn stale_tmp_of_crashed_run_is_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let b = dir.path().join("b");
    fs::create_dir(&b).unwrap();
    // The exact tmp name the run itself will use, plus an unrelated dotfile.
    let stale = b.join(format!(".{}.tmp", backup_name(100)));
    fs::write(&stale, b"partial").unwrap();
    fs::write(b.join(".other.tmp"), b"x").unwrap();
    db.backup(&b, 100, 14).await.unwrap();
    assert!(!stale.exists());
    assert!(b.join(".other.tmp").exists());
}

#[tokio::test]
async fn overlapping_backups_refuse_before_removing_an_in_flight_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let b = dir.path().join("backups");
    fs::create_dir(&b).unwrap();
    let active = b.join(format!(".{}.tmp", backup_name(100)));
    let lock = fs::File::open(&b).unwrap();
    lock.try_lock().unwrap();
    fs::write(&active, b"snapshot in progress").unwrap();
    // Independent opens are the same locking contract as maintenance and a separate CLI process.
    let live = db.backup(&b, 101, 14).await.unwrap_err();
    assert!(matches!(live, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    let offline = backup_file(&dir.path().join("nzbd.sqlite"), &b, 102, 14)
        .await
        .unwrap_err();
    assert!(
        matches!(offline, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(fs::read(&active).unwrap(), b"snapshot in progress");
    assert_eq!(fs::read_dir(&b).unwrap().count(), 1);
    drop(lock);
    // A crashed process releases the OS lock, so the next run can clean its partial snapshot.
    let rep = db.backup(&b, 103, 14).await.unwrap();
    assert!(!active.exists());
    assert!(rep.path.is_file());
}

#[tokio::test]
async fn cancelling_a_backup_caller_keeps_the_snapshot_locked_until_the_worker_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let b = dir.path().join("backups");
    fs::create_dir(&b).unwrap();
    // Hold the worker's private connection so it really waits at VACUUM INTO.await, after its
    // temporary snapshot and directory lock exist. Backups no longer borrow request readers.
    let worker_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(db.readers().connect_options().as_ref().clone())
        .await
        .unwrap();
    let held = worker_pool.acquire().await.unwrap();
    let running_pool = worker_pool.clone();
    let running_dir = b.clone();
    let caller = tokio::spawn(async move {
        crate::backup::backup_with_pool_for_test(running_pool, running_dir, 200, 14).await
    });
    let active = b.join(format!(".{}.tmp", backup_name(200)));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !active.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let contender = tokio::time::timeout(std::time::Duration::from_secs(2), db.backup(&b, 201, 14))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(contender, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    let offline = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        backup_file(&dir.path().join("nzbd.sqlite"), &b, 202, 14),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(offline, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(
        active.exists(),
        "neither contender removed the active snapshot"
    );
    drop(held);
    let published = b.join(backup_name(200));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let probe = fs::File::open(&b).unwrap();
            if published.exists()
                && probe.try_lock().is_ok()
                && worker_pool.is_closed()
                && worker_pool.size() == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        worker_pool.is_closed(),
        "the detached worker closes its pool"
    );
    assert_eq!(worker_pool.size(), 0, "the private connection is released");
    assert!(!active.exists());
    let restored = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&published)
                .read_only(true),
        )
        .await
        .unwrap();
    let check: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&restored)
        .await
        .unwrap();
    assert_eq!(check, "ok");
    restored.close().await;
    assert!(db.backup(&b, 203, 14).await.unwrap().path.is_file());
}

#[tokio::test]
async fn failed_backup_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    assert!(db.backup(&dir.path().join("missing"), 1, 14).await.is_err());
}

#[tokio::test]
async fn purges_sessions_and_old_logs() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let w = db.writer();
    sqlx::query(
        "INSERT INTO account (id, username, password_hash, created_at, password_changed_at) \
         VALUES (1,'u','h',0,0)",
    )
    .execute(w)
    .await
    .unwrap();
    for (i, exp) in [(1_u8, 99_i64), (2, 100), (3, 101)] {
        sqlx::query(
            "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, expires_at) \
             VALUES (?1, 1, 'active', zeroblob(32), 0, 0, ?2)",
        )
        .bind(vec![i; 32])
        .bind(exp)
        .execute(w)
        .await
        .unwrap();
    }
    assert_eq!(db.purge_expired_sessions(100).await.unwrap(), 2);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM session")
        .fetch_one(w)
        .await
        .unwrap();
    assert_eq!(left, 1);

    let day = 86_400_i64;
    let now = 100 * day;
    for ts in [now - 31 * day, now - 30 * day, now - day] {
        sqlx::query("INSERT INTO audit_log (ts, event) VALUES (?1, 'e')")
            .bind(ts)
            .execute(w)
            .await
            .unwrap();
        sqlx::query("INSERT INTO ingest_log (ts, source, outcome) VALUES (?1, 'watch', 'ok')")
            .bind(ts)
            .execute(w)
            .await
            .unwrap();
    }
    assert_eq!(db.purge_old_logs(now, 0).await.unwrap().audit, 0);
    let r = db.purge_old_logs(now, 30).await.unwrap();
    assert_eq!((r.audit, r.ingest), (1, 1));
}

/// SEC-094 / review 35 L5, the SQLite counterpart of the Postgres test of the same name: the anchor names the
/// library's identity, sequences and audit heads; an older *plain file copy* put in place by the operator's own tools
/// (it carries no `restore_pending`, unlike an nzbd backup) is reported `RESTORE_DETECTED`; a legitimate purge of
/// old audit rows keeps the anchored heads verifiable (`Consistent`); a different library never passes.
#[tokio::test]
async fn sec_094_restore_detected_from_the_anchor() {
    use crate::{AnchorVerdict, read_anchor, write_anchor};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nzbd.sqlite");
    let db = SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap();
    let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(db.readers())
        .await
        .unwrap();
    for n in 1..=3_u8 {
        let a = crate::release_tests::analysis(n, &format!("r{n}"), 1, None);
        db.insert_release(&crate::release_tests::new(&a))
            .await
            .unwrap();
    }
    // Old class-0 rows (past the 90-day floor) and a recent one.
    for age in [400, 300, 200] {
        db.audit_event(now - age * 86_400, Some("cli"), "download", None, None)
            .await
            .unwrap();
    }
    // Everything in the main file before the copy (a plain `cp` of a live WAL database misses the `-wal`).
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(db.writer())
        .await
        .unwrap();
    db.close().await;
    let older = dir.path().join("older.sqlite");
    fs::copy(&path, &older).unwrap();
    // The live library moves on; serve rewrites its anchor.
    let db = SqliteDb::open(&DbConfig { path: path.clone() })
        .await
        .unwrap();
    for n in 50..=52_u8 {
        let a = crate::release_tests::analysis(n, &format!("r{n}"), 1, None);
        db.insert_release(&crate::release_tests::new(&a))
            .await
            .unwrap();
    }
    db.audit_event(now, Some("cli"), "user.create", Some("later"), None)
        .await
        .unwrap();
    let anchor = db.capture_anchor().await.unwrap();
    assert_eq!(anchor.backend, "sqlite");
    let state = tempfile::tempdir().unwrap();
    let file = state.path().join("db-anchor.json");
    write_anchor(&file, &anchor).unwrap();
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let back = read_anchor(&file).unwrap().unwrap();
    assert_eq!(back, anchor);
    assert_eq!(
        db.check_anchor(&back).await.unwrap(),
        AnchorVerdict::Consistent
    );
    // A legitimate purge removes old rows below the anchored heads: still consistent (the heads are still there).
    let purged = db.purge_logs().await.unwrap();
    assert!(purged.audit >= 3, "{purged:?}");
    assert_eq!(
        db.check_anchor(&back).await.unwrap(),
        AnchorVerdict::Consistent
    );
    db.close().await;
    // The operator copies the older file over the database (their own tools, no nzbd backup).
    let rolled = SqliteDb::open(&DbConfig { path: older }).await.unwrap();
    assert!(
        !rolled.restore_pending().await.unwrap(),
        "a plain copy carries no mark"
    );
    let v = rolled.check_anchor(&back).await.unwrap();
    assert_eq!(v.code(), Some("RESTORE_DETECTED"), "{v:?}");
    // Another library is never mistaken for the anchored one.
    let other = SqliteDb::open(&DbConfig {
        path: dir.path().join("other.sqlite"),
    })
    .await
    .unwrap();
    assert_eq!(
        other.check_anchor(&back).await.unwrap(),
        AnchorVerdict::LibraryMismatch
    );
}

/// Review 34 L2 (SQLite twin of `pg_backup_tests::sec_094_backup_omits_sessions_and_throttle_state`): the backup copy
/// holds no session, staged credential, open invitation, recovery code or throttle row, their bytes are not left in
/// freed pages (the test greps the raw and the decrypted file), closed invitations stay, and the copy is
/// restore-pending.
#[tokio::test]
async fn sec_094_backup_omits_sessions_and_throttle_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let w = db.writer();
    for q in [
        "INSERT INTO account (id, username, password_hash, created_at, password_changed_at) VALUES (1,'u','h',0,0)",
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, expires_at) \
         VALUES (x'7777777777777777777777777777777777777777777777777777777777777777', 1, 'pending_mfa', \
         CAST('CANARYCSRFTOKEN0123' AS BLOB), 0, 0, 9999999999)",
        "INSERT INTO invite (id, purpose, token_hash, username, role, created_via, created_at, expires_at) \
         VALUES (1, 'invite', x'5555555555555555555555555555555555555555555555555555555555555555', 'openinv', 'uploader', \
         'cli', 0, 1000)",
        "INSERT INTO invite (id, purpose, token_hash, username, role, created_via, created_at, expires_at, used_at, used_by) \
         VALUES (2, 'invite', x'6666666666666666666666666666666666666666666666666666666666666666', 'gone', 'uploader', \
         'cli', 0, 1000, 10, 1)",
        "INSERT INTO credential_staging (account_id, session_hash, invite_id, password_hash, created_at, expires_at) \
         VALUES (1, x'7777777777777777777777777777777777777777777777777777777777777777', 1, 'CANARYSTAGEDHASH', 0, 600)",
        "INSERT INTO recovery_code (account_id, code_hash) \
         VALUES (1, x'9999999999999999999999999999999999999999999999999999999999999999')",
        "INSERT INTO login_lock (account_id, ip_key, failures, last_failure) VALUES (1, 'CANARYLOCKIP', 3, 1)",
        "INSERT INTO account_throttle (account_id, hour_start, hour_failures, day_start, day_mfa_failures) \
         VALUES (1, 0, 4, 0, 1)",
        "INSERT INTO user_known_ip (account_id, ip_key, last_seen) VALUES (1, 'CANARYKNOWNIP', 1)",
    ] {
        sqlx::query(q).execute(w).await.unwrap();
    }
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let plain = db.backup(&backups, 1_700_000_000, 14).await.unwrap();
    let k = crate::BackupKey::from_slice(&[3; 32]).unwrap();
    let sealed = db
        .backup_with(&backups, 1_700_000_001, 14, Some(&k))
        .await
        .unwrap();
    db.close().await;
    let opened = dir.path().join("opened.sqlite");
    crate::decrypt_file(&k, &sealed.path, &opened).unwrap();
    let canaries: [&[u8]; 6] = [
        &[0x77; 32],
        &[0x55; 32],
        &[0x99; 32],
        b"CANARYCSRFTOKEN0123",
        b"CANARYSTAGEDHASH",
        b"CANARYLOCKIP",
    ];
    for file in [&plain.path, &opened] {
        let bytes = fs::read(file).unwrap();
        for c in canaries {
            assert!(
                !bytes.windows(c.len()).any(|x| x == c),
                "{} still holds {:?}",
                file.display(),
                String::from_utf8_lossy(c)
            );
        }
        assert!(!bytes.windows(13).any(|x| x == b"CANARYKNOWNIP"));
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::new().filename(file).read_only(true))
            .await
            .unwrap();
        for table in [
            "session",
            "credential_staging",
            "recovery_code",
            "login_lock",
            "account_throttle",
            "user_known_ip",
        ] {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        // Only the closed invitation is carried; the open one (a usable code) is not.
        let kept: Vec<String> = sqlx::query_scalar("SELECT username FROM invite")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(kept, ["gone"]);
        let pending: i64 = sqlx::query_scalar("SELECT restore_pending FROM db_state WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(pending, 1);
        pool.close().await;
    }
}

/// Plain and encrypted backups must retain the latest database state after a clock correction.
pub(crate) async fn clock_rollback_retains_latest_backup(key: Option<&crate::BackupKey>) {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let now = 1_700_000_000;
    for keep in [0_usize, 1, 2] {
        let backups = dir.path().join(format!("backups-{keep}"));
        fs::create_dir(&backups).unwrap();
        let older = db
            .backup_with(&backups, now + 200, keep, key)
            .await
            .unwrap();
        let future = db
            .backup_with(&backups, now + 300, keep, key)
            .await
            .unwrap();
        let marker = format!("latest-after-clock-rollback-{keep}");
        db.audit_event(now, Some("cli"), "download", Some(&marker), None)
            .await
            .unwrap();
        let latest = db.backup_with(&backups, now, keep, key).await.unwrap();
        assert!(
            latest.path.is_file(),
            "rotation deleted the just-published backup after clock rollback (keep={keep})"
        );
        assert_eq!(crate::looks_encrypted(&latest.path), key.is_some());
        assert_eq!(fs::read_dir(&backups).unwrap().count(), keep.max(1));
        assert_eq!(latest.rotated, 1);
        assert!(!older.path.exists());
        assert_eq!(future.path.exists(), keep == 2);

        // Restore the returned path, not an earlier surviving filename: only this snapshot has
        // the marker written after the future-dated backups.
        let restored = dir.path().join(format!("restored-{keep}.sqlite"));
        if let Some(key) = key {
            crate::decrypt_file(key, &latest.path, &restored).unwrap();
        } else {
            fs::copy(&latest.path, &restored).unwrap();
        }
        let restored = SqliteDb::open(&DbConfig { path: restored }).await.unwrap();
        restored.integrity_check().await.unwrap();
        let detail: String =
            sqlx::query_scalar("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_one(restored.readers())
                .await
                .unwrap();
        assert_eq!(detail, marker);
        restored.close().await;
    }
    db.close().await;
}

#[tokio::test]
async fn sec_044_clock_rollback_keeps_latest_plain_backup() {
    clock_rollback_retains_latest_backup(None).await;
}
