//! v3 snapshot backup, restore and restore detection (T112; SEC-044, SEC-052, SEC-094).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::many_single_char_names
)]

use std::os::unix::fs::PermissionsExt as _;

use crate::pg::testing::{TEST_APP_PASSWORD, TEST_OWNER_PASSWORD, TestDb};
use crate::pg::{
    AnchorVerdict, PgDb, Readiness, RestoreOptions, read_anchor, restore_snapshot, write_anchor,
};
use crate::pg_testkit::{Env, T0, env, sess};
use crate::{BackupKey, SessionStage, Uploader};

/// Accounts, a key, releases, sessions, staging, throttle rows, open and closed invites, audit rows.
async fn populate(e: &Env) -> (i64, i64) {
    let admin = e.admin("root").await;
    let uploader = e.uploader("mem").await;
    e.key(uploader, 3).await;
    // Private per account (T127): exported and restored like the preferences.
    e.db.create_saved_search(uploader, "Mine", r#"{"q":"show"}"#, T0)
        .await
        .unwrap();
    let mut first = None;
    for n in 1..=5 {
        let id = e.release(n, &Uploader::Account(uploader)).await.unwrap();
        first.get_or_insert(id);
    }
    // The NFO of a release (T140), keyed by digest.
    if let Some(id) = first {
        let sha: Vec<u8> = sqlx::query_scalar("SELECT sha256 FROM release WHERE id = $1")
            .bind(id)
            .fetch_one(e.db.web())
            .await
            .unwrap();
        let sha = nzb_core::Sha256(<[u8; 32]>::try_from(sha.as_slice()).unwrap());
        e.db.attach_nfo_as(
            &Uploader::Account(uploader),
            id,
            &sha,
            b"\xdb\xb0 nfo",
            T0,
            None,
        )
        .await
        .unwrap();
    }
    e.db.insert_session(&sess(uploader, 7, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let w = e.db.web();
    for sql in [
        "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, expires_at) \
         VALUES ('invite', sha256('open'::bytea), 'newbie', 'viewer', 'cli', 1, 100)",
        "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, expires_at, revoked_at) \
         VALUES ('invite', sha256('closed'::bytea), 'gone', 'viewer', 'cli', 1, 100, 50)",
        "INSERT INTO login_lock (account_id, ip_key, failures, last_failure) VALUES (2, '1.2.3.4', 3, 1)",
        "INSERT INTO account_throttle (account_id, hour_start, hour_failures, day_start, day_mfa_failures) \
         VALUES (2, 1, 2, 1, 0)",
        "INSERT INTO user_known_ip (account_id, ip_key, last_seen) VALUES (2, '1.2.3.4', 1)",
        "INSERT INTO recovery_code (account_id, code_hash) VALUES (2, sha256('rc'::bytea))",
    ] {
        sqlx::query(sql).execute(w).await.unwrap();
    }
    e.db.audit_event(T0, Some("cli"), "user.create", Some("x"), None)
        .await
        .unwrap();
    (admin, uploader)
}

// Callers supply count queries over literal fixture tables, never application input.
async fn n(db: &PgDb, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(db.web())
        .await
        .unwrap()
}

fn key() -> BackupKey {
    BackupKey::from_slice(&[7; 32]).unwrap()
}

#[tokio::test]
async fn overlapping_snapshot_backups_preserve_the_active_file_and_cancel_cleanly() {
    use std::os::unix::fs::MetadataExt as _;
    use std::time::Duration;

    let e = env().await;
    e.admin("root").await;
    let dir = tempfile::tempdir().unwrap();
    // Exhaust the pool so the actual backup stops at begin().await, with its directory
    // lock and temporary file already owned. No large database or timing race is needed.
    let mut held = Vec::new();
    for _ in 0..e.db.background().options().get_max_connections() {
        held.push(e.db.background().acquire().await.unwrap());
    }
    let db = e.db.clone();
    let destination = dir.path().to_path_buf();
    let running = tokio::spawn(async move { db.snapshot_backup(&destination, T0, 3, None).await });
    let name = crate::pg::snapshot_name(T0);
    let active = dir.path().join(format!(".{name}.tmp"));
    let published = dir.path().join(&name);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !active.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let before = std::fs::metadata(&active).unwrap();
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        e.db.snapshot_backup(dir.path(), T0, 3, None),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(err, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(std::fs::metadata(&active).unwrap().ino(), before.ino());
    assert!(!published.exists());

    // Unlike SQLite's detached VACUUM worker, Postgres writes this file in the cancelled
    // future itself: cancellation must release its lock and must not publish a partial file.
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    assert!(!published.exists());
    let probe = std::fs::File::open(dir.path()).unwrap();
    probe.try_lock().unwrap();
    drop(probe);
    drop(held);

    // The next real backup cleans the abandoned temporary file and remains restorable.
    let rep = tokio::time::timeout(
        Duration::from_secs(10),
        e.db.snapshot_backup(dir.path(), T0, 3, None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rep.path, published);
    assert!(!active.exists());
    let target = TestDb::new().await;
    let restored = restore_snapshot(
        target.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions::default(),
        T0 + 1,
    )
    .await
    .unwrap();
    assert!(restored.audit_chain_ok);
    assert_eq!(restored.tables, rep.tables);
    assert_eq!(n(&target.db, "SELECT count(*) FROM account").await, 1);
}

#[tokio::test]
async fn sec_094_encrypted_restore_recovers_the_actual_decryption_temporary_file() {
    let e = env().await;
    e.admin("root").await;
    let dir = tempfile::tempdir().unwrap();
    let key = key();
    let rep =
        e.db.snapshot_backup(dir.path(), T0, 3, Some(&key))
            .await
            .unwrap();
    // decrypt_file prefixes the output name with a dot. The restore output itself starts
    // with a dot, so a kill during decryption leaves this double-dot temporary name.
    let stale = dir.path().join("..nzbd-restore.plain.tmp.decrypt.tmp");
    std::fs::write(
        &stale,
        b"authenticated partial plaintext from an interrupted restore",
    )
    .unwrap();
    let target = TestDb::new().await;
    let restored = restore_snapshot(
        target.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions {
            key: Some(&key),
            allow_unencrypted: false,
        },
        T0 + 1,
    )
    .await
    .unwrap();
    assert!(restored.audit_chain_ok);
    assert_eq!(restored.tables, rep.tables);
    assert_eq!(n(&target.db, "SELECT count(*) FROM account").await, 1);
    assert!(!stale.exists());
    assert!(!dir.path().join(".nzbd-restore.plain.tmp").exists());
}

#[tokio::test]
async fn snapshot_round_trip_restores_everything_that_is_exported() {
    let e = env().await;
    let (_admin, uploader) = populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let rep =
        e.db.snapshot_backup(dir.path(), T0 + 10, 3, None)
            .await
            .unwrap();
    let names: Vec<&str> = rep.tables.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names[0], "account");
    let target = TestDb::new().await;
    let r = restore_snapshot(
        target.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions::default(),
        T0 + 20,
    )
    .await
    .unwrap();
    assert!(r.audit_chain_ok);
    assert_eq!(r.tables, rep.tables);
    let t = &target.db;
    for sql in [
        "SELECT count(*) FROM account",
        "SELECT count(*) FROM api_key",
        "SELECT count(*) FROM release",
        "SELECT count(*) FROM nzb_file",
        "SELECT count(*) FROM audit_log",
        "SELECT count(*) FROM saved_search",
        "SELECT count(*) FROM release_nfo",
    ] {
        assert_eq!(n(t, sql).await, n(&e.db, sql).await, "{sql}");
    }
    assert_eq!(
        t.saved_searches(uploader).await.unwrap(),
        e.db.saved_searches(uploader).await.unwrap()
    );
    let nfo_digest =
        "SELECT md5(string_agg(sha256::text || bytes::text, ',' ORDER BY sha256)) FROM release_nfo";
    let a: Option<String> = sqlx::query_scalar(nfo_digest)
        .fetch_one(t.web())
        .await
        .unwrap();
    let b: Option<String> = sqlx::query_scalar(nfo_digest)
        .fetch_one(e.db.web())
        .await
        .unwrap();
    assert!(a.is_some());
    assert_eq!(a, b);
    // Content equality of the library and the chain.
    let digest = "SELECT md5(string_agg(sha256::text || title || category_id::text, ',' ORDER BY id)) FROM release";
    let a: String = sqlx::query_scalar(digest)
        .fetch_one(e.db.web())
        .await
        .unwrap();
    let b: String = sqlx::query_scalar(digest).fetch_one(t.web()).await.unwrap();
    assert_eq!(a, b);
    assert_eq!(
        e.db.audit_anchor().await.unwrap(),
        t.audit_anchor().await.unwrap()
    );
    // Totals were rebuilt exactly, and the identities continue above the restored ids.
    assert_eq!(
        e.db.release_totals().await.unwrap(),
        t.release_totals().await.unwrap()
    );
    // Restored but not servable until restore-finish (SEC-094).
    assert_eq!(t.readiness().await.unwrap(), Readiness::RestorePending);
    t.restore_finish(T0 + 30, false).await.unwrap();
    assert_eq!(t.readiness().await.unwrap(), Readiness::Ready);
    let a2 = crate::pg_release_tests::analysis(200, "after restore", 1, None);
    let id = t
        .insert_release(&crate::pg_release_tests::new(&a2))
        .await
        .unwrap();
    assert!(id > n(&e.db, "SELECT max(id) FROM release").await);
    let _ = uploader;
}

#[tokio::test]
async fn sec_094_backup_contains_no_role_passwords_or_key_files() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let rep = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    let bytes = std::fs::read(&rep.path).unwrap();
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    for secret in [
        TEST_APP_PASSWORD.as_bytes(),
        TEST_OWNER_PASSWORD.as_bytes(),
        b"SCRAM-SHA-256",
    ] {
        assert!(!contains(secret), "{}", String::from_utf8_lossy(secret));
    }
    // The backup key itself never goes into a backup, sealed or not.
    let sealed =
        e.db.snapshot_backup(dir.path(), T0 + 1, 3, Some(&key()))
            .await
            .unwrap();
    assert!(crate::looks_encrypted(&sealed.path));
    let sealed_bytes = std::fs::read(&sealed.path).unwrap();
    assert!(!sealed_bytes.windows(32).any(|w| w == [7_u8; 32]));
    // Session ids, CSRF tokens and the staged password of the populated rows are not in it either.
    assert!(!contains(&[7_u8; 32]), "session id hash");
}

#[tokio::test]
async fn sec_094_backup_omits_sessions_and_throttle_state() {
    let e = env().await;
    populate(&e).await;
    assert_eq!(n(&e.db, "SELECT count(*) FROM session").await, 1);
    let dir = tempfile::tempdir().unwrap();
    let rep = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    let target = TestDb::new().await;
    restore_snapshot(
        target.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions::default(),
        T0,
    )
    .await
    .unwrap();
    for table in [
        "session",
        "credential_staging",
        "login_lock",
        "account_throttle",
        "user_known_ip",
        "recovery_code",
    ] {
        assert_eq!(
            n(&target.db, &format!("SELECT count(*) FROM {table}")).await,
            0,
            "{table}"
        );
    }
    // Only the closed invitation is carried; the open one (a usable code) is not.
    let kept: Vec<String> = sqlx::query_scalar("SELECT username FROM invite")
        .fetch_all(target.db.web())
        .await
        .unwrap();
    assert_eq!(kept, ["gone"]);
}

#[tokio::test]
async fn sec_094_restore_requires_an_empty_schema_and_matching_version() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let rep = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    // Into the populated source itself: refused, nothing changes.
    let err = restore_snapshot(
        e.t.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions::default(),
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("empty database"), "{err}");
    assert_eq!(e.db.readiness().await.unwrap(), Readiness::Ready);
    // Into a database at another migration version: refused.
    let target = TestDb::new().await;
    let mut su = target.superuser_conn().await;
    sqlx::query(
        "INSERT INTO nzbd._sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (99999, 'future', true, '\\x00', 0)",
    )
    .execute(&mut su)
    .await
    .unwrap();
    let err = restore_snapshot(
        target.owner_options(),
        &rep.path,
        dir.path(),
        RestoreOptions::default(),
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("same schema version"), "{err}");
}

#[tokio::test]
async fn sec_094_interrupted_restore_is_never_servable() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let rep = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    for stop in [0_usize, 3, 6] {
        let target = TestDb::new().await;
        let err = crate::pg::restore_inner_for_tests(
            target.owner_options(),
            &rep.path,
            dir.path(),
            RestoreOptions::default(),
            T0,
            Some(stop),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("injected"), "{err}");
        // The mark of the first transaction stays; the data transaction left nothing behind.
        assert_eq!(
            target.db.readiness().await.unwrap(),
            Readiness::RestorePending
        );
        assert_eq!(n(&target.db, "SELECT count(*) FROM account").await, 0);
    }
}

#[tokio::test]
async fn sec_094_plaintext_restore_needs_explicit_flag_when_a_key_is_configured() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let plain = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    let k = key();
    let target = TestDb::new().await;
    let with_key = RestoreOptions {
        key: Some(&k),
        allow_unencrypted: false,
    };
    let err = restore_snapshot(
        target.owner_options(),
        &plain.path,
        dir.path(),
        with_key,
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("--allow-unencrypted"), "{err}");
    assert_eq!(
        target.db.readiness().await.unwrap(),
        Readiness::Ready,
        "nothing was marked"
    );
    let flagged = RestoreOptions {
        key: Some(&k),
        allow_unencrypted: true,
    };
    restore_snapshot(target.owner_options(), &plain.path, dir.path(), flagged, T0)
        .await
        .unwrap();
    // A sealed file restores with the key, and is refused with a wrong one.
    let sealed =
        e.db.snapshot_backup(dir.path(), T0 + 1, 3, Some(&k))
            .await
            .unwrap();
    let other = TestDb::new().await;
    let wrong = BackupKey::from_slice(&[8; 32]).unwrap();
    assert!(
        restore_snapshot(
            other.owner_options(),
            &sealed.path,
            dir.path(),
            RestoreOptions {
                key: Some(&wrong),
                allow_unencrypted: false
            },
            T0
        )
        .await
        .is_err()
    );
    restore_snapshot(
        other.owner_options(),
        &sealed.path,
        dir.path(),
        with_key,
        T0,
    )
    .await
    .unwrap();
    assert_eq!(n(&other.db, "SELECT count(*) FROM release").await, 5);
}

#[tokio::test]
async fn sec_094_tampered_backup_manifest_is_refused() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let rep = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    let orig = std::fs::read(&rep.path).unwrap();
    let tampered = dir.path().join("tampered.nzbdpg");
    // 1. One data byte flipped (inside the first table section).
    let mut b = orig.clone();
    b[40] ^= 0x01;
    std::fs::write(&tampered, &b).unwrap();
    // 2. The manifest's row count edited.
    let text = String::from_utf8_lossy(&orig).into_owned();
    let pos = text.find("\"rows\":").unwrap();
    let mut m = orig.clone();
    m[pos + 7] = if m[pos + 7] == b'9' { b'8' } else { b'9' };
    let tampered_m = dir.path().join("tampered-m.nzbdpg");
    std::fs::write(&tampered_m, &m).unwrap();
    // 3. Truncated.
    let truncated = dir.path().join("truncated.nzbdpg");
    std::fs::write(&truncated, &orig[..orig.len() - 20]).unwrap();
    for f in [&tampered, &tampered_m, &truncated] {
        let target = TestDb::new().await;
        let err = restore_snapshot(
            target.owner_options(),
            f,
            dir.path(),
            RestoreOptions::default(),
            T0,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("backup file"), "{err}");
        // Verified before anything was written: not even the restore mark.
        assert_eq!(target.db.readiness().await.unwrap(), Readiness::Ready);
        assert_eq!(n(&target.db, "SELECT count(*) FROM account").await, 0);
    }
}

#[tokio::test]
async fn sec_094_restore_detected_from_the_anchor() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let older = e.db.snapshot_backup(dir.path(), T0, 3, None).await.unwrap();
    // The live database moves on; serve rewrites its anchor.
    for n in 50..=52 {
        e.release(n, &Uploader::Unattributed).await.unwrap();
    }
    e.db.audit_event(T0 + 5, Some("cli"), "user.create", Some("later"), None)
        .await
        .unwrap();
    let anchor = e.db.capture_anchor().await.unwrap();
    let state = tempfile::tempdir().unwrap();
    let path = state.path().join("db-anchor.json");
    write_anchor(&path, &anchor).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let back = read_anchor(&path).unwrap().unwrap();
    assert_eq!(back, anchor);
    assert_eq!(
        e.db.check_anchor(&back).await.unwrap(),
        AnchorVerdict::Consistent
    );
    // An operator loads the older state with their own tools (here: our restore into a fresh database standing in
    // for a rolled-back volume): the anchor shows it, until restore-finish writes a new one.
    let rolled = TestDb::new().await;
    restore_snapshot(
        rolled.owner_options(),
        &older.path,
        dir.path(),
        RestoreOptions::default(),
        T0,
    )
    .await
    .unwrap();
    let v = rolled.db.check_anchor(&back).await.unwrap();
    assert_eq!(v.code(), Some("RESTORE_DETECTED"), "{v:?}");
    // A different, empty database is also never mistaken for the anchored one.
    let other = TestDb::new().await;
    assert_ne!(
        other.db.check_anchor(&back).await.unwrap(),
        AnchorVerdict::Consistent
    );
    assert!(
        read_anchor(&state.path().join("missing.json"))
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_044_backup_is_one_snapshot_under_concurrent_writes() {
    let e = env().await;
    populate(&e).await;
    let writer = {
        let db = e.db.clone();
        tokio::spawn(async move {
            for n in 100..=180_u8 {
                let a = crate::pg_release_tests::analysis(n, &format!("w{n}"), 7, None);
                db.insert_release(&crate::pg_release_tests::new(&a))
                    .await
                    .unwrap();
            }
        })
    };
    let dir = tempfile::tempdir().unwrap();
    let mut reports = Vec::new();
    for i in 0..3 {
        reports.push(
            e.db.snapshot_backup(dir.path(), T0 + i, 5, None)
                .await
                .unwrap(),
        );
    }
    writer.await.unwrap();
    for rep in reports {
        let target = TestDb::new().await;
        restore_snapshot(
            target.owner_options(),
            &rep.path,
            dir.path(),
            RestoreOptions::default(),
            T0,
        )
        .await
        .unwrap();
        // One snapshot: every release has exactly its file row, nothing half-exported.
        let t = &target.db;
        assert_eq!(
            n(t, "SELECT coalesce(sum(file_count), 0)::int8 FROM release").await,
            n(t, "SELECT count(*) FROM nzb_file").await
        );
        assert_eq!(
            n(t, "SELECT count(*) FROM release").await,
            i64::try_from(rep.tables.iter().find(|(n, _)| n == "release").unwrap().1).unwrap()
        );
    }
}

#[tokio::test]
async fn sec_044_backup_files_are_0600_and_rotated() {
    let e = env().await;
    populate(&e).await;
    let dir = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for i in 0..4 {
        let rep =
            e.db.snapshot_backup(dir.path(), T0 + i, 2, None)
                .await
                .unwrap();
        assert_eq!(
            std::fs::metadata(&rep.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        paths.push(rep.path);
    }
    // Keep 2: the two newest remain; foreign files are never touched.
    std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
    let rep =
        e.db.snapshot_backup(dir.path(), T0 + 10, 2, None)
            .await
            .unwrap();
    assert_eq!(rep.rotated, 1);
    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|d| d.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left.len(), 3, "{left:?}");
    assert!(left.contains(&"notes.txt".to_owned()));
    // A second backup in the same second never overwrites.
    assert!(
        e.db.snapshot_backup(dir.path(), T0 + 10, 2, None)
            .await
            .is_err()
    );
    let _ = paths;
}

/// Plain and encrypted snapshots must retain the latest database state after a clock correction.
pub(crate) async fn clock_rollback_retains_latest_backup(key: Option<&BackupKey>) {
    let source = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    for keep in [0_usize, 1, 2] {
        let backups = dir.path().join(format!("backups-{keep}"));
        std::fs::create_dir(&backups).unwrap();
        let older = source
            .db
            .snapshot_backup(&backups, T0 + 200, keep, key)
            .await
            .unwrap();
        let future = source
            .db
            .snapshot_backup(&backups, T0 + 300, keep, key)
            .await
            .unwrap();
        let marker = format!("latest-after-clock-rollback-{keep}");
        source
            .db
            .audit_event(T0, Some("cli"), "download", Some(&marker), None)
            .await
            .unwrap();
        let latest = source
            .db
            .snapshot_backup(&backups, T0, keep, key)
            .await
            .unwrap();
        assert!(
            latest.path.is_file(),
            "rotation deleted the just-published backup after clock rollback (keep={keep})"
        );
        assert_eq!(crate::looks_encrypted(&latest.path), key.is_some());
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), keep.max(1));
        assert_eq!(latest.rotated, 1);
        assert!(!older.path.exists());
        assert_eq!(future.path.exists(), keep == 2);

        // The returned snapshot alone contains the marker added after the future-dated files.
        let target = TestDb::new().await;
        let restored = restore_snapshot(
            target.owner_options(),
            &latest.path,
            dir.path(),
            RestoreOptions {
                key,
                allow_unencrypted: false,
            },
            T0 + 1,
        )
        .await
        .unwrap();
        assert!(restored.audit_chain_ok);
        assert_eq!(restored.tables, latest.tables);
        let detail: String =
            sqlx::query_scalar("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_one(target.db.web())
                .await
                .unwrap();
        assert_eq!(detail, marker);
    }
}

#[tokio::test]
async fn sec_044_clock_rollback_keeps_latest_plain_backup() {
    clock_rollback_retains_latest_backup(None).await;
}
