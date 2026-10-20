//! `restore-finish` post-restore hygiene (T107; SEC-036, SEC-065, SEC-068, SEC-069).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crate::acct_testkit::{Env, T0, env, sess};
use crate::{DbConfig, RESTORE_FINISH_EVENT, SessionStage, SqliteDb};

/// Fills every table the command touches, plus one key per owner.
async fn populate(e: &Env) -> (i64, i64) {
    let admin = e.admin("root").await;
    let uploader = e.uploader("mem").await;
    let (_k1, _) = e.key(admin, 1).await;
    let (_k2, _) = e.key(uploader, 2).await;
    let w = e.db.writer();
    sqlx::query(
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, \
         expires_at) VALUES (?1, ?2, 'active', ?3, 1, 1, 9999999999)",
    )
    .bind(
        sess(uploader, 7, SessionStage::Active, T0)
            .id_hash
            .as_slice(),
    )
    .bind(uploader)
    .bind([9u8; 32].as_slice())
    .execute(w)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, \
         expires_at) VALUES ('invite', ?1, 'newbie', 'viewer', 'cli', 1, 100)",
    )
    .bind([5u8; 32].as_slice())
    .execute(w)
    .await
    .unwrap();
    sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, randomblob(32))")
        .bind(uploader)
        .execute(w)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO login_lock (account_id, ip_key, failures, last_failure) VALUES (?1, '1.2.3.4', 3, 1)",
    )
    .bind(uploader)
    .execute(w)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO account_throttle (account_id, hour_start, hour_failures, day_start, \
         day_mfa_failures) VALUES (?1, 1, 2, 1, 0)",
    )
    .bind(uploader)
    .execute(w)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_known_ip (account_id, ip_key, last_seen) VALUES (?1, '1.2.3.4', 1)",
    )
    .bind(uploader)
    .execute(w)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO credential_staging (account_id, session_hash, invite_id, password_hash, \
         created_at, expires_at) VALUES (?1, ?2, 1, 'x', 1, 100)",
    )
    .bind(uploader)
    .bind([9u8; 32].as_slice())
    .execute(w)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE account SET enroll_token_hash = ?1, enroll_token_expires = 99999 WHERE id = ?2",
    )
    .bind([4u8; 32].as_slice())
    .bind(uploader)
    .execute(w)
    .await
    .unwrap();
    (admin, uploader)
}

async fn total_rows(db: &SqliteDb) -> i64 {
    let mut n = 0;
    for t in [
        "session",
        "invite",
        "recovery_code",
        "login_lock",
        "account_throttle",
        "user_known_ip",
        "credential_staging",
    ] {
        let c: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
            .fetch_one(db.readers())
            .await
            .unwrap();
        n += c;
    }
    n
}

async fn active_keys(db: &SqliteDb) -> i64 {
    db.count_active_api_keys().await.unwrap()
}

async fn chain_ok(db: &SqliteDb) -> bool {
    db.audit_walk(None, &mut |_| {}).await.unwrap().is_ok()
}

#[tokio::test]
async fn sec_068_restore_finish_clears_credentials_and_revokes_every_key_in_one_audit_row() {
    let e = env().await;
    let (admin, uploader) = populate(&e).await;
    assert_eq!(total_rows(&e.db).await, 7);
    let rep = e.db.restore_finish(T0 + 10, false).await.unwrap();
    assert_eq!(
        (
            rep.sessions,
            rep.credential_staging,
            rep.open_invites,
            rep.recovery_codes,
            rep.login_locks,
            rep.account_throttles,
            rep.known_ips,
            rep.enroll_tokens,
            rep.api_keys_revoked
        ),
        (1, 1, 1, 1, 1, 1, 1, 1, 2)
    );
    assert_eq!(total_rows(&e.db).await, 0);
    assert_eq!(active_keys(&e.db).await, 0);
    // A pre-snapshot enrollment token must not come back to life (T107 review M1).
    assert_eq!(
        e.count(
            "account",
            "enroll_token_hash IS NOT NULL OR enroll_token_expires IS NOT NULL"
        )
        .await,
        0
    );
    let by: Vec<Option<i64>> = sqlx::query_scalar("SELECT revoked_by FROM api_key")
        .fetch_all(e.db.readers())
        .await
        .unwrap();
    assert_eq!(by, vec![None, None]);
    // Exactly one `cli` row, counts only.
    let rows = e.audit(RESTORE_FINISH_EVENT).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("cli"));
    let d = rows[0].detail.clone().unwrap();
    assert!(
        d.contains("api_keys_revoked=2") && d.contains("sessions=1"),
        "{d}"
    );
    assert!(chain_ok(&e.db).await, "the chain verifies afterwards");
    // Accounts are untouched and listed.
    let accts = e.db.restore_finish_accounts().await.unwrap();
    assert_eq!(accts.len(), 2);
    assert_eq!((accts[0].id, accts[0].role.as_str()), (admin, "admin"));
    assert_eq!(
        (accts[1].id, accts[1].role.as_str()),
        (uploader, "uploader")
    );
    assert!(!accts[1].disabled && !accts[1].deleted);
}

#[tokio::test]
async fn sec_068_restore_finish_is_idempotent() {
    let e = env().await;
    populate(&e).await;
    e.db.restore_finish(T0 + 10, false).await.unwrap();
    let again = e.db.restore_finish(T0 + 20, false).await.unwrap();
    assert_eq!(again, crate::RestoreFinishReport::default());
    assert_eq!(total_rows(&e.db).await, 0);
    assert_eq!(active_keys(&e.db).await, 0);
    // The first revocation time is kept (never re-stamped).
    let ts: Vec<i64> = sqlx::query_scalar("SELECT revoked_at FROM api_key")
        .fetch_all(e.db.readers())
        .await
        .unwrap();
    assert!(ts.iter().all(|t| *t == T0 + 10));
    assert!(chain_ok(&e.db).await);
}

#[tokio::test]
async fn sec_068_restore_finish_dry_run_changes_nothing() {
    let e = env().await;
    populate(&e).await;
    let audit_before = e.count("audit_log", "1=1").await;
    let rep = e.db.restore_finish(T0 + 10, true).await.unwrap();
    assert_eq!(
        (rep.sessions, rep.api_keys_revoked, rep.open_invites),
        (1, 2, 1)
    );
    assert_eq!(total_rows(&e.db).await, 7);
    assert_eq!(active_keys(&e.db).await, 2);
    assert_eq!(e.count("audit_log", "1=1").await, audit_before);
}

#[tokio::test]
async fn sec_068_a_failure_midway_rolls_back_everything() {
    let e = env().await;
    populate(&e).await;
    sqlx::query(
        "CREATE TRIGGER inject BEFORE UPDATE ON api_key BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .execute(e.db.writer())
    .await
    .unwrap();
    assert!(e.db.restore_finish(T0 + 10, false).await.is_err());
    assert_eq!(total_rows(&e.db).await, 7, "deletes rolled back");
    assert_eq!(e.audit(RESTORE_FINISH_EVENT).await.len(), 0);
}

#[tokio::test]
async fn sec_068_restoring_an_older_backup_then_finishing_keeps_a_revoked_key_revoked() {
    let e = env().await;
    let admin = e.admin("root").await;
    let uploader = e.uploader("mem").await;
    let (key, hash) = e.key(uploader, 4).await;
    // Snapshot while the key is still valid.
    let backups = e.dir.path().join("backups");
    std::fs::create_dir(&backups).unwrap();
    let snap = e.db.backup(&backups, T0, 3).await.unwrap();
    // Later the operator revokes the leaked key and disables the account on the live file.
    assert!(
        e.db.revoke_api_key(
            key,
            T0 + 100,
            crate::Actor {
                name: "cli",
                ip: None,
            },
        )
        .await
        .unwrap()
    );
    assert!(e.db.find_api_key(&hash).await.unwrap().unwrap().revoked);
    let _ = admin;
    // The disk fails; the old snapshot becomes the database.
    let restored = SqliteDb::open(&DbConfig {
        path: snap.path.clone(),
    })
    .await
    .unwrap();
    assert!(
        !restored.find_api_key(&hash).await.unwrap().unwrap().revoked,
        "the restore silently un-revoked it (the very problem)"
    );
    restored.restore_finish(T0 + 200, false).await.unwrap();
    assert!(restored.find_api_key(&hash).await.unwrap().unwrap().revoked);
    assert!(chain_ok(&restored).await);
}

/// This is the mark consumed by nzbd's open/admit gates; their file-copy integration test lives in library.rs.
#[tokio::test]
async fn sec_068_serve_refuses_a_restored_database_until_restore_finish() {
    let e = env().await;
    e.admin("root").await;
    let uploader = e.uploader("mem").await;
    let (_, hash) = e.key(uploader, 4).await;
    assert!(!e.db.restore_pending().await.unwrap());
    let backups = e.dir.path().join("backups");
    std::fs::create_dir(&backups).unwrap();
    let snap = e.db.backup(&backups, T0, 3).await.unwrap();
    let restored = SqliteDb::open(&DbConfig { path: snap.path }).await.unwrap();
    assert!(restored.restore_pending().await.unwrap());
    restored.restore_finish(T0 + 1, true).await.unwrap();
    assert!(
        restored.restore_pending().await.unwrap(),
        "a dry run cannot admit restored credentials"
    );
    assert!(!restored.find_api_key(&hash).await.unwrap().unwrap().revoked);
    restored.restore_finish(T0 + 2, false).await.unwrap();
    assert!(!restored.restore_pending().await.unwrap());
    assert!(restored.find_api_key(&hash).await.unwrap().unwrap().revoked);
}

#[tokio::test]
async fn sec_068_restore_finish_rotates_the_index_epoch() {
    let e = env().await;
    let before = e.db.search_epoch().await.unwrap();
    assert_eq!(before.len(), 16);
    e.db.restore_finish(T0 + 1, true).await.unwrap();
    assert_eq!(
        e.db.search_epoch().await.unwrap(),
        before,
        "a dry run rotates nothing"
    );
    e.db.restore_finish(T0 + 2, false).await.unwrap();
    let after = e.db.search_epoch().await.unwrap();
    assert_ne!(after, before);
    e.db.restore_finish(T0 + 3, false).await.unwrap();
    assert_ne!(
        e.db.search_epoch().await.unwrap(),
        after,
        "every run rotates"
    );
}
