//! Session / throttle repository tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::{DbConfig, NewSession, SessionStage, SqliteDb, lock_secs_for};

async fn open() -> (tempfile::TempDir, SqliteDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    (dir, db)
}

fn sess(n: u8, user: i64, stage: SessionStage, now: i64) -> NewSession {
    NewSession {
        id_hash: [n; 32],
        user_id: user,
        stage,
        csrf_token: [n; 32],
        now,
        expires_at: now + 100,
        ip: None,
        user_agent: None,
    }
}

#[test]
fn sec_026_lock_schedule_doubles_and_caps() {
    assert_eq!(lock_secs_for(4), 0);
    assert_eq!(lock_secs_for(5), 60);
    assert_eq!(lock_secs_for(6), 120);
    assert_eq!(lock_secs_for(7), 240);
    assert_eq!(lock_secs_for(11), 3600);
    assert_eq!(lock_secs_for(1000), 3600);
    assert_eq!(lock_secs_for(i64::MAX), 3600);
}

#[tokio::test]
async fn sec_026_failures_lock_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = DbConfig {
        path: dir.path().join("t.sqlite"),
    };
    let db = SqliteDb::open(&cfg).await.unwrap();
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    for _ in 0..4 {
        assert_eq!(db.record_login_failure(uid, 1000).await.unwrap(), None);
    }
    assert_eq!(
        db.record_login_failure(uid, 1000).await.unwrap(),
        Some(1060)
    );
    assert_eq!(
        db.record_login_failure(uid, 2000).await.unwrap(),
        Some(2120)
    );
    db.close().await;
    let db = SqliteDb::open(&cfg).await.unwrap();
    let u = db.get_login_user("ALICE").await.unwrap().unwrap();
    assert_eq!((u.failed_logins, u.locked_until), (6, Some(2120)));
    db.record_login_success(uid).await.unwrap();
    let u = db.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert_eq!((u.failed_logins, u.locked_until), (0, None));
    assert!(format!("{u:?}").contains("REDACTED"));
}

#[tokio::test]
async fn sec_024_session_roundtrip_rotate_purge() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    db.insert_session(&sess(1, uid, SessionStage::PendingMfa, 10), 5)
        .await
        .unwrap();
    let row = db.get_session(&[1; 32]).await.unwrap().unwrap();
    assert_eq!(row.stage, SessionStage::PendingMfa);
    assert!(format!("{row:?}").contains("REDACTED"));
    db.rotate_session(&[1; 32], &sess(2, uid, SessionStage::Active, 20), 5)
        .await
        .unwrap();
    assert!(db.get_session(&[1; 32]).await.unwrap().is_none());
    assert!(db.get_session(&[2; 32]).await.unwrap().is_some());
    db.touch_session(&[2; 32], 50, 150).await.unwrap();
    assert_eq!(
        db.get_session(&[2; 32]).await.unwrap().unwrap().expires_at,
        150
    );
    // idle expiry purge, then absolute cutoff purge
    assert_eq!(db.purge_sessions(200, 0).await.unwrap(), 1);
    db.insert_session(&sess(3, uid, SessionStage::Active, 300), 5)
        .await
        .unwrap();
    assert_eq!(db.purge_sessions(301, 300).await.unwrap(), 1);
}

#[tokio::test]
async fn sec_024_expired_sessions_cannot_be_refreshed() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    db.insert_session(&sess(1, uid, SessionStage::Active, 10), 5)
        .await
        .unwrap();
    // The request began while authenticated, but its body completed at/after idle expiry.
    for now in [110, 111] {
        db.touch_session(&[1; 32], now, now + 100).await.unwrap();
        let row = db.get_session(&[1; 32]).await.unwrap().unwrap();
        assert_eq!(row.expires_at, 110);
        assert_eq!(row.last_seen_at, 10);
    }
    // A current session still slides normally.
    db.insert_session(&sess(2, uid, SessionStage::Active, 200), 5)
        .await
        .unwrap();
    db.touch_session(&[2; 32], 250, 350).await.unwrap();
    let row = db.get_session(&[2; 32]).await.unwrap().unwrap();
    assert_eq!((row.last_seen_at, row.expires_at), (250, 350));
}

#[tokio::test]
async fn sec_024_max_sessions_per_stage_evicts_oldest_and_pending_cannot_evict_active() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    for n in 0..6_u8 {
        db.insert_session(&sess(n, uid, SessionStage::Active, 10 + i64::from(n)), 5)
            .await
            .unwrap();
    }
    assert!(db.get_session(&[0; 32]).await.unwrap().is_none());
    assert!(db.get_session(&[1; 32]).await.unwrap().is_some());
    for n in 10..20_u8 {
        db.insert_session(
            &sess(n, uid, SessionStage::PendingMfa, 100 + i64::from(n)),
            5,
        )
        .await
        .unwrap();
    }
    for n in 1..6_u8 {
        assert!(db.get_session(&[n; 32]).await.unwrap().is_some(), "{n}");
    }
}

#[tokio::test]
async fn sec_026_concurrent_burst_cannot_slip_a_correct_password_past_the_lock() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    for _ in 0..4 {
        db.record_login_failure(uid, 1000).await.unwrap();
    }
    // Four wrong guesses and the correct password, all verified "in parallel" (their
    // verifications finished before any verdict): the verdicts serialise on the writer.
    let mut tasks = Vec::new();
    for verified in [false, false, false, false, true] {
        let db = db.clone();
        tasks.push(tokio::spawn(async move {
            db.login_password_step(Some(uid), verified, "bad_password", Some("192.0.2.1"), 1000)
                .await
                .unwrap()
        }));
    }
    let mut accepted = 0;
    for t in tasks {
        accepted += i32::from(t.await.unwrap());
    }
    // Whatever the interleaving, once the 5th failure engaged the lock the correct password
    // can no longer be accepted; it can only win if it ran before that failure (counter < 5).
    let u = db.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert!(u.locked_until.is_some(), "lock engaged");
    // Deterministic form: counter 4, the 5th failure first, then the correct password.
    let (_d2, db2) = open().await;
    let uid2 = db2.create_user("bob", "h", 1).await.unwrap();
    for _ in 0..4 {
        db2.record_login_failure(uid2, 1000).await.unwrap();
    }
    assert!(
        !db2.login_password_step(Some(uid2), false, "bad_password", None, 1000)
            .await
            .unwrap()
    );
    assert!(
        !db2.login_password_step(Some(uid2), true, "bad_password", None, 1000)
            .await
            .unwrap()
    );
    assert!(accepted <= 1);
    // The correct password after the lock has expired is accepted again.
    assert!(
        db2.login_password_step(Some(uid2), true, "bad_password", None, 1061)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_026_counter_decays_after_a_quiet_period() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    for _ in 0..8 {
        db.record_login_failure(uid, 1000).await.unwrap();
    }
    let u = db.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert_eq!(u.failed_logins, 8);
    // Within the window the counter keeps growing; after 24 h of quiet it starts over, so a
    // stray attempt gets no lock at all.
    let later = 1000 + crate::LOCKOUT_DECAY_SECS + 1;
    assert_eq!(db.record_login_failure(uid, later).await.unwrap(), None);
    let u = db.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert_eq!((u.failed_logins, u.locked_until), (1, None));
}

#[tokio::test]
async fn sec_026_every_password_step_branch_writes_one_audit_row() {
    let (_d, db) = open().await;
    let uid = db.create_user("alice", "h", 1).await.unwrap();
    let base = db.recent_audit(50).await.unwrap().len();
    assert!(
        db.login_password_step(Some(uid), true, "x", None, 10)
            .await
            .unwrap()
    );
    assert!(
        !db.login_password_step(Some(uid), false, "bad_password", None, 11)
            .await
            .unwrap()
    );
    assert!(
        !db.login_password_step(None, false, "bad_password", None, 12)
            .await
            .unwrap()
    );
    assert!(
        !db.login_password_step(None, true, "bad_password", None, 13)
            .await
            .unwrap()
    );
    let rows = db.recent_audit(10).await.unwrap();
    assert_eq!(rows.len() - base, 4);
    // The success did not touch the counter.
    let u = db.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert_eq!(u.failed_logins, 1);
}
