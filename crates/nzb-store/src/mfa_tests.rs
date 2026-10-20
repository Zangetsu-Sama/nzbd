//! MFA repository tests (TOTP replay floor, recovery single use, lock interplay).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::{
    DbConfig, FactorAttempt, NewSession, SecondFactor, SessionStage, SqliteDb, StoreError,
};

async fn open() -> (tempfile::TempDir, SqliteDb, i64) {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    let uid = db.create_user("alice", "hash", 10).await.unwrap();
    (dir, db, uid)
}

fn attempt(uid: i64, factor: SecondFactor, now: i64) -> FactorAttempt<'static> {
    FactorAttempt {
        user_id: uid,
        precondition_ok: true,
        factor,
        purpose: "login",
        ip: None,
        now,
    }
}

const TOKEN: [u8; 32] = [5; 32];

async fn enroll(db: &SqliteDb, uid: i64, step: i64, codes: &[[u8; 32]]) {
    assert!(db.set_enrollment_token(&TOKEN, 10_000, 50).await.unwrap());
    assert!(
        db.store_pending_totp(uid, b"sealed", false)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        db.confirm_totp_enrollment(uid, b"sealed", Some(TOKEN), Some(step), codes, None, 100)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_023_totp_step_is_accepted_once_and_older_steps_are_replays() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 10, &[]).await;
    // The enrollment code's own step (10) is already spent.
    for step in [10, 9, 1] {
        assert!(
            !db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(step)), 200))
                .await
                .unwrap()
        );
    }
    assert!(
        db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(11)), 200))
            .await
            .unwrap()
    );
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(11)), 200))
            .await
            .unwrap()
    );
    let st = db.get_mfa_state(uid).await.unwrap().unwrap();
    assert_eq!(st.totp_last_step, Some(11));
}

#[tokio::test]
async fn sec_023_concurrent_same_code_is_accepted_exactly_once() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 1, &[]).await;
    let mut hs = Vec::new();
    for _ in 0..8 {
        let db = db.clone();
        hs.push(tokio::spawn(async move {
            db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(5)), 300))
                .await
                .unwrap()
        }));
    }
    let mut ok = 0;
    for h in hs {
        ok += usize::from(h.await.unwrap());
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn sec_023_recovery_code_is_single_use_and_regeneration_invalidates_old() {
    let (_d, db, uid) = open().await;
    let (a, b) = ([1_u8; 32], [2_u8; 32]);
    enroll(&db, uid, 1, &[a, b]).await;
    assert_eq!(db.count_unused_recovery_codes(uid).await.unwrap(), 2);
    assert!(
        db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some(a)), 200))
            .await
            .unwrap()
    );
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some(a)), 201))
            .await
            .unwrap()
    );
    assert_eq!(db.count_unused_recovery_codes(uid).await.unwrap(), 1);
    db.insert_session(
        &NewSession {
            id_hash: [80; 32],
            user_id: uid,
            stage: SessionStage::Active,
            csrf_token: [9; 32],
            now: 202,
            expires_at: 10_000,
            ip: None,
            user_agent: None,
        },
        5,
    )
    .await
    .unwrap();
    db.replace_recovery_codes(uid, &[80; 32], &[[3; 32]], None, 202)
        .await
        .unwrap();
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some(b)), 203))
            .await
            .unwrap()
    );
    assert!(
        db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some([3; 32])), 204))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_026_wrong_factors_share_the_lockout_counter_and_a_lock_blocks_correct_codes() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 1, &[[9; 32]]).await;
    for _ in 0..5 {
        assert!(
            !db.second_factor_step(attempt(uid, SecondFactor::Totp(None), 500))
                .await
                .unwrap()
        );
    }
    // Locked now: even correct codes are refused and not consumed.
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(50)), 501))
            .await
            .unwrap()
    );
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some([9; 32])), 501))
            .await
            .unwrap()
    );
    assert_eq!(db.count_unused_recovery_codes(uid).await.unwrap(), 1);
    assert_eq!(
        db.get_mfa_state(uid).await.unwrap().unwrap().totp_last_step,
        Some(1)
    );
    // After the lock expires the correct code works.
    assert!(
        db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(50)), 600))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_023_enrollment_needs_a_pending_secret_and_a_matching_step() {
    let (_d, db, uid) = open().await;
    assert!(db.set_enrollment_token(&TOKEN, 10_000, 50).await.unwrap());
    // No pending secret: refused.
    assert!(
        !db.confirm_totp_enrollment(uid, b"one", Some(TOKEN), Some(3), &[], None, 100)
            .await
            .unwrap()
    );
    let first = db
        .store_pending_totp(uid, b"one", false)
        .await
        .unwrap()
        .unwrap();
    // A second page load keeps the first secret unless replacement is forced.
    let again = db
        .store_pending_totp(uid, b"two", false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, again);
    let forced = db
        .store_pending_totp(uid, b"two", true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(forced, b"two");
    assert!(
        !db.confirm_totp_enrollment(uid, b"two", Some(TOKEN), None, &[], None, 101)
            .await
            .unwrap()
    );
    assert!(
        db.confirm_totp_enrollment(uid, b"two", Some(TOKEN), Some(3), &[], None, 102)
            .await
            .unwrap()
    );
    // Enrolled: enrollment is closed and the secret cannot be swapped.
    assert!(
        db.store_pending_totp(uid, b"three", true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !db.confirm_totp_enrollment(uid, b"three", Some(TOKEN), Some(4), &[], None, 103)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_033_mfa_events_are_audited_without_secrets() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 1, &[[7; 32]]).await;
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Totp(None), 200))
            .await
            .unwrap()
    );
    assert!(
        db.second_factor_step(attempt(uid, SecondFactor::Recovery(Some([7; 32])), 201))
            .await
            .unwrap()
    );
    let rows = db.recent_audit(50).await.unwrap();
    let events: Vec<_> = rows.iter().map(|r| r.event.as_str()).collect();
    for e in ["mfa.enrolled", "mfa.fail", "mfa.recovery_used"] {
        assert!(events.contains(&e), "{e} missing in {events:?}");
    }
}

#[tokio::test]
async fn sec_023_enrollment_token_is_required_single_use_expiring_and_counted() {
    let (_d, db, uid) = open().await;
    // No token armed: nothing verifies, not even "no token".
    assert!(
        !db.check_enrollment_token(uid, Some(TOKEN), None, 60)
            .await
            .unwrap()
    );
    assert!(
        !db.check_enrollment_token(uid, None, None, 60)
            .await
            .unwrap()
    );
    assert!(db.set_enrollment_token(&TOKEN, 1000, 50).await.unwrap());
    assert!(
        !db.check_enrollment_token(uid, Some([6; 32]), None, 60)
            .await
            .unwrap()
    );
    assert!(
        db.check_enrollment_token(uid, Some(TOKEN), None, 60)
            .await
            .unwrap()
    );
    // Failures fed the shared lockout counter (3 so far); expiry is enforced.
    assert!(
        !db.check_enrollment_token(uid, Some(TOKEN), None, 1000)
            .await
            .unwrap()
    );
    // Confirmation needs the token as well, and consumes it.
    db.record_login_success(uid).await.unwrap();
    db.store_pending_totp(uid, b"blob", false)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !db.confirm_totp_enrollment(uid, b"blob", None, Some(9), &[], None, 70)
            .await
            .unwrap()
    );
    assert!(
        !db.confirm_totp_enrollment(uid, b"blob", Some([6; 32]), Some(9), &[], None, 71)
            .await
            .unwrap()
    );
    assert!(
        db.confirm_totp_enrollment(uid, b"blob", Some(TOKEN), Some(9), &[], None, 72)
            .await
            .unwrap()
    );
    assert!(
        !db.check_enrollment_token(uid, Some(TOKEN), None, 73)
            .await
            .unwrap(),
        "single use"
    );
    // Enrolled: arming is refused.
    assert!(!db.set_enrollment_token(&TOKEN, 5000, 80).await.unwrap());
}

#[tokio::test]
async fn sec_023_token_lock_blocks_the_correct_token() {
    let (_d, db, uid) = open().await;
    assert!(db.set_enrollment_token(&TOKEN, 10_000, 50).await.unwrap());
    for _ in 0..5 {
        assert!(
            !db.check_enrollment_token(uid, Some([1; 32]), None, 60)
                .await
                .unwrap()
        );
    }
    assert!(
        !db.check_enrollment_token(uid, Some(TOKEN), None, 61)
            .await
            .unwrap()
    );
    assert!(
        db.check_enrollment_token(uid, Some(TOKEN), None, 130)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_023_confirm_is_bound_to_the_secret_the_user_saw() {
    let (_d, db, uid) = open().await;
    assert!(db.set_enrollment_token(&TOKEN, 10_000, 50).await.unwrap());
    db.store_pending_totp(uid, b"seen", false)
        .await
        .unwrap()
        .unwrap();
    // The blob was swapped (forced replacement) after the user looked at "seen".
    db.store_pending_totp(uid, b"swapped", true)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !db.confirm_totp_enrollment(uid, b"seen", Some(TOKEN), Some(9), &[], None, 60)
            .await
            .unwrap()
    );
    let st = db.get_mfa_state(uid).await.unwrap().unwrap();
    assert!(!st.totp_enabled);
}

#[tokio::test]
async fn sec_023_replayed_own_code_in_reauth_is_refused_but_not_counted() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 10, &[]).await;
    let mut a = attempt(uid, SecondFactor::Totp(Some(10)), 200);
    a.purpose = "password_change";
    assert!(!db.second_factor_step(a).await.unwrap());
    assert!(!db.second_factor_step(a).await.unwrap());
    // Same replay at login still counts (a replayed sniffed code is an attack signal).
    for _ in 0..5 {
        assert!(
            !db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(10)), 201))
                .await
                .unwrap()
        );
    }
    assert!(
        !db.second_factor_step(attempt(uid, SecondFactor::Totp(Some(99)), 202))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_024_strict_rotation_refuses_a_vanished_pending_session() {
    use crate::{NewSession, SessionStage};
    let (_d, db, uid) = open().await;
    let mk = |n: u8, stage| NewSession {
        id_hash: [n; 32],
        user_id: uid,
        stage,
        csrf_token: [n; 32],
        now: 10,
        expires_at: 100,
        ip: None,
        user_agent: None,
    };
    db.insert_session(&mk(1, SessionStage::PendingMfa), 5)
        .await
        .unwrap();
    db.rotate_session_strict(&[1; 32], &mk(2, SessionStage::Active), 5)
        .await
        .unwrap();
    // The old id is gone: a second promotion creates nothing.
    let e = db
        .rotate_session_strict(&[1; 32], &mk(3, SessionStage::Active), 5)
        .await;
    assert!(matches!(e, Err(crate::StoreError::NotFound)));
    assert!(db.get_session(&[3; 32]).await.unwrap().is_none());
    assert!(db.get_session(&[2; 32]).await.unwrap().is_some());
}

#[tokio::test]
async fn recovery_code_regeneration_is_bound_to_the_reauthenticated_session() {
    let (_d, db, uid) = open().await;
    enroll(&db, uid, 1, &[[1; 32]]).await;
    // No live session: refused, and the old code keeps working.
    let r = db
        .replace_recovery_codes(uid, &[80; 32], &[[3; 32]], None, 150)
        .await;
    assert!(matches!(r, Err(StoreError::NotFound)));
    assert_eq!(db.count_unused_recovery_codes(uid).await.unwrap(), 1);
    db.insert_session(
        &NewSession {
            id_hash: [80; 32],
            user_id: uid,
            stage: SessionStage::Active,
            csrf_token: [9; 32],
            now: 150,
            expires_at: 10_000,
            ip: None,
            user_agent: None,
        },
        5,
    )
    .await
    .unwrap();
    db.replace_recovery_codes(uid, &[80; 32], &[[3; 32], [4; 32]], None, 151)
        .await
        .unwrap();
    assert_eq!(db.count_unused_recovery_codes(uid).await.unwrap(), 2);
}
