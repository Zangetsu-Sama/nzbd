//! Persisted login throttling: per-(account, address) locks, the aggregate, the daily second-factor
//! cap, known addresses and the pending-session cap (T101a; SEC-026, SEC-033, SEC-066, SEC-067).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::used_underscore_binding
)]

use crate::acct_testkit::{Env, T0, code, env, sess};
use crate::{
    AttemptContext, DbConfig, FactorAttempt, FailureKind, NewRecovery, Redemption, SecondFactor,
    SessionStage, SqliteDb,
};

fn ctx(ip: &str) -> AttemptContext<'_> {
    AttemptContext {
        ip_key: ip,
        session: None,
        bucket_refused: false,
    }
}

async fn wrong_password(e: &Env, user: i64, ip: &str, now: i64) -> bool {
    e.db.login_password_step_v2(
        e.db.get_login_user_by_id(user).await.unwrap().as_ref(),
        false,
        "bad_password",
        &ctx(ip),
        None,
        now,
    )
    .await
    .unwrap()
}

async fn right_password(e: &Env, user: i64, ip: &str, bucket_refused: bool, now: i64) -> bool {
    let c = AttemptContext {
        ip_key: ip,
        session: None,
        bucket_refused,
    };
    e.db.login_password_step_v2(
        e.db.get_login_user_by_id(user).await.unwrap().as_ref(),
        true,
        "bad_password",
        &c,
        None,
        now,
    )
    .await
    .unwrap()
}

fn attempt(
    user: i64,
    step: Option<i64>,
    purpose: &'static str,
    now: i64,
) -> FactorAttempt<'static> {
    FactorAttempt {
        user_id: user,
        precondition_ok: true,
        factor: SecondFactor::Totp(step),
        purpose,
        ip: None,
        now,
    }
}

/// admin + two enrolled uploaders.
async fn world() -> (Env, i64, i64, i64) {
    let e = env().await;
    let a = e.admin("root").await;
    let m1 = e.uploader("mem-one").await;
    let m2 = e.uploader("mem-two").await;
    for id in [a, m1, m2] {
        e.mfa(id).await;
    }
    (e, a, m1, m2)
}

#[tokio::test]
async fn sec_026_lockout_is_per_account_and_ip() {
    let (e, _a, m1, m2) = world().await;
    for i in 0..5 {
        assert!(!wrong_password(&e, m1, "192.0.2.1", T0 + i).await);
    }
    let st = e.db.throttle_state(m1, "192.0.2.1", T0 + 5).await.unwrap();
    assert!(st.hard_locked(T0 + 5));
    assert_eq!(st.hard_locked_until, Some(T0 + 4 + 60));
    // The lock refuses even the CORRECT password, but only for that address...
    assert!(!right_password(&e, m1, "192.0.2.1", false, T0 + 6).await);
    // ...another address of the same account is unaffected...
    assert!(right_password(&e, m1, "198.51.100.9", false, T0 + 6).await);
    // ...and so is another account from the locked address.
    assert!(right_password(&e, m2, "192.0.2.1", false, T0 + 6).await);
    // The lock ends by itself.
    assert!(right_password(&e, m1, "192.0.2.1", false, T0 + 4 + 61).await);
}

#[tokio::test]
async fn sec_066_lockout_does_not_cross_accounts() {
    let (e, _a, m1, m2) = world().await;
    for i in 0..5 {
        wrong_password(&e, m1, "192.0.2.1", T0 + i).await;
    }
    // A completed login of ANOTHER account from the same address changes nothing for the first.
    e.db.record_login_success_v2(m2, Some("192.0.2.1"), T0 + 6)
        .await
        .unwrap();
    assert!(
        e.db.throttle_state(m1, "192.0.2.1", T0 + 7)
            .await
            .unwrap()
            .hard_locked(T0 + 7)
    );
    // And the first account's failures never touched the second's counters.
    let st2 = e.db.throttle_state(m2, "192.0.2.1", T0 + 7).await.unwrap();
    assert_eq!((st2.hour_failures, st2.hard_locked_until), (0, None));
    assert_eq!(
        e.count("login_lock", &format!("account_id = {m2}")).await,
        0
    );
}

#[tokio::test]
async fn sec_066_one_ip_cannot_lock_account_from_other_ip() {
    let (e, _a, m1, _m2) = world().await;
    // The owner has logged in from home before.
    e.db.record_login_success_v2(m1, Some("203.0.113.5"), T0)
        .await
        .unwrap();
    // An attacker hammers the account from rotating addresses, tripping the aggregate and locks.
    for i in 0..40_i64 {
        let ip = format!("198.51.100.{}", i % 9);
        wrong_password(&e, m1, &ip, T0 + 10 + i).await;
    }
    let st =
        e.db.throttle_state(m1, "203.0.113.5", T0 + 60)
            .await
            .unwrap();
    assert!(st.aggregate_until.is_some(), "aggregate is tripped");
    assert!(!st.hard_locked(T0 + 60), "the owner's address has no lock");
    assert!(st.ip_known && !st.unknown_ip_throttled(T0 + 60));
    // The owner still gets in: correct password, bucket drained, from the known address.
    assert!(right_password(&e, m1, "203.0.113.5", true, T0 + 61).await);
    // The attacker's addresses are locked.
    assert!(
        e.db.throttle_state(m1, "198.51.100.0", T0 + 60)
            .await
            .unwrap()
            .hard_locked(T0 + 60)
    );
}

#[tokio::test]
async fn sec_066_admin_lock_is_capped() {
    let (e, a, m1, _m2) = world().await;
    for i in 0..20_i64 {
        e.db.record_failure(a, "192.0.2.1", FailureKind::Password, None, T0 + i)
            .await
            .unwrap();
        e.db.record_failure(m1, "192.0.2.1", FailureKind::Password, None, T0 + i)
            .await
            .unwrap();
    }
    let adm = e.db.throttle_state(a, "192.0.2.1", T0 + 20).await.unwrap();
    let mem = e.db.throttle_state(m1, "192.0.2.1", T0 + 20).await.unwrap();
    assert_eq!(
        adm.hard_locked_until,
        Some(T0 + 19 + 300),
        "admin cap: 5 minutes"
    );
    assert_eq!(
        mem.hard_locked_until,
        Some(T0 + 19 + 3600),
        "uploader cap: 1 hour"
    );
}

#[tokio::test]
async fn sec_066_unknown_ip_bucket_spares_known_ips() {
    let (e, _a, m1, _m2) = world().await;
    e.db.record_login_success_v2(m1, Some("203.0.113.5"), T0)
        .await
        .unwrap();
    for i in 0..25_i64 {
        e.db.record_failure(
            m1,
            &format!("192.0.2.{i}"),
            FailureKind::Password,
            None,
            T0 + 1 + i,
        )
        .await
        .unwrap();
    }
    let now = T0 + 40;
    let known = e.db.throttle_state(m1, "203.0.113.5", now).await.unwrap();
    let unknown = e.db.throttle_state(m1, "203.0.113.77", now).await.unwrap();
    assert!(!known.unknown_ip_throttled(now));
    assert!(unknown.unknown_ip_throttled(now));
    // The caller's bucket is what throttles unknown addresses: a correct password from an unknown
    // address is refused while the bucket is drained (accepted residual), and let through when the
    // bucket grants its one attempt per minute.
    assert!(!right_password(&e, m1, "203.0.113.77", true, now).await);
    assert!(right_password(&e, m1, "203.0.113.77", false, now + 60).await);
    // A known address is never refused by the aggregate.
    assert!(right_password(&e, m1, "203.0.113.5", true, now).await);
    // The refusal is audited (counted, one row per hour) and visible to health.
    assert_eq!(e.audit("account_throttled").await.len(), 1);
    assert_eq!(e.db.count_throttled_accounts(now).await.unwrap(), 1);
}

#[tokio::test]
async fn sec_066_aggregate_covers_second_factor_and_reauth_posts() {
    let (e, _a, m1, _m2) = world().await;
    // Four kinds of failed posts, each from its own address so the hard lock does not stop the count.
    for i in 0..5_i64 {
        wrong_password(&e, m1, "192.0.2.10", T0 + i).await;
    }
    for i in 0..5_i64 {
        let r =
            e.db.second_factor_step_v2(attempt(m1, None, "login", T0 + 10 + i), &ctx("192.0.2.11"))
                .await
                .unwrap();
        assert!(!r.accepted);
    }
    for i in 0..5_i64 {
        let r =
            e.db.second_factor_step_v2(
                attempt(m1, None, "password_change", T0 + 20 + i),
                &ctx("192.0.2.12"),
            )
            .await
            .unwrap();
        assert!(!r.accepted);
    }
    let st =
        e.db.throttle_state(m1, "192.0.2.99", T0 + 30)
            .await
            .unwrap();
    // 5 password + 5 second factor + 5 re-auth: the enrollment posts bring it to the limit.
    assert_eq!(st.hour_failures, 15);
    for i in 0..5_i64 {
        let ok = e
            .db
            .check_enrollment_token_v2(m1, Some([9; 32]), &ctx("192.0.2.13"), None, T0 + 30 + i)
            .await
            .unwrap();
        assert!(!ok);
    }
    let st =
        e.db.throttle_state(m1, "192.0.2.99", T0 + 40)
            .await
            .unwrap();
    assert_eq!(st.hour_failures, 20);
    assert!(st.aggregate_until.is_some());
    // 15 of them were second-factor class (not the password step): the daily counter says so.
    assert_eq!(st.day_mfa_failures, 15);
}

#[tokio::test]
async fn sec_066_aggregate_survives_restart() {
    let (e, _a, m1, _m2) = world().await;
    for i in 0..25_i64 {
        e.db.record_failure(
            m1,
            &format!("192.0.2.{i}"),
            FailureKind::SecondFactor,
            None,
            T0 + i,
        )
        .await
        .unwrap();
    }
    let before = e.db.throttle_state(m1, "192.0.2.3", T0 + 30).await.unwrap();
    assert!(before.aggregate_until.is_some() && before.hard_locked_until.is_none());
    e.db.close().await;
    let db = SqliteDb::open(&DbConfig {
        path: e.dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    let after = db.throttle_state(m1, "192.0.2.3", T0 + 30).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(db.count_throttled_accounts(T0 + 30).await.unwrap(), 1);
    // The window ends: after the throttle period nothing is in force.
    let later = db
        .throttle_state(m1, "192.0.2.3", T0 + 24 + 3601)
        .await
        .unwrap();
    assert!(!later.unknown_ip_throttled(T0 + 24 + 3601));
}

#[tokio::test]
async fn sec_066_unlock_clears_persisted_aggregate() {
    let (e, _a, m1, _m2) = world().await;
    for i in 0..25_i64 {
        e.db.record_failure(m1, "192.0.2.1", FailureKind::Password, None, T0 + i)
            .await
            .unwrap();
    }
    let st = e.db.throttle_state(m1, "192.0.2.1", T0 + 30).await.unwrap();
    assert!(st.aggregate_until.is_some() && st.hard_locked(T0 + 30));
    // `nzbd user unlock` runs in another process: it can only clear what is persisted.
    e.db.unlock_account_operator(m1, T0 + 31).await.unwrap();
    let st = e.db.throttle_state(m1, "192.0.2.1", T0 + 31).await.unwrap();
    assert_eq!(st.aggregate_until, None);
    assert_eq!(st.hard_locked_until, None);
    assert_eq!((st.hour_failures, st.day_mfa_failures), (0, 0));
    assert_eq!(e.db.count_throttled_accounts(T0 + 31).await.unwrap(), 0);
    let rows = e.audit("user_unlock").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("cli"));
}

#[tokio::test]
async fn sec_066_daily_second_factor_cap_refuses_unknown_addresses() {
    let (e, _a, m1, _m2) = world().await;
    e.db.record_login_success_v2(m1, Some("203.0.113.5"), T0)
        .await
        .unwrap();
    // 49 second-factor failures from rotating addresses: not yet.
    for i in 0..49_i64 {
        let fx =
            e.db.record_failure(
                m1,
                &format!("10.0.{}.{}", i / 200, i % 200),
                FailureKind::SecondFactor,
                None,
                T0 + 1 + i,
            )
            .await
            .unwrap();
        assert!(!fx.daily_tripped);
    }
    let now = T0 + 100;
    assert!(
        !e.db
            .throttle_state(m1, "10.9.9.9", now)
            .await
            .unwrap()
            .second_factor_refused(now)
    );
    // The 50th trips the cap: unknown addresses are refused for an hour, the counter is set back to 45.
    let fx =
        e.db.record_failure(m1, "10.0.9.9", FailureKind::SecondFactor, None, now)
            .await
            .unwrap();
    assert!(fx.daily_tripped);
    let st = e.db.throttle_state(m1, "10.7.7.7", now).await.unwrap();
    assert!(st.second_factor_refused(now));
    assert_eq!(st.day_mfa_failures, 45);
    assert_eq!(st.second_factor_refused_until, Some(now + 3600));
    // A CORRECT code from an unknown address is refused (answered like a wrong one)...
    let v =
        e.db.second_factor_step_v2(attempt(m1, Some(5_000), "login", now + 1), &ctx("10.7.7.7"))
            .await
            .unwrap();
    assert!(!v.accepted);
    // ...while the same code from a known address works.
    let v =
        e.db.second_factor_step_v2(
            attempt(m1, Some(5_000), "login", now + 2),
            &ctx("203.0.113.5"),
        )
        .await
        .unwrap();
    assert!(v.accepted);
    // R1: the completed login from the known address leaves the daily cap in force (it clears only
    // the hourly aggregate), so signing in does not refresh the guess budget.
    e.db.record_login_success_v2(m1, Some("203.0.113.5"), now + 3)
        .await
        .unwrap();
    let st = e.db.throttle_state(m1, "10.7.7.7", now + 3).await.unwrap();
    assert!(st.second_factor_refused(now + 3), "{st:?}");
    assert_eq!(st.day_mfa_failures, 45);
    assert_eq!(st.second_factor_refused_until, Some(now + 3600));
    assert_eq!(st.hour_failures, 0);
    // After the hour the unknown address may try again; five more failures trip it once more.
    let after = now + 3601;
    assert!(
        !e.db
            .throttle_state(m1, "10.7.7.7", after)
            .await
            .unwrap()
            .second_factor_refused(after)
    );
    for i in 0..4_i64 {
        let fx =
            e.db.record_failure(
                m1,
                &format!("10.1.0.{i}"),
                FailureKind::SecondFactor,
                None,
                after + i,
            )
            .await
            .unwrap();
        assert!(!fx.daily_tripped);
    }
    let fx =
        e.db.record_failure(m1, "10.1.0.9", FailureKind::SecondFactor, None, after + 10)
            .await
            .unwrap();
    assert!(fx.daily_tripped, "45 + 5 trips again");
    // The daily cap is cleared by `unlock`.
    e.db.unlock_account_operator(m1, after + 11).await.unwrap();
    assert!(
        !e.db
            .throttle_state(m1, "10.7.7.7", after + 11)
            .await
            .unwrap()
            .second_factor_refused(after + 11)
    );
}

#[tokio::test]
async fn sec_066_pending_session_dies_after_five_second_factor_failures() {
    let (e, _a, m1, _m2) = world().await;
    e.db.insert_session(&sess(m1, 70, SessionStage::PendingMfa, T0), 5)
        .await
        .unwrap();
    let hash = [70_u8; 32];
    let with_session = |ip: &'static str| AttemptContext {
        ip_key: ip,
        session: Some(&[70; 32]),
        bucket_refused: false,
    };
    // Four failures from four different addresses (no hard lock engaged anywhere).
    for (i, ip) in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
        .into_iter()
        .enumerate()
    {
        let v =
            e.db.second_factor_step_v2(
                attempt(m1, None, "login", T0 + i64::try_from(i).unwrap()),
                &with_session(ip),
            )
            .await
            .unwrap();
        assert!(!v.accepted && !v.session_killed);
    }
    assert!(e.db.get_session(&hash).await.unwrap().is_some());
    // The fifth destroys the session, from yet another address.
    let v =
        e.db.second_factor_step_v2(
            attempt(m1, None, "login", T0 + 5),
            &with_session("192.0.2.5"),
        )
        .await
        .unwrap();
    assert!(v.session_killed);
    assert!(e.db.get_session(&hash).await.unwrap().is_none());
    let rows = e.audit("session_pending_killed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].kind.as_deref(), rows[0].actor_id, rows[0].target_id),
        (Some("anonymous"), None, Some(m1))
    );
    // A staged recovery bound to the session dies with it.
    let act = e.actor(1).await;
    let h = code(5).hash();
    e.db.issue_recovery(
        &act,
        &NewRecovery {
            target_id: m1,
            code_hash: &h,
            ttl_secs: 3600,
        },
        None,
        T0 + 10,
    )
    .await
    .unwrap();
    let s = sess(0, 71, SessionStage::PendingMfa, T0 + 11);
    e.db.redeem_code_with_profile(
        &Redemption {
            code_hash: &h,
            password_hash: "new",
            session: &s,
            replacing: None,
        },
        &crate::RegistrationProfile {
            email: crate::acct_testkit::TEST_EMAIL,
            display_name: "Invitee_x",
        },
        crate::acct_testkit::POLICY,
        None,
        T0 + 11,
    )
    .await
    .unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    let ctx71 = |ip: &'static str| AttemptContext {
        ip_key: ip,
        session: Some(&[71; 32]),
        bucket_refused: false,
    };
    for (i, ip) in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        .into_iter()
        .enumerate()
    {
        e.db.second_factor_step_v2(
            attempt(m1, None, "login", T0 + 20 + i64::try_from(i).unwrap()),
            &ctx71(ip),
        )
        .await
        .unwrap();
    }
    assert!(e.db.get_session(&[71; 32]).await.unwrap().is_none());
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
}

#[tokio::test]
async fn sec_066_second_factor_guessing_is_bounded_across_ip_rotation() {
    let (e, _a, m1, _m2) = world().await;
    // One leaked password = one pending session = at most 5 code guesses, however many source
    // prefixes are rotated. A fresh password step is needed for every further 5.
    let mut guesses = 0;
    for round in 0..4_u8 {
        e.db.insert_session(
            &sess(
                m1,
                80 + round,
                SessionStage::PendingMfa,
                T0 + i64::from(round),
            ),
            5,
        )
        .await
        .unwrap();
        let hash = [80 + round; 32];
        for i in 0..20_u32 {
            if e.db.get_session(&hash).await.unwrap().is_none() {
                break;
            }
            let ip = format!("172.16.{round}.{i}");
            let c = AttemptContext {
                ip_key: &ip,
                session: Some(&hash),
                bucket_refused: false,
            };
            let v =
                e.db.second_factor_step_v2(
                    attempt(
                        m1,
                        None,
                        "login",
                        T0 + 100 * i64::from(round) + i64::from(i),
                    ),
                    &c,
                )
                .await
                .unwrap();
            assert!(!v.accepted);
            guesses += 1;
        }
        assert!(
            e.db.get_session(&hash).await.unwrap().is_none(),
            "round {round}: session destroyed"
        );
    }
    assert_eq!(guesses, 20, "5 guesses per session, 4 sessions");
    // And the per-account totals bound the whole run: the daily counter saw all of them.
    let st = e.db.throttle_state(m1, "1.2.3.4", T0 + 400).await.unwrap();
    assert!(st.day_mfa_failures >= 20 - 5);
}

#[tokio::test]
async fn sec_066_known_ip_is_recorded_only_after_second_factor() {
    let (e, _a, m1, _m2) = world().await;
    e.db.insert_session(&sess(m1, 90, SessionStage::PendingMfa, T0), 5)
        .await
        .unwrap();
    let c = AttemptContext {
        ip_key: "203.0.113.5",
        session: Some(&[90; 32]),
        bucket_refused: false,
    };
    // Password step ok, a pending session exists, a wrong second factor: no address is recorded.
    assert!(
        e.db.login_password_step_v2(
            e.db.get_login_user_by_id(m1).await.unwrap().as_ref(),
            true,
            "x",
            &c,
            None,
            T0 + 1
        )
        .await
        .unwrap()
    );
    assert_eq!(e.count("user_known_ip", "1=1").await, 0);
    let v =
        e.db.second_factor_step_v2(attempt(m1, None, "login", T0 + 2), &c)
            .await
            .unwrap();
    assert!(!v.accepted);
    assert_eq!(e.count("user_known_ip", "1=1").await, 0);
    // The accepted second factor itself does not write either: the completed-login call does, in the
    // transaction that clears the failure counters.
    let v =
        e.db.second_factor_step_v2(attempt(m1, Some(7_000), "login", T0 + 3), &c)
            .await
            .unwrap();
    assert!(v.accepted);
    assert_eq!(e.count("user_known_ip", "1=1").await, 0);
    e.db.record_login_success_v2(m1, Some("203.0.113.5"), T0 + 4)
        .await
        .unwrap();
    assert_eq!(
        e.count(
            "user_known_ip",
            &format!("account_id = {m1} AND ip_key = '203.0.113.5'")
        )
        .await,
        1
    );
    let acct = e.db.get_account(m1).await.unwrap().unwrap();
    assert_eq!(acct.last_login_at, Some(T0 + 4));
}

#[tokio::test]
async fn sec_066_known_ip_table_is_capped_at_five() {
    let (e, _a, m1, m2) = world().await;
    for i in 0..8_i64 {
        e.db.record_login_success_v2(m1, Some(&format!("192.0.2.{i}")), T0 + i)
            .await
            .unwrap();
    }
    e.db.record_login_success_v2(m2, Some("192.0.2.200"), T0)
        .await
        .unwrap();
    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT ip_key FROM user_known_ip WHERE account_id = ?1 ORDER BY last_seen",
    )
    .bind(m1)
    .fetch_all(e.db.writer())
    .await
    .unwrap();
    assert_eq!(
        kept,
        [
            "192.0.2.3",
            "192.0.2.4",
            "192.0.2.5",
            "192.0.2.6",
            "192.0.2.7"
        ]
    );
    // A repeat visit refreshes a row instead of adding one.
    e.db.record_login_success_v2(m1, Some("192.0.2.3"), T0 + 50)
        .await
        .unwrap();
    assert_eq!(
        e.count("user_known_ip", &format!("account_id = {m1}"))
            .await,
        5
    );
    // The other account's row is untouched.
    assert_eq!(
        e.count("user_known_ip", &format!("account_id = {m2}"))
            .await,
        1
    );
}

#[tokio::test]
async fn lock_rows_are_bounded_per_account_and_purged_when_idle() {
    let (e, _a, m1, _m2) = world().await;
    for i in 0..100_i64 {
        e.db.record_failure(
            m1,
            &format!("10.{}.{}.1", i / 50, i % 50),
            FailureKind::Password,
            None,
            T0 + i,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        e.count("login_lock", &format!("account_id = {m1}")).await,
        64
    );
    // Idle > 24 h: purged by the maintenance job; a recent lock row stays.
    e.db.record_failure(m1, "10.9.9.9", FailureKind::Password, None, T0 + 90_000)
        .await
        .unwrap();
    let rep = e.db.purge_account_state(T0 + 90_000 + 10).await.unwrap();
    assert_eq!(
        rep.locks, 63,
        "the 64 kept rows, minus the one evicted by the new row"
    );
    assert_eq!(
        e.count("login_lock", &format!("account_id = {m1}")).await,
        1
    );
    // known addresses: purged after 90 days.
    e.db.record_login_success_v2(m1, Some("192.0.2.1"), T0)
        .await
        .unwrap();
    let rep = e.db.purge_account_state(T0 + 91 * 86_400).await.unwrap();
    assert_eq!(rep.known_ips, 1);
}

#[tokio::test]
async fn sec_033_failures_are_anonymous_with_target_id() {
    let (e, _a, m1, _m2) = world().await;
    wrong_password(&e, m1, "192.0.2.1", T0).await;
    e.db.second_factor_step_v2(attempt(m1, None, "login", T0 + 1), &ctx("192.0.2.1"))
        .await
        .unwrap();
    // Unknown name: no target.
    e.db.login_password_step_v2(
        None,
        false,
        "bad_password",
        &ctx("192.0.2.1"),
        Some("192.0.2.1"),
        T0 + 2,
    )
    .await
    .unwrap();
    let fail = e.audit("login.fail").await;
    assert_eq!(fail.len(), 2);
    for r in &fail {
        assert_eq!(r.kind.as_deref(), Some("anonymous"));
        assert_eq!(
            (r.actor.as_deref(), r.actor_id, r.role.as_deref()),
            (None, None, None)
        );
    }
    assert_eq!(fail[0].target_id, Some(m1));
    assert_eq!(fail[0].detail.as_deref(), Some("bad_password"));
    assert_eq!(fail[1].target_id, None);
    assert_eq!(fail[1].detail.as_deref(), Some("unknown_user"));
    let mfa = e.audit("mfa.fail").await;
    assert_eq!(mfa.len(), 1);
    assert_eq!(
        (mfa[0].kind.as_deref(), mfa[0].actor_id, mfa[0].target_id),
        (Some("anonymous"), None, Some(m1))
    );
    // The accepted ones: password step is pre-auth (anonymous), the second factor is a completed
    // authentication attributed to the account with its role.
    assert!(right_password(&e, m1, "198.51.100.1", false, T0 + 5).await);
    e.db.second_factor_step_v2(
        attempt(m1, Some(9_000), "login", T0 + 6),
        &ctx("198.51.100.1"),
    )
    .await
    .unwrap();
    let ok = e.audit("login.password_ok").await;
    assert_eq!(
        (ok[0].kind.as_deref(), ok[0].target_id),
        (Some("anonymous"), Some(m1))
    );
    let mfa_ok = e.audit("mfa.ok").await;
    assert_eq!(mfa_ok.len(), 1);
    assert_eq!(
        (
            mfa_ok[0].kind.as_deref(),
            mfa_ok[0].actor_id,
            mfa_ok[0].role.as_deref()
        ),
        (Some("user"), Some(m1), Some("uploader"))
    );
}

#[tokio::test]
async fn sec_067_failed_login_is_not_attributed_to_target_account() {
    let (e, a, m1, _m2) = world().await;
    // 1.x callers still pass the submitted name as actor text: the row keeps the snapshot for display
    // but is `anonymous` and names the account only as target.
    e.db.login_password_step(Some(m1), false, "bad_password", Some("192.0.2.1"), T0)
        .await
        .unwrap();
    let r = e.audit("login.fail").await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].kind.as_deref(), Some("anonymous"));
    assert_eq!(
        (r[0].actor_id, r[0].role.as_deref(), r[0].target_id),
        (None, None, Some(m1))
    );
    // v2: not even the text.
    wrong_password(&e, a, "192.0.2.2", T0 + 1).await;
    let r = e.audit("login.fail").await;
    assert_eq!(r[1].actor, None);
    // No row anywhere credits a failure to a user.
    assert_eq!(
        e.count(
            "audit_log",
            "event IN ('login.fail','mfa.fail') AND actor_kind = 'user'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn disabled_and_locked_accounts_never_pass_the_password_step() {
    let (e, a, m1, m2) = world().await;
    let act = e.actor(a).await;
    e.db.disable_account(&act, m1, None, T0).await.unwrap();
    // Disabled: refused even with the right password, no failure counted against anything.
    assert!(!right_password(&e, m1, "192.0.2.1", false, T0 + 1).await);
    assert_eq!(
        e.count("login_lock", &format!("account_id = {m1}")).await,
        0
    );
    let rows = e.audit("login.fail").await;
    assert_eq!(rows.last().unwrap().detail.as_deref(), Some("disabled"));
    // The legacy single-lock path refuses a disabled account too.
    assert!(
        !e.db
            .login_password_step(Some(m1), true, "x", None, T0 + 2)
            .await
            .unwrap()
    );
    // An enabled account is unaffected.
    assert!(right_password(&e, m2, "192.0.2.1", false, T0 + 3).await);
}

#[tokio::test]
async fn enrollment_v2_counts_per_address_and_waives_the_token_for_proven_sessions() {
    let e = env().await;
    let a = e.admin("root").await;
    let act = e.actor(a).await;
    let h = crate::acct_testkit::code(3).hash();
    e.db.create_invite(
        &act,
        &crate::NewInvite {
            username: "newbie",
            role: crate::GrantableRole::Uploader,
            code_hash: &h,
            ttl_secs: 3600,
        },
        crate::acct_testkit::POLICY,
        None,
        T0,
    )
    .await
    .unwrap();
    let s = sess(0, 33, SessionStage::PendingMfa, T0 + 1);
    let r =
        e.db.redeem_code_with_profile(
            &Redemption {
                code_hash: &h,
                password_hash: "pw",
                session: &s,
                replacing: None,
            },
            &crate::RegistrationProfile {
                email: crate::acct_testkit::TEST_EMAIL,
                display_name: "Invitee_x",
            },
            crate::acct_testkit::POLICY,
            None,
            T0 + 1,
        )
        .await
        .unwrap();
    let crate::Redeemed::Account { user_id, .. } = r else {
        panic!("account expected");
    };
    let sealed = b"sealed-secret";
    let c = AttemptContext {
        ip_key: "192.0.2.50",
        session: Some(&[33; 32]),
        bucket_refused: false,
    };
    assert_eq!(
        e.db.store_pending_totp(user_id, sealed, false)
            .await
            .unwrap()
            .as_deref(),
        Some(sealed.as_slice())
    );
    let hashes = [[1_u8; 32]];
    // No token was ever issued for this account, yet the proven session may confirm with a code.
    let wrong = crate::EnrollConfirm {
        user_id,
        sealed: b"other",
        token_hash: None,
        step: Some(5),
        recovery_hashes: &hashes,
    };
    assert!(
        !e.db
            .confirm_totp_enrollment_v2(&wrong, &c, None, T0 + 2)
            .await
            .unwrap()
    );
    let good = crate::EnrollConfirm { sealed, ..wrong };
    assert!(
        e.db.confirm_totp_enrollment_v2(&good, &c, None, T0 + 3)
            .await
            .unwrap()
    );
    let acct = e.db.get_account(user_id).await.unwrap().unwrap();
    assert!(acct.totp_enabled);
    assert_eq!(
        e.count("recovery_code", &format!("account_id = {user_id}"))
            .await,
        1
    );
    // A NON-proven pending session of an account without a token cannot confirm.
    let m = e.uploader("plain").await;
    e.db.insert_session(&sess(m, 34, SessionStage::PendingMfa, T0 + 5), 5)
        .await
        .unwrap();
    e.db.store_pending_totp(m, sealed, false).await.unwrap();
    let c2 = AttemptContext {
        ip_key: "192.0.2.51",
        session: Some(&[34; 32]),
        bucket_refused: false,
    };
    let try_it = crate::EnrollConfirm {
        user_id: m,
        sealed,
        token_hash: Some([4; 32]),
        step: Some(5),
        recovery_hashes: &hashes,
    };
    assert!(
        !e.db
            .confirm_totp_enrollment_v2(&try_it, &c2, None, T0 + 6)
            .await
            .unwrap()
    );
}
