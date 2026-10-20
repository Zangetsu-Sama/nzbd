//! The two MFA steps of the login flow: `/login/mfa` (verify) and `/mfa/enroll` (first-time
//! setup) (`AUTH_SPEC` §Login flow, §TOTP, §Recovery codes; SEC-023/026/033).
//!
//! Both steps are reachable only with a `pending_mfa` session (`pending_gate`). Completing either
//! one: counts wrong codes into the per-(account, address) lock, the persisted aggregate and the
//! pending session's own 5-failure cap (one writer transaction each, `*_v2` verdicts), records the
//! completed login (`record_login_success_v2`, the only writer of the known-address set) and
//! mints a NEW `active` session id that replaces the pending one (fixation). Every failure
//! renders the same page with the same text.
//!
//! The enrollment page serves three kinds of pending session (T101):
//! * *token*: the 1.x flow, a host-printed enrollment token proves the holder first;
//! * *proven*: the session was created by an invitation redemption (`enroll_proven`), the code
//!   already played the part of the token;
//! * *recovery*: an admin-issued recovery code was redeemed; the new password and the new TOTP
//!   secret are only STAGED and replace the account's credentials at the final confirmation
//!   (`Store::commit_staged_recovery`), so abandoning the page changes nothing.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use nzb_store::prelude::*;
use nzb_store::{
    AccountError, CommitRecovery, EnrollConfirm, FactorAttempt, FailureKind, MfaState,
    SecondFactor, SessionStage, StoreError,
};
use zeroize::Zeroizing;

use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, SessionCtx};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::login::{html, internal};
use crate::session::see_other;
use crate::totp;

/// The one failure text for every wrong or malformed second-factor input.
pub const INVALID_CODE: &str = "Invalid code";
/// Failure text for a wrong, expired or missing enrollment token.
pub const INVALID_TOKEN: &str = "Invalid or expired enrollment token";

#[derive(Template)]
#[template(path = "mfa_verify.html")]
struct VerifyPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
mod session_tests {
    use super::*;
    use crate::auth::{AuthConfig, ManualWallClock, WallClock};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use futures_util::{StreamExt as _, stream};
    use nzb_store::test_backend::TestStore;
    use nzb_store::{AccountPolicy, NewAccount, NewSession, Role, Store};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tower::ServiceExt as _;

    const NOW: i64 = 1_700_000_000;

    async fn owner(db: &Store, name: &str) -> i64 {
        db.create_account_operator(
            &NewAccount {
                username: name,
                password_hash: "unused-test-hash",
                role: Some(Role::Admin),
            },
            AccountPolicy {
                multi_user: true,
                ..AccountPolicy::default()
            },
            NOW,
        )
        .await
        .unwrap()
    }

    async fn confirmation_cases(token_mode: bool) {
        let dir = tempfile::tempdir().unwrap();
        let test = TestStore::open(dir.path()).await;
        let db = &test.store;
        for (index, case) in [
            "revoked", "expired", "active", "foreign", "disabled", "live",
        ]
        .into_iter()
        .enumerate()
        {
            let uid = owner(db, &format!("owner{index}")).await;
            let session_uid = if case == "foreign" {
                owner(db, "other").await
            } else {
                uid
            };
            let sid = [u8::try_from(index).unwrap() + 10; 32];
            db.insert_session(
                &NewSession {
                    id_hash: sid,
                    user_id: session_uid,
                    stage: if case == "active" {
                        SessionStage::Active
                    } else {
                        SessionStage::PendingMfa
                    },
                    csrf_token: [21; 32],
                    now: NOW,
                    expires_at: NOW + 10,
                    ip: None,
                    user_agent: None,
                },
                5,
            )
            .await
            .unwrap();
            if !token_mode {
                test.exec(&format!(
                    "UPDATE session SET enroll_proven = true WHERE account_id = {session_uid}"
                ))
                .await;
            }
            if token_mode {
                assert!(
                    db.set_enrollment_token_for(uid, &[91; 32], NOW + 600, NOW)
                        .await
                        .unwrap()
                );
            }
            db.store_pending_totp(uid, b"sealed-test", false)
                .await
                .unwrap();
            if case == "revoked" {
                assert!(db.delete_session(&sid).await.unwrap());
            }
            if case == "disabled" {
                test.exec(&format!(
                    "UPDATE account SET disabled_at = {NOW} WHERE id = {uid}"
                ))
                .await;
            }
            let context = nzb_store::AttemptContext {
                ip_key: "192.0.2.88",
                session: Some(&sid),
                bucket_refused: false,
            };
            let confirm = EnrollConfirm {
                user_id: uid,
                sealed: b"sealed-test",
                token_hash: token_mode.then_some([91; 32]),
                step: Some(99),
                recovery_hashes: &[[92; 32]],
            };
            let verdict = db
                .confirm_totp_enrollment_v2(
                    &confirm,
                    &context,
                    None,
                    if case == "expired" { NOW + 10 } else { NOW },
                )
                .await;
            // No live pending session of this account behind the cookie (revoked, expired, already
            // active, another account's) is a distinct verdict: the page must not show the secret
            // again as if the code were wrong.
            match (case, verdict) {
                (
                    "revoked" | "expired" | "active" | "foreign",
                    Err(nzb_store::StoreError::NotFound),
                )
                | ("disabled", Ok(false))
                | ("live", Ok(true)) => {}
                (_, other) => panic!("case {case}, token mode {token_mode}: {other:?}"),
            }
            assert_eq!(
                db.get_mfa_state(uid).await.unwrap().unwrap().totp_enabled,
                case == "live"
            );
            assert_eq!(
                test.i64(&format!(
                    "SELECT count(*) FROM recovery_code WHERE account_id = {uid}"
                ))
                .await,
                i64::from(case == "live")
            );
        }
    }

    #[tokio::test]
    async fn enrollment_confirmation_requires_live_proven_session() {
        confirmation_cases(false).await;
    }

    #[tokio::test]
    async fn enrollment_token_does_not_replace_browser_session_authority() {
        confirmation_cases(true).await;
    }

    #[tokio::test]
    async fn enrollment_secret_reads_and_writes_require_live_pending_session() {
        let dir = tempfile::tempdir().unwrap();
        let test = TestStore::open(dir.path()).await;
        let db = &test.store;
        let uid = owner(db, "owner").await;
        let other = owner(db, "other").await;
        let session = NewSession {
            id_hash: [21; 32],
            user_id: uid,
            stage: SessionStage::PendingMfa,
            csrf_token: [22; 32],
            now: NOW,
            expires_at: NOW + 10,
            ip: None,
            user_agent: None,
        };
        db.insert_session(&session, 5).await.unwrap();
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"unproven", false, None, NOW)
                .await
                .unwrap(),
            None
        );
        test.exec(&format!(
            "UPDATE session SET enroll_proven = true WHERE account_id = {uid}"
        ))
        .await;
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"first", false, None, NOW)
                .await
                .unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"second", false, None, NOW)
                .await
                .unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            db.store_pending_totp_for_session(other, &session.id_hash, b"other", false, None, NOW)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.store_pending_totp_for_session(
                uid,
                &session.id_hash,
                b"expired",
                true,
                None,
                NOW + 10
            )
            .await
            .unwrap(),
            None
        );
        assert!(db.delete_session(&session.id_hash).await.unwrap());
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"revoked", true, None, NOW)
                .await
                .unwrap(),
            None
        );
        let active = NewSession {
            stage: SessionStage::Active,
            ..session.clone()
        };
        db.insert_session(&active, 5).await.unwrap();
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"active", true, None, NOW)
                .await
                .unwrap(),
            None
        );
        assert!(db.delete_session(&session.id_hash).await.unwrap());
        db.insert_session(&session, 5).await.unwrap();
        test.exec(&format!(
            "UPDATE account SET disabled_at = {NOW} WHERE id = {uid}"
        ))
        .await;
        assert_eq!(
            db.store_pending_totp_for_session(uid, &session.id_hash, b"disabled", true, None, NOW)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc,
            Some(b"first".to_vec())
        );
        assert_eq!(
            db.get_mfa_state(other)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc,
            None
        );
    }

    struct SecretEnv {
        _dir: tempfile::TempDir,
        test: TestStore,
        auth: AuthState,
        session: SessionCtx,
        cookie: String,
        clock: Arc<ManualWallClock>,
    }

    async fn secret_env(proven: bool) -> SecretEnv {
        let dir = tempfile::tempdir().unwrap();
        let test = TestStore::open(dir.path()).await;
        let uid = owner(&test.store, "owner").await;
        let clock = Arc::new(ManualWallClock::new(NOW));
        let auth = AuthState::new(
            test.store.clone(),
            AuthConfig {
                insecure_cookies: true,
                pending_secs: 120,
                totp_key: Some(Arc::new(totp::TotpKey::from_slice(&[37; 32]).unwrap())),
                ..AuthConfig::default()
            },
            clock.clone(),
        )
        .await
        .unwrap();
        let (set_cookie, _) = auth
            .start_session_full(uid, SessionStage::PendingMfa, &ClientMeta::default(), None)
            .await
            .unwrap();
        if proven {
            test.exec(&format!(
                "UPDATE session SET enroll_proven = true WHERE account_id = {uid}"
            ))
            .await;
        }
        let mut headers = HeaderMap::new();
        let cookie = set_cookie
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        let session = auth.peek_session(&headers).await.unwrap().unwrap();
        SecretEnv {
            _dir: dir,
            test,
            auth,
            session,
            cookie,
            clock,
        }
    }

    async fn assert_secret_refused(response: Response) {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(!html.contains("otpauth") && !html.contains("data:image"));
    }

    #[tokio::test]
    async fn enrollment_token_rotation_blocks_secret_creation_and_read() {
        let e = secret_env(false).await;
        let db = &e.test.store;
        let uid = e.session.user_id;
        let first = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let replacement = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let old_hash = totp::enroll_token_hash(first);
        let new_hash = totp::enroll_token_hash(replacement);
        assert!(
            db.set_enrollment_token_for(uid, &old_hash, NOW + 60, NOW)
                .await
                .unwrap()
        );
        let mode = enroll_mode(&e.auth, &e.session).await.unwrap();
        let ctx = nzb_store::AttemptContext {
            ip_key: "192.0.2.89",
            session: Some(&e.session.id_hash),
            bucket_refused: false,
        };
        assert!(
            db.check_enrollment_token_v2(uid, Some(old_hash), &ctx, None, NOW)
                .await
                .unwrap()
        );
        // Deterministic interleaving at the actual boundary between token verdict and secret
        // access. Rotation clears the old secret but keeps this ordinary pending session alive.
        assert!(
            db.set_enrollment_token_for(uid, &new_hash, NOW + 60, NOW)
                .await
                .unwrap()
        );
        assert!(db.get_session(&e.session.id_hash).await.unwrap().is_some());
        assert_secret_refused(show_secret(&e.auth, &e.session, &mode, first).await).await;
        assert_eq!(
            db.get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc,
            None
        );

        // The new token still works. An old verdict must not reveal the resulting secret either,
        // including when the caller already holds a cached MfaState with a decryptable blob.
        assert!(
            db.check_enrollment_token_v2(uid, Some(new_hash), &ctx, None, NOW)
                .await
                .unwrap()
        );
        let mode = enroll_mode(&e.auth, &e.session).await.unwrap();
        assert_eq!(
            show_secret(&e.auth, &e.session, &mode, replacement)
                .await
                .status(),
            StatusCode::OK
        );
        let expected = db
            .get_mfa_state(uid)
            .await
            .unwrap()
            .unwrap()
            .totp_secret_enc;
        assert!(expected.is_some());
        let cached = enroll_mode(&e.auth, &e.session).await.unwrap();
        assert_secret_refused(show_secret(&e.auth, &e.session, &cached, first).await).await;
        assert_eq!(
            db.get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc,
            expected
        );
        assert_eq!(e.test.i64("SELECT count(*) FROM recovery_code").await, 0);
    }

    #[tokio::test]
    async fn enrollment_secret_rechecks_expired_token_and_removed_proof() {
        for proven in [false, true] {
            let e = secret_env(proven).await;
            let db = &e.test.store;
            let uid = e.session.user_id;
            let token = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
            if !proven {
                assert!(
                    db.set_enrollment_token_for(
                        uid,
                        &totp::enroll_token_hash(token),
                        NOW + 20,
                        NOW
                    )
                    .await
                    .unwrap()
                );
            }
            let mode = enroll_mode(&e.auth, &e.session).await.unwrap();
            assert_eq!(
                show_secret(&e.auth, &e.session, &mode, token)
                    .await
                    .status(),
                StatusCode::OK
            );
            let expected = db
                .get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc;
            assert!(expected.is_some());
            if proven {
                e.test
                    .exec(&format!(
                        "UPDATE session SET enroll_proven = false WHERE account_id = {uid}"
                    ))
                    .await;
            } else {
                // The token expires first: the session is still live, so that check alone cannot help.
                e.clock.advance(20);
                assert_eq!(
                    db.get_session(&e.session.id_hash)
                        .await
                        .unwrap()
                        .unwrap()
                        .expires_at,
                    NOW + 120
                );
            }
            assert_secret_refused(show_secret(&e.auth, &e.session, &mode, token).await).await;
            assert_eq!(
                db.get_mfa_state(uid)
                    .await
                    .unwrap()
                    .unwrap()
                    .totp_secret_enc,
                expected
            );
            assert!(!db.get_mfa_state(uid).await.unwrap().unwrap().totp_enabled);
            assert_eq!(e.test.i64("SELECT count(*) FROM recovery_code").await, 0);
        }
    }

    fn post(path: &str, cookie: &str, csrf: &str) -> axum::http::request::Builder {
        Request::post(path)
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    }

    #[tokio::test]
    async fn sec_107_enrollment_confirmation_rejects_invalid_tokens_without_disclosing_secret() {
        const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const WRONG: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        const SECRET: &[u8] = b"12345678901234567890";

        for seeded in [false, true] {
            for (case, supplied, expired) in [
                ("wrong", Some(WRONG), false),
                ("missing", None, false),
                ("malformed", Some("not-base32"), false),
                ("expired", Some(TOKEN), true),
            ] {
                let e = secret_env(false).await;
                let db = &e.test.store;
                let uid = e.session.user_id;
                assert!(
                    db.set_enrollment_token_for(
                        uid,
                        &totp::enroll_token_hash(TOKEN),
                        NOW + 20,
                        NOW,
                    )
                    .await
                    .unwrap()
                );
                if seeded {
                    let blob = totp::seal(e.auth.totp_key().unwrap(), uid, SECRET).unwrap();
                    db.store_pending_totp(uid, &blob, false).await.unwrap();
                }
                let before = db.get_mfa_state(uid).await.unwrap().unwrap();
                assert_eq!(before.totp_secret_enc.is_some(), seeded);
                if expired {
                    e.clock.advance(20);
                }
                let app = crate::router_with_auth(
                    &crate::WebConfig {
                        insecure_cookies: true,
                        ..crate::WebConfig::default()
                    },
                    &e.auth,
                    axum::Router::new(),
                );
                // A syntactically valid code selects the confirmation branch. An invalid
                // enrollment token must stop it before either creating or reading a secret.
                let form = supplied.map_or_else(
                    || "code=000000".to_owned(),
                    |token| format!("token={token}&code=000000"),
                );
                let response = app
                    .oneshot(
                        post("/mfa/enroll", &e.cookie, &e.session.csrf_token)
                            .body(Body::from(form))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{case}, seeded={seeded}");
                let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
                let html = std::str::from_utf8(&bytes).unwrap();
                assert!(html.contains(INVALID_TOKEN), "{case}, seeded={seeded}");
                assert!(html.contains("name=\"token\""));
                for forbidden in ["otpauth", "data:image", "class=\"secret\"", "name=\"code\""] {
                    assert!(
                        !html.contains(forbidden),
                        "{case}, seeded={seeded}: {forbidden}"
                    );
                }
                assert!(!html.contains(&totp::base32_encode(SECRET)));
                let after = db.get_mfa_state(uid).await.unwrap().unwrap();
                assert_eq!(after.totp_secret_enc, before.totp_secret_enc);
                assert!(!after.totp_enabled);
                assert_eq!(e.test.i64("SELECT count(*) FROM recovery_code").await, 0);
                let session = db.get_session(&e.session.id_hash).await.unwrap().unwrap();
                assert_eq!(session.stage, SessionStage::PendingMfa);
                assert!(!session.enroll_proven);
                assert!(session.expires_at > e.auth.now());
            }
        }
    }

    #[tokio::test]
    async fn enrollment_valid_token_without_code_reveals_pending_secret() {
        let e = secret_env(false).await;
        let db = &e.test.store;
        let uid = e.session.user_id;
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            db.set_enrollment_token_for(uid, &totp::enroll_token_hash(token), NOW + 60, NOW)
                .await
                .unwrap()
        );
        assert!(
            db.get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc
                .is_none()
        );
        let app = crate::router_with_auth(
            &crate::WebConfig {
                insecure_cookies: true,
                ..crate::WebConfig::default()
            },
            &e.auth,
            axum::Router::new(),
        );
        let response = app
            .oneshot(
                post("/mfa/enroll", &e.cookie, &e.session.csrf_token)
                    .body(Body::from(format!("token={token}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        for expected in ["otpauth", "data:image", "class=\"secret\"", "name=\"code\""] {
            assert!(html.contains(expected), "missing {expected}");
        }
        assert!(!html.contains(INVALID_TOKEN));
        let state = db.get_mfa_state(uid).await.unwrap().unwrap();
        let secret = secret_of_state(&e.auth, uid, &state).unwrap();
        assert!(html.contains(&totp::base32_encode(&secret)));
        assert!(!state.totp_enabled);
        assert_eq!(e.test.i64("SELECT count(*) FROM recovery_code").await, 0);
        let session = db.get_session(&e.session.id_hash).await.unwrap().unwrap();
        assert_eq!(session.stage, SessionStage::PendingMfa);
        assert!(!session.enroll_proven);
    }

    /// Pauses HTTP clock reads while the controller inspects committed database state. The
    /// request runs on a blocking worker so this synchronous trait never blocks the test's
    /// database driver. No clock-call count or timing delay chooses the confirmation boundary.
    struct ConfirmationClock {
        time: ManualWallClock,
        armed: AtomicBool,
        checkpoints: tokio::sync::mpsc::UnboundedSender<std::sync::mpsc::Sender<()>>,
    }

    impl WallClock for ConfirmationClock {
        fn now_secs(&self) -> i64 {
            if self.armed.load(Ordering::SeqCst) {
                let (resume, paused) = std::sync::mpsc::channel();
                self.checkpoints.send(resume).unwrap();
                paused.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            self.time.now_secs()
        }
    }

    #[tokio::test]
    async fn enrollment_confirmation_rechecks_session_after_reading_secret() {
        const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        for proven in [false, true] {
            for case in ["revoked", "expired", "live"] {
                let dir = tempfile::tempdir().unwrap();
                let test = TestStore::open(dir.path()).await;
                let db = &test.store;
                let uid = owner(db, "owner").await;
                let (checkpoints, mut checks) = tokio::sync::mpsc::unbounded_channel();
                let clock = Arc::new(ConfirmationClock {
                    time: ManualWallClock::new(NOW),
                    armed: AtomicBool::new(false),
                    checkpoints,
                });
                let auth = AuthState::new(
                    db.clone(),
                    AuthConfig {
                        insecure_cookies: true,
                        pending_secs: 120,
                        totp_key: Some(Arc::new(totp::TotpKey::from_slice(&[37; 32]).unwrap())),
                        ..AuthConfig::default()
                    },
                    clock.clone(),
                )
                .await
                .unwrap();
                let (set_cookie, csrf) = auth
                    .start_session_full(uid, SessionStage::PendingMfa, &ClientMeta::default(), None)
                    .await
                    .unwrap();
                let cookie = set_cookie.to_str().unwrap().split(';').next().unwrap();
                let mut headers = HeaderMap::new();
                headers.insert(header::COOKIE, cookie.parse().unwrap());
                let session = auth.peek_session(&headers).await.unwrap().unwrap();
                if proven {
                    test.exec(&format!(
                        "UPDATE session SET enroll_proven = true WHERE account_id = {uid}"
                    ))
                    .await;
                } else {
                    assert!(
                        db.set_enrollment_token_for(
                            uid,
                            &totp::enroll_token_hash(TOKEN),
                            NOW + 600,
                            NOW,
                        )
                        .await
                        .unwrap()
                    );
                }
                assert!(
                    db.get_mfa_state(uid)
                        .await
                        .unwrap()
                        .unwrap()
                        .totp_secret_enc
                        .is_none()
                );
                let app = crate::router_with_auth(
                    &crate::WebConfig {
                        insecure_cookies: true,
                        ..crate::WebConfig::default()
                    },
                    &auth,
                    axum::Router::new(),
                );
                // An invalid code guarantees the live control renders the secret page. Dead
                // sessions must instead take the distinct NotFound branch after reading it.
                let request = post("/mfa/enroll", cookie, &csrf)
                    .body(Body::from(format!("token={TOKEN}&code=not-a-code")))
                    .unwrap();
                let router = app.clone();
                let runtime = tokio::runtime::Handle::current();
                clock.armed.store(true, Ordering::SeqCst);
                let mut task = tokio::task::spawn_blocking(move || {
                    runtime.block_on(router.oneshot(request)).unwrap()
                });
                let mut before_confirmation = None;
                let response = tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        tokio::select! {
                            response = &mut task => break response.unwrap(),
                            Some(resume) = checks.recv() => {
                                let state = db.get_mfa_state(uid).await.unwrap().unwrap();
                                if before_confirmation.is_none() && state.totp_secret_enc.is_some() {
                                    // The secret-store transaction has committed. The request's
                                    // next clock read is the confirmation verdict timestamp.
                                    before_confirmation = Some(state);
                                    match case {
                                        "revoked" => {
                                            assert!(db.delete_session(&session.id_hash).await.unwrap());
                                        }
                                        "expired" => clock.time.advance(120),
                                        "live" => {}
                                        _ => unreachable!(),
                                    }
                                }
                                resume.send(()).unwrap();
                            }
                        }
                    }
                })
                .await
                .unwrap();
                clock.armed.store(false, Ordering::SeqCst);
                let before = before_confirmation.unwrap();
                let secret = secret_of_state(&auth, uid, &before).unwrap();
                assert!(!response.headers().contains_key(header::SET_COOKIE));
                if case == "live" {
                    assert_eq!(response.status(), StatusCode::OK);
                } else {
                    assert_eq!(response.status(), StatusCode::SEE_OTHER);
                    assert_eq!(
                        response.headers().get(header::LOCATION).unwrap(),
                        "/mfa/enroll"
                    );
                }
                let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
                let html = std::str::from_utf8(&bytes).unwrap();
                for marker in ["otpauth", "data:image", "class=\"secret\"", INVALID_CODE] {
                    assert_eq!(
                        html.contains(marker),
                        case == "live",
                        "{case}, proven={proven}: {marker}"
                    );
                }
                assert_eq!(html.contains(&totp::base32_encode(&secret)), case == "live");
                let after = db.get_mfa_state(uid).await.unwrap().unwrap();
                assert_eq!(after.totp_secret_enc, before.totp_secret_enc);
                assert!(!after.totp_enabled);
                assert_eq!(after.totp_last_step, before.totp_last_step);
                assert_eq!(test.i64("SELECT count(*) FROM recovery_code").await, 0);
                assert_eq!(
                    test.i64("SELECT count(*) FROM session WHERE stage = 'active'")
                        .await,
                    0
                );
                if case != "live" {
                    let response = app
                        .oneshot(
                            Request::get("/mfa/enroll")
                                .header(header::HOST, "localhost")
                                .header(header::COOKIE, cookie)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_secret_refused(response).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn enrollment_rechecks_session_after_waiting_for_body() {
        for (seeded, expire) in [(false, false), (true, false), (false, true), (true, true)] {
            let dir = tempfile::tempdir().unwrap();
            let test = TestStore::open(dir.path()).await;
            let db = test.store.clone();
            let uid = owner(&db, "owner").await;
            let key = Arc::new(totp::TotpKey::from_slice(&[33; 32]).unwrap());
            if seeded {
                let blob = totp::seal(&key, uid, b"12345678901234567890").unwrap();
                db.store_pending_totp(uid, &blob, false).await.unwrap();
            }
            let before = db
                .get_mfa_state(uid)
                .await
                .unwrap()
                .unwrap()
                .totp_secret_enc;
            let clock = Arc::new(ManualWallClock::new(NOW));
            let auth = AuthState::new(
                db.clone(),
                AuthConfig {
                    insecure_cookies: true,
                    pending_secs: 10,
                    totp_key: Some(key),
                    ..AuthConfig::default()
                },
                clock.clone(),
            )
            .await
            .unwrap();
            let (cookie, csrf) = auth
                .start_session_full(uid, SessionStage::PendingMfa, &ClientMeta::default(), None)
                .await
                .unwrap();
            let cookie = cookie.to_str().unwrap().split(';').next().unwrap();
            test.exec(&format!(
                "UPDATE session SET enroll_proven = true WHERE account_id = {uid}"
            ))
            .await;
            let app = crate::router_with_auth(
                &crate::WebConfig {
                    insecure_cookies: true,
                    ..crate::WebConfig::default()
                },
                &auth,
                axum::Router::new(),
            );
            let (reached, waiting) = oneshot::channel();
            let (resume, paused) = oneshot::channel();
            let chunks = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"unused="))])
                .chain(stream::once(async move {
                    let _ = reached.send(());
                    paused
                        .await
                        .map_err(|_| std::io::Error::other("cancelled test body"))?;
                    Ok::<_, std::io::Error>(Bytes::from_static(b"value"))
                }));
            let router = app.clone();
            let request = post("/mfa/enroll", cookie, &csrf)
                .body(Body::from_stream(chunks))
                .unwrap();
            let task = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap();
            assert!(!task.is_finished());
            if expire {
                clock.advance(10);
            } else {
                let response = app
                    .oneshot(post("/logout", cookie, &csrf).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
            }
            resume.send(()).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SEE_OTHER,
                "seeded={seeded}, expire={expire}"
            );
            assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/login");
            let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
            let html = std::str::from_utf8(&body).unwrap();
            assert!(!html.contains("otpauth") && !html.contains("data:image"));
            assert_eq!(
                db.get_mfa_state(uid)
                    .await
                    .unwrap()
                    .unwrap()
                    .totp_secret_enc,
                before
            );
            assert_eq!(test.i64("SELECT count(*) FROM recovery_code").await, 0);
        }
    }
}

#[derive(Template)]
#[template(path = "mfa_enroll_token.html")]
struct TokenPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "mfa_enroll.html")]
struct EnrollPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
    qr: String,
    secret_text: Zeroizing<String>,
    uri: Zeroizing<String>,
    /// The token that proved the holder (token mode only); empty otherwise.
    token: String,
    /// Shown once after a valid invitation redemption.
    welcome: Option<String>,
    /// Recovery flow: the new password applies only after this confirmation.
    recovery: bool,
}

/// Page that shows freshly generated recovery codes exactly once.
#[derive(Template)]
#[template(path = "recovery_codes.html")]
pub(crate) struct RecoveryCodesPage {
    pub(crate) layout: Layout,
    pub(crate) heading: &'static str,
    pub(crate) codes: Vec<String>,
    pub(crate) continue_href: &'static str,
    pub(crate) continue_label: &'static str,
}

/// Decrypts the user's stored secret. `None` when no key is configured or the blob is unreadable.
pub(crate) fn secret_of_state(
    auth: &AuthState,
    user_id: i64,
    st: &MfaState,
) -> Option<Zeroizing<Vec<u8>>> {
    let key = auth.totp_key()?;
    totp::open(key, user_id, st.totp_secret_enc.as_deref()?)
}

/// Classifies the single `code` field: six digits are a TOTP code, 16 base32 characters a
/// recovery code, anything else is counted as a wrong TOTP code. Length/charset come first.
pub(crate) fn factor_from_input(secret: &[u8], now: i64, input: &str) -> SecondFactor {
    if let Some(code) = totp::parse_totp_code(input) {
        SecondFactor::Totp(totp::matching_step(secret, now, &code))
    } else if let Some(canon) = totp::normalize_recovery(input) {
        SecondFactor::Recovery(Some(totp::recovery_hash(&canon)))
    } else {
        SecondFactor::Totp(None)
    }
}

/// Renders a freshly generated batch of recovery codes (shown once), optionally setting a cookie.
pub(crate) fn recovery_response(
    layout: Layout,
    heading: &'static str,
    codes: &[String],
    continue_href: &'static str,
    continue_label: &'static str,
    cookie: Option<axum::http::HeaderValue>,
) -> Response {
    let page = RecoveryCodesPage {
        layout,
        heading,
        codes: codes.iter().map(|c| totp::format_recovery(c)).collect(),
        continue_href,
        continue_label,
    };
    let mut resp = page
        .render()
        .map_or_else(|_| internal(), |b| html(StatusCode::OK, b));
    if let Some(c) = cookie {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, c);
    }
    resp
}

/// Where a pending session belongs: `Ok(state)` for the step it asked for, `Err(redirect)`
/// otherwise.
#[allow(clippy::result_large_err)]
async fn state_for(
    auth: &AuthState,
    sess: &SessionCtx,
    want_enrolled: bool,
) -> Result<MfaState, Response> {
    match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(st)) if st.totp_enabled == want_enrolled => Ok(st),
        Ok(Some(_)) => Err(see_other(
            if want_enrolled {
                "/mfa/enroll"
            } else {
                "/login/mfa"
            },
            None,
        )),
        Ok(None) => Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            Err(internal())
        }
    }
}

/// A staged credential swap belongs to the enrollment page, never to the code prompt.
#[allow(clippy::result_large_err)]
async fn redirect_if_recovery(auth: &AuthState, sess: &SessionCtx) -> Result<(), Response> {
    match auth
        .db()
        .staged_swap(sess.user_id, &sess.id_hash, auth.now())
        .await
    {
        Ok(Some(_)) => Err(see_other("/mfa/enroll", None)),
        Ok(None) => Ok(()),
        Err(e) => {
            tracing::error!(error = %e, "staged swap lookup failed");
            Err(internal())
        }
    }
}

fn render_verify(sess: &SessionCtx, error: Option<&'static str>) -> Response {
    VerifyPage {
        layout: Layout::new("Two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

pub(crate) async fn get_verify(
    State(auth): State<AuthState>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    if let Err(r) = redirect_if_recovery(&auth, &sess).await {
        return r;
    }
    match state_for(&auth, &sess, true).await {
        Ok(_) => render_verify(&sess, None),
        Err(r) => r,
    }
}

pub(crate) async fn post_verify(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = redirect_if_recovery(&auth, &sess).await {
        return r;
    }
    let st = match state_for(&auth, &sess, true).await {
        Ok(st) => st,
        Err(r) => return r,
    };
    let Some(secret) = secret_of_state(&auth, sess.user_id, &st) else {
        // No key configured or the stored blob is unreadable: fail closed, never skip MFA.
        tracing::error!("TOTP secret unavailable; refusing second-factor login");
        return internal();
    };
    let form = csrf::parse_form(&body);
    let input = csrf::form_get(&form, "code").unwrap_or_default();
    let now = auth.now();
    let factor = factor_from_input(&secret, now, input);
    let recovery = matches!(factor, SecondFactor::Recovery(_));
    let ip_text = ip.to_string();
    let attempt = match auth
        .attempt(Some(sess.user_id), ip, Some(sess.id_hash))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "throttle state failed");
            return internal();
        }
    };
    // The verification above is done whatever the throttle says; a refused (locked, throttled,
    // capped) attempt is answered exactly like a wrong code, after the same work (SEC-064).
    let accepted = match auth
        .db()
        .second_factor_step_v2(
            FactorAttempt {
                user_id: sess.user_id,
                precondition_ok: true,
                factor,
                purpose: "login",
                ip: Some(&ip_text),
                now,
            },
            &attempt.ctx(),
        )
        .await
    {
        Ok(v) => v.accepted,
        Err(e) => {
            tracing::error!(error = %e, "second factor verdict failed");
            return internal();
        }
    };
    if !accepted {
        return render_verify(&sess, Some(INVALID_CODE));
    }
    // The login is complete: only now are the lock state and the known-address set updated, and
    // the session id is replaced (never promoted) so the pending id cannot be reused.
    if let Err(e) = auth
        .db()
        .record_login_success_v2(sess.user_id, Some(attempt.ip_key()), now)
        .await
    {
        tracing::error!(error = %e, "could not record the completed login");
        return internal();
    }
    let meta = ClientMeta::from_request(&headers, Some(ip));
    match auth
        .promote_session(sess.user_id, &meta, &sess.id_hash)
        .await
    {
        // A recovery code was spent: the account page explains how to get a new set.
        Ok((cookie, _)) => see_other(if recovery { "/account" } else { "/" }, Some(cookie)),
        // The pending session vanished (logout, CLI reset, a concurrent request used it first).
        Err(AuthError::Store(StoreError::NotFound)) => {
            see_other("/login", Some(auth.clear_cookie()))
        }
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            internal()
        }
    }
}

/// Pending secret: the stored one, or a freshly generated, sealed and stored one (first visit
/// after the token check, or when the stored blob no longer decrypts, e.g. after a key change).
/// Returns the sealed blob too, so the confirmation can be bound to exactly this secret.
#[allow(clippy::result_large_err)]
async fn pending_secret(
    auth: &AuthState,
    key: &totp::TotpKey,
    sess: &SessionCtx,
    st: &MfaState,
    token_hash: Option<[u8; 32]>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Response> {
    let uid = sess.user_id;
    let (sealed, replace) = if secret_of_state(auth, uid, st).is_some() {
        (st.totp_secret_enc.clone().ok_or_else(internal)?, false)
    } else {
        let fresh = totp::generate_secret().map_err(|_| internal())?;
        (
            totp::seal(key, uid, &*fresh).map_err(|_| internal())?,
            st.totp_secret_enc.is_some(),
        )
    };
    // Reading an existing secret needs the same session check as creating one: the request
    // may have waited for its body or another database operation after admission.
    let stored = match auth
        .db()
        .store_pending_totp_for_session(
            uid,
            &sess.id_hash,
            &sealed,
            replace,
            token_hash,
            auth.now(),
        )
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return Err(see_other("/login", Some(auth.clear_cookie()))),
        Err(e) => {
            tracing::error!(error = %e, "could not store pending TOTP secret");
            return Err(internal());
        }
    };
    let secret = totp::open(key, uid, &stored).ok_or_else(internal)?;
    Ok((secret, stored))
}

fn render_token_prompt(sess: &SessionCtx, error: Option<&'static str>) -> Response {
    TokenPage {
        layout: Layout::new("Set up two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

/// What the enrollment page is for (see the module docs).
enum Mode {
    /// 1.x: the holder must prove the host-printed enrollment token first.
    Token(MfaState),
    /// Created by an invitation redemption: the code already proved the holder.
    Proven(MfaState),
    /// An admin-issued recovery code was redeemed: credentials are staged, not yet replaced.
    Recovery(MfaState, nzb_store::StagedSwap),
}

impl Mode {
    fn state(&self) -> &MfaState {
        match self {
            Self::Token(st) | Self::Proven(st) | Self::Recovery(st, _) => st,
        }
    }
}

/// Decides which kind of enrollment this pending session is, or where it belongs instead.
#[allow(clippy::result_large_err)]
async fn enroll_mode(auth: &AuthState, sess: &SessionCtx) -> Result<Mode, Response> {
    let pending = match auth.db().get_session(&sess.id_hash).await {
        Ok(Some(row))
            if row.user_id == sess.user_id
                && row.stage == SessionStage::PendingMfa
                && row.expires_at > auth.now() =>
        {
            row
        }
        Ok(_) => return Err(see_other("/login", Some(auth.clear_cookie()))),
        Err(e) => {
            tracing::error!(error = %e, "enrollment session lookup failed");
            return Err(internal());
        }
    };
    let st = match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(st)) => st,
        Ok(None) => return Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return Err(internal());
        }
    };
    match auth
        .db()
        .staged_swap(sess.user_id, &sess.id_hash, auth.now())
        .await
    {
        Ok(Some(staged)) => return Ok(Mode::Recovery(st, staged)),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "staged swap lookup failed");
            return Err(internal());
        }
    }
    if st.totp_enabled {
        return Err(see_other("/login/mfa", None));
    }
    if pending.enroll_proven {
        Ok(Mode::Proven(st))
    } else {
        Ok(Mode::Token(st))
    }
}

/// Renders the secret page. `token` is the canonical enrollment token the user already proved
/// (token mode; empty otherwise): it rides along in a hidden field and is verified again,
/// atomically, at confirmation.
fn render_enroll(
    sess: &SessionCtx,
    mode: &Mode,
    secret: &[u8],
    token: &str,
    error: Option<&'static str>,
) -> Response {
    let username = &mode.state().username;
    let uri = Zeroizing::new(totp::otpauth_uri(username, secret));
    let Some(qr) = totp::qr_svg_data_uri(&uri) else {
        return internal();
    };
    EnrollPage {
        layout: Layout::new("Set up two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
        qr,
        secret_text: Zeroizing::new(totp::base32_encode(secret)),
        uri,
        token: token.to_owned(),
        // The invitee's login name is shown after a valid redemption only (SEC-064).
        welcome: matches!(mode, Mode::Proven(_)).then(|| username.clone()),
        recovery: matches!(mode, Mode::Recovery(..)),
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

/// `GET /mfa/enroll`: a plain enrollment asks for the one-time enrollment token printed on the
/// host (`nzbd user create|reset-mfa|enroll-token`); the secret is not generated or shown before
/// it is proven, so knowing the password alone never yields the authenticator secret. A session
/// that came from an invitation or a recovery code shows its (staged) secret directly.
pub(crate) async fn get_enroll(
    State(auth): State<AuthState>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    match enroll_mode(&auth, &sess).await {
        Ok(Mode::Token(_)) => render_token_prompt(&sess, None),
        Ok(mode) => show_secret(&auth, &sess, &mode, "").await,
        Err(r) => r,
    }
}

/// Shows the pending secret of a proven or recovery session (creating and storing it first).
async fn show_secret(auth: &AuthState, sess: &SessionCtx, mode: &Mode, token: &str) -> Response {
    let Some(key) = auth.totp_key() else {
        tracing::error!("no TOTP key configured; enrollment unavailable");
        return internal();
    };
    let token_hash = matches!(mode, Mode::Token(_)).then(|| totp::enroll_token_hash(token));
    match pending_for(auth, key, sess, mode, token_hash).await {
        Ok((secret, _)) => render_enroll(sess, mode, &secret, token, None),
        Err(r) => r,
    }
}

/// The pending secret and its sealed blob for any mode (the blob binds the confirmation to
/// exactly the secret that was displayed).
#[allow(clippy::result_large_err)]
async fn pending_for(
    auth: &AuthState,
    key: &totp::TotpKey,
    sess: &SessionCtx,
    mode: &Mode,
    token_hash: Option<[u8; 32]>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Response> {
    match mode {
        Mode::Token(st) | Mode::Proven(st) => pending_secret(auth, key, sess, st, token_hash).await,
        Mode::Recovery(_, staged) => {
            let sealed = if let Some(blob) = staged.totp_secret_enc.clone()
                && let Some(secret) = totp::open(key, sess.user_id, &blob)
            {
                drop(secret);
                blob
            } else {
                let fresh = totp::generate_secret().map_err(|_| internal())?;
                totp::seal(key, sess.user_id, &*fresh).map_err(|_| internal())?
            };
            let stored = match auth
                .db()
                .stage_totp_secret(sess.user_id, &sess.id_hash, &sealed, auth.now())
                .await
            {
                Ok(Some(b)) => b,
                Ok(None) => return Err(see_other("/login", Some(auth.clear_cookie()))),
                Err(e) => {
                    tracing::error!(error = %e, "could not stage the TOTP secret");
                    return Err(internal());
                }
            };
            let secret = totp::open(key, sess.user_id, &stored).ok_or_else(internal)?;
            Ok((secret, stored))
        }
    }
}

/// Step 1 of token enrollment: prove the token, then show (creating on first use) the secret.
async fn enroll_reveal(
    auth: &AuthState,
    sess: &SessionCtx,
    mode: &Mode,
    canon: Option<String>,
    token_hash: Option<[u8; 32]>,
    attempt: &crate::auth::Attempt,
    ip: &str,
) -> Response {
    let ok = match auth
        .db()
        .check_enrollment_token_v2(
            sess.user_id,
            token_hash,
            &attempt.ctx(),
            Some(ip),
            auth.now(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "enrollment token check failed");
            return internal();
        }
    };
    let (true, Some(canon)) = (ok, canon) else {
        return render_token_prompt(sess, Some(INVALID_TOKEN));
    };
    show_secret(auth, sess, mode, &canon).await
}

// One handler for the three modes of the enrollment POST; splitting it would only scatter the
// shared steps (code parsing, recovery codes, session promotion).
#[allow(clippy::too_many_lines)]
pub(crate) async fn post_enroll(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mode = match enroll_mode(&auth, &sess).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let Some(key) = auth.totp_key() else {
        tracing::error!("no TOTP key configured; enrollment unavailable");
        return internal();
    };
    let form = csrf::parse_form(&body);
    let now = auth.now();
    let ip_text = ip.to_string();
    let attempt = match auth
        .attempt(Some(sess.user_id), ip, Some(sess.id_hash))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "throttle state failed");
            return internal();
        }
    };
    let token_mode = matches!(mode, Mode::Token(_));
    let canon = if token_mode {
        csrf::form_get(&form, "token").and_then(totp::normalize_enroll_token)
    } else {
        None
    };
    let token_hash = canon.as_deref().map(totp::enroll_token_hash);
    let has_code = csrf::form_get(&form, "code").is_some();
    if !has_code {
        if token_mode {
            return enroll_reveal(&auth, &sess, &mode, canon, token_hash, &attempt, &ip_text).await;
        }
        return show_secret(&auth, &sess, &mode, "").await;
    }
    // Step 2: confirm with a code. In token mode the token is proven before the secret is created
    // or shown (a wrong token must never reach the secret page), then re-verified inside the
    // confirming transaction.
    if token_mode {
        let ok = match auth
            .db()
            .check_enrollment_token_v2(
                sess.user_id,
                token_hash,
                &attempt.ctx(),
                Some(&ip_text),
                now,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "enrollment token check failed");
                return internal();
            }
        };
        if !ok || canon.is_none() {
            return render_token_prompt(&sess, Some(INVALID_TOKEN));
        }
    }
    let (secret, blob) = match pending_for(&auth, key, &sess, &mode, token_hash).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let input = csrf::form_get(&form, "code").unwrap_or_default();
    let step = totp::parse_totp_code(input).and_then(|c| totp::matching_step(&secret, now, &c));
    let Ok(codes) = totp::generate_recovery_codes() else {
        return internal();
    };
    let hashes: Vec<[u8; 32]> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    let meta = ClientMeta::from_request(&headers, Some(ip));
    let token_text = canon.clone().unwrap_or_default();
    if let Mode::Recovery(..) = &mode {
        // The commit point of a staged recovery: password, TOTP secret and recovery codes are
        // replaced, every other session and key of the account dies, in one transaction.
        let Some(step) = step else {
            let _ = auth
                .db()
                .record_failure(
                    sess.user_id,
                    attempt.ip_key(),
                    FailureKind::Enrollment,
                    Some(&sess.id_hash),
                    now,
                )
                .await;
            return render_enroll(&sess, &mode, &secret, "", Some(INVALID_CODE));
        };
        let (new_session, cookie, csrf_token) =
            match auth.prepare_session(sess.user_id, SessionStage::Active, &meta) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "session preparation failed");
                    return internal();
                }
            };
        let commit = CommitRecovery {
            user_id: sess.user_id,
            session_hash: &sess.id_hash,
            sealed: &blob,
            step,
            recovery_hashes: &hashes,
            new_session: &new_session,
            ip_key: Some(attempt.ip_key()),
        };
        return match auth
            .db()
            .commit_staged_recovery(&commit, Some(&ip_text), auth.now())
            .await
        {
            Ok(()) => recovery_response(
                Layout::authed("Recovery codes", csrf_token)
                    .hiding(&sess.hidden_categories)
                    .themed(sess.prefs.theme),
                "Your new password and authenticator are active",
                &codes,
                "/",
                "Continue to nzbd",
                Some(cookie),
            ),
            Err(StoreError::Account(AccountError::StagingInvalid)) => {
                // Expired, cancelled or no longer valid: nothing was replaced.
                see_other("/login", Some(auth.clear_cookie()))
            }
            Err(e) => {
                tracing::error!(error = %e, "recovery commit failed");
                internal()
            }
        };
    }
    let confirm = EnrollConfirm {
        user_id: sess.user_id,
        sealed: &blob,
        token_hash: if token_mode { token_hash } else { None },
        step,
        recovery_hashes: &hashes,
    };
    let enrolled = match auth
        .db()
        .confirm_totp_enrollment_v2(&confirm, &attempt.ctx(), Some(&ip_text), auth.now())
        .await
    {
        Ok(v) => v,
        // The pending session died meanwhile (revoked, expired): never the secret page again.
        // The enrollment gate sends a dead session to the login page.
        Err(StoreError::NotFound) => return see_other("/mfa/enroll", None),
        Err(e) => {
            tracing::error!(error = %e, "enrollment verdict failed");
            return internal();
        }
    };
    if !enrolled {
        // Wrong code (or the token expired meanwhile): the secret page again, same text.
        return render_enroll(&sess, &mode, &secret, &token_text, Some(INVALID_CODE));
    }
    if let Err(e) = auth
        .db()
        .record_login_success_v2(sess.user_id, Some(attempt.ip_key()), now)
        .await
    {
        tracing::error!(error = %e, "could not record the completed login");
    }
    match auth
        .promote_session(sess.user_id, &meta, &sess.id_hash)
        .await
    {
        Ok((cookie, csrf_token)) => recovery_response(
            Layout::authed("Recovery codes", csrf_token)
                .hiding(&sess.hidden_categories)
                .themed(sess.prefs.theme),
            "Two-factor authentication is on",
            &codes,
            "/",
            "Continue to nzbd",
            Some(cookie),
        ),
        Err(e) => {
            // MFA is already enabled and the hashes are committed: never lose the codes. Show
            // them without a cookie; the user signs in again with TOTP.
            tracing::error!(error = %e, "session creation failed after enrollment");
            recovery_response(
                Layout::new("Recovery codes"),
                "Two-factor authentication is on",
                &codes,
                "/login",
                "Sign in again",
                Some(auth.clear_cookie()),
            )
        }
    }
}
