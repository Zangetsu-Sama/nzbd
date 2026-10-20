//! Login and logout (the MFA steps live in `mfa.rs`) (`AUTH_SPEC` §Login flow; SEC-024/025/026/027).
//!
//! Every credential failure takes the same path: one full Argon2id verification (against the
//! dummy hash when the user is unknown, the input is over-length, or the stored hash is
//! unusable), the same `200` login page and the same text, so the response reveals neither
//! whether the account exists nor whether it is locked.
//!
//! The password step only ever yields a `pending_mfa` session. Failure state is cleared by the
//! *second factor* completing (`mfa.rs` calls `Store::record_login_success_v2`), never by the
//! password step, otherwise an attacker holding the password could reset the counter between
//! TOTP guesses.
//!
//! Throttling is the per-(account, address) lock, the persisted aggregate and the unknown-address
//! bucket of the store's `_v2` verdicts. A throttled attempt has already paid for the same
//! Argon2 verification (or the dummy one) and gets the response of a wrong password.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use nzb_store::prelude::*;
use nzb_store::{LoginUser, SessionStage, StoreError, username_is_valid};
use tokio::sync::Semaphore;

use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, MAX_VERIFY_WAITERS};
use crate::crypto::sha256;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::mfa;
use crate::password::{self, MAX_PASSWORD_CHARS};
use crate::session::{csrf_rejected, enforce_csrf, host_layer, pending_gate, see_other};

/// The one failure text shown for every credential problem.
pub const INVALID_CREDENTIALS: &str = "Invalid credentials";
const EXPIRED_FORM: &str = "This form expired. Please try again.";

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    layout: Layout,
    notice: Option<&'static str>,
    login_token: String,
    username: String,
    // T135 (review 49 L1): no invitation link and no other trace of the instance switches. The
    // page is identical whatever `multi_user`, `registration_enabled` and `invite_path` say, so
    // it tells an anonymous caller neither that invitations exist nor where they are redeemed.
}

pub(crate) fn html(status: StatusCode, body: String) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

pub(crate) fn internal() -> Response {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
}

/// Renders the login form with a fresh single-use token. The token is bound to the `HttpOnly`
/// nonce cookie set on this response: `reuse` keeps the browser's existing nonce (a plain GET,
/// so two open tabs both keep working); `None` mints a new one (after any POST).
fn render_login(
    auth: &AuthState,
    notice: Option<&'static str>,
    username: &str,
    reuse: Option<String>,
) -> Response {
    let nonce = match reuse {
        Some(n) => n,
        None => match csrf::new_login_nonce() {
            Ok(n) => n,
            Err(_) => return internal(),
        },
    };
    let Ok(login_token) = csrf::issue_login_token(&auth.0.token_key, auth.now(), &nonce) else {
        return internal();
    };
    let Some(cookie) = auth.login_nonce_cookie(&nonce) else {
        return internal();
    };
    // Echo the name only when it is a valid username: nothing hostile is reflected, and the
    // output is auto-escaped regardless.
    let username = if username_is_valid(username) {
        username.to_owned()
    } else {
        String::new()
    };
    let page = LoginPage {
        layout: Layout::new("Sign in"),
        notice,
        login_token,
        username,
    };
    match page.render() {
        Ok(body) => {
            let mut resp = html(StatusCode::OK, body);
            resp.headers_mut().append(header::SET_COOKIE, cookie);
            resp
        }
        Err(_) => internal(),
    }
}

async fn get_login(State(auth): State<AuthState>, headers: HeaderMap) -> Response {
    // Already signed in: go to the app. A pending or unknown cookie is simply ignored here.
    if let Ok(Some(s)) = auth.load_session(&headers).await
        && s.stage == SessionStage::Active
    {
        return see_other("/", None);
    }
    render_login(&auth, None, "", auth.presented_login_nonce(&headers))
}

fn is_urlencoded_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        })
}

/// Removes an admitted waiter even if its request is cancelled before a slot is available.
struct PasswordWaiter<'a>(&'a AtomicUsize);

impl Drop for PasswordWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Runs password work with a bounded, cancellation-safe queue. The blocking task owns the
/// permit: dropping its request cannot release capacity while Argon2 is still using memory.
pub(crate) async fn password_work<T, F>(
    slots: &Arc<Semaphore>,
    waiting: &AtomicUsize,
    max_waiters: usize,
    work: F,
) -> Result<T, AuthError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if waiting.fetch_add(1, Ordering::AcqRel) >= max_waiters {
        waiting.fetch_sub(1, Ordering::AcqRel);
        return Err(AuthError::Busy);
    }
    let waiter = PasswordWaiter(waiting);
    let permit = Arc::clone(slots)
        .acquire_owned()
        .await
        .map_err(|_| AuthError::Task)?;
    drop(waiter);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| AuthError::Task)
}

/// One Argon2id verification on the blocking pool, bounded by `verify_concurrency` (each run
/// needs 64 MiB). The wait queue is bounded too (L3): when it is full the request is refused
/// with `AuthError::Busy` instead of piling up until the request timeout.
pub(crate) async fn verify_blocking(
    auth: &AuthState,
    pw: String,
    hash: String,
) -> Result<bool, AuthError> {
    let state = auth.clone();
    password_work(
        &auth.0.verify_slots,
        &auth.0.verify_waiting,
        MAX_VERIFY_WAITERS,
        move || {
            let accepted = password::verify_password(&pw, &hash);
            state.0.verify_runs.fetch_add(1, Ordering::Relaxed);
            accepted
        },
    )
    .await
}

/// Hashes a new password on the blocking pool under the same bounded slots as verification
/// (each Argon2id run needs 64 MiB).
pub(crate) async fn hash_blocking(auth: &AuthState, pw: String) -> Result<String, AuthError> {
    password_work(
        &auth.0.verify_slots,
        &auth.0.verify_waiting,
        MAX_VERIFY_WAITERS,
        move || password::hash_password(&pw),
    )
    .await?
    .map_err(AuthError::from)
}

enum Outcome {
    /// Password accepted; preserve the observed credentials until pending-session insertion.
    PasswordOk(LoginUser),
    Failed,
}

async fn check_credentials(
    auth: &AuthState,
    username: &str,
    password: &str,
    ip: std::net::IpAddr,
) -> Result<Outcome, AuthError> {
    // Cap input BEFORE any hashing or lookup (review M2): name <= 64 bytes, password <= 256 chars.
    let name_ok = username.len() <= nzb_store::MAX_USERNAME_LEN && username_is_valid(username);
    let pw_ok = password.chars().take(MAX_PASSWORD_CHARS + 1).count() <= MAX_PASSWORD_CHARS;
    let user = if name_ok {
        auth.db().get_login_user(username).await?
    } else {
        None
    };
    // One throttle-state read for every attempt, known name or not, before the verification.
    let attempt = auth.attempt(user.as_ref().map(|u| u.id), ip, None).await?;
    let ip_text = ip.to_string();
    // Unknown user, tombstone (`!` sentinel), unusable stored hash: burn the same work against
    // the dummy hash. A disabled account verifies its real hash (same work) and is refused by
    // the verdict below with the answer of a wrong password.
    let (hash, known) = match &user {
        Some(u) if password::hash_is_usable(&u.password_hash) => (u.password_hash.clone(), true),
        _ => (auth.0.dummy_hash.clone(), false),
    };
    // Over-length input is never hashed; a fixed empty probe keeps the cost identical.
    let probe = if pw_ok {
        password.to_owned()
    } else {
        String::new()
    };
    let verified = verify_blocking(auth, probe, hash).await? && known && pw_ok;
    // The verdict (lock re-read, counter, audit row) is ONE writer transaction taken after the
    // verification, identical in shape for every branch (M1, L1). `user` above is only a hint
    // for which hash to verify; its lock fields are never trusted.
    let reason = if pw_ok { "bad_password" } else { "oversize" };
    let accepted = auth
        .db()
        .login_password_step_v2(
            user.as_ref(),
            verified,
            reason,
            &attempt.ctx(),
            Some(&ip_text),
            auth.now(),
        )
        .await?;
    match (accepted, user) {
        (true, Some(u)) => Ok(Outcome::PasswordOk(u)),
        _ => Ok(Outcome::Failed),
    }
}

async fn post_login(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !csrf::same_origin(&headers, !auth.config().insecure_cookies) {
        return csrf_rejected();
    }
    if !is_urlencoded_form(&headers) {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response();
    }
    let form = csrf::parse_form(&body);
    // Token AND the cookie nonce it was issued with, then one-time consumption. Whatever the
    // outcome below, the nonce is rotated: the next form comes with a fresh pair.
    let now = auth.now();
    let token_ok = match (
        auth.presented_login_nonce(&headers),
        csrf::form_get(&form, "login_token"),
    ) {
        (Some(nonce), Some(t)) => csrf::verify_login_token(&auth.0.token_key, now, &nonce, t)
            .is_some_and(|id| auth.0.login_tokens.consume(&id, now)),
        _ => false,
    };
    let username = csrf::form_get(&form, "username").unwrap_or_default();
    if !token_ok {
        // Stale or forged form: no credential check happens, nothing is counted.
        return render_login(&auth, Some(EXPIRED_FORM), username, None);
    }
    let password = csrf::form_get(&form, "password").unwrap_or_default();
    let outcome = match check_credentials(&auth, username, password, ip).await {
        Ok(o) => o,
        Err(AuthError::Busy) => {
            return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "login failed internally");
            return internal();
        }
    };
    let Outcome::PasswordOk(seen) = outcome else {
        return render_login(&auth, Some(INVALID_CREDENTIALS), username, None);
    };
    finish_login(&auth, &seen, username, &headers, ip).await
}

/// Keep the verified credential observation until issuance commits, including when another
/// request changes the password after `check_credentials` returned successfully.
async fn finish_login(
    auth: &AuthState,
    seen: &LoginUser,
    username: &str,
    headers: &HeaderMap,
    ip: std::net::IpAddr,
) -> Response {
    // Fixation: the presented cookie (if any) is revoked and never reused; the new id is fresh.
    let old = auth.presented_id(headers).map(|id| sha256(id.as_bytes()));
    let meta = ClientMeta::from_request(headers, Some(ip));
    match auth.start_login_session(seen, &meta, old.as_ref()).await {
        Ok(cookie) => {
            let mut resp = see_other(
                if seen.totp_enabled {
                    "/login/mfa"
                } else {
                    "/mfa/enroll"
                },
                Some(cookie),
            );
            // The nonce did its job; drop it (the session cookie stays the first Set-Cookie).
            resp.headers_mut()
                .append(header::SET_COOKIE, auth.clear_login_nonce_cookie());
            resp
        }
        Err(AuthError::Store(StoreError::NotFound)) => {
            // The credentials changed between the verdict and the issuance (review 55): audited like
            // the verdict's own `credentials_changed` refusal, and like it not counted as a guess (the
            // password was right). A failed audit write does not change the answer.
            let ip_text = ip.to_string();
            let entry = nzb_store::AuditEntry {
                who: nzb_store::AuditActor::anonymous(),
                event: "login.fail",
                detail: Some("credentials_changed"),
                ip: Some(&ip_text),
                target_id: Some(seen.id),
            };
            if let Err(e) = auth.db().audit_entry(&entry, auth.now()).await {
                tracing::error!(error = %e, "login audit failed");
            }
            render_login(auth, Some(INVALID_CREDENTIALS), username, None)
        }
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            internal()
        }
    }
}

async fn post_logout(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    req: axum::extract::Request,
) -> Response {
    let sess = match auth.load_session(req.headers()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed");
            return internal();
        }
    };
    let Some(sess) = sess else {
        // Nothing to revoke: just drop whatever cookie the browser holds.
        return see_other("/login", Some(auth.clear_cookie()));
    };
    if let Err(resp) = enforce_csrf(&sess, req, !auth.config().insecure_cookies).await {
        return resp;
    }
    if let Err(e) = auth.end_session(&sess).await {
        tracing::error!(error = %e, "session revoke failed");
        return internal();
    }
    // Attributed to the signing-out account (SEC-067); a pending session (nothing completed yet)
    // is anonymous.
    let who = if sess.stage == SessionStage::Active {
        sess.audit_actor()
    } else {
        nzb_store::AuditActor::anonymous()
    };
    let ip_text = ip.to_string();
    let entry = nzb_store::AuditEntry {
        who,
        event: "logout",
        detail: None,
        ip: Some(&ip_text),
        target_id: None,
    };
    if let Err(e) = auth.db().audit_entry(&entry, auth.now()).await {
        tracing::error!(error = %e, "audit write failed");
    }
    see_other("/login", Some(auth.clear_cookie()))
}

/// The login-flow routes (`RouteClass::LoginFlow`), behind the Host allowlist. The MFA steps
/// additionally require a `pending_mfa` session and CSRF.
pub(crate) fn routes(auth: &AuthState) -> Router {
    // The invitation page (at `security.invite_path`) exists only while `security.multi_user` is
    // on (404 for everybody otherwise).
    let invite = if auth.config().multi_user {
        crate::invite::routes(auth)
    } else {
        Router::new()
    };
    let mfa = Router::new()
        .route("/login/mfa", get(mfa::get_verify).post(mfa::post_verify))
        .route("/mfa/enroll", get(mfa::get_enroll).post(mfa::post_enroll))
        .layer(from_fn_with_state(auth.clone(), pending_gate));
    Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/logout", post(post_logout))
        .with_state(auth.clone())
        .merge(invite)
        .merge(mfa.with_state(auth.clone()))
        .layer(from_fn_with_state(auth.clone(), host_layer))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    #[tokio::test]
    #[allow(clippy::panic, clippy::too_many_lines)] // one deterministic before/change/after lifecycle
    async fn sec_107_password_change_after_verdict_refuses_cookie_issuance() {
        use crate::auth::{AuthConfig, COOKIE_NAME, ManualWallClock};
        use axum::body::to_bytes;
        use nzb_store::test_backend::TestStore;

        let dir = tempfile::tempdir().unwrap();
        let test = TestStore::open(dir.path()).await;
        let now = 1_700_000_000;
        let old_password = "old password for the lifecycle fixture";
        let new_password = "new password for the lifecycle fixture";
        let old_hash = password::hash_password(old_password).unwrap();
        let new_hash = password::hash_password(new_password).unwrap();
        let uid = test
            .store
            .create_user("owner", &old_hash, now)
            .await
            .unwrap();
        let auth = AuthState::new(
            test.store.clone(),
            AuthConfig::default(),
            Arc::new(ManualWallClock::new(now)),
        )
        .await
        .unwrap();
        let ip = "192.0.2.7".parse().unwrap();
        let headers = HeaderMap::new();
        let meta = ClientMeta::from_request(&headers, Some(ip));
        let owner = auth
            .prepare_session(uid, SessionStage::Active, &meta)
            .unwrap()
            .0;
        auth.db().insert_session(&owner, 5).await.unwrap();
        let Outcome::PasswordOk(seen) = check_credentials(&auth, "owner", old_password, ip)
            .await
            .unwrap()
        else {
            panic!("the original password must pass before the change");
        };
        let replacement = auth
            .prepare_session(uid, SessionStage::Active, &meta)
            .unwrap()
            .0;
        auth.db()
            .change_password(uid, &owner.id_hash, &new_hash, &replacement, None, now)
            .await
            .unwrap();
        let response = finish_login(&auth, &seen, "owner", &headers, ip).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .all(|cookie| { !cookie.to_str().unwrap().starts_with(COOKIE_NAME) })
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains(INVALID_CREDENTIALS)
        );
        assert!(
            auth.db()
                .get_session(&replacement.id_hash)
                .await
                .unwrap()
                .is_some()
        );
        // Review 55: the refusal is audited like the verdict's own `credentials_changed` refusal.
        let fails: Vec<_> = auth
            .db()
            .recent_audit(50)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.event == "login.fail")
            .collect();
        assert_eq!(fails.len(), 1, "one audit row for the refused issuance");
        let fail = fails.first().unwrap();
        assert_eq!(fail.detail.as_deref(), Some("credentials_changed"));
        assert_eq!(fail.ip.as_deref(), Some("192.0.2.7"));

        // The same handler still sets a pending cookie when the verified hash is current.
        let Outcome::PasswordOk(fresh) = check_credentials(&auth, "owner", new_password, ip)
            .await
            .unwrap()
        else {
            panic!("the replacement password must pass");
        };
        let response = finish_login(&auth, &fresh, "owner", &headers, ip).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/mfa/enroll"
        );
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find(|value| value.to_str().unwrap().starts_with(COOKIE_NAME))
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut request = HeaderMap::new();
        request.insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(
            auth.peek_session(&request).await.unwrap().unwrap().stage,
            SessionStage::PendingMfa
        );
    }

    fn hash_work() -> bool {
        password::hash_password("queue cancellation regression").is_ok()
    }

    fn verify_work() -> bool {
        // Valid bounded work factors, deliberately unrelated digest: still runs full Argon2.
        let phc = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        !password::verify_password("queue cancellation regression", phc)
    }

    async fn cancelled_waiter(work: fn() -> bool) {
        // Both the login and the invitation queue must remain usable after cancellation.
        for limit in [MAX_VERIFY_WAITERS, crate::auth::MAX_INVITE_WAITERS] {
            let slots = Arc::new(Semaphore::new(1));
            let waiting = AtomicUsize::new(0);
            let occupied = slots.acquire().await.unwrap();
            // Repeat beyond the capacity: the old counter leak permanently filled the queue.
            for _ in 0..=limit {
                let mut pending = Box::pin(password_work(&slots, &waiting, limit, work));
                assert!(futures_util::poll!(pending.as_mut()).is_pending());
                assert_eq!(waiting.load(Ordering::Acquire), 1);
                drop(pending);
                assert_eq!(waiting.load(Ordering::Acquire), 0);
            }
            drop(occupied);
            assert!(password_work(&slots, &waiting, limit, work).await.unwrap());
            assert_eq!(slots.available_permits(), 1);
        }
    }

    async fn cancelled_running_work(work: fn() -> bool) {
        let slots = Arc::new(Semaphore::new(1));
        let waiting = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let task_slots = Arc::clone(&slots);
        let task_waiting = Arc::clone(&waiting);
        let request = tokio::spawn(async move {
            password_work(&task_slots, &task_waiting, MAX_VERIFY_WAITERS, move || {
                started_tx.send(()).unwrap();
                // The latch makes cancellation deterministic, without relying on Argon2 speed.
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let result = work();
                let _ = finished_tx.send(result);
                result
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .unwrap()
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(waiting.load(Ordering::Acquire), 0);
        assert_eq!(slots.available_permits(), 0);
        assert!(slots.try_acquire().is_err());
        release_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(10), finished_rx)
                .await
                .unwrap()
                .unwrap()
        );
        // The worker itself releases the slot when the blocking work actually finishes.
        let permit = tokio::time::timeout(Duration::from_secs(10), slots.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_hash_waiter_does_not_poison_queue() {
        cancelled_waiter(hash_work).await;
    }

    #[tokio::test]
    async fn sec_107_cancelled_verify_waiter_does_not_poison_queue() {
        cancelled_waiter(verify_work).await;
    }

    #[tokio::test]
    async fn cancelled_hash_request_keeps_running_work_permit() {
        cancelled_running_work(hash_work).await;
    }

    #[tokio::test]
    async fn sec_107_cancelled_verify_request_keeps_running_work_permit() {
        cancelled_running_work(verify_work).await;
    }

    #[tokio::test]
    async fn password_queue_overflow_and_closed_semaphore_restore_waiter_count() {
        let slots = Arc::new(Semaphore::new(0));
        let waiting = AtomicUsize::new(0);
        let mut pending = Box::pin(password_work(&slots, &waiting, 1, || true));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        assert!(matches!(
            password_work(&slots, &waiting, 1, || true).await,
            Err(AuthError::Busy)
        ));
        assert_eq!(waiting.load(Ordering::Acquire), 1);
        slots.close();
        assert!(matches!(pending.await, Err(AuthError::Task)));
        assert_eq!(waiting.load(Ordering::Acquire), 0);
    }
}
