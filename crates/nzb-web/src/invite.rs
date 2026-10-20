//! Invitation acceptance: `GET/POST` at the invitation path (`security.invite_path`, default
//! `/invite`, T135; anonymous, token-gated; `AUTH_SPEC` "Accounts: creation paths" 3, SEC-061,
//! SEC-063, SEC-064).
//!
//! The page is mounted at the configured path only; with a custom path `/invite` is not routed at
//! all and answers the uniform 404 like any unknown path. The form posts back to the configured
//! path (the visitor already knows it); no other anonymous page names it.
//!
//! The route exists only while `security.multi_user = true` (it is not mounted otherwise). A
//! redemption is NOT registration: the code is an unguessable single-use credential issued by an
//! admin or the operator, and the account name and role come from the invitation row, never from
//! the request.
//!
//! Work shape (SEC-064): the pre-session form token is consumed first (like `/login`), password
//! input mistakes re-render the form and consume nothing, and then the Argon2id hash of the new
//! password is computed BEFORE the code is looked up, on this route's own small queue (one
//! permit, two waiters; overflow is the uniform `503 BUSY`) so an anonymous flood cannot make the
//! owner's login answer `503`. Unknown, malformed, expired, used and revoked codes all take the
//! same path and give the same page.
//!
//! Registration profile (DECISIONS D32, SEC-085): the form also carries an `email` and a
//! `display_name`. They are passed raw to the store, which looks at them only once the code is
//! proven to be a valid invitation (recovery codes ignore them). So their refusals ("invalid
//! display name", "invalid email", "not available") can only ever reach the holder of a valid
//! code; an invalid code answers the generic page whatever the profile says, and that page never
//! echoes the profile. The 3rd "not available" answer cancels the invitation in the store.

use nzb_store::prelude::*;
use std::sync::atomic::Ordering;

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use nzb_store::{
    AccountError, InviteCode, MAX_EMAIL_LEN, MAX_SELF_DISPLAY_NAME_CHARS, Redeemed, Redemption,
    RegistrationProfile, SessionStage,
};

use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, MAX_INVITE_WAITERS};
use crate::crypto;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::login::{html, internal};
use crate::password::{self, MAX_PASSWORD_CHARS};
use crate::session::{csrf_rejected, see_other};

/// The one page for every invitation problem (SEC-064).
pub const INVALID_INVITATION: &str =
    "This invitation is invalid or has expired. Ask an administrator for a new one.";
/// The same page while registration is off (D28): only recovery codes exist then.
const INVALID_RECOVERY: &str =
    "This recovery code is invalid or has expired. Ask an administrator for a new one.";
const EXPIRED_FORM: &str = "This form expired. Please try again.";
const MISMATCH: &str = "The passwords do not match.";
/// Shape refusal of the chosen display name (valid invitation only; nothing consumed).
pub const BAD_DISPLAY_NAME: &str =
    "Display name: 3 to 32 characters, letters, digits, - and _ only.";
/// Shape refusal of the email (valid invitation only; nothing consumed).
pub const BAD_EMAIL: &str = "Enter a valid email address.";
/// The chosen display name is taken or reserved (valid invitation only; counted, D32).
pub const NAME_UNAVAILABLE: &str = "That display name is not available. Choose another one; after 3 refusals the invitation is cancelled.";
/// The 3rd "not available" answer: the store has just revoked the invitation (D32). Only the
/// holder of what was a valid code sees it; any later attempt gets [`INVALID_INVITATION`].
pub const NAME_UNAVAILABLE_REVOKED: &str = "That display name is not available either. This invitation is now cancelled after 3 refusals; ask an administrator for a new one.";

#[derive(Template)]
#[template(path = "invite.html")]
struct InvitePage {
    layout: Layout,
    notice: Option<&'static str>,
    login_token: String,
    /// `false` (D28): only recovery codes are accepted, so the page says so (and the profile
    /// fields are hidden).
    registration: bool,
    /// Echo of the typed email (escaped by askama); empty on the generic invalid page.
    email: String,
    /// Echo of the typed display name (escaped by askama); empty on the generic invalid page.
    display_name: String,
    /// The configured invitation path (form action).
    action: String,
}

/// What a re-rendered form may echo back: the profile fields only, never the code or a password.
/// The generic invalid page uses [`Echo::NONE`] so it stays byte-identical whatever was typed
/// (SEC-064).
#[derive(Clone, Copy)]
struct Echo<'a> {
    email: &'a str,
    display_name: &'a str,
}

impl Echo<'_> {
    const NONE: Echo<'static> = Echo {
        email: "",
        display_name: "",
    };
}

/// At most `max` characters of `s` (the inputs carry the same `maxlength`).
fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Renders the form with a fresh single-use token bound to the nonce cookie (as `/login` does).
fn render(
    auth: &AuthState,
    notice: Option<&'static str>,
    status: StatusCode,
    reuse: Option<String>,
) -> Response {
    render_echo(auth, notice, status, reuse, Echo::NONE)
}

/// [`render`] with the typed profile fields put back into the form.
fn render_echo(
    auth: &AuthState,
    notice: Option<&'static str>,
    status: StatusCode,
    reuse: Option<String>,
    echo: Echo<'_>,
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
    let page = InvitePage {
        layout: Layout::new(if auth.config().registration_enabled {
            "Accept an invitation"
        } else {
            "Redeem a recovery code"
        }),
        notice,
        login_token,
        registration: auth.config().registration_enabled,
        email: clip(echo.email, MAX_EMAIL_LEN),
        display_name: clip(echo.display_name, MAX_SELF_DISPLAY_NAME_CHARS),
        action: auth.config().invite_path.as_str().to_owned(),
    };
    match page.render() {
        Ok(body) => {
            let mut resp = html(status, body);
            resp.headers_mut().append(header::SET_COOKIE, cookie);
            resp
        }
        Err(_) => internal(),
    }
}

async fn get_invite(State(auth): State<AuthState>, headers: HeaderMap) -> Response {
    if let Ok(Some(s)) = auth.load_session(&headers).await
        && s.stage == SessionStage::Active
    {
        return see_other("/", None);
    }
    render(
        &auth,
        None,
        StatusCode::OK,
        auth.presented_login_nonce(&headers),
    )
}

/// Argon2id hash of the chosen password on the `/invite` queue (1 permit, 2 waiters).
async fn hash_on_invite_queue(auth: &AuthState, pw: String) -> Result<String, AuthError> {
    let state = auth.clone();
    crate::login::password_work(
        &auth.0.invite_slots,
        &auth.0.invite_waiting,
        MAX_INVITE_WAITERS,
        move || {
            let hashed = password::hash_password(&pw);
            state.0.verify_runs.fetch_add(1, Ordering::Relaxed);
            hashed
        },
    )
    .await?
    .map_err(AuthError::from)
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

// One linear request pipeline; the order of its steps is the contract (see the module docs).
#[allow(clippy::too_many_lines)]
async fn post_invite(
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
    // The pre-session token AND the nonce cookie it was issued with, consumed once.
    let now = auth.now();
    let token_ok = match (
        auth.presented_login_nonce(&headers),
        csrf::form_get(&form, "login_token"),
    ) {
        (Some(nonce), Some(t)) => csrf::verify_login_token(&auth.0.token_key, now, &nonce, t)
            .is_some_and(|id| auth.0.login_tokens.consume(&id, now)),
        _ => false,
    };
    if !token_ok {
        return render(&auth, Some(EXPIRED_FORM), StatusCode::OK, None);
    }
    // Mass assignment: only `code`, `password`, `password2`, `email` and `display_name` are read;
    // a `role`, `username` or `user_id` in the body is ignored (the invitation row decides). The
    // two profile fields are handed to the store raw and only matter for a valid invitation (D32).
    let code = csrf::form_get(&form, "code").unwrap_or_default();
    let pw = csrf::form_get(&form, "password").unwrap_or_default();
    let pw2 = csrf::form_get(&form, "password2").unwrap_or_default();
    let email = csrf::form_get(&form, "email").unwrap_or_default();
    let display_name = csrf::form_get(&form, "display_name").unwrap_or_default();
    // Echoing what the visitor typed reveals nothing (it came from this very request); the
    // generic invalid page below never echoes, so it stays identical for any input.
    let echo = Echo {
        email,
        display_name,
    };
    // Input-only checks on the password come first and consume nothing. A malformed or
    // wrong-length CODE is deliberately not reported here.
    if pw != pw2 {
        return render_echo(&auth, Some(MISMATCH), StatusCode::OK, None, echo);
    }
    if pw.chars().take(MAX_PASSWORD_CHARS + 1).count() > MAX_PASSWORD_CHARS {
        return render_echo(
            &auth,
            Some("The new password must be at most 256 characters."),
            StatusCode::OK,
            None,
            echo,
        );
    }
    // The one policy of `password::validate_policy` (SEC-022). The "not the username" rule needs
    // the name the code applies to: it is looked up (read-only) for every request, a malformed or
    // unknown code simply yields none, so the work shape is the same. Only the holder of a valid
    // code can ever see that refusal.
    let code_hash = match InviteCode::parse(code) {
        Some(c) => c.hash(),
        None => match crypto::random_bytes::<32>() {
            Ok(r) => crypto::sha256(&r),
            Err(_) => return internal(),
        },
    };
    let name = match auth.db().open_code_login_name(&code_hash, now).await {
        Ok(n) => n.unwrap_or_default(),
        Err(e) => {
            tracing::error!(error = %e, "code lookup failed");
            return internal();
        }
    };
    if let Err(e) = password::validate_policy(&name, pw) {
        return render_echo(
            &auth,
            Some(crate::account::policy_text(&e)),
            StatusCode::OK,
            None,
            echo,
        );
    }
    let phc = match hash_on_invite_queue(&auth, pw.to_owned()).await {
        Ok(h) => h,
        Err(AuthError::Busy) => {
            return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
                .retry_after(5)
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "invitation password hashing failed");
            return internal();
        }
    };
    let meta = ClientMeta::from_request(&headers, Some(ip));
    let (session, cookie, _csrf) = match auth.prepare_session(0, SessionStage::PendingMfa, &meta) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "session preparation failed");
            return internal();
        }
    };
    let ip_text = ip.to_string();
    let replacing = auth
        .presented_id(&headers)
        .map(|old| crypto::sha256(old.as_bytes()));
    let redeemed = auth
        .db()
        .redeem_code_with_profile(
            &Redemption {
                code_hash: &code_hash,
                password_hash: &phc,
                session: &session,
                replacing: replacing.as_ref(),
            },
            &RegistrationProfile {
                email,
                display_name,
            },
            auth.config().account_policy(),
            Some(&ip_text),
            now,
        )
        .await;
    match redeemed {
        // Both purposes continue on the enrollment page; which one it is stays server-side.
        Ok(Redeemed::Account { .. } | Redeemed::Recovery { .. }) => {
            let mut resp = see_other("/mfa/enroll", Some(cookie));
            resp.headers_mut()
                .append(header::SET_COOKIE, auth.clear_login_nonce_cookie());
            resp
        }
        Err(nzb_store::StoreError::Account(AccountError::InvalidCode)) => {
            let text = if auth.config().registration_enabled {
                INVALID_INVITATION
            } else {
                INVALID_RECOVERY
            };
            render(&auth, Some(text), StatusCode::OK, None)
        }
        // D32: these four answers exist only for a valid invitation code (the store checks the
        // code first). Shape refusals consumed nothing; "not available" was counted.
        Err(nzb_store::StoreError::Account(AccountError::InvalidDisplayName)) => {
            render_echo(&auth, Some(BAD_DISPLAY_NAME), StatusCode::OK, None, echo)
        }
        Err(nzb_store::StoreError::Account(AccountError::InvalidEmail)) => {
            render_echo(&auth, Some(BAD_EMAIL), StatusCode::OK, None, echo)
        }
        Err(nzb_store::StoreError::Account(AccountError::DisplayNameUnavailable {
            invite_revoked: false,
        })) => render_echo(&auth, Some(NAME_UNAVAILABLE), StatusCode::OK, None, echo),
        Err(nzb_store::StoreError::Account(AccountError::DisplayNameUnavailable {
            invite_revoked: true,
        })) => render(&auth, Some(NAME_UNAVAILABLE_REVOKED), StatusCode::OK, None),
        Err(e) => {
            tracing::error!(error = %e, "invitation redemption failed");
            internal()
        }
    }
}

/// `GET/POST` at the configured invitation path (merged into the login-flow routes only while
/// `multi_user` is on). [`crate::invite_path::InvitePath`] is valid by construction, so the
/// route syntax cannot be refused here.
pub(crate) fn routes(auth: &AuthState) -> Router {
    Router::new()
        .route(
            auth.config().invite_path.as_str(),
            get(get_invite).post(post_invite),
        )
        .with_state(auth.clone())
}
