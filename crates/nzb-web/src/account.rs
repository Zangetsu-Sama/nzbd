//! The account page (`AUTH_SPEC` §Account page): MFA status, recovery-code regeneration, password
//! change and session management. Everything here sits behind the `active` session gate (CSRF on
//! every POST). Password change and recovery-code regeneration re-authenticate with the current
//! password AND a fresh TOTP code; wrong attempts feed the same lockout counter as login.
//!
//! API keys (T050) live in `account_keys`; this page only renders their section.

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use nzb_store::prelude::*;
use nzb_store::{
    FactorAttempt, SecondFactor, SessionInfo, SessionStage, StoreError, Theme, UserPrefs,
};

use crate::account_keys::{self, KeyView};
use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, SessionCtx};
use crate::crypto;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::login::{hash_blocking, html, internal, verify_blocking};
use crate::mfa::{recovery_response, secret_of_state};
use crate::password::{self, MAX_PASSWORD_CHARS, PasswordError};
use crate::session::see_other;
use crate::totp;

/// Shown for any failed re-authentication (wrong password, wrong code, lock): one text only.
const REAUTH_FAILED: &str = "Verification failed";
/// Warn when fewer recovery codes than this remain.
const LOW_RECOVERY: i64 = 3;

struct SessionView {
    handle: String,
    created: String,
    last_seen: String,
    ip: String,
    user_agent: String,
    current: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
#[allow(clippy::struct_excessive_bools)] // display flags of one page
struct AccountPage {
    layout: Layout,
    csrf_token: String,
    message: Option<&'static str>,
    error: Option<&'static str>,
    recovery_left: i64,
    recovery_low: bool,
    sessions: Vec<SessionView>,
    api_keys: Vec<KeyView>,
    api_keys_active: usize,
    api_keys_max: u32,
    /// The caller's own login name (shown to the account itself).
    username: String,
    /// Handle other accounts see in attribution.
    display_name: String,
    /// `Viewer` / `Uploader` / `Admin` (text badge).
    role_label: &'static str,
    /// Uploaders and admins manage API keys (T103); viewers get no key section.
    show_keys: bool,
    /// The owner column is for admins only (login names are admin-only, D26 d).
    show_key_owner: bool,
    /// "Your sign-in credentials were replaced on ..." (30 days after a recovery).
    replaced_notice: Option<String>,
    /// The caller's own email (D32, SEC-085): read from the caller's own row only, never from
    /// another account; `None` until one is set (CLI-created and pre-2.x accounts).
    email: Option<String>,
    /// The Email row exists only with `security.multi_user = true`: a single-user instance has no invitations, so
    /// there is no way to set one and "not set" would only confuse (`SECURITY_REVIEW` 26.3 c).
    show_email: bool,
    /// The caller's own preferences (T120), as read with the session.
    prefs: PrefsView,
}

/// The Preferences section (T120): the stored values and whether the operator already hides XXX for
/// everyone (`ui.show_xxx = false`), in which case the checkbox is replaced by a note.
struct PrefsView {
    hide_xxx: bool,
    instance_hides_xxx: bool,
    themes: [ThemeChoice; 3],
    /// Releases per page (T133), the allowlisted sizes with the stored one selected.
    release_sizes: Vec<crate::index::Choice>,
    /// Files per page of a release (T133).
    file_sizes: Vec<crate::index::Choice>,
}

struct ThemeChoice {
    value: &'static str,
    label: &'static str,
    checked: bool,
}

fn prefs_view(auth: &AuthState, prefs: UserPrefs) -> PrefsView {
    let choice = |t: Theme, label: &'static str| ThemeChoice {
        value: t.as_str(),
        label,
        checked: prefs.theme == t,
    };
    PrefsView {
        hide_xxx: prefs.hide_xxx,
        instance_hides_xxx: auth
            .config()
            .hidden_categories
            .contains(&nzb_core::XXX_CATEGORY),
        themes: [
            choice(Theme::Auto, "Automatic (follow the device setting)"),
            choice(Theme::Light, "Light"),
            choice(Theme::Dark, "Dark"),
        ],
        release_sizes: crate::page_size::choices(
            nzb_store::ReleasePageSize::CHOICES,
            prefs.page_size_releases.get(),
        ),
        file_sizes: crate::page_size::choices(
            nzb_store::FilePageSize::CHOICES,
            prefs.page_size_files.get(),
        ),
    }
}

/// How long the account page keeps the "credentials were replaced" notice.
const REPLACED_NOTICE_SECS: i64 = 30 * 86_400;

/// Formats unix seconds as `YYYY-MM-DD HH:MM UTC` (civil-from-days, no time crate needed).
#[must_use]
pub fn fmt_utc(ts: i64) -> String {
    // Clamp to years 1970..9999 so the arithmetic below cannot overflow.
    let ts = ts.clamp(0, 253_402_300_799);
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn view(s: &SessionInfo, current: &[u8; 32]) -> SessionView {
    SessionView {
        handle: crypto::hex(&s.id_hash),
        created: fmt_utc(s.created_at),
        last_seen: fmt_utc(s.last_seen_at),
        // Client-supplied text: shown through askama autoescape only (review L7).
        ip: s.ip.clone().unwrap_or_default(),
        user_agent: s.user_agent.clone().unwrap_or_default(),
        current: &s.id_hash == current,
    }
}

pub(crate) async fn render_account(
    auth: &AuthState,
    sess: &SessionCtx,
    message: Option<&'static str>,
    error: Option<&'static str>,
) -> Response {
    let left = auth.db().count_unused_recovery_codes(sess.user_id).await;
    let list = auth
        .db()
        .list_active_sessions(sess.user_id, auth.now())
        .await;
    // Uploaders manage their own keys, admins every key (T103); viewers cannot upload, so they own none.
    let show_keys = sess.role >= nzb_store::Role::Uploader;
    let show_key_owner = sess.role == nzb_store::Role::Admin;
    let keys = if show_keys {
        account_keys::key_views(auth, sess).await
    } else {
        Some((Vec::new(), 0))
    };
    let (Ok(left), Ok(list), Some((api_keys, api_keys_active))) = (left, list, keys) else {
        tracing::error!("account page queries failed");
        return internal();
    };
    let own = match auth.db().get_account(sess.user_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed");
            return internal();
        }
    };
    let email = own.as_ref().and_then(|a| a.email.clone());
    let replaced_notice = match own {
        Some(a) => match a.credentials_replaced_at {
            Some(at) if auth.now().saturating_sub(at) <= REPLACED_NOTICE_SECS => {
                let issuer = match a.credentials_replaced_by {
                    Some(id) => match auth.db().get_account(id).await {
                        Ok(Some(i)) if i.is_live() => i.handle(),
                        Ok(Some(_)) => "a deleted account".to_owned(),
                        _ => "an administrator".to_owned(),
                    },
                    None => "the operator".to_owned(),
                };
                Some(format!(
                    "Your sign-in credentials were replaced on {} through a recovery issued by {issuer}.",
                    fmt_utc(at)
                ))
            }
            _ => None,
        },
        None => None,
    };
    let page = AccountPage {
        layout: Layout::for_session("Account", sess),
        csrf_token: sess.csrf_token.clone(),
        message,
        error,
        recovery_left: left,
        recovery_low: left < LOW_RECOVERY,
        sessions: list.iter().map(|s| view(s, &sess.id_hash)).collect(),
        api_keys,
        api_keys_active,
        api_keys_max: account_keys::max_keys(),
        username: sess.username.clone(),
        display_name: sess.display_name.clone(),
        role_label: role_label(sess.role),
        show_keys,
        show_key_owner,
        replaced_notice,
        email,
        show_email: auth.config().multi_user,
        prefs: prefs_view(auth, sess.prefs),
    };
    page.render()
        .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

async fn get_account(
    State(auth): State<AuthState>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    render_account(&auth, &sess, None, None).await
}

/// Text of a role badge.
pub(crate) const fn role_label(r: nzb_store::Role) -> &'static str {
    match r {
        nzb_store::Role::Viewer => "Viewer",
        nzb_store::Role::Uploader => "Uploader",
        nzb_store::Role::Admin => "Admin",
    }
}

/// Re-authenticates the signed-in user: current password and a fresh TOTP code, in one verdict
/// transaction (`precondition_ok` carries the password result), so the response and the lockout
/// accounting are identical whichever half was wrong. The verdict is the store's `_v2` one: it
/// feeds the per-(account, address) lock and the persisted aggregate, and a throttled attempt has
/// already paid for the same verification (SEC-064, SEC-066).
#[allow(clippy::result_large_err)]
pub(crate) async fn reauth(
    auth: &AuthState,
    sess: &SessionCtx,
    ip: &str,
    purpose: &'static str,
    form: &[(String, String)],
) -> Result<bool, Response> {
    let busy = || ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY").into_response();
    let user = match auth.db().get_login_user_by_id(sess.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return Err(internal());
        }
    };
    let st = match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "mfa lookup failed");
            return Err(internal());
        }
    };
    let Some(secret) = secret_of_state(auth, sess.user_id, &st) else {
        tracing::error!("TOTP secret unavailable; refusing re-authentication");
        return Err(internal());
    };
    let password = csrf::form_get(form, "current_password").unwrap_or_default();
    let code = csrf::form_get(form, "code").unwrap_or_default();
    // Same input discipline as login: cap first, never hash over-length input.
    let pw_ok_len = password.chars().take(MAX_PASSWORD_CHARS + 1).count() <= MAX_PASSWORD_CHARS;
    let (hash, known) = if password::hash_is_usable(&user.password_hash) {
        (user.password_hash.clone(), true)
    } else {
        (auth.0.dummy_hash.clone(), false)
    };
    let probe = if pw_ok_len {
        password.to_owned()
    } else {
        String::new()
    };
    let verified = match verify_blocking(auth, probe, hash).await {
        Ok(v) => v && known && pw_ok_len,
        Err(AuthError::Busy) => return Err(busy()),
        Err(e) => {
            tracing::error!(error = %e, "password verification failed");
            return Err(internal());
        }
    };
    let now = auth.now();
    let step = totp::parse_totp_code(code).and_then(|c| totp::matching_step(&secret, now, &c));
    let ip_addr = ip.parse::<std::net::IpAddr>().ok();
    let attempt = match auth
        .attempt(
            Some(sess.user_id),
            ip_addr.unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
            None,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "throttle state failed");
            return Err(internal());
        }
    };
    match auth
        .db()
        .second_factor_step_v2(
            FactorAttempt {
                user_id: sess.user_id,
                precondition_ok: verified,
                factor: SecondFactor::Totp(step),
                purpose,
                ip: Some(ip),
                now,
            },
            &attempt.ctx(),
        )
        .await
    {
        Ok(v) => Ok(v.accepted),
        Err(e) => {
            tracing::error!(error = %e, "re-authentication verdict failed");
            Err(internal())
        }
    }
}

pub(crate) const fn policy_text(e: &PasswordError) -> &'static str {
    match e {
        PasswordError::TooShort => "The new password must be at least 12 characters.",
        PasswordError::TooLong => "The new password must be at most 256 characters.",
        PasswordError::SameAsUsername => "The new password must differ from the username.",
        PasswordError::ControlChars => "The new password must not contain control characters.",
        PasswordError::TooFewDistinct => {
            "The new password must contain at least 6 different characters."
        }
        PasswordError::NoAlphanumeric => "The new password must contain letters or digits.",
        PasswordError::Pattern => {
            "The new password must not be a keyboard or sequence pattern such as qwertyuiopas."
        }
        PasswordError::Common => "The new password is too common. Choose a less guessable one.",
        PasswordError::Hash => "The new password could not be processed.",
    }
}

async fn post_password(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let form = csrf::parse_form(&body);
    let new = csrf::form_get(&form, "new_password").unwrap_or_default();
    let confirm = csrf::form_get(&form, "confirm_password").unwrap_or_default();
    let username = match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(st)) => st.username,
        Ok(None) => return see_other("/login", None),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return internal();
        }
    };
    // Input-only checks first: they reveal nothing and must not burn the user's TOTP step.
    if new != confirm {
        return render_account(&auth, &sess, None, Some("The new passwords do not match.")).await;
    }
    if let Err(e) = password::validate_policy(&username, new) {
        return render_account(&auth, &sess, None, Some(policy_text(&e))).await;
    }
    let ip_text = ip.to_string();
    match reauth(&auth, &sess, &ip_text, "password_change", &form).await {
        Ok(true) => {}
        Ok(false) => return render_account(&auth, &sess, None, Some(REAUTH_FAILED)).await,
        Err(r) => return r,
    }
    let hash = match hash_blocking(&auth, new.to_owned()).await {
        Ok(h) => h,
        Err(AuthError::Busy) => {
            return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "password hashing failed");
            return internal();
        }
    };
    // Every session (including this one) is revoked; the caller continues on a fresh id, inserted
    // in the same transaction, which refuses if this session died meanwhile (a recovery, reset or
    // revocation must not be undone by a change that was already re-authenticated).
    let meta = ClientMeta::from_request(&headers, Some(ip));
    let (new_session, cookie, _) =
        match auth.prepare_session(sess.user_id, SessionStage::Active, &meta) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "session preparation failed");
                return internal();
            }
        };
    match auth
        .db()
        .change_password(
            sess.user_id,
            &sess.id_hash,
            &hash,
            &new_session,
            Some(&ip_text),
            auth.now(),
        )
        .await
    {
        Ok(()) => see_other("/account", Some(cookie)),
        Err(StoreError::NotFound) => see_other("/login", Some(auth.clear_cookie())),
        Err(e) => {
            tracing::error!(error = %e, "password change failed");
            internal()
        }
    }
}

async fn post_recovery(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let form = csrf::parse_form(&body);
    let ip_text = ip.to_string();
    match reauth(&auth, &sess, &ip_text, "recovery_regen", &form).await {
        Ok(true) => {}
        Ok(false) => return render_account(&auth, &sess, None, Some(REAUTH_FAILED)).await,
        Err(r) => return r,
    }
    let Ok(codes) = totp::generate_recovery_codes() else {
        return internal();
    };
    let hashes: Vec<[u8; 32]> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    match auth
        .db()
        .replace_recovery_codes(
            sess.user_id,
            &sess.id_hash,
            &hashes,
            Some(&ip_text),
            auth.now(),
        )
        .await
    {
        Ok(()) => {}
        Err(StoreError::NotFound) => return see_other("/login", Some(auth.clear_cookie())),
        Err(e) => {
            tracing::error!(error = %e, "recovery code replacement failed");
            return internal();
        }
    }
    recovery_response(
        Layout::for_session("Recovery codes", &sess),
        "New recovery codes",
        &codes,
        "/account",
        "Back to the account page",
        None,
    )
}

async fn post_revoke(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let form = csrf::parse_form(&body);
    let target = csrf::form_get(&form, "session")
        .filter(|h| h.len() == 64)
        .and_then(crypto::unhex)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let Some(target) = target else {
        return render_account(&auth, &sess, None, Some("That session could not be found.")).await;
    };
    if target == sess.id_hash {
        return render_account(
            &auth,
            &sess,
            None,
            Some("Use Log out to end the current session."),
        )
        .await;
    }
    match auth
        .db()
        .revoke_user_session(
            sess.user_id,
            &sess.id_hash,
            &target,
            Some(&ip.to_string()),
            auth.now(),
        )
        .await
    {
        Ok(true) => render_account(&auth, &sess, Some("Session revoked."), None).await,
        Ok(false) => {
            render_account(&auth, &sess, None, Some("That session could not be found.")).await
        }
        Err(StoreError::NotFound) => see_other("/login", Some(auth.clear_cookie())),
        Err(e) => {
            tracing::error!(error = %e, "session revoke failed");
            internal()
        }
    }
}

async fn post_revoke_others(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    match auth
        .db()
        .revoke_other_sessions(
            sess.user_id,
            &sess.id_hash,
            Some(&ip.to_string()),
            auth.now(),
        )
        .await
    {
        Ok(_) => render_account(&auth, &sess, Some("All other sessions were revoked."), None).await,
        Err(StoreError::NotFound) => see_other("/login", Some(auth.clear_cookie())),
        Err(e) => {
            tracing::error!(error = %e, "session revoke failed");
            internal()
        }
    }
}

/// Single-value fields of the preferences form: a repeated one is refused, never "first wins".
const PREF_SINGLETONS: &[&str] = &[
    "csrf_token",
    "theme",
    "hide_xxx",
    "page_size_releases",
    "page_size_files",
];
/// Fields the preferences form may carry at most (token, theme, flag, two page sizes, slack).
const PREF_MAX_FIELDS: usize = 8;

/// `POST /account/preferences` (T120): the caller's own "Hide XXX for me" and theme. Session + CSRF +
/// Origin (the gate), any role, UI rate class plus [`crate::auth::PREF_SAVES_PER_MIN`] requests per account
/// and minute (`429 RATE_LIMITED`, review 37 L3). Strict input: `theme` is exactly `auto`/`light`/`dark`, `hide_xxx`
/// absent/`0`/`1`, no repeated field; anything else is `400 BAD_REQUEST` (never echoed). The page sizes (T133)
/// `page_size_releases` / `page_size_files` take an allowlisted value and ignore any other (the stored one
/// stays). The store
/// re-validates the actor and audits the changed key names only (`pref_change keys=...`). The page is
/// rendered again with the new values applied to this response (theme, hidden set).
async fn post_preferences(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    // Every request counts, whatever its outcome (like the bulk edit budget): the audit log cannot be flooded.
    if let crate::ratelimit::Decision::Deny { retry_after_secs } =
        auth.0.pref_saves.check(sess.user_id)
    {
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
            .retry_after(retry_after_secs)
            .into_response();
    }
    let bad = || ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response();
    let Some(form) = csrf::parse_form_strict(&body, PREF_MAX_FIELDS) else {
        return bad();
    };
    if !csrf::singletons_ok(&form, PREF_SINGLETONS) {
        return bad();
    }
    let Some(theme) = csrf::form_get(&form, "theme").and_then(Theme::parse) else {
        return bad();
    };
    let hide_xxx = match csrf::form_get(&form, "hide_xxx") {
        None | Some("0") => false,
        Some("1") => true,
        Some(_) => return bad(),
    };
    // Page sizes (T133): an allowlisted value is taken; an absent or other value is ignored (the stored choice stays),
    // never an error, like the "Per page" control under the tables.
    let page_size_releases = csrf::form_get(&form, "page_size_releases")
        .and_then(nzb_store::ReleasePageSize::parse)
        .unwrap_or(sess.prefs.page_size_releases);
    let page_size_files = csrf::form_get(&form, "page_size_files")
        .and_then(nzb_store::FilePageSize::parse)
        .unwrap_or(sess.prefs.page_size_files);
    let prefs = UserPrefs {
        hide_xxx,
        theme,
        page_size_releases,
        page_size_files,
    };
    // Only the fields this form changes relative to the row read with the session are written, applied to the row as
    // it is inside the write transaction (T133 review 48 L1): a page size stored by "Per page" a moment earlier (or
    // concurrently) is not reverted by a form that merely re-sent it.
    let patch = nzb_store::PrefsPatch::between(sess.prefs, prefs);
    match auth
        .db()
        .patch_user_prefs_as(&sess.actor(), patch, Some(&ip.to_string()), auth.now())
        .await
    {
        Ok(changed) => {
            // Render what is stored now (the patch merged with any concurrent change).
            let prefs = match auth.db().user_prefs(sess.user_id).await {
                Ok(p) => p,
                Err(_) => patch.applied_to(sess.prefs),
            };
            let mut now = sess.clone();
            now.prefs = prefs;
            now.hidden_categories = auth.hidden_for(prefs);
            let msg = if changed {
                "Preferences saved."
            } else {
                "Nothing changed."
            };
            render_account(&auth, &now, Some(msg), None).await
        }
        Err(StoreError::Account(nzb_store::AccountError::Forbidden)) => {
            ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "preference change failed");
            internal()
        }
    }
}

/// The account routes (`RouteClass::Session`). Merge them into the `session_routes` handed to
/// [`crate::router_with_auth`] so they sit behind the active-session gate and CSRF.
pub fn account_routes(auth: &AuthState) -> Router {
    Router::new()
        .route("/account", get(get_account))
        .route("/account/password", post(post_password))
        .route("/account/recovery-codes", post(post_recovery))
        .route("/account/sessions/revoke", post(post_revoke))
        .route("/account/sessions/revoke-others", post(post_revoke_others))
        .route("/account/preferences", post(post_preferences))
        .with_state(auth.clone())
        .merge(account_keys::routes(auth))
}

#[cfg(test)]
mod tests {
    use super::fmt_utc;

    #[test]
    fn utc_formatting_known_values() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(fmt_utc(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(fmt_utc(i64::MAX), "9999-12-31 23:59 UTC");
        assert_eq!(fmt_utc(-5), "1970-01-01 00:00 UTC");
    }
}
