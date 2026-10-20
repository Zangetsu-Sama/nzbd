//! The Users page and the account actions behind it (`GET /admin/users` and friends; T101,
//! `AUTH_SPEC` "Target rules for `/admin/users/{id}/*`", SEC-061, SEC-062, SEC-063).
//!
//! Every route here is admin-only, exists only while `security.multi_user = true` (the access
//! gate answers the uniform 404 otherwise) and is mounted with its access declared in
//! [`crate::routes::INVENTORY`]. The `{id}` is a *target*: it is authorized against the actor,
//! the target's role and the rules below, and the store's writers re-read the target inside their
//! transaction (the form is never trusted for the role).
//!
//! * The HTTP role domain is `uploader`/`viewer` ([`GrantableRole`]); an `admin` value fails to
//!   parse (400). No handler can create, promote, demote, disable, enable, unlock, delete or
//!   recover an admin: the only HTTP action on an admin target is `revoke-sessions` with the
//!   acting admin's password and a fresh TOTP code.
//! * Re-authentication reuses the shared second-factor verdict (same lock and aggregate as the
//!   login), so a stolen session (session + CSRF, no password or TOTP) can neither mint codes nor
//!   change roles.
//! * Refusals by the target rules are `409` with a fixed alert text, a re-rendered Users page and
//!   an audit row; nothing request-derived is echoed.

use nzb_store::prelude::*;
use std::collections::{HashMap, HashSet};

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use nzb_store::{
    AccountError, AccountRow, AuditEntry, GrantableRole, InviteCode, InviteRow, NewInvite,
    NewRecovery, Role, StoreError,
};

use crate::account::{fmt_utc, reauth, role_label};
use crate::assets::Layout;
use crate::auth::{AuthState, SessionCtx};
use crate::crypto;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::login::{html, internal};
use crate::release::{not_found, parse_id};
use crate::session::see_other;

/// Tombstones stay listed (muted) for this long; older ones remain in the audit trail only.
const TOMBSTONE_SHOWN_SECS: i64 = 30 * 86_400;

const ALERT_SELF: &str = "You cannot change your own account here.";
const ALERT_CLI: &str = "Administrators are managed with the nzbd command line.";
const ALERT_LAST_ADMIN: &str = "At least one active administrator is required.";
const ALERT_NAME: &str = "That username is not available.";
const ALERT_DISPLAY: &str = "That display name is not available.";
/// A session seen within this many seconds counts as "online" (sessions are touched once a minute).
const ONLINE_WINDOW_SECS: i64 = 300;
const ALERT_DISABLE_FIRST: &str = "The account must be disabled first.";
const ALERT_STATE: &str = "That action does not apply to this account right now.";
const ALERT_LIMIT: &str = "The limit of accounts or open invitations is reached.";
const ALERT_REAUTH: &str = "Verification failed";

#[derive(Clone)]
struct St {
    auth: AuthState,
}

// ---------------------------------------------------------------------------------------------
// Views

#[allow(clippy::struct_excessive_bools)] // display flags of one table row
struct UserView {
    id: i64,
    /// Login name: this page is admin-only, so it is shown here (escaped by askama).
    username: String,
    display: String,
    /// Email (D32, SEC-085): admin-only by construction (this page is admin-only), escaped by
    /// askama; empty for tombstones (the store clears it at deletion anyway).
    email: Option<String>,
    role: &'static str,
    deleted: bool,
    disabled: bool,
    is_self: bool,
    is_admin: bool,
    last_admin: bool,
    reserved_form: bool,
    /// "Credentials replaced <time> (recovery by <name>)".
    replaced: Option<String>,
    /// "Recovery pending (staged, redeemed <time>)".
    recovery_pending: Option<String>,
    locked: bool,
    online: bool,
    mfa_missing: bool,
    last_login: String,
    sessions: i64,
    created_by: String,
}

struct InviteView {
    id: i64,
    kind: &'static str,
    /// The reserved login name (invitation) or the target's display handle (recovery).
    subject: String,
    role: &'static str,
    created_by: String,
    expires: String,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersPage {
    layout: Layout,
    csrf_token: String,
    alert: Option<&'static str>,
    users: Vec<UserView>,
    invites: Vec<InviteView>,
    max_accounts: u32,
    /// `security.registration_enabled` (D28): the invite button is hidden when off.
    registration: bool,
}

#[derive(Template)]
#[template(path = "user_action.html")]
struct ActionPage {
    layout: Layout,
    csrf_token: String,
    /// `role`, `enable`, `recover`, `delete` or `revoke-sessions` (a fixed set).
    action: &'static str,
    heading: &'static str,
    explain: &'static str,
    button: &'static str,
    danger: bool,
    reauth: bool,
    id: i64,
    target_display: String,
    target_username: String,
    target_role: &'static str,
    /// Only the role page: the role the form offers first.
    other_role: &'static str,
    other_role_label: &'static str,
    alert: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "user_invite.html")]
struct InviteFormPage {
    layout: Layout,
    csrf_token: String,
    alert: Option<&'static str>,
    /// Public form choices retained after a refusal; credentials are never echoed.
    username: String,
    uploader: bool,
}

#[derive(Template)]
#[template(path = "invite_created.html")]
struct CodePage {
    layout: Layout,
    heading: &'static str,
    username: String,
    role: &'static str,
    code: String,
    /// Whether a public address is configured (`server.public_url` or the first allowed host).
    has_address: bool,
    /// The invitation page to hand out: the full URL when an address is configured, else the
    /// configured path alone (T135).
    invite_url: String,
    expires: String,
    is_recovery: bool,
}

fn render<T: Template>(status: StatusCode, t: &T) -> Response {
    match t.render() {
        Ok(body) => {
            let mut resp = html(status, body);
            if status == StatusCode::CONFLICT {
                // A refusal page (`409`) with its fixed alert text is the answer, not the
                // uniform error body.
                resp.extensions_mut()
                    .insert(crate::error::KeepBody(StatusCode::CONFLICT));
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "users page render failed");
            internal()
        }
    }
}

fn handle_of(accounts: &HashMap<i64, AccountRow>, id: Option<i64>) -> String {
    match id {
        None => "operator".to_owned(),
        Some(i) => match accounts.get(&i) {
            Some(a) if a.is_live() => a.handle(),
            Some(_) => "Deleted account".to_owned(),
            None => "unknown".to_owned(),
        },
    }
}

#[allow(clippy::too_many_lines)] // one view assembly
async fn users_page(
    st: &St,
    sess: &SessionCtx,
    status: StatusCode,
    alert: Option<&'static str>,
) -> Response {
    let auth = &st.auth;
    let now = auth.now();
    let db = auth.db();
    let (accounts, invites, locked, counts, online) = match tokio::try_join!(
        db.list_accounts(true),
        db.list_open_invites(now),
        db.locked_account_ids(now),
        db.active_session_counts(now),
        db.online_account_ids(now, now.saturating_sub(ONLINE_WINDOW_SECS)),
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "users page queries failed");
            return internal();
        }
    };
    let reserved: HashSet<i64> = match db.reserved_login_accounts().await {
        Ok(v) => v
            .into_iter()
            .filter(|r| r.kind == nzb_store::ReservedKind::HandleForm)
            .map(|r| r.id)
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "reserved account lookup failed");
            return internal();
        }
    };
    let locked: HashSet<i64> = locked.into_iter().collect();
    let online: HashSet<i64> = online.into_iter().collect();
    let counts: HashMap<i64, i64> = counts.into_iter().collect();
    let enabled_admins = accounts
        .iter()
        .filter(|a| a.is_enabled() && a.role == Role::Admin)
        .count();
    let by_id: HashMap<i64, AccountRow> = accounts.iter().map(|a| (a.id, a.clone())).collect();
    let users: Vec<UserView> = accounts
        .iter()
        .filter(|a| {
            a.deleted_at
                .is_none_or(|d| now.saturating_sub(d) <= TOMBSTONE_SHOWN_SECS)
        })
        .map(|a| UserView {
            id: a.id,
            username: if a.is_live() {
                a.username.clone()
            } else {
                String::new()
            },
            display: a.handle(),
            email: if a.is_live() { a.email.clone() } else { None },
            role: role_label(a.role),
            deleted: !a.is_live(),
            disabled: a.disabled_at.is_some(),
            is_self: a.id == sess.user_id,
            is_admin: a.role == Role::Admin,
            last_admin: a.role == Role::Admin && a.is_enabled() && enabled_admins == 1,
            reserved_form: reserved.contains(&a.id),
            replaced: a.credentials_replaced_at.map(|t| {
                format!(
                    "Credentials replaced {} (recovery by {})",
                    fmt_utc(t),
                    handle_of(&by_id, a.credentials_replaced_by)
                )
            }),
            recovery_pending: a
                .recovery_staged_at
                .map(|t| format!("Recovery pending (staged, redeemed {})", fmt_utc(t))),
            locked: a.is_live() && locked.contains(&a.id),
            online: a.is_enabled() && online.contains(&a.id),
            mfa_missing: a.is_live() && !a.totp_enabled,
            last_login: a.last_login_at.map_or_else(|| "never".to_owned(), fmt_utc),
            sessions: counts.get(&a.id).copied().unwrap_or(0),
            created_by: handle_of(&by_id, a.created_by),
        })
        .collect();
    let invites: Vec<InviteView> = invites
        .iter()
        .map(|i: &InviteRow| InviteView {
            id: i.id,
            kind: match i.purpose {
                nzb_store::InvitePurpose::Invite => "Invitation",
                nzb_store::InvitePurpose::Recover => "Recovery code",
            },
            subject: match i.purpose {
                nzb_store::InvitePurpose::Invite => i.username.clone().unwrap_or_default(),
                nzb_store::InvitePurpose::Recover => match i.user_id.and_then(|u| by_id.get(&u)) {
                    Some(a) => a.handle(),
                    None => String::new(),
                },
            },
            role: i.role.map_or("", role_label),
            created_by: handle_of(&by_id, i.created_by),
            expires: fmt_utc(i.expires_at),
        })
        .collect();
    render(
        status,
        &UsersPage {
            layout: Layout::for_session("Users", sess),
            csrf_token: sess.csrf_token.clone(),
            alert,
            users,
            invites,
            max_accounts: auth.config().max_accounts,
            registration: auth.config().registration_enabled,
        },
    )
}

async fn list(State(st): State<St>, Extension(sess): Extension<SessionCtx>) -> Response {
    users_page(&st, &sess, StatusCode::OK, None).await
}

// ---------------------------------------------------------------------------------------------
// Actions on a target

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Role,
    Disable,
    Enable,
    Unlock,
    RevokeSessions,
    Recover,
    CancelRecovery,
    Delete,
    DisplayName,
}

impl Action {
    /// Audit/refusal tag (a fixed lowercase word).
    const fn tag(self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Unlock => "unlock",
            Self::RevokeSessions => "revoke_sessions",
            Self::Recover => "recover",
            Self::CancelRecovery => "recover_cancel",
            Self::Delete => "delete",
            Self::DisplayName => "display_name",
        }
    }

    /// The `purpose` of the shared second-factor verdict.
    const fn purpose(self) -> &'static str {
        match self {
            Self::Role => "user_role",
            Self::Enable => "user_enable",
            Self::Recover => "user_recover",
            Self::Delete => "user_delete",
            _ => "user_revoke_sessions",
        }
    }
}

/// A target-rule refusal known before any credential is looked at.
fn pre_refusal(action: Action, sess: &SessionCtx, target: &AccountRow) -> Option<&'static str> {
    let is_self = target.id == sess.user_id;
    if is_self && action != Action::DisplayName {
        return Some(ALERT_SELF);
    }
    if target.role == Role::Admin && !is_self && action != Action::RevokeSessions {
        return Some(ALERT_CLI);
    }
    None
}

/// The fixed alert of a store refusal; `None` = not a rule refusal (404 or 500 by the caller).
fn alert_for(e: &StoreError) -> Option<&'static str> {
    let StoreError::Account(a) = e else {
        return match e {
            StoreError::InvalidUsername => Some(ALERT_NAME),
            _ => None,
        };
    };
    match a {
        AccountError::SelfTarget => Some(ALERT_SELF),
        AccountError::AdminIsCliOnly => Some(ALERT_CLI),
        AccountError::LastAdmin | AccountError::LastUsableAdmin => Some(ALERT_LAST_ADMIN),
        AccountError::NotDisabled => Some(ALERT_DISABLE_FIRST),
        AccountError::InvalidState | AccountError::StagingInvalid => Some(ALERT_STATE),
        AccountError::UsernameUnavailable | AccountError::ReservedName => Some(ALERT_NAME),
        AccountError::DisplayNameTaken
        | AccountError::InvalidDisplayName
        | AccountError::DisplayNameUnavailable { .. } => Some(ALERT_DISPLAY),
        AccountError::AccountLimit
        | AccountError::TooManyOpenInvites
        | AccountError::MultiUserDisabled => Some(ALERT_LIMIT),
        _ => None,
    }
}

/// A refused action: the audit row, then the Users page with the fixed alert (409).
async fn refused(
    st: &St,
    sess: &SessionCtx,
    ip: &str,
    action: Action,
    target: i64,
    alert: &'static str,
) -> Response {
    let detail = format!("action={}", action.tag());
    let entry = AuditEntry {
        who: sess.audit_actor(),
        event: "user_action_refused",
        detail: Some(&detail),
        ip: Some(ip),
        target_id: Some(target),
    };
    if let Err(e) = st.auth.db().audit_entry(&entry, st.auth.now()).await {
        tracing::error!(error = %e, "audit write failed");
    }
    users_page(st, sess, StatusCode::CONFLICT, Some(alert)).await
}

/// Maps a failed store call: a rule refusal is a 409 page, a vanished account or lost role the
/// uniform 404, anything else a 500.
async fn failed(
    st: &St,
    sess: &SessionCtx,
    ip: &str,
    action: Action,
    target: i64,
    e: StoreError,
) -> Response {
    if let Some(alert) = alert_for(&e) {
        return refused(st, sess, ip, action, target, alert).await;
    }
    match e {
        StoreError::Account(AccountError::TargetNotFound | AccountError::Forbidden) => not_found(),
        other => {
            tracing::error!(error = %other, "account action failed");
            internal()
        }
    }
}

fn confirm_text(action: Action) -> (&'static str, &'static str, &'static str, bool, bool) {
    // (heading, explanation, button, danger, needs re-authentication for a uploader/viewer target)
    match action {
        Action::Role => (
            "Change role",
            "The account's sessions are signed out and any open recovery code for it is revoked.",
            "Change role",
            false,
            true,
        ),
        Action::Enable => (
            "Enable account",
            "The account can sign in again with its existing password and authenticator.",
            "Enable account",
            false,
            true,
        ),
        Action::Recover => (
            "Issue a recovery code",
            "A single-use code is shown once. Whoever redeems it chooses a new password and a new authenticator, but nothing changes until they confirm; the current credentials keep working until then.",
            "Issue recovery code",
            true,
            true,
        ),
        Action::Delete => (
            "Delete account",
            "The account is removed for good: its credentials, sessions and keys are destroyed and its name is freed. Releases it added stay in the library.",
            "Delete account",
            true,
            true,
        ),
        _ => (
            "Revoke sessions",
            "Every signed-in session of the account is ended.",
            "Revoke sessions",
            false,
            false,
        ),
    }
}

fn action_page(
    sess: &SessionCtx,
    action: Action,
    target: &AccountRow,
    alert: Option<&'static str>,
) -> ActionPage {
    let (heading, explain, button, danger, target_reauth) = confirm_text(action);
    // Revoking the sessions of an ADMIN is the one admin-target action; it re-authenticates.
    let reauth = target_reauth || (action == Action::RevokeSessions && target.role == Role::Admin);
    let (other_role, other_role_label) = if target.role == Role::Uploader {
        ("viewer", "Viewer")
    } else {
        ("uploader", "Uploader")
    };
    ActionPage {
        layout: Layout::for_session("User action", sess),
        csrf_token: sess.csrf_token.clone(),
        action: match action {
            Action::Role => "role",
            Action::Enable => "enable",
            Action::Recover => "recover",
            Action::Delete => "delete",
            _ => "revoke-sessions",
        },
        heading,
        explain,
        button,
        danger,
        reauth,
        id: target.id,
        target_display: target.handle(),
        target_username: target.username.clone(),
        target_role: role_label(target.role),
        other_role,
        other_role_label,
        alert,
    }
}

/// `GET /admin/users/{id}/<action>`: the confirmation page. It renders only the escaped display
/// name, login name and role of the target (admin-only pages), then the form.
async fn get_confirm(st: &St, sess: &SessionCtx, id_raw: &str, action: Action) -> Response {
    let Some(id) = parse_id(id_raw) else {
        return not_found();
    };
    let target = match st.auth.db().get_account(id).await {
        Ok(Some(a)) if a.is_live() => a,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed");
            return internal();
        }
    };
    if let Some(alert) = pre_refusal(action, sess, &target) {
        return refused(st, sess, "-", action, target.id, alert).await;
    }
    render(StatusCode::OK, &action_page(sess, action, &target, None))
}

macro_rules! confirm_route {
    ($name:ident, $action:expr) => {
        async fn $name(
            State(st): State<St>,
            Extension(sess): Extension<SessionCtx>,
            Path(id): Path<String>,
        ) -> Response {
            get_confirm(&st, &sess, &id, $action).await
        }
    };
}
confirm_route!(get_role, Action::Role);
confirm_route!(get_enable, Action::Enable);
confirm_route!(get_recover, Action::Recover);
confirm_route!(get_delete, Action::Delete);
confirm_route!(get_revoke, Action::RevokeSessions);

/// Common prefix of every POST on a target: parse the id, load the live target, apply the
/// credential-free target rules. Returns the target or the response.
#[allow(clippy::result_large_err)]
async fn prepare(
    st: &St,
    sess: &SessionCtx,
    ip: &str,
    id_raw: &str,
    action: Action,
) -> Result<AccountRow, Response> {
    let Some(id) = parse_id(id_raw) else {
        return Err(not_found());
    };
    let target = match st.auth.db().get_account(id).await {
        Ok(Some(a)) if a.is_live() => a,
        Ok(_) => return Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed");
            return Err(internal());
        }
    };
    if let Some(alert) = pre_refusal(action, sess, &target) {
        return Err(refused(st, sess, ip, action, target.id, alert).await);
    }
    Ok(target)
}

/// Re-authenticates the acting admin; a failure re-renders the confirmation page.
#[allow(clippy::result_large_err)]
async fn confirm_identity(
    st: &St,
    sess: &SessionCtx,
    ip: &str,
    action: Action,
    target: &AccountRow,
    form: &[(String, String)],
) -> Result<(), Response> {
    match reauth(&st.auth, sess, ip, action.purpose(), form).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(render(
            StatusCode::OK,
            &action_page(sess, action, target, Some(ALERT_REAUTH)),
        )),
        Err(r) => Err(r),
    }
}

fn back_to_users() -> Response {
    see_other("/admin/users", None)
}

async fn post_role(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Role).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let form = csrf::parse_form(&body);
    // `GrantableRole` has no admin variant: any other value is a 400 (mass assignment of a role
    // is impossible by construction).
    let role = match csrf::form_get(&form, "role") {
        Some("uploader") => GrantableRole::Uploader,
        Some("viewer") => GrantableRole::Viewer,
        _ => return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response(),
    };
    if let Err(r) = confirm_identity(&st, &sess, &ip, Action::Role, &target, &form).await {
        return r;
    }
    let now = st.auth.now();
    match st
        .auth
        .db()
        .set_role(&sess.actor(), target.id, role, Some(&ip), now)
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::Role, target.id, e).await,
    }
}

async fn post_enable(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Enable).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let form = csrf::parse_form(&body);
    if let Err(r) = confirm_identity(&st, &sess, &ip, Action::Enable, &target, &form).await {
        return r;
    }
    match st
        .auth
        .db()
        .enable_account(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::Enable, target.id, e).await,
    }
}

async fn post_delete(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Delete).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    // A live account is not deletable: refuse before a credential is consumed.
    if target.disabled_at.is_none() {
        return refused(
            &st,
            &sess,
            &ip,
            Action::Delete,
            target.id,
            ALERT_DISABLE_FIRST,
        )
        .await;
    }
    let form = csrf::parse_form(&body);
    if let Err(r) = confirm_identity(&st, &sess, &ip, Action::Delete, &target, &form).await {
        return r;
    }
    match st
        .auth
        .db()
        .delete_account(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::Delete, target.id, e).await,
    }
}

async fn post_disable(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Disable).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match st
        .auth
        .db()
        .disable_account(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::Disable, target.id, e).await,
    }
}

async fn post_unlock(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Unlock).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match st
        .auth
        .db()
        .unlock_account(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::Unlock, target.id, e).await,
    }
}

async fn post_revoke_sessions(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::RevokeSessions).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    // The one HTTP action on an admin target: password + fresh TOTP. A uploader/viewer target is
    // CSRF only (the gate already checked it).
    if target.role == Role::Admin {
        let form = csrf::parse_form(&body);
        if let Err(r) =
            confirm_identity(&st, &sess, &ip, Action::RevokeSessions, &target, &form).await
        {
            return r;
        }
    }
    match st
        .auth
        .db()
        .revoke_account_sessions(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(_) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::RevokeSessions, target.id, e).await,
    }
}

async fn post_cancel_recovery(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::CancelRecovery).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match st
        .auth
        .db()
        .cancel_recovery(&sess.actor(), target.id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::CancelRecovery, target.id, e).await,
    }
}

async fn post_display_name(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::DisplayName).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let form = csrf::parse_form(&body);
    // A blank value resets the account to its default handle; the store validates the rest.
    let raw = csrf::form_get(&form, "display_name").map(str::trim);
    let name = raw.filter(|n| !n.is_empty());
    match st
        .auth
        .db()
        .set_display_name(&sess.actor(), target.id, name, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(e) => failed(&st, &sess, &ip, Action::DisplayName, target.id, e).await,
    }
}

async fn post_recover(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let target = match prepare(&st, &sess, &ip, &id, Action::Recover).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let form = csrf::parse_form(&body);
    if let Err(r) = confirm_identity(&st, &sess, &ip, Action::Recover, &target, &form).await {
        return r;
    }
    let Some(code) = new_code() else {
        return internal();
    };
    let hash = code.hash();
    let ttl = st.auth.config().recover_ttl_secs;
    let now = st.auth.now();
    match st
        .auth
        .db()
        .issue_recovery(
            &sess.actor(),
            &NewRecovery {
                target_id: target.id,
                code_hash: &hash,
                ttl_secs: ttl,
            },
            Some(&ip),
            now,
        )
        .await
    {
        Ok(_) => render(
            StatusCode::OK,
            &CodePage {
                layout: Layout::for_session("Invitation created", &sess),
                heading: "Recovery code",
                username: target.handle(),
                role: role_label(target.role),
                code: code.grouped(),
                has_address: st.auth.config().public_address().is_some(),
                invite_url: st.auth.config().invite_url(),
                expires: fmt_utc(now.saturating_add(ttl)),
                is_recovery: true,
            },
        ),
        Err(e) => failed(&st, &sess, &ip, Action::Recover, target.id, e).await,
    }
}

// ---------------------------------------------------------------------------------------------
// Invitations

/// A fresh 160-bit code from the OS CSPRNG (shown once, never stored).
fn new_code() -> Option<InviteCode> {
    let bytes = crypto::random_bytes::<{ nzb_store::CODE_ENTROPY_BYTES }>().ok()?;
    Some(InviteCode::from_entropy(&bytes))
}

async fn get_invite_form(
    State(_st): State<St>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    render(
        StatusCode::OK,
        &InviteFormPage {
            layout: Layout::for_session("Invite a user", &sess),
            csrf_token: sess.csrf_token.clone(),
            alert: None,
            username: String::new(),
            uploader: false,
        },
    )
}

async fn post_invite_create(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let ip = ip.to_string();
    let form = csrf::parse_form(&body);
    // The role domain over HTTP is uploader|viewer; never echo an unrecognised role.
    let role = match csrf::form_get(&form, "role") {
        Some("uploader") => GrantableRole::Uploader,
        Some("viewer") => GrantableRole::Viewer,
        _ => return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response(),
    };
    let username = csrf::form_get(&form, "username").unwrap_or_default().trim();
    let page = |status: StatusCode, alert: Option<&'static str>| {
        render(
            status,
            &InviteFormPage {
                layout: Layout::for_session("Invite a user", &sess),
                csrf_token: sess.csrf_token.clone(),
                alert,
                // Bound the echo to the input's character limit; Askama escapes the attribute.
                username: username.chars().take(64).collect(),
                uploader: role == GrantableRole::Uploader,
            },
        )
    };
    // Input-only: a name that can never be valid does not burn the admin's TOTP step.
    if nzb_store::check_login_name(username).is_err() {
        return page(StatusCode::OK, Some(ALERT_NAME));
    }
    match reauth(&st.auth, &sess, &ip, "user_invite", &form).await {
        Ok(true) => {}
        Ok(false) => return page(StatusCode::OK, Some(ALERT_REAUTH)),
        Err(r) => return r,
    }
    let Some(code) = new_code() else {
        return internal();
    };
    let hash = code.hash();
    let ttl = st.auth.config().invite_ttl_secs;
    let now = st.auth.now();
    match st
        .auth
        .db()
        .create_invite(
            &sess.actor(),
            &NewInvite {
                username,
                role,
                code_hash: &hash,
                ttl_secs: ttl,
            },
            st.auth.config().account_policy(),
            Some(&ip),
            now,
        )
        .await
    {
        Ok(_) => render(
            StatusCode::OK,
            &CodePage {
                layout: Layout::for_session("Invitation created", &sess),
                heading: "Invitation code",
                username: username.to_owned(),
                role: role_label(role.into()),
                code: code.grouped(),
                has_address: st.auth.config().public_address().is_some(),
                invite_url: st.auth.config().invite_url(),
                expires: fmt_utc(now.saturating_add(ttl)),
                is_recovery: false,
            },
        ),
        Err(e) => match alert_for(&e) {
            Some(alert) => {
                let detail = "action=invite".to_owned();
                let entry = AuditEntry {
                    who: sess.audit_actor(),
                    event: "user_action_refused",
                    detail: Some(&detail),
                    ip: Some(&ip),
                    target_id: None,
                };
                if let Err(e) = st.auth.db().audit_entry(&entry, now).await {
                    tracing::error!(error = %e, "audit write failed");
                }
                page(StatusCode::CONFLICT, Some(alert))
            }
            None => match e {
                StoreError::Account(AccountError::Forbidden | AccountError::InvitesDisabled) => {
                    not_found()
                }
                other => {
                    tracing::error!(error = %other, "invitation creation failed");
                    internal()
                }
            },
        },
    }
}

async fn post_invite_revoke(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let ip = ip.to_string();
    match st
        .auth
        .db()
        .revoke_invite(&sess.actor(), id, Some(&ip), st.auth.now())
        .await
    {
        Ok(()) => back_to_users(),
        Err(StoreError::Account(AccountError::TargetNotFound | AccountError::Forbidden)) => {
            not_found()
        }
        Err(StoreError::Account(AccountError::InvalidState)) => {
            users_page(&st, &sess, StatusCode::CONFLICT, Some(ALERT_STATE)).await
        }
        Err(e) => {
            tracing::error!(error = %e, "invitation revoke failed");
            internal()
        }
    }
}

/// The Users routes. Mounted by `nzbd` only while `security.multi_user = true`; the access gate
/// answers the uniform 404 for them otherwise even when mounted (belt and braces).
pub fn routes(auth: &AuthState) -> Router {
    Router::new()
        .route("/admin/users", get(list))
        .route(
            "/admin/users/invite",
            get(get_invite_form).post(post_invite_create),
        )
        .route("/admin/users/{id}/role", get(get_role).post(post_role))
        .route("/admin/users/{id}/disable", post(post_disable))
        .route("/admin/users/{id}/unlock", post(post_unlock))
        .route(
            "/admin/users/{id}/enable",
            get(get_enable).post(post_enable),
        )
        .route(
            "/admin/users/{id}/revoke-sessions",
            get(get_revoke).post(post_revoke_sessions),
        )
        .route(
            "/admin/users/{id}/recover",
            get(get_recover).post(post_recover),
        )
        .route(
            "/admin/users/{id}/recover/cancel",
            post(post_cancel_recovery),
        )
        .route(
            "/admin/users/{id}/delete",
            get(get_delete).post(post_delete),
        )
        .route("/admin/users/{id}/display-name", post(post_display_name))
        .route("/admin/invites/{id}/revoke", post(post_invite_revoke))
        .with_state(St { auth: auth.clone() })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

    use std::sync::Arc;

    use axum::body::{Body, to_bytes};
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{AuthConfig, ClientMeta, ManualWallClock};
    use crate::totp;

    fn attribute<'a>(tag: &'a str, name: &str) -> &'a str {
        tag.split_once(&format!("{name}=\""))
            .and_then(|(_, rest)| rest.split_once('"'))
            .map_or("", |(value, _)| value)
    }

    fn input_value<'a>(html: &'a str, id: &str) -> &'a str {
        let tag = html
            .split("<input ")
            .filter_map(|part| part.split_once('>').map(|(tag, _)| tag))
            .find(|tag| attribute(tag, "id") == id)
            .expect("the returned form must contain its input");
        attribute(tag, "value")
    }

    fn selected_role(html: &str) -> &str {
        let select = html
            .split_once("<select id=\"role\"")
            .unwrap()
            .1
            .split_once("</select>")
            .unwrap()
            .0;
        let options: Vec<_> = select
            .split("<option ")
            .skip(1)
            .filter_map(|part| part.split_once('>').map(|(tag, _)| tag))
            .collect();
        let selected = options
            .iter()
            .find(|tag| tag.split_whitespace().any(|part| part == "selected"))
            .or_else(|| options.first())
            .unwrap();
        attribute(selected, "value")
    }

    async fn post_form(app: &Router, cookie: &str, body: String) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(
                Request::post("/admin/users/invite")
                    .header("host", "localhost")
                    .header("origin", "http://localhost")
                    .header("accept", "text/html")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", cookie)
                    .extension(ConnectInfo(
                        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// The browser retries the form returned after a refusal: its selected role must still be
    /// the role the administrator chose, while password and TOTP inputs must be empty.
    #[tokio::test]
    async fn invitation_retry_preserves_public_choices_without_echoing_credentials() {
        const NOW: i64 = 3_000;
        const PASSWORD: &str = "Audit-Invitation-Password-47";
        const SECRET: &[u8] = b"12345678901234567890";
        const TOKEN: [u8; 32] = [7; 32];

        let dir = tempfile::tempdir().unwrap();
        let test_store = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = test_store.store.clone();
        let key = Arc::new(totp::TotpKey::from_slice(&[9; 32]).unwrap());
        let config = AuthConfig {
            multi_user: true,
            insecure_cookies: true,
            totp_key: Some(key.clone()),
            ..AuthConfig::default()
        };
        let hash = crate::password::hash_password(PASSWORD).unwrap();
        let uid = db
            .create_account_operator(
                &nzb_store::NewAccount {
                    username: "root",
                    password_hash: &hash,
                    role: Some(Role::Admin),
                },
                config.account_policy(),
                NOW - 60,
            )
            .await
            .unwrap();
        let sealed = totp::seal(&key, uid, SECRET).unwrap();
        assert!(
            db.set_enrollment_token_for(uid, &TOKEN, NOW + 600, NOW - 60)
                .await
                .unwrap()
        );
        assert!(
            db.store_pending_totp(uid, &sealed, false)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.confirm_totp_enrollment(uid, &sealed, Some(TOKEN), Some(98), &[], None, NOW - 60)
                .await
                .unwrap()
        );
        let auth = AuthState::new(db.clone(), config, Arc::new(ManualWallClock::new(NOW)))
            .await
            .unwrap();
        let (cookie, csrf) = auth
            .start_session_full(
                uid,
                nzb_store::SessionStage::Active,
                &ClientMeta::default(),
                None,
            )
            .await
            .unwrap();
        let cookie = cookie.to_str().unwrap().split(';').next().unwrap();
        let app = crate::router_with_auth(
            &crate::WebConfig {
                insecure_cookies: true,
                ..crate::WebConfig::default()
            },
            &auth,
            routes(&auth),
        );
        let form = |username: &str, role: &str, code: &str| {
            format!(
                "csrf_token={csrf}&username={}&role={role}&current_password={PASSWORD}&code={code}",
                crate::index::pct_encode(username)
            )
        };

        // Input validation retains an escaped public username and the allowlisted role.
        let hostile = "bad\"><img src=x>";
        let (status, body) = post_form(&app, cookie, form(hostile, "uploader", "not-a-code")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(ALERT_NAME));
        assert_eq!(selected_role(&body), "uploader");
        assert!(input_value(&body, "username").contains("img"));
        assert!(!body.contains("<img") && !body.contains(hostile));
        assert_eq!(input_value(&body, "current_password"), "");
        assert_eq!(input_value(&body, "code"), "");
        assert!(!body.contains(PASSWORD) && !body.contains("not-a-code"));
        let (status, _) = post_form(&app, cookie, form("invitee", "admin", "not-a-code")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(db.list_open_invites(NOW).await.unwrap().len(), 0);

        // A six-digit code outside the accepted window exercises real MFA refusal.
        let wrong = (0..10)
            .map(|n| format!("{n:06}"))
            .find(|code| totp::matching_step(SECRET, NOW, code).is_none())
            .unwrap();
        let (status, body) = post_form(&app, cookie, form("invitee", "uploader", &wrong)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(ALERT_REAUTH));
        assert_eq!(input_value(&body, "username"), "invitee");
        assert_eq!(selected_role(&body), "uploader");
        assert_eq!(input_value(&body, "current_password"), "");
        assert_eq!(input_value(&body, "code"), "");
        assert!(!body.contains(PASSWORD));
        assert_eq!(db.list_open_invites(NOW).await.unwrap().len(), 0);

        // Retry using the public choices from the returned HTML, not the initial request.
        let code = totp::code_at(SECRET, NOW / totp::STEP_SECS).unwrap();
        let (status, body) = post_form(
            &app,
            cookie,
            form(input_value(&body, "username"), selected_role(&body), &code),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Invitation code"));
        let invites = db.list_open_invites(NOW).await.unwrap();
        assert_eq!(invites.len(), 1);
        let invite = invites.first().unwrap();
        assert_eq!(invite.username.as_deref(), Some("invitee"));
        assert_eq!(invite.role, Some(Role::Uploader));
    }
}
