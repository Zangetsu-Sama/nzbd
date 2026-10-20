//! API key management on the account page (`AUTH_SPEC` §Account page, SEC-036, T103): list,
//! create (re-authenticated with password and TOTP like the other sensitive account actions,
//! secret shown once on a `no-store` page) and revoke. Uploaders manage their own keys; an admin
//! additionally sees and can revoke every key (the owner column and the audit row name who).
//! The owner of a new key is always the session's account, never a form field. All routes sit
//! behind the active-session gate (role `uploader` or higher, a viewer gets the uniform 404),
//! which also enforces Origin and CSRF on the POSTs.

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use nzb_store::ApiKeyRow;
use nzb_store::prelude::*;

use crate::account::{fmt_utc, reauth, render_account};
use crate::apikey::{self, IssueError, MAX_ACTIVE_KEYS};
use crate::assets::Layout;
use crate::auth::{AuthState, SessionCtx};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::login::{html, internal};
use crate::session::see_other;
use axum::response::IntoResponse;
use nzb_store::Role;

/// One row of the key table. All fields are rendered through askama autoescape.
pub(crate) struct KeyView {
    pub(crate) id: i64,
    pub(crate) label: String,
    pub(crate) prefix: String,
    pub(crate) scope: String,
    /// "Instance default" or "N per minute".
    pub(crate) rate: String,
    /// Owner as an admin sees it: handle and login name. Empty for non-admins (their list is
    /// their own keys, and login names are admin-only, D26 d).
    pub(crate) owner: String,
    pub(crate) created: String,
    pub(crate) last_used: String,
    /// "<date>" or "<date> by an administrator".
    pub(crate) revoked: Option<String>,
}

fn view(k: &ApiKeyRow, viewer: &SessionCtx) -> KeyView {
    let admin = viewer.role == Role::Admin;
    let owner = if admin {
        match (&k.owner_handle, &k.owner_username) {
            (Some(h), _) if k.owner_deleted => format!("{h} (deleted account)"),
            (Some(h), Some(u)) => format!("{h} ({u})"),
            (Some(h), None) => h.clone(),
            _ => "operator".to_owned(),
        }
    } else {
        String::new()
    };
    let revoked = k.revoked_at.map(|t| match k.revoked_by {
        Some(by) if Some(by) != k.owner_id => format!("{} by an administrator", fmt_utc(t)),
        _ => fmt_utc(t),
    });
    KeyView {
        id: k.id,
        label: k.label.clone(),
        prefix: format!("{}{}", apikey::KEY_PREFIX, k.prefix),
        scope: k.scope.clone(),
        rate: k.rate_per_min.map_or_else(
            || "Instance default".to_owned(),
            |n| format!("{n} per minute"),
        ),
        owner,
        created: fmt_utc(k.created_at),
        last_used: k.last_used_at.map_or_else(|| "never".to_owned(), fmt_utc),
        revoked,
    }
}

/// Most revoked keys listed on the account page (older ones stay in the database until the
/// maintenance purge removes them).
const MAX_REVOKED_SHOWN: u32 = 20;

/// Key table data for the account page, plus the number of the caller's own unrevoked keys.
/// An uploader sees only their own keys; an admin sees every key with its owner.
pub(crate) async fn key_views(
    auth: &AuthState,
    sess: &SessionCtx,
) -> Option<(Vec<KeyView>, usize)> {
    let scope = (sess.role != Role::Admin).then_some(sess.user_id);
    let rows = auth
        .db()
        .list_api_keys_recent(scope, MAX_REVOKED_SHOWN)
        .await
        .ok()?;
    let active = rows
        .iter()
        .filter(|k| k.revoked_at.is_none() && k.owner_id == Some(sess.user_id))
        .count();
    Some((rows.iter().map(|k| view(k, sess)).collect(), active))
}

/// Maximum number of unrevoked keys (for the page text).
pub(crate) const fn max_keys() -> u32 {
    MAX_ACTIVE_KEYS
}

#[derive(Template)]
#[template(path = "api_key_created.html")]
struct CreatedPage {
    layout: Layout,
    label: String,
    secret: String,
}

/// `Ok(None)` for an empty field, `Err` for anything outside 1..=30.
fn parse_rate(raw: Option<&str>) -> Result<Option<u32>, ()> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(t) => match t.parse::<u32>() {
            Ok(n) if (1..=nzb_store::MAX_RATE_PER_MIN).contains(&n) => Ok(Some(n)),
            _ => Err(()),
        },
    }
}

async fn post_create(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let form = csrf::parse_form(&body);
    let label = csrf::form_get(&form, "label").unwrap_or_default();
    // Optional per-key budget (1..=30 uploads a minute; empty = the instance default).
    let Ok(rate) = parse_rate(csrf::form_get(&form, "rate")) else {
        return render_account(
            &auth,
            &sess,
            None,
            Some("The upload rate must be a whole number from 1 to 30 per minute."),
        )
        .await;
    };
    // Input-only check first: it reveals nothing and must not burn the user's TOTP step.
    if nzb_store::sanitize_label(label).is_none() {
        return render_account(
            &auth,
            &sess,
            None,
            Some("The label must be 1 to 64 letters, digits, spaces or . _ - : @ ( ) + # /"),
        )
        .await;
    }
    // Cap check before re-authentication: at the limit a create can only fail, so it must not
    // consume the user's TOTP step. (`issue` re-checks atomically; this is the early answer.)
    match auth.db().count_active_api_keys_of(sess.user_id).await {
        Ok(n) if n >= i64::from(MAX_ACTIVE_KEYS) => {
            return render_account(
                &auth,
                &sess,
                None,
                Some("The limit of active API keys is reached. Revoke one first."),
            )
            .await;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "api key count failed");
            return internal();
        }
    }
    let ip_text = ip.to_string();
    match reauth(&auth, &sess, &ip_text, "apikey_create", &form).await {
        Ok(true) => {}
        Ok(false) => return render_account(&auth, &sess, None, Some("Verification failed")).await,
        Err(r) => return r,
    }
    // The key belongs to the creating account (owner = the session's account, never a form field).
    match apikey::issue_for_rate(
        auth.db(),
        label,
        sess.user_id,
        rate,
        Some(&sess.id_hash),
        &sess.audit_actor(),
        Some(&ip_text),
        auth.now(),
    )
    .await
    {
        Ok((_, key)) => {
            let page = CreatedPage {
                layout: Layout::for_session("New API key", &sess),
                label: label.trim().to_owned(),
                secret: key.secret.to_string(),
            };
            // `no-store` comes from the global header layer; the key is not in any URL.
            page.render()
                .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
        }
        Err(IssueError::LimitReached) => {
            render_account(
                &auth,
                &sess,
                None,
                Some("The limit of active API keys is reached. Revoke one first."),
            )
            .await
        }
        Err(IssueError::InstanceLimitReached) => {
            render_account(
                &auth,
                &sess,
                None,
                Some("The instance has reached its limit of API keys. Ask an administrator to revoke unused keys."),
            )
            .await
        }
        // The session died after the re-authentication (recovery, reset or revocation): sign in again.
        Err(IssueError::Store(nzb_store::StoreError::NotFound)) => {
            see_other("/login", Some(auth.clear_cookie()))
        }
        // The account lost its role between the gate and the transaction: same answer as the gate.
        Err(IssueError::Store(nzb_store::StoreError::Account(
            nzb_store::AccountError::Forbidden,
        ))) => ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response(),
        Err(IssueError::InvalidLabel) => {
            render_account(&auth, &sess, None, Some("That label is not allowed.")).await
        }
        Err(IssueError::InvalidRate) => {
            render_account(&auth, &sess, None, Some("That upload rate is not allowed.")).await
        }
        Err(e) => {
            tracing::error!(error = %e, "api key creation failed");
            internal()
        }
    }
}

async fn post_revoke(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let form = csrf::parse_form(&body);
    let Some(id) = csrf::form_get(&form, "key").and_then(|v| v.parse::<i64>().ok()) else {
        return render_account(&auth, &sess, None, Some("That API key could not be found.")).await;
    };
    let ip_text = ip.to_string();
    match auth
        .db()
        .revoke_api_key_by(&sess.actor(), id, Some(&ip_text), auth.now())
        .await
    {
        Ok(true) => render_account(&auth, &sess, Some("API key revoked."), None).await,
        Ok(false) => {
            render_account(&auth, &sess, None, Some("That API key could not be found.")).await
        }
        Err(nzb_store::StoreError::Account(nzb_store::AccountError::Forbidden)) => {
            ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "api key revoke failed");
            internal()
        }
    }
}

/// Routes merged into [`crate::account_routes`].
pub(crate) fn routes(auth: &AuthState) -> Router {
    Router::new()
        .route("/account/api-keys", post(post_create))
        .route("/account/api-keys/revoke", post(post_revoke))
        .with_state(auth.clone())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{AuthConfig, ManualWallClock};

    /// T4: an account that lost its role between the session gate and the transaction gets the
    /// uniform 404 of a refused role, not a 500 and not an error log line.
    #[tokio::test]
    async fn sec_036_actor_demoted_between_gate_and_transaction_is_the_uniform_404() {
        let dir = tempfile::tempdir().unwrap();
        let test_store = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = test_store.store.clone();
        let policy = nzb_store::AccountPolicy {
            multi_user: true,
            max_accounts: 10,
            registration_enabled: true,
        };
        let mk = |n: &'static str, role| nzb_store::NewAccount {
            username: n,
            password_hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
            role: Some(role),
        };
        db.create_account_operator(&mk("root", Role::Admin), policy, 1)
            .await
            .unwrap();
        // The database says viewer; the context handed over by the gate (read earlier) says uploader.
        let uid = db
            .create_account_operator(&mk("late", Role::Viewer), policy, 1)
            .await
            .unwrap();
        let auth = AuthState::new(
            db,
            AuthConfig::default(),
            Arc::new(ManualWallClock::new(100)),
        )
        .await
        .unwrap();
        let sess = SessionCtx {
            user_id: uid,
            stage: nzb_store::SessionStage::Active,
            csrf_token: String::new(),
            hidden_categories: Arc::from(Vec::new()),
            prefs: nzb_store::UserPrefs::default(),
            role: Role::Uploader,
            username: "late".to_owned(),
            display_name: "user-2".to_owned(),
            enroll_proven: false,
            multi_user: true,
            id_hash: [0; 32],
            last_seen_at: 0,
            created_at: 0,
            library_gen: Arc::default(),
        };
        let app = routes(&auth)
            .layer(axum::Extension(sess))
            .layer(axum::Extension(ClientIp("127.0.0.1".parse().unwrap())));
        let req = Request::post("/account/api-keys/revoke")
            .body(Body::from("key=1"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
