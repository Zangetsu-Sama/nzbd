//! Route inventory (SEC-028): the complete, reviewed list of HTTP routes (`docs/UI_SPEC.md`).
//!
//! Every route added by later tasks must be listed here; the inventory tests fail for any
//! reachable path that is not listed and for any listed session route that answers without a
//! session. Since T101 it also carries the minimum role of every session route.
//!
//! The invitation page (T135) is served at the configured `security.invite_path`
//! ([`crate::invite_path::InvitePath`]); the inventory lists it under the placeholder
//! [`INVITE_PATH_PLACEHOLDER`] (`/invite`, also the default). The placeholder keeps this table a
//! `const`; a walk over it maps the placeholder to the configured path with
//! [`crate::invite_path::InvitePath::resolve`]. The login-flow routes are mounted directly (the
//! access gate only consults [`RouteClass::Session`] entries), so nothing at runtime looks the
//! placeholder up; it exists for the route-matrix tests and for the startup collision check.

use nzb_store::Role;

/// Authentication class of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    /// No authentication, reveals nothing (`/healthz`).
    Public,
    /// Vendored assets under `/static/`.
    Static,
    /// Login flow pages: reachable before an active session (`/login*`, `/mfa/enroll`, `/logout`).
    /// Pending-MFA sessions are limited to these routes.
    LoginFlow,
    /// Requires an `active` session (password and MFA completed).
    Session,
    /// Requires a valid upload-scope API key; ignores cookies.
    ApiKey,
}

/// One entry of the inventory.
///
/// This table is the single source of truth for access (SEC-028, SEC-060): the access gate looks
/// the matched route pattern up here and answers the uniform 404 for a pattern that is not listed,
/// so a handler mounted without an entry is unreachable, and the route-matrix tests walk exactly
/// this table. `AUTH_SPEC` "Permission matrix: HTTP routes" is its prose form.
#[derive(Clone, Copy, Debug)]
pub struct RouteSpec {
    /// HTTP method.
    pub method: &'static str,
    /// Path pattern; `{name}` marks a parameter.
    pub path: &'static str,
    /// Authentication class.
    pub class: RouteClass,
    /// Minimum role of a [`RouteClass::Session`] route (`Viewer` for every other class: unused).
    pub min_role: Role,
    /// The route exists only while `security.multi_user = true` (404 for everybody otherwise).
    pub multi_user_only: bool,
    /// The route exists only while `security.registration_enabled = true` as well (D28): the
    /// invitation form and its POST. Implies `multi_user_only`.
    pub registration_only: bool,
}

/// Inventory placeholder of the invitation page; the page itself is served at the configured
/// `security.invite_path` (T135). Equal to the default path.
pub const INVITE_PATH_PLACEHOLDER: &str = "/invite";

impl RouteSpec {
    /// `true` for the two entries of the invitation page (their path is the configured one).
    #[must_use]
    pub fn is_invite_placeholder(&self) -> bool {
        self.path == INVITE_PATH_PLACEHOLDER
    }
}

const fn r(
    method: &'static str,
    path: &'static str,
    class: RouteClass,
    min_role: Role,
) -> RouteSpec {
    RouteSpec {
        method,
        path,
        class,
        min_role,
        multi_user_only: false,
        registration_only: false,
    }
}

/// Like [`r`] for a route that exists only with `security.multi_user = true`.
const fn mu(
    method: &'static str,
    path: &'static str,
    class: RouteClass,
    min_role: Role,
) -> RouteSpec {
    RouteSpec {
        method,
        path,
        class,
        min_role,
        multi_user_only: true,
        registration_only: false,
    }
}

/// Like [`mu`] for a route that also needs `security.registration_enabled = true` (D28).
const fn reg(
    method: &'static str,
    path: &'static str,
    class: RouteClass,
    min_role: Role,
) -> RouteSpec {
    RouteSpec {
        method,
        path,
        class,
        min_role,
        multi_user_only: true,
        registration_only: true,
    }
}

use Role::{Admin, Uploader, Viewer};

/// Every route the application may expose. Anything else must answer 404.
///
/// Reserved first segments (T135): no route may start with `join` (the installer generates
/// `security.invite_path = "/join-<12 random>"`, and a colliding route would make every such
/// install refuse to start; `sec_028_installer_invite_prefix_is_reserved` fails first) nor with
/// `invite` other than the placeholder below.
pub const INVENTORY: &[RouteSpec] = &[
    r("GET", "/healthz", RouteClass::Public, Viewer),
    r("GET", "/static/{name}", RouteClass::Static, Viewer),
    r("GET", "/login", RouteClass::LoginFlow, Viewer),
    r("POST", "/login", RouteClass::LoginFlow, Viewer),
    // The invitation page: at the configured `security.invite_path` (placeholder, see above).
    mu(
        "GET",
        INVITE_PATH_PLACEHOLDER,
        RouteClass::LoginFlow,
        Viewer,
    ),
    mu(
        "POST",
        INVITE_PATH_PLACEHOLDER,
        RouteClass::LoginFlow,
        Viewer,
    ),
    r("GET", "/login/mfa", RouteClass::LoginFlow, Viewer),
    r("POST", "/login/mfa", RouteClass::LoginFlow, Viewer),
    r("GET", "/mfa/enroll", RouteClass::LoginFlow, Viewer),
    r("POST", "/mfa/enroll", RouteClass::LoginFlow, Viewer),
    r("POST", "/logout", RouteClass::LoginFlow, Viewer),
    r("GET", "/", RouteClass::Session, Viewer),
    r("GET", "/release/{id}", RouteClass::Session, Viewer),
    r(
        "GET",
        "/release/{id}/file/{idx}/segments",
        RouteClass::Session,
        Viewer,
    ),
    r("GET", "/release/{id}/raw", RouteClass::Session, Viewer),
    r("GET", "/release/{id}/download", RouteClass::Session, Viewer),
    // Partial download (T125): a POST only because a selection does not fit a link; it changes
    // nothing, so it keeps the download's role.
    r(
        "POST",
        "/release/{id}/download/selected",
        RouteClass::Session,
        Viewer,
    ),
    r("POST", "/release/{id}/category", RouteClass::Session, Admin),
    r("POST", "/release/{id}/source", RouteClass::Session, Admin),
    // NFO viewer (T140): reading is the download's role; removing is an edit (admin, D40).
    r("GET", "/release/{id}/nfo", RouteClass::Session, Viewer),
    r(
        "GET",
        "/release/{id}/nfo/download",
        RouteClass::Session,
        Viewer,
    ),
    r(
        "POST",
        "/release/{id}/nfo/delete",
        RouteClass::Session,
        Admin,
    ),
    r("GET", "/release/{id}/delete", RouteClass::Session, Admin),
    r("POST", "/release/{id}/delete", RouteClass::Session, Admin),
    // Bulk actions (T119): edits like the single edits (admin, D40), delete like the single delete
    // (admin; the confirmation page is its own route so the gate decides the role).
    r("POST", "/releases/bulk", RouteClass::Session, Admin),
    r(
        "POST",
        "/releases/bulk/delete/confirm",
        RouteClass::Session,
        Admin,
    ),
    r("POST", "/releases/bulk/delete", RouteClass::Session, Admin),
    // Bulk download (T130): changes nothing, so it keeps the download's role (viewer).
    r(
        "POST",
        "/releases/bulk/download",
        RouteClass::Session,
        Viewer,
    ),
    // Saved searches (T127): any role, owner only (scoped by the session's account in the store).
    r("GET", "/search/saved", RouteClass::Session, Viewer),
    r("POST", "/search/saved", RouteClass::Session, Viewer),
    r("GET", "/search/saved/{id}", RouteClass::Session, Viewer),
    r(
        "POST",
        "/search/saved/{id}/rename",
        RouteClass::Session,
        Viewer,
    ),
    r(
        "POST",
        "/search/saved/{id}/delete",
        RouteClass::Session,
        Viewer,
    ),
    // Statistics page (T132): every role; per caller (hidden categories excluded), read-only.
    r("GET", "/stats", RouteClass::Session, Viewer),
    r("GET", "/upload", RouteClass::Session, Uploader),
    r("POST", "/upload", RouteClass::Session, Uploader),
    r("GET", "/admin", RouteClass::Session, Admin),
    r("GET", "/admin/health", RouteClass::Session, Admin),
    r("POST", "/admin/health/deep", RouteClass::Session, Admin),
    r("GET", "/admin/activity", RouteClass::Session, Admin),
    r("GET", "/admin/cleanup", RouteClass::Session, Admin),
    r(
        "GET",
        "/admin/cleanup/purge/{bucket}",
        RouteClass::Session,
        Admin,
    ),
    r(
        "POST",
        "/admin/cleanup/purge/{bucket}",
        RouteClass::Session,
        Admin,
    ),
    mu("GET", "/admin/users", RouteClass::Session, Admin),
    reg("GET", "/admin/users/invite", RouteClass::Session, Admin),
    reg("POST", "/admin/users/invite", RouteClass::Session, Admin),
    mu("GET", "/admin/users/{id}/role", RouteClass::Session, Admin),
    mu("POST", "/admin/users/{id}/role", RouteClass::Session, Admin),
    mu(
        "POST",
        "/admin/users/{id}/disable",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/unlock",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "GET",
        "/admin/users/{id}/enable",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/enable",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "GET",
        "/admin/users/{id}/revoke-sessions",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/revoke-sessions",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "GET",
        "/admin/users/{id}/recover",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/recover",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/recover/cancel",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "GET",
        "/admin/users/{id}/delete",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/delete",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/users/{id}/display-name",
        RouteClass::Session,
        Admin,
    ),
    mu(
        "POST",
        "/admin/invites/{id}/revoke",
        RouteClass::Session,
        Admin,
    ),
    r("GET", "/account", RouteClass::Session, Viewer),
    r("POST", "/account/password", RouteClass::Session, Viewer),
    r(
        "POST",
        "/account/recovery-codes",
        RouteClass::Session,
        Viewer,
    ),
    r("POST", "/account/preferences", RouteClass::Session, Viewer),
    // The "Per page" control under the release list and the files table (T133): any role, own preference only.
    // Mounted with the index routes (it re-validates the index filters for its redirect).
    r("POST", "/page-size", RouteClass::Session, Viewer),
    r("POST", "/account/api-keys", RouteClass::Session, Uploader),
    r(
        "POST",
        "/account/api-keys/revoke",
        RouteClass::Session,
        Uploader,
    ),
    r(
        "POST",
        "/account/sessions/revoke",
        RouteClass::Session,
        Viewer,
    ),
    r(
        "POST",
        "/account/sessions/revoke-others",
        RouteClass::Session,
        Viewer,
    ),
    r("POST", "/api/v1/nzb", RouteClass::ApiKey, Viewer),
];

/// The access declared for a matched route pattern (`MatchedPath`): minimum role, multi-user-only,
/// registration-only; or `None` when the pattern
/// is not in [`INVENTORY`] (the gate then answers the uniform 404: an unlisted route is
/// unreachable). All methods of one path carry the same minimum role (checked by a test).
#[must_use]
pub fn session_access(pattern: &str) -> Option<(Role, bool, bool)> {
    INVENTORY
        .iter()
        .find(|s| s.class == RouteClass::Session && s.path == pattern)
        .map(|s| (s.min_role, s.multi_user_only, s.registration_only))
}

/// Fixed route-class token of a refused-role `authz_denied` row (T119 review I3). Only the bulk
/// routes carry one so far; every other row keeps its 2.0 detail (`needs=.. role=..`).
#[must_use]
pub fn denied_token(pattern: &str) -> Option<&'static str> {
    match pattern {
        "/releases/bulk" => Some("bulk_edit"),
        "/releases/bulk/delete/confirm" | "/releases/bulk/delete" => Some("bulk_delete"),
        _ => None,
    }
}

/// Replaces `{param}` segments with a concrete value so the pattern can be requested.
#[must_use]
pub fn concretize(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                if seg == "{name}" { "app.css" } else { "1" }
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
