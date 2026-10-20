//! `nzb-web` — HTTP app: router assembly, security middleware, static assets, base templates,
//! log redaction, sessions/login/CSRF. UI and upload routes arrive with T045+ (docs/TASKS.md).
#![forbid(unsafe_code)]

/// Whether a real availability check against a news server exists.
///
/// It does not: the app has no network. The gaps nzbd can see (holes in the NZB's own segment
/// numbering, or fewer segments than the subject's declared total) say nothing about whether
/// the articles are still on a server, so while this is `false` the UI shows segment counts as
/// full (`max/max`), 100% completeness, and hides the gap-derived Incomplete and Repairability
/// badges, the Incomplete tile and the Incomplete filter control. The stored flags, counters and
/// missing ranges stay untouched. Flip to `true` when the news-server health check is
/// implemented; every `health: bool` parameter in the view code then takes the original path.
pub const SEGMENT_HEALTH_CHECK_AVAILABLE: bool = false;

mod account;
mod account_keys;
pub mod activity;
pub mod admin;
pub mod apikey;
pub mod assets;
pub mod auth;
pub mod bulk;
pub mod bulk_download;
pub mod cleanup;
pub mod crypto;
pub mod csrf;
pub mod ctx;
pub mod download;
pub mod error;
pub mod health;
pub mod index;
mod invite;
pub mod invite_path;
pub mod listener;
mod login;
pub mod metrics;
mod mfa;
mod middleware;
mod nfo;
pub mod page_size;
pub mod password;
pub mod ratelimit;
pub mod redact;
pub mod release;
pub mod routes;
pub mod saved;
mod session;
pub mod starting;
mod stats;
pub mod totp;
pub mod upload;
pub mod upload_guard;
pub mod users;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::IntoResponse;
use axum::routing::{MethodRouter, get, post};

pub use account::{account_routes, fmt_utc};
pub use auth::{AuthConfig, AuthState, SessionCtx};
pub use error::ApiError;
pub use middleware::{
    CSP, DEFAULT_CACHE_CONTROL, MAX_UI_UPLOAD_FILES, SECURITY_HEADERS, UI_UPLOAD_CEILING_FILES,
    security_headers_report,
};
use ratelimit::{Clock, RateLimits, SystemClock};
pub use session::DeferredCsrf;

/// Runtime settings of the web layer (built from `nzbd`'s config in `main`).
#[derive(Clone)]
pub struct WebConfig {
    /// Peers allowed to set `X-Forwarded-*` (SEC-031).
    pub trusted_proxies: Vec<IpAddr>,
    /// Plain-HTTP dev opt-out for cookies (D16); consumed by T043.
    pub insecure_cookies: bool,
    /// Hard cap for one uploaded NZB (SEC-035).
    pub max_file_bytes: u64,
    /// Body ceiling for every non-upload route (64 KiB).
    pub max_body_bytes: u64,
    /// Cap for the sum of header names and values.
    pub max_header_bytes: usize,
    /// Timeout for ordinary requests.
    pub request_timeout: Duration,
    /// Timeout for upload requests (must stay below `idle_timeout`).
    pub upload_timeout: Duration,
    /// Concurrent in-flight requests before answering 503.
    pub max_in_flight: usize,
    /// Concurrent TCP connections (see [`WebConfig::limit_listener`]).
    pub max_connections: usize,
    /// Connection idle timeout (see [`WebConfig::limit_listener`]).
    pub idle_timeout: Duration,
    /// Concurrent connections per client IP (IPv6 per /64; loopback exempt).
    pub max_connections_per_ip: usize,
    /// Connections reserved for loopback peers (container healthcheck).
    pub loopback_reserved_connections: usize,
    /// Absolute time to receive one complete request head, including the wait between
    /// keep-alive requests (slowloris defence; enforced by [`listener::serve`]). A reverse proxy
    /// must drop its idle upstream connections sooner than this (the bundled Caddy uses 8 s),
    /// or a request sent on a connection nzbd is closing fails with a 502.
    pub header_read_timeout: Duration,
    /// Per-IP budgets per minute.
    pub rate_limits: RateLimits,
    /// Time source for rate limiting.
    pub clock: Arc<dyn Clock>,
    /// Extra liveness condition for `/healthz` (e.g. the ingest scan heartbeat is fresh).
    /// `None` = always healthy. Must be cheap and non-blocking.
    pub health_check: Option<HealthCheck>,
}

/// Cheap synchronous health predicate; `false` makes `/healthz` answer 503.
pub type HealthCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Extension carrying the optional [`HealthCheck`] to the handler.
#[derive(Clone)]
struct HealthProbe(Option<HealthCheck>);

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            insecure_cookies: false,
            max_file_bytes: 64 * 1024 * 1024,
            max_body_bytes: 64 * 1024,
            max_header_bytes: 16 * 1024,
            request_timeout: middleware::DEFAULT_REQUEST_TIMEOUT,
            upload_timeout: Duration::from_secs(60),
            max_in_flight: 128,
            max_connections: 256,
            idle_timeout: Duration::from_secs(120),
            max_connections_per_ip: 32,
            loopback_reserved_connections: 8,
            header_read_timeout: Duration::from_secs(10),
            rate_limits: RateLimits::default(),
            clock: Arc::new(SystemClock::new()),
            health_check: None,
        }
    }
}

impl WebConfig {
    /// Wraps a listener with connection caps and an idle timeout (SEC-032). Pass the wrapper
    /// to [`listener::serve`] to enforce request-head deadlines and size caps in the HTTP parser.
    pub fn limit_listener<L>(&self, inner: L) -> listener::LimitedListener<L> {
        listener::LimitedListener::new(
            inner,
            listener::ListenerLimits {
                max_connections: self.max_connections,
                loopback_reserved: self.loopback_reserved_connections,
                max_per_ip: self.max_connections_per_ip,
                idle: self.idle_timeout,
                header_timeout: self.header_read_timeout,
                // Request line + names/values + ": \r\n" framing of up to 100 headers + slack.
                max_head_bytes: self
                    .max_header_bytes
                    .saturating_add(middleware::MAX_URI_BYTES)
                    .saturating_add(4096),
            },
        )
    }
}

/// Liveness probe. Unauthenticated by design (container `HEALTHCHECK`); reveals nothing.
async fn healthz(axum::Extension(probe): axum::Extension<HealthProbe>) -> impl IntoResponse {
    let healthy = probe.0.as_ref().is_none_or(|f| f());
    let (status, body) = if healthy {
        (StatusCode::OK, "ok\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unhealthy\n")
    };
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

/// `POST /api/v1/nzb` placeholder used when no [`AuthState`] is wired (no key database): fails
/// closed with the uniform 401. Cookies are never consulted.
async fn api_upload_unauthorized() -> impl IntoResponse {
    ApiError::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED")
}

/// Applies the security middleware stack (outermost first: context/request-id/IP, security
/// headers, rate limit, limits and timeouts) to `router`.
pub fn harden(router: Router, cfg: &WebConfig) -> Router {
    harden_with(router, cfg, None)
}

/// [`harden`] with the mounted invitation path (`None` when the page is not mounted): the rate
/// limiter and the body-ceiling classification key on it (T135), so the invitation page keeps
/// the login class wherever it is served and any other path, the old `/invite` included, is
/// classified like an unknown path.
fn harden_with(router: Router, cfg: &WebConfig, invite: Option<invite_path::InvitePath>) -> Router {
    let sh = Arc::new(middleware::Shared::new(cfg, invite));
    let hardened = router
        .layer(from_fn_with_state(sh.clone(), middleware::limits_layer))
        .layer(from_fn_with_state(sh.clone(), middleware::rate_limit_layer))
        .layer(from_fn(middleware::headers_layer))
        .layer(from_fn_with_state(sh, middleware::context_layer));
    // A method router attaches `Allow` AFTER the layers that wrap its handlers ran, so a 404 that
    // the access gate produced for a refused role (or any other non-405) would still list the
    // methods of the route. Nesting the whole stack as the fallback of an outer router puts one
    // more layer outside of every method router; it removes `Allow` unless the status is 405.
    Router::new()
        .fallback_service(hardened)
        .layer(from_fn(middleware::strip_allow))
}

/// Builds the application router with no session routes yet.
pub fn router(cfg: &WebConfig) -> Router {
    router_with(cfg, Router::new())
}

/// Builds the application router with a fail-closed session gate: no login routes exist and no
/// request is ever admitted to `session_routes` (used by middleware tests). Production wiring
/// uses [`router_with_auth`]. Every path must also appear in [`routes::INVENTORY`].
pub fn router_with(cfg: &WebConfig, session_routes: Router) -> Router {
    // `layer` also wraps this router's fallback; the gate therefore answers a generic 404 for
    // unmatched paths itself (`route_layer` would panic on an empty router).
    let session_routes = session_routes.layer(from_fn(session::require_active_session));
    let app = Router::new()
        .route(
            "/healthz",
            get(healthz).layer(axum::Extension(HealthProbe(cfg.health_check.clone()))),
        )
        .route("/static/{*path}", get(assets::serve))
        .route("/api/v1/nzb", post(api_upload_unauthorized))
        .merge(session_routes);
    harden(app, cfg)
}

/// Builds the production router without an upload pipeline: `POST /api/v1/nzb` authenticates
/// but answers 501 (used by tests of the gates). See [`router_with_upload`].
pub fn router_with_auth(cfg: &WebConfig, auth: &AuthState, session_routes: Router) -> Router {
    router_with_upload(cfg, auth, session_routes, None)
}

/// Builds the production router: login flow (`/login`, `/login/mfa`, `/mfa/enroll`, `/logout`,
/// and the invitation page at `AuthConfig::invite_path` while `multi_user` is on)
/// plus `session_routes` behind the real gate (database-validated `active` session, Host
/// allowlist, CSRF on state-changing methods). Handlers behind the gate receive the
/// [`SessionCtx`] as a request extension. `api_upload` is the handler of `POST /api/v1/nzb`
/// ([`upload::api_route`]); it is always wrapped in the API-key gate here, so a handler can
/// never be reached unauthenticated.
pub fn router_with_upload(
    cfg: &WebConfig,
    auth: &AuthState,
    session_routes: Router,
    api_upload: Option<MethodRouter>,
) -> Router {
    // The gate looks the matched route up in `routes::INVENTORY` (minimum role, multi-user
    // switch); a route that is not listed there is unreachable (uniform 404).
    let gate = session::Gate::new(auth, cfg);
    let session_routes = session_routes
        .layer(from_fn_with_state(gate, session::active_gate))
        .layer(from_fn_with_state(auth.clone(), session::host_layer));
    let api = api_upload.unwrap_or_else(|| post(apikey::upload_disabled));
    let app = Router::new()
        .route(
            "/healthz",
            get(healthz).layer(axum::Extension(HealthProbe(cfg.health_check.clone()))),
        )
        .route("/static/{*path}", get(assets::serve))
        // Key-authenticated; ignores cookies.
        .route(
            "/api/v1/nzb",
            api.layer(from_fn_with_state(
                apikey::ApiKeyGate::new(auth),
                apikey::api_key_gate,
            )),
        )
        .merge(login::routes(auth))
        .merge(session_routes);
    let invite = auth
        .config()
        .multi_user
        .then(|| auth.config().invite_path.clone());
    harden_with(app, cfg, invite)
}

#[cfg(test)]
mod log_visibility_tests;
