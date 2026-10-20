//! The security middleware stack (`AUTH_SPEC` §Authorization order):
//! request-id + trusted-proxy IP + error finalisation -> security headers -> rate limit ->
//! limits/timeouts -> (session loader / CSRF, added by T043) -> route.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::WebConfig;
use crate::ctx::{ClientIp, RequestId, ViaTls, resolve_client};
use crate::error::{ApiError, finalize};
use crate::invite_path::InvitePath;
use crate::listener::PeerAddr;
use crate::ratelimit::{Class, Decision, IpUploadBucket, RateLimiter};
use crate::redact::path_for_log;

/// Max files in one UI upload request (SEC-035).
pub const MAX_UI_UPLOAD_FILES: u64 = 20;
/// The `/upload` body ceiling is this many maximum-size files, not [`MAX_UI_UPLOAD_FILES`]
/// of them: 20 files fit as long as together they stay within the ceiling, and a bigger batch is
/// split over several requests (T052; the old 20 x 64 MiB = 1.25 GiB ceiling was twice the
/// container memory budget and bought nothing for NZBs that are normally a few MiB).
pub const UI_UPLOAD_CEILING_FILES: u64 = 5;
/// Slack on top of the file bytes for multipart framing (API: one file, at most 8 parts).
const MULTIPART_SLACK: u64 = 64 * 1024;
/// Same for the UI form: the part allowance of the framing meter (4 KiB x the part cap of 64)
/// on top of [`MULTIPART_SLACK`].
const UI_MULTIPART_SLACK: u64 = MULTIPART_SLACK + 64 * 4 * 1024;
/// Longest accepted request target.
pub(crate) const MAX_URI_BYTES: usize = 8 * 1024;

/// Strict CSP (SEC-020). Exposed so tests and docs share one source of truth.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), display-capture=(), \
fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), \
payment=(), publickey-credentials-get=(), usb=(), interest-cohort=()";
const HSTS: &str = "max-age=31536000";

/// Headers [`headers_layer`] sets on every response (SEC-020, SEC-021), lowercase names. Public so
/// `nzbd security-headers` prints exactly what the middleware sends (the header audit of
/// `deploy/audit-headers.sh` compares a proxied page against it).
pub const SECURITY_HEADERS: [(&str, &str); 8] = [
    ("content-security-policy", CSP),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("x-frame-options", "DENY"),
    ("x-permitted-cross-domain-policies", "none"),
];

/// `Cache-Control` of every response that did not set its own (HTML pages, errors); static
/// assets override it with an immutable policy.
pub const DEFAULT_CACHE_CONTROL: &str = "no-store";

/// The security headers an HTML page (e.g. `/login`) carries, as `Name: value` lines with
/// conventional capitalisation: [`SECURITY_HEADERS`] then `Cache-Control`. HSTS is left out: nzbd
/// sends it only when a trusted proxy reports TLS, so the audit checks it on its own.
#[must_use]
pub fn security_headers_report() -> String {
    let mut out = String::new();
    let all = SECURITY_HEADERS
        .iter()
        .copied()
        .chain(std::iter::once(("cache-control", DEFAULT_CACHE_CONTROL)));
    for (name, value) in all {
        let pretty: Vec<String> = name
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_ascii_uppercase().to_string() + chars.as_str()
                })
            })
            .collect();
        out.push_str(&pretty.join("-"));
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// Marker: the request declared a `Content-Length` above the ceiling of its class. Role-gated
/// routes must answer a refused caller with the uniform 404 *before* any size verdict (a 413
/// would tell a viewer that an admin route exists), so for routes behind the access gate the
/// limits layer records the fact and the gate turns it into `413` only for admitted callers.
/// Unknown paths never read a body, so they simply answer 404.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeclaredOversize;

/// Shared, immutable middleware state.
pub(crate) struct Shared {
    pub(crate) cfg: WebConfig,
    limiter: Arc<RateLimiter>,
    in_flight: Semaphore,
    /// The invitation path while the page is mounted (T135; `None` while `multi_user` is off):
    /// login class and pre-auth body verdict. An unmounted path is classified like any unknown
    /// path, so neither counting nor a `413` can tell it apart.
    invite: Option<InvitePath>,
}

impl Shared {
    pub(crate) fn new(cfg: &WebConfig, invite: Option<InvitePath>) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(cfg.rate_limits, cfg.clock.clone())),
            in_flight: Semaphore::new(cfg.max_in_flight.max(1)),
            cfg: cfg.clone(),
            invite,
        }
    }
}

type St = State<Arc<Shared>>;

/// Route class used for rate limiting, body ceilings and timeouts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Exempt,
    Ui,
    Download,
    ApiUpload,
    UiUpload,
    Login,
    /// A credential-class POST of a ROLE-GATED route (admin pages, delete, purge, API keys): its
    /// per-IP budget is charged by the access gate AFTER the role decision, so a refused role or an
    /// unknown path never reveals the route by counting (`SEC-060`, review R2).
    GatedLogin,
}

/// The shared per-IP limiter, handed to the access gate (which charges [`Kind::GatedLogin`] and
/// `/upload` after the role check).
#[derive(Clone)]
pub(crate) struct SharedLimiter(pub(crate) Arc<RateLimiter>);

/// Route patterns (matched paths) whose per-IP class is charged after the access decision, and
/// that class. `/upload` is the Upload class (and hands the handler its per-file bucket).
pub(crate) fn gated_class(method: &Method, pattern: &str) -> Option<Class> {
    if *method != Method::POST {
        return None;
    }
    match pattern {
        "/upload" => Some(Class::Upload),
        "/account/api-keys"
        | "/admin/users/invite"
        | "/admin/health/deep"
        | "/admin/users/{id}/role"
        | "/admin/users/{id}/enable"
        | "/admin/users/{id}/recover"
        | "/admin/users/{id}/delete"
        | "/admin/users/{id}/revoke-sessions"
        | "/release/{id}/delete"
        | "/releases/bulk/delete"
        | "/admin/cleanup/purge/{bucket}" => Some(Class::Login),
        _ => None,
    }
}

/// Charges the per-IP class of a gated route (after the role check). `Err` is the 429.
#[allow(clippy::result_large_err)]
pub(crate) fn charge_gated(req: &mut Request, pattern: &str) -> Result<(), Response> {
    let Some(class) = gated_class(req.method(), pattern) else {
        return Ok(());
    };
    // Fail closed: `rate_limit_layer` always installs the limiter, so its absence is a wiring
    // bug and must never become "unlimited" (S5).
    let Some(lim) = req.extensions().get::<SharedLimiter>().cloned() else {
        tracing::error!("shared rate limiter missing for a gated route");
        return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response());
    };
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    if let Decision::Deny { retry_after_secs } = lim.0.check(class, ip) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
            .retry_after(retry_after_secs)
            .into_response());
    }
    if class == Class::Upload {
        req.extensions_mut()
            .insert(IpUploadBucket::new(Arc::clone(&lim.0), ip));
    }
    Ok(())
}

/// `invite` is the mounted invitation path: only it joins the login class; the built-in
/// `/invite` is then an ordinary unknown path (UI class), exactly like any other (T135).
///
/// `path` must be exactly what the router matches: the raw `uri().path()`, case-sensitive and
/// never percent-decoded or slash-normalised (axum matches it that way). Normalising here and not
/// there would put a variant such as `/%69nvite` or `//join-x` in a different class than the
/// route that answers it, and the class would then tell such a variant apart (review 49 I2).
fn classify(method: &Method, path: &str, invite: Option<&str>) -> Kind {
    if path == "/healthz" || path.starts_with("/static/") {
        return Kind::Exempt;
    }
    if method == Method::POST && path == "/api/v1/nzb" {
        return Kind::ApiUpload;
    }
    if method == Method::POST
        && (matches!(
            path,
            "/login"
                | "/login/mfa"
                | "/mfa/enroll"
                | "/account/password"
                | "/account/recovery-codes"
        )
            // The invitation page shares the login budget so code guessing and password
            // spraying spend one pool (T101, SEC-066).
            || invite == Some(path))
    {
        return Kind::Login;
    }
    // Role-gated credential POSTs: same tight budget as credential POSTs, charged by the gate
    // after the role decision (see `Kind::GatedLogin`).
    if method == Method::POST
        && matches!(
            path,
            "/account/api-keys" | "/admin/users/invite" | "/admin/health/deep"
        )
    {
        return Kind::GatedLogin;
    }
    // Re-authenticated account actions of the Users page.
    if method == Method::POST
        && path.starts_with("/admin/users/")
        && [
            "/role",
            "/enable",
            "/recover",
            "/delete",
            "/revoke-sessions",
        ]
        .iter()
        .any(|s| path.ends_with(s))
    {
        return Kind::GatedLogin;
    }
    // Destructive, re-authenticated actions share the credential budget (T081).
    if method == Method::POST
        && ((path.starts_with("/release/") && path.ends_with("/delete"))
            || path == "/releases/bulk/delete"
            || path.starts_with("/admin/cleanup/purge/"))
    {
        return Kind::GatedLogin;
    }
    if method == Method::POST && path == "/upload" {
        return Kind::UiUpload;
    }
    if (method == Method::GET || method == Method::HEAD)
        && path.starts_with("/release/")
        && path.ends_with("/download")
    {
        return Kind::Download;
    }
    // The partial download (T125) and the bulk download (T130) share the download budget.
    if method == Method::POST && path == "/releases/bulk/download" {
        return Kind::Download;
    }
    if method == Method::POST
        && path.starts_with("/release/")
        && path.ends_with("/download/selected")
    {
        return Kind::Download;
    }
    Kind::Ui
}

/// `Retry-After` of the uniform busy answer (SEC-095).
const BUSY_RETRY_AFTER_SECS: u64 = 2;

/// Outermost layer: request id, trusted-proxy client IP, uniform error bodies, access log.
pub(crate) async fn context_layer(State(sh): St, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    let id = RequestId::generate();
    // No peer info (cannot happen under `serve`) maps to 0.0.0.0, which is never a trusted proxy.
    let peer = req
        .extensions()
        .get::<ConnectInfo<PeerAddr>>()
        .map(|c| c.0.0)
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0)
        })
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.ip());
    let (ip, tls) = resolve_client(peer, &sh.cfg.trusted_proxies, req.headers());
    req.extensions_mut().insert(id.clone());
    req.extensions_mut().insert(ClientIp(ip));
    req.extensions_mut().insert(ViaTls(tls));

    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path(), axum::http::uri::PathAndQuery::as_str);
    // Query strings can carry tokens: never logged. Cap length against log flooding.
    let path_log: String = path_for_log(target).chars().take(200).collect();
    // Native form POSTs request HTML too. Their validation errors must remain navigable pages;
    // API routes always retain JSON, and non-browser callers keep JSON unless they ask for HTML.
    let wants_html = !req.uri().path().starts_with("/api/")
        && req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));

    // SEC-095: a store call that failed because the database was busy (pool timeout, statement or lock timeout,
    // SQLite busy) turns this request's generic 500 into the uniform `503 BUSY` with `Retry-After`.
    let (resp, busy) = nzb_store::busy::scope(next.run(req)).await;
    let resp = if busy && resp.status() == StatusCode::INTERNAL_SERVER_ERROR {
        let mut busy_response =
            crate::error::ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
                .retry_after(BUSY_RETRY_AFTER_SECS)
                .into_response();
        // This replacement happens outside headers_layer, so it needs the same protections.
        apply_security_headers(&mut busy_response, tls);
        busy_response
    } else {
        resp
    };
    let mut resp = finalize(resp, &id.0, wants_html);
    if let Ok(v) = HeaderValue::from_str(&id.0) {
        resp.headers_mut().insert("x-request-id", v);
    }
    tracing::info!(
        request_id = %id.0,
        method = %method,
        path = %path_log,
        status = resp.status().as_u16(),
        ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        ip = %ip,
        "request"
    );
    resp
}

/// Outermost: `Allow` belongs to a 405 only; any other status must not reveal the methods of a
/// route (`AUTH_SPEC` "Uniform 404 completeness" 1, T101).
pub(crate) async fn strip_allow(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    if resp.status() != StatusCode::METHOD_NOT_ALLOWED {
        resp.headers_mut().remove(header::ALLOW);
    }
    resp
}

/// Security headers on every response, including errors generated by inner layers
/// (SEC-020, SEC-021). `Cache-Control: no-store` is the default; static assets override it.
pub(crate) async fn headers_layer(req: Request, next: Next) -> Response {
    let tls = req.extensions().get::<ViaTls>().is_some_and(|t| t.0);
    let mut resp = next.run(req).await;
    apply_security_headers(&mut resp, tls);
    resp
}

fn apply_security_headers(resp: &mut Response, tls: bool) {
    let h = resp.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        h.insert(name, HeaderValue::from_static(value));
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(DEFAULT_CACHE_CONTROL),
        );
    }
    if tls {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
}

/// Per-IP rate limiting (SEC-029). Health checks and static assets are exempt.
pub(crate) async fn rate_limit_layer(State(sh): St, mut req: Request, next: Next) -> Response {
    let class = match classify(
        req.method(),
        req.uri().path(),
        sh.invite.as_ref().map(InvitePath::as_str),
    ) {
        Kind::Exempt => None,
        // `/upload` and the gated credential POSTs pay the general UI budget here, exactly like an
        // unknown path would (so counting cannot tell them apart, S1); their Login/Upload class
        // is charged by the access gate after the role decision, for admitted callers only (R2).
        Kind::Ui | Kind::UiUpload | Kind::GatedLogin => Some(Class::Ui),
        Kind::Download => Some(Class::Download),
        Kind::ApiUpload => Some(Class::Upload),
        Kind::Login => Some(Class::Login),
    };
    req.extensions_mut()
        .insert(SharedLimiter(Arc::clone(&sh.limiter)));
    if let Some(class) = class {
        let ip = req
            .extensions()
            .get::<ClientIp>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
        if let Decision::Deny { retry_after_secs } = sh.limiter.check(class, ip) {
            return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
                .retry_after(retry_after_secs)
                .into_response();
        }
        // The request itself cost one token. The UI upload handler spends one more per file
        // after the first (files, not requests, are what the bucket is meant to count).
        if matches!(class, Class::Upload) {
            req.extensions_mut()
                .insert(IpUploadBucket::new(Arc::clone(&sh.limiter), ip));
        }
    }
    next.run(req).await
}

fn header_bytes(req: &Request) -> usize {
    req.headers()
        .iter()
        .map(|(k, v)| k.as_str().len().saturating_add(v.len()))
        .fold(0_usize, usize::saturating_add)
}

/// Header/URI size caps, concurrency cap, body ceiling and request timeout (SEC-032).
pub(crate) async fn limits_layer(State(sh): St, mut req: Request, next: Next) -> Response {
    if req.uri().to_string().len() > MAX_URI_BYTES {
        return ApiError::new(StatusCode::URI_TOO_LONG, "REQUEST_TOO_LARGE").into_response();
    }
    if header_bytes(&req) > sh.cfg.max_header_bytes {
        return ApiError::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "REQUEST_TOO_LARGE",
        )
        .into_response();
    }
    let kind = classify(
        req.method(),
        req.uri().path(),
        sh.invite.as_ref().map(InvitePath::as_str),
    );
    let (cap, timeout) = match kind {
        Kind::ApiUpload => (
            sh.cfg.max_file_bytes.saturating_add(MULTIPART_SLACK),
            sh.cfg.upload_timeout,
        ),
        Kind::UiUpload => (
            sh.cfg
                .max_file_bytes
                .saturating_mul(UI_UPLOAD_CEILING_FILES)
                .saturating_add(UI_MULTIPART_SLACK),
            sh.cfg.upload_timeout,
        ),
        _ => (sh.cfg.max_body_bytes, sh.cfg.request_timeout),
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > cap) {
        // The pre-authentication routes (login flow, invitation, API key upload, probes and
        // assets) have no role to protect: refuse at once. Everything else can be a role-gated
        // route (or an unknown path): the access gate answers the uniform 404 to a refused caller
        // first and turns the marker into the 413 only for an admitted one (AUTH_SPEC "Uniform
        // 404 completeness" 2).
        let path = req.uri().path();
        let pre_auth = matches!(kind, Kind::ApiUpload | Kind::Exempt)
            || matches!(path, "/login" | "/login/mfa" | "/mfa/enroll" | "/logout")
            || sh.invite.as_ref().is_some_and(|i| i.as_str() == path);
        if pre_auth {
            return ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE").into_response();
        }
        req.extensions_mut().insert(DeclaredOversize);
    }
    // Held for the whole request; released when the response future completes. The liveness
    // probe takes no permit: a flood must not turn /healthz into a 503 and get a healthy
    // container restarted (it is trivially cheap and still bounded by the connection caps).
    let _permit = if req.uri().path() == "/healthz" {
        None
    } else {
        match sh.in_flight.try_acquire() {
            Ok(p) => Some(p),
            Err(_) => {
                return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
                    .retry_after(1)
                    .into_response();
            }
        }
    };
    // Enforces the ceiling on the stream itself (chunked bodies have no Content-Length).
    let limit = usize::try_from(cap).unwrap_or(usize::MAX);
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, Body::new(http_body_util::Limited::new(body, limit)));
    match tokio::time::timeout(timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => ApiError::new(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT").into_response(),
    }
}

/// Convenience for configs: default request timeout.
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod busy_header_tests {
    use super::*;
    use axum::{Router, routing::get};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One response matrix checks negotiation, TLS trust and error replacement.
    async fn busy_error_replacement_retains_all_security_headers() {
        let cfg = WebConfig {
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..WebConfig::default()
        };
        let app = crate::harden(
            Router::new()
                .route(
                    "/busy",
                    get(|| async {
                        nzb_store::busy::note(&nzb_store::StoreError::Io(std::io::Error::from(
                            std::io::ErrorKind::TimedOut,
                        )));
                        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
                    }),
                )
                .route(
                    "/ordinary",
                    get(|| async { ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL") }),
                ),
            &cfg,
        );
        for busy in [true, false] {
            for accept in ["text/html", "application/json"] {
                for (peer, scheme, tls) in [
                    ("127.0.0.1:12345", "https", true),
                    ("127.0.0.1:12345", "http", false),
                    ("198.51.100.7:12345", "https", false),
                ] {
                    let response = app
                        .clone()
                        .oneshot(
                            Request::builder()
                                .uri(if busy { "/busy" } else { "/ordinary" })
                                .header(header::ACCEPT, accept)
                                .header("x-forwarded-proto", scheme)
                                .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        if busy {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    );
                    for (name, value) in SECURITY_HEADERS {
                        assert_eq!(
                            response.headers().get(name),
                            Some(&HeaderValue::from_static(value)),
                            "missing or changed {name}: busy={busy}, accept={accept}, peer={peer}"
                        );
                    }
                    assert_eq!(
                        response.headers().get(header::CACHE_CONTROL),
                        Some(&HeaderValue::from_static("no-store"))
                    );
                    assert_eq!(
                        response.headers().get(header::STRICT_TRANSPORT_SECURITY),
                        tls.then(|| HeaderValue::from_static(HSTS)).as_ref()
                    );
                    assert_eq!(
                        response.headers().get(header::RETRY_AFTER),
                        busy.then(|| HeaderValue::from_static("2")).as_ref()
                    );
                    assert!(response.headers().contains_key("x-request-id"));
                    assert!(
                        response
                            .headers()
                            .get(header::CONTENT_TYPE)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .starts_with(accept)
                    );
                    let bytes = response.into_body().collect().await.unwrap().to_bytes();
                    let text = std::str::from_utf8(&bytes).unwrap();
                    assert!(text.contains(if busy { "BUSY" } else { "INTERNAL" }));
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{Router, routing::post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one response matrix verifies negotiation and the shared security headers
    async fn form_post_errors_are_html_but_api_and_json_clients_keep_json() {
        let app = crate::harden(
            Router::new()
                .route(
                    "/release/7/download/selected",
                    post(|| async { ApiError::new(StatusCode::BAD_REQUEST, "NO_FILES_SELECTED") }),
                )
                .route(
                    "/releases/bulk/download",
                    post(|| async { ApiError::new(StatusCode::BAD_REQUEST, "NO_SELECTION") }),
                )
                .route(
                    "/api/v1/nzb",
                    post(|| async { ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST") }),
                ),
            &WebConfig::default(),
        );
        for (path, accept, htmx, html, code) in [
            (
                "/release/7/download/selected",
                "text/html,application/xhtml+xml",
                false,
                true,
                "NO_FILES_SELECTED",
            ),
            (
                "/releases/bulk/download",
                "text/html",
                false,
                true,
                "NO_SELECTION",
            ),
            (
                "/release/7/download/selected",
                "text/html",
                true,
                true,
                "NO_FILES_SELECTED",
            ),
            (
                "/release/7/download/selected",
                "application/json",
                false,
                false,
                "NO_FILES_SELECTED",
            ),
            (
                "/releases/bulk/download",
                "*/*",
                false,
                false,
                "NO_SELECTION",
            ),
            ("/api/v1/nzb", "text/html", false, false, "BAD_REQUEST"),
        ] {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::ACCEPT, accept)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if htmx {
                req = req.header("hx-request", "true");
            }
            let resp = app
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            // HTMX must retain the error status so its normal responseError handler announces it.
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path} {accept}");
            assert_eq!(
                resp.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(
                resp.headers().get("x-content-type-options").unwrap(),
                "nosniff"
            );
            let request_id = resp
                .headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let text = std::str::from_utf8(&body).unwrap();
            if html {
                assert!(content_type.starts_with("text/html"));
                assert!(text.contains("Nothing selected"));
                assert!(text.contains("Back to the index"));
                assert!(text.contains(code) && text.contains(&request_id));
            } else {
                assert_eq!(content_type, "application/json");
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(
                    json.pointer("/error/code")
                        .and_then(serde_json::Value::as_str),
                    Some(code)
                );
                assert_eq!(
                    json.pointer("/error/request_id")
                        .and_then(serde_json::Value::as_str),
                    Some(request_id.as_str())
                );
            }
        }
    }
}
