//! Gates in front of authenticated routes.
//!
//! * [`require_active_session`] is the fail-closed stub used when no [`AuthState`] is wired
//!   (`router`/`router_with`): it never admits anyone.
//! * [`active_gate`] admits only `stage = active` sessions validated against the database,
//!   applies the route's minimum role from [`crate::routes::INVENTORY`] (a refusal is the uniform
//!   404, byte-identical to an unknown path, SEC-060) and enforces CSRF (SEC-025) on
//!   state-changing methods before the route runs.
//! * [`pending_gate`] guards the MFA steps: only `pending_mfa` sessions pass.
//! * [`host_layer`] rejects unexpected `Host` values (DNS rebinding, review L4).

use nzb_store::prelude::*;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use nzb_store::SessionStage;

use crate::WebConfig;
use crate::auth::{AuthState, SessionCtx};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::middleware::{DeclaredOversize, charge_gated};
use crate::ratelimit::{Decision, KeyedLimiter};
use crate::routes;

/// Largest form body buffered to read the CSRF field (equals the global request ceiling).
const MAX_FORM_BYTES: usize = 64 * 1024;

/// Set on multipart `/upload` requests that carry no `X-CSRF-Token` header: a plain HTML form
/// cannot set headers, so the upload handler (T051) must verify the `csrf_token` form part itself
/// with [`csrf::token_matches`] before reading any file part. Absent otherwise.
#[derive(Clone)]
pub struct DeferredCsrf {
    /// The token the form part must equal.
    pub expected: String,
}

/// A bare redirect, optionally setting/clearing the session cookie.
pub(crate) fn see_other(location: &'static str, cookie: Option<HeaderValue>) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    if let Some(c) = cookie {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    resp
}

/// A session transition must replace the whole document, including when navigation was
/// enhanced by HTMX. A 303 is followed by `XMLHttpRequest` before HTMX can read its headers,
/// which otherwise tries to select the old page's fragment from the login document.
///
/// Only an HTMX `GET` gets `200` + `HX-Redirect`. Any other method keeps a non-2xx answer
/// (review 55, SEC-028: a state-changing request without a usable session never reads as a
/// success): an HTMX one gets `401` + `HX-Redirect` (htmx follows `HX-Redirect` before it looks
/// at the status), a plain one the usual `303`.
fn session_redirect(
    method: &Method,
    headers: &HeaderMap,
    location: &'static str,
    cookie: Option<HeaderValue>,
) -> Response {
    let mut resp = see_other(location, cookie);
    if headers.get("hx-request").is_some_and(|v| v == "true") {
        *resp.status_mut() = if *method == Method::GET {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        resp.headers_mut().remove(header::LOCATION);
        resp.headers_mut()
            .insert("hx-redirect", HeaderValue::from_static(location));
    }
    resp
}

pub(crate) fn csrf_rejected() -> Response {
    ApiError::new(StatusCode::FORBIDDEN, "CSRF_REJECTED").into_response()
}

fn internal() -> Response {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
}

/// Rejects the request unless it carries an active session (currently: never).
///
/// Cookies and `X-Api-Key` are deliberately not inspected here; neither can grant access.
pub(crate) async fn require_active_session(mut req: Request, _next: Next) -> Response {
    // No matched route means we are the fallback of the merged router: behave like a 404.
    let Some(pattern) = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
    else {
        return ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response();
    };
    // Nobody is admitted here; the per-IP class of a gated route is still charged so the stub
    // router keeps the budgets the middleware tests assert.
    if let Err(resp) = charge_gated(&mut req, &pattern) {
        return resp;
    }
    session_redirect(req.method(), req.headers(), "/login", None)
}

/// Host-header allowlist for every route that handles credentials or sessions.
pub(crate) async fn host_layer(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    if !csrf::host_allowed(host, &auth.config().allowed_hosts) {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_HOST").into_response();
    }
    next.run(req).await
}

fn is_safe_method(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Enforces SEC-025 for a request belonging to `sess`: same-origin proof, then the per-session
/// synchronizer token from `X-CSRF-Token` or the `csrf_token` urlencoded form field. Returns the
/// request (body restored) or the rejection response. Query-string tokens are never accepted.
// The rejection is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
pub(crate) async fn enforce_csrf(
    sess: &SessionCtx,
    req: Request,
    require_https: bool,
) -> Result<Request, Response> {
    if is_safe_method(req.method()) {
        return Ok(req);
    }
    if !csrf::same_origin(req.headers(), require_https) {
        return Err(csrf_rejected());
    }
    if let Some(h) = req.headers().get("x-csrf-token") {
        return match h.to_str() {
            Ok(t) if csrf::token_matches(&sess.csrf_token, t) => Ok(req),
            _ => Err(csrf_rejected()),
        };
    }
    let ctype = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if ctype.starts_with("application/x-www-form-urlencoded") {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, MAX_FORM_BYTES)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response())?;
        let form = csrf::parse_form(&bytes);
        if !csrf::form_get(&form, "csrf_token")
            .is_some_and(|t| csrf::token_matches(&sess.csrf_token, t))
        {
            return Err(csrf_rejected());
        }
        return Ok(Request::from_parts(parts, Body::from(bytes)));
    }
    // A multipart upload form cannot be buffered here (it streams up to the file cap); the
    // handler must check the first form part. Everything else without a header is refused.
    if ctype.starts_with("multipart/form-data") && req.uri().path() == "/upload" {
        let mut req = req;
        req.extensions_mut().insert(DeferredCsrf {
            expected: sess.csrf_token.clone(),
        });
        return Ok(req);
    }
    Err(csrf_rejected())
}

/// Where a `pending_mfa` session must go next. A recovery session (a staged credential swap is
/// bound to it) belongs to the enrollment page even though the account has MFA enabled.
pub(crate) async fn pending_target(
    auth: &AuthState,
    sess: &SessionCtx,
) -> Result<&'static str, ()> {
    match auth
        .db()
        .staged_swap(sess.user_id, &sess.id_hash, auth.now())
        .await
    {
        Ok(Some(_)) => return Ok("/mfa/enroll"),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "staged swap lookup failed");
            return Err(());
        }
    }
    match auth.db().get_login_user_by_id(sess.user_id).await {
        Ok(Some(u)) if u.totp_enabled => Ok("/login/mfa"),
        Ok(Some(_)) => Ok("/mfa/enroll"),
        Ok(None) => Ok("/login"),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            Err(())
        }
    }
}

/// State of [`active_gate`]: the auth state and the per-account buckets (SEC-029, SEC-066), which
/// apply after the role check, next to the per-IP buckets of the rate-limit layer.
#[derive(Clone)]
pub(crate) struct Gate {
    pub(crate) auth: AuthState,
    ui: Arc<KeyedLimiter<i64>>,
    downloads: Arc<KeyedLimiter<i64>>,
}

/// Upper bound of tracked accounts per bucket (the account cap is far below it).
const GATE_MAX_KEYS: usize = 4096;

impl Gate {
    pub(crate) fn new(auth: &AuthState, cfg: &WebConfig) -> Self {
        Self {
            auth: auth.clone(),
            ui: Arc::new(KeyedLimiter::new(
                cfg.rate_limits.ui,
                GATE_MAX_KEYS,
                Arc::clone(&cfg.clock),
            )),
            downloads: Arc::new(KeyedLimiter::new(
                cfg.rate_limits.download,
                GATE_MAX_KEYS,
                Arc::clone(&cfg.clock),
            )),
        }
    }
}

/// The response of an unknown path (also what a refused role gets, `AUTH_SPEC` "Uniform 404
/// completeness"): produced in one place so the two cannot drift apart.
pub(crate) fn uniform_not_found() -> Response {
    ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response()
}

/// Admits only fully authenticated (`active`) sessions whose role reaches the route's minimum.
///
/// Order (`AUTH_SPEC` "Evaluation order"): matched route -> multi-user switch -> session (no
/// session: login redirect; pending: its MFA step) -> **role** (refusal = uniform 404, nothing
/// read or touched) -> declared size -> CSRF/Origin -> per-account limiter -> handler.
pub(crate) async fn active_gate(State(gate): State<Gate>, req: Request, next: Next) -> Response {
    let auth = &gate.auth;
    let Some(pattern) = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
    else {
        return uniform_not_found();
    };
    // An unlisted route is unreachable; a multi-user route does not exist while the flag is off,
    // for anonymous callers either.
    let Some((min_role, multi_user_only, registration_only)) = routes::session_access(&pattern)
    else {
        return uniform_not_found();
    };
    if registration_only && !auth.config().registration_enabled {
        return uniform_not_found();
    }
    if multi_user_only && !auth.config().multi_user {
        return uniform_not_found();
    }
    let had_cookie = auth.presented_id(req.headers()).is_some();
    let sess = match auth.peek_session(req.headers()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed");
            return internal();
        }
    };
    let s = match sess {
        None => {
            return session_redirect(
                req.method(),
                req.headers(),
                "/login",
                had_cookie.then(|| auth.clear_cookie()),
            );
        }
        Some(s) if s.stage == SessionStage::PendingMfa => {
            return match pending_target(auth, &s).await {
                Ok(target) => session_redirect(req.method(), req.headers(), target, None),
                Err(()) => internal(),
            };
        }
        Some(s) => s,
    };
    if s.role < min_role {
        // Read-only for the refused request: the audit row is queued off the request path.
        auth.note_denied(
            &s,
            min_role,
            routes::denied_token(&pattern),
            req.extensions().get::<ClientIp>().map(|c| c.0.to_string()),
        );
        return uniform_not_found();
    }
    // The per-IP class of credential and upload POSTs is charged only now: a refused role and an
    // unknown path never spend (and so never reveal) the budget of a gated route (R2).
    let mut req = req;
    if let Err(resp) = charge_gated(&mut req, &pattern) {
        return resp;
    }
    if req.extensions().get::<DeclaredOversize>().is_some() {
        return ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE").into_response();
    }
    let mut req = match enforce_csrf(&s, req, !auth.config().insecure_cookies).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // The bulk download (T130) spends the download bucket here; its strict bulk budget is charged
    // by the handler after its capacity check, so a busy answer costs none of it (review 46 L4).
    let limiter = match pattern.as_str() {
        "/release/{id}/download"
        | "/release/{id}/download/selected"
        | "/releases/bulk/download" => &gate.downloads,
        _ => &gate.ui,
    };
    if let Decision::Deny { retry_after_secs } = limiter.check(s.user_id) {
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
            .retry_after(retry_after_secs)
            .into_response();
    }
    if let Err(e) = auth.touch(&s).await {
        tracing::error!(error = %e, "session touch failed");
        return internal();
    }
    req.extensions_mut().insert(s);
    next.run(req).await
}

/// Admits only `pending_mfa` sessions (the MFA steps). Active sessions are sent to `/`.
pub(crate) async fn pending_gate(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Response {
    let had_cookie = auth.presented_id(req.headers()).is_some();
    let sess = match auth.load_session(req.headers()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed");
            return internal();
        }
    };
    match sess {
        None => session_redirect(
            req.method(),
            req.headers(),
            "/login",
            had_cookie.then(|| auth.clear_cookie()),
        ),
        Some(s) if s.stage == SessionStage::Active => {
            session_redirect(req.method(), req.headers(), "/", None)
        }
        Some(s) => {
            let mut req = match enforce_csrf(&s, req, !auth.config().insecure_cookies).await {
                Ok(r) => r,
                Err(resp) => return resp,
            };
            req.extensions_mut().insert(s);
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_transitions_navigate_the_whole_document_for_htmx() {
        for location in ["/login", "/login/mfa", "/mfa/enroll", "/"] {
            let mut headers = HeaderMap::new();
            headers.insert("hx-request", HeaderValue::from_static("true"));
            let cookie = HeaderValue::from_static("session=; Max-Age=0; HttpOnly");
            let response = session_redirect(&Method::GET, &headers, location, Some(cookie.clone()));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("hx-redirect")
                    .and_then(|v| v.to_str().ok()),
                Some(location)
            );
            assert!(!response.headers().contains_key(header::LOCATION));
            assert_eq!(response.headers().get(header::SET_COOKIE), Some(&cookie));
        }
    }

    #[test]
    fn ordinary_navigation_keeps_the_http_redirect() {
        for hx in [None, Some("false"), Some("unexpected")] {
            let mut headers = HeaderMap::new();
            if let Some(value) = hx {
                headers.insert("hx-request", HeaderValue::from_static(value));
            }
            for method in [Method::GET, Method::POST] {
                let response = session_redirect(&method, &headers, "/login", None);
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                assert_eq!(
                    response
                        .headers()
                        .get(header::LOCATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("/login")
                );
                assert!(!response.headers().contains_key("hx-redirect"));
            }
        }
    }

    /// Review 55 / SEC-028: an HTMX write without a usable session is never a 2xx.
    #[test]
    fn sec_028_htmx_writes_without_a_session_stay_non_2xx() {
        let mut headers = HeaderMap::new();
        headers.insert("hx-request", HeaderValue::from_static("true"));
        for method in [
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
        ] {
            let response = session_redirect(&method, &headers, "/login", None);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method}");
            assert_eq!(
                response
                    .headers()
                    .get("hx-redirect")
                    .and_then(|v| v.to_str().ok()),
                Some("/login")
            );
            assert!(!response.headers().contains_key(header::LOCATION));
        }
    }
}
