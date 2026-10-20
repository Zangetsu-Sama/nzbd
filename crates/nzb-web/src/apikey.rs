//! Upload-only API keys (SEC-036, `AUTH_SPEC` §API keys).
//!
//! * Format `nzbd_<43 base64url chars>` = 256 bits from the OS CSPRNG. The secret is returned to
//!   the creator once; the database keeps `SHA-256("nzbd/apikey/v1\0" || key)` (a fast hash is
//!   sound here because the input is 256-bit random, not a human password) plus a six character
//!   display prefix and a sanitized label.
//! * The key is accepted ONLY in the `X-Api-Key` header. A request that carries something key
//!   shaped in its query string is refused with the same uniform 401 as every other failure, so a
//!   key in a URL is never honoured (and the access log never records query strings anyway).
//! * [`api_key_gate`] is independent of the session machinery: cookies are never looked at, and
//!   nothing in the session gate looks at `X-Api-Key`.
//! * Unknown, revoked, malformed, duplicated or missing keys all produce the identical 401 and do
//!   the same work on the request path (one hash, one indexed read, one constant-time compare);
//!   the audit row for a failure is written off the request path and throttled.

use nzb_store::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nzb_store::{Actor, CreateKey, NewApiKey, Store, StoreError};
use zeroize::Zeroizing;

use crate::auth::AuthState;
use crate::crypto::{self, RandomError};
use crate::ctx::ClientIp;
use crate::error::ApiError;

/// Every key starts with this.
pub const KEY_PREFIX: &str = "nzbd_";
/// Characters of the random part: 32 bytes in unpadded base64url.
const RANDOM_CHARS: usize = 43;
/// Total length of a well-formed key.
pub const KEY_LEN: usize = KEY_PREFIX.len() + RANDOM_CHARS;
/// Characters of the random part kept for display.
const PREFIX_CHARS: usize = 6;
/// Most unrevoked keys per owner at any time (T103; with one account this is the 1.x cap). The
/// instance as a whole is capped by `nzb_store::MAX_ACTIVE_KEYS_INSTANCE`.
pub const MAX_ACTIVE_KEYS: u32 = nzb_store::MAX_ACTIVE_KEYS_PER_OWNER;
/// `last_used_at` is refreshed at most this often per key (`AUTH_SPEC`: at most once a minute).
pub const TOUCH_INTERVAL_SECS: i64 = 60;
/// At most one failure audit row per this many seconds (the writer is a shared resource).
const FAILURE_AUDIT_INTERVAL_SECS: i64 = 60;
/// Longest header value that is hashed (anything longer cannot be a key).
const MAX_PRESENTED_BYTES: usize = 128;
/// Domain separation for the stored hash.
const HASH_DOMAIN: &[u8] = b"nzbd/apikey/v1\0";

/// A freshly generated key. `Debug` never prints the secret; the buffer is zeroized on drop.
pub struct GeneratedKey {
    /// The full secret, `nzbd_...`. Shown once to the operator, never stored or logged.
    pub secret: Zeroizing<String>,
    /// Non-secret display prefix (first characters of the random part).
    pub prefix: String,
    /// The value to store.
    pub hash: [u8; 32],
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("secret", &"[REDACTED]")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Draws a new key from the OS CSPRNG.
///
/// # Errors
/// [`RandomError`] if the kernel random source is unavailable (no weaker fallback).
pub fn generate() -> Result<GeneratedKey, RandomError> {
    let raw = Zeroizing::new(crypto::random_bytes::<32>()?);
    let random = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()));
    let secret = Zeroizing::new(format!("{KEY_PREFIX}{}", random.as_str()));
    let prefix: String = random.chars().take(PREFIX_CHARS).collect();
    let hash = hash_key(secret.as_bytes());
    Ok(GeneratedKey {
        secret,
        prefix,
        hash,
    })
}

/// Domain-separated SHA-256 of a presented or generated key.
#[must_use]
pub fn hash_key(key: &[u8]) -> [u8; 32] {
    let mut buf = Zeroizing::new(Vec::with_capacity(
        HASH_DOMAIN.len().saturating_add(key.len()),
    ));
    buf.extend_from_slice(HASH_DOMAIN);
    buf.extend_from_slice(key);
    crypto::sha256(&buf)
}

/// Whether `s` has the exact shape of a key (cheap syntactic check; not authentication).
#[must_use]
pub fn is_well_formed(s: &[u8]) -> bool {
    s.len() == KEY_LEN
        && s.starts_with(KEY_PREFIX.as_bytes())
        && s.iter()
            .skip(KEY_PREFIX.len())
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

/// Why creating a key failed.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// Label empty, too long or with disallowed characters.
    #[error("invalid label: use 1-64 letters, digits, spaces or . _ - : @ ( ) + # /")]
    InvalidLabel,
    /// The cap of unrevoked keys (per owner, or of the instance) is reached.
    #[error("limit of {MAX_ACTIVE_KEYS} active API keys reached; revoke one first")]
    LimitReached,
    /// The instance-wide cap of unrevoked keys is reached.
    #[error("the instance limit of active API keys is reached")]
    InstanceLimitReached,
    /// The per-key rate is outside 1..=30 uploads per minute.
    #[error("invalid rate: use 1 to 30 uploads per minute")]
    InvalidRate,
    /// No secure random bytes.
    #[error("operating system random source unavailable")]
    Random,
    /// Storage failure.
    #[error("{0}")]
    Store(StoreError),
}

/// Generates and stores a key; returns the id and the secret (to be shown once). Shared by the
/// CLI and the account page so both enforce the same label rule and cap.
///
/// # Errors
/// See [`IssueError`].
pub async fn issue(
    db: &Store,
    label: &str,
    now: i64,
    actor: Actor<'_>,
) -> Result<(i64, GeneratedKey), IssueError> {
    issue_with_rate(db, label, None, now, actor).await
}

/// [`issue`] (owner: the oldest enabled admin) with an optional per-key budget in uploads per
/// minute, `1..=30`.
///
/// # Errors
/// See [`IssueError`].
pub async fn issue_with_rate(
    db: &Store,
    label: &str,
    rate_per_min: Option<u32>,
    now: i64,
    actor: Actor<'_>,
) -> Result<(i64, GeneratedKey), IssueError> {
    if nzb_store::sanitize_label(label).is_none() {
        return Err(IssueError::InvalidLabel);
    }
    if rate_per_min.is_some_and(|n| !(1..=nzb_store::MAX_RATE_PER_MIN).contains(&n)) {
        return Err(IssueError::InvalidRate);
    }
    let key = generate().map_err(|_| IssueError::Random)?;
    let new = NewApiKey {
        label,
        prefix: &key.prefix,
        key_hash: &key.hash,
        rate_per_min,
    };
    match db.create_api_key(new, MAX_ACTIVE_KEYS, now, actor).await {
        Ok(CreateKey::Created(id)) => Ok((id, key)),
        Ok(CreateKey::LimitReached) => Err(IssueError::LimitReached),
        Ok(CreateKey::InstanceLimitReached) => Err(IssueError::InstanceLimitReached),
        Err(StoreError::InvalidLabel) => Err(IssueError::InvalidLabel),
        Err(e) => Err(IssueError::Store(e)),
    }
}

/// Like [`issue`] with an explicit OWNER and audit identity (T101): the key belongs to `owner`
/// (a live, enabled uploader or admin; the store re-checks it) and the attribution of its uploads
/// follows the owner. `owner` comes from the session, never from a form.
///
/// # Errors
/// See [`IssueError`]; an unusable owner is `Store(Account(Forbidden))`.
pub async fn issue_for(
    db: &Store,
    label: &str,
    owner: i64,
    who: &nzb_store::AuditActor,
    ip: Option<&str>,
    now: i64,
) -> Result<(i64, GeneratedKey), IssueError> {
    issue_for_rate(db, label, owner, None, None, who, ip, now).await
}

/// [`issue_for`] with an optional per-key budget in uploads per minute (`1..=30`; the effective
/// budget is the lower of this and `limits.upload_per_key_per_min`). From the web, `session` is the
/// session that re-authenticated: the key is only created while it is still live.
///
/// # Errors
/// See [`IssueError`]; a rate outside `1..=30` is [`IssueError::InvalidRate`]; a `session` that is
/// gone is `Store(NotFound)`.
#[allow(clippy::too_many_arguments)] // CLI and web entry point; each value is a distinct input
pub async fn issue_for_rate(
    db: &Store,
    label: &str,
    owner: i64,
    rate_per_min: Option<u32>,
    session: Option<&[u8; 32]>,
    who: &nzb_store::AuditActor,
    ip: Option<&str>,
    now: i64,
) -> Result<(i64, GeneratedKey), IssueError> {
    if nzb_store::sanitize_label(label).is_none() {
        return Err(IssueError::InvalidLabel);
    }
    if rate_per_min.is_some_and(|n| !(1..=nzb_store::MAX_RATE_PER_MIN).contains(&n)) {
        return Err(IssueError::InvalidRate);
    }
    let key = generate().map_err(|_| IssueError::Random)?;
    let new = NewApiKey {
        label,
        prefix: &key.prefix,
        key_hash: &key.hash,
        rate_per_min,
    };
    let created = match session {
        Some(h) => {
            db.create_api_key_for_session(new, owner, h, MAX_ACTIVE_KEYS, now, who, ip)
                .await
        }
        None => {
            db.create_api_key_for(new, owner, MAX_ACTIVE_KEYS, now, who, ip)
                .await
        }
    };
    match created {
        Ok(CreateKey::Created(id)) => Ok((id, key)),
        Ok(CreateKey::LimitReached) => Err(IssueError::LimitReached),
        Ok(CreateKey::InstanceLimitReached) => Err(IssueError::InstanceLimitReached),
        Err(StoreError::InvalidLabel) => Err(IssueError::InvalidLabel),
        Err(e) => Err(IssueError::Store(e)),
    }
}

/// Request extension set by [`api_key_gate`] for authenticated calls. The per-key upload bucket
/// (SEC-029) is keyed on `id`.
#[derive(Clone, Copy, Debug)]
pub struct ApiKeyCtx {
    /// `api_key.id` of the authenticated key.
    pub id: i64,
    /// The key's owner (the account whose upload budget it also spends).
    pub owner_id: Option<i64>,
    /// The key's own budget in uploads per minute (`None` = the instance budget).
    pub rate_per_min: Option<u32>,
}

/// Failure reasons recorded in the audit log; each has its own throttle slot so one noisy
/// reason cannot mask another (`SECURITY_REVIEW` T050 L1).
const REASONS: [&str; 5] = ["query", "malformed", "unknown", "revoked", "owner"];

/// Per-reason audit throttle with a count of suppressed events.
struct AuditThrottle {
    last: [AtomicI64; 5],
    suppressed: [AtomicU64; 5],
}

impl AuditThrottle {
    fn new() -> Self {
        Self {
            last: [(); 5].map(|()| AtomicI64::new(i64::MIN)),
            suppressed: [(); 5].map(|()| AtomicU64::new(0)),
        }
    }

    /// Decides whether `reason` is recorded now. Returns the number of events suppressed since
    /// the previous row, or `None` when this event itself is suppressed. `revoked` (a leaked key
    /// being replayed) is never suppressed; the per-IP upload limiter bounds its rate.
    fn admit(&self, reason: &str, now: i64) -> Option<u64> {
        let i = REASONS.iter().position(|r| *r == reason).unwrap_or(2);
        let (Some(last), Some(sup)) = (self.last.get(i), self.suppressed.get(i)) else {
            return Some(0);
        };
        if reason != "revoked" {
            let prev = last.load(Ordering::Relaxed);
            if now.saturating_sub(prev) < FAILURE_AUDIT_INTERVAL_SECS
                || last
                    .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_err()
            {
                sup.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        Some(sup.swap(0, Ordering::Relaxed))
    }
}

/// State of the API gate: the auth state (database + clock) and the failure-audit throttle.
#[derive(Clone)]
pub struct ApiKeyGate {
    auth: AuthState,
    throttle: Arc<AuditThrottle>,
}

impl ApiKeyGate {
    /// Builds the gate over the shared auth state.
    #[must_use]
    pub fn new(auth: &AuthState) -> Self {
        Self {
            auth: auth.clone(),
            throttle: Arc::new(AuditThrottle::new()),
        }
    }

    /// Records a failed attempt (SEC-033) without blocking the response; throttled per reason
    /// (one row per interval, `revoked` always), with the number of suppressed events folded
    /// into the next row. No request data beyond the client IP and a coarse reason.
    fn audit_failure(&self, reason: &'static str, ip: Option<String>) {
        let now = self.auth.now();
        let Some(suppressed) = self.throttle.admit(reason, now) else {
            return;
        };
        let detail = if suppressed > 0 {
            format!("{reason} suppressed={suppressed}")
        } else {
            reason.to_owned()
        };
        let db = self.auth.db().clone();
        tokio::spawn(async move {
            if let Err(e) = db
                .audit_event(
                    now,
                    Some("api"),
                    "apikey.use_failure",
                    Some(detail.as_str()),
                    ip.as_deref(),
                )
                .await
            {
                tracing::error!(error = %e, "api key failure audit failed");
            }
        });
    }
}

fn unauthorized() -> Response {
    ApiError::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED").into_response()
}

/// Whether the query string carries something that looks like an API key or a parameter named
/// like one. Such a request is refused even if it also has a valid header.
fn query_has_key(query: &str) -> bool {
    if query.contains(KEY_PREFIX) {
        return true;
    }
    query.split('&').any(|pair| {
        let name = pair
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        matches!(
            name.as_str(),
            "apikey" | "api_key" | "api-key" | "x-api-key" | "x_api_key" | "key"
        )
    })
}

/// Authenticates `POST /api/v1/nzb` by `X-Api-Key` alone.
pub async fn api_key_gate(
    State(gate): State<ApiKeyGate>,
    mut req: Request,
    next: Next,
) -> Response {
    let ip = req.extensions().get::<ClientIp>().map(|c| c.0.to_string());
    if req.uri().query().is_some_and(query_has_key) {
        gate.audit_failure("query", ip);
        return unauthorized();
    }
    let mut values = req.headers().get_all("x-api-key").iter();
    let (first, extra) = (values.next(), values.next().is_some());
    let Some(first) = first else {
        // No credential at all (e.g. a browser with only a cookie): not worth an audit row.
        return unauthorized();
    };
    let presented = first.as_bytes();
    // Always hash and look up, whatever the shape, so malformed input costs the same as a miss.
    let capped = presented.get(..MAX_PRESENTED_BYTES).unwrap_or(presented);
    let hash = hash_key(capped);
    let found = gate.auth.db().find_api_key(&hash).await;
    let shaped = is_well_formed(presented) && !extra;
    let verdict = match found {
        // The key is accepted only while its owner is a live, enabled uploader or admin (SEC-036,
        // checked on every use; the ingest transaction checks again, N9).
        Ok(Some(k)) if crypto::ct_eq(&k.key_hash, &hash) && shaped && k.may_upload() => Ok(k),
        Ok(Some(k)) if k.revoked => Err("revoked"),
        Ok(Some(k)) if shaped && crypto::ct_eq(&k.key_hash, &hash) => Err("owner"),
        Ok(_) if !shaped => Err("malformed"),
        Ok(_) => Err("unknown"),
        Err(e) => {
            tracing::error!(error = %e, "api key lookup failed");
            // Fail closed, and not as a distinguishable error.
            return unauthorized();
        }
    };
    match verdict {
        Ok(k) => {
            let now = gate.auth.now();
            let stale = k
                .last_used_at
                .is_none_or(|t| now.saturating_sub(t) >= TOUCH_INTERVAL_SECS);
            if stale
                && let Err(e) = gate
                    .auth
                    .db()
                    .touch_api_key(k.id, now, TOUCH_INTERVAL_SECS)
                    .await
            {
                tracing::error!(error = %e, "api key touch failed");
            }
            req.extensions_mut().insert(ApiKeyCtx {
                id: k.id,
                owner_id: k.owner_id,
                rate_per_min: k.rate_per_min,
            });
            next.run(req).await
        }
        Err(reason) => {
            gate.audit_failure(reason, ip);
            unauthorized()
        }
    }
}

/// `POST /api/v1/nzb` for authenticated callers when no upload pipeline is wired (gate tests
/// only; `nzbd` always wires [`crate::upload::api_route`]): a uniform 501 that never reads the
/// body and ingests nothing.
pub async fn upload_disabled() -> Response {
    ApiError::new(StatusCode::NOT_IMPLEMENTED, "UPLOAD_DISABLED").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_well_formed_unique_and_hashed_consistently() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert!(is_well_formed(a.secret.as_bytes()));
        assert_eq!(a.secret.len(), KEY_LEN);
        assert_ne!(a.secret.as_str(), b.secret.as_str());
        assert_eq!(a.hash, hash_key(a.secret.as_bytes()));
        assert_ne!(a.hash, crypto::sha256(a.secret.as_bytes()));
        assert!(a.secret.contains(&a.prefix));
        assert!(!format!("{a:?}").contains(a.secret.as_str()));
    }

    #[test]
    fn shape_check_rejects_near_misses() {
        let k = generate().unwrap();
        let s = k.secret.as_str();
        assert!(!is_well_formed(format!("{s}A").as_bytes()));
        assert!(!is_well_formed(&s.as_bytes()[..s.len() - 1]));
        assert!(!is_well_formed(s.replacen("nzbd_", "nzbx_", 1).as_bytes()));
        assert!(!is_well_formed(
            format!("{} ", &s[..s.len() - 1]).as_bytes()
        ));
        assert!(!is_well_formed(b""));
    }

    #[test]
    fn query_detection() {
        assert!(query_has_key("api_key=abc"));
        assert!(query_has_key("a=1&X-Api-Key=abc"));
        assert!(query_has_key("foo=nzbd_whatever"));
        assert!(!query_has_key("category=anime"));
        assert!(!query_has_key(""));
    }
}
