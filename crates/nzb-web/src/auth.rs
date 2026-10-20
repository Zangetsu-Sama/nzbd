//! Session management shared by the login flow, the session gate and (later) MFA/account pages.
//!
//! Invariants (SEC-024, review carry-forward):
//! * session ids are 256 bits from the OS CSPRNG; only `SHA-256(id)` is stored;
//! * every request is validated against the database (no in-memory session cache), so CLI
//!   resets and logouts take effect immediately;
//! * a new id is minted for every stage change (login, MFA completion); a presented cookie is
//!   never promoted or reused (session fixation);
//! * cookies are `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, unless
//!   the D16 opt-out is configured.

use nzb_store::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nzb_store::{
    AccountActor, AccountPolicy, AttemptContext, AuditActor, AuditEntry, LoginUser, NewSession,
    Role, SessionStage, Store, StoreError,
};
use tokio::sync::{Semaphore, mpsc};

use crate::crypto::{self, RandomError};
use crate::password::{self, PasswordError};
use crate::ratelimit::{self, Clock, Decision, KeyedLimiter};
use crate::totp::TotpKey;

/// Cookie name with the `__Host-` prefix (default).
pub const COOKIE_NAME: &str = "__Host-nzbd_session";
/// Cookie name used only with the D16 plain-HTTP opt-out (`__Host-` requires `Secure`).
pub const COOKIE_NAME_INSECURE: &str = "nzbd_session";
/// Login-form nonce cookie name (`__Host-` prefix; T083).
pub const LOGIN_NONCE_COOKIE: &str = "__Host-nzbd_login";
/// Its name with the D16 plain-HTTP opt-out.
pub const LOGIN_NONCE_COOKIE_INSECURE: &str = "nzbd_login";
/// Pending-MFA sessions live this long (`AUTH_SPEC`).
pub const PENDING_SECS: i64 = 300;
/// `last_seen_at` is refreshed at most this often.
pub const TOUCH_INTERVAL_SECS: i64 = 60;
/// Length of an encoded session id (256 bits, base64url without padding).
const SESSION_ID_CHARS: usize = 43;
/// At most this many logins may queue behind the running Argon2 verifications; more get 503.
pub const MAX_VERIFY_WAITERS: usize = 8;
/// `/invite` Argon2 queue (L2): one permit and two waiters, separate from the login queue, so an
/// anonymous flood of invitation attempts cannot make the owner's `/login` answer `503`.
pub const MAX_INVITE_WAITERS: usize = 2;
/// Interval of the background purge task.
pub const PURGE_INTERVAL: Duration = Duration::from_secs(600);

/// Wall-clock time source (unix seconds) so tests control expiry deterministically.
pub trait WallClock: Send + Sync + 'static {
    /// Current unix time in seconds.
    fn now_secs(&self) -> i64;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_secs(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

/// Settable clock for tests.
#[derive(Debug, Default)]
pub struct ManualWallClock(AtomicI64);

impl ManualWallClock {
    /// Starts at `secs`.
    #[must_use]
    pub fn new(secs: i64) -> Self {
        Self(AtomicI64::new(secs))
    }

    /// Moves time forward.
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::Relaxed);
    }
}

impl WallClock for ManualWallClock {
    fn now_secs(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Authentication settings (from `security.*` and `server.*` config).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Idle timeout for active sessions.
    pub idle_secs: i64,
    /// Absolute lifetime of any session.
    pub max_secs: i64,
    /// Lifetime of a `pending_mfa` session.
    pub pending_secs: i64,
    /// D16 opt-out: plain-HTTP cookies without `__Host-`/`Secure`.
    pub insecure_cookies: bool,
    /// Extra accepted `Host` names (lowercase, no port); loopback and IP literals are implicit.
    pub allowed_hosts: Vec<String>,
    /// Sessions kept per stage; the oldest of that stage is revoked beyond this.
    pub max_sessions: u32,
    /// Concurrent Argon2 verifications (each needs 64 MiB).
    pub verify_concurrency: usize,
    /// Key that encrypts TOTP secrets at rest (from `security.totp_key_file`). `None` makes every
    /// MFA step fail closed (500); there is deliberately no default key.
    pub totp_key: Option<Arc<TotpKey>>,
    /// Category ids whose releases are not displayed (`ui.show_xxx = false`: the XXX category
    /// and its children, derived once from the taxonomy). Carried to every handler through
    /// [`SessionCtx::hidden_categories`]; empty shows everything.
    pub hidden_categories: Arc<[u16]>,
    /// The XXX category and its children (taxonomy subtree of 6000), hidden for an account whose
    /// preference "Hide XXX for me" is on (T120). Derived once from the taxonomy; the default is the
    /// built-in taxonomy's subtree.
    pub xxx_categories: Arc<[u16]>,
    /// `security.multi_user` (default `false`): `/invite` and every `/admin/users*` and
    /// `/admin/invites*` route exist only while it is `true` (`AUTH_SPEC` "`security.multi_user`").
    pub multi_user: bool,
    /// Lifetime of an invitation code in seconds (`security.invite_ttl_hours`).
    pub invite_ttl_secs: i64,
    /// Lifetime of an admin-issued recovery code in seconds (`security.recover_ttl_hours`).
    pub recover_ttl_secs: i64,
    /// `security.registration_enabled` (D28, default `true`; no effect while `multi_user` is off):
    /// `false` removes the invitation surface (create, redeem); recovery codes keep working.
    pub registration_enabled: bool,
    /// Live account cap (`security.max_accounts`).
    pub max_accounts: u32,
    /// `server.public_url`: scheme and host (and port) printed on invitation pages. Never taken
    /// from the request `Host` header (L4).
    pub public_url: Option<String>,
    /// `security.invite_path` (T135, default `/invite`): where the invitation page is served
    /// (while `multi_user` is on). Anywhere else, `/invite` included, is the uniform 404. Shown
    /// only on the admin invitation/recovery result pages, never on an anonymous page (except
    /// the login page's link, which exists only for the default path).
    pub invite_path: crate::invite_path::InvitePath,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            idle_secs: 30 * 60,
            max_secs: 12 * 3600,
            pending_secs: PENDING_SECS,
            insecure_cookies: false,
            allowed_hosts: Vec::new(),
            max_sessions: 5,
            verify_concurrency: 2,
            totp_key: None,
            hidden_categories: Arc::from(Vec::new()),
            xxx_categories: builtin_xxx_categories(),
            multi_user: false,
            invite_ttl_secs: 48 * 3600,
            recover_ttl_secs: 2 * 3600,
            registration_enabled: true,
            max_accounts: nzb_store::DEFAULT_MAX_ACCOUNTS,
            public_url: None,
            invite_path: crate::invite_path::InvitePath::default(),
        }
    }
}

/// `POST /account/preferences` requests per account and minute (review 37 L3), on top of the per-address UI budget.
/// Every saved change is audited (`pref_change`), so this bounds the audit rows one account can write to about one per
/// 10 s whatever the number of addresses, without coalescing (no change ever goes unaudited) and without spending the
/// shared login budget of the caller's address. A constant: there is no per-account limits section to put it in.
pub const PREF_SAVES_PER_MIN: u32 = 6;

/// The XXX subtree of the built-in taxonomy (the only taxonomy the app loads).
fn builtin_xxx_categories() -> Arc<[u16]> {
    let ids = nzb_core::Taxonomy::builtin().map_or_else(
        // Unreachable (the built-in taxonomy is compiled in and tested); the root id alone still hides the parent.
        |_| vec![nzb_core::XXX_CATEGORY],
        |t| t.subtree_ids(nzb_core::XXX_CATEGORY),
    );
    Arc::from(ids)
}

impl AuthConfig {
    /// The instance policy handed to the account writers of the store.
    #[must_use]
    pub fn account_policy(&self) -> AccountPolicy {
        AccountPolicy {
            multi_user: self.multi_user,
            max_accounts: self.max_accounts,
            registration_enabled: self.registration_enabled,
        }
    }

    /// The full address of the invitation page handed to an invitee: [`Self::public_address`]
    /// followed by the configured path, or the path alone when no address is configured.
    #[must_use]
    pub fn invite_url(&self) -> String {
        self.invite_path.url(self.public_address().as_deref())
    }

    /// The address printed on an invitation page: `server.public_url`, else
    /// `https://<allowed_hosts[0]>` (`http://` only with the D16 opt-out), else none. The request
    /// `Host` header is never consulted (L4).
    #[must_use]
    pub fn public_address(&self) -> Option<String> {
        if let Some(u) = &self.public_url {
            return Some(u.clone());
        }
        self.allowed_hosts.first().map(|h| {
            let scheme = if self.insecure_cookies {
                "http"
            } else {
                "https"
            };
            format!("{scheme}://{h}")
        })
    }
}

/// Errors from session handling. Messages carry no secrets.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Database failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// OS randomness unavailable.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// Password machinery failed (startup: dummy hash).
    #[error("password error: {0}")]
    Password(#[from] PasswordError),
    /// A background task failed.
    #[error("background task failed")]
    Task,
    /// The password-verification queue is full (SEC-032).
    #[error("verification queue full")]
    Busy,
}

/// An authenticated request's session, inserted as a request extension by the gates.
#[derive(Clone)]
pub struct SessionCtx {
    /// Owning user id.
    pub user_id: i64,
    /// Session stage (`Active` for everything behind the main gate).
    pub stage: SessionStage,
    /// Per-session CSRF synchronizer token (hex) to embed in pages/forms.
    pub csrf_token: String,
    /// Category ids that must not be displayed to THIS caller: the instance rule
    /// ([`AuthConfig::hidden_categories`], `ui.show_xxx = false`) plus, when the account's preference
    /// "Hide XXX for me" is on, the XXX subtree (T120). A preference only adds; it never shows what the
    /// operator hid. Every user-facing view filters with this set (store and index queries, 404s).
    pub hidden_categories: Arc<[u16]>,
    /// The account's own preferences (read with the session in one statement; T120).
    pub prefs: nzb_store::UserPrefs,
    /// The account's role, read from the database for THIS request (never from the cookie).
    pub role: Role,
    /// Login name: shown to the account itself and on admin pages only.
    pub username: String,
    /// Non-login label used for attribution (default `user-<id>`).
    pub display_name: String,
    /// The pending session already proved an invitation code (no enrollment token needed).
    pub enroll_proven: bool,
    /// `security.multi_user`, for navigation (the Users link) only.
    pub multi_user: bool,
    pub(crate) id_hash: [u8; 32],
    pub(crate) last_seen_at: i64,
    pub(crate) created_at: i64,
    /// The app's library change counter (Statistics cache invalidation, T132 review 47 L2).
    pub(crate) library_gen: Arc<crate::stats::LibraryGeneration>,
}

impl SessionCtx {
    /// True when a release in `category_id` must be treated as non-existent by every
    /// user-facing view (display rule `ui.show_xxx = false`).
    #[must_use]
    pub fn hides_category(&self, category_id: u32) -> bool {
        u16::try_from(category_id).is_ok_and(|c| self.hidden_categories.contains(&c))
    }

    /// The caller as the store's writers expect it (they re-validate it from the database).
    #[must_use]
    pub fn actor(&self) -> AccountActor {
        AccountActor {
            session: Some(self.id_hash),
            user_id: self.user_id,
            role: self.role,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            stage: self.stage,
            prefs: self.prefs,
        }
    }

    /// The audit identity of a completed-authentication action by this session.
    #[must_use]
    pub fn audit_actor(&self) -> AuditActor {
        AuditActor::account(self.user_id, self.role, &self.username)
    }

    /// The hidden ids as store-level exclusion ids.
    #[must_use]
    pub fn hidden_ids(&self) -> Vec<u32> {
        self.hidden_categories
            .iter()
            .map(|c| u32::from(*c))
            .collect()
    }
}

impl std::fmt::Debug for SessionCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCtx")
            .field("user_id", &self.user_id)
            .field("role", &self.role)
            .field("stage", &self.stage)
            .field("csrf_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Where a session was created from (display/audit only).
#[derive(Clone, Debug, Default)]
pub struct ClientMeta {
    /// Effective client IP as text.
    pub ip: Option<String>,
    /// User agent, truncated.
    pub user_agent: Option<String>,
}

impl ClientMeta {
    /// Builds metadata from request headers and the resolved client address.
    #[must_use]
    pub fn from_request(headers: &HeaderMap, ip: Option<std::net::IpAddr>) -> Self {
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect::<String>()
            });
        Self {
            ip: ip.map(|i| i.to_string()),
            user_agent,
        }
    }
}

pub(crate) struct Inner {
    pub(crate) db: Store,
    pub(crate) cfg: AuthConfig,
    /// The hidden set of an account with "Hide XXX for me": instance set UNION XXX subtree (built once).
    pub(crate) pref_hidden: Arc<[u16]>,
    pub(crate) clock: Arc<dyn WallClock>,
    /// Valid Argon2id hash of an unknowable password: unknown users, over-length input and
    /// unusable stored hashes are verified against it so every login costs one full verify.
    pub(crate) dummy_hash: String,
    /// Per-process key for the stateless pre-session login tokens.
    pub(crate) token_key: [u8; 32],
    /// Consumed login-form token ids (single use, bounded, fail closed; in memory only).
    pub(crate) login_tokens: crate::csrf::SingleUseSet,
    pub(crate) verify_slots: Arc<Semaphore>,
    /// Requests currently waiting for a verify slot; bounded by `MAX_VERIFY_WAITERS`.
    pub(crate) verify_waiting: AtomicUsize,
    /// Completed Argon2 verifications (any branch); lets tests prove every failure path pays
    /// for one.
    pub(crate) verify_runs: AtomicU64,
    /// The shared bucket of 1 attempt/min that unknown addresses get while an account's aggregate
    /// throttle is in force (N2); keyed on the account id.
    pub(crate) unknown_ip: KeyedLimiter<i64>,
    /// Per-account budget of `POST /account/preferences` ([`PREF_SAVES_PER_MIN`], review 37 L3).
    pub(crate) pref_saves: KeyedLimiter<i64>,
    /// Argon2 queue of `/invite` (1 permit, [`MAX_INVITE_WAITERS`] waiters).
    pub(crate) invite_slots: Arc<Semaphore>,
    pub(crate) invite_waiting: AtomicUsize,
    /// Bounded channel to the writer task of the throttled `authz_denied` audit rows (I-1): a
    /// refused request itself stays read-only.
    pub(crate) denied_tx: mpsc::Sender<DeniedEvent>,
    /// Bumped by every release category change and delete of this app (T132 review 47 L2): the Statistics
    /// cache compares it on every read.
    pub(crate) library_gen: Arc<crate::stats::LibraryGeneration>,
}

/// One refused-role request to audit (route class and role; never the path or any input).
pub(crate) struct DeniedEvent {
    pub(crate) who: AuditActor,
    pub(crate) detail: String,
    pub(crate) ip: Option<String>,
}

/// Adapter: the injectable wall clock as the limiter's millisecond clock, so a test that moves the
/// wall clock also moves the 1/min unknown-address bucket.
struct WallMs(Arc<dyn WallClock>);

impl Clock for WallMs {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.now_secs().max(0))
            .unwrap_or(0)
            .saturating_mul(1000)
    }
}

/// The throttling context of one authentication attempt, resolved before the verification work
/// and handed to the store's verdict afterwards (`AUTH_SPEC` "Throttling").
pub(crate) struct Attempt {
    ip_key: String,
    session: Option<[u8; 32]>,
    bucket_refused: bool,
}

impl Attempt {
    /// The store-facing view.
    pub(crate) fn ctx(&self) -> AttemptContext<'_> {
        AttemptContext {
            ip_key: &self.ip_key,
            session: self.session.as_ref(),
            bucket_refused: self.bucket_refused,
        }
    }

    /// The address key (IPv4 text or IPv6 /64) of the attempt.
    pub(crate) fn ip_key(&self) -> &str {
        &self.ip_key
    }
}

/// Pending `authz_denied` rows; a full queue drops the event (it is a debugging aid).
const DENIED_QUEUE: usize = 64;

/// Writes the `authz_denied` rows off the request path, throttled to one per account per minute.
fn spawn_denied_writer(db: Store, clock: Arc<dyn WallClock>, mut rx: mpsc::Receiver<DeniedEvent>) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let entry = AuditEntry {
                who: ev.who,
                event: "authz_denied",
                detail: Some(&ev.detail),
                ip: ev.ip.as_deref(),
                target_id: None,
            };
            if let Err(e) = db.audit_entry_throttled(&entry, 60, clock.now_secs()).await {
                tracing::error!(error = %e, "authz_denied audit failed");
            }
        }
    });
}

/// Shared authentication state (cheap to clone).
#[derive(Clone)]
pub struct AuthState(pub(crate) Arc<Inner>);

impl AuthState {
    /// Builds the state. Computes the dummy hash once and draws the token key; any failure
    /// aborts startup instead of degrading (fail closed).
    ///
    /// # Errors
    /// Randomness or hashing failure.
    pub async fn new(
        db: Store,
        cfg: AuthConfig,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, AuthError> {
        let dummy_hash = tokio::task::spawn_blocking(password::dummy_hash)
            .await
            .map_err(|_| AuthError::Task)??;
        let token_key = crypto::random_bytes::<32>()?;
        let slots = cfg.verify_concurrency.max(1);
        let wall_ms: Arc<dyn Clock> = Arc::new(WallMs(Arc::clone(&clock)));
        let (denied_tx, denied_rx) = mpsc::channel(DENIED_QUEUE);
        spawn_denied_writer(db.clone(), Arc::clone(&clock), denied_rx);
        let mut pref_hidden: Vec<u16> = cfg.hidden_categories.to_vec();
        pref_hidden.extend(cfg.xxx_categories.iter().copied());
        pref_hidden.sort_unstable();
        pref_hidden.dedup();
        Ok(Self(Arc::new(Inner {
            db,
            pref_hidden: Arc::from(pref_hidden),
            cfg,
            clock,
            dummy_hash,
            token_key,
            login_tokens: crate::csrf::SingleUseSet::new(crate::csrf::LOGIN_TOKEN_SET_CAP),
            verify_slots: Arc::new(Semaphore::new(slots)),
            verify_waiting: AtomicUsize::new(0),
            verify_runs: AtomicU64::new(0),
            pref_saves: KeyedLimiter::new(PREF_SAVES_PER_MIN, 4096, Arc::clone(&wall_ms)),
            unknown_ip: KeyedLimiter::new(1, 4096, wall_ms),
            invite_slots: Arc::new(Semaphore::new(1)),
            invite_waiting: AtomicUsize::new(0),
            denied_tx,
            library_gen: Arc::default(),
        })))
    }

    /// Number of Argon2 verifications run so far (observability/test hook, carries no data).
    #[must_use]
    pub fn verify_runs(&self) -> u64 {
        self.0.verify_runs.load(Ordering::Relaxed)
    }

    /// The category ids hidden for an account with `prefs`: the instance set, plus the XXX subtree when
    /// "Hide XXX for me" is on (T120). A preference only adds to the instance set (SEC-090).
    #[must_use]
    pub fn hidden_for(&self, prefs: nzb_store::UserPrefs) -> Arc<[u16]> {
        if prefs.hide_xxx {
            Arc::clone(&self.0.pref_hidden)
        } else {
            Arc::clone(&self.0.cfg.hidden_categories)
        }
    }

    /// The database handle (for MFA/account handlers).
    #[must_use]
    pub fn db(&self) -> &Store {
        &self.0.db
    }

    /// The TOTP encryption key, if configured.
    #[must_use]
    pub fn totp_key(&self) -> Option<&TotpKey> {
        self.0.cfg.totp_key.as_deref()
    }

    /// Current unix time from the injected clock.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.0.clock.now_secs()
    }

    /// Settings in effect.
    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.0.cfg
    }

    fn cookie_name(&self) -> &'static str {
        if self.0.cfg.insecure_cookies {
            COOKIE_NAME_INSECURE
        } else {
            COOKIE_NAME
        }
    }

    /// `Set-Cookie` value carrying `id`.
    #[must_use]
    pub fn session_cookie(&self, id: &str) -> Option<HeaderValue> {
        let secure = if self.0.cfg.insecure_cookies {
            ""
        } else {
            "; Secure"
        };
        HeaderValue::from_str(&format!(
            "{}={id}; HttpOnly{secure}; SameSite=Strict; Path=/",
            self.cookie_name()
        ))
        .ok()
    }

    /// `Set-Cookie` value that expires the session cookie.
    #[must_use]
    pub fn clear_cookie(&self) -> HeaderValue {
        let secure = if self.0.cfg.insecure_cookies {
            ""
        } else {
            "; Secure"
        };
        HeaderValue::from_str(&format!(
            "{}=; Max-Age=0; HttpOnly{secure}; SameSite=Strict; Path=/",
            self.cookie_name()
        ))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    fn login_nonce_name(&self) -> &'static str {
        if self.0.cfg.insecure_cookies {
            LOGIN_NONCE_COOKIE_INSECURE
        } else {
            LOGIN_NONCE_COOKIE
        }
    }

    /// `Set-Cookie` for the login-form nonce: `HttpOnly`, SameSite=Strict, 10 minutes. `Path=/` is
    /// mandatory for a `__Host-` cookie (browsers drop it otherwise).
    #[must_use]
    pub fn login_nonce_cookie(&self, nonce: &str) -> Option<HeaderValue> {
        let secure = if self.0.cfg.insecure_cookies {
            ""
        } else {
            "; Secure"
        };
        HeaderValue::from_str(&format!(
            "{}={nonce}; Max-Age={}; HttpOnly{secure}; SameSite=Strict; Path=/",
            self.login_nonce_name(),
            crate::csrf::LOGIN_TOKEN_TTL_SECS
        ))
        .ok()
    }

    /// `Set-Cookie` that expires the login-form nonce cookie.
    #[must_use]
    pub fn clear_login_nonce_cookie(&self) -> HeaderValue {
        let secure = if self.0.cfg.insecure_cookies {
            ""
        } else {
            "; Secure"
        };
        HeaderValue::from_str(&format!(
            "{}=; Max-Age=0; HttpOnly{secure}; SameSite=Strict; Path=/",
            self.login_nonce_name()
        ))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// The login-form nonce from the request: exactly one cookie of that name, well formed.
    #[must_use]
    pub fn presented_login_nonce(&self, headers: &HeaderMap) -> Option<String> {
        let name = self.login_nonce_name();
        let mut found: Option<&str> = None;
        for line in headers.get_all(header::COOKIE) {
            for part in line.to_str().ok()?.split(';') {
                if let Some((k, v)) = part.trim().split_once('=')
                    && k == name
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some(v);
                }
            }
        }
        found
            .filter(|v| crate::csrf::valid_login_nonce(v))
            .map(str::to_owned)
    }

    /// Extracts the session id from the request cookies. Zero or several cookies of that name
    /// (cookie tossing) yield `None`; so does anything that is not a 43-char base64url id.
    #[must_use]
    pub fn presented_id(&self, headers: &HeaderMap) -> Option<String> {
        let name = self.cookie_name();
        let mut found: Option<&str> = None;
        for line in headers.get_all(header::COOKIE) {
            for part in line.to_str().ok()?.split(';') {
                if let Some((k, v)) = part.trim().split_once('=')
                    && k == name
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some(v);
                }
            }
        }
        let v = found?;
        (v.len() == SESSION_ID_CHARS
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .then(|| v.to_owned())
    }

    /// Issues a pending login bound to the credentials that passed the password verdict.
    /// A concurrent credential change returns `Store(NotFound)` without issuing a cookie.
    pub(crate) async fn start_login_session(
        &self,
        seen: &LoginUser,
        meta: &ClientMeta,
        replacing: Option<&[u8; 32]>,
    ) -> Result<HeaderValue, AuthError> {
        let (new, cookie, _) = self.prepare_session(seen.id, SessionStage::PendingMfa, meta)?;
        self.0
            .db
            .insert_login_session(seen, &new, replacing, self.0.cfg.max_sessions)
            .await?;
        Ok(cookie)
    }

    /// Mints a session for `user_id` at `stage`, replacing `replacing` atomically (rotation),
    /// and returns the `Set-Cookie` value. The id is fresh randomness: nothing from the request
    /// influences it.
    ///
    /// # Errors
    /// Randomness or database failure.
    pub async fn start_session(
        &self,
        user_id: i64,
        stage: SessionStage,
        meta: &ClientMeta,
        replacing: Option<&[u8; 32]>,
    ) -> Result<HeaderValue, AuthError> {
        self.start_session_full(user_id, stage, meta, replacing)
            .await
            .map(|(cookie, _)| cookie)
    }

    /// Like [`AuthState::start_session`], also returning the new session's CSRF token (hex) so the
    /// response that sets the cookie can already render forms for it.
    ///
    /// # Errors
    /// Randomness or database failure.
    pub async fn start_session_full(
        &self,
        user_id: i64,
        stage: SessionStage,
        meta: &ClientMeta,
        replacing: Option<&[u8; 32]>,
    ) -> Result<(HeaderValue, String), AuthError> {
        self.mint(user_id, stage, meta, replacing.map(|r| (r, false)))
            .await
    }

    /// Promotes a pending session: like [`AuthState::start_session_full`] but fails with
    /// `StoreError::NotFound` (and creates nothing) if `pending` no longer exists, so a revoked or
    /// concurrently consumed pending session can never yield an `active` one.
    ///
    /// # Errors
    /// `Store(NotFound)` when `pending` is gone; randomness or database failure.
    pub async fn promote_session(
        &self,
        user_id: i64,
        meta: &ClientMeta,
        pending: &[u8; 32],
    ) -> Result<(HeaderValue, String), AuthError> {
        self.mint(user_id, SessionStage::Active, meta, Some((pending, true)))
            .await
    }

    /// Builds a session row (fresh id and CSRF token, nothing stored) together with its cookie and
    /// the hex CSRF token. Used where the store inserts the row itself (invite redemption, the
    /// staged-recovery commit), so the id is still generated here, from the OS CSPRNG only.
    ///
    /// # Errors
    /// Randomness failure.
    pub fn prepare_session(
        &self,
        user_id: i64,
        stage: SessionStage,
        meta: &ClientMeta,
    ) -> Result<(NewSession, HeaderValue, String), AuthError> {
        let id = URL_SAFE_NO_PAD.encode(crypto::random_bytes::<32>()?);
        let csrf_token = crypto::random_bytes::<32>()?;
        let now = self.now();
        let lifetime = match stage {
            SessionStage::PendingMfa => self.0.cfg.pending_secs,
            SessionStage::Active => self.0.cfg.idle_secs,
        };
        let new = NewSession {
            id_hash: crypto::sha256(id.as_bytes()),
            user_id,
            stage,
            csrf_token,
            now,
            expires_at: now.saturating_add(lifetime),
            ip: meta.ip.clone(),
            user_agent: meta.user_agent.clone(),
        };
        let cookie = self.session_cookie(&id).ok_or(AuthError::Task)?;
        Ok((new, cookie, crypto::hex(&csrf_token)))
    }

    async fn mint(
        &self,
        user_id: i64,
        stage: SessionStage,
        meta: &ClientMeta,
        replacing: Option<(&[u8; 32], bool)>,
    ) -> Result<(HeaderValue, String), AuthError> {
        let (new, cookie, csrf_hex) = self.prepare_session(user_id, stage, meta)?;
        match replacing {
            Some((old, strict)) => {
                let max = self.0.cfg.max_sessions;
                if strict {
                    self.0.db.rotate_session_strict(old, &new, max).await?;
                } else {
                    self.0.db.rotate_session(old, &new, max).await?;
                }
            }
            None => {
                self.0
                    .db
                    .insert_session(&new, self.0.cfg.max_sessions)
                    .await?;
            }
        }
        Ok((cookie, csrf_hex))
    }

    /// Validates the request's cookie against the database: exists, not past the idle/pending
    /// deadline, not past the absolute lifetime, and its account is live and enabled. Active
    /// sessions slide their idle deadline (at most once a minute). Expired rows are deleted on
    /// sight. The role is read from the database here, on every request (SEC-060).
    ///
    /// # Errors
    /// Database failure (callers must fail closed).
    pub async fn load_session(&self, headers: &HeaderMap) -> Result<Option<SessionCtx>, AuthError> {
        let Some(ctx) = self.peek_session(headers).await? else {
            return Ok(None);
        };
        self.touch(&ctx).await?;
        Ok(Some(ctx))
    }

    /// Like [`AuthState::load_session`] without sliding the idle deadline: the access gate calls
    /// it first and touches only once the request is admitted (a refused request refreshes
    /// nothing, `AUTH_SPEC` "Uniform 404 completeness" 4).
    ///
    /// # Errors
    /// Database failure (callers must fail closed).
    pub async fn peek_session(&self, headers: &HeaderMap) -> Result<Option<SessionCtx>, AuthError> {
        let Some(id) = self.presented_id(headers) else {
            return Ok(None);
        };
        let id_hash = crypto::sha256(id.as_bytes());
        let Some(row) = self.0.db.get_session(&id_hash).await? else {
            return Ok(None);
        };
        let now = self.now();
        let abs_deadline = row.created_at.saturating_add(self.0.cfg.max_secs);
        if now >= row.expires_at || now >= abs_deadline {
            self.0.db.delete_session(&id_hash).await?;
            return Ok(None);
        }
        // One join: a disabled or deleted account is "no session" (its sessions are revoked in the
        // same transaction anyway; this is the belt to that suspender).
        let Some(actor) = self.0.db.session_actor(&id_hash, now).await? else {
            return Ok(None);
        };
        Ok(Some(SessionCtx {
            user_id: actor.user_id,
            stage: actor.stage,
            csrf_token: crypto::hex(&row.csrf_token),
            hidden_categories: self.hidden_for(actor.prefs),
            prefs: actor.prefs,
            role: actor.role,
            username: actor.username,
            display_name: actor.display_name,
            enroll_proven: row.enroll_proven,
            multi_user: self.0.cfg.multi_user,
            id_hash,
            last_seen_at: row.last_seen_at,
            created_at: row.created_at,
            library_gen: Arc::clone(&self.0.library_gen),
        }))
    }

    /// Slides the idle deadline of an active session (at most once a minute).
    ///
    /// # Errors
    /// Database failure.
    pub async fn touch(&self, ctx: &SessionCtx) -> Result<(), AuthError> {
        let now = self.now();
        if ctx.stage == SessionStage::Active
            && now.saturating_sub(ctx.last_seen_at) >= TOUCH_INTERVAL_SECS
        {
            let abs_deadline = ctx.created_at.saturating_add(self.0.cfg.max_secs);
            let expires = now.saturating_add(self.0.cfg.idle_secs).min(abs_deadline);
            self.0.db.touch_session(&ctx.id_hash, now, expires).await?;
        }
        Ok(())
    }

    /// Resolves the throttling context of an attempt for `user_id` (`None` = unknown name,
    /// tombstone or `~` input) from `ip`. One state read happens for every attempt, known account
    /// or not, so the work does not reveal which names exist; the 1/min unknown-address bucket is
    /// spent only when the account's aggregate throttle applies to this address (N2).
    ///
    /// # Errors
    /// Database failure.
    pub(crate) async fn attempt(
        &self,
        user_id: Option<i64>,
        ip: std::net::IpAddr,
        session: Option<[u8; 32]>,
    ) -> Result<Attempt, AuthError> {
        let ip_key = ratelimit::ip_key(ip);
        let now = self.now();
        let st = self
            .0
            .db
            .throttle_state(user_id.unwrap_or(0), &ip_key, now)
            .await?;
        let bucket_refused = user_id.is_some_and(|id| {
            st.unknown_ip_throttled(now)
                && matches!(self.0.unknown_ip.check(id), Decision::Deny { .. })
        });
        Ok(Attempt {
            ip_key,
            session,
            bucket_refused,
        })
    }

    /// Queues the throttled `authz_denied` audit row of a refused role (best effort, never blocks).
    /// `route` is an optional fixed route-class token appended as `route=<token>` (only the bulk
    /// routes carry one, T119 review I3; the other rows keep their 2.0 format).
    pub(crate) fn note_denied(
        &self,
        ctx: &SessionCtx,
        needs: Role,
        route: Option<&'static str>,
        ip: Option<String>,
    ) {
        let mut detail = format!("needs={} role={}", needs.as_str(), ctx.role.as_str());
        if let Some(r) = route {
            detail.push_str(" route=");
            detail.push_str(r);
        }
        let _ = self.0.denied_tx.try_send(DeniedEvent {
            who: ctx.audit_actor(),
            detail,
            ip,
        });
    }

    /// Revokes the session behind `ctx`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn end_session(&self, ctx: &SessionCtx) -> Result<(), AuthError> {
        self.0.db.delete_session(&ctx.id_hash).await?;
        Ok(())
    }

    /// Deletes expired sessions (idle, pending and absolute). Returns how many were removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn purge_expired(&self) -> Result<u64, AuthError> {
        let now = self.now();
        Ok(self
            .0
            .db
            .purge_sessions(now, now.saturating_sub(self.0.cfg.max_secs))
            .await?)
    }

    /// Spawns the periodic purge (every 10 minutes). Detached; ends with the runtime.
    pub fn spawn_purger(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PURGE_INTERVAL);
            loop {
                tick.tick().await;
                if let Err(e) = this.purge_expired().await {
                    tracing::warn!(error = %e, "session purge failed");
                }
            }
        });
    }

    /// Records an audit event; failures are logged, never surfaced to the client.
    pub async fn audit(
        &self,
        actor: Option<&str>,
        event: &str,
        detail: Option<&str>,
        ip: Option<&str>,
    ) {
        if let Err(e) = self
            .0
            .db
            .audit_event(self.now(), actor, event, detail, ip)
            .await
        {
            tracing::error!(error = %e, event, "audit write failed");
        }
    }
}
