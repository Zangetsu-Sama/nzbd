//! Per-IP request rate limiting (SEC-029) with an injectable clock.
//!
//! Sliding-window counter: the previous window's count is weighted by how much of it still
//! overlaps the last 60 s, which avoids the 2x burst of a plain fixed window while using
//! two integers per key. Integer math only.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

const WINDOW_MS: u64 = 60_000;
/// Upper bound on tracked keys; beyond it stale entries are pruned, then new keys are denied.
const MAX_KEYS: usize = 50_000;

/// Monotonic millisecond clock (injected so tests are deterministic).
pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since an arbitrary fixed origin; never decreases.
    fn now_ms(&self) -> u64;
}

/// Production clock based on [`Instant`].
#[derive(Debug)]
pub struct SystemClock(Instant);

impl SystemClock {
    /// Starts counting from now.
    #[must_use]
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Test clock advanced by hand.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// Moves time forward.
    pub fn advance_secs(&self, secs: u64) {
        self.0
            .fetch_add(secs.saturating_mul(1000), Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Route classes with their own budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Everything behind the UI (and the login pages).
    Ui,
    /// `GET /release/{id}/download`.
    Download,
    /// `POST /upload` and `POST /api/v1/nzb` (per-IP part; per-key/session buckets: [`KeyedLimiter`]).
    Upload,
    /// Credential-bearing POSTs (`/login`, `/login/mfa`, `/mfa/enroll`, `/invite`): 10/min/IP
    /// (SEC-026).
    Login,
    /// The enclosing IPv6 /48 of a [`Class::Login`] request (N1): one customer prefix holds 65,536
    /// /64s, so without it rotating /64s would multiply the per-address budget. Internal; applies
    /// to IPv6 clients only, with six times the per-address budget.
    LoginPrefix,
    /// `POST /releases/bulk/download` (T130): [`BULK_DOWNLOADS_PER_MIN`] per IP, charged by the
    /// handler after its capacity check, on top of [`Class::Download`].
    BulkDownload,
}

/// Bulk downloads (`POST /releases/bulk/download`, up to 100 NZBs and 1 GiB each) per minute, per
/// client IP and per account (T130). A constant on purpose: there is no per-account limits section
/// in the configuration, and one bulk download already moves up to 100 NZBs.
pub const BULK_DOWNLOADS_PER_MIN: u32 = 2;

/// Requests per minute per client IP, by class (SEC-029 defaults: 300 / 30 / 60).
#[derive(Clone, Copy, Debug)]
pub struct RateLimits {
    /// UI routes.
    pub ui: u32,
    /// Downloads.
    pub download: u32,
    /// Uploads.
    pub upload: u32,
    /// Login attempts (POSTs to the login-flow routes).
    pub login: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            ui: 300,
            download: 30,
            upload: 60,
            login: 10,
        }
    }
}

/// Outcome of a rate-limit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Request may proceed.
    Allow,
    /// Budget exhausted; retry after this many seconds (>= 1).
    Deny {
        /// Value for the `Retry-After` header.
        retry_after_secs: u64,
    },
}

#[derive(Clone, Copy)]
struct Window {
    start_ms: u64,
    cur: u64,
    prev: u64,
}

/// Windows and their full-table pruning bound share one lock. Known hits only advance a window's
/// start, so a cached oldest start may request an extra scan but never hide an expired entry.
struct Buckets<K> {
    windows: HashMap<K, Window>,
    full_oldest_start: Option<u64>,
    #[cfg(test)]
    prune_scans: u64,
}

impl<K: std::hash::Hash + Eq> Buckets<K> {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
            full_oldest_start: None,
            #[cfg(test)]
            prune_scans: 0,
        }
    }

    fn hit(&mut self, key: K, now: u64, limit: u64, max_keys: usize) -> Decision {
        if self.windows.len() >= max_keys && !self.windows.contains_key(&key) {
            if self
                .full_oldest_start
                .is_none_or(|start| now.saturating_sub(start) >= 2 * WINDOW_MS)
            {
                self.prune(now, max_keys);
            }
            if self.windows.len() >= max_keys {
                // Do not reset live clients' counters to admit a new key.
                return Decision::Deny {
                    retry_after_secs: WINDOW_MS.div_ceil(1000),
                };
            }
        }
        self.windows
            .entry(key)
            .or_insert(Window {
                start_ms: now,
                cur: 0,
                prev: 0,
            })
            .hit(now, limit)
    }

    fn prune(&mut self, now: u64, max_keys: usize) {
        #[cfg(test)]
        {
            self.prune_scans = self.prune_scans.saturating_add(1);
        }
        let mut oldest: Option<u64> = None;
        self.windows.retain(|_, w| {
            let live = now.saturating_sub(w.start_ms) < 2 * WINDOW_MS;
            if live {
                oldest = Some(oldest.map_or(w.start_ms, |start| start.min(w.start_ms)));
            }
            live
        });
        // An admitted request can carry a time sampled before it waited for this lock. Once
        // pruning frees room, invalidate the bound so an older new window cannot escape a scan.
        self.full_oldest_start = if self.windows.len() >= max_keys {
            oldest
        } else {
            None
        };
    }
}

/// The per-IP upload bucket of one request, handed to the upload handler by the rate-limit
/// layer so a multi-file UI request can spend one per-IP token per file (T083, residual-risk
/// L-12). The layer already spent the first token for the request itself.
#[derive(Clone)]
pub struct IpUploadBucket {
    limiter: Arc<RateLimiter>,
    ip: IpAddr,
}

impl IpUploadBucket {
    pub(crate) fn new(limiter: Arc<RateLimiter>, ip: IpAddr) -> Self {
        Self { limiter, ip }
    }

    /// Spends one more upload token of this client address.
    #[must_use]
    pub fn charge(&self) -> Decision {
        self.limiter.check(Class::Upload, self.ip)
    }
}

/// Keyed sliding-window limiter.
pub struct RateLimiter {
    clock: Arc<dyn Clock>,
    limits: RateLimits,
    state: Mutex<Buckets<(Class, IpAddr)>>,
    max_keys: usize,
}

/// Budget of the /48 login bucket relative to the per-address one (10/min -> 60/min).
const PREFIX_FACTOR: u32 = 6;

/// IPv6 clients are bucketed per /64 (a single host owns a whole /64), IPv4 per address.
fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The enclosing /48 of an IPv6 client; `None` for IPv4.
fn prefix48_key(ip: IpAddr) -> Option<IpAddr> {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 80);
            Some(IpAddr::V6(Ipv6Addr::from(masked)))
        }
        IpAddr::V4(_) => None,
    }
}

/// The address key the persisted per-(account, address) locks and the known-address set use:
/// the IPv4 text or the IPv6 /64 prefix, exactly the bucket the limiter applies (SEC-066).
#[must_use]
pub fn ip_key(ip: IpAddr) -> String {
    bucket_key(ip).to_string()
}

impl RateLimiter {
    /// Creates a limiter with the given budgets and clock.
    #[must_use]
    pub fn new(limits: RateLimits, clock: Arc<dyn Clock>) -> Self {
        Self::with_max_keys(limits, clock, MAX_KEYS)
    }

    /// Like [`RateLimiter::new`] with an explicit bound on tracked keys.
    #[must_use]
    pub fn with_max_keys(limits: RateLimits, clock: Arc<dyn Clock>, max_keys: usize) -> Self {
        Self {
            clock,
            limits,
            state: Mutex::new(Buckets::new()),
            max_keys: max_keys.max(1),
        }
    }

    fn limit_for(&self, class: Class) -> u64 {
        u64::from(match class {
            Class::Ui => self.limits.ui,
            Class::Download => self.limits.download,
            Class::Upload => self.limits.upload,
            Class::Login => self.limits.login,
            Class::LoginPrefix => self.limits.login.saturating_mul(PREFIX_FACTOR),
            Class::BulkDownload => BULK_DOWNLOADS_PER_MIN,
        })
    }

    /// Records one request from `ip` in `class` and decides whether it may proceed.
    #[must_use]
    pub fn check(&self, class: Class, ip: IpAddr) -> Decision {
        let first = self.check_key(class, bucket_key(ip));
        if class == Class::Login
            && first == Decision::Allow
            && let Some(prefix) = prefix48_key(ip)
        {
            return self.check_key(Class::LoginPrefix, prefix);
        }
        first
    }

    fn check_key(&self, class: Class, bucket: IpAddr) -> Decision {
        let now = self.clock.now_ms();
        let limit = self.limit_for(class);
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hit((class, bucket), now, limit, self.max_keys)
    }
}

impl Window {
    /// Counts one hit at `now` against `limit` per window (sliding-window estimate).
    fn hit(&mut self, now: u64, limit: u64) -> Decision {
        let w = self;
        let mut elapsed = now.saturating_sub(w.start_ms);
        if elapsed >= 2 * WINDOW_MS {
            *w = Window {
                start_ms: now,
                cur: 0,
                prev: 0,
            };
            elapsed = 0;
        } else if elapsed >= WINDOW_MS {
            w.prev = w.cur;
            w.cur = 0;
            w.start_ms = w.start_ms.saturating_add(WINDOW_MS);
            elapsed = now.saturating_sub(w.start_ms);
        }
        let weighted = w
            .prev
            .saturating_mul(WINDOW_MS.saturating_sub(elapsed))
            .checked_div(WINDOW_MS)
            .unwrap_or(0)
            .saturating_add(w.cur);
        if weighted >= limit {
            let remaining_ms = WINDOW_MS.saturating_sub(elapsed);
            Decision::Deny {
                retry_after_secs: remaining_ms.div_ceil(1000).max(1),
            }
        } else {
            w.cur = w.cur.saturating_add(1);
            Decision::Allow
        }
    }
}

/// Sliding-window limiter for authenticated subjects (an API key id, a session): the SEC-029
/// "per key / per session" upload budget. Keyed only *after* authentication, so unauthenticated
/// requests can never spend a valid subject's budget. The table is bounded; when it is full of
/// live subjects, unknown subjects are refused (fail closed) instead of wiping known counters.
pub struct KeyedLimiter<K> {
    clock: Arc<dyn Clock>,
    limit: u64,
    max_keys: usize,
    state: Mutex<Buckets<K>>,
}

impl<K: std::hash::Hash + Eq> KeyedLimiter<K> {
    /// `per_minute` hits per key per window, at most `max_keys` tracked keys.
    #[must_use]
    pub fn new(per_minute: u32, max_keys: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            limit: u64::from(per_minute),
            max_keys: max_keys.max(1),
            state: Mutex::new(Buckets::new()),
        }
    }

    /// Records one hit for `key` and decides whether it may proceed.
    #[must_use]
    pub fn check(&self, key: K) -> Decision {
        self.check_limited(key, u32::MAX)
    }

    /// Like [`KeyedLimiter::check`] with a per-subject budget that can only LOWER the limiter's own
    /// (a per-API-key budget stored in the database never exceeds the instance setting).
    #[must_use]
    pub fn check_limited(&self, key: K, per_minute: u32) -> Decision {
        let limit = self.limit.min(u64::from(per_minute));
        let now = self.clock.now_ms();
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hit(key, now, limit, self.max_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    #[test]
    fn denies_after_budget_and_recovers() {
        let clock = Arc::new(ManualClock::default());
        let rl = RateLimiter::new(RateLimits::default(), clock.clone());
        for _ in 0..30 {
            assert_eq!(rl.check(Class::Download, ip("10.0.0.1")), Decision::Allow);
        }
        assert!(matches!(
            rl.check(Class::Download, ip("10.0.0.1")),
            Decision::Deny {
                retry_after_secs: 60
            }
        ));
        assert_eq!(rl.check(Class::Download, ip("10.0.0.2")), Decision::Allow);
        clock.advance_secs(121);
        assert_eq!(rl.check(Class::Download, ip("10.0.0.1")), Decision::Allow);
    }

    #[test]
    fn sec_029_full_table_fails_closed_without_resetting_existing_counters() {
        let clock = Arc::new(ManualClock::default());
        let limits = RateLimits {
            ui: 2,
            download: 2,
            upload: 2,
            login: 2,
        };
        let rl = RateLimiter::with_max_keys(limits, clock.clone(), 3);
        // The attacker's own key is exhausted, then the table is filled with other keys.
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.1")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.1")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.2")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.3")), Decision::Allow);
        // A new key cannot trigger a wipe: it is denied, and the attacker is still limited.
        assert!(matches!(
            rl.check(Class::Ui, ip("10.0.0.4")),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rl.check(Class::Ui, ip("10.0.0.1")),
            Decision::Deny { .. }
        ));
        // Known keys keep working, and stale entries free room later.
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.2")), Decision::Allow);
        clock.advance_secs(121);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.4")), Decision::Allow);
    }

    #[test]
    fn sec_029_keyed_limiter_is_bounded_fails_closed_and_evicts_expired_subjects() {
        let clock = Arc::new(ManualClock::default());
        let rl: KeyedLimiter<i64> = KeyedLimiter::new(2, 2, clock.clone());
        assert_eq!(rl.check(1), Decision::Allow);
        assert_eq!(rl.check(1), Decision::Allow);
        assert!(matches!(rl.check(1), Decision::Deny { .. }));
        assert_eq!(rl.check(2), Decision::Allow);
        // Table full of live subjects: a new one is refused, known ones keep their counters.
        assert!(matches!(rl.check(3), Decision::Deny { .. }));
        assert!(matches!(rl.check(1), Decision::Deny { .. }));
        // Expired entries are evicted to make room.
        clock.advance_secs(121);
        assert_eq!(rl.check(3), Decision::Allow);
        assert_eq!(rl.check(1), Decision::Allow);
    }

    #[test]
    fn ipv6_shares_a_slash_64() {
        assert_eq!(
            bucket_key(ip("2001:db8::1")),
            bucket_key(ip("2001:db8::ffff"))
        );
        assert_ne!(bucket_key(ip("2001:db8::1")), bucket_key(ip("2001:db9::1")));
    }
}

#[cfg(test)]
mod full_table_diagnostics {
    use super::*;

    const KEYS: u32 = 50_000;
    const SAMPLES: usize = 5;
    const CHECKS_PER_SAMPLE: usize = 64;

    fn diagnostic_ip(key: u32) -> IpAddr {
        // These addresses are only HashMap keys. This test opens no socket.
        IpAddr::from((0x0a00_0001_u32 + key).to_be_bytes())
    }

    fn measure_denials(check: &impl Fn(u32) -> Decision, key: u32) -> u64 {
        let started = Instant::now();
        let mut denied = 0;
        for _ in 0..CHECKS_PER_SAMPLE {
            if std::hint::black_box(check(std::hint::black_box(key)))
                == (Decision::Deny {
                    retry_after_secs: 60,
                })
            {
                denied += 1;
            }
        }
        let ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        assert_eq!(denied, CHECKS_PER_SAMPLE, "every sampled call must deny");
        ns
    }

    fn samples(check: &impl Fn(u32) -> Decision) -> serde_json::Value {
        let mut known_denied_ns = Vec::with_capacity(SAMPLES);
        let mut unknown_full_ns = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            // Alternate order to avoid always measuring one path with the warmer cache.
            let (known, unknown) = if sample % 2 == 0 {
                let known = measure_denials(check, 0);
                (known, measure_denials(check, KEYS))
            } else {
                let unknown = measure_denials(check, KEYS);
                (measure_denials(check, 0), unknown)
            };
            known_denied_ns.push(known);
            unknown_full_ns.push(unknown);
        }
        serde_json::json!({
            "known_denied_ns": known_denied_ns,
            "unknown_full_ns": unknown_full_ns,
        })
    }

    fn assert_initial_windows<K>(state: &Mutex<Buckets<K>>) {
        let map = &state.lock().unwrap_or_else(PoisonError::into_inner).windows;
        assert_eq!(map.len(), MAX_KEYS, "denial must not admit an unknown key");
        assert!(
            map.values()
                .all(|w| w.start_ms == 0 && w.cur == 1 && w.prev == 0),
            "denial must preserve every existing counter and window"
        );
    }

    /// Bounded diagnostic of the real limiters, not a CI timing threshold or a network attack.
    #[test]
    fn full_tables_describe_unknown_and_known_denials_without_timing_assertions() {
        assert_eq!(usize::try_from(KEYS).unwrap(), MAX_KEYS);
        let clock = Arc::new(ManualClock::default());
        let limits = RateLimits {
            ui: 1,
            download: 1,
            upload: 1,
            login: 1,
        };
        let per_ip = RateLimiter::new(limits, clock.clone());
        let keyed = KeyedLimiter::new(1, MAX_KEYS, clock.clone());
        let ip_check = |key| per_ip.check(Class::Ui, diagnostic_ip(key));
        let keyed_check = |key| keyed.check(key);
        // Population is outside the timed samples. Every key exhausts exactly one token.
        for key in 0..KEYS {
            assert_eq!(ip_check(key), Decision::Allow);
            assert_eq!(keyed_check(key), Decision::Allow);
        }
        assert_initial_windows(&per_ip.state);
        assert_initial_windows(&keyed.state);
        assert_eq!(clock.now_ms(), 0);
        let ip_samples = samples(&ip_check);
        let keyed_samples = samples(&keyed_check);
        assert_eq!(clock.now_ms(), 0, "sampled limiter time must remain fixed");
        assert_initial_windows(&per_ip.state);
        assert_initial_windows(&keyed.state);

        let deny = Decision::Deny {
            retry_after_secs: 60,
        };
        // Live entries cannot be evicted early. One existing key becomes live in the next
        // window; at 120 seconds pruning may drop the others but must keep this counter.
        clock.advance_secs(119);
        assert_eq!(ip_check(KEYS), deny);
        assert_eq!(keyed_check(KEYS), deny);
        assert_eq!(ip_check(0), Decision::Allow);
        assert_eq!(keyed_check(0), Decision::Allow);
        assert_eq!(ip_check(KEYS), deny);
        assert_eq!(keyed_check(KEYS), deny);
        clock.advance_secs(1);
        assert_eq!(ip_check(KEYS), Decision::Allow);
        assert_eq!(keyed_check(KEYS), Decision::Allow);
        assert_eq!(ip_check(KEYS), deny);
        assert_eq!(keyed_check(KEYS), deny);
        assert_eq!(ip_check(0), deny);
        assert_eq!(keyed_check(0), deny);
        assert_eq!(
            per_ip
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .windows
                .len(),
            2
        );
        assert_eq!(
            keyed
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .windows
                .len(),
            2
        );
        println!(
            "RATE_FULL_TABLE_DIAGNOSTIC {}",
            serde_json::json!({
                "keys_per_limiter": KEYS,
                "samples_per_path": SAMPLES,
                "checks_per_sample": CHECKS_PER_SAMPLE,
                "sample_clock_ms": 0,
                "sample_order": "known-first on even samples; unknown-first on odd samples",
                "rate_limiter": ip_samples,
                "keyed_limiter": keyed_samples,
                "decision_and_window_guards": "passed",
                "timing_assertions": false,
                "network_requests": 0,
                "scope": "single-threaded aggregate durations; not a production latency estimate",
            })
        );
    }
}

#[cfg(test)]
mod prune_cache_regressions {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const FULL: Decision = Decision::Deny {
        retry_after_secs: 60,
    };

    #[derive(Default)]
    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl TestClock {
        fn set_ms(&self, now: u64) {
            assert!(now >= self.now_ms());
            self.0.store(now, Ordering::Relaxed);
        }
    }

    fn ip(key: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, key])
    }

    /// Exercise both public limiters with the same decisions and inspect their real buckets.
    struct Pair {
        clock: Arc<TestClock>,
        per_ip: RateLimiter,
        keyed: KeyedLimiter<u8>,
    }

    impl Pair {
        fn new(max_keys: usize) -> Self {
            let clock = Arc::new(TestClock::default());
            let limits = RateLimits {
                ui: 1,
                download: 1,
                upload: 1,
                login: 1,
            };
            Self {
                per_ip: RateLimiter::with_max_keys(limits, clock.clone(), max_keys),
                keyed: KeyedLimiter::new(1, max_keys, clock.clone()),
                clock,
            }
        }

        fn check(&self, key: u8) -> Decision {
            let per_ip = self.per_ip.check(Class::Ui, ip(key));
            assert_eq!(per_ip, self.keyed.check(key));
            per_ip
        }

        fn inspect(&self, expected: &[(u8, u64, u64, u64)], scans: u64, oldest: Option<u64>) {
            let per_ip = self.per_ip.state.lock().unwrap();
            let keyed = self.keyed.state.lock().unwrap();
            assert_eq!(per_ip.windows.len(), expected.len());
            assert_eq!(keyed.windows.len(), expected.len());
            assert_eq!(per_ip.prune_scans, scans);
            assert_eq!(keyed.prune_scans, scans);
            assert_eq!(per_ip.full_oldest_start, oldest);
            assert_eq!(keyed.full_oldest_start, oldest);
            for &(key, start, cur, prev) in expected {
                for window in [&per_ip.windows[&(Class::Ui, ip(key))], &keyed.windows[&key]] {
                    assert_eq!(
                        (window.start_ms, window.cur, window.prev),
                        (start, cur, prev)
                    );
                }
            }
        }
    }

    #[test]
    fn full_tables_cache_denials_until_exact_expiry() {
        let pair = Pair::new(3);
        for key in 0..3 {
            assert_eq!(pair.check(key), Decision::Allow);
        }
        for key in 3..67 {
            assert_eq!(pair.check(key), FULL);
            assert_eq!(pair.check(0), FULL);
        }
        let initial = [(0, 0, 1, 0), (1, 0, 1, 0), (2, 0, 1, 0)];
        pair.inspect(&initial, 1, Some(0));
        pair.clock.set_ms(119_999);
        assert_eq!(pair.check(3), FULL);
        pair.inspect(&initial, 1, Some(0));
        pair.clock.set_ms(120_000);
        assert_eq!(pair.check(3), Decision::Allow);
        assert_eq!(pair.check(3), FULL);
        pair.inspect(&[(3, 120_000, 1, 0)], 2, None);
    }

    #[test]
    fn oldest_refresh_only_causes_a_safe_extra_scan() {
        let pair = Pair::new(2);
        assert_eq!(pair.check(0), Decision::Allow);
        pair.clock.set_ms(60_000);
        assert_eq!(pair.check(1), Decision::Allow);
        assert_eq!(pair.check(2), FULL);
        pair.clock.set_ms(119_000);
        assert_eq!(pair.check(0), Decision::Allow);
        let refreshed = [(0, 60_000, 1, 1), (1, 60_000, 1, 0)];
        pair.inspect(&refreshed, 1, Some(0));
        pair.clock.set_ms(120_000);
        for _ in 0..64 {
            assert_eq!(pair.check(2), FULL);
        }
        pair.inspect(&refreshed, 2, Some(60_000));
        pair.clock.set_ms(180_000);
        assert_eq!(pair.check(2), Decision::Allow);
        pair.inspect(&[(2, 180_000, 1, 0)], 3, None);
    }

    #[test]
    fn partial_pruning_then_refill_preserves_survivors() {
        let pair = Pair::new(3);
        assert_eq!(pair.check(0), Decision::Allow);
        pair.clock.set_ms(60_000);
        assert_eq!(pair.check(1), Decision::Allow);
        assert_eq!(pair.check(2), Decision::Allow);
        assert_eq!(pair.check(3), FULL);
        pair.clock.set_ms(120_000);
        assert_eq!(pair.check(3), Decision::Allow);
        let first = [(1, 60_000, 1, 0), (2, 60_000, 1, 0), (3, 120_000, 1, 0)];
        pair.inspect(&first, 2, None);
        assert_eq!(pair.check(4), FULL);
        pair.inspect(&first, 3, Some(60_000));
        pair.clock.set_ms(180_000);
        assert_eq!(pair.check(4), Decision::Allow);
        pair.inspect(&[(3, 120_000, 1, 0), (4, 180_000, 1, 0)], 4, None);
        assert_eq!(pair.check(5), Decision::Allow);
        assert_eq!(pair.check(6), FULL);
        let refilled = [(3, 120_000, 1, 0), (4, 180_000, 1, 0), (5, 180_000, 1, 0)];
        pair.inspect(&refilled, 5, Some(120_000));
        pair.clock.set_ms(239_999);
        assert_eq!(pair.check(6), FULL);
        pair.inspect(&refilled, 5, Some(120_000));
        pair.clock.set_ms(240_000);
        assert_eq!(pair.check(6), Decision::Allow);
        pair.inspect(
            &[(4, 180_000, 1, 0), (5, 180_000, 1, 0), (6, 240_000, 1, 0)],
            6,
            None,
        );
    }

    #[test]
    fn delayed_sample_after_prune_does_not_hide_expired_insert() {
        // Public checks sample now before acquiring the map mutex. Invoke the same production
        // helper in lock order, including a request sampled at zero but admitted after pruning.
        let mut buckets = Buckets::new();
        assert_eq!(buckets.hit(0, 0, 1, 3), Decision::Allow);
        assert_eq!(buckets.hit(1, 0, 1, 3), Decision::Allow);
        assert_eq!(buckets.hit(2, 60_000, 1, 3), Decision::Allow);
        assert_eq!(buckets.hit(3, 60_000, 1, 3), FULL);
        assert_eq!(buckets.full_oldest_start, Some(0));
        assert_eq!(buckets.hit(3, 120_000, 1, 3), Decision::Allow);
        assert_eq!(buckets.windows.len(), 2);
        assert_eq!(buckets.full_oldest_start, None);
        assert_eq!(buckets.hit(4, 0, 1, 3), Decision::Allow);
        assert_eq!(buckets.hit(5, 120_001, 1, 3), Decision::Allow);
        assert!(!buckets.windows.contains_key(&4));
        assert_eq!(buckets.windows.len(), 3);
        assert_eq!(buckets.prune_scans, 3);
        assert_eq!(buckets.full_oldest_start, None);
        for (key, start) in [(2, 60_000), (3, 120_000), (5, 120_001)] {
            let window = &buckets.windows[&key];
            assert_eq!((window.start_ms, window.cur, window.prev), (start, 1, 0));
        }
    }

    #[test]
    fn u64_max_clock_never_overflows_or_evicts_live_entries() {
        let pair = Pair::new(2);
        pair.clock.set_ms(u64::MAX - 120_000);
        assert_eq!(pair.check(0), Decision::Allow);
        assert_eq!(pair.check(1), Decision::Allow);
        assert_eq!(pair.check(2), FULL);
        pair.clock.set_ms(u64::MAX - 1);
        assert_eq!(pair.check(2), FULL);
        pair.inspect(
            &[(0, u64::MAX - 120_000, 1, 0), (1, u64::MAX - 120_000, 1, 0)],
            1,
            Some(u64::MAX - 120_000),
        );
        pair.clock.set_ms(u64::MAX);
        assert_eq!(pair.check(2), Decision::Allow);
        pair.inspect(&[(2, u64::MAX, 1, 0)], 2, None);

        let pair = Pair::new(2);
        pair.clock.set_ms(u64::MAX - 119_999);
        assert_eq!(pair.check(0), Decision::Allow);
        pair.clock.set_ms(u64::MAX);
        assert_eq!(pair.check(1), Decision::Allow);
        for _ in 0..64 {
            assert_eq!(pair.check(2), FULL);
        }
        pair.inspect(
            &[(0, u64::MAX - 119_999, 1, 0), (1, u64::MAX, 1, 0)],
            1,
            Some(u64::MAX - 119_999),
        );

        let pair = Pair::new(1);
        pair.clock.set_ms(u64::MAX);
        assert_eq!(pair.check(0), Decision::Allow);
        assert_eq!(pair.check(1), FULL);
        assert_eq!(pair.check(2), FULL);
        pair.inspect(&[(0, u64::MAX, 1, 0)], 1, Some(u64::MAX));
    }

    #[test]
    fn cached_full_ip_tables_keep_class_and_ipv6_budgets() {
        let clock = Arc::new(TestClock::default());
        let limits = RateLimits {
            ui: 1,
            download: 2,
            upload: 0,
            login: 1,
        };
        let limiter = RateLimiter::with_max_keys(limits, clock.clone(), 3);
        assert_eq!(limiter.check(Class::Ui, ip(0)), Decision::Allow);
        assert_eq!(limiter.check(Class::Ui, ip(0)), FULL);
        assert_eq!(limiter.check(Class::Download, ip(0)), Decision::Allow);
        assert_eq!(limiter.check(Class::Download, ip(0)), Decision::Allow);
        assert_eq!(limiter.check(Class::Download, ip(0)), FULL);
        assert_eq!(limiter.check(Class::Upload, ip(0)), FULL);
        for key in 1..65 {
            assert_eq!(limiter.check(Class::Ui, ip(key)), FULL);
        }
        assert_eq!(limiter.check(Class::Ui, ip(0)), FULL);
        assert_eq!(limiter.check(Class::Download, ip(0)), FULL);
        assert_eq!(limiter.check(Class::Upload, ip(0)), FULL);
        {
            let state = limiter.state.lock().unwrap();
            assert_eq!(state.windows.len(), 3);
            assert_eq!(state.prune_scans, 1);
            for (class, cur) in [(Class::Ui, 1), (Class::Download, 2), (Class::Upload, 0)] {
                let window = &state.windows[&(class, ip(0))];
                assert_eq!((window.start_ms, window.cur, window.prev), (0, cur, 0));
            }
        }

        let limiter = RateLimiter::with_max_keys(limits, clock, 8);
        let v6 = |subnet, host| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, subnet, 0, 0, 0, host));
        for subnet in 1..=6 {
            assert_eq!(limiter.check(Class::Login, v6(subnet, 1)), Decision::Allow);
        }
        // A seventh /64 spends its own token, but the shared /48 budget is exhausted.
        assert_eq!(limiter.check(Class::Login, v6(7, 1)), FULL);
        assert_eq!(limiter.check(Class::Login, v6(8, 1)), FULL);
        assert_eq!(limiter.check(Class::Login, v6(9, 1)), FULL);
        assert_eq!(limiter.check(Class::Login, v6(1, 2)), FULL);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.windows.len(), 8);
        assert_eq!(state.prune_scans, 1);
        let prefix = prefix48_key(v6(1, 1)).unwrap();
        assert_eq!(state.windows[&(Class::LoginPrefix, prefix)].cur, 6);
        for subnet in 1..=7 {
            assert_eq!(
                state.windows[&(Class::Login, bucket_key(v6(subnet, 1)))].cur,
                1
            );
        }
    }

    #[test]
    fn cached_full_keyed_tables_keep_subject_budget_ceiling() {
        let limiter = KeyedLimiter::new(3, 3, Arc::new(TestClock::default()));
        assert_eq!(limiter.check_limited(1, 1), Decision::Allow);
        assert_eq!(limiter.check_limited(1, 1), FULL);
        assert_eq!(limiter.check_limited(2, 0), FULL);
        assert_eq!(limiter.check_limited(3, u32::MAX), Decision::Allow);
        for key in 4..68 {
            assert_eq!(limiter.check_limited(key, u32::MAX), FULL);
        }
        assert_eq!(limiter.check_limited(1, 1), FULL);
        for key in [1, 3] {
            assert_eq!(limiter.check_limited(key, u32::MAX), Decision::Allow);
            assert_eq!(limiter.check_limited(key, u32::MAX), Decision::Allow);
            assert_eq!(limiter.check_limited(key, u32::MAX), FULL);
        }
        assert_eq!(limiter.check_limited(2, 0), FULL);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.windows.len(), 3);
        assert_eq!(state.prune_scans, 1);
        for (key, cur) in [(1, 3), (2, 0), (3, 3)] {
            let window = &state.windows[&key];
            assert_eq!((window.start_ms, window.cur, window.prev), (0, cur, 0));
        }
    }
}
