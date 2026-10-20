//! `GET /admin/health` and `POST /admin/health/deep` (`docs/UI_SPEC.md` Health page).
//!
//! The page renders a list of [`Check`]s produced elsewhere (`nzbd/src/health.rs`, which also
//! feeds the `nzbd health` CLI) through the [`CollectFn`] closures in [`HealthDeps`]. Keeping
//! the engine out of this crate keeps the web layer decoupled from the config, the filesystem
//! layout and the ingest internals (same pattern as [`crate::admin`]).
//!
//! Safety properties, all covered by tests:
//!
//! * read-only: no check modifies data, and the page itself has no state-changing action other
//!   than the deep-check button;
//! * nothing secret is rendered: a [`Check`] carries only a fixed name, a status, a short
//!   value and a hint, every string goes through `sanitize_text` and askama auto-escaping, and
//!   CSS classes come from a fixed `match`, never from data;
//! * cost control: the cheap checks run at most once per [`CACHE_SECS`] behind a single-flight
//!   lock (an owned task, so a cancelled request cannot start a second collection); the
//!   deep check is a separate `POST` (session + CSRF + Origin through the shared gate, login
//!   rate class), runs in an owned task holding a one-permit semaphore until work ends even
//!   after the response deadline, and
//!   its result is shown for [`DEEP_TTL_SECS`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use nzb_core::sanitize_text;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use crate::account::fmt_utc;
use crate::assets::Layout;
use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::error::ApiError;
use crate::session::see_other;

/// Seconds the cheap checks are reused.
pub const CACHE_SECS: i64 = 15;
/// Seconds a finished deep check stays on the page.
pub const DEEP_TTL_SECS: i64 = 600;
/// Minimum seconds between two deep runs (the rate limiter is per minute; this also guards
/// repeated clicks from different sessions).
pub const DEEP_COOLDOWN_SECS: i64 = 30;
/// Deadline for publishing a deep result; unfinished work retains its permit.
pub const DEEP_DEADLINE: Duration = Duration::from_secs(60);
/// Deadline for answering one cheap-check request.
pub const CHEAP_DEADLINE: Duration = Duration::from_secs(10);

/// Outcome of one check. Always rendered as text; colour is only a second cue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Healthy.
    Ok,
    /// Works but needs attention.
    Warn,
    /// Broken or unsafe.
    Fail,
    /// Informational value, never counted in the banner.
    Info,
}

impl Status {
    /// Badge text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Info => "INFO",
        }
    }

    /// CSS class from the fixed design system.
    const fn class(self) -> &'static str {
        match self {
            Self::Ok => "st-ok",
            Self::Warn => "st-warn",
            Self::Fail => "st-bad",
            Self::Info => "",
        }
    }
}

/// Section of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Process facts.
    App,
    /// SQLite.
    Database,
    /// Watch folder, workers, counters.
    Ingest,
    /// Directories and the blob store.
    Storage,
    /// Configuration and account hygiene.
    Security,
    /// Self-check of the HTTP side.
    Http,
    /// Results of the on-demand deep check.
    Deep,
}

impl Group {
    /// Section title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::App => "Application",
            Self::Database => "Database",
            Self::Ingest => "Ingest",
            Self::Storage => "Storage",
            Self::Security => "Security and configuration",
            Self::Http => "HTTP",
            Self::Deep => "Deep check",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Database => "db",
            Self::Ingest => "ingest",
            Self::Storage => "storage",
            Self::Security => "security",
            Self::Http => "http",
            Self::Deep => "deep",
        }
    }

    /// Groups in display order (without [`Group::Deep`], which has its own section).
    pub const ALL: [Self; 6] = [
        Self::App,
        Self::Database,
        Self::Ingest,
        Self::Storage,
        Self::Security,
        Self::Http,
    ];
}

/// One row of the page. `value` and `hint` are display text only (no markup, no paths, no
/// secrets): the producer builds them from typed facts, the renderer sanitizes and escapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Section.
    pub group: Group,
    /// Fixed human name.
    pub name: &'static str,
    /// Result.
    pub status: Status,
    /// Short value or detail.
    pub value: String,
    /// One-line "what to do"; empty when nothing is needed.
    pub hint: String,
}

impl Check {
    /// Builds a check.
    #[must_use]
    pub fn new(
        group: Group,
        name: &'static str,
        status: Status,
        value: impl Into<String>,
        hint: &str,
    ) -> Self {
        Self {
            group,
            name,
            status,
            value: value.into(),
            hint: hint.to_owned(),
        }
    }
}

/// Counts for the banner and the CLI exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    /// Number of `WARN` rows.
    pub warnings: usize,
    /// Number of `FAIL` rows.
    pub failures: usize,
}

impl Summary {
    /// Counts `checks`.
    #[must_use]
    pub fn of(checks: &[Check]) -> Self {
        let n = |s: Status| checks.iter().filter(|c| c.status == s).count();
        Self {
            warnings: n(Status::Warn),
            failures: n(Status::Fail),
        }
    }

    /// Process exit code of `nzbd health`: 0 all OK, 1 warnings, 2 failures.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        if self.failures > 0 {
            2
        } else if self.warnings > 0 {
            1
        } else {
            0
        }
    }

    fn banner(self) -> (&'static str, &'static str, String) {
        if self.failures > 0 {
            (
                "st-bad",
                "FAIL",
                format!(
                    "{} failure(s) and {} warning(s). Fix the failures first.",
                    self.failures, self.warnings
                ),
            )
        } else if self.warnings > 0 {
            (
                "st-warn",
                "WARN",
                format!("{} warning(s). Nothing is broken.", self.warnings),
            )
        } else {
            ("st-ok", "ALL OK", "Every check passed.".to_owned())
        }
    }
}

/// Boxed future (the collectors are plain closures, no `async_trait`).
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Produces checks for the given unix time. Must be read-only.
pub type CollectFn = Arc<dyn Fn(i64) -> BoxFut<Vec<Check>> + Send + Sync>;

/// Everything the health routes need from the rest of the process.
#[derive(Clone)]
pub struct HealthDeps {
    /// Wall clock (deterministic in tests).
    pub clock: Arc<dyn WallClock>,
    /// Cheap checks, cached for [`CACHE_SECS`].
    pub cheap: CollectFn,
    /// Deep checks; `None` hides the button.
    pub deep: Option<CollectFn>,
    /// Deadline of one deep run ([`DEEP_DEADLINE`] in production).
    pub deep_deadline: Duration,
}

impl HealthDeps {
    /// Deps with the production deadline.
    #[must_use]
    pub fn new(clock: Arc<dyn WallClock>, cheap: CollectFn, deep: Option<CollectFn>) -> Self {
        Self {
            clock,
            cheap,
            deep,
            deep_deadline: DEEP_DEADLINE,
        }
    }
}

#[derive(Clone)]
enum DeepState {
    Idle,
    Running { since: i64 },
    Done { at: i64, checks: Arc<Vec<Check>> },
}

/// Cheap checks with the time they were collected.
type CachedChecks = Option<(i64, Arc<Vec<Check>>)>;

#[derive(Clone)]
struct HealthState {
    deps: HealthDeps,
    cache: Arc<AsyncMutex<CachedChecks>>,
    deep: Arc<Mutex<DeepState>>,
    permit: Arc<Semaphore>,
}

impl HealthState {
    fn deep_state(&self) -> DeepState {
        self.deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_deep(&self, s: DeepState) {
        *self.deep.lock().unwrap_or_else(PoisonError::into_inner) = s;
    }

    /// Cache acquisition and the response wait are bounded, but the single owned collector
    /// keeps its cache lock until its real work ends. Dropping a blocking task's `JoinHandle`
    /// does not stop that task, so a response deadline must not cancel the collector itself.
    async fn cheap(&self, now: i64) -> Arc<Vec<Check>> {
        let collect = async {
            // Waiters do not create background tasks. Cancelling one only removes its lock
            // request; a running collector remains the sole owner of the cache guard.
            let mut guard = Arc::clone(&self.cache).lock_owned().await;
            if let Some((at, checks)) = guard.as_ref()
                && (0..CACHE_SECS).contains(&self.deps.clock.now_secs().saturating_sub(*at))
            {
                return Ok(Arc::clone(checks));
            }
            let this = self.clone();
            tokio::spawn(async move {
                let checks = Arc::new((this.deps.cheap)(now).await);
                *guard = Some((this.deps.clock.now_secs(), Arc::clone(&checks)));
                checks
            })
            .await
        };
        match tokio::time::timeout(CHEAP_DEADLINE, collect).await {
            Ok(Ok(checks)) => checks,
            Ok(Err(_)) => Arc::new(vec![Check::new(
                Group::App,
                "Health collection",
                Status::Fail,
                "failed internally",
                "See the server log.",
            )]),
            Err(_) => Arc::new(vec![Check::new(
                Group::App,
                "Health collection",
                Status::Fail,
                "timed out",
                "A probe is hanging, usually a stuck disk or network mount. Check the host.",
            )]),
        }
    }
}

/// Routes of the health page; merge them into the `session_routes` of
/// [`crate::router_with_auth`].
pub fn routes(deps: HealthDeps) -> Router {
    Router::new()
        .route("/admin/health", get(page))
        .route("/admin/health/deep", post(run_deep))
        .with_state(HealthState {
            deps,
            cache: Arc::new(AsyncMutex::new(None)),
            deep: Arc::new(Mutex::new(DeepState::Idle)),
            permit: Arc::new(Semaphore::new(1)),
        })
}

struct RowView {
    name: String,
    class: &'static str,
    label: &'static str,
    value: String,
    hint: String,
}

fn row_view(c: &Check) -> RowView {
    RowView {
        name: sanitize_text(c.name, 80),
        class: c.status.class(),
        label: c.status.label(),
        value: sanitize_text(&c.value, 300),
        hint: sanitize_text(&c.hint, 300),
    }
}

struct GroupView {
    id: &'static str,
    title: &'static str,
    rows: Vec<RowView>,
}

fn group_views(checks: &[Check]) -> Vec<GroupView> {
    Group::ALL
        .iter()
        .filter_map(|g| {
            let rows: Vec<RowView> = checks
                .iter()
                .filter(|c| c.group == *g)
                .map(row_view)
                .collect();
            (!rows.is_empty()).then_some(GroupView {
                id: g.id(),
                title: g.title(),
                rows,
            })
        })
        .collect()
}

#[derive(Template)]
#[template(path = "health.html")]
struct HealthPage {
    layout: Layout,
    banner_class: &'static str,
    banner_label: &'static str,
    banner_text: String,
    checked_at: String,
    groups: Vec<GroupView>,
    deep_enabled: bool,
    deep_status: &'static str,
    deep_notice: &'static str,
    deep_at: String,
    deep_rows: Vec<RowView>,
}

/// Fixed notice for the `?deep=` redirect marker; the query value is never echoed.
fn notice(raw: Option<&str>) -> &'static str {
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    match csrf::form_get(&form, "deep") {
        Some("started") => "Deep check started. Reload this page in a minute to see the result.",
        Some("busy") => "A deep check is already running.",
        Some("wait") => "A deep check finished moments ago. Try again in a few seconds.",
        _ => "",
    }
}

async fn page(
    State(st): State<HealthState>,
    Extension(sess): Extension<SessionCtx>,
    uri: Uri,
) -> Response {
    let now = st.deps.clock.now_secs();
    let checks = st.cheap(now).await;
    let mut all = Summary::of(&checks);
    let (deep_status, deep_at, deep_rows) = match st.deep_state() {
        DeepState::Running { since } => ("running", fmt_utc(since), Vec::new()),
        DeepState::Done { at, checks } if now.saturating_sub(at) <= DEEP_TTL_SECS => {
            let s = Summary::of(&checks);
            all.warnings = all.warnings.saturating_add(s.warnings);
            all.failures = all.failures.saturating_add(s.failures);
            ("done", fmt_utc(at), checks.iter().map(row_view).collect())
        }
        _ => ("none", String::new(), Vec::new()),
    };
    let (banner_class, banner_label, banner_text) = all.banner();
    let view = HealthPage {
        layout: Layout::for_session("Health", &sess),
        banner_class,
        banner_label,
        banner_text,
        checked_at: fmt_utc(now),
        groups: group_views(&checks),
        deep_enabled: st.deps.deep.is_some(),
        deep_status,
        deep_notice: notice(uri.query()),
        deep_at,
        deep_rows,
    };
    match view.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health render failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
        }
    }
}

/// Publishes a `Done` state when dropped before the run completed (panic or cancellation), so
/// the page never stays on "running" and the failure is visible.
struct RunGuard {
    st: HealthState,
    armed: bool,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if self.armed {
            let at = self.st.deps.clock.now_secs();
            self.st.set_deep(DeepState::Done {
                at,
                checks: Arc::new(vec![aborted()]),
            });
        }
    }
}

fn aborted() -> Check {
    Check::new(
        Group::Deep,
        "Deep check",
        Status::Fail,
        "aborted",
        "The run ended unexpectedly. See the server log, then run it again.",
    )
}

async fn run_deep(State(st): State<HealthState>) -> Response {
    let Some(deep) = st.deps.deep.clone() else {
        return ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response();
    };
    let now = st.deps.clock.now_secs();
    // One permit: a second click while running, or from a second session, is refused.
    let Ok(permit) = Arc::clone(&st.permit).try_acquire_owned() else {
        return see_other("/admin/health?deep=busy", None);
    };
    if let DeepState::Done { at, .. } = st.deep_state()
        && (0..DEEP_COOLDOWN_SECS).contains(&now.saturating_sub(at))
    {
        return see_other("/admin/health?deep=wait", None);
    }
    st.set_deep(DeepState::Running { since: now });
    let deadline = st.deps.deep_deadline;
    // An owned monitor publishes the result even if the client disconnects. Its inner
    // worker retains the permit until the collector ends, including after a timeout.
    tokio::spawn(async move {
        // Both tasks retain ownership: normal completion/panic cannot release the permit
        // before the monitor publishes Done, and timeout cannot release it before I/O ends.
        let permit = Arc::new(permit);
        let mut guard = RunGuard {
            st: st.clone(),
            armed: true,
        };
        let worker_permit = Arc::clone(&permit);
        let job = tokio::spawn(async move {
            let _permit = worker_permit;
            deep(now).await
        });
        let checks = match tokio::time::timeout(deadline, job).await {
            Ok(Ok(c)) => c,
            Ok(Err(_)) => vec![aborted()],
            Err(_) => vec![Check::new(
                Group::Deep,
                "Deep check",
                Status::Fail,
                "deadline exceeded",
                "The store or database is very slow. Run `nzbd store verify --quick` on the host.",
            )],
        };
        guard.armed = false;
        let at = st.deps.clock.now_secs();
        st.set_deep(DeepState::Done {
            at,
            checks: Arc::new(checks),
        });
    });
    see_other("/admin/health?deep=started", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: Status) -> Check {
        Check::new(Group::App, "x", s, "v", "")
    }

    #[test]
    fn summary_and_exit_codes() {
        assert_eq!(
            Summary::of(&[c(Status::Ok), c(Status::Info)]).exit_code(),
            0
        );
        assert_eq!(
            Summary::of(&[c(Status::Ok), c(Status::Warn)]).exit_code(),
            1
        );
        assert_eq!(
            Summary::of(&[c(Status::Warn), c(Status::Fail), c(Status::Fail)]).exit_code(),
            2
        );
        let s = Summary::of(&[c(Status::Warn), c(Status::Fail), c(Status::Fail)]);
        assert_eq!((s.warnings, s.failures), (1, 2));
    }

    #[test]
    fn banner_text_is_always_present() {
        for (s, label) in [
            (Summary::default(), "ALL OK"),
            (
                Summary {
                    warnings: 2,
                    failures: 0,
                },
                "WARN",
            ),
            (
                Summary {
                    warnings: 0,
                    failures: 1,
                },
                "FAIL",
            ),
        ] {
            let (class, l, text) = s.banner();
            assert_eq!(l, label);
            assert_ne!(text, "");
            assert!(class.starts_with("st-"));
        }
    }

    #[test]
    fn notice_never_echoes_the_query() {
        assert_eq!(notice(Some("deep=<script>")), "");
        assert!(notice(Some("deep=started")).contains("started"));
        assert_eq!(notice(None), "");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod worker_lifetime_tests {
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::auth::ManualWallClock;

    const NOW: i64 = 1_800_000_000;

    struct ProbeState {
        gate: (Mutex<bool>, Condvar),
        started: Semaphore,
        calls: AtomicUsize,
    }

    /// A real blocking worker, released on every exit path (including a failed assertion).
    struct BlockingProbe(Arc<ProbeState>);

    impl BlockingProbe {
        fn new() -> Self {
            Self(Arc::new(ProbeState {
                gate: (Mutex::new(false), Condvar::new()),
                started: Semaphore::new(0),
                calls: AtomicUsize::new(0),
            }))
        }

        fn collector(&self) -> CollectFn {
            let probe = Arc::clone(&self.0);
            Arc::new(move |_| {
                let probe = Arc::clone(&probe);
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || {
                        probe.calls.fetch_add(1, Ordering::SeqCst);
                        probe.started.add_permits(1);
                        let (lock, ready) = &probe.gate;
                        let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
                        let _guard = ready
                            .wait_while(guard, |released| !*released)
                            .unwrap_or_else(PoisonError::into_inner);
                        vec![Check::new(
                            Group::Storage,
                            "Filesystem probe",
                            Status::Ok,
                            "finished",
                            "",
                        )]
                    })
                    .await
                    .unwrap()
                })
            })
        }

        async fn started(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.0.started.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }

        fn release(&self) {
            let (lock, ready) = &self.0.gate;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
            ready.notify_all();
        }
    }

    impl Drop for BlockingProbe {
        fn drop(&mut self) {
            self.release();
        }
    }

    fn state(probe: &BlockingProbe, clock: Arc<ManualWallClock>) -> HealthState {
        let collect = probe.collector();
        let mut deps = HealthDeps::new(clock, Arc::clone(&collect), Some(collect));
        deps.deep_deadline = Duration::from_millis(20);
        HealthState {
            deps,
            cache: Arc::new(AsyncMutex::new(None)),
            deep: Arc::new(Mutex::new(DeepState::Idle)),
            permit: Arc::new(Semaphore::new(1)),
        }
    }

    async fn cheap_worker_remains_owned(cancel_client: bool) {
        let probe = BlockingProbe::new();
        let clock = Arc::new(ManualWallClock::new(NOW));
        let st = state(&probe, Arc::clone(&clock));
        let caller = {
            let st = st.clone();
            tokio::spawn(async move { st.cheap(NOW).await })
        };
        probe.started().await;
        if cancel_client {
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            tokio::time::sleep(CHEAP_DEADLINE + Duration::from_millis(100)).await;
        } else {
            let checks = tokio::time::timeout(CHEAP_DEADLINE + Duration::from_secs(2), caller)
                .await
                .unwrap()
                .unwrap();
            assert!(checks.iter().any(|c| c.value == "timed out"));
        }
        clock.advance(CACHE_SECS + 1);
        let next = {
            let st = st.clone();
            let now = clock.now_secs();
            tokio::spawn(async move { st.cheap(now).await })
        };
        // The first worker is still parked. A second started worker is a real concurrency breach,
        // not a spawn queued on the blocking pool. Wait long enough to observe that breach.
        let overlap = tokio::time::timeout(Duration::from_secs(2), probe.0.started.acquire())
            .await
            .is_ok();
        // This request began before the preceding collector completed. Cache age must be
        // evaluated after obtaining the lock, against the current clock.
        clock.advance(1);
        probe.release();
        let checks = tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !overlap,
            "health timeout released single-flight while filesystem work was still running"
        );
        assert!(checks.iter().any(|c| c.value == "finished"));
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 1);
        // Late completion starts the cache TTL; a waiting request reuses the same result.
        st.cheap(clock.now_secs()).await;
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 1);
        clock.advance(CACHE_SECS + 1);
        st.cheap(clock.now_secs()).await;
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cheap_timeout_retains_started_filesystem_worker() {
        cheap_worker_remains_owned(false).await;
    }

    #[tokio::test]
    async fn cheap_client_cancellation_retains_started_filesystem_worker() {
        cheap_worker_remains_owned(true).await;
    }

    #[tokio::test]
    async fn deep_timeout_retains_started_filesystem_worker() {
        let probe = BlockingProbe::new();
        let clock = Arc::new(ManualWallClock::new(NOW));
        let st = state(&probe, Arc::clone(&clock));
        let first = run_deep(State(st.clone())).await;
        assert_eq!(
            first.headers().get("location").unwrap(),
            "/admin/health?deep=started"
        );
        probe.started().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !matches!(st.deep_state(), DeepState::Done { .. }) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        clock.advance(DEEP_COOLDOWN_SECS + 1);
        let next = run_deep(State(st.clone())).await;
        probe.release();
        assert_eq!(
            next.headers().get("location").unwrap(),
            "/admin/health?deep=busy",
            "deep timeout released the permit while filesystem work was still running"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while st.permit.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 1);
        let again = run_deep(State(st.clone())).await;
        assert_eq!(
            again.headers().get("location").unwrap(),
            "/admin/health?deep=started"
        );
        probe.started().await;
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 2);
    }
}
