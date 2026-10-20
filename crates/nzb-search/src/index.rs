//! [`TantivyIndex`]: the v3 engine behind the unchanged [`SearchIndex`] trait, plus the v3 extension
//! [`SearchIndexV3`] (match modes, `Total::AtLeast`, facets, narrowed notice, fuzzy fallback).
//!
//! Every engine call runs in `spawn_blocking` with an **owned** semaphore permit moved into the
//! closure (review M6 b): a dropped or timed-out request cannot free its slot while its engine work
//! still runs. Waiting longer than `search.semaphore_wait_ms` is [`SearchError::Busy`] (uniform 503).
//! The deadline starts when the engine work starts and covers expansion, weight builds and collection.
//!
//! The engine returns ordered ids; rows are hydrated from the source of truth ([`Hydrator`]) and rows
//! that are gone or whose **current** category is excluded for the caller are dropped (SEC-090,
//! defence in depth against index lag). Cursors are therefore always built from displayed rows
//! (review L3): the trait returns only hydrated rows, and the web layer derives Next/Previous from them.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use nzb_store::{
    KeysetPage, MAX_LIMIT, Page, PageCursor, ReleaseRow, SearchDoc, SearchIndex, SearchQuery,
    SeekDir, SortKey, StoreError,
};
use tantivy::query::Query;
use tokio::sync::Semaphore;

use crate::clock::{Clock, Deadline};
use crate::collect::{self, Limits, PageMode};
use crate::config::{FuzzyMode, SearchConfig};
use crate::cursor::{self, CursorParts};
use crate::engine::Engine;
use crate::error::SearchError;
use crate::query::{self, Budgets, Expand, ExpansionStats};
use crate::request::{MatchMode, SearchPage, SearchRequest, Total};
use crate::sidecar::Family;
use crate::stats::{self, LibraryStats, StatsRequest};
use crate::walk::{self, WalkFilter, WalkLimits};

/// Reads current rows from the source of truth (Postgres in v3; the 2.x `SqliteDb` in tests). The shape of
/// T112's `PgDb::hydrate(ids, exclude)`, so the v3 implementation is one call.
pub trait Hydrator: Clone + Send + Sync + 'static {
    /// The current rows of `ids`, ideally in the order given; ids that no longer exist and rows whose
    /// **current** category is in `exclude` may be dropped. The caller re-orders and re-checks both
    /// anyway (defence in depth, SEC-090), so an implementation that does neither is still correct.
    ///
    /// # Errors
    /// Database errors.
    fn hydrate(
        &self,
        ids: &[i64],
        exclude: &[u32],
    ) -> impl Future<Output = Result<Vec<ReleaseRow>, StoreError>> + Send;

    /// Announces `ids` to the indexer without changing them: one outbox row each (T112
    /// `PgDb::enqueue_reindex`; the D35 SQLite backend needs the same outbox table and call).
    ///
    /// # Errors
    /// Database errors.
    fn enqueue_reindex(&self, ids: &[i64]) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Whether listings are served from the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// An index generation is installed and servable.
    Serving,
    /// No servable index (missing, corrupt, other epoch/schema, ahead of the database, writer lost):
    /// the UI runs in degraded browse mode until a rebuild installs a generation.
    Degraded(&'static str),
}

/// State shared by the search side and the indexer: the installed generation, the search semaphore,
/// settings and the clock.
pub struct SearchService {
    engine: RwLock<Option<Arc<Engine>>>,
    status: Mutex<ServiceStatus>,
    semaphore: Arc<Semaphore>,
    cfg: SearchConfig,
    clock: Arc<dyn Clock>,
    check_every: AtomicU64,
    force: Mutex<Option<PathChoice>>,
}

impl std::fmt::Debug for SearchService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchService")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl SearchService {
    /// A service with no generation installed yet (degraded until [`SearchService::install`]).
    #[must_use]
    pub fn new(cfg: SearchConfig, clock: Arc<dyn Clock>) -> Arc<Self> {
        let cfg = cfg.clamped();
        Arc::new(Self {
            engine: RwLock::new(None),
            status: Mutex::new(ServiceStatus::Degraded("no index yet")),
            semaphore: Arc::new(Semaphore::new(cfg.max_concurrent_searches)),
            cfg,
            clock,
            check_every: AtomicU64::new(collect::CHECK_EVERY),
            force: Mutex::new(None),
        })
    }

    /// Serves `engine` from now on.
    pub fn install(&self, engine: Arc<Engine>) {
        *write(&self.engine) = Some(engine);
        *lock(&self.status) = ServiceStatus::Serving;
    }

    /// Stops serving the index (degraded browse mode) for `reason`.
    pub fn degrade(&self, reason: &'static str) {
        *write(&self.engine) = None;
        *lock(&self.status) = ServiceStatus::Degraded(reason);
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> ServiceStatus {
        *lock(&self.status)
    }

    /// The installed generation.
    ///
    /// # Errors
    /// [`SearchError::NotServable`] in degraded mode.
    pub fn engine(&self) -> Result<Arc<Engine>, SearchError> {
        read(&self.engine)
            .clone()
            .ok_or_else(|| match self.status() {
                ServiceStatus::Degraded(r) => SearchError::NotServable(r),
                ServiceStatus::Serving => SearchError::NotServable("no index"),
            })
    }

    /// Settings (clamped).
    #[must_use]
    pub const fn config(&self) -> &SearchConfig {
        &self.cfg
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Free search slots (metrics, tests).
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Documents between two clock readings during collection (tests lower it to 1).
    #[cfg(test)]
    pub(crate) fn set_check_every(&self, n: u64) {
        self.check_every.store(n.max(1), Ordering::SeqCst);
    }

    /// Forces the page path of every search (tests comparing both paths).
    #[cfg(test)]
    pub(crate) fn force_path(&self, p: Option<PathChoice>) {
        *lock(&self.force) = p;
    }

    /// Runs engine work in a blocking task holding a search slot until the work ends.
    ///
    /// # Errors
    /// [`SearchError::Busy`] when no slot frees up within `semaphore_wait_ms`; the closure's errors;
    /// [`SearchError::Task`] if it panicked.
    pub(crate) async fn run_blocking<T, F>(&self, f: F) -> Result<T, SearchError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Engine>, Deadline, Tuning) -> Result<T, SearchError> + Send + 'static,
    {
        self.run_blocking_bounded(None, f).await
    }

    /// [`SearchService::run_blocking`] with an optional caller deadline
    /// ([`SearchRequest::caller_deadline_ms`]): with one, the slot is taken only if it is free now (no wait) and the
    /// engine deadline is the smaller of the two, so best-effort work never queues behind searches and stops when the
    /// caller stops waiting (review 42 L1).
    ///
    /// # Errors
    /// As [`SearchService::run_blocking`]; [`SearchError::Busy`] at once when a caller deadline is given and no slot
    /// is free.
    pub(crate) async fn run_blocking_bounded<T, F>(
        &self,
        caller_ms: Option<u64>,
        f: F,
    ) -> Result<T, SearchError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Engine>, Deadline, Tuning) -> Result<T, SearchError> + Send + 'static,
    {
        let permit = match caller_ms {
            Some(_) => Arc::clone(&self.semaphore)
                .try_acquire_owned()
                .map_err(|_| SearchError::Busy)?,
            None => tokio::time::timeout(
                Duration::from_millis(self.cfg.semaphore_wait_ms),
                Arc::clone(&self.semaphore).acquire_owned(),
            )
            .await
            .map_err(|_| SearchError::Busy)?
            .map_err(|_| SearchError::Busy)?,
        };
        let engine = self.engine()?;
        let clock = Arc::clone(&self.clock);
        let budget = caller_ms.map_or(self.cfg.query_deadline_ms, |ms| {
            ms.clamp(1, self.cfg.query_deadline_ms)
        });
        let tuning = Tuning {
            check_every: self.check_every.load(Ordering::SeqCst),
            force: *lock(&self.force),
        };
        tokio::task::spawn_blocking(move || {
            // The permit lives exactly as long as the engine work (review M6 b).
            let _permit = permit;
            let deadline = Deadline::after(clock, budget);
            f(engine, deadline, tuning)
        })
        .await
        .map_err(|_| SearchError::Task)?
    }
}

/// How a page is located.
#[derive(Debug, Clone)]
enum Nav {
    Offset(u32),
    Keyset(SeekDir, CursorParts),
}

/// What the engine part of a search returns (ids only; rows come from hydration).
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // independent result flags, not a state machine
struct EnginePage {
    ids: Vec<i64>,
    total: u64,
    has_more: bool,
    facets: Vec<(u32, u64)>,
    narrowed: bool,
    /// Expansion is possible for this request/configuration, independent of dictionary contents.
    expansion_bounded: bool,
    fuzzy_fallback: bool,
    stats: ExpansionStats,
    /// The count stopped at the count budget: `total` is a lower bound (Q1).
    total_cut: bool,
    /// The page came from the sorted walk.
    walked: bool,
    /// Documents visited by all passes so far.
    visited: u64,
}

/// Result of [`engine_search`]: ids only (no hydration), with the expansion counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent result flags, not a state machine
pub struct EngineResult {
    /// Release ids of the page in sort order.
    pub ids: Vec<i64>,
    /// Matches (exact).
    pub total: u64,
    /// The listing continues in the direction of travel.
    pub has_more: bool,
    /// An expansion was cut by a budget.
    pub narrowed: bool,
    /// The fuzzy fallback produced the page.
    pub fuzzy_fallback: bool,
    /// Expansion counters of the query that produced the page.
    pub stats: ExpansionStats,
    /// `total` is a lower bound (count budget, Q1).
    pub total_cut: bool,
    /// The page came from the sorted walk (plan diagnostics).
    pub walked: bool,
    /// Documents visited by every pass (collect and walk, fuzzy fallback included): the work done.
    pub visited: u64,
}

/// Engine-only search of one generation, synchronous and without hydration: the exact code path of
/// [`TantivyIndex`] minus the semaphore and the row fetch. For diagnostics (`nzbd search verify`),
/// benchmarks and the `search_query` fuzz target. `at` selects a keyset page instead of `offset`;
/// `force` overrides the planner (diagnostics, fuzzing both paths).
///
/// # Errors
/// As [`SearchIndexV3::search_page`].
pub fn engine_search(
    engine: &Engine,
    req: &SearchRequest,
    at: Option<(SeekDir, &PageCursor)>,
    cfg: &SearchConfig,
    deadline: &Deadline,
    force: Option<PathChoice>,
) -> Result<EngineResult, SearchError> {
    let nav = match at {
        None => Nav::Offset(req.query.offset),
        Some((dir, c)) => Nav::Keyset(dir, cursor::parts(c, req.query.sort)?),
    };
    let tuning = Tuning {
        check_every: collect::CHECK_EVERY,
        force,
    };
    let p = engine_page(engine, req, &nav, cfg, deadline, tuning, false)?;
    Ok(EngineResult {
        ids: p.ids,
        total: p.total,
        has_more: p.has_more,
        narrowed: p.narrowed,
        fuzzy_fallback: p.fuzzy_fallback,
        stats: p.stats,
        total_cut: p.total_cut,
        walked: p.walked,
        visited: p.visited,
    })
}

/// The v3 additions to [`SearchIndex`] (ARCHITECTURE v3 3.5 item 4); an extension trait so the 2.x
/// trait stays unchanged.
pub trait SearchIndexV3: SearchIndex {
    /// One offset page of `req` with v3 matching, facets and the narrowed/fuzzy flags.
    ///
    /// # Errors
    /// [`SearchError::OutOfRange`] for an offset beyond `search.max_offset` that is not near the end
    /// (D35, Q2); engine, deadline, busy and hydration errors.
    fn search_page(
        &self,
        req: &SearchRequest,
    ) -> impl Future<Output = Result<SearchPage, SearchError>> + Send;

    /// The keyset page next to `at`.
    ///
    /// # Errors
    /// As [`SearchIndexV3::search_page`]; [`SearchError::OutOfRange`] for a cursor of another sort.
    fn search_keyset_page(
        &self,
        req: &SearchRequest,
        dir: SeekDir,
        at: &PageCursor,
    ) -> impl Future<Output = Result<SearchPage, SearchError>> + Send;

    /// Number of matches of `req`, counted at most `search.count_budget_ms` (D35, Q1):
    /// beyond it [`Total::AtLeast`].
    ///
    /// # Errors
    /// Engine, deadline and busy errors.
    fn count_total(
        &self,
        req: &SearchRequest,
    ) -> impl Future<Output = Result<Total, SearchError>> + Send;

    /// The engine sections of the Statistics page (T132): top groups, quality breakdown and the ingest timeline of
    /// the releases visible to the caller (`req.exclude` is a `MustNot` like in every listing, SEC-090). Each section
    /// runs in its own search slot under the query deadline (SEC-095) and fails alone. The default answers every
    /// section as not servable (engines and test doubles without aggregations).
    fn library_stats(&self, req: &StatsRequest) -> impl Future<Output = LibraryStats> + Send {
        let _ = req;
        async { LibraryStats::unavailable("no statistics") }
    }
}

/// The Tantivy engine as a [`SearchIndex`].
pub struct TantivyIndex<H> {
    svc: Arc<SearchService>,
    hydrator: H,
}

impl<H: Clone> Clone for TantivyIndex<H> {
    fn clone(&self) -> Self {
        Self {
            svc: Arc::clone(&self.svc),
            hydrator: self.hydrator.clone(),
        }
    }
}

impl<H: Hydrator> TantivyIndex<H> {
    /// The index of `svc`, hydrating from (and reindexing through) `hydrator`.
    #[must_use]
    pub const fn new(svc: Arc<SearchService>, hydrator: H) -> Self {
        Self { svc, hydrator }
    }

    /// The shared service.
    #[must_use]
    pub const fn service(&self) -> &Arc<SearchService> {
        &self.svc
    }

    async fn engine_page(
        &self,
        req: &SearchRequest,
        nav: Nav,
        exact_only: bool,
    ) -> Result<EnginePage, SearchError> {
        let req = req.clone();
        let cfg = self.svc.config().clone();
        self.svc
            .run_blocking_bounded(req.caller_deadline_ms, move |engine, deadline, tuning| {
                engine_page(&engine, &req, &nav, &cfg, &deadline, tuning, exact_only)
            })
            .await
    }

    async fn hydrate(
        &self,
        req: &SearchRequest,
        page: EnginePage,
        limit: u32,
    ) -> Result<SearchPage, SearchError> {
        let rows = if page.ids.is_empty() {
            Vec::new()
        } else {
            self.hydrator
                .hydrate(&page.ids, &req.query.exclude_categories)
                .await?
        };
        let mut by_id: HashMap<i64, ReleaseRow> = rows.into_iter().map(|r| (r.id, r)).collect();
        let excluded = &req.query.exclude_categories;
        let mut items = Vec::with_capacity(page.ids.len());
        let mut dropped = 0usize;
        for id in &page.ids {
            match by_id.remove(id) {
                // The **current** category decides (index lag after a category change, SEC-090).
                Some(r) if !excluded.contains(&r.category_id) => items.push(r),
                _ => dropped = dropped.saturating_add(1),
            }
        }
        Ok(SearchPage {
            items,
            total: if page.total_cut {
                Total::AtLeast(page.total)
            } else {
                Total::Exact(page.total)
            },
            has_more: page.has_more,
            limit,
            facets: page.facets,
            narrowed: page.narrowed,
            expansion_bounded: page.expansion_bounded,
            fuzzy_fallback: page.fuzzy_fallback,
            dropped,
        })
    }

    async fn page(
        &self,
        req: &SearchRequest,
        nav: Nav,
        exact_only: bool,
    ) -> Result<SearchPage, SearchError> {
        let limit = req.query.limit.clamp(1, MAX_LIMIT);
        let page = self.engine_page(req, nav, exact_only).await?;
        self.hydrate(req, page, limit).await
    }
}

/// The 2.x planner's measured cost ratio (one seek+sort visit ~ 4 walk steps, docs/BENCHMARK.md T087),
/// reused for collect vs walk until T117 measures the Tantivy paths: walk when
/// `matches^2 x WALK_COST_RATIO > wanted x documents`.
pub const WALK_COST_RATIO: u64 = 4;

/// Which page path a search uses (production plans; tests can force one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChoice {
    /// One pass over the matches (top-k + count).
    Collect,
    /// Sorted walk over the sidecars (no text, no flags).
    Walk,
}

/// Per-call knobs of the engine path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tuning {
    pub check_every: u64,
    pub force: Option<PathChoice>,
}

/// The walk filter when `req` should be walked for a page of `wanted` rows.
fn plan(
    engine: &Engine,
    searcher: &tantivy::Searcher,
    req: &SearchRequest,
    wanted: usize,
    force: Option<PathChoice>,
) -> Result<Option<WalkFilter>, SearchError> {
    let Some(f) = WalkFilter::of(req) else {
        return Ok(None);
    };
    // Only with every sidecar already loaded: building one is never request work (review 32 M1).
    if !engine.sidecars_ready(searcher, Family::of(req.query.sort)) {
        return Ok(None);
    }
    match force {
        Some(PathChoice::Collect) => return Ok(None),
        Some(PathChoice::Walk) => return Ok(Some(f)),
        None => {}
    }
    let n = searcher.num_docs();
    if n == 0 {
        return Ok(None);
    }
    let est = u128::from(walk::estimate(engine, searcher, &f)?);
    let wanted = u128::from(u64::try_from(wanted).unwrap_or(u64::MAX));
    let walk = est
        .saturating_mul(est)
        .saturating_mul(u128::from(WALK_COST_RATIO))
        > wanted.saturating_mul(u128::from(n));
    Ok(walk.then_some(f))
}

/// Engine part of one search: plan, build, page, totals, fuzzy fallback.
fn engine_page(
    engine: &Engine,
    req: &SearchRequest,
    nav: &Nav,
    cfg: &SearchConfig,
    deadline: &Deadline,
    tuning: Tuning,
    exact_only: bool,
) -> Result<EnginePage, SearchError> {
    let searcher = engine.searcher();
    let fields = engine.fields();
    let mut budgets = Budgets {
        terms_max: cfg.expansion_terms_max,
        postings: cfg.expansion_postings_budget,
        dict_entries: cfg.expansion_dict_entries,
        visibility_postings: cfg
            .expansion_postings_budget
            .min(query::MAX_VISIBILITY_POSTINGS),
    };
    let prefix = !exact_only && cfg.prefix && req.match_mode != MatchMode::Exact;
    let fuzzy_allowed = !exact_only
        && req.match_mode != MatchMode::Exact
        && match cfg.fuzzy {
            FuzzyMode::Off => false,
            FuzzyMode::Fallback => true,
            FuzzyMode::Toggle => req.fuzzy_requested || req.match_mode == MatchMode::Fuzzy,
        };
    let tokens = query::text_tokens(req.query.q.as_deref());
    let expansion_bounded = tokens.iter().enumerate().any(|(i, token)| {
        let chars = token.chars().count();
        (prefix && i + 1 == tokens.len() && chars >= crate::config::PREFIX_MIN_CHARS)
            || (fuzzy_allowed && chars >= crate::config::FUZZY_MIN_CHARS)
    });
    let limit = usize::try_from(req.query.limit.clamp(1, MAX_LIMIT)).unwrap_or(1);
    let wanted = match nav {
        Nav::Offset(o) => usize::try_from(*o)
            .unwrap_or(usize::MAX)
            .saturating_add(limit),
        Nav::Keyset(..) => limit.saturating_add(1),
    };
    let walk_filter = plan(engine, &searcher, req, wanted, tuning.force)?;
    // The count budget (Q1) only cuts a separate count (walk path); a collect pass counts the page's
    // own matches, and the 2.x path promises exact totals.
    let budget = (!exact_only).then(|| deadline.sub(cfg.count_budget_ms));
    let ctx = Ctx {
        engine,
        searcher: &searcher,
        req,
        cfg,
        limits: Limits {
            deadline,
            count_budget: budget.as_ref(),
            check_every: tuning.check_every,
        },
        walk: walk_filter,
        walked: std::cell::Cell::new(false),
        visited: std::cell::Cell::new(0),
    };
    let mut expand = Expand {
        prefix,
        fuzzy: false,
    };
    let mut fuzzy_fallback = false;
    loop {
        let built = query::build(&searcher, fields, req, expand, budgets, deadline)?;
        // The zero-hit fallback shares the same visibility work allowance as the first pass.
        budgets.visibility_postings = budgets
            .visibility_postings
            .saturating_sub(built.stats.visibility_postings);
        let mut page = ctx.run_nav(&*built.query, nav)?;
        page.narrowed = built.narrowed;
        page.expansion_bounded = expansion_bounded;
        page.fuzzy_fallback = fuzzy_fallback;
        page.stats = built.stats;
        if page.total == 0 && built.has_text && fuzzy_allowed && !expand.fuzzy {
            expand.fuzzy = true;
            fuzzy_fallback = true;
            continue;
        }
        return Ok(page);
    }
}

/// Everything one search needs besides the query and the navigation.
struct Ctx<'a> {
    engine: &'a Engine,
    searcher: &'a tantivy::Searcher,
    req: &'a SearchRequest,
    cfg: &'a SearchConfig,
    limits: Limits<'a>,
    walk: Option<WalkFilter>,
    /// A page actually came from the walk (diagnostics, plan tests).
    walked: std::cell::Cell<bool>,
    /// Documents visited by every pass of this search (collect and walk).
    visited: std::cell::Cell<u64>,
}

/// Total, facets and whether the count was cut.
type Totals = (u64, Vec<(u32, u64)>, bool);

impl Ctx<'_> {
    fn sort(&self) -> SortKey {
        self.req.query.sort
    }

    /// Ids of a page by the planned path; with collect also the totals of the same pass.
    fn page_ids(
        &self,
        q: &dyn Query,
        mode: &PageMode,
    ) -> Result<(Vec<i64>, Option<Totals>), SearchError> {
        if let Some(f) = &self.walk {
            let lim = WalkLimits {
                deadline: self.limits.deadline,
                check_every: self.limits.check_every,
            };
            if let Some((ids, steps)) =
                walk::walk(self.engine, self.searcher, self.sort(), mode, f, &lim)?
            {
                self.walked.set(true);
                self.visited.set(self.visited.get().saturating_add(steps));
                return Ok((ids, None));
            }
            // A sidecar vanished between plan and walk (cache pruned by a commit): collect.
        }
        let c = collect::run(
            self.searcher,
            q,
            self.sort(),
            mode,
            self.req.want_facets,
            &self.limits,
        )?;
        self.visited
            .set(self.visited.get().saturating_add(c.visited));
        Ok((
            c.ids,
            Some((c.total, c.facets.into_iter().collect(), false)),
        ))
    }

    /// Totals for the walk path: histograms (exact) or a count pass (budgeted unless `exact`).
    fn totals(&self, q: &dyn Query, exact: bool) -> Result<Totals, SearchError> {
        if let Some(f) = &self.walk
            && f.histogram_only()
        {
            let (total, per_cat) = walk::histogram_counts(self.engine, self.searcher, f)?;
            let facets = if self.req.want_facets {
                per_cat.into_iter().collect()
            } else {
                Vec::new()
            };
            return Ok((total, facets, false));
        }
        let limits = Limits {
            deadline: self.limits.deadline,
            count_budget: if exact {
                None
            } else {
                self.limits.count_budget
            },
            check_every: self.limits.check_every,
        };
        let c = collect::run(
            self.searcher,
            q,
            self.sort(),
            &PageMode::CountOnly,
            self.req.want_facets,
            &limits,
        )?;
        self.visited
            .set(self.visited.get().saturating_add(c.visited));
        // A cut count's facets are partial: none are shown.
        let facets = if c.cut {
            Vec::new()
        } else {
            c.facets.into_iter().collect()
        };
        Ok((c.total, facets, c.cut))
    }

    fn run_nav(&self, q: &dyn Query, nav: &Nav) -> Result<EnginePage, SearchError> {
        let limit = usize::try_from(self.req.query.limit.clamp(1, MAX_LIMIT)).unwrap_or(1);
        let mut out = EnginePage::default();
        let set = |t: Totals, out: &mut EnginePage| {
            out.total = t.0;
            out.facets = t.1;
            out.total_cut = t.2;
        };
        match nav {
            Nav::Offset(offset) => {
                let offset_u = usize::try_from(*offset).unwrap_or(usize::MAX);
                if *offset <= self.cfg.max_offset {
                    let (ids, t) =
                        self.page_ids(q, &PageMode::First(offset_u.saturating_add(limit)))?;
                    let t = match t {
                        Some(t) => t,
                        None => self.totals(q, false)?,
                    };
                    out.ids = ids.into_iter().skip(offset_u).collect();
                    let shown =
                        u64::try_from(offset_u.saturating_add(out.ids.len())).unwrap_or(u64::MAX);
                    out.has_more = shown < t.0 || t.2;
                    set(t, &mut out);
                } else {
                    // Beyond the offset cap only pages near the end are served, from the end (2.x
                    // "Last"); that needs the exact total.
                    let t = self.totals(q, true)?;
                    let tail = t.0.saturating_sub(u64::from(*offset));
                    let cap = u64::from(self.cfg.max_offset)
                        .saturating_add(u64::try_from(limit).unwrap_or(0));
                    if tail > cap {
                        return Err(SearchError::OutOfRange("offset beyond search.max_offset"));
                    }
                    if tail > 0 {
                        let (ids, _) =
                            self.page_ids(q, &PageMode::Last(usize::try_from(tail).unwrap_or(0)))?;
                        out.ids = ids.into_iter().take(limit).collect();
                        out.has_more = tail > u64::try_from(out.ids.len()).unwrap_or(0);
                    }
                    set(t, &mut out);
                }
            }
            Nav::Keyset(dir, at) => {
                let k = limit.saturating_add(1);
                let mode = match dir {
                    SeekDir::After => PageMode::After(at.clone(), k),
                    SeekDir::Before => PageMode::Before(at.clone(), k),
                };
                let (ids, t) = self.page_ids(q, &mode)?;
                let t = match t {
                    Some(t) => t,
                    None => self.totals(q, false)?,
                };
                out.has_more = ids.len() > limit;
                out.ids = match dir {
                    SeekDir::After => ids.into_iter().take(limit).collect(),
                    SeekDir::Before => {
                        let skip = ids.len().saturating_sub(limit);
                        ids.into_iter().skip(skip).collect()
                    }
                };
                set(t, &mut out);
            }
        }
        out.walked = self.walked.get();
        out.visited = self.visited.get();
        Ok(out)
    }
}

impl<H: Hydrator> SearchIndexV3 for TantivyIndex<H> {
    async fn search_page(&self, req: &SearchRequest) -> Result<SearchPage, SearchError> {
        self.page(req, Nav::Offset(req.query.offset), false).await
    }

    async fn search_keyset_page(
        &self,
        req: &SearchRequest,
        dir: SeekDir,
        at: &PageCursor,
    ) -> Result<SearchPage, SearchError> {
        let parts = cursor::parts(at, req.query.sort)?;
        self.page(req, Nav::Keyset(dir, parts), false).await
    }

    async fn count_total(&self, req: &SearchRequest) -> Result<Total, SearchError> {
        let req = req.clone();
        let cfg = self.svc.config().clone();
        self.svc
            .run_blocking_bounded(req.caller_deadline_ms, move |engine, deadline, tuning| {
                count(&engine, &req, &cfg, &deadline, tuning, false)
            })
            .await
    }

    async fn library_stats(&self, req: &StatsRequest) -> LibraryStats {
        // One slot per section, one after the other: the page never holds more than one search slot, and a section
        // that runs out of time (or finds no slot) fails alone.
        let r = req.clone();
        let groups = self
            .svc
            .run_blocking(move |e, d, t| stats::groups(&e, &r, &d, t.check_every))
            .await;
        let r = req.clone();
        let quality = self
            .svc
            .run_blocking(move |e, d, t| stats::quality(&e, &r, &d, t.check_every))
            .await;
        let r = req.clone();
        let timeline = self
            .svc
            .run_blocking(move |e, d, t| stats::timeline(&e, &r, &d, t.check_every))
            .await;
        LibraryStats {
            groups,
            quality,
            timeline,
        }
    }
}

/// Matches of `req`: from the category histograms when only categories/exclusions filter (exact
/// and cheap), else a count pass, budgeted (Q1) unless `exact`.
fn count(
    engine: &Engine,
    req: &SearchRequest,
    cfg: &SearchConfig,
    deadline: &Deadline,
    tuning: Tuning,
    exact: bool,
) -> Result<Total, SearchError> {
    let searcher = engine.searcher();
    if let Some(f) = WalkFilter::of(req)
        && f.histogram_only()
    {
        return Ok(Total::Exact(
            walk::histogram_counts(engine, &searcher, &f)?.0,
        ));
    }
    let budgets = Budgets {
        terms_max: cfg.expansion_terms_max,
        postings: cfg.expansion_postings_budget,
        dict_entries: cfg.expansion_dict_entries,
        visibility_postings: cfg
            .expansion_postings_budget
            .min(query::MAX_VISIBILITY_POSTINGS),
    };
    let expand = Expand {
        prefix: !exact && cfg.prefix && req.match_mode != MatchMode::Exact,
        fuzzy: false,
    };
    let built = query::build(&searcher, engine.fields(), req, expand, budgets, deadline)?;
    let budget = deadline.sub(cfg.count_budget_ms);
    let limits = Limits {
        deadline,
        count_budget: (!exact).then_some(&budget),
        check_every: tuning.check_every,
    };
    let c = collect::run(
        &searcher,
        &*built.query,
        req.query.sort,
        &PageMode::CountOnly,
        false,
        &limits,
    )?;
    Ok(if c.cut {
        Total::AtLeast(c.total)
    } else {
        Total::Exact(c.total)
    })
}

impl<H: Hydrator> SearchIndex for TantivyIndex<H> {
    async fn search(&self, q: &SearchQuery) -> Result<Page<ReleaseRow>, StoreError> {
        // The 2.x contract: exact token matching (FTS5 parity), exact totals.
        let req = SearchRequest::from(q.clone());
        let p = self.page(&req, Nav::Offset(q.offset), true).await?;
        Ok(Page {
            items: p.items,
            total: p.total.value(),
            offset: q.offset,
            limit: p.limit,
        })
    }

    async fn search_keyset(
        &self,
        q: &SearchQuery,
        dir: SeekDir,
        at: &PageCursor,
    ) -> Result<KeysetPage, StoreError> {
        let req = SearchRequest::from(q.clone());
        let parts = cursor::parts(at, q.sort)?;
        let p = self.page(&req, Nav::Keyset(dir, parts), true).await?;
        Ok(KeysetPage {
            items: p.items,
            total: p.total.value(),
            limit: p.limit,
            has_more: p.has_more,
        })
    }

    async fn count(&self, q: &SearchQuery) -> Result<u64, StoreError> {
        // Exact (the 2.x trait promises an exact count); bounded by the query deadline only.
        let req = SearchRequest::from(q.clone());
        let cfg = self.svc.config().clone();
        let n = self
            .svc
            .run_blocking(move |engine, deadline, tuning| {
                count(&engine, &req, &cfg, &deadline, tuning, true)
            })
            .await?;
        Ok(n.value())
    }

    /// Reconciliation hook (review 32 L5): asks the source of truth to re-index `doc.release_id`
    /// (T112 `PgDb::enqueue_reindex`: one outbox row). The indexer then writes the release's
    /// **current** state; the text in `doc` is not used, because v3 never indexes anything that is
    /// not in the database (and a direct write would bypass a running rebuild). The 2.x FTS5 hook wrote
    /// the given text at once; the ported conformance suite checks the v3 meaning.
    async fn upsert(&self, doc: &SearchDoc<'_>) -> Result<(), StoreError> {
        self.hydrator.enqueue_reindex(&[doc.release_id]).await
    }

    /// Reconciliation hook: as [`SearchIndex::upsert`]; a release that no longer exists is removed by
    /// the indexer, one that still exists is re-indexed (the index never drops a live release).
    async fn remove(&self, release_id: i64) -> Result<(), StoreError> {
        self.hydrator.enqueue_reindex(&[release_id]).await
    }
}
