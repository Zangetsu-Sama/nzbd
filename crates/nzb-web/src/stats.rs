//! `GET /stats`: the Statistics page (T132, `docs/UI_SPEC.md` "Statistics page"). Any signed-in role.
//!
//! Server-rendered, no JavaScript, no chart library: bars are `<span class="sbar"><i class="wNN"></i></span>` with a
//! width class in steps of 5 computed here (the CSP forbids inline styles), hidden from screen readers next to the
//! exact number as text.
//!
//! Sources. The overview and the per-category table come from the exact `category_stats` totals (one O(categories)
//! read, no scan of `release`); top groups, the quality breakdown and the timeline come from bounded aggregations of
//! the search index ([`SearchIndexV3::library_stats`]). Every number is **per caller**: the caller's hidden categories
//! (instance `ui.show_xxx` plus the caller's "Hide XXX for me") are dropped from the category rows before summing and
//! are the `MustNot` of every aggregation, exactly like the release list (SEC-090), so a hidden release changes no
//! number on the page, not even the list of group names.
//!
//! Cost. The numbers are cached per hidden set for [`TTL_SECS`] (a section that failed is retried after
//! [`RETRY_SECS`]); concurrent requests for the same set share one computation (single-flight: the slot's lock is held
//! while computing). Each engine section runs in its own search slot under the query deadline; one that cannot be
//! computed in time reads "not available right now" while the others are shown.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use askama::Template;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use nzb_core::Taxonomy;
use nzb_search::SearchIndexV3;
use nzb_search::stats::{LibraryStats, QualityStats, Ranked, StatsRequest, TimelineStats};
use nzb_store::prelude::*;
use nzb_store::{CategoryTotals, SortKey};

use crate::assets::Layout;
use crate::auth::SessionCtx;
use crate::error::ApiError;
use crate::index::{
    IndexParams, IndexState, civil_from_days, compact_count_exact, days_from_civil, human_bytes,
    parse_params,
};

/// How long computed numbers are reused, seconds (owner choice: 10 minutes).
pub const TTL_SECS: i64 = 600;
/// How long numbers with a failed section are reused before the next attempt, seconds.
pub const RETRY_SECS: i64 = 60;
/// Release groups listed.
pub const TOP_GROUPS: usize = 10;
/// Years listed.
pub const TOP_YEARS: usize = 10;
/// Months in the timeline (the current month and the 23 before it).
pub const MONTHS: usize = 24;
/// Longest group name shown, in characters (the index filter accepts 64; longer names are cut and not linked).
pub const MAX_GROUP_DISPLAY_CHARS: usize = 64;
/// Byte bound of the display sanitizer (above the index keyword cap of 128 bytes).
const MAX_GROUP_DISPLAY_BYTES: usize = 256;
/// A result computed within this many seconds after a library change is recomputed then (one indexer cycle,
/// target <= 2 s, plus margin).
pub const SETTLE_SECS: i64 = 5;
/// How long a request waits for another request's computation of the same numbers.
const WAITER_TIMEOUT: Duration = Duration::from_secs(10);
/// Hidden sets cached at once (in practice two: the instance set, and the instance set plus XXX).
const MAX_CACHED_SETS: usize = 8;

const DAY: i64 = 86_400;

/// Everything the page shows, computed once per hidden set and TTL.
#[derive(Debug)]
pub(crate) struct StatsData {
    /// Per-category totals of the visible categories (`None`: the store could not be read).
    categories: Option<Vec<CategoryTotals>>,
    engine: LibraryStats,
    /// Wall-clock time of the computation: the month labels follow the boundaries the counts used.
    at: i64,
}

impl StatsData {
    fn complete(&self) -> bool {
        self.categories.is_some()
            && self.engine.groups.is_ok()
            && self.engine.quality.is_ok()
            && self.engine.timeline.is_ok()
    }
}

impl StatsData {
    /// Every section unavailable (a waiter that gave up, a computation task that failed); never cached.
    fn unavailable(at: i64) -> Self {
        Self {
            categories: None,
            engine: LibraryStats::unavailable("statistics busy"),
            at,
        }
    }
}

/// Release category changes and deletes of this app (T132 review 47 L2). A change bumps the generation, which
/// invalidates every cached result; a result computed shortly after a change is kept only until [`SETTLE_SECS`] after
/// it (the index may not have the change yet), so a release moved into a hidden category leaves the page within one
/// indexer cycle plus that margin.
#[derive(Debug, Default)]
pub(crate) struct LibraryGeneration {
    generation: AtomicU64,
    changed_at: AtomicI64,
}

impl LibraryGeneration {
    /// Records a change at wall time `now`.
    pub(crate) fn note_change(&self, now: i64) {
        self.changed_at.fetch_max(now, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    fn read(&self) -> (u64, i64) {
        (
            self.generation.load(Ordering::SeqCst),
            self.changed_at.load(Ordering::SeqCst),
        )
    }
}

struct Cached {
    expires: i64,
    generation: u64,
    data: Arc<StatsData>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Cached>>>;

/// The per-hidden-set cache with single-flight (bounded: at most [`MAX_CACHED_SETS`] sets).
pub(crate) struct LibraryCache {
    slots: std::sync::Mutex<Vec<(Vec<u32>, Slot)>>,
    /// How long a request waits for another request's computation of the same set (review 47 I2).
    wait: Duration,
}

impl Default for LibraryCache {
    fn default() -> Self {
        Self::with_wait(WAITER_TIMEOUT)
    }
}

impl LibraryCache {
    fn with_wait(wait: Duration) -> Self {
        Self {
            slots: std::sync::Mutex::default(),
            wait,
        }
    }

    fn slot(&self, hidden: &[u32]) -> Slot {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, s)) = slots.iter().find(|(h, _)| h.as_slice() == hidden) {
            return Arc::clone(s);
        }
        if slots.len() >= MAX_CACHED_SETS {
            // Only reachable with an unusual taxonomy; dropping the oldest set costs one recomputation.
            slots.remove(0);
        }
        let s: Slot = Arc::default();
        slots.push((hidden.to_vec(), Arc::clone(&s)));
        s
    }

    /// The cached numbers of `hidden`, or `compute()` run now. The computation runs in its own task that owns the
    /// set's lock and stores the result (review 47 M2): a request that goes away only stops waiting, the scan it
    /// started still fills the cache. Requests arriving meanwhile wait at most [`LibraryCache::wait`] for it and are
    /// then answered with every section unavailable (never cached).
    async fn get<F, Fut>(
        &self,
        hidden: &[u32],
        now: i64,
        changes: &LibraryGeneration,
        compute: F,
    ) -> Arc<StatsData>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = StatsData> + Send + 'static,
    {
        let slot = self.slot(hidden);
        let Ok(mut guard) = tokio::time::timeout(self.wait, slot.lock_owned()).await else {
            return Arc::new(StatsData::unavailable(now));
        };
        let (generation, changed_at) = changes.read();
        if let Some(c) = guard.as_ref()
            && c.generation == generation
            && now < c.expires
        {
            return Arc::clone(&c.data);
        }
        let work = compute();
        let task = tokio::spawn(async move {
            let data = Arc::new(work.await);
            let ttl = if data.complete() {
                TTL_SECS
            } else {
                RETRY_SECS
            };
            let mut expires = now.saturating_add(ttl);
            let settled = changed_at.saturating_add(SETTLE_SECS);
            if now < settled {
                expires = expires.min(settled);
            }
            *guard = Some(Cached {
                expires,
                generation,
                data: Arc::clone(&data),
            });
            data
        });
        match task.await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "statistics computation failed");
                Arc::new(StatsData::unavailable(now))
            }
        }
    }
}

impl<S: SearchIndexV3 + Clone + Send + Sync + 'static> IndexState<S> {
    /// The numbers for `hidden` (sorted, deduplicated, subtree-closed ids).
    async fn library(&self, hidden: &[u32], changes: &LibraryGeneration) -> Arc<StatsData> {
        let now = self.clock.now_secs();
        let st = self.clone();
        let set = hidden.to_vec();
        self.library
            .get(hidden, now, changes, move || async move {
                st.compute(&set, now).await
            })
            .await
    }

    async fn compute(&self, hidden: &[u32], now: i64) -> StatsData {
        let categories = match self.db.category_stats_list().await {
            Ok(rows) => Some(
                rows.into_iter()
                    .filter(|r| !hidden.contains(&r.category_id))
                    .collect(),
            ),
            Err(e) => {
                tracing::warn!(error = %e, "statistics: category totals unavailable");
                None
            }
        };
        let req = StatsRequest {
            exclude: hidden.to_vec(),
            top_groups: TOP_GROUPS,
            top_years: TOP_YEARS,
            month_bounds: month_bounds(now, MONTHS),
            recent_since: vec![now.saturating_sub(7 * DAY), now.saturating_sub(30 * DAY)],
        };
        let engine = self.search.library_stats(&req).await;
        for (name, failed) in [
            ("groups", engine.groups.as_ref().err()),
            ("quality", engine.quality.as_ref().err()),
            ("timeline", engine.timeline.as_ref().err()),
        ] {
            if let Some(e) = failed {
                tracing::warn!(section = name, error = %e, "statistics section unavailable");
            }
        }
        StatsData {
            categories,
            engine,
            at: now,
        }
    }
}

/// Unix time of 00:00 UTC on the first day of the month `offset` months after the month of `secs`.
fn month_start(secs: i64, offset: i64) -> i64 {
    let (y, m, _) = civil_from_days(secs.div_euclid(DAY));
    let idx = y
        .saturating_mul(12)
        .saturating_add(m - 1)
        .saturating_add(offset);
    days_from_civil(idx.div_euclid(12), idx.rem_euclid(12) + 1, 1).saturating_mul(DAY)
}

/// `months + 1` ascending boundaries: the first day of each of the last `months` months (the current one last) and
/// the first day of the next month.
fn month_bounds(now: i64, months: usize) -> Vec<i64> {
    let n = i64::try_from(months).unwrap_or(0);
    (0..=n).map(|i| month_start(now, i - n + 1)).collect()
}

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `Oct 2026` for a month start.
fn month_label(start: i64) -> String {
    let (y, m, _) = civil_from_days(start.div_euclid(DAY));
    let name = usize::try_from(m - 1)
        .ok()
        .and_then(|i| MONTH_NAMES.get(i))
        .copied()
        .unwrap_or("?");
    format!("{name} {y}")
}

/// Width class (`w0`..`w100`, steps of 5) of `n` against the largest value `max`. A non-zero value is at least `w5`,
/// so it never looks like nothing; the number next to the bar is exact.
pub(crate) fn width_class(n: u64, max: u64) -> &'static str {
    const CLASSES: [&str; 21] = [
        "w0", "w5", "w10", "w15", "w20", "w25", "w30", "w35", "w40", "w45", "w50", "w55", "w60",
        "w65", "w70", "w75", "w80", "w85", "w90", "w95", "w100",
    ];
    if n == 0 || max == 0 {
        return "w0";
    }
    let pct = u128::from(n.min(max))
        .saturating_mul(100)
        .saturating_add(u128::from(max) / 2)
        / u128::from(max);
    let step = usize::try_from(pct.saturating_add(2) / 5)
        .unwrap_or(20)
        .clamp(1, 20);
    CLASSES.get(step).copied().unwrap_or("w100")
}

/// An index link for one validated filter, or `None` when the value would not pass the index parser (the link is
/// built by the index's own builder and checked by reading it back).
fn filter_href(tax: &Taxonomy, set: impl FnOnce(&mut IndexParams) -> Option<()>) -> Option<String> {
    let mut p = IndexParams {
        page: 1,
        ..IndexParams::default()
    };
    set(&mut p)?;
    let href = p.href(tax, SortKey::DateDesc, 1, true);
    let back = parse_params(href.strip_prefix("/?"), tax).ok()?;
    (back.group == p.group
        && back.family == p.family
        && back.resolution == p.resolution
        && back.source == p.source
        && back.year == p.year
        && back.category == p.category)
        .then_some(href)
}

/// One bar row.
pub(crate) struct BarRow {
    label: String,
    href: Option<String>,
    count: String,
    width: &'static str,
    /// A muted row ("Unknown", "No group").
    other: bool,
}

/// One per-category row.
pub(crate) struct CatRow {
    /// The display name split at `/` (rendered with a line-break opportunity after each slash, so a narrow
    /// column wraps `TV/Anime` between the parts, never inside a word).
    name_parts: Vec<String>,
    href: Option<String>,
    releases: String,
    size: String,
    average: String,
    width: &'static str,
    child: bool,
}

/// A list of bars, or the reason it is missing.
pub(crate) struct BarList {
    rows: Vec<BarRow>,
    available: bool,
}

/// One bar list of the quality section.
pub(crate) struct QualityList {
    id: &'static str,
    title: &'static str,
    list: BarList,
}

#[derive(Template)]
#[template(path = "stats.html")]
struct StatsPage {
    layout: Layout,
    releases: Option<String>,
    size: Option<String>,
    week: Option<String>,
    month: Option<String>,
    categories: Option<Vec<CatRow>>,
    groups: BarList,
    groups_note: String,
    quality: Vec<QualityList>,
    timeline: BarList,
    timeline_note: String,
}

fn unavailable() -> BarList {
    BarList {
        rows: Vec::new(),
        available: false,
    }
}

fn bars(items: Vec<(String, Option<String>, u64, bool)>) -> BarList {
    let max = items.iter().map(|(_, _, n, _)| *n).max().unwrap_or(0);
    BarList {
        rows: items
            .into_iter()
            .map(|(label, href, n, other)| BarRow {
                label,
                href,
                count: compact_count_exact(n),
                width: width_class(n, max),
                other,
            })
            .collect(),
        available: true,
    }
}

/// `(category id, releases, bytes)`.
type CatSum = (u16, u64, u64);

/// Per-category rows: each visible top-level category with releases, followed by its non-empty descendants; parents
/// by releases (then id), descendants likewise. Bars are relative to the largest parent. Every descendant (not only
/// direct children) is summed into and listed under its top-level category (review 47 I3): the built-in taxonomy has
/// two levels, a deeper one would list grandchildren flat under the top level instead of losing them.
fn category_rows(tax: &Taxonomy, rows: &[CategoryTotals]) -> Vec<CatRow> {
    let get = |id: u16| -> (u64, u64) {
        rows.iter()
            .find(|r| r.category_id == u32::from(id))
            .map_or((0, 0), |r| (r.releases, r.bytes))
    };
    let mut parents: Vec<(CatSum, Vec<CatSum>)> = Vec::new();
    for c in tax.entries().iter().filter(|c| c.parent.is_none()) {
        let (mut n, mut b) = get(c.id);
        let mut children: Vec<CatSum> = Vec::new();
        for ch in tax.subtree_ids(c.id).into_iter().filter(|id| *id != c.id) {
            let (cn, cb) = get(ch);
            if cn > 0 {
                children.push((ch, cn, cb));
            }
            n = n.saturating_add(cn);
            b = b.saturating_add(cb);
        }
        if n > 0 {
            children.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
            parents.push(((c.id, n, b), children));
        }
    }
    // XXX is listed last whatever its size (T146); the others stay by releases, then id.
    parents.sort_by(|x, y| {
        (x.0.0 == nzb_core::XXX_CATEGORY)
            .cmp(&(y.0.0 == nzb_core::XXX_CATEGORY))
            .then(y.0.1.cmp(&x.0.1))
            .then(x.0.0.cmp(&y.0.0))
    });
    let max = parents.iter().map(|p| p.0.1).max().unwrap_or(0);
    let row = |id: u16, n: u64, b: u64, child: bool| CatRow {
        name_parts: tax
            .get(id)
            .map(|c| c.name.split('/').map(str::to_owned).collect())
            .unwrap_or_default(),
        href: filter_href(tax, |p| {
            p.category = Some(id);
            Some(())
        }),
        releases: compact_count_exact(n),
        size: human_bytes(b),
        average: human_bytes(b.checked_div(n).unwrap_or(0)),
        width: width_class(n, max),
        child,
    };
    let mut out = Vec::new();
    for ((id, n, b), children) in parents {
        out.push(row(id, n, b, false));
        out.extend(
            children
                .into_iter()
                .map(|(cid, cn, cb)| row(cid, cn, cb, true)),
        );
    }
    out
}

fn group_list(tax: &Taxonomy, g: &Ranked) -> BarList {
    let mut items: Vec<(String, Option<String>, u64, bool)> = g
        .top
        .iter()
        .map(|(name, n)| {
            // Index keywords come from sanitized names; sanitize again for display anyway (bidi and invisible
            // characters, SEC-004) and only link a name the index filter takes unchanged.
            let clean = nzb_core::sanitize_text(name, MAX_GROUP_DISPLAY_BYTES);
            let shown: String = clean.chars().take(MAX_GROUP_DISPLAY_CHARS).collect();
            let href = if shown == *name {
                filter_href(tax, |p| {
                    p.group = Some(name.clone());
                    Some(())
                })
            } else {
                None
            };
            (shown, href, *n, false)
        })
        .collect();
    if g.without > 0 {
        items.push(("No group".to_owned(), None, g.without, true));
    }
    bars(items)
}

fn family_label(v: &str) -> Option<String> {
    crate::index::FAMILIES
        .contains(&v)
        .then(|| crate::index::family_label(v))
}

fn ranked_list(
    tax: &Taxonomy,
    r: &Ranked,
    label: impl Fn(&str) -> String,
    link: impl Fn(&mut IndexParams, &str) -> Option<()>,
) -> BarList {
    let mut items: Vec<(String, Option<String>, u64, bool)> = r
        .top
        .iter()
        .map(|(v, n)| (label(v), filter_href(tax, |p| link(p, v)), *n, false))
        .collect();
    if r.without > 0 {
        items.push(("Unknown".to_owned(), None, r.without, true));
    }
    bars(items)
}

fn quality_lists(tax: &Taxonomy, q: Option<&QualityStats>) -> Vec<QualityList> {
    let pick = |list: &'static [&'static str], v: &str| list.iter().find(|x| **x == v).copied();
    let make = |id, title, f: &dyn Fn(&QualityStats) -> BarList| QualityList {
        id,
        title,
        list: q.map_or_else(unavailable, f),
    };
    vec![
        make("q-res", "By resolution", &|q| {
            ranked_list(tax, &q.resolution, str::to_owned, |p, v| {
                p.resolution = Some(pick(crate::index::RESOLUTIONS, v)?);
                Some(())
            })
        }),
        make("q-src", "By source", &|q| {
            ranked_list(tax, &q.source, str::to_owned, |p, v| {
                p.source = Some(pick(crate::index::SOURCES, v)?);
                Some(())
            })
        }),
        make("q-fam", "By family", &|q| {
            ranked_list(
                tax,
                &q.family,
                |v| family_label(v).unwrap_or_else(|| v.to_owned()),
                |p, v| {
                    p.family = Some(pick(crate::index::FAMILIES, v)?);
                    Some(())
                },
            )
        }),
        make("q-year", "Top years", &|q| {
            ranked_list(tax, &q.year, str::to_owned, |p, v| {
                p.year = Some(v.parse().ok()?);
                Some(())
            })
        }),
    ]
}

fn timeline_list(now: i64, t: &TimelineStats) -> BarList {
    let bounds = month_bounds(now, MONTHS);
    let items = bounds
        .iter()
        .zip(t.months.iter())
        .map(|(start, n)| (month_label(*start), None, *n, false))
        .collect();
    bars(items)
}

/// The caller's hidden ids with every descendant added, sorted and deduplicated (review 47 L1): production sets are
/// already whole subtrees, but a set that names only a parent must still hide its children everywhere on the page.
pub(crate) fn subtree_closed(tax: &Taxonomy, hidden: &[u16]) -> Vec<u32> {
    let mut out: Vec<u32> = hidden
        .iter()
        .flat_map(|h| {
            let mut ids = tax.subtree_ids(*h);
            ids.push(*h);
            ids
        })
        .map(u32::from)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// `GET /stats`.
pub(crate) async fn page<S: SearchIndexV3 + Clone + Send + Sync + 'static>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    let tax = st.taxonomy.as_ref();
    let hidden = subtree_closed(tax, &sess.hidden_categories);
    let data = st.library(&hidden, &sess.library_gen).await;
    let (releases, size) = data.categories.as_ref().map_or((None, None), |rows| {
        let n = rows.iter().fold(0_u64, |a, r| a.saturating_add(r.releases));
        let b = rows.iter().fold(0_u64, |a, r| a.saturating_add(r.bytes));
        (Some(compact_count_exact(n)), Some(human_bytes(b)))
    });
    let timeline = data.engine.timeline.as_ref().ok();
    let recent = |i: usize| {
        timeline
            .and_then(|t| t.recent.get(i))
            .map(|n| compact_count_exact(*n))
    };
    let groups = data.engine.groups.as_ref().ok();
    let view = StatsPage {
        layout: Layout::for_session("Statistics", &sess),
        releases,
        size,
        week: recent(0),
        month: recent(1),
        categories: data
            .categories
            .as_ref()
            .map(|rows| category_rows(tax, rows)),
        groups: groups.map_or_else(unavailable, |g| group_list(tax, g)),
        groups_note: groups.map_or_else(String::new, |g| {
            if g.capped {
                format!(
                    "More than {} release groups: the list counts the first {} seen and may be incomplete.",
                    compact_count_exact(g.distinct),
                    compact_count_exact(g.distinct)
                )
            } else {
                format!(
                    "{} release groups in total.",
                    compact_count_exact(g.distinct)
                )
            }
        }),
        quality: quality_lists(tax, data.engine.quality.as_ref().ok()),
        timeline: timeline.map_or_else(unavailable, |t| timeline_list(data.at, t)),
        timeline_note: timeline.map_or_else(String::new, |t| {
            let shown = t.months.iter().fold(0_u64, |a, n| a.saturating_add(*n));
            format!(
                "{} releases added in the last {MONTHS} months.",
                compact_count_exact(shown)
            )
        }),
    };
    match view.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "statistics render failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn width_classes_are_clamped_and_never_hide_a_value() {
        assert_eq!(width_class(0, 10), "w0");
        assert_eq!(width_class(5, 0), "w0");
        assert_eq!(width_class(10, 10), "w100");
        assert_eq!(width_class(20, 10), "w100");
        assert_eq!(width_class(1, 1_000_000), "w5");
        assert_eq!(width_class(5, 10), "w50");
        assert_eq!(width_class(u64::MAX, u64::MAX), "w100");
    }

    #[test]
    fn month_bounds_are_month_starts() {
        // 2026-10-17 12:00 UTC.
        let now = days_from_civil(2026, 10, 17) * DAY + 12 * 3600;
        let b = month_bounds(now, 24);
        assert_eq!(b.len(), 25);
        assert_eq!(b[0], days_from_civil(2024, 11, 1) * DAY);
        assert_eq!(b[23], days_from_civil(2026, 10, 1) * DAY);
        assert_eq!(b[24], days_from_civil(2026, 11, 1) * DAY);
        assert!(b.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(month_label(b[0]), "Nov 2024");
        assert_eq!(month_label(b[23]), "Oct 2026");
        // Across a year end.
        let jan = days_from_civil(2027, 1, 31) * DAY;
        assert_eq!(month_bounds(jan, 2)[0], days_from_civil(2026, 12, 1) * DAY);
    }

    /// A three-level taxonomy whose hidden parent has a child and a grandchild (the built-in XXX has none).
    fn deep_taxonomy() -> Taxonomy {
        Taxonomy::from_toml_str(
            r#"
[[category]]
id = 6000
slug = "xxx"
name = "XXX"

[[category]]
id = 6010
parent = 6000
slug = "xxx.dvd"
name = "XXX/DVD"

[[category]]
id = 6011
parent = 6010
slug = "xxx.dvd.old"
name = "XXX/DVD/Old"

[[category]]
id = 8000
slug = "other"
name = "Other"

[[category]]
id = 8010
parent = 8000
slug = "other.misc"
name = "Other/Misc"
"#,
        )
        .unwrap()
    }

    fn totals(id: u32, releases: u64) -> CategoryTotals {
        CategoryTotals {
            category_id: id,
            releases,
            bytes: releases * 1024,
        }
    }

    fn names(rows: &[CatRow]) -> Vec<(String, String, bool)> {
        rows.iter()
            .map(|r| (r.name_parts.join("/"), r.releases.clone(), r.child))
            .collect()
    }

    /// Review 47 L1: a hidden set naming only a parent hides its whole subtree on the page.
    #[test]
    fn sec_090_hidden_parent_hides_children_and_grandchildren() {
        let tax = deep_taxonomy();
        assert_eq!(subtree_closed(&tax, &[6000]), vec![6000, 6010, 6011]);
        assert_eq!(subtree_closed(&tax, &[]), Vec::<u32>::new());
        let rows = [totals(6010, 2), totals(6011, 3), totals(8010, 1)];
        let hidden = subtree_closed(&tax, &[6000]);
        let visible: Vec<CategoryTotals> = rows
            .iter()
            .copied()
            .filter(|r| !hidden.contains(&r.category_id))
            .collect();
        let out = category_rows(&tax, &visible);
        assert_eq!(
            names(&out),
            vec![
                ("Other".to_owned(), "1".to_owned(), false),
                ("Other/Misc".to_owned(), "1".to_owned(), true),
            ]
        );
    }

    /// Review 47 I3: a grandchild is summed into its top-level category and listed under it, never lost.
    #[test]
    fn category_tree_keeps_grandchildren() {
        // T146: XXX is listed last whatever its size.
        let tax = deep_taxonomy();
        let rows = [totals(6010, 2), totals(6011, 3), totals(8010, 1)];
        assert_eq!(
            names(&category_rows(&tax, &rows)),
            vec![
                ("Other".to_owned(), "1".to_owned(), false),
                ("Other/Misc".to_owned(), "1".to_owned(), true),
                ("XXX".to_owned(), "5".to_owned(), false),
                ("XXX/DVD/Old".to_owned(), "3".to_owned(), true),
                ("XXX/DVD".to_owned(), "2".to_owned(), true),
            ]
        );
        // The built-in taxonomy has two levels (the case the page is laid out for).
        let builtin = Taxonomy::builtin().unwrap();
        for c in builtin.entries() {
            if let Some(p) = c.parent {
                assert!(builtin.get(p).unwrap().parent.is_none(), "{}", c.slug);
            }
        }
    }

    fn complete(at: i64) -> StatsData {
        StatsData {
            categories: Some(Vec::new()),
            engine: LibraryStats {
                groups: Ok(Ranked::default()),
                quality: Ok(QualityStats::default()),
                timeline: Ok(TimelineStats::default()),
            },
            at,
        }
    }

    /// A computation that counts its runs and takes `ms`.
    fn counted(
        runs: &Arc<AtomicU64>,
        ms: u64,
        at: i64,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = StatsData> + Send>> {
        let runs = Arc::clone(runs);
        move || {
            Box::pin(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                complete(at)
            })
        }
    }

    /// Review 47 M2: a request that goes away does not throw the computation away: the next request finds it
    /// (waits for it, then reads the cache) and nothing runs twice.
    #[tokio::test]
    async fn sec_095_aborted_request_still_fills_the_cache() {
        let cache = Arc::new(LibraryCache::default());
        let changes = Arc::new(LibraryGeneration::default());
        let runs = Arc::new(AtomicU64::new(0));
        let (c, g, r) = (Arc::clone(&cache), Arc::clone(&changes), Arc::clone(&runs));
        let first = tokio::spawn(async move { c.get(&[], 100, &g, counted(&r, 100, 100)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        first.abort();
        let data = cache.get(&[], 101, &changes, counted(&runs, 0, 101)).await;
        assert!(data.complete());
        assert_eq!(data.at, 100, "the aborted request's result");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        // And it is cached for the TTL.
        let again = cache.get(&[], 102, &changes, counted(&runs, 0, 102)).await;
        assert_eq!((again.at, runs.load(Ordering::SeqCst)), (100, 1));
    }

    /// Review 47 I2: a request does not wait longer than the waiter timeout for another request's computation; it is
    /// answered with every section unavailable, which is not cached.
    #[tokio::test]
    async fn sec_095_single_flight_waiters_time_out() {
        let cache = Arc::new(LibraryCache::with_wait(Duration::from_millis(50)));
        let changes = Arc::new(LibraryGeneration::default());
        let runs = Arc::new(AtomicU64::new(0));
        let (c, g, r) = (Arc::clone(&cache), Arc::clone(&changes), Arc::clone(&runs));
        let first = tokio::spawn(async move { c.get(&[], 100, &g, counted(&r, 400, 100)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = std::time::Instant::now();
        let waiter = cache.get(&[], 100, &changes, counted(&runs, 0, 100)).await;
        assert!(started.elapsed() < Duration::from_millis(300));
        assert!(waiter.categories.is_none() && waiter.engine.groups.is_err());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(first.await.unwrap().complete());
        // The timed-out answer was not cached: the next request reads the first computation.
        let next = cache.get(&[], 101, &changes, counted(&runs, 0, 101)).await;
        assert_eq!((next.at, runs.load(Ordering::SeqCst)), (100, 1));
    }

    /// Review 47 L2: a library change invalidates the cache at once, and a result computed right after a change is
    /// recomputed once the index has had time to catch up ([`SETTLE_SECS`]).
    #[tokio::test]
    async fn sec_090_library_change_invalidates_the_cache() {
        let cache = LibraryCache::default();
        let changes = LibraryGeneration::default();
        let runs = Arc::new(AtomicU64::new(0));
        let t = 1_000;
        cache.get(&[], t, &changes, counted(&runs, 0, t)).await;
        cache
            .get(&[], t + 1, &changes, counted(&runs, 0, t + 1))
            .await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        // A change: the next read recomputes.
        changes.note_change(t + 2);
        let d = cache
            .get(&[], t + 2, &changes, counted(&runs, 0, t + 2))
            .await;
        assert_eq!((d.at, runs.load(Ordering::SeqCst)), (t + 2, 2));
        // Within the settle window the fresh result is reused; after it, recomputed once more, then cached for the TTL.
        cache
            .get(&[], t + 3, &changes, counted(&runs, 0, t + 3))
            .await;
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        let d = cache
            .get(&[], t + 2 + SETTLE_SECS, &changes, counted(&runs, 0, t + 7))
            .await;
        assert_eq!((d.at, runs.load(Ordering::SeqCst)), (t + 7, 3));
        cache
            .get(&[], t + 300, &changes, counted(&runs, 0, t + 300))
            .await;
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        // Another hidden set has its own entry, invalidated by the same changes.
        cache
            .get(&[6000], t + 300, &changes, counted(&runs, 0, t + 300))
            .await;
        assert_eq!(runs.load(Ordering::SeqCst), 4);
    }
}
