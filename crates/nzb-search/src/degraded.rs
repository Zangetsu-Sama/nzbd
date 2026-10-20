//! Degraded listing mode while no index generation is servable (ARCHITECTURE v3 3.3, review L5).
//!
//! Newest-first browse by `release.id` (primary-key keyset walk in Postgres), no text search, no
//! filter other than category, totals from `category_stats`. Bounded so a rebuild window cannot
//! exhaust the `web` pool:
//! * a **category page** is served only when `category_stats.releases` of its allowed set is at least
//!   `limit x` [`CATEGORY_FACTOR`] (there is no `category_id` index; the walk then finds a page within
//!   about 50k rows); otherwise the page says "available after the rebuild";
//! * **every** degraded page reads at most [`ROW_BUDGET`] primary-key entries and stops there with a
//!   "more after the rebuild" notice.
//!
//! The bounded primary-key walk itself is the source's: T112's `PgDb::degraded_browse(before, categories,
//! exclude, limit)` (its `DEGRADED_SCAN_BUDGET` is [`ROW_BUDGET`]). This module adds the category-size rule
//! (from `category_stats`), expands a parent to its direct children, re-checks the rows (SEC-090) and takes
//! the next-page cursor only from a **displayed** row (review L3).

use std::collections::{BTreeSet, HashMap};
use std::future::Future;

use nzb_core::Taxonomy;
use nzb_store::{MAX_LIMIT, ReleaseRow};

use crate::error::SearchError;

/// Primary-key entries one degraded page may read (the source enforces it).
pub const ROW_BUDGET: u64 = 200_000;
/// A category page needs at least `limit x CATEGORY_FACTOR` releases in its allowed set.
pub const CATEGORY_FACTOR: u64 = 1000;

/// What the source's bounded walk returns (the shape of T112's `DegradedPage`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkPage {
    /// Rows newest first, already restricted to `categories` and outside `exclude`.
    pub items: Vec<ReleaseRow>,
    /// The source's continuation id (not used as a cursor here unless it is a displayed row).
    pub next_before: Option<i64>,
    /// The row budget stopped the walk before the page was full.
    pub budget_exhausted: bool,
}

/// The Postgres side of degraded mode (T112).
pub trait DegradedSource: Send + Sync {
    /// `PgDb::degraded_browse`: newest first below `before`, restricted to `categories` (exact ids, empty
    /// = all) and outside `exclude`, at most [`ROW_BUDGET`] primary-key entries read.
    ///
    /// # Errors
    /// Database errors.
    fn browse(
        &self,
        before: Option<i64>,
        categories: &[u32],
        exclude: &[u32],
        limit: u32,
    ) -> impl Future<Output = Result<WalkPage, SearchError>> + Send;

    /// `SELECT category_id, releases FROM category_stats`.
    ///
    /// # Errors
    /// Database errors.
    fn category_totals(&self) -> impl Future<Output = Result<Vec<(u32, u64)>, SearchError>> + Send;
}

/// One degraded request (already validated: category ids from the taxonomy, a hidden category named
/// explicitly is refused before this point, as in normal mode).
#[derive(Debug, Clone, Default)]
pub struct DegradedRequest {
    /// Category ids; a parent also matches its direct children. Empty = every category.
    pub categories: Vec<u32>,
    /// Exact category ids hidden for this caller (instance rule + preference).
    pub exclude_categories: Vec<u32>,
    /// Continue below this release id (the last displayed row of the previous page).
    pub before: Option<i64>,
    /// Page size (clamped to `1..=100`).
    pub limit: u32,
}

/// Result of a degraded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradedPage {
    /// A page (possibly short).
    Page {
        /// Hydrated rows, newest first.
        items: Vec<ReleaseRow>,
        /// Releases in the allowed categories (`category_stats`, exact and current).
        total: u64,
        /// Cursor for the next page: the id of the last displayed row, when the walk can continue.
        next_before: Option<i64>,
        /// The row budget ended the walk: the UI shows "more after the rebuild".
        budget_exhausted: bool,
    },
    /// The category set is too small to be found by a bounded walk: "available after the rebuild".
    CategoryUnavailable,
}

/// The allowed category set of `req`: the requested ids and their direct children (or everything),
/// minus the exclusions.
fn allowed(taxonomy: &Taxonomy, req: &DegradedRequest) -> BTreeSet<u32> {
    let excluded: BTreeSet<u32> = req.exclude_categories.iter().copied().collect();
    taxonomy
        .entries()
        .iter()
        .filter(|c| {
            let id = u32::from(c.id);
            let parent = c.parent.map(u32::from);
            req.categories.is_empty()
                || req.categories.contains(&id)
                || parent.is_some_and(|p| req.categories.contains(&p))
        })
        .map(|c| u32::from(c.id))
        .filter(|id| !excluded.contains(id))
        .collect()
}

/// Serves one degraded page under the L5 bounds.
///
/// # Errors
/// Source errors.
pub async fn browse<S: DegradedSource>(
    source: &S,
    taxonomy: &Taxonomy,
    req: &DegradedRequest,
) -> Result<DegradedPage, SearchError> {
    let limit = req.limit.clamp(1, MAX_LIMIT);
    let allowed = allowed(taxonomy, req);
    let totals: HashMap<u32, u64> = source.category_totals().await?.into_iter().collect();
    let total = allowed
        .iter()
        .map(|c| totals.get(c).copied().unwrap_or(0))
        .fold(0u64, u64::saturating_add);
    if !req.categories.is_empty() && total < u64::from(limit).saturating_mul(CATEGORY_FACTOR) {
        return Ok(DegradedPage::CategoryUnavailable);
    }
    // The source wants exact ids: a requested parent comes with its children (and no excluded id).
    let cats: Vec<u32> = if req.categories.is_empty() {
        Vec::new()
    } else {
        allowed.iter().copied().collect()
    };
    let page = source
        .browse(req.before, &cats, &req.exclude_categories, limit)
        .await?;
    let full = page.items.len() >= usize::try_from(limit).unwrap_or(usize::MAX);
    let items: Vec<ReleaseRow> = page
        .items
        .into_iter()
        .filter(|r| allowed.contains(&r.category_id))
        .collect();
    // Only a displayed row becomes a cursor (review L3): a page that showed nothing has none.
    let next_before = if full || page.budget_exhausted {
        items.last().map(|r| r.id)
    } else {
        None
    };
    Ok(DegradedPage::Page {
        items,
        total,
        next_before,
        budget_exhausted: page.budget_exhausted,
    })
}
