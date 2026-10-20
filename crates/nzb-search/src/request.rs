//! v3 request and result types (ARCHITECTURE v3 3.5 item 4). The 2.x [`SearchQuery`] is carried as is;
//! the v3 additions are server-chosen values, never syntax.

use nzb_core::Taxonomy;
use nzb_store::{ReleaseRow, SearchQuery};

/// How query tokens match (chosen by the server, never by the text).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MatchMode {
    /// Every token must match a whole term (the 2.x FTS5 semantics).
    #[default]
    Exact,
    /// As `Exact`, and the last token (>= 3 chars) also matches terms it is a prefix of (bounded).
    Prefix,
    /// As `Exact`/`Prefix`, and tokens of >= 5 chars also match terms at edit distance 1 (bounded).
    Fuzzy,
}

/// A v3 search: the 2.x query plus the v3 fields.
#[derive(Debug, Clone, Default)]
pub struct SearchRequest {
    /// Text, filters, exclusions, sort and paging (2.x semantics).
    pub query: SearchQuery,
    /// Token matching.
    pub match_mode: MatchMode,
    /// Only releases uploaded by this account (`added_by` filter).
    pub added_by: Option<i64>,
    /// Only releases with this source label (ASCII case-insensitive).
    pub source_label: Option<String>,
    /// Only releases ingested at or after this Unix time (the `added` fast field, inclusive: one-second resolution, so
    /// the second of the visit is counted once more rather than lost, review 42 I2): the "N new" badge of a saved
    /// search (T127). Server-chosen (the account's own `last_seen_at`), never request text.
    pub ingested_since: Option<i64>,
    /// Caller deadline in milliseconds for best-effort work such as the saved-search badges (T127, review 42 L1):
    /// the search slot is taken only when one is free right now (never queued behind other searches; else
    /// [`crate::SearchError::Busy`]) and the engine stops at `min(this, search.query_deadline_ms)`, so work the
    /// caller has stopped waiting for frees its slot early. `None`: the normal slot wait and query deadline.
    pub caller_deadline_ms: Option<u64>,
    /// Count matches per category in the same pass.
    pub want_facets: bool,
    /// Apply the fuzzy fallback when the request asks for it (`search.fuzzy = "toggle"`).
    pub fuzzy_requested: bool,
}

impl From<SearchQuery> for SearchRequest {
    fn from(query: SearchQuery) -> Self {
        Self {
            query,
            ..Self::default()
        }
    }
}

/// A total that may be a lower bound (owner question Q1, decided by D35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Total {
    /// Exact number of matches in the searcher snapshot.
    Exact(u64),
    /// At least this many: counting stopped at `search.count_budget_ms` ("more than n").
    AtLeast(u64),
}

impl Total {
    /// The number (exact, or the lower bound).
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Exact(n) | Self::AtLeast(n) => n,
        }
    }
}

/// One page of a v3 search.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent pagination and expansion metadata, not exclusive states.
pub struct SearchPage {
    /// Hydrated rows in the sort order; rows that are gone or hidden for the caller were dropped.
    pub items: Vec<ReleaseRow>,
    /// Matches of the query (hidden categories excluded inside the query).
    pub total: Total,
    /// Whether the listing continues in the direction of travel.
    pub has_more: bool,
    /// Effective page size.
    pub limit: u32,
    /// Matches per category id, ascending id (only with `want_facets`; empty when the count was cut).
    pub facets: Vec<(u32, u64)>,
    /// A prefix/fuzzy expansion was cut by a budget. This diagnostic is not safe to display with
    /// category exclusions: shared dictionaries and work limits can depend on hidden documents.
    /// Use the corpus-independent `expansion_bounded` notice in that case instead.
    pub narrowed: bool,
    /// Prefix/fuzzy expansion is possible for the request/configuration. Independent of dictionary
    /// contents and actual truncation; lets a filtered UI explain that alternatives are bounded
    /// without revealing which hidden dictionary caused a limit. False for exact/no-text queries.
    pub expansion_bounded: bool,
    /// The fuzzy fallback produced this page (the exact query had no hit).
    pub fuzzy_fallback: bool,
    /// Index hits dropped at hydration (gone or now hidden): pages can be shorter than `limit`.
    pub dropped: usize,
}

/// The exact category ids hidden for one request: the instance rule (`ui.show_xxx = false`) plus the
/// caller's preference (T120 `hide_xxx`). A preference can only add to the instance set, never remove
/// from it (SEC-090): with `show_xxx = false` the XXX tree is hidden whatever the preference says.
#[must_use]
pub fn exclusion_set(taxonomy: &Taxonomy, show_xxx: bool, user_hide_xxx: bool) -> Vec<u32> {
    if show_xxx && !user_hide_xxx {
        return Vec::new();
    }
    let mut ids: Vec<u32> = taxonomy
        .subtree_ids(nzb_core::XXX_CATEGORY)
        .into_iter()
        .map(u32::from)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}
