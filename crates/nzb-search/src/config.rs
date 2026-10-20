//! `[search]` settings (ARCHITECTURE v3 section 7) with their hard maxima: configuration may only
//! lower a bound, never raise it past the constants here.
//!
//! Owner questions Q1, Q2 and Q5 (TASKS T111) were answered by D35 (2026-10-15): "more than n" past
//! 150 ms, numbered paging capped at 100,000 rows, prefix on with typo tolerance only as a zero-hit
//! fallback. Each is one constant below.

/// D35 (Q1): a count that runs longer than this returns `Total::AtLeast(n)` ("more than n").
pub const DEFAULT_COUNT_BUDGET_MS: u64 = 150;
/// D35 (Q2): offset pages (`page=N`) end here; keyset Next/Prev and Last are unaffected.
pub const DEFAULT_MAX_OFFSET: u32 = 100_000;
/// D35 (Q5): fuzzy matching only as a fallback for a text query with no exact hit.
pub const DEFAULT_FUZZY: FuzzyMode = FuzzyMode::Fallback;
/// D35 (Q5): prefix matching on the last token, bounded by the M6 budgets.
pub const DEFAULT_PREFIX: bool = true;

/// Hard maximum of `expansion_postings_budget` (summed document frequency of all expansions).
pub const MAX_EXPANSION_POSTINGS: u64 = 20_000_000;
/// Hard maximum of `expansion_terms_max` (distinct expanded terms per token and field, all segments).
pub const MAX_EXPANSION_TERMS: usize = 64;
/// Dictionary entries visited per token, field and segment during an expansion (review M6).
pub const MAX_DICT_ENTRIES_PER_SEGMENT: usize = 4096;
/// Raw query text kept, in characters (SEC-089; the 2.x web cap of 200 applies first where lower).
pub const MAX_Q_CHARS: usize = 256;
/// Analyzed query tokens kept (extra tokens are dropped, as in 2.x).
pub const MAX_Q_TOKENS: usize = 16;
/// A prefix expansion needs a last token of at least this many characters.
pub const PREFIX_MIN_CHARS: usize = 3;
/// A fuzzy alternative needs a token of at least this many characters.
pub const FUZZY_MIN_CHARS: usize = 5;
/// At most this many tokens of one query get fuzzy alternatives.
pub const MAX_FUZZY_TOKENS: usize = 4;
/// Hard maximum of concurrent engine searches.
pub const MAX_CONCURRENT_SEARCHES: usize = 64;
/// Hard maximum of the per-query deadline.
pub const MAX_QUERY_DEADLINE_MS: u64 = 10_000;

/// When fuzzy alternatives are used (`search.fuzzy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzyMode {
    /// Never.
    Off,
    /// Only when the exact (or prefix) query has 0 hits.
    Fallback,
    /// Only when the request asks for it (a form checkbox); never on every query by default.
    Toggle,
}

/// Search engine settings.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Commit at the latest after this many ms of pending changes (100..=60000).
    pub commit_interval_ms: u64,
    /// Commit at the latest after this many pending documents.
    pub commit_max_docs: usize,
    /// Indexing heap of the steady-state writer, MiB.
    pub writer_heap_mib: usize,
    /// Indexing threads of the steady-state writer.
    pub writer_threads: usize,
    /// Indexing heap of the rebuild writer, MiB.
    pub rebuild_heap_mib: usize,
    /// Concurrent engine searches (semaphore).
    pub max_concurrent_searches: usize,
    /// How long a request may wait for a search slot before `Busy`, ms.
    pub semaphore_wait_ms: u64,
    /// Wall-clock deadline of one search (expansion, weight builds, collection), ms.
    pub query_deadline_ms: u64,
    /// D35 (Q1): count budget, ms.
    pub count_budget_ms: u64,
    /// D35 (Q2): offset pagination cap, rows.
    pub max_offset: u32,
    /// D35 (Q5): fuzzy mode.
    pub fuzzy: FuzzyMode,
    /// D35 (Q5): prefix matching allowed.
    pub prefix: bool,
    /// Summed document frequency budget of all expansions of one query.
    pub expansion_postings_budget: u64,
    /// Distinct expanded terms per token and field across all segments.
    pub expansion_terms_max: usize,
    /// Dictionary entries visited per token, field and segment (hard maximum
    /// [`MAX_DICT_ENTRIES_PER_SEGMENT`]; lowered by tests and the fuzz target).
    pub expansion_dict_entries: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            commit_interval_ms: 1000,
            commit_max_docs: 10_000,
            writer_heap_mib: 256,
            writer_threads: 2,
            rebuild_heap_mib: 2048,
            max_concurrent_searches: 8,
            semaphore_wait_ms: 1000,
            query_deadline_ms: 2000,
            count_budget_ms: DEFAULT_COUNT_BUDGET_MS,
            max_offset: DEFAULT_MAX_OFFSET,
            fuzzy: DEFAULT_FUZZY,
            prefix: DEFAULT_PREFIX,
            expansion_postings_budget: 5_000_000,
            expansion_terms_max: MAX_EXPANSION_TERMS,
            expansion_dict_entries: MAX_DICT_ENTRIES_PER_SEGMENT,
        }
    }
}

impl SearchConfig {
    /// The settings with every value clamped into its allowed range.
    #[must_use]
    pub fn clamped(mut self) -> Self {
        self.commit_interval_ms = self.commit_interval_ms.clamp(100, 60_000);
        self.commit_max_docs = self.commit_max_docs.clamp(1, 1_000_000);
        // Tantivy refuses a heap below ~15 MB per thread; keep a sane floor and ceiling.
        self.writer_heap_mib = self.writer_heap_mib.clamp(32, 4096);
        self.writer_threads = self.writer_threads.clamp(1, 8);
        self.rebuild_heap_mib = self.rebuild_heap_mib.clamp(32, 16_384);
        self.max_concurrent_searches = self
            .max_concurrent_searches
            .clamp(1, MAX_CONCURRENT_SEARCHES);
        self.semaphore_wait_ms = self.semaphore_wait_ms.min(10_000);
        self.query_deadline_ms = self.query_deadline_ms.clamp(1, MAX_QUERY_DEADLINE_MS);
        self.count_budget_ms = self.count_budget_ms.min(self.query_deadline_ms);
        // Offset pages retain offset + page-size winners. Never let configuration turn a
        // hostile offset into a multi-gigabyte allocation before the query deadline is checked.
        self.max_offset = self.max_offset.min(DEFAULT_MAX_OFFSET);
        self.expansion_postings_budget = self.expansion_postings_budget.min(MAX_EXPANSION_POSTINGS);
        self.expansion_terms_max = self.expansion_terms_max.clamp(1, MAX_EXPANSION_TERMS);
        self.expansion_dict_entries = self
            .expansion_dict_entries
            .clamp(1, MAX_DICT_ENTRIES_PER_SEGMENT);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_window_remains_bounded_even_with_extreme_configuration() {
        for requested in [0, 1, DEFAULT_MAX_OFFSET, DEFAULT_MAX_OFFSET + 1, u32::MAX] {
            let cfg = SearchConfig {
                max_offset: requested,
                ..SearchConfig::default()
            }
            .clamped();
            assert!(cfg.max_offset <= DEFAULT_MAX_OFFSET);
            assert!(cfg.max_offset <= requested);
            if requested <= DEFAULT_MAX_OFFSET {
                assert_eq!(cfg.max_offset, requested);
            }
        }
    }
}
