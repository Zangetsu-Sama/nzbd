//! `nzb-search` — the v3 Tantivy search index (T113, `docs/v3/ARCHITECTURE.md` section 2).
//!
//! Layout: [`analyzer`] (the `scene` analyzer shared by indexing and queries), [`schema`] (fields, index
//! schema version), [`doc`] (the indexer's document builder), [`query`] (hostile request -> bounded
//! Tantivy query), [`engine`] (one index generation: reader, single writer, commit payload).
//!
//! # Search index contract in v3 (ARCHITECTURE v3 3.5; changes to the 2.x contract of `SearchIndex`)
//! 1. **Eventual consistency:** a committed release is listed after at most one indexer cycle (target <= 2 s);
//!    a listing never *displays* a row that is not in `release` or that is hidden for the caller (hydration
//!    re-checks existence and the current category); a crash never leaves a release permanently unfindable
//!    (outbox rows survive until applied; quarantine is reported). Within one cycle totals and facets may still
//!    count a release that just moved into a hidden category; it is never rendered.
//! 2. **Totals:** exact for the searcher snapshot through the 2.x trait. Through [`SearchIndexV3`] a separate
//!    count may stop at `search.count_budget_ms` and return [`request::Total::AtLeast`] (owner Q1, provisional).
//! 3. **Concurrent readers:** a page is one searcher snapshot plus one hydration statement; under concurrent
//!    deletes a page may hold fewer rows than `limit`, never a row that is not in `release`.
//! 4. **Cursors** are built only from displayed (hydrated) rows (review L3).
//! 5. **Hidden categories** are a `MustNot` clause of every query (SEC-090): hits, totals, facets and keyset pages
//!    exclude them.
#![forbid(unsafe_code)]

pub mod analyzer;
pub mod clock;
mod collect;
pub mod config;
mod cursor;
pub mod degraded;
pub mod doc;
pub mod engine;
mod error;
pub mod index;
pub mod indexer;
pub mod query;
pub mod request;
pub mod schema;
mod sidecar;
pub mod stats;
mod store_source;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
mod walk;

pub use error::SearchError;
pub use index::{
    EngineResult, Hydrator, PathChoice, SearchIndexV3, SearchService, ServiceStatus, TantivyIndex,
    engine_search,
};

#[cfg(test)]
mod analyzer_tests;
#[cfg(test)]
mod ban_probe;
#[cfg(test)]
mod collect_tests;
#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod degraded_tests;
#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod indexer_tests;
#[cfg(test)]
mod lint_tests;
#[cfg(test)]
mod query_tests;
#[cfg(test)]
mod stats_tests;
#[cfg(test)]
mod store_source_tests;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod walk_tests;
