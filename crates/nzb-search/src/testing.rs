//! Test support for the crates that serve listings through the index (`nzb-web`, `nzbd`, the bench): a
//! [`SettlingIndex`] over the configured [`Store`] that runs the indexer to an empty outbox before every read, so a
//! test sees its own writes at once (production serves with ~1 s of index lag, ARCHITECTURE v3 3.5). Behind the
//! `test-support` feature; never part of a release build.

use std::path::Path;
use std::sync::Arc;

use nzb_store::{
    KeysetPage, Page, PageCursor, ReleaseRow, SearchDoc, SearchIndex, SearchQuery, SeekDir,
};
use nzb_store::{Store, StoreError};
use tokio::sync::Mutex;

use crate::SearchError;
use crate::clock::SystemClock;
use crate::config::SearchConfig;
use crate::engine::IndexDir;
use crate::index::{SearchIndexV3, SearchService, TantivyIndex};
use crate::indexer::{Indexer, IndexerSettings};
use crate::request::{SearchPage, SearchRequest, Total};
use crate::stats::{LibraryStats, StatsRequest};

/// [`TantivyIndex`] over a [`Store`] with the indexer settled before every call.
#[derive(Clone)]
pub struct SettlingIndex {
    inner: TantivyIndex<Store>,
    indexer: Arc<Mutex<Indexer<Store>>>,
}

impl SettlingIndex {
    /// Opens (or creates) the index in `dir` for `store` and builds it.
    ///
    /// # Panics
    /// When the index cannot be opened or built (test support).
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    pub async fn open(store: &Store, dir: &Path) -> Self {
        Self::open_with(store, dir, SearchConfig::default()).await
    }

    /// [`SettlingIndex::open`] with explicit engine settings.
    ///
    /// # Panics
    /// When the index cannot be opened or built (test support).
    #[allow(clippy::expect_used)]
    pub async fn open_with(store: &Store, dir: &Path, cfg: SearchConfig) -> Self {
        let svc = SearchService::new(cfg.clone(), Arc::new(SystemClock::new()));
        let mut settings = IndexerSettings::from_config(&cfg);
        settings.writer.heap_bytes = 32 << 20;
        settings.writer.threads = 1;
        settings.rebuild_writer = settings.writer;
        let mut ix = Indexer::start(
            Arc::clone(&svc),
            store.clone(),
            IndexDir::open(dir).expect("index dir"),
            settings,
        )
        .await
        .expect("indexer");
        ix.settle().await.expect("initial build");
        Self {
            inner: TantivyIndex::new(svc, store.clone()),
            indexer: Arc::new(Mutex::new(ix)),
        }
    }

    /// Runs the indexer until the outbox is empty.
    ///
    /// # Errors
    /// Indexer errors.
    pub async fn settle(&self) -> Result<(), SearchError> {
        self.indexer.lock().await.settle().await
    }

    /// The service (status, degraded mode).
    #[must_use]
    pub fn service(&self) -> &Arc<SearchService> {
        self.inner.service()
    }
}

impl SearchIndex for SettlingIndex {
    async fn search(&self, q: &SearchQuery) -> Result<Page<ReleaseRow>, StoreError> {
        self.settle().await?;
        self.inner.search(q).await
    }

    async fn search_keyset(
        &self,
        q: &SearchQuery,
        dir: SeekDir,
        at: &PageCursor,
    ) -> Result<KeysetPage, StoreError> {
        self.settle().await?;
        self.inner.search_keyset(q, dir, at).await
    }

    async fn count(&self, q: &SearchQuery) -> Result<u64, StoreError> {
        self.settle().await?;
        self.inner.count(q).await
    }

    async fn upsert(&self, doc: &SearchDoc<'_>) -> Result<(), StoreError> {
        self.inner.upsert(doc).await
    }

    async fn remove(&self, release_id: i64) -> Result<(), StoreError> {
        self.inner.remove(release_id).await
    }
}

impl SearchIndexV3 for SettlingIndex {
    async fn search_page(&self, req: &SearchRequest) -> Result<SearchPage, SearchError> {
        self.settle().await?;
        self.inner.search_page(req).await
    }

    async fn search_keyset_page(
        &self,
        req: &SearchRequest,
        dir: SeekDir,
        at: &PageCursor,
    ) -> Result<SearchPage, SearchError> {
        self.settle().await?;
        self.inner.search_keyset_page(req, dir, at).await
    }

    async fn count_total(&self, req: &SearchRequest) -> Result<Total, SearchError> {
        self.settle().await?;
        self.inner.count_total(req).await
    }

    async fn library_stats(&self, req: &StatsRequest) -> LibraryStats {
        if let Err(e) = self.settle().await {
            return LibraryStats {
                groups: Err(SearchError::Task),
                quality: Err(SearchError::Task),
                timeline: Err(e),
            };
        }
        self.inner.library_stats(req).await
    }
}
