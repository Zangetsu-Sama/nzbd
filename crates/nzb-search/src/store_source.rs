//! The one adapter between the storage seam and the search engine (ARCHITECTURE v3 13.1, review 34 L4): the
//! configured [`Store`] (SQLite or Postgres) is the indexer's [`IndexSource`], the [`Hydrator`] of
//! [`crate::TantivyIndex`] and the [`DegradedSource`] of the degraded browse. Error mapping happens here once; both
//! backends keep the `IndexSource` contract themselves (file text cut in SQL and per streamed row at
//! [`MAX_FILES_BYTES`], the byte bound of `scan`, the replay flag read inside the consume transaction).

use std::future::Future;

use nzb_store::{IndexRow, LibraryRepo as _, ReleaseRow, Store, StoreError};

use crate::analyzer::MAX_FILES_BYTES;
use crate::degraded::{DegradedSource, WalkPage};
use crate::doc::IndexDoc;
use crate::error::SearchError;
use crate::index::Hydrator;
use crate::indexer::{IndexSource, OutboxRow, SourceState};

fn doc_of(r: &IndexRow) -> IndexDoc {
    IndexDoc::from_row(
        &r.release,
        r.category_parent,
        &r.files,
        r.version,
        r.added_by,
    )
}

impl IndexSource for Store {
    async fn read_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>, SearchError> {
        Ok(self
            .search_outbox_read(limit)
            .await?
            .into_iter()
            .map(|e| OutboxRow {
                seq: e.seq,
                release_id: e.release_id,
            })
            .collect())
    }

    async fn load(&self, ids: &[i64]) -> Result<Vec<IndexDoc>, SearchError> {
        Ok(self
            .search_index_load(ids, MAX_FILES_BYTES)
            .await?
            .into_iter()
            .map(|r| doc_of(&r))
            .collect())
    }

    async fn consume(&self, rows: &[OutboxRow]) -> Result<(), SearchError> {
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        let ids: Vec<i64> = rows.iter().map(|r| r.release_id).collect();
        Ok(self.search_outbox_consume(&seqs, &ids).await?)
    }

    async fn quarantine(&self, release_id: i64, code: &'static str) -> Result<(), SearchError> {
        Ok(self.search_quarantine(release_id, code).await?)
    }

    async fn state(&self) -> Result<SourceState, SearchError> {
        let s = self.search_source_state().await?;
        Ok(SourceState {
            epoch: s.epoch,
            outbox_last_seq: s.outbox_last_seq,
            replay: s.replay,
            rebuild_requested: s.rebuild_requested,
            finished_generation: s.finished_generation,
        })
    }

    async fn begin_rebuild(&self) -> Result<(), SearchError> {
        Ok(self.search_begin_rebuild().await?)
    }

    async fn scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<IndexDoc>, SearchError> {
        Ok(self
            .search_index_scan(after_id, limit, max_bytes, MAX_FILES_BYTES)
            .await?
            .into_iter()
            .map(|r| doc_of(&r))
            .collect())
    }

    async fn replay_ids(&self, after_id: i64, limit: usize) -> Result<Vec<i64>, SearchError> {
        Ok(self.search_replay_ids(after_id, limit).await?)
    }

    async fn finish_rebuild(&self, generation: u64) -> Result<(), SearchError> {
        Ok(self.search_finish_rebuild(generation).await?)
    }
}

impl Hydrator for Store {
    fn hydrate(
        &self,
        ids: &[i64],
        exclude: &[u32],
    ) -> impl Future<Output = Result<Vec<ReleaseRow>, StoreError>> + Send {
        nzb_store::LibraryRepo::hydrate(self, ids, exclude)
    }

    fn enqueue_reindex(&self, ids: &[i64]) -> impl Future<Output = Result<(), StoreError>> + Send {
        nzb_store::LibraryRepo::enqueue_reindex(self, ids)
    }
}

impl DegradedSource for Store {
    async fn browse(
        &self,
        before: Option<i64>,
        categories: &[u32],
        exclude: &[u32],
        limit: u32,
    ) -> Result<WalkPage, SearchError> {
        let p = self
            .degraded_browse(before, categories, exclude, limit)
            .await?;
        Ok(WalkPage {
            items: p.items,
            next_before: p.next_before,
            budget_exhausted: p.budget_exhausted,
        })
    }

    async fn category_totals(&self) -> Result<Vec<(u32, u64)>, SearchError> {
        Ok(nzb_store::LibraryRepo::category_totals(self).await?)
    }
}
