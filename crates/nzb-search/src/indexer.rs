//! The indexer: the single writer that applies the transactional outbox to the index, and the
//! new-generation rebuild (ARCHITECTURE v3 3.2-3.3, SEC-091, SEC-092).
//!
//! The source of truth is abstract ([`IndexSource`]); T112 implements it on Postgres. Ordering, per
//! round: read outbox rows -> load the **current** rows of their ids (one snapshot) -> `delete_term` +
//! `add_document` -> commit with payload `max_seq` -> delete **exactly** the rows read. A crash before
//! the commit loses nothing (the rows are still in the outbox); a crash between commit and delete applies
//! them again (idempotent: documents are rebuilt from current state, keyed by release id). No other
//! recovery state exists.
//!
//! Rebuild (new generation while the old one serves): `replay` flag committed **before** the scan
//! (from then on every outbox delete copies its ids into `search_replay`, the flag being read inside
//! that transaction, review L6 a) -> scan by id range into `gen-<n+1>`, committing `scan_upto_id`
//! (resumable) and running live rounds on the old generation between batches -> apply the replay set ->
//! drain the outbox into the new generation -> final commit -> `CURRENT` -> install -> clear the
//! rebuild state in one transaction -> remove old generations.
//!
//! Writer failures (review I3): an apply/commit error or a panic in the blocking task drops the
//! writer and reopens it from the last commit; after [`MAX_WRITER_FAILURES`] failures within
//! [`WRITER_FAILURE_WINDOW_MS`] the service degrades and a rebuild starts. The indexer never exits
//! the process, so a bad segment cannot crash-loop the container.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;

use crate::analyzer::{
    MAX_FILES_BYTES, MAX_POSTER_BYTES, MAX_SOURCE_NAME_BYTES, MAX_TITLE_BYTES, cap_bytes,
};
use crate::config::SearchConfig;
use crate::doc::IndexDoc;
use crate::engine::{Engine, IndexDir, Payload, WriterSettings, check_servable};
use crate::error::SearchError;
use crate::index::SearchService;
use crate::schema::INDEX_SCHEMA_VERSION;

/// Writer failures tolerated within [`WRITER_FAILURE_WINDOW_MS`] before degrading and rebuilding.
pub const MAX_WRITER_FAILURES: usize = 3;
/// Window of [`MAX_WRITER_FAILURES`], ms (10 minutes).
pub const WRITER_FAILURE_WINDOW_MS: u64 = 600_000;
/// Attempts of a document that cannot be built before its release is quarantined.
pub const MAX_DOC_ATTEMPTS: u32 = 3;
/// Consecutive live rounds that fail on a document-source error before the next one bisects the batch
/// with per-document loads (review 55): one release whose load always fails must not stall the outbox
/// forever, while a short database outage still never bisects (it would only add load).
pub const MAX_STORE_ERROR_ROUNDS: u32 = 8;
/// Fixed quarantine error code (never a message with data).
pub const QUARANTINE_DOC_BUILD: &str = "DOC_BUILD_FAILED";
/// Quarantine code of a document whose add or commit breaks the Tantivy writer (review 32 L4).
pub const QUARANTINE_DOC_INDEX: &str = "DOC_INDEX_FAILED";
/// Most text one release contributes to a load or scan batch: the per-field index caps
/// (`IndexSource` contract: `load` and `scan` cut file names at [`MAX_FILES_BYTES`] in SQL).
pub const MAX_DOC_TEXT_BYTES: usize =
    MAX_TITLE_BYTES + MAX_POSTER_BYTES + MAX_SOURCE_NAME_BYTES + MAX_FILES_BYTES;
/// Text bytes one load or scan batch may hold (review 32 M2).
pub const BATCH_TEXT_BYTES: usize = 64 << 20;
/// Ids per `load` call: `BATCH_TEXT_BYTES / MAX_DOC_TEXT_BYTES` (254).
pub const LOAD_CHUNK: usize = BATCH_TEXT_BYTES / MAX_DOC_TEXT_BYTES;

/// Re-applies the per-release text caps (the source should already have; a source that did not still
/// cannot make a document bigger than the index would keep).
fn cap_text(docs: &mut [IndexDoc]) {
    for d in docs {
        for (s, max) in [
            (&mut d.title, MAX_TITLE_BYTES),
            (&mut d.poster, MAX_POSTER_BYTES),
            (&mut d.source_name, MAX_SOURCE_NAME_BYTES),
            (&mut d.files, MAX_FILES_BYTES),
        ] {
            let keep = cap_bytes(s, max).len();
            s.truncate(keep);
        }
    }
}

/// One outbox row. No payload by design (SEC-092): the indexer always reads the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutboxRow {
    /// `search_outbox.seq`.
    pub seq: i64,
    /// `search_outbox.release_id` (may name a release that no longer exists: a delete).
    pub release_id: i64,
}

/// Database state the indexer needs at start and before serving (`search_state` + the outbox
/// sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceState {
    /// `search_state.epoch` (rotated by restores).
    pub epoch: [u8; 16],
    /// `last_value` of the outbox identity sequence (0 when never used): an index whose payload
    /// `max_seq` exceeds it is ahead of the database (review M2 a).
    pub outbox_last_seq: i64,
    /// `search_state.replay`: a rebuild is in progress.
    pub replay: bool,
    /// `search_state.rebuild_requested_at IS NOT NULL` (`nzbd search rebuild`).
    pub rebuild_requested: bool,
    /// `search_state.rebuild_generation`: the generation the last **finished** rebuild activated
    /// (0 = none yet). A higher active generation with `replay` still set is a rebuild that crashed
    /// after its switch and only needs [`IndexSource::finish_rebuild`].
    pub finished_generation: u64,
}

/// What the indexer needs from the source of truth. T112 implements it on Postgres; every method is
/// one statement or one short transaction on the `background` pool.
pub trait IndexSource: Send + Sync + 'static {
    /// `SELECT seq, release_id FROM search_outbox ORDER BY seq LIMIT $1`.
    ///
    /// # Errors
    /// Database errors.
    fn read_outbox(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<OutboxRow>, SearchError>> + Send;

    /// The current documents of `ids` in **one** snapshot (release row + aggregated file names +
    /// category parent). Ids that no longer exist are absent. The indexer asks for at most
    /// [`LOAD_CHUNK`] ids per call.
    ///
    /// **Size contract (review 32 M2):** a document's file-name text is at most [`MAX_FILES_BYTES`]
    /// bytes, cut **in SQL** before it is materialized (aggregate a bounded subquery, `ORDER BY idx
    /// LIMIT n`, and cut the aggregate with `left(...)`); title and poster are bounded by their column
    /// CHECKs (512 bytes). The same holds for [`IndexSource::scan`] and for every backend (the SQLite
    /// source of D35 uses `substr`). The indexer cuts again, but only after the rows are in memory.
    ///
    /// # Errors
    /// Database errors.
    fn load(&self, ids: &[i64]) -> impl Future<Output = Result<Vec<IndexDoc>, SearchError>> + Send;

    /// One transaction: `DELETE FROM search_outbox WHERE seq = ANY($1)` for exactly `rows`, and, when
    /// `search_state.replay` (read **inside** this transaction) is set, insert their release ids into
    /// `search_replay` (review L6 a).
    ///
    /// # Errors
    /// Database errors (the rows stay and are applied again: idempotent).
    fn consume(&self, rows: &[OutboxRow]) -> impl Future<Output = Result<(), SearchError>> + Send;

    /// `INSERT INTO search_quarantine (release_id, error_code, at) ... ON CONFLICT DO NOTHING`.
    ///
    /// # Errors
    /// Database errors.
    fn quarantine(
        &self,
        release_id: i64,
        code: &'static str,
    ) -> impl Future<Output = Result<(), SearchError>> + Send;

    /// Epoch, outbox sequence position, replay and rebuild-request flags.
    ///
    /// # Errors
    /// Database errors.
    fn state(&self) -> impl Future<Output = Result<SourceState, SearchError>> + Send;

    /// `UPDATE search_state SET replay = true` and **commit**, before the scan reads anything.
    ///
    /// # Errors
    /// Database errors.
    fn begin_rebuild(&self) -> impl Future<Output = Result<(), SearchError>> + Send;

    /// Current documents with `id > after_id`, ascending id, at most `limit`, and no more documents
    /// once their text reaches `max_bytes` (at least one is returned while any remains). Release in id
    /// order merged with the file names of the same id range; the size contract of
    /// [`IndexSource::load`] applies.
    ///
    /// # Errors
    /// Database errors.
    fn scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<IndexDoc>, SearchError>> + Send;

    /// Ids in `search_replay` with `id > after_id`, ascending, at most `limit`.
    ///
    /// # Errors
    /// Database errors.
    fn replay_ids(
        &self,
        after_id: i64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<i64>, SearchError>> + Send;

    /// One transaction: `replay = false`, `rebuild_requested_at = NULL`, `rebuild_generation = $1`,
    /// `DELETE FROM search_replay` (the app role has no `TRUNCATE`).
    ///
    /// # Errors
    /// Database errors.
    fn finish_rebuild(
        &self,
        generation: u64,
    ) -> impl Future<Output = Result<(), SearchError>> + Send;
}

/// Test-only crash points (fault injection). Each is "the process dies right here".
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Fault {
    AfterRead,
    AfterLoad,
    AfterApply,
    AfterCommit,
    AfterConsume,
    RebuildAfterBegin,
    RebuildAfterCreate,
    RebuildAfterScanCommit,
    RebuildAfterScan,
    RebuildAfterReplay,
    RebuildAfterDrainCommit,
    RebuildAfterCurrent,
    RebuildAfterInstall,
    RebuildAfterFinish,
    WriterPanic,
}

/// What one live round did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundReport {
    /// Outbox rows read.
    pub rows: usize,
    /// Documents written (replaced or added).
    pub upserts: usize,
    /// Releases removed.
    pub deletes: usize,
    /// Releases quarantined this round.
    pub quarantined: usize,
}

/// Indexer settings (from `[search]`).
#[derive(Debug, Clone, Copy)]
pub struct IndexerSettings {
    /// Outbox rows per round (`search.commit_max_docs`).
    pub batch: usize,
    /// Documents per rebuild scan batch.
    pub scan_batch: usize,
    /// Scan documents between two rebuild commits (1M in production).
    pub scan_commit_docs: usize,
    /// Steady-state writer.
    pub writer: WriterSettings,
    /// Rebuild writer.
    pub rebuild_writer: WriterSettings,
}

impl IndexerSettings {
    /// Production settings of `cfg`.
    #[must_use]
    pub fn from_config(cfg: &SearchConfig) -> Self {
        Self {
            batch: cfg.commit_max_docs,
            scan_batch: 10_000,
            scan_commit_docs: 1_000_000,
            writer: WriterSettings::steady(cfg),
            rebuild_writer: WriterSettings::rebuild(cfg),
        }
    }
}

/// The single writer of the index directory.
pub struct Indexer<S> {
    svc: Arc<SearchService>,
    source: S,
    dir: IndexDir,
    settings: IndexerSettings,
    /// The generation the live rounds write to (the installed one, if any).
    live: Option<(u64, Arc<Engine>)>,
    doc_failures: HashMap<i64, u32>,
    writer_failures: VecDeque<u64>,
    /// Consecutive live rounds that ended in a document-source error ([`MAX_STORE_ERROR_ROUNDS`]).
    store_error_rounds: u32,
    rebuild_needed: bool,
    #[cfg(test)]
    faults: std::sync::Mutex<std::collections::HashSet<Fault>>,
}

impl<S> std::fmt::Debug for Indexer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Indexer")
            .field("live", &self.live.as_ref().map(|(g, _)| *g))
            .field("rebuild_needed", &self.rebuild_needed)
            .finish_non_exhaustive()
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, SearchError> + Send + 'static,
) -> Result<T, SearchError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| SearchError::Task)?
}

impl<S: IndexSource> Indexer<S> {
    /// Opens the index directory and decides what to serve.
    ///
    /// The active generation is installed only when its payload matches the database (epoch, schema,
    /// not ahead of the outbox sequence, not an unfinished rebuild); otherwise the service stays in
    /// degraded mode and [`Indexer::rebuild_needed`] is set. A rebuild that was interrupted after its
    /// generation became active is finished here.
    ///
    /// # Errors
    /// Source errors; [`SearchError::Engine`] with a lock error when another writer holds the
    /// directory (`INDEXER_LOCKED`).
    pub async fn start(
        svc: Arc<SearchService>,
        source: S,
        dir: IndexDir,
        settings: IndexerSettings,
    ) -> Result<Self, SearchError> {
        let mut me = Self {
            svc,
            source,
            dir,
            settings,
            live: None,
            doc_failures: HashMap::new(),
            writer_failures: VecDeque::new(),
            store_error_rounds: 0,
            rebuild_needed: false,
            #[cfg(test)]
            faults: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        let state = me.source.state().await?;
        let current = me.dir.current();
        let newest = me.dir.generations()?.last().copied();
        if let Some(g) = current
            && state.replay
            && newest == current
            && g > state.finished_generation
        {
            // Interrupted after the switch: the active generation is the rebuilt one.
            me.source.finish_rebuild(g).await?;
            me.gc(g)?;
        }
        let state = me.source.state().await?;
        if let Some(g) = current {
            match me.open_generation(g, &state).await {
                Ok(engine) => {
                    me.svc.install(Arc::clone(&engine));
                    me.live = Some((g, engine));
                }
                Err(SearchError::NotServable(reason)) => {
                    me.svc.degrade(reason);
                    me.rebuild_needed = true;
                }
                Err(e) if is_lock_error(&e) => return Err(e),
                Err(_) => {
                    me.svc.degrade("index does not open");
                    me.rebuild_needed = true;
                }
            }
        } else {
            me.svc.degrade("no index yet");
            me.rebuild_needed = true;
        }
        if state.replay || state.rebuild_requested {
            me.rebuild_needed = true;
        }
        if !state.replay
            && let Some((g, _)) = &me.live
        {
            // Generations other than the active one are leftovers of a rebuild that never set its
            // replay flag (derived data, not user files).
            let g = *g;
            me.gc(g)?;
        }
        Ok(me)
    }

    async fn open_generation(
        &self,
        g: u64,
        state: &SourceState,
    ) -> Result<Arc<Engine>, SearchError> {
        let path = self.dir.generation(g);
        let ws = self.settings.writer;
        let engine = blocking(move || Engine::open(&path, ws)).await?;
        check_servable(&engine.payload(), state.epoch, state.outbox_last_seq)?;
        // Sidecars are loaded (validated) or built before the generation serves (review 32 M1).
        let engine = Arc::new(engine);
        let e = Arc::clone(&engine);
        blocking(move || e.warm_sidecars()).await?;
        Ok(engine)
    }

    /// A rebuild must run before (or while) the index serves.
    #[must_use]
    pub const fn rebuild_needed(&self) -> bool {
        self.rebuild_needed
    }

    #[cfg(test)]
    pub(crate) fn inject(&self, f: Fault) {
        self.faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(f);
    }

    #[cfg(test)]
    pub(crate) fn clear_faults(&self) {
        self.faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    #[cfg(test)]
    fn hit(&self, f: Fault) -> Result<(), SearchError> {
        let set = self
            .faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if set.contains(&f) {
            Err(SearchError::Injected)
        } else {
            Ok(())
        }
    }

    /// One live round on the installed generation (no-op without one).
    ///
    /// # Errors
    /// Source errors; writer errors after the writer was reopened (the rows stay in the outbox);
    /// injected faults in tests.
    pub async fn run_once(&mut self) -> Result<RoundReport, SearchError> {
        let Some((_, engine)) = self.live.clone() else {
            return Ok(RoundReport::default());
        };
        self.round(&engine, true).await
    }

    /// Reads, loads, applies and commits one batch of outbox rows into `engine`; consumes them when
    /// `consume`.
    ///
    /// Memory (review 32 M2): ids are loaded [`LOAD_CHUNK`] at a time and each chunk is handed to the
    /// writer before the next is read; with the per-release text caps of the [`IndexSource`] contract
    /// (enforced again here) one chunk holds at most [`BATCH_TEXT_BYTES`] of text, whatever
    /// `commit_max_docs` is. Nothing is committed before every chunk is applied.
    async fn round(
        &mut self,
        engine: &Arc<Engine>,
        consume: bool,
    ) -> Result<RoundReport, SearchError> {
        let rows = self.source.read_outbox(self.settings.batch).await?;
        #[cfg(test)]
        self.hit(Fault::AfterRead)?;
        if rows.is_empty() {
            return Ok(RoundReport::default());
        }
        let ids: BTreeSet<i64> = rows.iter().map(|r| r.release_id).collect();
        let ids: Vec<i64> = ids.into_iter().collect();
        let max_seq = rows.iter().map(|r| r.seq).max().unwrap_or(0);
        let mut report = RoundReport {
            rows: rows.len(),
            ..RoundReport::default()
        };
        let mut build_failed: Vec<i64> = Vec::new();
        let mut index_failed: Vec<i64> = Vec::new();
        let applied = self
            .apply_ids(engine, &ids, &mut report, &mut build_failed)
            .await;
        let applied = match applied {
            Ok(()) => self.commit_round(engine, max_seq).await,
            Err(e) => Err(e),
        };
        match applied {
            Ok(()) => self.store_error_rounds = 0,
            #[cfg(test)]
            Err(SearchError::Injected) => return Err(SearchError::Injected),
            Err(err @ SearchError::Store(_))
                if self.store_error_rounds.saturating_add(1) < MAX_STORE_ERROR_ROUNDS =>
            {
                // The document source failed (database down, statement timeout), not the writer:
                // bisecting the batch would only hammer the database and a few of these rounds would
                // degrade the index for nothing. Drop the uncommitted work and leave the outbox rows
                // for the next round (idempotent).
                self.store_error_rounds = self.store_error_rounds.saturating_add(1);
                let e = Arc::clone(engine);
                if blocking(move || e.reopen_writer()).await.is_err() {
                    self.writer_failed(engine).await;
                }
                return Err(err);
            }
            Err(err) => {
                // The writer lost the round's uncommitted work. Before blaming the writer, look for a
                // document that breaks it (review 32 L4). After MAX_STORE_ERROR_ROUNDS source errors in
                // a row (the outbox answered every time), look for a document whose load fails instead.
                let per_doc_loads = matches!(err, SearchError::Store(_));
                let (bad, failed) = match self.isolate(engine, &ids, per_doc_loads).await {
                    Ok(v) => {
                        self.store_error_rounds = 0;
                        v
                    }
                    // Isolation already discarded the interrupted group's pending changes.
                    Err(source @ SearchError::Store(_)) => {
                        self.store_error_rounds = self.store_error_rounds.saturating_add(1);
                        return Err(source);
                    }
                    Err(_) => {
                        self.writer_failed(engine).await;
                        return Err(err);
                    }
                };
                // A quarantined release leaves the listings (its older copy too).
                self.apply(engine, Vec::new(), bad.clone()).await?;
                index_failed = bad;
                build_failed = failed;
                self.commit_round(engine, max_seq).await?;
            }
        }
        #[cfg(test)]
        self.hit(Fault::AfterCommit)?;
        for id in &index_failed {
            self.source.quarantine(*id, QUARANTINE_DOC_INDEX).await?;
            report.quarantined = report.quarantined.saturating_add(1);
        }
        // Rows of documents that failed to build stay in the outbox for a retry, up to the limit.
        let mut keep: BTreeSet<i64> = BTreeSet::new();
        for id in build_failed {
            let n = self.doc_failures.entry(id).or_insert(0);
            *n = n.saturating_add(1);
            if *n >= MAX_DOC_ATTEMPTS {
                self.source.quarantine(id, QUARANTINE_DOC_BUILD).await?;
                self.doc_failures.remove(&id);
                report.quarantined = report.quarantined.saturating_add(1);
            } else {
                keep.insert(id);
            }
        }
        report.upserts = report
            .upserts
            .saturating_sub(keep.len().saturating_add(report.quarantined));
        if consume {
            let done: Vec<OutboxRow> = rows
                .into_iter()
                .filter(|r| !keep.contains(&r.release_id))
                .collect();
            self.source.consume(&done).await?;
            for r in &done {
                self.doc_failures.remove(&r.release_id);
            }
        }
        #[cfg(test)]
        self.hit(Fault::AfterConsume)?;
        Ok(report)
    }

    /// Loads `ids` chunk by chunk and queues them in `engine`'s writer (no commit).
    async fn apply_ids(
        &mut self,
        engine: &Arc<Engine>,
        ids: &[i64],
        report: &mut RoundReport,
        build_failed: &mut Vec<i64>,
    ) -> Result<(), SearchError> {
        for chunk in ids.chunks(LOAD_CHUNK) {
            let mut docs = self.source.load(chunk).await?;
            #[cfg(test)]
            self.hit(Fault::AfterLoad)?;
            cap_text(&mut docs);
            let present: BTreeSet<i64> = docs.iter().map(|d| d.id).collect();
            let deletes: Vec<i64> = chunk
                .iter()
                .copied()
                .filter(|id| !present.contains(id))
                .collect();
            report.upserts = report.upserts.saturating_add(docs.len());
            report.deletes = report.deletes.saturating_add(deletes.len());
            build_failed.extend(self.apply(engine, docs, deletes).await?);
        }
        Ok(())
    }

    /// Queues documents and deletes in a blocking task. Returns the ids whose document could not be built.
    async fn apply(
        &self,
        engine: &Arc<Engine>,
        docs: Vec<IndexDoc>,
        deletes: Vec<i64>,
    ) -> Result<Vec<i64>, SearchError> {
        #[cfg(test)]
        let panic_now = self.hit(Fault::WriterPanic).is_err();
        let e = Arc::clone(engine);
        blocking(move || {
            #[cfg(test)]
            if panic_now {
                e.poison_writer();
                #[allow(clippy::panic)]
                {
                    panic!("injected writer panic");
                }
            }
            let failed = e.apply(&docs, &deletes)?;
            Ok(failed.into_iter().map(|(id, _)| id).collect::<Vec<i64>>())
        })
        .await
    }

    /// Commits what is queued with `max_seq`, then warms the sidecars of new and merged segments (off
    /// the query path; a failure only means the planner collects until the next warm-up).
    async fn commit_round(&self, engine: &Arc<Engine>, max_seq: i64) -> Result<(), SearchError> {
        #[cfg(test)]
        let applied_hook = self.hit(Fault::AfterApply);
        let e = Arc::clone(engine);
        blocking(move || {
            #[cfg(test)]
            applied_hook?;
            let mut p = e.payload();
            p.max_seq = p.max_seq.max(max_seq);
            e.commit(&p)?;
            let _ = e.warm_sidecars();
            Ok(())
        })
        .await
    }

    /// After a failed batch: reopen the writer, check it can commit, then bisect `ids` (apply + commit
    /// per group) to find the documents whose add or commit breaks the writer. Returns those (to be
    /// quarantined as [`QUARANTINE_DOC_INDEX`]) and the documents that could not be built.
    ///
    /// With `per_doc_loads` (a live round after [`MAX_STORE_ERROR_ROUNDS`] source errors in a row), a
    /// group whose load fails is bisected too, and a single document that cannot be loaded joins the
    /// "could not be built" list (retried, then quarantined as [`QUARANTINE_DOC_BUILD`]), so one bad
    /// row cannot hold back the rest of the outbox.
    ///
    /// # Errors
    /// Source errors stop isolation and discard the interrupted group's uncommitted work (with
    /// `per_doc_loads`: only when no group loads at all, which points at the database, not a
    /// document; a batch of one document is that document).
    /// The writer itself is broken: it cannot commit an empty change, or no group succeeds at all
    /// (every document failing means the writer, not the documents).
    async fn isolate(
        &self,
        engine: &Arc<Engine>,
        ids: &[i64],
        per_doc_loads: bool,
    ) -> Result<(Vec<i64>, Vec<i64>), SearchError> {
        let healthy = |e: Arc<Engine>| {
            blocking(move || {
                e.reopen_writer()?;
                e.commit(&e.payload())
            })
        };
        healthy(Arc::clone(engine)).await?;
        let mut bad = Vec::new();
        let mut build_failed = Vec::new();
        let mut unloadable: Vec<i64> = Vec::new();
        let mut last_source_err: Option<SearchError> = None;
        let mut any_ok = false;
        let mut stack: Vec<Vec<i64>> = vec![ids.to_vec()];
        while let Some(group) = stack.pop() {
            let mut failed = Vec::new();
            let mut report = RoundReport::default();
            let r = async {
                for chunk in group.chunks(LOAD_CHUNK) {
                    let mut docs = self.source.load(chunk).await?;
                    cap_text(&mut docs);
                    let present: BTreeSet<i64> = docs.iter().map(|d| d.id).collect();
                    let deletes: Vec<i64> = chunk
                        .iter()
                        .copied()
                        .filter(|id| !present.contains(id))
                        .collect();
                    report.upserts = report.upserts.saturating_add(docs.len());
                    failed.extend(self.apply(engine, docs, deletes).await?);
                }
                let e = Arc::clone(engine);
                blocking(move || e.commit(&e.payload())).await
            }
            .await;
            match r {
                Ok(()) => {
                    any_ok = true;
                    build_failed.extend(failed);
                    continue;
                }
                Err(err @ SearchError::Store(_)) => {
                    // A failed load says nothing about the documents or the writer. Drop this
                    // group's queued work and leave every outbox event available for a retry.
                    let e = Arc::clone(engine);
                    blocking(move || e.reopen_writer()).await?;
                    if !per_doc_loads {
                        return Err(err);
                    }
                    if let [one] = group.as_slice() {
                        unloadable.push(*one);
                    } else {
                        let (a, b) = group.split_at(group.len() / 2);
                        stack.push(b.to_vec());
                        stack.push(a.to_vec());
                    }
                    last_source_err = Some(err);
                    continue;
                }
                Err(_) => {}
            }
            healthy(Arc::clone(engine)).await?;
            if let [one] = group.as_slice() {
                bad.push(*one);
            } else {
                let (a, b) = group.split_at(group.len() / 2);
                stack.push(b.to_vec());
                stack.push(a.to_vec());
            }
        }
        if !any_ok {
            let lone_unloadable = ids.len() == 1 && unloadable.len() == 1;
            if !lone_unloadable {
                return Err(last_source_err.unwrap_or(SearchError::WriterUnavailable));
            }
        }
        build_failed.extend(unloadable);
        bad.sort_unstable();
        Ok((bad, build_failed))
    }

    /// Writer lost (error or panic): reopen it; too many failures in the window -> degrade + rebuild.
    async fn writer_failed(&mut self, engine: &Arc<Engine>) {
        let now = self.svc.clock().now_ms();
        self.writer_failures.push_back(now);
        while self
            .writer_failures
            .front()
            .is_some_and(|t| now.saturating_sub(*t) > WRITER_FAILURE_WINDOW_MS)
        {
            self.writer_failures.pop_front();
        }
        let e = Arc::clone(engine);
        let reopened = blocking(move || e.reopen_writer()).await.is_ok();
        if !reopened || self.writer_failures.len() >= MAX_WRITER_FAILURES {
            self.svc.degrade("index writer failed");
            self.live = None;
            self.rebuild_needed = true;
        }
    }

    /// Builds a new generation from the source and makes it active (or resumes an interrupted one).
    ///
    /// # Errors
    /// Source and engine errors; injected faults in tests. On error nothing is lost: the replay flag
    /// stays set and the next start resumes.
    pub async fn rebuild(&mut self) -> Result<u64, SearchError> {
        let (g, new) = self.prepare_generation().await?;
        self.scan_into(&new).await?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterScan)?;
        self.apply_replay(&new).await?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterReplay)?;
        let new = self.drain_and_complete(g, &new).await?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterDrainCommit)?;
        self.activate(g, new).await?;
        Ok(g)
    }

    /// Step 1: discard stale generations, commit the replay flag, create (or resume) `gen-<n>`.
    async fn prepare_generation(&mut self) -> Result<(u64, Arc<Engine>), SearchError> {
        let state = self.source.state().await?;
        let current = self.dir.current();
        let gens = self.dir.generations()?;
        // Resume an unfinished generation of the same epoch when the replay flag survived; anything
        // else above the active generation is discarded.
        let mut resume: Option<(u64, Arc<Engine>)> = None;
        if state.replay {
            for g in gens.iter().rev().copied().filter(|g| Some(*g) != current) {
                let path = self.dir.generation(g);
                let ws = self.settings.rebuild_writer;
                if let Ok(e) = blocking(move || Engine::open(&path, ws)).await {
                    let p = e.payload();
                    if p.epoch == state.epoch
                        && p.schema == INDEX_SCHEMA_VERSION
                        && p.scan_upto_id.is_some()
                    {
                        resume = Some((g, Arc::new(e)));
                        break;
                    }
                }
            }
        }
        for g in gens.iter().copied() {
            if Some(g) != current && resume.as_ref().is_none_or(|(r, _)| *r != g) {
                self.dir.remove(g)?;
            }
        }
        // Committed before the scan reads anything (review L6 a).
        self.source.begin_rebuild().await?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterBegin)?;
        let out = if let Some(r) = resume {
            r
        } else {
            let g = gens
                .last()
                .copied()
                .max(current)
                .map_or(1, |m| m.saturating_add(1));
            let path = self.dir.generation(g);
            let ws = self.settings.rebuild_writer;
            let mut payload = Payload::new(state.epoch);
            payload.scan_upto_id = Some(0);
            let e = blocking(move || Engine::create(&path, payload, ws)).await?;
            (g, Arc::new(e))
        };
        #[cfg(test)]
        self.hit(Fault::RebuildAfterCreate)?;
        Ok(out)
    }

    /// Step 2: scan by id range; commit every `scan_commit_docs` with the position (resumable); live
    /// rounds keep the old generation fresh meanwhile (their consumed rows land in `search_replay`).
    async fn scan_into(&mut self, new: &Arc<Engine>) -> Result<(), SearchError> {
        let mut after = new.payload().scan_upto_id.unwrap_or(0);
        let mut since_commit = 0usize;
        // Releases quarantined during this scan: skipped when a failure makes the scan go back.
        let mut skip: BTreeSet<i64> = BTreeSet::new();
        loop {
            let mut docs = self
                .source
                .scan(after, self.settings.scan_batch, BATCH_TEXT_BYTES)
                .await?;
            let Some(last) = docs.last().map(|d| d.id) else {
                break;
            };
            docs.retain(|d| !skip.contains(&d.id));
            cap_text(&mut docs);
            let n = docs.len();
            let ids: Vec<i64> = docs.iter().map(|d| d.id).collect();
            match self.apply(new, docs, Vec::new()).await {
                Ok(failed) => self.quarantine_all(&failed).await?,
                #[cfg(test)]
                Err(SearchError::Injected) => return Err(SearchError::Injected),
                Err(e) => {
                    // The writer dropped everything since the last scan commit: quarantine the
                    // document that broke it (review 32 L4), then go back to that commit.
                    let (bad, failed) =
                        self.isolate(new, &ids, false).await.map_err(|isolation| {
                            if matches!(isolation, SearchError::Store(_)) {
                                isolation
                            } else {
                                e
                            }
                        })?;
                    for id in &bad {
                        self.source.quarantine(*id, QUARANTINE_DOC_INDEX).await?;
                    }
                    self.quarantine_all(&failed).await?;
                    skip.extend(bad.iter().chain(&failed));
                    after = new.payload().scan_upto_id.unwrap_or(0);
                    since_commit = 0;
                    continue;
                }
            }
            after = last;
            since_commit = since_commit.saturating_add(n);
            if since_commit >= self.settings.scan_commit_docs {
                since_commit = 0;
                self.commit_scan(new, after).await?;
                #[cfg(test)]
                self.hit(Fault::RebuildAfterScanCommit)?;
            }
            if let Some((_, old)) = self.live.clone() {
                self.round(&old, true).await?;
            }
        }
        self.commit_scan(new, i64::MAX).await
    }

    /// Step 3: changes committed during the scan (the replay set), current state again; one commit
    /// per batch so a writer failure loses only that batch.
    async fn apply_replay(&self, new: &Arc<Engine>) -> Result<(), SearchError> {
        let mut after = 0i64;
        loop {
            let ids = self.source.replay_ids(after, LOAD_CHUNK).await?;
            let Some(last) = ids.last().copied() else {
                break;
            };
            let mut docs = self.source.load(&ids).await?;
            cap_text(&mut docs);
            let present: BTreeSet<i64> = docs.iter().map(|d| d.id).collect();
            let gone: Vec<i64> = ids
                .iter()
                .copied()
                .filter(|i| !present.contains(i))
                .collect();
            let applied = match self.apply(new, docs, gone).await {
                Ok(failed) => self.commit_scan(new, i64::MAX).await.map(|()| failed),
                Err(e) => Err(e),
            };
            match applied {
                Ok(failed) => self.quarantine_all(&failed).await?,
                #[cfg(test)]
                Err(SearchError::Injected) => return Err(SearchError::Injected),
                Err(e) => {
                    let (bad, failed) =
                        self.isolate(new, &ids, false).await.map_err(|isolation| {
                            if matches!(isolation, SearchError::Store(_)) {
                                isolation
                            } else {
                                e
                            }
                        })?;
                    for id in &bad {
                        self.source.quarantine(*id, QUARANTINE_DOC_INDEX).await?;
                    }
                    self.quarantine_all(&failed).await?;
                }
            }
            after = last;
        }
        self.commit_scan(new, i64::MAX).await
    }

    /// Step 4: the live indexer is this task, so it is "stopped" while the outbox drains into the new
    /// generation; then the final commit marks it complete, and it is reopened with the steady-state
    /// writer (the rebuild heap is big).
    async fn drain_and_complete(
        &mut self,
        g: u64,
        new: &Arc<Engine>,
    ) -> Result<Arc<Engine>, SearchError> {
        loop {
            let r = self.round(new, true).await?;
            if r.rows < self.settings.batch {
                break;
            }
        }
        let e = Arc::clone(new);
        let path = self.dir.generation(g);
        let ws = self.settings.writer;
        let reopened = blocking(move || {
            let mut p = e.payload();
            p.scan_upto_id = None;
            e.commit(&p)?;
            e.close()?;
            drop(e);
            Engine::open(&path, ws)
        })
        .await?;
        Ok(Arc::new(reopened))
    }

    /// Step 5: `CURRENT`, install, clear the rebuild state (one transaction), remove old generations.
    async fn activate(&mut self, g: u64, new: Arc<Engine>) -> Result<(), SearchError> {
        self.dir.set_current(g)?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterCurrent)?;
        // Every sidecar of the new generation exists before it serves (review 32 M1): the freshly merged
        // segments of a rebuild are the largest ones.
        let warm = Arc::clone(&new);
        blocking(move || warm.warm_sidecars()).await?;
        if let Some((_, old)) = self.live.take() {
            let _ = blocking(move || old.close()).await;
        }
        self.svc.install(Arc::clone(&new));
        self.live = Some((g, new));
        #[cfg(test)]
        self.hit(Fault::RebuildAfterInstall)?;
        self.source.finish_rebuild(g).await?;
        #[cfg(test)]
        self.hit(Fault::RebuildAfterFinish)?;
        self.gc(g)?;
        self.rebuild_needed = false;
        self.writer_failures.clear();
        Ok(())
    }

    /// A full scan does not retry: a document that cannot be built is quarantined at once.
    async fn quarantine_all(&self, failed: &[i64]) -> Result<(), SearchError> {
        for id in failed {
            self.source.quarantine(*id, QUARANTINE_DOC_BUILD).await?;
        }
        Ok(())
    }

    async fn commit_scan(&self, e: &Arc<Engine>, upto: i64) -> Result<(), SearchError> {
        let e = Arc::clone(e);
        blocking(move || {
            let mut p = e.payload();
            p.scan_upto_id = Some(upto);
            e.commit(&p)
        })
        .await
    }

    /// Removes every generation except `keep`.
    fn gc(&self, keep: u64) -> Result<(), SearchError> {
        for g in self.dir.generations()? {
            if g != keep {
                self.dir.remove(g)?;
            }
        }
        Ok(())
    }

    /// Runs until the outbox is empty (and rebuilds first when needed). Tests and the CLI.
    ///
    /// # Errors
    /// As [`Indexer::run_once`] / [`Indexer::rebuild`].
    pub async fn settle(&mut self) -> Result<(), SearchError> {
        if self.rebuild_needed {
            self.rebuild().await?;
        }
        loop {
            let r = self.run_once().await?;
            if r.rows == 0 {
                return Ok(());
            }
            if self.rebuild_needed {
                self.rebuild().await?;
            }
        }
    }

    /// The generation the live rounds write to.
    #[must_use]
    pub fn live_engine(&self) -> Option<Arc<Engine>> {
        self.live.as_ref().map(|(_, e)| Arc::clone(e))
    }
}

fn is_lock_error(e: &SearchError) -> bool {
    matches!(
        e,
        SearchError::Engine(tantivy::TantivyError::LockFailure(..))
    )
}
