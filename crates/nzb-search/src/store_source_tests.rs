//! The indexer, hydrator and degraded browse against the real storage seam (T122, review 34 L4): every test body
//! runs on both backends through [`Store`] (`sqlite::<name>`, `postgres::<name>`), including crash at every step and
//! the batch memory bound. The model-based `indexer_tests` (in-memory source) stay the exhaustive engine tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::{Arc, Mutex};

use nzb_store::{DbConfig, FixtureRepo as _, LibraryRepo as _, SqliteDb, Store};

use crate::analyzer::MAX_FILES_BYTES;
use crate::clock::SystemClock;
use crate::config::SearchConfig;
use crate::doc::IndexDoc;
use crate::engine::{IndexDir, WriterSettings};
use crate::error::SearchError;
use crate::index::{SearchService, ServiceStatus};
use crate::indexer::{IndexSource, Indexer, IndexerSettings, OutboxRow, SourceState};
use crate::indexer_tests::{LIVE_FAULTS, REBUILD_FAULTS};
use crate::testkit::Spec;

pub(crate) struct Opened {
    pub(crate) store: Store,
    _keep: Box<dyn std::any::Any + Send>,
}

pub(crate) async fn open_sqlite() -> Opened {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    Opened {
        store: Store::Sqlite(db),
        _keep: Box::new(dir),
    }
}

pub(crate) async fn open_postgres() -> Opened {
    let t = nzb_store::pg::testing::TestDb::new().await;
    Opened {
        store: Store::Postgres(t.db.clone()),
        _keep: Box::new(t),
    }
}

/// Writes performed while the rebuild scan stands at a given position (ids relative to the corpus' first id).
#[derive(Clone, Copy)]
enum Hook {
    /// Edit the 1st, insert one, delete the 7th (the crash test).
    Churn(i64),
    /// Re-categorize the 2nd (already scanned) and delete the 3rd (the replay test).
    Replay(i64),
}

/// The store as an [`IndexSource`], with call recording and a write hook inside `scan`.
#[derive(Clone)]
struct Probe {
    store: Store,
    hook: Arc<Mutex<Option<(i64, Hook)>>>,
    loads: Arc<Mutex<Vec<Vec<IndexDoc>>>>,
    scans: Arc<Mutex<Vec<usize>>>,
}

impl Probe {
    fn new(store: &Store) -> Self {
        Self {
            store: store.clone(),
            hook: Arc::default(),
            loads: Arc::default(),
            scans: Arc::default(),
        }
    }
}

fn text_bytes(d: &IndexDoc) -> usize {
    d.title.len()
        + d.poster.len()
        + d.source_name.len()
        + d.group.as_deref().map_or(0, |g| g.len() + 1)
        + d.files.len()
}

impl IndexSource for Probe {
    async fn read_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>, SearchError> {
        self.store.read_outbox(limit).await
    }

    async fn load(&self, ids: &[i64]) -> Result<Vec<IndexDoc>, SearchError> {
        let docs = self.store.load(ids).await?;
        self.loads.lock().unwrap().push(docs.clone());
        Ok(docs)
    }

    async fn consume(&self, rows: &[OutboxRow]) -> Result<(), SearchError> {
        self.store.consume(rows).await
    }

    async fn quarantine(&self, release_id: i64, code: &'static str) -> Result<(), SearchError> {
        self.store.quarantine(release_id, code).await
    }

    async fn state(&self) -> Result<SourceState, SearchError> {
        self.store.state().await
    }

    async fn begin_rebuild(&self) -> Result<(), SearchError> {
        self.store.begin_rebuild().await
    }

    async fn scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<IndexDoc>, SearchError> {
        let fire = {
            let mut h = self.hook.lock().unwrap();
            match *h {
                Some((at, hook)) if at == after_id => {
                    *h = None;
                    Some(hook)
                }
                _ => None,
            }
        };
        match fire {
            Some(Hook::Churn(first)) => {
                self.store.set_category(first, 5040).await?;
                Spec::new(
                    u32::try_from(first + 5_000).unwrap(),
                    "inserted during the scan",
                    5,
                    Some(1),
                    8010,
                )
                .insert_into(&self.store)
                .await;
                self.store.delete_release(first + 6).await?;
            }
            Some(Hook::Replay(first)) => {
                self.store.set_category(first + 1, 5040).await?;
                self.store.delete_release(first + 2).await?;
            }
            None => {}
        }
        let docs = self.store.scan(after_id, limit, max_bytes).await?;
        self.scans
            .lock()
            .unwrap()
            .push(docs.iter().map(text_bytes).sum());
        Ok(docs)
    }

    async fn replay_ids(&self, after_id: i64, limit: usize) -> Result<Vec<i64>, SearchError> {
        self.store.replay_ids(after_id, limit).await
    }

    async fn finish_rebuild(&self, generation: u64) -> Result<(), SearchError> {
        self.store.finish_rebuild(generation).await
    }
}

fn settings() -> IndexerSettings {
    let w = WriterSettings {
        heap_bytes: 32 << 20,
        threads: 1,
    };
    IndexerSettings {
        batch: 3,
        scan_batch: 2,
        scan_commit_docs: 2,
        writer: w,
        rebuild_writer: w,
    }
}

async fn start(dir: &std::path::Path, src: &Probe) -> (Arc<SearchService>, Indexer<Probe>) {
    start_with(dir, src, settings()).await
}

async fn start_with(
    dir: &std::path::Path,
    src: &Probe,
    s: IndexerSettings,
) -> (Arc<SearchService>, Indexer<Probe>) {
    let svc = SearchService::new(SearchConfig::default(), Arc::new(SystemClock::new()));
    let ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(dir).unwrap(),
        s,
    )
    .await
    .unwrap();
    (svc, ix)
}

/// `(id, version)` of every release in the database, ascending id.
async fn expected(store: &Store) -> Vec<(i64, u64)> {
    store
        .search_index_scan(0, usize::MAX, usize::MAX, MAX_FILES_BYTES)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.release.id, r.version))
        .collect()
}

/// The index holds exactly the database's rows (by id and version), it is served, and the outbox and the
/// replay state are empty.
async fn assert_consistent(svc: &SearchService, store: &Store, ctx: &str) {
    assert_eq!(svc.status(), ServiceStatus::Serving, "{ctx}");
    let engine = svc.engine().unwrap();
    assert_eq!(
        engine.live_versions().unwrap(),
        expected(store).await,
        "{ctx}"
    );
    assert!(
        store.search_outbox_read(1).await.unwrap().is_empty(),
        "{ctx}"
    );
    let st = store.search_source_state().await.unwrap();
    assert!(!st.replay && !st.rebuild_requested, "{ctx}");
    assert!(
        store.search_replay_ids(0, 1).await.unwrap().is_empty(),
        "{ctx}"
    );
    assert!(engine.payload().max_seq <= st.outbox_last_seq, "{ctx}");
}

async fn seed(store: &Store, n: u32) {
    for i in 1..=n {
        Spec::new(
            i,
            &format!("release {i}"),
            u64::from(i),
            Some(i64::from(i)),
            8010,
        )
        .insert_into(store)
        .await;
    }
}

/// A batch of changes: an edit, a delete, an insert and two explicit re-index requests (ids relative to the
/// corpus' first id; digests from `tag` so repeated calls never collide).
async fn churn(store: &Store, first: i64, tag: u32) {
    let cat = if tag.is_multiple_of(2) { 5030 } else { 5040 };
    store.set_category(first + 1, cat).await.unwrap();
    let gone = first + 2 + i64::from(tag % 4);
    if store.get_release(gone).await.unwrap().is_some() {
        store.delete_release(gone).await.unwrap();
    }
    let id = Spec::new(900_000 + tag, "new", 1, None, 8010)
        .insert_into(store)
        .await;
    store.enqueue_reindex(&[first, id]).await.unwrap();
}

pub(crate) async fn indexer_follows_the_database(store: &Store) {
    let d = tempfile::tempdir().unwrap();
    seed(store, 8).await;
    let src = Probe::new(store);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    assert_consistent(&svc, store, "initial").await;
    churn(store, 1, 1).await;
    ix.settle().await.unwrap();
    assert_consistent(&svc, store, "after churn").await;
    // Edits reach the index: release 2 is now in 5040, so a category filter finds it there.
    let docs = store.load(&[2]).await.unwrap();
    assert_eq!(docs[0].category_id, 5040);
    // T131: both read paths carry the `.nzb` file name into the document.
    assert_eq!(docs[0].source_name, "orig.nzb");
    let scanned = store.scan(0, 2, usize::MAX).await.unwrap();
    assert_eq!(scanned.len(), 2);
    assert!(scanned.iter().all(|d| d.source_name == "orig.nzb"));
}

/// Review 35 L4: a change whose outbox row was consumed without being applied (a lost apply) leaves the index
/// document behind the database's `index_version` on both backends, which is what `nzbd search verify` reports as
/// stale. (On SQLite every document used to carry version 1, so the check could never fire.)
pub(crate) async fn a_lost_apply_shows_as_a_stale_document(store: &Store) {
    let d = tempfile::tempdir().unwrap();
    seed(store, 3).await;
    let src = Probe::new(store);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    assert_consistent(&svc, store, "initial").await;
    store.set_category(2, 5040).await.unwrap();
    let rows = store.search_outbox_read(10).await.unwrap();
    assert_ne!(rows.len(), 0);
    let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
    let ids: Vec<i64> = rows.iter().map(|r| r.release_id).collect();
    store.search_outbox_consume(&seqs, &ids).await.unwrap();
    let have: std::collections::BTreeMap<i64, u64> = svc
        .engine()
        .unwrap()
        .live_versions()
        .unwrap()
        .into_iter()
        .collect();
    let stale: Vec<i64> = expected(store)
        .await
        .into_iter()
        .filter(|(id, v)| have.get(id).is_some_and(|h| h < v))
        .map(|(id, _)| id)
        .collect();
    assert_eq!(stale, [2]);
}

pub(crate) async fn crash_at_every_step_keeps_index_and_database_consistent(store: &Store) {
    // Every fault on a fresh corpus in this backend's database (the store outlives the crash; the index
    // directory is reopened from disk).
    let mut tag = 0_u32;
    for (k, fault) in LIVE_FAULTS.into_iter().enumerate() {
        let first = reset(store, 1_000 * u32::try_from(k + 1).unwrap()).await;
        let d = tempfile::tempdir().unwrap();
        let src = Probe::new(store);
        {
            let (_svc, mut ix) = start(d.path(), &src).await;
            ix.settle().await.unwrap();
            tag += 1;
            churn(store, first, tag).await;
            ix.inject(fault);
            let e = ix.run_once().await.unwrap_err();
            assert!(matches!(e, SearchError::Injected), "{fault:?} {e:?}");
        } // crash: indexer, service and engines dropped, uncommitted work lost
        tag += 1;
        churn(store, first, tag).await;
        let (svc, mut ix) = start(d.path(), &src).await;
        assert!(!ix.rebuild_needed(), "{fault:?}");
        ix.settle().await.unwrap();
        assert_consistent(&svc, store, &format!("{fault:?}")).await;
    }
    for (k, fault) in REBUILD_FAULTS.into_iter().enumerate() {
        let first = reset(store, 100_000 * u32::try_from(k + 1).unwrap()).await;
        let d = tempfile::tempdir().unwrap();
        let src = Probe::new(store);
        {
            let (_svc, mut ix) = start(d.path(), &src).await;
            ix.settle().await.unwrap();
            // The operator asks for a rebuild; writes keep arriving during the scan.
            store.search_request_rebuild(1).await.unwrap();
            *src.hook.lock().unwrap() = Some((first + 1, Hook::Churn(first)));
            tag += 1;
            churn(store, first, tag).await;
            ix.inject(fault);
            let e = ix.rebuild().await.unwrap_err();
            assert!(matches!(e, SearchError::Injected), "{fault:?} {e:?}");
        }
        *src.hook.lock().unwrap() = None;
        tag += 1;
        churn(store, first, tag).await;
        let (svc, mut ix) = start(d.path(), &src).await;
        ix.settle().await.unwrap();
        assert_consistent(&svc, store, &format!("{fault:?}")).await;
        let dir = IndexDir::open(d.path()).unwrap();
        assert_eq!(
            dir.generations().unwrap(),
            [dir.current().unwrap()],
            "{fault:?}"
        );
    }
}

/// Empties the library through the store (the outbox records every removal), drains the outbox (no index
/// exists for the next run yet), clears any rebuild state and seeds 9 fresh releases (digests from `base`).
/// Returns the first new id.
async fn reset(store: &Store, base: u32) -> i64 {
    for (id, _) in expected(store).await {
        store.delete_release(id).await.unwrap();
    }
    loop {
        let rows = store.search_outbox_read(1_000).await.unwrap();
        if rows.is_empty() {
            break;
        }
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        store.search_outbox_consume(&seqs, &[]).await.unwrap();
    }
    store.search_finish_rebuild(0).await.unwrap();
    let mut first = None;
    for i in 1..=9 {
        let id = Spec::new(base + i, &format!("release {i}"), 1, Some(1), 8010)
            .insert_into(store)
            .await;
        first.get_or_insert(id);
    }
    first.unwrap()
}

pub(crate) async fn sec_091_rebuild_loses_no_change_committed_during_the_scan(store: &Store) {
    let d = tempfile::tempdir().unwrap();
    seed(store, 10).await;
    let src = Probe::new(store);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    // While the scan stands at id 4, release 2 (already scanned) changes and 3 (scanned) is deleted: the live
    // rounds consume their outbox rows on the old generation and the replay flag (committed before the scan)
    // copies their ids into search_replay, so the new generation gets them too.
    *src.hook.lock().unwrap() = Some((4, Hook::Replay(1)));
    let g = ix.rebuild().await.unwrap();
    assert_eq!(g, 2);
    assert_consistent(&svc, store, "after rebuild").await;
    assert!(store.get_release(3).await.unwrap().is_none());
    let docs = store.load(&[2]).await.unwrap();
    assert_eq!(docs[0].category_id, 5040);
}

pub(crate) async fn sec_095_indexer_batch_memory_is_bounded(store: &Store) {
    use crate::indexer::{BATCH_TEXT_BYTES, LOAD_CHUNK, MAX_DOC_TEXT_BYTES};
    let d = tempfile::tempdir().unwrap();
    // 12 releases with 3,000 file names of 100 bytes each (~300 KB of names, above the 256 KiB cap).
    for i in 1..=12_u32 {
        let mut s = Spec::new(i, &format!("big {i}"), 1, Some(1), 8010);
        s.files = (0..3_000).map(|k| format!("{k:0>96}.mkv")).collect();
        s.insert_into(store).await;
    }
    let src = Probe::new(store);
    let w = WriterSettings {
        heap_bytes: 64 << 20,
        threads: 1,
    };
    let (svc, mut ix) = start_with(
        d.path(),
        &src,
        IndexerSettings {
            batch: 10_000,
            scan_batch: 10_000,
            scan_commit_docs: 1_000_000,
            writer: w,
            rebuild_writer: w,
        },
    )
    .await;
    ix.settle().await.unwrap();
    let ids: Vec<i64> = expected(store)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    store.enqueue_reindex(&ids).await.unwrap();
    ix.settle().await.unwrap();
    assert_consistent(&svc, store, "big releases").await;
    let loads = src.loads.lock().unwrap();
    assert!(!loads.is_empty());
    for docs in loads.iter() {
        assert!(docs.len() <= LOAD_CHUNK);
        assert!(docs.iter().map(text_bytes).sum::<usize>() <= BATCH_TEXT_BYTES);
        for doc in docs {
            // Cut by the source (in SQL, then per streamed row), on a character boundary.
            assert!(doc.files.len() <= MAX_FILES_BYTES, "{}", doc.files.len());
            assert!(
                doc.files.len() > MAX_FILES_BYTES - 200,
                "{}",
                doc.files.len()
            );
        }
    }
    for b in src.scans.lock().unwrap().iter() {
        assert!(*b <= BATCH_TEXT_BYTES + MAX_DOC_TEXT_BYTES, "{b}");
    }
}

pub(crate) async fn hydrator_rechecks_existence_and_category(store: &Store) {
    seed(store, 4).await;
    store.set_category(3, 6000).await.unwrap();
    let rows = crate::index::Hydrator::hydrate(store, &[4, 99, 3, 1], &[6000])
        .await
        .unwrap();
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [4, 1]);
    store.enqueue_reindex(&[1, 2]).await.unwrap();
    let out = store.search_outbox_read(100).await.unwrap();
    assert_eq!(
        out.iter()
            .rev()
            .take(2)
            .map(|e| e.release_id)
            .collect::<Vec<_>>(),
        [2, 1]
    );
}

pub(crate) async fn degraded_browse_reads_the_store(store: &Store) {
    use crate::degraded::DegradedSource as _;
    seed(store, 6).await;
    store.set_category(5, 5040).await.unwrap();
    let p = store.browse(None, &[], &[5040], 3).await.unwrap();
    assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [6, 4, 3]);
    let p = store.browse(Some(3), &[8010], &[], 10).await.unwrap();
    assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1]);
    assert!(!p.budget_exhausted);
    let mut totals = crate::degraded::DegradedSource::category_totals(store)
        .await
        .unwrap();
    totals.sort_unstable();
    assert_eq!(totals, [(5040, 1), (8010, 5)]);
}

/// D41 (owner decision 2026-10-19, T142 abandoned): NFO text is display data only, never indexed or searchable. A
/// word that appears only in an attached NFO finds nothing; the release's own title still finds it.
pub(crate) async fn t142_nfo_text_is_never_searchable(store: &Store) {
    use nzb_store::{NfoAttach, SearchIndex as _, SearchQuery};
    let d = tempfile::tempdir().unwrap();
    let id = Spec::new(1, "Plain Title GRP", 10, Some(1), 8010)
        .insert_into(store)
        .await;
    let sha = crate::testkit::sha(1);
    assert_eq!(
        store
            .attach_watch_nfo(id, &sha, b"zqxnfoonlyword greetings Plain", 1_700_000_000)
            .await
            .unwrap(),
        NfoAttach::Attached
    );
    let index = crate::testing::SettlingIndex::open(store, d.path()).await;
    index.settle().await.unwrap();
    let q = |text: &str| SearchQuery {
        q: Some(text.to_owned()),
        limit: 10,
        ..SearchQuery::default()
    };
    let hit = index.search(&q("Title")).await.unwrap();
    assert_eq!(hit.items.iter().map(|r| r.id).collect::<Vec<_>>(), [id]);
    for word in ["zqxnfoonlyword", "greetings"] {
        let miss = index.search(&q(word)).await.unwrap();
        assert_eq!(miss.total, 0, "{word}");
        assert!(miss.items.is_empty(), "{word}");
    }
}

macro_rules! store_suite {
    ($open:path; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread")]
            async fn $name() {
                let o = $open().await;
                super::$name(&o.store).await;
            }
        )*
    };
}

macro_rules! both {
    ($($name:ident),* $(,)?) => {
        mod sqlite {
            store_suite!(super::open_sqlite; $($name),*);
        }
        mod postgres {
            store_suite!(super::open_postgres; $($name),*);
        }
    };
}

both!(
    indexer_follows_the_database,
    a_lost_apply_shows_as_a_stale_document,
    crash_at_every_step_keeps_index_and_database_consistent,
    sec_091_rebuild_loses_no_change_committed_during_the_scan,
    sec_095_indexer_batch_memory_is_bounded,
    hydrator_rechecks_existence_and_category,
    degraded_browse_reads_the_store,
    t142_nfo_text_is_never_searchable,
);
