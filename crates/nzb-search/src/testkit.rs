//! Test helpers: a 2.x SQLite [`SqliteDb`] as the source of truth (hydrator + mirror into a Tantivy engine),
//! deterministic corpora, in-memory engines.
#![allow(
    clippy::type_complexity,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_arguments,
    clippy::assert_is_empty,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cloned_ref_to_slice_refs,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::manual_is_multiple_of,
    clippy::some_filter,
    clippy::uninlined_format_args,
    clippy::unused_async_trait_impl
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use nzb_core::{Analysis, FileInfo, FileKind, ReleaseFlags, Sha256, Taxonomy};
use nzb_store::{
    CategorySource, DbConfig, NewRelease, ReleaseRow, SceneColumns, SqliteDb, StoreError,
};

use crate::clock::{Clock, SystemClock};
use crate::config::SearchConfig;
use crate::doc::IndexDoc;
use crate::engine::{Engine, Payload};
use crate::index::{Hydrator, SearchService, TantivyIndex};

pub(crate) const EPOCH: [u8; 16] = [7; 16];

pub(crate) async fn open_db() -> (tempfile::TempDir, SqliteDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    (dir, db)
}

pub(crate) fn sha(n: u32) -> Sha256 {
    let mut b = [0x5a; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    Sha256(b)
}

fn file(idx: u32, name: &str) -> FileInfo {
    FileInfo {
        idx,
        subject: format!("subject {name}"),
        filename: Some(name.to_owned()),
        kind: FileKind::Video,
        poster: None,
        posted_at: Some(100),
        bytes: 10,
        segment_count: 3,
        declared_segments: Some(3),
        missing_ranges: vec![],
        missing_truncated: false,
        par2_blocks: None,
        groups: vec!["alt.binaries.test".into()],
    }
}

/// A release for the corpus.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    pub n: u32,
    pub title: String,
    pub files: Vec<String>,
    pub poster: Option<String>,
    pub bytes: u64,
    pub posted: Option<i64>,
    pub cat: u32,
    pub flags: ReleaseFlags,
    pub scene: SceneColumns,
    pub label: Option<String>,
}

impl Spec {
    pub fn new(n: u32, title: &str, bytes: u64, posted: Option<i64>, cat: u32) -> Self {
        Self {
            n,
            title: title.to_owned(),
            files: vec![format!("{title}.mkv")],
            poster: Some("poster <p@x>".into()),
            bytes,
            posted,
            cat,
            flags: ReleaseFlags::EMPTY,
            scene: SceneColumns::default(),
            label: None,
        }
    }

    pub fn analysis(&self) -> Analysis {
        Analysis {
            sha256: sha(self.n),
            name_candidates: vec![],
            meta_name_candidates: 0,
            title: self.title.clone(),
            poster: self.poster.clone(),
            posted_at: self.posted,
            total_bytes: self.bytes,
            file_count: u32::try_from(self.files.len()).unwrap(),
            segment_count: 3,
            duplicate_segments: 0,
            par2_blocks: 0,
            flags: self.flags,
            meta_category: None,
            repairable_estimate: None,
            files: self
                .files
                .iter()
                .enumerate()
                .map(|(i, f)| file(u32::try_from(i).unwrap(), f))
                .collect(),
        }
    }

    pub async fn insert(&self, db: &SqliteDb) -> i64 {
        self.insert_into(db).await
    }

    /// Inserts through the storage seam (either backend).
    pub async fn insert_into<S: nzb_store::FixtureRepo>(&self, db: &S) -> i64 {
        let a = self.analysis();
        db.insert_release(&NewRelease {
            analysis: &a,
            nzb_size_bytes: 1234,
            source_name: Some("orig.nzb"),
            source_label: self.label.as_deref(),
            category_id: self.cat,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: self.scene.clone(),
            ingested_at: 1_700_000_000,
        })
        .await
        .unwrap()
    }
}

/// `(id, title, bytes, posted, category)`, the 2.x conformance row shape.
pub(crate) type Row = (i64, String, u64, Option<i64>, u32);

/// The 2.x `seed_ordered` corpus: ties in every sort key, undated rows, several categories.
pub(crate) async fn seed_ordered(db: &SqliteDb) -> Vec<Row> {
    let mut rows = Vec::new();
    for n in 1..=60u32 {
        let title = format!("{} rel{:02}", if n % 3 == 0 { "b" } else { "A" }, n % 11);
        let bytes = u64::from(n % 5) * 100;
        let posted = (n % 7 != 0).then_some(1000 + i64::from(n % 9));
        let cat = [8010u32, 5040, 5030, 2040][usize::try_from(n % 4).unwrap()];
        let id = Spec::new(n, &title, bytes, posted, cat).insert(db).await;
        rows.push((id, title, bytes, posted, cat));
    }
    rows
}

/// Hydrates from a 2.x [`SqliteDb`] (one `get_release` per id: fine for tests); reindex requests go to an
/// in-memory queue that [`settle`] drains (the 2.x schema has no outbox).
#[derive(Clone)]
pub(crate) struct DbHydrator(pub SqliteDb, pub Arc<std::sync::Mutex<BTreeSet<i64>>>);

impl Hydrator for DbHydrator {
    async fn hydrate(&self, ids: &[i64], _exclude: &[u32]) -> Result<Vec<ReleaseRow>, StoreError> {
        let mut out = Vec::new();
        for id in ids {
            if let Some(r) = self.0.get_release(*id).await? {
                out.push(r);
            }
        }
        Ok(out)
    }

    async fn enqueue_reindex(&self, ids: &[i64]) -> Result<(), StoreError> {
        self.1.lock().unwrap().extend(ids);
        Ok(())
    }
}

pub(crate) async fn file_names(db: &SqliteDb, id: i64) -> String {
    let files = db.list_files(id).await.unwrap();
    files
        .iter()
        .filter_map(|f| f.filename.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn parent_of(category: u32) -> u32 {
    let tax = Taxonomy::builtin().unwrap();
    u16::try_from(category)
        .ok()
        .and_then(|c| tax.get(c))
        .and_then(|c| c.parent)
        .map_or(category, u32::from)
}

/// The current document of `id` in `db`, as the v3 source would load it.
pub(crate) async fn load_doc(db: &SqliteDb, id: i64) -> Option<IndexDoc> {
    let row = db.get_release(id).await.unwrap()?;
    let files = file_names(db, id).await;
    Some(IndexDoc::from_row(
        &row,
        parent_of(row.category_id),
        &files,
        1,
        None,
    ))
}

pub(crate) async fn db_ids(db: &SqliteDb) -> BTreeSet<i64> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM release")
        .fetch_all(db.readers())
        .await
        .unwrap();
    ids.into_iter().collect()
}

/// Brings `engine` in line with the database by id set (adds missing releases, drops vanished ones)
/// and re-indexes the queued reindex requests. This models "after one indexer cycle" for the 2.x
/// write path, which has no outbox.
pub(crate) async fn settle(h: &DbHydrator, engine: &Engine) {
    let db = &h.0;
    let queued: Vec<i64> = std::mem::take(&mut *h.1.lock().unwrap())
        .into_iter()
        .collect();
    let want = db_ids(db).await;
    let have: BTreeSet<i64> = engine
        .live_versions()
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let mut docs = Vec::new();
    for id in want.difference(&have) {
        if let Some(d) = load_doc(db, *id).await {
            docs.push(d);
        }
    }
    let mut gone: Vec<i64> = have.difference(&want).copied().collect();
    for id in queued {
        match load_doc(db, id).await {
            Some(d) => docs.push(d),
            None => gone.push(id),
        }
    }
    if docs.is_empty() && gone.is_empty() {
        return;
    }
    assert!(engine.apply(&docs, &gone).unwrap().is_empty());
    engine.commit(&engine.payload()).unwrap();
    // What the indexer does after its commits: the walk path stays available.
    engine.warm_sidecars().unwrap();
}

/// A service serving a fresh in-memory generation.
pub(crate) fn mem_service(
    cfg: SearchConfig,
    clock: Arc<dyn Clock>,
) -> (Arc<SearchService>, Arc<Engine>) {
    let svc = SearchService::new(cfg, clock);
    let engine = Arc::new(Engine::in_ram(Payload::new(EPOCH)).unwrap());
    svc.install(Arc::clone(&engine));
    (svc, engine)
}

/// A Tantivy index over `db` (in-memory generation), already settled.
pub(crate) async fn tantivy_over(
    db: &SqliteDb,
) -> (TantivyIndex<DbHydrator>, Arc<Engine>, DbHydrator) {
    let (svc, engine) = mem_service(SearchConfig::default(), Arc::new(SystemClock::new()));
    let h = DbHydrator(db.clone(), Arc::default());
    settle(&h, &engine).await;
    (TantivyIndex::new(svc, h.clone()), engine, h)
}

/// A document with defaults (category 8010, dated, 100 bytes).
pub(crate) fn doc(id: i64, title: &str) -> IndexDoc {
    IndexDoc {
        id,
        version: 1,
        title: title.to_owned(),
        files: String::new(),
        poster: String::new(),
        source_name: String::new(),
        category_id: 8010,
        category_parent: 8000,
        posted_at: Some(1_000 + id),
        ingested_at: 1_700_000_000,
        total_bytes: 100,
        flags: ReleaseFlags::EMPTY,
        family: None,
        resolution: None,
        source: None,
        year: None,
        group: None,
        season: None,
        episode: None,
        series_key: None,
        source_label: None,
        added_by: None,
    }
}

/// An in-memory engine with one segment per batch (a commit each).
pub(crate) fn engine_with(batches: &[Vec<IndexDoc>]) -> Engine {
    let e = Engine::in_ram(Payload::new(EPOCH)).unwrap();
    for b in batches {
        assert!(e.apply(b, &[]).unwrap().is_empty());
        e.commit(&e.payload()).unwrap();
    }
    e.warm_sidecars().unwrap();
    e
}

/// The row a hydrator returns for `d` (what Postgres would hold).
pub(crate) fn row_of(d: &IndexDoc) -> ReleaseRow {
    ReleaseRow {
        id: d.id,
        sha256: sha(u32::try_from(d.id).unwrap_or(0)),
        title: d.title.clone(),
        category_id: d.category_id,
        category_overridden: false,
        category_source: CategorySource::Fallback,
        posted_at: d.posted_at,
        ingested_at: d.ingested_at,
        total_bytes: d.total_bytes,
        poster: Some(d.poster.clone()).filter(|p| !p.is_empty()),
        file_count: 1,
        segment_count: 1,
        missing_segment_count: 0,
        par2_blocks: 0,
        flags: d.flags,
        nzb_size_bytes: 1,
        source_name: None,
        source_label: d.source_label.clone(),
        origin: None,
        meta_json: None,
        scene: SceneColumns::default(),
    }
}

/// An in-memory source of truth for hydration.
#[derive(Clone, Default)]
pub(crate) struct MemHydrator(
    pub Arc<std::sync::Mutex<std::collections::HashMap<i64, ReleaseRow>>>,
    /// Reindex requests received.
    pub Arc<std::sync::Mutex<Vec<i64>>>,
);

impl MemHydrator {
    pub fn with(docs: &[IndexDoc]) -> Self {
        let h = Self::default();
        for d in docs {
            h.put(row_of(d));
        }
        h
    }

    pub fn put(&self, r: ReleaseRow) {
        self.0.lock().unwrap().insert(r.id, r);
    }

    pub fn remove(&self, id: i64) {
        self.0.lock().unwrap().remove(&id);
    }
}

impl Hydrator for MemHydrator {
    async fn hydrate(&self, ids: &[i64], exclude: &[u32]) -> Result<Vec<ReleaseRow>, StoreError> {
        // Like T112's PgDb::hydrate: index order kept, gone and excluded rows dropped.
        let m = self.0.lock().unwrap();
        Ok(ids
            .iter()
            .filter_map(|id| m.get(id).cloned())
            .filter(|r| !exclude.contains(&r.category_id))
            .collect())
    }

    async fn enqueue_reindex(&self, ids: &[i64]) -> Result<(), StoreError> {
        self.1.lock().unwrap().extend(ids);
        Ok(())
    }
}

/// A service + index over `batches` (one segment each), hydrating from the same documents.
pub(crate) fn mem_index(
    cfg: SearchConfig,
    clock: Arc<dyn Clock>,
    batches: &[Vec<IndexDoc>],
) -> (TantivyIndex<MemHydrator>, MemHydrator, Arc<Engine>) {
    let svc = SearchService::new(cfg, clock);
    let engine = Arc::new(engine_with(batches));
    svc.install(Arc::clone(&engine));
    let all: Vec<IndexDoc> = batches.iter().flatten().cloned().collect();
    let h = MemHydrator::with(&all);
    (TantivyIndex::new(svc, h.clone()), h, engine)
}

/// Text bytes of a document (title + poster + file names).
pub(crate) fn doc_text_bytes(d: &IndexDoc) -> usize {
    d.title.len()
        + d.poster.len()
        + d.source_name.len()
        + d.group.as_deref().map_or(0, |g| g.len() + 1)
        + d.files.len()
}

/// The `search_*` tables and `release` rows of a database, in memory (each method is one
/// "transaction": it runs under the lock).
#[derive(Default)]
pub(crate) struct MemDb {
    pub rows: std::collections::BTreeMap<i64, IndexDoc>,
    pub outbox: std::collections::BTreeMap<i64, i64>,
    pub last_seq: i64,
    pub epoch: [u8; 16],
    pub replay: bool,
    pub replay_ids: BTreeSet<i64>,
    pub quarantine: std::collections::BTreeMap<i64, &'static str>,
    pub rebuild_requested: bool,
    pub finished_generation: u64,
    /// Releases whose document cannot be built (loaded with version 0).
    pub poison: BTreeSet<i64>,
    /// Runs at every scan call (models writes committed concurrently with a rebuild scan).
    pub scan_hook: Option<Box<dyn FnMut(&mut MemDb, i64) + Send>>,
    pub scan_calls: Vec<i64>,
    /// `(ids asked, text bytes returned)` of every `load` call.
    pub load_calls: Vec<(usize, usize)>,
    /// Loading a chunk containing this id fails with a store timeout (zero returned bytes).
    pub load_error_for: Option<i64>,
    /// Text bytes returned by every `scan` call.
    pub scan_bytes: Vec<usize>,
}

impl MemDb {
    /// A write transaction on release `id`: row replaced (version bumped) + one outbox row.
    pub fn upsert(&mut self, id: i64, title: &str) {
        let version = self.rows.get(&id).map_or(1, |d| d.version + 1);
        let mut d = doc(id, title);
        d.version = version;
        self.rows.insert(id, d);
        self.enqueue(id);
    }

    /// A delete (trash) transaction: row removed + one outbox row.
    pub fn delete(&mut self, id: i64) {
        self.rows.remove(&id);
        self.enqueue(id);
    }

    /// An outbox row only (reconciliation, duplicates).
    pub fn enqueue(&mut self, id: i64) {
        self.last_seq += 1;
        self.outbox.insert(self.last_seq, id);
    }

    /// `(id, version)` the index must hold: every row except quarantined ones.
    pub fn expected(&self) -> Vec<(i64, u64)> {
        self.rows
            .values()
            .filter(|d| !self.quarantine.contains_key(&d.id))
            .map(|d| (d.id, d.version))
            .collect()
    }

    /// The source's size contract (review 32 M2): file names cut at `MAX_FILES_BYTES` while loading,
    /// as the SQL of a real source does.
    fn load_one(&self, id: i64) -> Option<IndexDoc> {
        let mut d = self.rows.get(&id)?.clone();
        let keep = crate::analyzer::cap_bytes(&d.files, crate::analyzer::MAX_FILES_BYTES).len();
        d.files.truncate(keep);
        if self.poison.contains(&id) {
            d.version = 0;
        }
        Some(d)
    }
}

#[derive(Clone, Default)]
pub(crate) struct MemSource(pub Arc<std::sync::Mutex<MemDb>>);

impl MemSource {
    pub fn with(epoch: [u8; 16]) -> Self {
        let s = Self::default();
        s.db().epoch = epoch;
        s
    }

    pub fn db(&self) -> std::sync::MutexGuard<'_, MemDb> {
        self.0.lock().unwrap()
    }
}

impl crate::indexer::IndexSource for MemSource {
    async fn read_outbox(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::indexer::OutboxRow>, crate::SearchError> {
        Ok(self
            .db()
            .outbox
            .iter()
            .take(limit)
            .map(|(seq, id)| crate::indexer::OutboxRow {
                seq: *seq,
                release_id: *id,
            })
            .collect())
    }

    async fn load(&self, ids: &[i64]) -> Result<Vec<IndexDoc>, crate::SearchError> {
        let mut db = self.db();
        if db.load_error_for.is_some_and(|id| ids.contains(&id)) {
            db.load_calls.push((ids.len(), 0));
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "injected source timeout",
            ))
            .into());
        }
        let docs: Vec<IndexDoc> = ids.iter().filter_map(|id| db.load_one(*id)).collect();
        let bytes = docs.iter().map(doc_text_bytes).sum();
        db.load_calls.push((ids.len(), bytes));
        Ok(docs)
    }

    async fn consume(&self, rows: &[crate::indexer::OutboxRow]) -> Result<(), crate::SearchError> {
        let mut db = self.db();
        for r in rows {
            db.outbox.remove(&r.seq);
        }
        if db.replay {
            db.replay_ids.extend(rows.iter().map(|r| r.release_id));
        }
        Ok(())
    }

    async fn quarantine(
        &self,
        release_id: i64,
        code: &'static str,
    ) -> Result<(), crate::SearchError> {
        self.db().quarantine.entry(release_id).or_insert(code);
        Ok(())
    }

    async fn state(&self) -> Result<crate::indexer::SourceState, crate::SearchError> {
        let db = self.db();
        Ok(crate::indexer::SourceState {
            epoch: db.epoch,
            outbox_last_seq: db.last_seq,
            replay: db.replay,
            rebuild_requested: db.rebuild_requested,
            finished_generation: db.finished_generation,
        })
    }

    async fn begin_rebuild(&self) -> Result<(), crate::SearchError> {
        self.db().replay = true;
        Ok(())
    }

    async fn scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<IndexDoc>, crate::SearchError> {
        let mut db = self.db();
        db.scan_calls.push(after_id);
        if let Some(mut hook) = db.scan_hook.take() {
            hook(&mut db, after_id);
            db.scan_hook = Some(hook);
        }
        let ids: Vec<i64> = db
            .rows
            .range(after_id.saturating_add(1)..)
            .take(limit)
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for id in ids {
            if !out.is_empty() && bytes >= max_bytes {
                break;
            }
            if let Some(d) = db.load_one(id) {
                bytes += doc_text_bytes(&d);
                out.push(d);
            }
        }
        db.scan_bytes.push(bytes);
        Ok(out)
    }

    async fn replay_ids(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<i64>, crate::SearchError> {
        Ok(self
            .db()
            .replay_ids
            .range(after_id.saturating_add(1)..)
            .take(limit)
            .copied()
            .collect())
    }

    async fn finish_rebuild(&self, generation: u64) -> Result<(), crate::SearchError> {
        let mut db = self.db();
        db.replay = false;
        db.rebuild_requested = false;
        db.finished_generation = generation;
        db.replay_ids.clear();
        Ok(())
    }
}
