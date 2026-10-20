//! One opened index generation: Tantivy index + reader + the single writer, and the commit payload
//! that binds it to a database (ARCHITECTURE v3 3.2-3.3, SEC-091).
//!
//! Layout of `search.index_dir` (from config only, never derived from input; 0700):
//! ```text
//! index_dir/CURRENT        decimal generation number + "\n" (tmp + fsync + rename + dir fsync)
//! index_dir/gen-<n>/       Tantivy files of generation n
//! ```
//! Payload of every commit: `{"v":1,"epoch":"<32 hex>","schema":<INDEX_SCHEMA_VERSION>,"max_seq":<n>}`,
//! plus `"scan_upto_id"` while a rebuild generation is being filled. An index whose payload is missing,
//! unreadable, of another epoch or schema, or ahead of the database's outbox sequence is never served.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tantivy::index::SegmentId;
use tantivy::indexer::IndexWriterOptions;
use tantivy::merge_policy::LogMergePolicy;
use tantivy::schema::Schema;
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Searcher, SegmentReader, Term};

use crate::analyzer::{SCENE_ANALYZER, scene_analyzer};
use crate::collect::Columns;
use crate::config::SearchConfig;
use crate::doc::{DocError, IndexDoc};
use crate::error::SearchError;
use crate::schema::{self, Fields, INDEX_SCHEMA_VERSION};
use crate::sidecar::{self, Family, Perm};

/// Test hook: documents whose `add` breaks the writer (ids are unique to the tests that use them).
#[cfg(test)]
pub(crate) static FAIL_ON: Mutex<std::collections::BTreeSet<i64>> =
    Mutex::new(std::collections::BTreeSet::new());

/// Per-segment cache slot: built once, shared by concurrent searches.
type Slot<T> = Arc<OnceLock<Arc<T>>>;
/// Alive documents per `(category, parent category)` of one segment version.
pub(crate) type Histogram = BTreeMap<(u32, u32), u64>;
/// Histograms by segment and delete opstamp (a new delete makes a new entry).
type HistogramCache = HashMap<(SegmentId, Option<u64>), Slot<Histogram>>;

/// Payload format version.
const PAYLOAD_V: u64 = 1;
/// Longest payload accepted (it is ours, but the file is on disk: bound the parse).
const MAX_PAYLOAD_BYTES: usize = 1024;
/// Tantivy's minimum indexing arena per thread (about 15 MB).
const MIN_HEAP_PER_THREAD: usize = 15_000_000;
/// Doc-store cache blocks of the search readers: 0, so tantivy never constructs its `LruCache` for a
/// searcher (`NonZeroUsize::new(0)` is `None`). There are no stored fields to cache (review 32 L1; the
/// RUSTSEC-2026-0253 lru fix arrived with tantivy 0.27, T143, but there is still nothing to cache).
pub const DOC_STORE_CACHE_BLOCKS: usize = 0;

/// Name of the file naming the active generation.
pub const CURRENT_FILE: &str = "CURRENT";
/// Marker file written into every generation directory nzbd creates, before any index file. Only a directory that
/// carries it is ever removed: `search.index_dir` is operator-configured, and a `gen-<n>` directory that nzbd did not
/// make (for example user files after a misconfiguration) must never be deleted (review 39 L1).
pub const GENERATION_MARKER: &str = "NZBD_GENERATION";

/// What a commit records about the database it reflects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    /// `search_state.epoch` of the database the index was built from (rotated by restores).
    pub epoch: [u8; 16],
    /// Index schema version of the binary that wrote it.
    pub schema: u32,
    /// Highest outbox `seq` applied (review M2 a: an index ahead of the database is not served).
    pub max_seq: i64,
    /// While a rebuild generation is being filled: every release id `<=` this is in it.
    pub scan_upto_id: Option<i64>,
}

impl Payload {
    /// A payload for a new, empty generation of `epoch`.
    #[must_use]
    pub const fn new(epoch: [u8; 16]) -> Self {
        Self {
            epoch,
            schema: INDEX_SCHEMA_VERSION,
            max_seq: 0,
            scan_upto_id: None,
        }
    }

    /// JSON text stored with the commit.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut epoch = String::with_capacity(32);
        for b in self.epoch {
            let _ = std::fmt::Write::write_fmt(&mut epoch, format_args!("{b:02x}"));
        }
        let mut v = serde_json::json!({
            "v": PAYLOAD_V,
            "epoch": epoch,
            "schema": self.schema,
            "max_seq": self.max_seq,
        });
        if let (Some(id), Some(obj)) = (self.scan_upto_id, v.as_object_mut()) {
            obj.insert("scan_upto_id".to_owned(), serde_json::Value::from(id));
        }
        v.to_string()
    }

    /// Strict parse of [`Payload::encode`]'s output.
    ///
    /// # Errors
    /// [`SearchError::NotServable`] for anything else.
    pub fn decode(s: &str) -> Result<Self, SearchError> {
        const BAD: SearchError = SearchError::NotServable("payload unreadable");
        if s.len() > MAX_PAYLOAD_BYTES {
            return Err(BAD);
        }
        let v: serde_json::Value = serde_json::from_str(s).map_err(|_| BAD)?;
        let obj = v.as_object().ok_or(BAD)?;
        if obj.get("v").and_then(serde_json::Value::as_u64) != Some(PAYLOAD_V) {
            return Err(BAD);
        }
        for k in obj.keys() {
            if !matches!(
                k.as_str(),
                "v" | "epoch" | "schema" | "max_seq" | "scan_upto_id"
            ) {
                return Err(BAD);
            }
        }
        let hex = obj
            .get("epoch")
            .and_then(serde_json::Value::as_str)
            .ok_or(BAD)?;
        let epoch = parse_epoch(hex).ok_or(BAD)?;
        let schema = obj
            .get("schema")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(BAD)?;
        let max_seq = obj
            .get("max_seq")
            .and_then(serde_json::Value::as_i64)
            .ok_or(BAD)?;
        let scan_upto_id = match obj.get("scan_upto_id") {
            None => None,
            Some(x) => Some(x.as_i64().ok_or(BAD)?),
        };
        if max_seq < 0 {
            return Err(BAD);
        }
        Ok(Self {
            epoch,
            schema,
            max_seq,
            scan_upto_id,
        })
    }
}

fn parse_epoch(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        let pair = hex.get(at..at.checked_add(2)?)?;
        if !pair
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Why an index must not be served, given the database's current state.
///
/// # Errors
/// [`SearchError::NotServable`] with the reason.
pub fn check_servable(
    p: &Payload,
    db_epoch: [u8; 16],
    db_outbox_last_seq: i64,
) -> Result<(), SearchError> {
    if p.epoch != db_epoch {
        return Err(SearchError::NotServable("epoch mismatch"));
    }
    if p.schema != INDEX_SCHEMA_VERSION {
        return Err(SearchError::NotServable("schema version mismatch"));
    }
    if p.max_seq > db_outbox_last_seq {
        // The index has seen outbox rows this database never wrote: a restore nzbd did not perform.
        return Err(SearchError::NotServable("index ahead of the database"));
    }
    if p.scan_upto_id.is_some() {
        return Err(SearchError::NotServable("rebuild generation incomplete"));
    }
    Ok(())
}

/// The generation directory layout under `search.index_dir`.
#[derive(Debug, Clone)]
pub struct IndexDir {
    root: PathBuf,
}

impl IndexDir {
    /// `root` from config (`search.index_dir`); created 0700 when missing.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(root: &Path) -> Result<Self, SearchError> {
        create_private_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// `root` for read-only use (`nzbd search status|verify`): nothing is created and no mode is changed; a missing
    /// directory simply has no generation (review 39 L1).
    #[must_use]
    pub fn read_only(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory of generation `n`.
    #[must_use]
    pub fn generation(&self, n: u64) -> PathBuf {
        self.root.join(format!("gen-{n}"))
    }

    /// The active generation, `None` when there is none (or the file is unreadable: rebuild).
    #[must_use]
    pub fn current(&self) -> Option<u64> {
        // At most 21 bytes are read: a decimal u64 and a newline (a bigger file is invalid anyway).
        let mut text = String::new();
        let f = fs::File::open(self.root.join(CURRENT_FILE)).ok()?;
        std::io::Read::read_to_string(&mut std::io::Read::take(f, 21), &mut text).ok()?;
        let digits = text.strip_suffix('\n')?;
        if digits.is_empty() || digits.len() > 19 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    }

    /// Makes generation `n` the active one (tmp + fsync + rename + directory fsync).
    ///
    /// # Errors
    /// I/O errors.
    pub fn set_current(&self, n: u64) -> Result<(), SearchError> {
        let tmp = self.root.join(".CURRENT.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(format!("{n}\n").as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.root.join(CURRENT_FILE))?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    /// Generation numbers present on disk, ascending (directories named `gen-<n>` only).
    ///
    /// # Errors
    /// I/O errors.
    pub fn generations(&self) -> Result<Vec<u64>, SearchError> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.root)? {
            let e = e?;
            if !e.file_type()?.is_dir() {
                continue;
            }
            let name = e.file_name();
            let Some(n) = name.to_str().and_then(|s| s.strip_prefix("gen-")) else {
                continue;
            };
            if !n.is_empty()
                && n.len() <= 19
                && n.bytes().all(|b| b.is_ascii_digit())
                && let Ok(n) = n.parse::<u64>()
            {
                out.push(n);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Removes generation `n` (derived data, never a user NZB). A `gen-<n>` directory without the
    /// [`GENERATION_MARKER`] (or a symbolic link) is not nzbd's and is left alone.
    ///
    /// # Errors
    /// I/O errors other than "already gone".
    pub fn remove(&self, n: u64) -> Result<(), SearchError> {
        let dir = self.generation(n);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        match fs::symlink_metadata(dir.join(GENERATION_MARKER)) {
            Ok(m) if m.is_file() => {}
            _ => return Ok(()),
        }
        match fs::remove_dir_all(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

fn create_private_dir(p: &Path) -> Result<(), SearchError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !p.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(p)?;
        }
        let meta = fs::symlink_metadata(p)?;
        if !meta.is_dir() {
            return Err(SearchError::NotServable("index path is not a directory"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(p)?;
    Ok(())
}

/// Writer settings of an engine.
#[derive(Debug, Clone, Copy)]
pub struct WriterSettings {
    /// Total indexing heap, bytes.
    pub heap_bytes: usize,
    /// Indexing threads.
    pub threads: usize,
}

impl WriterSettings {
    /// Steady-state writer of `cfg`.
    #[must_use]
    pub fn steady(cfg: &SearchConfig) -> Self {
        Self {
            heap_bytes: cfg.writer_heap_mib.saturating_mul(1 << 20),
            threads: cfg.writer_threads,
        }
    }

    /// Rebuild writer of `cfg` (bigger heap, `max(2, cores / 2)` threads).
    #[must_use]
    pub fn rebuild(cfg: &SearchConfig) -> Self {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        Self {
            heap_bytes: cfg.rebuild_heap_mib.saturating_mul(1 << 20),
            threads: (cores / 2).max(2),
        }
    }
}

/// One open generation.
pub struct Engine {
    index: Index,
    fields: Fields,
    reader: IndexReader,
    writer: Mutex<Option<IndexWriter>>,
    writer_settings: WriterSettings,
    payload: Mutex<Payload>,
    /// Generation directory (`None` in RAM): where sidecars live.
    path: Option<PathBuf>,
    sidecars: Mutex<HashMap<(SegmentId, Family), Slot<Perm>>>,
    histograms: Mutex<HistogramCache>,
    /// Sidecars loaded or built by this engine (only `warm_sidecars` does it; tests and metrics).
    sidecar_loads: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// Creates a new, empty generation in `dir` (must not exist yet) and commits `payload` to it.
    ///
    /// # Errors
    /// I/O and engine errors.
    pub fn create(dir: &Path, payload: Payload, ws: WriterSettings) -> Result<Self, SearchError> {
        create_private_dir(dir)?;
        // First file of the generation: marks the directory as nzbd's so that `IndexDir::remove` may delete it.
        fs::File::create(dir.join(GENERATION_MARKER))?.sync_all()?;
        let (schema, fields) = schema::build();
        let index = Index::create_in_dir(dir, schema)?;
        let e = Self::from_index(index, fields, payload, ws, Some(dir))?;
        e.commit(&payload)?;
        Ok(e)
    }

    /// Opens generation `dir` and reads its payload.
    ///
    /// # Errors
    /// [`SearchError::NotServable`] when the files do not open, the schema differs from this binary's
    /// or the payload is missing/unreadable.
    pub fn open(dir: &Path, ws: WriterSettings) -> Result<Self, SearchError> {
        let index =
            Index::open_in_dir(dir).map_err(|_| SearchError::NotServable("index does not open"))?;
        let (schema, fields) = schema::build();
        if !same_schema(&index.schema(), &schema) {
            return Err(SearchError::NotServable("schema version mismatch"));
        }
        let meta = index
            .load_metas()
            .map_err(|_| SearchError::NotServable("index does not open"))?;
        let payload = Payload::decode(meta.payload.as_deref().unwrap_or(""))?;
        Self::from_index(index, fields, payload, ws, Some(dir))
    }

    /// An in-memory generation (tests, fuzzing).
    ///
    /// # Errors
    /// Engine errors.
    pub fn in_ram(payload: Payload) -> Result<Self, SearchError> {
        let (schema, fields) = schema::build();
        let index = Index::create_in_ram(schema);
        let ws = WriterSettings {
            heap_bytes: 32 << 20,
            threads: 1,
        };
        let e = Self::from_index(index, fields, payload, ws, None)?;
        e.commit(&payload)?;
        Ok(e)
    }

    fn from_index(
        index: Index,
        fields: Fields,
        payload: Payload,
        ws: WriterSettings,
        path: Option<&Path>,
    ) -> Result<Self, SearchError> {
        index
            .tokenizers()
            .register(SCENE_ANALYZER, scene_analyzer());
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .doc_store_cache_num_blocks(DOC_STORE_CACHE_BLOCKS)
            .try_into()?;
        let writer = open_writer(&index, ws)?;
        Ok(Self {
            index,
            fields,
            reader,
            writer: Mutex::new(Some(writer)),
            writer_settings: ws,
            payload: Mutex::new(payload),
            path: path.map(Path::to_path_buf),
            sidecars: Mutex::new(HashMap::new()),
            histograms: Mutex::new(HashMap::new()),
            sidecar_loads: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Field handles.
    #[must_use]
    pub const fn fields(&self) -> &Fields {
        &self.fields
    }

    /// A searcher on the last reloaded commit.
    #[must_use]
    pub fn searcher(&self) -> Searcher {
        self.reader.searcher()
    }

    /// The payload of the last commit.
    #[must_use]
    pub fn payload(&self) -> Payload {
        *lock(&self.payload)
    }

    /// The underlying index (segment metadata for sidecars and tests).
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Queues the removal of `deletes` and the replacement of `upserts` (each is `delete_term(id)` +
    /// `add_document`; Tantivy orders by opstamp, so only the older copy goes). Nothing is visible
    /// before [`Engine::commit`]. Returns the ids whose document could not be built.
    ///
    /// # Errors
    /// [`SearchError::WriterUnavailable`] / engine errors: the writer is then dropped and must be
    /// reopened ([`Engine::reopen_writer`]); uncommitted work is lost (it is still in the outbox).
    pub fn apply(
        &self,
        upserts: &[IndexDoc],
        deletes: &[i64],
    ) -> Result<Vec<(i64, DocError)>, SearchError> {
        let mut guard = lock(&self.writer);
        let Some(w) = guard.as_mut() else {
            return Err(SearchError::WriterUnavailable);
        };
        #[cfg(test)]
        if upserts.iter().any(|d| lock(&FAIL_ON).contains(&d.id)) {
            // A document that breaks the writer (review 32 L4): the writer and its pending work go.
            *guard = None;
            return Err(SearchError::WriterUnavailable);
        }
        let mut failed = Vec::new();
        let result = (|| -> Result<(), SearchError> {
            for id in deletes {
                w.delete_term(Term::from_field_i64(self.fields.id, *id));
            }
            for d in upserts {
                w.delete_term(Term::from_field_i64(self.fields.id, d.id));
                match d.to_document(&self.fields) {
                    Ok(doc) => {
                        w.add_document(doc)?;
                    }
                    Err(e) => failed.push((d.id, e)),
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            *guard = None;
            return Err(e);
        }
        Ok(failed)
    }

    /// Commits everything queued with `payload`, then reloads the reader.
    ///
    /// # Errors
    /// As [`Engine::apply`].
    pub fn commit(&self, payload: &Payload) -> Result<(), SearchError> {
        let mut guard = lock(&self.writer);
        let Some(w) = guard.as_mut() else {
            return Err(SearchError::WriterUnavailable);
        };
        // `max_seq` never goes down: a reconciliation commit that read the payload before an indexer
        // commit must not hide outbox rows already applied (the M2 a check relies on it).
        let mut payload = *payload;
        payload.max_seq = payload.max_seq.max(lock(&self.payload).max_seq);
        let payload = &payload;
        let text = payload.encode();
        let r = (|| -> Result<(), SearchError> {
            let mut pc = w.prepare_commit()?;
            pc.set_payload(&text);
            pc.commit()?;
            Ok(())
        })();
        if let Err(e) = r {
            *guard = None;
            return Err(e);
        }
        drop(guard);
        *lock(&self.payload) = *payload;
        self.reader.reload()?;
        // Sidecars of merged-away segments (review L6 b); a failure only leaves files for next time.
        let _ = self.gc_sidecars();
        Ok(())
    }

    /// The sidecar of `seg` for `family` if it is already loaded; never builds or reads a file. This is
    /// the only lookup on the request path (review 32 M1): a missing sidecar makes the planner collect.
    pub(crate) fn sidecar_ready(&self, seg: &SegmentReader, family: Family) -> Option<Arc<Perm>> {
        lock(&self.sidecars)
            .get(&(seg.segment_id(), family))
            .and_then(|slot| slot.get().cloned())
    }

    /// Loads (validated) or builds the sidecar of `seg` for `family`. Off the request path only: the
    /// indexer after its commits and before a generation is installed (`warm_sidecars`).
    fn ensure_sidecar(&self, seg: &SegmentReader, cols: &Columns, family: Family) -> Arc<Perm> {
        let slot = Arc::clone(
            lock(&self.sidecars)
                .entry((seg.segment_id(), family))
                .or_default(),
        );
        Arc::clone(slot.get_or_init(|| {
            self.sidecar_loads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Arc::new(sidecar::load_or_build(
                self.path.as_deref(),
                seg,
                cols,
                family,
            ))
        }))
    }

    /// Loads or builds every sidecar of the current segments. Called by the indexer after each commit
    /// (new and merged segments) and before a generation is installed, never by a search; builds are
    /// serialized process-wide (`sidecar::load_or_build`).
    ///
    /// # Errors
    /// Engine errors reading fast fields.
    pub fn warm_sidecars(&self) -> Result<(), SearchError> {
        let searcher = self.searcher();
        for seg in searcher.segment_readers() {
            let cols = Columns::open(seg)?;
            for family in [Family::Date, Family::Size, Family::Title] {
                self.ensure_sidecar(seg, &cols, family);
            }
        }
        Ok(())
    }

    /// Sidecars this engine has loaded or built so far.
    #[must_use]
    pub fn sidecar_loads(&self) -> u64 {
        self.sidecar_loads
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Every sidecar of `family` is loaded for every segment of `searcher` (the walk may run).
    pub(crate) fn sidecars_ready(&self, searcher: &Searcher, family: Family) -> bool {
        searcher
            .segment_readers()
            .iter()
            .all(|seg| self.sidecar_ready(seg, family).is_some())
    }

    /// Alive documents per category of `seg` (cached per segment and delete opstamp).
    ///
    /// # Errors
    /// Engine errors reading the `cat` column.
    pub(crate) fn histogram(&self, seg: &SegmentReader) -> Result<Arc<Histogram>, SearchError> {
        let slot = Arc::clone(
            lock(&self.histograms)
                .entry((seg.segment_id(), seg.delete_opstamp()))
                .or_default(),
        );
        if let Some(h) = slot.get() {
            return Ok(Arc::clone(h));
        }
        let cat = seg.fast_fields().u64(schema::col::CAT)?;
        let parent = seg
            .fast_fields()
            .column_opt::<u64>(schema::col::CAT_PARENT)?;
        let to32 = |v: Option<u64>| v.and_then(|v| u32::try_from(v).ok());
        let mut h = Histogram::new();
        for doc in seg.doc_ids_alive() {
            if let Some(c) = to32(cat.first(doc)) {
                let p = parent
                    .as_ref()
                    .and_then(|p| to32(p.first(doc)))
                    .unwrap_or(c);
                let e = h.entry((c, p)).or_insert(0);
                *e = e.saturating_add(1);
            }
        }
        Ok(Arc::clone(slot.get_or_init(|| Arc::new(h))))
    }

    /// Drops cached sidecars/histograms of segments no longer in the index and deletes their files.
    ///
    /// # Errors
    /// I/O errors listing the generation directory; engine errors reading `meta.json`.
    pub fn gc_sidecars(&self) -> Result<usize, SearchError> {
        // The live set is the reloaded searcher's segments, not `meta.json`: a merge published after the
        // reload must not drop the sidecars of segments this reader still serves (review 32 I3).
        let live: HashSet<SegmentId> = self
            .searcher()
            .segment_readers()
            .iter()
            .map(SegmentReader::segment_id)
            .collect();
        lock(&self.sidecars).retain(|(s, _), _| live.contains(s));
        lock(&self.histograms).retain(|(s, _), _| live.contains(s));
        let Some(dir) = &self.path else { return Ok(0) };
        let names: HashSet<String> = live.iter().map(SegmentId::uuid_string).collect();
        sidecar::gc(dir, &names)
    }

    /// The generation directory (`None` in RAM).
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Drops pending (uncommitted) work and the writer (a poisoned writer after a panic), then opens a
    /// new writer on the last commit.
    ///
    /// # Errors
    /// Engine errors (e.g. the directory lock is held by another writer).
    pub fn reopen_writer(&self) -> Result<(), SearchError> {
        let mut guard = lock(&self.writer);
        // Dropping the old writer releases Tantivy's directory lock before the new one takes it.
        *guard = None;
        *guard = Some(open_writer(&self.index, self.writer_settings)?);
        Ok(())
    }

    /// Merges every segment into one and commits (tests: merged-away segments lose their sidecars).
    #[cfg(test)]
    pub(crate) fn merge_all(&self) -> Result<(), SearchError> {
        let ids = self.index.searchable_segment_ids()?;
        {
            let mut guard = lock(&self.writer);
            let w = guard.as_mut().ok_or(SearchError::WriterUnavailable)?;
            w.merge(&ids).wait()?;
        }
        self.commit(&self.payload())
    }

    /// Simulates a writer lost to a panic (fault injection in tests).
    #[cfg(test)]
    #[allow(dead_code)] // used by the indexer tests (next milestone)
    pub(crate) fn poison_writer(&self) {
        *lock(&self.writer) = None;
    }

    /// Whether a writer is open.
    #[must_use]
    pub fn has_writer(&self) -> bool {
        lock(&self.writer).is_some()
    }

    /// `(id, version)` of every live document, ascending id (verify, tests). O(documents).
    ///
    /// # Errors
    /// Engine errors.
    pub fn live_versions(&self) -> Result<Vec<(i64, u64)>, SearchError> {
        let searcher = self.searcher();
        let mut out = Vec::new();
        for seg in searcher.segment_readers() {
            let ids = seg.fast_fields().i64(schema::col::ID)?;
            let versions = seg.fast_fields().u64(schema::col::VERSION)?;
            for doc in seg.doc_ids_alive() {
                if let Some(id) = ids.first(doc) {
                    out.push((id, versions.first(doc).unwrap_or(0)));
                }
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Waits for background merges to finish and releases the writer (clean shutdown, tests).
    ///
    /// # Errors
    /// Engine errors.
    pub fn close(&self) -> Result<(), SearchError> {
        if let Some(w) = lock(&self.writer).take() {
            w.wait_merging_threads()?;
        }
        Ok(())
    }
}

fn open_writer(index: &Index, ws: WriterSettings) -> Result<IndexWriter, SearchError> {
    let threads = ws
        .threads
        .clamp(1, (ws.heap_bytes / MIN_HEAP_PER_THREAD).clamp(1, 8));
    let per_thread = (ws.heap_bytes / threads).max(MIN_HEAP_PER_THREAD);
    let w: IndexWriter = index.writer_with_options(
        IndexWriterOptions::builder()
            .num_worker_threads(threads)
            .memory_budget_per_thread(per_thread)
            .num_merge_threads(2)
            .build(),
    )?;
    let mut policy = LogMergePolicy::default();
    policy.set_min_num_segments(8);
    policy.set_max_docs_before_merge(10_000_000);
    policy.set_del_docs_ratio_before_merge(0.2);
    w.set_merge_policy(Box::new(policy));
    Ok(w)
}

fn same_schema(a: &Schema, b: &Schema) -> bool {
    let fa: Vec<_> = a.fields().map(|(_, e)| e.clone()).collect();
    let fb: Vec<_> = b.fields().map(|(_, e)| e.clone()).collect();
    fa == fb
}

/// Locks a mutex, recovering from poisoning (a panic while holding it): the protected state is a
/// writer handle or a payload copy, both of which stay valid or are reset by the caller.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
