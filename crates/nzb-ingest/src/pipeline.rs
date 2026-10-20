//! The ingest pipeline (`INGEST_SPEC` steps 1-7, SEC-005/006/008).
//!
//! One entry point serves every source: [`IngestHandle::submit`] queues a [`Job`] (watch
//! candidate, staged upload file, or in-memory bytes) on a bounded queue and awaits the
//! [`IngestOutcome`]. Workers run [`Pipeline::process`].
//!
//! Ingest at scale (T114, ARCHITECTURE v3 5): `workers` tasks read, hash, parse, categorize and
//! store the blob of each job in parallel; one **commit-group writer** then commits up to
//! `group_max_jobs` prepared jobs (or what arrived within `group_window`) in ONE transaction
//! ([`nzb_store::LibraryRepo::insert_release_group`]) and finishes each job afterwards (source
//! removal, reply). Memory is bounded by bytes, not by count: a job takes `size` permits of the
//! `max_inflight_bytes` budget before its file is read and gives them back only when its outcome
//! is final, so the queue, the parse stage and the groups waiting for the writer together never
//! hold more than the budget of NZB bytes (plus their parsed form, proportional to it).
//! Backpressure is the bounded queue, the byte budget and the bounded hand-over to the writer.
//!
//! Ordering guarantees (crash safety, mandatory), per job and therefore per group:
//! 1. the blob is in the store (`put`: tmp, fsync, rename, dir fsync) **before** the group's
//!    transaction starts;
//! 2. the release row and its `ingest_log(ok)` row commit in **one** transaction (the group's;
//!    a group is all-or-nothing, a job that fails alone writes nothing);
//! 3. the source is removed **after** that commit, and only if it is still byte-for-byte the
//!    file that was read (same inode, size, mtime).
//!
//! A crash between 1 and 2 leaves harmless orphan blobs (GC reclaims them, see
//! `nzb_store::FsStore::gc_checked`); between 2 and 3 the sources are re-processed and land in
//! `duplicates/`. A commit whose outcome is unknown (connection lost during `COMMIT`) is treated
//! as not committed: the sources stay and the re-run finds the duplicate (SEC-008). A user's NZB
//! is never deleted unless its bytes are verifiably in the store (and `duplicates_action =
//! delete` is explicitly configured for duplicates); an imported file (`nzbd import`) is never
//! moved or deleted at all.
//!
//! File names are display data: destination names are `<UTC stamp>-<sha8>` only (SEC-005).

use futures_util::FutureExt as _;
use nzb_store::prelude::*;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nzb_core::{
    Analysis, CategorizeError, CategorizeRequest, CategoryRules, Limits, SceneInfo, Sha256,
    analyze, categorize,
};
use nzb_store::{
    CategorySource, GroupItem, GroupOutcome, IngestLogEntry, LogOutcome, LogSource, NewRelease,
    NfoAttach, NzbStore, SceneColumns, Store, StoreError, Uploader,
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use crate::error::{Disposition, IngestError};
use crate::failure;
use crate::fsops::{self, Loaded};
use crate::rules::WatchRules;
use crate::scanner::Candidate;
use crate::sidecar;
use crate::timefmt::{utc_stamp, utc_year};

/// Capacity of the bounded job queue of [`Pipeline::spawn_workers`] (`INGEST_SPEC` §Backpressure);
/// `serve` uses `ingest.queue_cap` through [`Pipeline::spawn`].
pub const QUEUE_CAP: usize = 64;
/// Hard ceiling of `ingest.queue_cap`.
pub const MAX_QUEUE_CAP: usize = 8192;
/// Hard ceiling of `ingest.workers` (parallel parse).
pub const MAX_WORKERS: usize = 32;
/// Default in-flight byte budget (`ingest.max_inflight_bytes`, PERFORMANCE v3 7.3: 256 MiB at ~1M).
pub const DEFAULT_MAX_INFLIGHT_BYTES: u64 = 256 * 1024 * 1024;
/// Default jobs per commit group (ARCHITECTURE v3 5).
pub const DEFAULT_GROUP_MAX_JOBS: usize = 256;
/// Default time a commit group waits for more prepared jobs (ARCHITECTURE v3 5).
pub const DEFAULT_GROUP_WINDOW: Duration = Duration::from_millis(50);
/// Default writer hold cap of one group on SQLite (review 34 L5: ~50 ms).
pub const DEFAULT_WRITER_HOLD: Duration = Duration::from_millis(50);
/// Budget unit: permits are KiB, so a 512 MiB budget fits a `u32` permit count.
const BUDGET_UNIT: u64 = 1024;

/// Throughput and memory settings of [`Pipeline::spawn`] (`[ingest]`, ARCHITECTURE v3 5, T114).
#[derive(Debug, Clone, Copy)]
pub struct IngestSettings {
    /// Parallel prepare tasks (read, hash, parse, categorize, blob put); clamped to 1..=[`MAX_WORKERS`].
    pub workers: usize,
    /// Jobs that may wait in the queue; clamped to 1..=[`MAX_QUEUE_CAP`].
    pub queue_cap: usize,
    /// NZB bytes in flight (read, parsed, waiting for the writer); a job larger than the whole budget
    /// takes all of it.
    pub max_inflight_bytes: u64,
    /// Jobs per commit group; clamped to 1..=[`nzb_store::MAX_GROUP_JOBS`].
    pub group_max_jobs: usize,
    /// How long a group waits for more prepared jobs while workers are still busy.
    pub group_window: Duration,
    /// Writer hold cap of one group on SQLite (the rest is committed in the next group).
    pub writer_hold: Duration,
}

impl Default for IngestSettings {
    fn default() -> Self {
        Self {
            workers: 1,
            queue_cap: QUEUE_CAP,
            max_inflight_bytes: DEFAULT_MAX_INFLIGHT_BYTES,
            group_max_jobs: DEFAULT_GROUP_MAX_JOBS,
            group_window: DEFAULT_GROUP_WINDOW,
            writer_hold: DEFAULT_WRITER_HOLD,
        }
    }
}

impl IngestSettings {
    fn clamped(self) -> Self {
        Self {
            workers: self.workers.clamp(1, MAX_WORKERS),
            queue_cap: self.queue_cap.clamp(1, MAX_QUEUE_CAP),
            max_inflight_bytes: self.max_inflight_bytes.max(BUDGET_UNIT),
            group_max_jobs: self.group_max_jobs.clamp(1, nzb_store::MAX_GROUP_JOBS),
            group_window: self.group_window.min(Duration::from_secs(1)),
            writer_hold: self.writer_hold.min(Duration::from_secs(1)),
        }
    }
}

/// Wall clock (Unix seconds), injectable for deterministic tests.
pub trait WallClock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// [`WallClock`] backed by the system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

/// What to do with a duplicate found in the watch folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicatesAction {
    /// Move to `duplicates/` (default; BETA never deletes).
    Move,
    /// Delete the watch copy, but only after the identical blob is confirmed in the store.
    Delete,
}

/// Pipeline settings (mapped from `[paths]`, `[limits]`, `[ingest]`).
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Parser limits; `max_file_bytes` also caps the source read, `parse_deadline` the parse.
    pub limits: Limits,
    /// Watch root (candidates must lie under it).
    pub watch_dir: PathBuf,
    /// Quarantine directory for rejected sources.
    pub failed_dir: PathBuf,
    /// Destination for duplicates.
    pub duplicates_dir: PathBuf,
    /// Duplicate handling for watch files.
    pub duplicates_action: DuplicatesAction,
    /// Use the first-level sub-folder name as category hint (slug allowlist only).
    pub category_from_subfolder: bool,
    /// Keep at most this many rejected *uploads* in `failed/` (0 = unlimited). Oldest first;
    /// watch-folder rejects are never rotated.
    pub failed_uploads_max_files: usize,
    /// Keep at most this many bytes of rejected uploads in `failed/` (0 = unlimited).
    pub failed_uploads_max_bytes: u64,
}

/// A retry-class failure of the same watch path is logged once per this many attempts.
const RETRY_LOG_EVERY: u32 = 10;
/// Panics before quarantining a watch file whose validated read identity is still available.
const MAX_PANICS: u32 = 3;
/// Bound on the in-memory per-path attempt table.
const MAX_TRACKED_PATHS: usize = 4096;

/// The bytes of a submission.
#[derive(Debug)]
pub enum Payload {
    /// A stable watch-folder file. The candidate is kept alive until the source is handled.
    Watch(Candidate),
    /// A file staged by the upload handler (under `tmp/`, mode 0600). The pipeline takes
    /// ownership: it is removed after a successful store, or moved to `failed/`.
    Staged(PathBuf),
    /// In-memory bytes. Use only for small inputs: queued jobs hold their bytes.
    Bytes(Vec<u8>),
    /// A file of `nzbd import` (T115), already opened without following symlinks and checked to
    /// be a regular file. Read only: it is never moved, renamed or deleted, whatever the outcome.
    Import(ImportFile),
}

/// A source file of `nzbd import`: an open descriptor (never a path, so a name can not be
/// swapped for a symlink between the walk and the read) and its display name.
#[derive(Debug)]
pub struct ImportFile {
    pub(crate) file: std::fs::File,
    pub(crate) size: u64,
    pub(crate) name: Option<String>,
    /// `--include-deleted`: bring back releases whose digest is in the trash (review 38 L1).
    pub(crate) include_deleted: bool,
}

/// `ingest_log.detail` of every row written for an imported file, so the log tells an import from the
/// watch folder without a new `source` value (review 38 I1).
pub const IMPORT_LOG_DETAIL: &str = "import";

/// Display-only name of a watch-folder file: sanitized (bidi/zero-width/control characters
/// removed) and capped, since it is shown in the UI and used as a categorizer name candidate.
pub(crate) fn display_name(path: &std::path::Path) -> Option<String> {
    path.file_name()
        .map(|n| nzb_core::sanitize_text(&n.to_string_lossy(), 255))
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod display_name_tests {
    use super::display_name;
    use std::path::Path;

    #[test]
    fn watch_file_names_are_sanitized_and_capped() {
        let n = display_name(Path::new("/w/a\u{202e}gp\u{200b}j\u{7}.nzb")).unwrap_or_default();
        assert_eq!(n, "agpj.nzb");
        let long = format!("/w/{}.nzb", "x".repeat(1000));
        assert!(display_name(Path::new(&long)).unwrap_or_default().len() <= 255);
        assert_eq!(display_name(Path::new("/w/\u{202e}")), None);
    }
}

/// One unit of work.
#[derive(Debug)]
pub struct Job {
    source: LogSource,
    payload: Payload,
    source_name: Option<String>,
    /// Free-text origin from the uploader; sanitized by the store on insert.
    source_label: Option<String>,
    hint: Option<String>,
    /// 1-based number of the watch rule that matched (T126); set by the pipeline, watch jobs only.
    rule: Option<usize>,
    api_key_id: Option<i64>,
    /// Who submitted it (T101b): recorded in `release.added_by` / `ingest_log.user_id` after the
    /// store re-validates it inside the insert transaction (N9).
    uploader: Uploader,
}

impl Job {
    /// A watch-folder job. The display name is the (sanitized) file name; the hint and label
    /// come from the watch rules and `category_from_subfolder`, applied by the pipeline.
    #[must_use]
    pub fn watch(candidate: Candidate) -> Self {
        let source_name = display_name(&candidate.path);
        Self {
            source: LogSource::Watch,
            payload: Payload::Watch(candidate),
            source_name,
            source_label: None,
            hint: None,
            rule: None,
            api_key_id: None,
            uploader: Uploader::Unattributed,
        }
    }

    /// An import job (`nzbd import`, T115): recorded like a watch-folder file (`source = watch`,
    /// unattributed), but the source is only ever read.
    #[must_use]
    pub fn import(file: ImportFile) -> Self {
        let source_name = file.name.clone();
        Self {
            source: LogSource::Watch,
            payload: Payload::Import(file),
            source_name,
            source_label: None,
            hint: None,
            rule: None,
            api_key_id: None,
            uploader: Uploader::Unattributed,
        }
    }

    /// Bytes this job will read: what it takes from the in-flight budget.
    fn size_hint(&self) -> u64 {
        match &self.payload {
            // The NFO sidecar (T141) is read after the commit while the permits are still held.
            Payload::Watch(c) => c.size.saturating_add(crate::sidecar::size_hint(&c.path)),
            Payload::Staged(p) => std::fs::symlink_metadata(p).map_or(0, |m| m.len()),
            Payload::Bytes(b) => u64::try_from(b.len()).unwrap_or(u64::MAX),
            Payload::Import(f) => f.size,
        }
    }

    /// An upload job (`UploadUi` or `UploadApi`).
    #[must_use]
    pub fn upload(source: LogSource, payload: Payload) -> Self {
        Self {
            source,
            payload,
            source_name: None,
            source_label: None,
            hint: None,
            rule: None,
            api_key_id: None,
            uploader: Uploader::Unattributed,
        }
    }

    /// Original file name, display only.
    #[must_use]
    pub fn with_source_name(mut self, name: Option<String>) -> Self {
        self.source_name = name;
        self
    }

    /// Free-text origin ("torrent", "personal archive", ...). Untrusted; the store sanitizes and
    /// caps it. Ignored when the NZB is already indexed (a duplicate never relabels).
    #[must_use]
    pub fn with_source_label(mut self, label: Option<String>) -> Self {
        self.source_label = label;
        self
    }

    /// Raw category hint (id or slug); an unknown value fails the job with `INVALID_CATEGORY`.
    #[must_use]
    pub fn with_hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }

    /// API key row for `ingest_log.api_key_id`.
    #[must_use]
    pub fn with_api_key(mut self, id: Option<i64>) -> Self {
        self.api_key_id = id;
        self
    }

    /// The submitting account or API key (default: unattributed, as for the watch folder). The
    /// store re-validates it in the transaction that writes the row: a session expired/revoked,
    /// a key revoked or an owner disabled while the body streamed is refused with
    /// [`IngestError::UploaderRefused`] and nothing is written.
    #[must_use]
    pub fn with_uploader(mut self, uploader: Uploader) -> Self {
        self.uploader = uploader;
        self
    }

    fn path(&self) -> Option<&Path> {
        match &self.payload {
            Payload::Watch(c) => Some(&c.path),
            Payload::Staged(p) => Some(p),
            Payload::Bytes(_) | Payload::Import(_) => None,
        }
    }

    /// What failure handling needs, copied out so it survives a panicking job.
    fn meta(&self) -> JobMeta {
        JobMeta {
            source: self.source,
            source_name: self.source_name.clone(),
            api_key_id: self.api_key_id,
            uploader: self.uploader,
            path: self.path().map(Path::to_path_buf),
            staged: matches!(self.payload, Payload::Staged(_)),
            import: matches!(self.payload, Payload::Import(_)),
        }
    }

    /// The job will never run (queue full / shutting down): the staged upload is the
    /// pipeline's own tmp file, remove it so it cannot leak. Watch files are never touched.
    fn discard(self) {
        if let Payload::Staged(p) = self.payload {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Copy of the job fields used by failure handling.
#[derive(Debug, Clone)]
struct JobMeta {
    source: LogSource,
    source_name: Option<String>,
    api_key_id: Option<i64>,
    uploader: Uploader,
    path: Option<PathBuf>,
    staged: bool,
    import: bool,
}

/// Per-path in-memory attempt counters (bounded).
#[derive(Debug, Default, Clone, Copy)]
struct Attempts {
    retries: u32,
    panics: u32,
}

/// File name only, Debug-escaped: hostile names cannot forge log lines and full paths stay
/// out of the logs.
#[allow(clippy::unnecessary_debug_formatting)] // the escaping is the point
fn shown(path: &Path) -> String {
    format!("{:?}", path.file_name().unwrap_or_default())
}

/// How a submission ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// A new release was indexed.
    Ingested,
    /// The same SHA-256 was already indexed (HTTP 200 for uploads).
    Duplicate,
}

/// Successful result of [`IngestHandle::submit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOutcome {
    /// New release or duplicate.
    pub kind: OutcomeKind,
    /// Content hash (public id of the release).
    pub sha256: Sha256,
    /// Row id of the (existing) release.
    pub release_id: i64,
    /// Display title of the release.
    pub title: String,
    /// Category id.
    pub category_id: u32,
}

/// Counters for `/admin` and the periodic log line.
#[derive(Debug, Default)]
struct Counters {
    ingested_ok: AtomicU64,
    duplicates: AtomicU64,
    failed: AtomicU64,
    last_success_at: AtomicI64,
    commit_groups: AtomicU64,
}

/// Snapshot of the counters (`last_success_at` is Unix seconds, 0 = never).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Releases indexed.
    pub ingested_ok: u64,
    /// Duplicates seen.
    pub duplicates: u64,
    /// Failed submissions.
    pub failed: u64,
    /// Time of the last success or duplicate.
    pub last_success_at: i64,
    /// Commit-group transactions run (T114: well below `ingested_ok` under load).
    pub commit_groups: u64,
    /// NZB bytes currently holding the in-flight budget (0 without [`Pipeline::spawn`]).
    pub inflight_bytes: u64,
}

/// Fault-injection points: in tests the "process dies" right there (see `Pipeline::crash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    BeforePut,
    AfterPut,
    /// The group writer is about to open the group transaction (every blob is durable).
    BeforeGroupCommit,
    AfterCommit,
    /// The watch-folder NFO sidecar was attached (T141); neither it nor the NZB is disposed yet.
    AfterNfoAttach,
    /// Failure path: the source is in `failed/`, no `reason.json` yet.
    AfterQuarantineMove,
    /// `reason.json` written to its tmp name, not yet renamed.
    ReasonTmpWritten,
    /// `reason.json` published.
    AfterReason,
    /// `failed retry`: file moved into watch, stale sidecar still present.
    RetryAfterMove,
    /// Startup recovery finished phase `n` (see `recovery::recover`).
    RecoveryPhase(u8),
}

struct Inner {
    cfg: PipelineConfig,
    db: Store,
    store: Arc<dyn NzbStore>,
    rules: CategoryRules,
    /// `[[ingest.rules]]` (T126): watch-folder files only.
    watch_rules: WatchRules,
    clock: Arc<dyn WallClock>,
    counters: Counters,
    attempts: std::sync::Mutex<std::collections::HashMap<PathBuf, Attempts>>,
    /// Jobs a worker has taken but not yet handed to the writer (or finished): while it is not
    /// zero more prepared jobs are on their way, so an open group waits for them (up to its window).
    in_prep: AtomicUsize,
    /// The in-flight byte budget of the spawned workers and its size in permits (KiB).
    budget: std::sync::OnceLock<(Arc<Semaphore>, u32)>,
    #[cfg(test)]
    hook: std::sync::Mutex<Option<TestHook>>,
    /// Test fault: the next multi-job group fails as a whole once (review 38 L5).
    #[cfg(test)]
    fail_next_group: std::sync::atomic::AtomicBool,
    /// Test fault: every group transaction holding this release panics.
    #[cfg(test)]
    panic_on_commit: std::sync::Mutex<Option<Sha256>>,
}

/// Test hook: called at each [`CrashPoint`]; `true` simulates the process dying right there.
#[cfg(test)]
type TestHook = Arc<dyn Fn(CrashPoint) -> bool + Send + Sync>;

/// The pipeline. Cheap to clone.
#[derive(Clone)]
pub struct Pipeline {
    inner: Arc<Inner>,
}

/// Per-job scratch state.
#[derive(Default)]
struct Ctx {
    sha: Option<Sha256>,
    ident: Option<fsops::SourceIdent>,
    /// Test-only: an injected crash happened; skip failure handling (a dead process does none).
    crashed: bool,
    /// A blocking step (read, parse) or the job's own commit panicked: counted like a panicking
    /// job, so a validated watch source is quarantined after [`MAX_PANICS`].
    panicked: bool,
}

/// The result of a blocking task of a job; a panic in it marks the job as panicked (see
/// [`Ctx::panicked`]), so hostile input whose identity was validated can be quarantined.
fn joined<T>(r: Result<T, tokio::task::JoinError>, ctx: &mut Ctx) -> Result<T, IngestError> {
    r.map_err(|e| {
        ctx.panicked |= e.is_panic();
        IngestError::Internal
    })
}

/// The outcome of a group transaction of exactly one job.
fn committed_one(res: Result<Vec<GroupOutcome>, StoreError>) -> Committed {
    match res {
        Ok(mut v) if v.len() == 1 => v
            .pop()
            .map_or(Committed::Failed(IngestError::Internal), Committed::from),
        Ok(_) => Committed::Failed(IngestError::Internal),
        Err(e) => Committed::Failed(uploader_error(e)),
    }
}

impl Pipeline {
    /// Builds the pipeline.
    ///
    /// # Errors
    /// [`IngestError::Internal`] if the embedded category rules are broken.
    pub fn new(
        cfg: PipelineConfig,
        db: Store,
        store: Arc<dyn NzbStore>,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, IngestError> {
        Self::new_with_rules(cfg, WatchRules::default(), db, store, clock)
    }

    /// [`Pipeline::new`] with the validated `[[ingest.rules]]` applied to watch-folder files
    /// (T126). Uploads and imports never see them.
    ///
    /// # Errors
    /// As [`Pipeline::new`].
    pub fn new_with_rules(
        cfg: PipelineConfig,
        watch_rules: WatchRules,
        db: Store,
        store: Arc<dyn NzbStore>,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, IngestError> {
        // Leftover partial copies of a crashed cross-filesystem move (never the only copy).
        for dir in [&cfg.failed_dir, &cfg.duplicates_dir] {
            let n = fsops::clean_stale_parts(dir);
            if n > 0 {
                tracing::info!(removed = n, "removed stale partial copies");
            }
        }
        Self::build(cfg, watch_rules, db, store, clock)
    }

    /// The pipeline of `nzbd import` (T115): like [`Pipeline::new`] but it leaves `failed/` and
    /// `duplicates/` alone (they belong to `serve`; an import never writes there), so it can run
    /// next to a server.
    ///
    /// # Errors
    /// As [`Pipeline::new`].
    pub fn new_import(
        cfg: PipelineConfig,
        db: Store,
        store: Arc<dyn NzbStore>,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, IngestError> {
        Self::build(cfg, WatchRules::default(), db, store, clock)
    }

    fn build(
        cfg: PipelineConfig,
        watch_rules: WatchRules,
        db: Store,
        store: Arc<dyn NzbStore>,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, IngestError> {
        let year = utc_year(clock.now_unix()).saturating_add(1);
        let rules = CategoryRules::builtin(year).map_err(|e| {
            tracing::error!(error = %e, "embedded category rules are invalid");
            IngestError::Internal
        })?;
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                db,
                store,
                rules,
                watch_rules,
                clock,
                counters: Counters::default(),
                attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
                in_prep: AtomicUsize::new(0),
                budget: std::sync::OnceLock::new(),
                #[cfg(test)]
                hook: std::sync::Mutex::new(None),
                #[cfg(test)]
                fail_next_group: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                panic_on_commit: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Counter snapshot.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let c = &self.inner.counters;
        Stats {
            ingested_ok: c.ingested_ok.load(Ordering::Relaxed),
            duplicates: c.duplicates.load(Ordering::Relaxed),
            failed: c.failed.load(Ordering::Relaxed),
            last_success_at: c.last_success_at.load(Ordering::Relaxed),
            commit_groups: c.commit_groups.load(Ordering::Relaxed),
            inflight_bytes: self.inflight_bytes(),
        }
    }

    /// NZB bytes (rounded up to KiB per job) currently reserved from the in-flight budget.
    #[must_use]
    pub fn inflight_bytes(&self) -> u64 {
        self.inner.budget.get().map_or(0, |(sem, total)| {
            let used = u64::from(*total)
                .saturating_sub(u64::try_from(sem.available_permits()).unwrap_or(u64::MAX));
            used.saturating_mul(BUDGET_UNIT)
        })
    }

    /// Starts `workers` tasks consuming a bounded queue ([`QUEUE_CAP`]) with the default group and
    /// budget settings. See [`Pipeline::spawn`].
    #[must_use]
    pub fn spawn_workers(&self, workers: usize) -> (IngestHandle, Vec<JoinHandle<()>>) {
        self.spawn(IngestSettings {
            workers,
            ..IngestSettings::default()
        })
    }

    /// Starts the worker tasks and the commit-group writer. Workers stop once every
    /// [`IngestHandle`] clone is dropped and the queue is drained; the writer stops after them,
    /// once every handed-over job is committed and finished. Await the returned join handles
    /// (workers and writer) for a graceful shutdown.
    #[must_use]
    pub fn spawn(&self, settings: IngestSettings) -> (IngestHandle, Vec<JoinHandle<()>>) {
        let s = settings.clamped();
        let (tx, rx) = mpsc::channel::<Queued>(s.queue_cap);
        let rx = Arc::new(Mutex::new(rx));
        // At most one group in the hand-over: a slow writer blocks the workers (backpressure).
        let (ready_tx, ready_rx) = mpsc::channel::<Ready>(s.group_max_jobs);
        let total = u32::try_from(s.max_inflight_bytes.div_ceil(BUDGET_UNIT))
            .unwrap_or(u32::MAX)
            .min(u32::try_from(Semaphore::MAX_PERMITS).unwrap_or(u32::MAX));
        let budget = Arc::new(Semaphore::new(usize::try_from(total).unwrap_or(0)));
        // The first spawn's budget is the one reported (a pipeline is spawned once in production).
        let _ = self.inner.budget.set((Arc::clone(&budget), total));
        let mut handles: Vec<JoinHandle<()>> = (0..s.workers)
            .map(|_| {
                let rx = Arc::clone(&rx);
                let pipeline = self.clone();
                let ready_tx = ready_tx.clone();
                let budget = Arc::clone(&budget);
                tokio::spawn(async move { pipeline.worker(&rx, &ready_tx, &budget, total).await })
            })
            .collect();
        drop(ready_tx);
        let writer = self.clone();
        handles.push(tokio::spawn(async move {
            writer.writer(ready_rx, s).await;
        }));
        (IngestHandle { tx }, handles)
    }

    /// One worker: takes a job, reserves its bytes, prepares it in its own task (a panic is a
    /// failure of that job only) and hands it to the writer or answers it directly.
    async fn worker(
        &self,
        rx: &Mutex<mpsc::Receiver<Queued>>,
        ready_tx: &mpsc::Sender<Ready>,
        budget: &Arc<Semaphore>,
        total: u32,
    ) {
        loop {
            // The lock is held only while waiting for the next job.
            let next = rx.lock().await.recv().await;
            let Some(Queued { job, reply }) = next else {
                break;
            };
            // Bytes before the read (ARCHITECTURE v3 5.2): waits while the budget is spent.
            let want = u32::try_from(job.size_hint().div_ceil(BUDGET_UNIT))
                .unwrap_or(u32::MAX)
                .clamp(1, total.max(1));
            let permit = Arc::clone(budget).acquire_many_owned(want).await.ok();
            self.inner.in_prep.fetch_add(1, Ordering::SeqCst);
            let meta = job.meta();
            let p = self.clone();
            let prepared = tokio::spawn(async move { p.prepare(job).await }).await;
            match prepared {
                Ok(Prepared::Ready(mut ready)) => {
                    ready.reply = Some(reply);
                    ready.permit = permit;
                    if let Err(mpsc::error::SendError(lost)) = ready_tx.send(*ready).await {
                        {
                            // The writer is gone (it only ends after every worker, so this is a
                            // panic): answer, keep the source, and stop this worker so the
                            // supervisor notices.
                            tracing::error!("commit-group writer is gone");
                            if let Some(tx) = lost.reply {
                                let _ = tx.send(Err(IngestError::ShuttingDown));
                            }
                            self.inner.in_prep.fetch_sub(1, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(Prepared::Done(r)) => {
                    drop(permit);
                    let _ = reply.send(r);
                }
                // A panic inside a job must not kill the worker. The read identity did not
                // survive this task, so a watch source must remain in place for scanner backoff.
                Err(_) => {
                    drop(permit);
                    let _ = reply.send(Err(self.fail_panicked(&meta, None, None).await));
                }
            }
            self.inner.in_prep.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// The commit-group writer (one per pipeline): collects prepared jobs into groups, commits
    /// each group in one transaction and finishes its jobs in their own tasks. Deferred jobs
    /// (SQLite writer hold cap) lead the next group.
    async fn writer(&self, mut rx: mpsc::Receiver<Ready>, s: IngestSettings) {
        let mut pending: VecDeque<Ready> = VecDeque::new();
        let mut finishing: JoinSet<()> = JoinSet::new();
        let mut open = true;
        loop {
            while finishing.try_join_next().is_some() {}
            if pending.is_empty() {
                if !open {
                    break;
                }
                match rx.recv().await {
                    Some(r) => pending.push_back(r),
                    None => break,
                }
            }
            if open {
                open = self.collect(&mut rx, &mut pending, s).await;
            }
            let take = pending.len().min(s.group_max_jobs);
            let group: Vec<Ready> = pending.drain(..take).collect();
            let mut deferred = Vec::new();
            for (mut ready, c) in self.commit(group, s.writer_hold).await {
                if matches!(c, Committed::Deferred) {
                    deferred.push(ready);
                    continue;
                }
                let reply = ready.reply.take();
                let p = self.clone();
                finishing.spawn(async move {
                    let meta = ready.job.meta();
                    let q = p.clone();
                    let r = match tokio::spawn(async move { q.finish(ready, c).await }).await {
                        Ok(r) => r,
                        Err(_) => Err(p.fail_panicked(&meta, None, None).await),
                    };
                    if let Some(tx) = reply {
                        let _ = tx.send(r);
                    }
                });
            }
            for r in deferred.into_iter().rev() {
                pending.push_front(r);
            }
        }
        // Every job that reached the writer ends consistently before the pipeline reports done.
        while finishing.join_next().await.is_some() {}
    }

    /// Fills `pending` up to one group: whatever is already waiting, then more while workers are
    /// still preparing jobs, at most `group_window` in total. Returns `false` once the channel is
    /// closed (every worker ended).
    async fn collect(
        &self,
        rx: &mut mpsc::Receiver<Ready>,
        pending: &mut VecDeque<Ready>,
        s: IngestSettings,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + s.group_window;
        loop {
            while pending.len() < s.group_max_jobs {
                match rx.try_recv() {
                    Ok(r) => pending.push_back(r),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return false,
                }
            }
            let now = tokio::time::Instant::now();
            if pending.len() >= s.group_max_jobs
                || self.inner.in_prep.load(Ordering::SeqCst) == 0
                || now >= deadline
            {
                return true;
            }
            // Short slices: re-check whether anything is still being prepared.
            let slice = (now + Duration::from_millis(5)).min(deadline);
            match tokio::time::timeout_at(slice, rx.recv()).await {
                Ok(Some(r)) => pending.push_back(r),
                Ok(None) => return false,
                Err(_) => {}
            }
        }
    }

    /// Runs steps 1-7 for one job (a commit group of one). Failures are logged to `ingest_log`
    /// and the source is handled per [`Disposition`].
    ///
    /// # Errors
    /// See [`IngestError`].
    pub async fn process(&self, job: Job) -> Result<IngestOutcome, IngestError> {
        let mut ready = match self.prepare(job).await {
            Prepared::Done(r) => return r,
            Prepared::Ready(ready) => *ready,
        };
        // The first job of a group always runs, so a group of one is never deferred; bounded anyway.
        for _ in 0..3 {
            let mut results = self.commit(vec![ready], DEFAULT_WRITER_HOLD).await;
            let Some((r, c)) = results.pop() else {
                return Err(IngestError::Internal);
            };
            if !matches!(c, Committed::Deferred) {
                return self.finish(r, c).await;
            }
            ready = r;
        }
        Err(self
            .failed(ready.job, ready.ctx, IngestError::Internal)
            .await)
    }

    /// Steps 1-5 of one job: up to the durable blob, or a final outcome (duplicate, failure).
    pub(crate) async fn prepare(&self, mut job: Job) -> Prepared {
        let mut ctx = Ctx::default();
        match self.stage(&mut job, &mut ctx).await {
            Ok(Step::Done(outcome)) => {
                if let Some(p) = job.path() {
                    self.forget(p);
                }
                Prepared::Done(Ok(outcome))
            }
            Ok(Step::Ready(st)) => Prepared::Ready(Box::new(Ready {
                job,
                ctx,
                st: *st,
                reply: None,
                permit: None,
            })),
            Err(e) => Prepared::Done(Err(self.failed(job, ctx, e).await)),
        }
    }

    /// Failure bookkeeping of a job that ended with `e`; returns `e`.
    async fn failed(&self, job: Job, mut ctx: Ctx, e: IngestError) -> IngestError {
        if matches!(e, IngestError::Trashed) {
            // A deliberate skip of `nzbd import`, counted in its report: no row, no log line.
            return e;
        }
        if matches!(e, IngestError::UploaderRefused) {
            // The key or its owner is no longer usable: nothing is written (no row, no
            // `failed/` copy); the staged upload is the pipeline's own tmp file.
            job.discard();
            return e;
        }
        if ctx.panicked {
            return self
                .fail_panicked(&job.meta(), ctx.sha, ctx.ident.take())
                .await;
        }
        if !ctx.crashed {
            self.fail(&job.meta(), ctx.sha, ctx.ident.take(), &e, 0)
                .await;
        }
        e
    }

    /// Step 6 for a group: one transaction ([`nzb_store::LibraryRepo::insert_release_group`]).
    /// When the whole group fails (not one job: I/O, a lost connection, a deadlock) or panics, each
    /// job is retried alone, so one bad job never fails the others (ARCHITECTURE v3 5). A job whose own
    /// transaction panics is counted like a panicking job (quarantined after [`MAX_PANICS`]) instead
    /// of taking the writer, and with it the process, down.
    pub(crate) async fn commit(
        &self,
        mut group: Vec<Ready>,
        hold: Duration,
    ) -> Vec<(Ready, Committed)> {
        if group.is_empty() {
            return Vec::new();
        }
        if self.hit(CrashPoint::BeforeGroupCommit) {
            // The process "dies" with every blob durable and nothing committed.
            for r in &mut group {
                r.ctx.crashed = true;
            }
            return group.into_iter().map(|r| (r, Committed::Crashed)).collect();
        }
        let outcomes = self.commit_outcomes(&mut group, hold).await;
        group.into_iter().zip(outcomes).collect()
    }

    /// The outcome of each job of `group`, in order (see [`Pipeline::commit`]).
    async fn commit_outcomes(&self, group: &mut [Ready], hold: Duration) -> Vec<Committed> {
        let now = self.now();
        self.inner
            .counters
            .commit_groups
            .fetch_add(1, Ordering::Relaxed);
        let whole = {
            let items: Vec<GroupItem<'_>> = group.iter().map(|r| r.item(now)).collect();
            self.insert_caught(&items, hold).await
        };
        match whole {
            Some(Ok(v)) if v.len() == group.len() => {
                return v.into_iter().map(Committed::from).collect();
            }
            Some(Ok(_)) => {
                return group
                    .iter()
                    .map(|_| Committed::Failed(IngestError::Internal))
                    .collect();
            }
            Some(Err(e)) if group.len() == 1 => return vec![Committed::Failed(uploader_error(e))],
            Some(Err(e)) => tracing::warn!(
                jobs = group.len(),
                error = %e,
                "commit group failed; committing its jobs one by one"
            ),
            None => tracing::error!(
                jobs = group.len(),
                "commit group panicked; committing its jobs one by one"
            ),
        }
        let mut one_by_one = Vec::with_capacity(group.len());
        for r in group.iter_mut() {
            let res = {
                // A failed group may have waited for a database lock. Recheck credentials with
                // a fresh injected wall-clock value for each retry, rather than its old timestamp.
                let item = [r.item(self.now())];
                self.insert_caught(&item, hold).await
            };
            one_by_one.push(res.map_or_else(
                || {
                    r.ctx.panicked = true;
                    Committed::Failed(IngestError::Internal)
                },
                committed_one,
            ));
        }
        one_by_one
    }

    /// [`Pipeline::insert_group`] with a panic contained: `None` when it panicked (an unfinished
    /// transaction is rolled back when it is dropped).
    async fn insert_caught(
        &self,
        items: &[GroupItem<'_>],
        hold: Duration,
    ) -> Option<Result<Vec<GroupOutcome>, StoreError>> {
        AssertUnwindSafe(self.insert_group(items, hold))
            .catch_unwind()
            .await
            .ok()
    }

    /// One group transaction (the test build can make a multi-job group fail as a whole once, or
    /// panic).
    async fn insert_group(
        &self,
        items: &[GroupItem<'_>],
        hold: Duration,
    ) -> Result<Vec<GroupOutcome>, StoreError> {
        #[cfg(test)]
        if items.len() > 1 && self.inner.fail_next_group.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Io(std::io::Error::other(
                "injected group failure",
            )));
        }
        #[cfg(test)]
        if let Some(sha) = self.inner.panic_on_commit.lock().ok().and_then(|g| *g)
            && items.iter().any(|i| i.new.analysis.sha256 == sha)
        {
            #[allow(clippy::panic)] // the injected fault itself
            std::panic::panic_any("injected commit panic");
        }
        self.inner.db.insert_release_group(items, hold).await
    }

    /// Test fault injection: the next group of more than one job fails as a whole once.
    #[cfg(test)]
    pub(crate) fn fail_next_group(&self) {
        self.inner.fail_next_group.store(true, Ordering::SeqCst);
    }

    /// Test fault injection: every group transaction holding `sha` panics.
    #[cfg(test)]
    pub(crate) fn panic_on_commit(&self, sha: Sha256) {
        if let Ok(mut g) = self.inner.panic_on_commit.lock() {
            *g = Some(sha);
        }
    }

    /// Step 7 of a committed (or refused) job: source removal, counters, outcome.
    pub(crate) async fn finish(
        &self,
        ready: Ready,
        c: Committed,
    ) -> Result<IngestOutcome, IngestError> {
        let Ready {
            job, mut ctx, st, ..
        } = ready;
        let r = match c {
            Committed::Crashed | Committed::Deferred => Err(IngestError::Internal),
            Committed::Failed(e) => Err(e),
            Committed::Inserted(release_id) => {
                let sha = st.analysis.sha256;
                let disposed = async {
                    self.crash(CrashPoint::AfterCommit, &mut ctx)?;
                    // T141: the sidecar is attached in its own transaction after the release commit and
                    // before any source is touched, so a crash in between re-processes the NZB as a
                    // duplicate, which attaches it then (INGEST_SPEC §NFO sidecar).
                    let sc = self
                        .attach_sidecar(&job, release_id, sha, ctx.ident.as_ref())
                        .await;
                    self.crash(CrashPoint::AfterNfoAttach, &mut ctx)?;
                    // Only now are the sources disposable: the sidecar first, so a crash before the NZB
                    // is removed leaves the NZB (re-processed as a duplicate), never an orphan sidecar.
                    let fate = NzbFate::Removed {
                        dir: &self.inner.cfg.failed_dir,
                        sha,
                    };
                    self.dispose_sidecar(sc, fate).await;
                    self.remove_source(&job, ctx.ident.as_ref()).await;
                    Ok::<(), IngestError>(())
                }
                .await;
                if let Err(e) = disposed {
                    Err(e)
                } else {
                    let inner = &self.inner;
                    inner.counters.ingested_ok.fetch_add(1, Ordering::Relaxed);
                    inner
                        .counters
                        .last_success_at
                        .store(self.now(), Ordering::Relaxed);
                    Ok(IngestOutcome {
                        kind: OutcomeKind::Ingested,
                        sha256: st.analysis.sha256,
                        release_id,
                        title: st.analysis.title,
                        category_id: st.category_id,
                    })
                }
            }
            // Lost a race against another job, worker or upload with the same content: not an
            // error. The blob was put by this job, so there is nothing to heal.
            Committed::Duplicate => {
                let sha = st.analysis.sha256;
                match self.inner.db.get_release_by_sha(&sha.to_hex()).await {
                    Ok(Some(row)) => {
                        self.finish_duplicate(
                            &job,
                            sha,
                            ctx.ident.as_ref(),
                            None,
                            row.id,
                            row.title,
                            row.category_id,
                        )
                        .await
                    }
                    Ok(None) => Err(IngestError::Storage(StoreError::Duplicate)),
                    Err(e) => Err(IngestError::Storage(e)),
                }
            }
        };
        match r {
            Ok(outcome) => {
                if let Some(p) = job.path() {
                    self.forget(p);
                }
                Ok(outcome)
            }
            Err(e) => Err(self.failed(job, ctx, e).await),
        }
    }

    fn attempts_mut<R>(
        &self,
        f: impl FnOnce(&mut std::collections::HashMap<PathBuf, Attempts>) -> R,
    ) -> R {
        let mut g = self
            .inner
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.len() > MAX_TRACKED_PATHS {
            // Retry-only entries go first, so a flood of failing files cannot reset the panic
            // count that quarantines a panicking one.
            g.retain(|_, a| a.panics > 0);
            if g.len() > MAX_TRACKED_PATHS {
                g.clear();
            }
        }
        f(&mut g)
    }

    fn forget(&self, path: &Path) {
        self.attempts_mut(|m| {
            m.remove(path);
        });
    }

    /// A job panicked: log it as `INTERNAL` and count it; the third panic of the same watch
    /// path quarantines the file only when its validated read identity is still available.
    async fn fail_panicked(
        &self,
        meta: &JobMeta,
        sha: Option<Sha256>,
        ident: Option<fsops::SourceIdent>,
    ) -> IngestError {
        let panics = meta.path.as_ref().map_or(MAX_PANICS, |p| {
            self.attempts_mut(|m| {
                // A flood of panicking paths cannot be tracked individually (the table would be
                // reset); a path that would overflow it is eligible for immediate quarantine
                // when its read identity is available.
                if m.len() >= MAX_TRACKED_PATHS && !m.contains_key(p) {
                    return MAX_PANICS;
                }
                let a = m.entry(p.clone()).or_default();
                a.panics = a.panics.saturating_add(1);
                a.panics
            })
        });
        tracing::error!("ingest job panicked");
        self.fail(meta, sha, ident, &IngestError::Internal, panics)
            .await;
        IngestError::Internal
    }

    fn now(&self) -> i64 {
        self.inner.clock.now_unix()
    }

    #[cfg(test)]
    fn crash(&self, point: CrashPoint, ctx: &mut Ctx) -> Result<(), IngestError> {
        let hook = self.inner.hook.lock().ok().and_then(|g| g.clone());
        if hook.is_some_and(|h| h(point)) {
            ctx.crashed = true;
            return Err(IngestError::Internal);
        }
        Ok(())
    }

    /// Fault injection for the failure path: `true` = the process "dies" here.
    #[cfg(test)]
    fn hit(&self, point: CrashPoint) -> bool {
        let hook = self.inner.hook.lock().ok().and_then(|g| g.clone());
        hook.is_some_and(|h| h(point))
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn hit(&self, _point: CrashPoint) -> bool {
        false
    }

    #[cfg(test)]
    pub(crate) fn set_hook(&self, hook: Option<TestHook>) {
        if let Ok(mut g) = self.inner.hook.lock() {
            *g = hook;
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn crash(&self, _point: CrashPoint, _ctx: &mut Ctx) -> Result<(), IngestError> {
        Ok(())
    }

    /// Step 1: bounded read + hash, off the async threads.
    async fn load(&self, job: &mut Job, ctx: &mut Ctx) -> Result<Loaded, IngestError> {
        let max = self.inner.cfg.limits.max_file_bytes;
        match &mut job.payload {
            Payload::Bytes(b) => {
                if u64::try_from(b.len()).unwrap_or(u64::MAX) > max {
                    return Err(IngestError::FileTooLarge);
                }
                let bytes = std::mem::take(b);
                let r = tokio::task::spawn_blocking(move || {
                    let sha = fsops::digest(&bytes);
                    Loaded {
                        bytes,
                        sha,
                        ident: None,
                    }
                })
                .await;
                joined(r, ctx)
            }
            Payload::Staged(path) => {
                let path = path.clone();
                let r =
                    tokio::task::spawn_blocking(move || fsops::read_source(&path, max, None, None))
                        .await;
                joined(r, ctx)?
            }
            Payload::Watch(c) => {
                let path = c.path.clone();
                let id = c.id.clone();
                let root = self.inner.cfg.watch_dir.clone();
                let r = tokio::task::spawn_blocking(move || {
                    fsops::read_source(&path, max, Some(&id), Some(&root))
                })
                .await;
                joined(r, ctx)?
            }
            Payload::Import(f) => {
                // The descriptor was opened by the walk (no-follow, regular file); read it once.
                let file = f
                    .file
                    .try_clone()
                    .map_err(|_| IngestError::SourceUnreadable)?;
                let size = f.size;
                let r =
                    tokio::task::spawn_blocking(move || fsops::read_opened(file, size, max, || {}))
                        .await;
                joined(r, ctx)?
            }
        }
    }

    /// Applies the watch rules and `category_from_subfolder` to a watch-folder job (T126): the
    /// first matching rule's category (else the sub-folder slug, when enabled) becomes the hint,
    /// its label the source label. Both are validated values from the configuration or the slug
    /// allowlist, never the file or folder name itself. Other payloads are left alone.
    fn apply_watch_rules(&self, job: &mut Job) {
        let Payload::Watch(c) = &job.payload else {
            return;
        };
        if job.hint.is_some() || job.rule.is_some() {
            return;
        }
        let inner = &self.inner;
        let eff = inner.watch_rules.effect(
            c.subfolder.as_deref(),
            job.source_name.as_deref(),
            inner.cfg.category_from_subfolder,
            &inner.rules.taxonomy,
        );
        if let Some(n) = eff.rule {
            // The name is Debug-escaped (`shown`), never echoed raw.
            tracing::info!(rule = n, file = %shown(&c.path), "watch rule matched");
        }
        let rule = eff.rule;
        let hint = eff.category.map(|(slug, _)| slug.to_owned());
        let label = eff.source_label.map(str::to_owned);
        job.rule = rule;
        job.hint = hint;
        if job.source_label.is_none() {
            job.source_label = label;
        }
    }

    /// `ingest_log.detail` token naming the matched watch rule (`rule=<n>`), if any.
    fn rule_detail(job: &Job) -> Option<String> {
        job.rule.map(|n| format!("rule={n}"))
    }

    /// Steps 1-5: bounded read + hash, duplicate check, analyze, categorize, durable blob put.
    async fn stage(&self, job: &mut Job, ctx: &mut Ctx) -> Result<Step, IngestError> {
        let inner = &self.inner;
        self.apply_watch_rules(job);
        // Step 1: bounded read + SHA-256.
        let mut loaded = self.load(job, ctx).await?;
        let sha = loaded.sha;
        ctx.sha = Some(sha);
        ctx.ident.clone_from(&loaded.ident);

        // Step 2: already indexed? An uploader that is no longer usable learns nothing about the
        // library either (N9): validated before the duplicate answer as well as in the insert.
        if let Err(e) = inner.db.validate_uploader(&job.uploader, self.now()).await {
            return Err(uploader_error(e));
        }
        if let Some(row) = inner.db.get_release_by_sha(&sha.to_hex()).await? {
            return self
                .finish_duplicate(
                    job,
                    sha,
                    loaded.ident.as_ref(),
                    Some(&loaded.bytes),
                    row.id,
                    row.title,
                    row.category_id,
                )
                .await
                .map(Step::Done);
        }

        // An import never brings back a release that was deleted from the library (review 38 L1).
        if let Payload::Import(f) = &job.payload
            && !f.include_deleted
            && inner.db.release_is_trashed(&sha).await?
        {
            return Err(IngestError::Trashed);
        }

        // Step 3: analyze (hostile input) off the async threads, with the parse deadline.
        let limits = inner.cfg.limits;
        let deadline = Instant::now() + limits.parse_deadline;
        let bytes = std::mem::take(&mut loaded.bytes);
        let r = tokio::task::spawn_blocking(move || {
            let r = analyze(&bytes, &limits, deadline);
            (bytes, r)
        })
        .await;
        let (bytes, analysed) = joined(r, ctx)?;
        loaded.bytes = bytes;
        let mut analysis = analysed?;
        if analysis.sha256 != sha {
            // Cannot happen; refuse to index under a hash that is not the stored address.
            return Err(IngestError::Internal);
        }
        // D39 (T131): a usable `.nzb` file name is the title (fully obfuscated NZBs carry their real name only
        // there), else the analyzer's meta / derived title. Display data only; a duplicate never gets here, so a
        // re-upload under another name does not retitle.
        nzb_core::apply_source_title(&mut analysis, job.source_name.as_deref());

        // Step 4: categorize (Scene first, then hint, meta, fallback). New rows are never
        // manually overridden, so the override rule (never re-categorize) is not in play here.
        let request = CategorizeRequest {
            hint: job.hint.as_deref(),
            source_stem: job.source_name.as_deref(),
        };
        let cat = categorize(&analysis, &request, &inner.rules).map_err(|e| match e {
            CategorizeError::InvalidCategory => IngestError::InvalidCategory,
        })?;
        analysis.flags.insert(cat.flags);
        let scene = scene_columns(&cat.scene);
        let disagreement = cat
            .hint_disagreement
            .map(|d| format!("hint_disagreement hint={} scene={}", d.hint_id, d.scene_id));
        let detail = match (Self::rule_detail(job), disagreement) {
            (Some(r), Some(d)) => Some(format!("{r} {d}")),
            (r, d) => r.or(d),
        };
        let size = u64::try_from(loaded.bytes.len()).unwrap_or(u64::MAX);

        // Step 5: the blob reaches the store (durably) before any row refers to it.
        self.crash(CrashPoint::BeforePut, ctx)?;
        inner.store.put(sha, &loaded.bytes).await?;
        self.crash(CrashPoint::AfterPut, ctx)?;
        // The bytes are not needed any more: only the parsed form waits for the group.
        Ok(Step::Ready(Box::new(Staged {
            analysis,
            category_id: u32::from(cat.category_id),
            category_source: map_source(cat.source),
            scene,
            detail,
            size,
        })))
    }

    /// Removes a fully ingested source (watch file or staged upload) if it is still exactly
    /// the file that was read (identity captured before the first read). Imported files have no
    /// path here and are never removed.
    async fn remove_source(&self, job: &Job, ident: Option<&fsops::SourceIdent>) {
        let (Some(path), Some(ident)) = (job.path(), ident.cloned()) else {
            return;
        };
        let path = path.to_path_buf();
        let name = shown(&path);
        let res =
            tokio::task::spawn_blocking(move || fsops::remove_if_unchanged(&path, &ident)).await;
        match res {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                tracing::warn!(file = %name, "source changed after ingest; left in place");
            }
            Ok(Err(e)) => {
                tracing::error!(file = %name, error = %e.kind(), "cannot remove ingested source");
            }
            Err(_) => tracing::error!("source removal task failed"),
        }
    }

    /// Duplicate: refresh/heal the blob (when this job still holds the bytes), log, then move (or
    /// delete) the source. An imported duplicate leaves no log row (re-running an import adds
    /// nothing) and its source is never touched.
    #[allow(clippy::too_many_arguments)] // the parts of a job that a duplicate needs
    async fn finish_duplicate(
        &self,
        job: &Job,
        sha: Sha256,
        ident: Option<&fsops::SourceIdent>,
        bytes: Option<&[u8]>,
        release_id: i64,
        title: String,
        category_id: u32,
    ) -> Result<IngestOutcome, IngestError> {
        let inner = &self.inner;
        // Idempotent: restores a blob that went missing and refreshes its mtime so a concurrent
        // GC cannot reclaim it (SECURITY_REVIEW M3).
        if let Some(bytes) = bytes {
            inner.store.put(sha, bytes).await?;
        }
        if !matches!(job.payload, Payload::Import(_)) {
            inner
                .db
                .log_ingest_as(
                    &IngestLogEntry {
                        ts: self.now(),
                        source: job.source,
                        api_key_id: job.api_key_id,
                        source_name: job.source_name.as_deref(),
                        sha256: Some(sha),
                        outcome: LogOutcome::Duplicate,
                        error_code: None,
                        detail: Self::rule_detail(job).as_deref(),
                    },
                    Some(release_id),
                    &job.uploader,
                )
                .await?;
        }
        match &job.payload {
            Payload::Watch(_) => {
                // T141: a known NZB may still bring the NFO its release lacks (D41 b: only while it has none).
                let sc = self.attach_sidecar(job, release_id, sha, ident).await;
                self.dispose_watch_duplicate(job, sha, ident, sc).await;
            }
            // Uploads: acknowledge without keeping a second copy.
            Payload::Staged(_) => self.remove_source(job, ident).await,
            Payload::Bytes(_) | Payload::Import(_) => {}
        }
        inner.counters.duplicates.fetch_add(1, Ordering::Relaxed);
        inner
            .counters
            .last_success_at
            .store(self.now(), Ordering::Relaxed);
        Ok(IngestOutcome {
            kind: OutcomeKind::Duplicate,
            sha256: sha,
            release_id,
            title,
            category_id,
        })
    }

    async fn dispose_watch_duplicate(
        &self,
        job: &Job,
        sha: Sha256,
        ident: Option<&fsops::SourceIdent>,
        sc: Option<SidecarState>,
    ) {
        let inner = &self.inner;
        let delete = inner.cfg.duplicates_action == DuplicatesAction::Delete
            // Never delete unless the identical blob is confirmed present.
            && matches!(inner.store.exists(&sha).await, Ok(true));
        if delete {
            let fate = NzbFate::Removed {
                dir: &inner.cfg.duplicates_dir,
                sha,
            };
            self.dispose_sidecar(sc, fate).await;
            self.remove_source(job, ident).await;
        } else if let Some(path) = job.path() {
            let dest = self
                .move_to(
                    path,
                    &inner.cfg.duplicates_dir.clone(),
                    Some(sha),
                    ident,
                    false,
                )
                .await;
            if let Some(dest) = dest {
                self.dispose_sidecar(sc, NzbFate::MovedTo(&dest)).await;
            }
        }
    }

    /// Examines the NFO sidecar of the watch NZB `nzb` (read with identity `nzb_ident`) relative to its verified
    /// directory (T141, review 54 L1). `None` when there is none, or when it is refused for anything but its size
    /// (logged with the stable code and the Debug-escaped name, never content): such a file is never touched.
    async fn examine_sidecar(
        &self,
        nzb: &Path,
        nzb_ident: &fsops::SourceIdent,
    ) -> Option<(SidecarState, bool)> {
        let (path, root, dev_ino) = (
            nzb.to_path_buf(),
            self.inner.cfg.watch_dir.clone(),
            nzb_ident.dev_ino(),
        );
        let probed = tokio::task::spawn_blocking(move || {
            let (dir, name) = sidecar::open_dir(&path, dev_ino, &root)?;
            let p = sidecar::probe(&dir, &name);
            Ok::<_, &'static str>((dir, p))
        })
        .await
        .ok()?;
        let nzb_name = shown(nzb);
        match probed {
            Err(code) => {
                tracing::warn!(code, nzb = %nzb_name, "watch NFO sidecar not looked for");
                None
            }
            Ok((_, sidecar::Probe::Absent)) => None,
            Ok((_, sidecar::Probe::Refused(code))) => {
                tracing::warn!(code, nzb = %nzb_name, "watch NFO sidecar not attached; left in place");
                None
            }
            Ok((dir, sidecar::Probe::Unattachable(e, code))) => {
                tracing::warn!(code, file = ?e.name, "watch NFO sidecar not attached");
                Some((
                    SidecarState {
                        dir,
                        e,
                        stored: false,
                    },
                    false,
                ))
            }
            Ok((dir, sidecar::Probe::Ready(e))) => Some((
                SidecarState {
                    dir,
                    e,
                    stored: false,
                },
                true,
            )),
        }
    }

    /// Finds and reads the NFO sidecar of a watch-folder job and attaches it to `release_id` (T141). `None` when
    /// the job is not a watch file or has no sidecar it may touch; the NZB is unaffected either way.
    async fn attach_sidecar(
        &self,
        job: &Job,
        release_id: i64,
        sha: Sha256,
        nzb_ident: Option<&fsops::SourceIdent>,
    ) -> Option<SidecarState> {
        let Payload::Watch(c) = &job.payload else {
            return None;
        };
        let (mut sc, attachable) = self.examine_sidecar(&c.path, nzb_ident?).await?;
        let (Some(bytes), true) = (&sc.e.bytes, attachable) else {
            return Some(sc);
        };
        let file = format!("{:?}", sc.e.name);
        let db = &self.inner.db;
        sc.stored = match db
            .attach_watch_nfo(release_id, &sha, bytes, self.now())
            .await
        {
            Ok(NfoAttach::Attached) => {
                tracing::info!(file = %file, "watch NFO sidecar attached");
                true
            }
            Ok(NfoAttach::AlreadyPresent) => {
                // Removable only when the database already holds these very bytes (a re-run after a crash).
                let same = matches!(
                    db.release_nfo(release_id).await,
                    Ok(Some(n)) if &n.bytes == bytes
                );
                tracing::info!(
                    code = "NFO_EXISTS",
                    same,
                    file = %file,
                    "the release already has an NFO; watch sidecar not attached"
                );
                same
            }
            Err(e) => {
                tracing::warn!(
                    code = "NFO_STORE_FAILED",
                    error = %e,
                    file = %file,
                    "watch NFO sidecar not attached"
                );
                false
            }
        };
        Some(sc)
    }

    /// The sidecar follows its NZB (T141): next to it when the NZB was moved (`failed/`, `duplicates/`, exactly the
    /// NZB's generated stem with `.nfo`, never a counter); when the NZB was removed, the sidecar is removed only if
    /// the database holds its bytes, else it is moved into `dir` as exactly `<stamp>-<sha8>.nfo` (BETA: move, don't
    /// delete). Every step is relative to the verified directory and re-checks the examined identity; a taken name
    /// or a changed file leaves the sidecar where it is.
    async fn dispose_sidecar(&self, sc: Option<SidecarState>, fate: NzbFate<'_>) {
        let Some(sc) = sc else { return };
        let (dest_dir, dest_name, remove) = match fate {
            NzbFate::MovedTo(dest) => {
                let (Some(dir), Some(stem)) =
                    (dest.parent(), dest.file_stem().and_then(|s| s.to_str()))
                else {
                    return;
                };
                (dir.to_path_buf(), format!("{stem}.nfo"), false)
            }
            NzbFate::Removed { dir, sha } => (
                dir.to_path_buf(),
                format!("{}-{}.nfo", utc_stamp(self.now()), sha.short()),
                sc.stored,
            ),
        };
        let file = format!("{:?}", sc.e.name);
        let dest_shown = format!("{dest_name:?}");
        let res = tokio::task::spawn_blocking(move || {
            if remove {
                sidecar::remove(&sc.dir, &sc.e.name, &sc.e.id, || {})
            } else {
                sidecar::move_to(&sc.dir, &sc.e, &dest_dir, &dest_name, || {})
            }
        })
        .await;
        match res {
            Ok(sidecar::Outcome::Removed) => {}
            // Review 54 I2: an unattached NFO is findable by its generated name (no input in it).
            Ok(sidecar::Outcome::Moved) => {
                tracing::info!(file = %file, dest = %dest_shown, "watch NFO sidecar moved");
            }
            Ok(sidecar::Outcome::Left(code)) => {
                tracing::warn!(code, file = %file, "watch NFO sidecar left in place");
            }
            Err(_) => tracing::error!("sidecar task failed"),
        }
    }

    /// Moves `path` into `dir` as `<UTC stamp>-<sha8>[-up].nzb` (collision-free; `-up` marks a
    /// rejected upload, the only kind of file `failed/` rotation may ever delete). Failure is
    /// logged; the caller's scan loop notices the file is still there and backs off. Returns
    /// the final path.
    async fn move_to(
        &self,
        path: &Path,
        dir: &Path,
        sha: Option<Sha256>,
        read: Option<&fsops::SourceIdent>,
        upload_reject: bool,
    ) -> Option<PathBuf> {
        let src = path.to_path_buf();
        let dir = dir.to_path_buf();
        let stem = format!(
            "{}-{}{}",
            utc_stamp(self.now()),
            sha.map_or_else(|| "unknown".to_owned(), |s| s.short()),
            if upload_reject { "-up" } else { "" }
        );
        let name = shown(path);
        let read = read.cloned();
        let res = tokio::task::spawn_blocking(move || {
            fsops::move_no_clobber(&src, &dir, &stem, read.as_ref())
        })
        .await;
        match res {
            Ok(Ok(dest)) => Some(dest),
            Ok(Err(e)) => {
                tracing::error!(file = %name, error = %e, "cannot move source; leaving it in place");
                None
            }
            Err(_) => {
                tracing::error!("move task failed");
                None
            }
        }
    }

    /// Second half of quarantining: `reason.json` next to the moved file, then (for rejected
    /// uploads) the oldest-first rotation. Failures are logged; the file is already safe.
    async fn record_reason(&self, dest: PathBuf, reason: failure::Reason, upload_reject: bool) {
        if self.hit(CrashPoint::AfterQuarantineMove) {
            return;
        }
        let (max_files, max_bytes) = (
            self.inner.cfg.failed_uploads_max_files,
            self.inner.cfg.failed_uploads_max_bytes,
        );
        let this = self.clone();
        let res = tokio::task::spawn_blocking(move || {
            let (Some(dir), Some(name)) =
                (dest.parent(), dest.file_name().and_then(|n| n.to_str()))
            else {
                return Ok(());
            };
            let size = std::fs::symlink_metadata(&dest)?.len();
            let reason = failure::Reason { size, ..reason };
            failure::write_reason(dir, name, &reason, &|p| this.hit(p))?;
            if upload_reject {
                fsops::rotate_upload_rejects(dir, max_files, max_bytes);
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "cannot write reason.json"),
            Err(_) => tracing::error!("reason task failed"),
        }
    }

    /// Failure bookkeeping: counters, `ingest_log(failed)`, and the source per [`Disposition`].
    /// Watch rejects with a validated identity are moved to `failed/` and get a `reason.json`
    /// (see [`crate::failure`]). Retry-class failures and unvalidated watch sources are logged once
    /// per [`RETRY_LOG_EVERY`] attempts, so a stuck file cannot flood the log table.
    /// `panics` counts panics for this path (eligible for quarantine at [`MAX_PANICS`]).
    async fn fail(
        &self,
        meta: &JobMeta,
        sha: Option<Sha256>,
        ident: Option<fsops::SourceIdent>,
        err: &IngestError,
        panics: u32,
    ) {
        if !err.reached_worker() {
            return;
        }
        let inner = &self.inner;
        // A failed read may never have validated the scanner's source identity (for example,
        // growth past the size cap). Do not acquire authority over whatever now occupies that
        // watch path. Staged uploads are service-owned and still need failure cleanup.
        let quarantine = meta.staged
            || (meta.path.is_some()
                && ident.is_some()
                && (err.disposition() == Disposition::Reject || panics >= MAX_PANICS));
        if !quarantine
            && (panics == 0 || ident.is_none())
            && let Some(p) = &meta.path
        {
            let n = self.attempts_mut(|m| {
                let a = m.entry(p.clone()).or_default();
                a.retries = a.retries.saturating_add(1);
                a.retries
            });
            if n % RETRY_LOG_EVERY != 1 {
                return;
            }
        }
        inner.counters.failed.fetch_add(1, Ordering::Relaxed);
        // Failures of the same content before this one (read before the new row is written).
        let retry_count = match (quarantine, sha) {
            (true, Some(s)) => inner.db.count_failed_for_sha(&s).await.unwrap_or(0),
            _ => 0,
        };
        tracing::warn!(
            code = err.code(),
            source = meta.source.as_str(),
            "ingest failed"
        );
        let logged = inner
            .db
            .log_ingest_as(
                &IngestLogEntry {
                    ts: self.now(),
                    source: meta.source,
                    api_key_id: meta.api_key_id,
                    source_name: meta.source_name.as_deref(),
                    sha256: sha,
                    outcome: LogOutcome::Failed,
                    error_code: Some(err.code()),
                    detail: meta.import.then_some(IMPORT_LOG_DETAIL),
                },
                None,
                &meta.uploader,
            )
            .await;
        if let Err(e) = logged {
            tracing::error!(error = %e, "cannot write ingest_log");
        }
        if quarantine && let Some(path) = &meta.path {
            // T141: a watch NZB's sidecar is examined while the NZB still sits next to it (its directory is
            // proven by the NZB's inode), then follows it into `failed/` (never attached: no release).
            let sc = match (&ident, meta.staged) {
                (Some(id), false) => self.examine_sidecar(path, id).await.map(|(sc, _)| sc),
                _ => None,
            };
            let dest = self
                .move_to(
                    path,
                    &inner.cfg.failed_dir.clone(),
                    sha,
                    ident.as_ref(),
                    meta.staged,
                )
                .await;
            if let Some(dest) = dest {
                self.dispose_sidecar(sc, NzbFate::MovedTo(&dest)).await;
                let reason = failure::Reason::new(
                    err.code(),
                    &err.to_string(),
                    meta.source.as_str(),
                    meta.source_name.as_deref(),
                    sha.map(|s| s.to_hex()),
                    0, // replaced by the size of the moved file
                    self.now(),
                    retry_count,
                );
                self.record_reason(dest, reason, meta.staged).await;
            }
            if !meta.staged {
                self.forget(path);
            }
        }
    }
}

/// The NFO sidecar of a watch job after the attach attempt (T141).
struct SidecarState {
    /// The NZB's verified directory (every later step is relative to it).
    dir: sidecar::Dir,
    /// What was examined (and read).
    e: sidecar::Examined,
    /// The database holds exactly these bytes for the release (so the file may be removed with the NZB).
    stored: bool,
}

/// Where the NZB of a sidecar went.
enum NzbFate<'a> {
    /// Moved to this path (`failed/` or `duplicates/`).
    MovedTo(&'a Path),
    /// Removed from the watch folder (its bytes are in the store); an unstored sidecar goes to `dir`.
    Removed { dir: &'a Path, sha: Sha256 },
}

/// The parsed form of a job that waits for its commit group (its bytes are already in the store).
struct Staged {
    analysis: Analysis,
    category_id: u32,
    category_source: CategorySource,
    scene: SceneColumns,
    detail: Option<String>,
    size: u64,
}

/// A prepared job on its way through the writer.
pub(crate) struct Ready {
    job: Job,
    ctx: Ctx,
    st: Staged,
    reply: Option<oneshot::Sender<Result<IngestOutcome, IngestError>>>,
    /// The job's share of the in-flight byte budget, returned when the job is finished.
    permit: Option<OwnedSemaphorePermit>,
}

impl Ready {
    /// Test access: the release hash of this job.
    #[cfg(test)]
    pub(crate) fn sha256(&self) -> Sha256 {
        self.st.analysis.sha256
    }

    /// Test access: whether this job panicked (counted towards [`MAX_PANICS`]).
    #[cfg(test)]
    pub(crate) fn panicked(&self) -> bool {
        self.ctx.panicked
    }

    /// The job as one item of a commit group.
    fn item(&self, now: i64) -> GroupItem<'_> {
        let job = &self.job;
        GroupItem {
            new: NewRelease {
                analysis: &self.st.analysis,
                nzb_size_bytes: self.st.size,
                source_name: job.source_name.as_deref(),
                source_label: job.source_label.as_deref(),
                category_id: self.st.category_id,
                category_source: self.st.category_source,
                meta_json: None,
                scene: self.st.scene.clone(),
                ingested_at: now,
            },
            log: IngestLogEntry {
                ts: now,
                source: job.source,
                api_key_id: job.api_key_id,
                source_name: job.source_name.as_deref(),
                sha256: Some(self.st.analysis.sha256),
                outcome: LogOutcome::Ok,
                error_code: None,
                detail: if matches!(job.payload, Payload::Import(_)) {
                    Some(IMPORT_LOG_DETAIL)
                } else {
                    self.st.detail.as_deref()
                },
            },
            uploader: job.uploader,
        }
    }
}

/// Result of steps 1-5.
enum Step {
    /// Final (a duplicate found before parsing).
    Done(IngestOutcome),
    /// Ready for a commit group.
    Ready(Box<Staged>),
}

/// What a worker hands on.
pub(crate) enum Prepared {
    Done(Result<IngestOutcome, IngestError>),
    Ready(Box<Ready>),
}

/// The group transaction's answer for one job.
pub(crate) enum Committed {
    Inserted(i64),
    Duplicate,
    Deferred,
    Failed(IngestError),
    /// Test fault injection: the process died before the group transaction.
    Crashed,
}

impl From<GroupOutcome> for Committed {
    fn from(o: GroupOutcome) -> Self {
        match o {
            GroupOutcome::Inserted(id) => Self::Inserted(id),
            GroupOutcome::Duplicate => Self::Duplicate,
            GroupOutcome::Deferred => Self::Deferred,
            GroupOutcome::Failed(e) => Self::Failed(uploader_error(e)),
        }
    }
}

/// A store error of the uploader re-check becomes [`IngestError::UploaderRefused`]; anything
/// else stays a storage error.
fn uploader_error(e: StoreError) -> IngestError {
    match e {
        StoreError::Account(
            nzb_store::AccountError::KeyRefused | nzb_store::AccountError::Forbidden,
        ) => IngestError::UploaderRefused,
        other => IngestError::Storage(other),
    }
}

fn map_source(s: nzb_core::CategorySource) -> CategorySource {
    match s {
        nzb_core::CategorySource::Scene => CategorySource::Scene,
        nzb_core::CategorySource::Upload => CategorySource::Upload,
        nzb_core::CategorySource::Meta => CategorySource::Meta,
        nzb_core::CategorySource::Fallback => CategorySource::Fallback,
    }
}

/// Denormalized `scene_*` columns; only `group` is filled when the Scene rules were inconclusive.
fn scene_columns(s: &SceneInfo) -> SceneColumns {
    if !s.is_conclusive() {
        // Only the group survives an inconclusive parse (display data).
        return SceneColumns {
            group: s.release_group.clone(),
            ..SceneColumns::default()
        };
    }
    SceneColumns {
        family: s.family.as_str().map(str::to_owned),
        year: s.year.map(u32::from),
        season: s.season,
        episode: s
            .episodes
            .first()
            .copied()
            .or(s.episode_range.map(|(a, _)| a)),
        resolution: s.resolution.as_str().map(str::to_owned),
        source: s.source.as_str().map(str::to_owned),
        codec: s.video_codec.clone(),
        group: s.release_group.clone(),
        languages_json: if s.languages.is_empty() {
            None
        } else {
            serde_json::to_string(&s.languages).ok()
        },
        json: serde_json::to_string(s).ok(),
    }
}

/// A queued job with its reply channel.
pub(crate) struct Queued {
    pub(crate) job: Job,
    pub(crate) reply: oneshot::Sender<Result<IngestOutcome, IngestError>>,
}

/// Submit side of the bounded queue. Cheap to clone; shared by the scan loop and the upload
/// handlers (T051).
#[derive(Clone)]
pub struct IngestHandle {
    tx: mpsc::Sender<Queued>,
}

impl IngestHandle {
    #[cfg(test)]
    pub(crate) fn from_sender(tx: mpsc::Sender<Queued>) -> Self {
        Self { tx }
    }

    /// Queues `job` and waits for its outcome. Never blocks on a full queue.
    ///
    /// Callers apply their own timeout (HTTP 504); dropping the future does not cancel the job
    /// (a started ingest always runs to a consistent end state).
    ///
    /// # Errors
    /// [`IngestError::QueueFull`] (HTTP 503) if the queue is full (`queue_cap` jobs waiting),
    /// [`IngestError::ShuttingDown`] if the workers are gone, otherwise the job's own error.
    pub async fn submit(&self, job: Job) -> Result<IngestOutcome, IngestError> {
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(Queued { job, reply }) {
            Ok(()) => {}
            // The job never ran: do not leak its staged upload.
            Err(mpsc::error::TrySendError::Full(q)) => {
                q.job.discard();
                return Err(IngestError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(q)) => {
                q.job.discard();
                return Err(IngestError::ShuttingDown);
            }
        }
        rx.await.map_err(|_| IngestError::ShuttingDown)?
    }

    /// Free queue slots (the scanner offers at most this many candidates per cycle).
    #[must_use]
    pub fn free_slots(&self) -> usize {
        self.tx.capacity()
    }

    /// Jobs currently waiting.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.tx.max_capacity().saturating_sub(self.tx.capacity())
    }
}

#[cfg(test)]
mod retry_capacity_tests {
    #![allow(clippy::unwrap_used, clippy::too_many_lines)]

    use super::*;

    struct FixedClock;

    impl WallClock for FixedClock {
        fn now_unix(&self) -> i64 {
            1_700_000_000
        }
    }

    #[tokio::test]
    async fn panic_tracker_saturation_quarantines_overflow_without_resetting_existing_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let directory = |name: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).unwrap();
            path
        };
        let watch = directory("watch");
        let failed = directory("failed");
        let duplicates = directory("duplicates");
        let store_root = directory("store");
        let test_store = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let pipeline = Pipeline::new(
            PipelineConfig {
                limits: Limits::default(),
                watch_dir: watch.clone(),
                failed_dir: failed.clone(),
                duplicates_dir: duplicates,
                duplicates_action: DuplicatesAction::Move,
                category_from_subfolder: false,
                failed_uploads_max_files: 0,
                failed_uploads_max_bytes: 0,
            },
            test_store.store.clone(),
            Arc::new(nzb_store::FsStore::open(&store_root).unwrap()),
            Arc::new(FixedClock),
        )
        .unwrap();
        let tracked = watch.join("tracked-0.nzb");
        let overflow = watch.join("overflow.nzb");
        std::fs::write(&tracked, b"original tracked file").unwrap();
        std::fs::write(&overflow, b"original overflow file").unwrap();
        let tracked_ident = fsops::read_source(&tracked, 1024, None, Some(&watch))
            .unwrap()
            .ident;
        let overflow_ident = fsops::read_source(&overflow, 1024, None, Some(&watch))
            .unwrap()
            .ident;
        assert!(tracked_ident.is_some());
        assert!(overflow_ident.is_some());
        // Seed only the prior observations, then exercise real failure logging and moving.
        // Thousands of actual panics/SQL writes would add runtime without testing another path.
        pipeline.attempts_mut(|attempts| {
            for n in 0..MAX_TRACKED_PATHS {
                attempts.insert(
                    watch.join(format!("tracked-{n}.nzb")),
                    Attempts {
                        retries: 0,
                        panics: 1,
                    },
                );
            }
        });
        let meta = |path: &Path| JobMeta {
            source: LogSource::Watch,
            source_name: path.file_name().map(|n| n.to_string_lossy().into_owned()),
            api_key_id: None,
            uploader: Uploader::Unattributed,
            path: Some(path.to_path_buf()),
            staged: false,
            import: false,
        };
        let error = pipeline
            .fail_panicked(&meta(&overflow), None, overflow_ident)
            .await;
        assert_eq!(error.code(), "INTERNAL");
        assert!(
            !overflow.exists(),
            "an untrackable panic must be quarantined immediately"
        );
        assert!(
            tracked.exists(),
            "existing paths retain their retry allowance"
        );
        pipeline.attempts_mut(|attempts| {
            assert_eq!(attempts.len(), MAX_TRACKED_PATHS);
            assert_eq!(attempts.get(&tracked).unwrap().panics, 1);
            assert!(!attempts.contains_key(&overflow));
        });

        // A retry-only entry can temporarily cross the cap; pruning it must not erase the
        // panic counters or let an already tracked file start its three attempts over.
        let retry = watch.join("retry-only.nzb");
        pipeline.attempts_mut(|attempts| {
            attempts.insert(
                retry.clone(),
                Attempts {
                    retries: 1,
                    panics: 0,
                },
            );
        });
        pipeline
            .fail_panicked(&meta(&tracked), None, tracked_ident.clone())
            .await;
        assert!(tracked.exists());
        pipeline.attempts_mut(|attempts| {
            assert_eq!(attempts.len(), MAX_TRACKED_PATHS);
            assert_eq!(attempts.get(&tracked).unwrap().panics, 2);
            assert!(!attempts.contains_key(&retry));
        });
        pipeline
            .fail_panicked(&meta(&tracked), None, tracked_ident)
            .await;
        assert!(
            !tracked.exists(),
            "the third tracked panic still quarantines"
        );
        pipeline.attempts_mut(|attempts| {
            assert_eq!(attempts.len(), MAX_TRACKED_PATHS - 1);
            assert!(attempts.values().all(|a| a.panics == 1));
        });
        let entries = failure::list_failed(&failed).unwrap();
        assert_eq!(entries.len(), 2);
        for entry in entries {
            let reason = entry.reason.unwrap();
            assert_eq!(reason.error_code, "INTERNAL");
            let expected: &[u8] = if reason.source_name.as_deref() == Some("overflow.nzb") {
                b"original overflow file"
            } else {
                assert_eq!(reason.source_name.as_deref(), Some("tracked-0.nzb"));
                b"original tracked file"
            };
            assert_eq!(std::fs::read(failed.join(entry.name)).unwrap(), expected);
        }
        assert_eq!(pipeline.stats().failed, 3);
    }
}
