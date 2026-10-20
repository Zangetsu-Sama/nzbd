//! Cleanup (T081): classification, counting and purging of the three buckets the admin
//! **Cleanup** panel and `nzbd cleanup` expose, plus restoring a deleted release.
//!
//! | Bucket | Contents |
//! |---|---|
//! | **Trash** | deleted releases (`release_trash` rows and their `store/.trash` blobs), the store's `.gc-trash` quarantine, provably redundant `.nzbd-trash.*` leftovers in `failed/` |
//! | **Blocked** | `failed/` and `failed/expired/` files rejected by policy or hostile-input codes (see [`is_blocked_code`]) |
//! | **Failed** | every other file there, including files with an unknown code or no sidecar |
//!
//! Nothing in this module runs on its own: it is called from an explicit, re-authenticated
//! user action (web purge page, `nzbd cleanup purge --yes`). Safety rules, all covered by
//! tests (`SECURITY_REVIEW` T081):
//!
//! * the walk is `read_dir` of the fixed directories (`failed/`, `failed/expired/`,
//!   `store/.trash`, `store/.gc-trash`); every name is filtered by an exact grammar and
//!   resolved from the listing, never joined from input; nothing under `watch/`,
//!   `duplicates/`, `tmp/`, `backups/` or the live `store/aa/bb/` blobs is ever looked at;
//! * a `failed/` file is removed only if it has a valid nzbd sidecar written for exactly that
//!   file, whose reason code belongs to the purged bucket, whose recorded digest (or size)
//!   matches the content hashed through a no-follow, non-blocking, regular, single-link
//!   descriptor, and it is unlinked through [`remove_if_unchanged`] (identity re-check, rename
//!   out of reach, verify, unlink). Foreign files, symlinks, FIFOs, hard-linked files, files
//!   without sidecar and mismatching sidecars are counted and left alone;
//! * `.nzbd-trash.*` leftovers are crash residue of a verified removal that startup recovery
//!   normally handles; they are removed only if they are provably redundant (a second name of
//!   the inode exists, or the content is an indexed release), otherwise they are left for
//!   recovery;
//! * quarantined `.gc-trash` blobs are removed only after [`QUARANTINE_MIN_AGE_SECS`] (the
//!   same 7 days `store gc` grants, because they may be the only copy after a database restore).

use nzb_store::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use nzb_core::Sha256;
use nzb_store::{Store, StoreError, TrashPurge, TrashStore, sha8};
use sha2::{Digest, Sha256 as Hasher};

use crate::failure::{
    EXPIRED_DIR, FailedEntry, REASON_SUFFIX, is_failed_name, is_failed_nfo_name, list_failed,
};
use crate::fsops::{
    SourceIdent, fsync_dir, is_generated_part, move_no_clobber, remove_if_unchanged, unique_tag,
};
use crate::scanner::open_regular;

/// Quarantined blobs younger than this are never purged (7 days, as `store gc`).
pub const QUARANTINE_MIN_AGE_SECS: i64 = 7 * 86_400;
/// Files handled by one purge run; the rest is reported as `remaining`.
pub const MAX_PURGE_FILES: usize = 20_000;
/// Deleted releases listed/purged per run.
const MAX_TRASH_ROWS: u32 = 10_000;
/// Safety bound for directory walks.
const MAX_ENTRIES: usize = 100_000;
const LEFTOVER_PREFIX: &str = ".nzbd-trash.";

/// One of the three purgeable buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// Deleted releases, GC quarantine, leftovers.
    Trash,
    /// `failed/` items rejected by policy or hostile-input codes.
    Blocked,
    /// All other `failed/` items.
    Failed,
}

impl Bucket {
    /// Buckets in display order.
    pub const ALL: [Self; 3] = [Self::Trash, Self::Blocked, Self::Failed];

    /// Stable lowercase name; also the word the user types to confirm a purge.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Trash => "trash",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }

    /// Parses a slug (exact match).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.slug() == s)
    }
}

/// Whether a stable reason code is a policy / hostile-input rejection (the **Blocked**
/// bucket): `NZB_DOCTYPE_FORBIDDEN`, `NZB_NOT_UTF8`, `FILE_TOO_LARGE`, `INVALID_CATEGORY` and
/// every `NZB_LIMIT_*`. Everything else, unknown codes included, is **Failed**.
#[must_use]
pub fn is_blocked_code(code: &str) -> bool {
    match code {
        "NZB_DOCTYPE_FORBIDDEN" | "NZB_NOT_UTF8" | "FILE_TOO_LARGE" | "INVALID_CATEGORY" => true,
        other => other.strip_prefix("NZB_LIMIT_").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        }),
    }
}

/// Bucket of a `failed/` item given its sidecar code (`None`: no valid sidecar).
#[must_use]
pub fn classify(code: Option<&str>) -> Bucket {
    if code.is_some_and(is_blocked_code) {
        Bucket::Blocked
    } else {
        Bucket::Failed
    }
}

/// Everything the cleanup operations need.
#[derive(Clone)]
pub struct CleanupEnv {
    /// Database (trash rows, live digests).
    pub db: Store,
    /// Blob store with a trash area.
    pub store: Arc<dyn TrashStore>,
    /// The `failed/` directory.
    pub failed_dir: PathBuf,
}

/// Errors of the cleanup operations (never contain names or paths).
#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    /// Database or blob store failure.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    /// Filesystem failure (the kind only).
    #[error("io error: {0:?}")]
    Io(io::ErrorKind),
    /// A blocking task failed.
    #[error("internal error")]
    Internal,
}

impl From<io::Error> for CleanupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Counts of a `failed/` bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FailedBucketStatus {
    /// Files in the bucket (`failed/` and `failed/expired/`).
    pub items: u64,
    /// Their size on disk.
    pub bytes: u64,
    /// Of `items`, how many have no valid nzbd sidecar and are therefore never purged.
    pub unmanaged: u64,
}

/// Counts of the Trash bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrashStatus {
    /// Deleted releases (`release_trash` rows).
    pub releases: u64,
    /// Bytes of their trash blobs on disk.
    pub release_bytes: u64,
    /// Trash blobs without a record (never purged here).
    pub unrecorded: u64,
    /// Files in the store's `.gc-trash` quarantine.
    pub quarantine: u64,
    /// Their size.
    pub quarantine_bytes: u64,
    /// `.nzbd-trash.*` leftovers in `failed/` and `failed/expired/`.
    pub leftovers: u64,
    /// Their size.
    pub leftover_bytes: u64,
    /// Foreign entries in the trash directories (never touched).
    pub foreign: u64,
}

impl TrashStatus {
    /// Items a purge may remove: deleted releases, quarantined blobs, leftovers.
    #[must_use]
    pub const fn items(&self) -> u64 {
        self.releases
            .saturating_add(self.quarantine)
            .saturating_add(self.leftovers)
    }

    /// Bytes of those items.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.release_bytes
            .saturating_add(self.quarantine_bytes)
            .saturating_add(self.leftover_bytes)
    }
}

/// Counts of all three buckets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupStatus {
    /// Trash.
    pub trash: TrashStatus,
    /// Blocked.
    pub blocked: FailedBucketStatus,
    /// Failed.
    pub failed: FailedBucketStatus,
    /// Entries in `failed/` and `failed/expired/` that nzbd did not write (never touched).
    pub foreign_files: u64,
}

/// What a purge did. Numbers only: no names, no paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// The purged bucket.
    pub bucket: Bucket,
    /// Items removed.
    pub removed: u64,
    /// Bytes freed.
    pub bytes: u64,
    /// Skipped because nzbd did not write them (no valid sidecar, foreign names).
    pub unmanaged: u64,
    /// Skipped by a safety check (symlink, FIFO, hard link, content or identity mismatch,
    /// changed meanwhile, not provably redundant).
    pub refused: u64,
    /// Quarantined blobs younger than the minimum age (kept).
    pub kept_recent: u64,
    /// Not processed because the per-run file limit or the deadline was reached.
    pub remaining: u64,
    /// I/O errors while removing.
    pub errors: u64,
    /// The authority gate refused before a batch (the acting admin was disabled, demoted or
    /// deleted mid-run, SEC-060); the rest of the bucket was left alone.
    pub aborted: bool,
}

/// Re-check of the authority a purge runs under, called before EVERY batch of [`PURGE_BATCH`]
/// items (and before each phase). Returning `false` aborts the run. Synchronous because the
/// `failed/` walk runs on a blocking thread; async callers wrap their lookup in a `block_on`.
pub type PurgeGate = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// Items handled between two authority re-checks.
pub const PURGE_BATCH: u64 = nzb_store::QuarantinePurge::BATCH_SIZE;

impl PurgeReport {
    const fn new(bucket: Bucket) -> Self {
        Self {
            bucket,
            removed: 0,
            bytes: 0,
            unmanaged: 0,
            refused: 0,
            kept_recent: 0,
            remaining: 0,
            errors: 0,
            aborted: false,
        }
    }

    /// Items left behind for any reason.
    #[must_use]
    pub const fn skipped(&self) -> u64 {
        self.unmanaged
            .saturating_add(self.refused)
            .saturating_add(self.kept_recent)
            .saturating_add(self.remaining)
            .saturating_add(self.errors)
    }
}

fn join_err(_: &tokio::task::JoinError) -> CleanupError {
    CleanupError::Internal
}

/// The directories holding `failed/` items: `failed/` and, if it is a real directory,
/// `failed/expired/`.
fn failed_dirs(failed: &Path) -> Vec<PathBuf> {
    let mut v = vec![failed.to_path_buf()];
    let ex = failed.join(EXPIRED_DIR);
    if fs::symlink_metadata(&ex).is_ok_and(|m| m.is_dir()) {
        v.push(ex);
    }
    v
}

/// `(name, size)` of regular `.nzbd-trash.*` files directly inside `dir`.
fn list_leftovers(dir: &Path) -> Vec<(String, u64)> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .take(MAX_ENTRIES)
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_owned();
            if !name.starts_with(LEFTOVER_PREFIX) {
                return None;
            }
            // `DirEntry::metadata` does not follow symlinks.
            let m = e.metadata().ok()?;
            m.file_type().is_file().then_some((name, m.len()))
        })
        .collect()
}

/// Entries of a `failed/` directory that nzbd did not write: anything that is not a generated
/// failed name, its sidecar, a hidden leftover/part name, or (top level) the `expired/` folder.
/// They are never listed or touched; the count is shown so they do not go unnoticed.
fn count_foreign(dir: &Path, top: bool) -> u64 {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut n = 0u64;
    for e in rd.flatten().take(MAX_ENTRIES) {
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            n = n.saturating_add(1);
            continue;
        };
        let t = e.file_type();
        if top && name == EXPIRED_DIR && t.as_ref().is_ok_and(fs::FileType::is_dir) {
            continue;
        }
        let known = is_failed_name(name)
            || is_failed_nfo_name(name)
            || name.strip_suffix(REASON_SUFFIX).is_some_and(is_failed_name)
            || name.starts_with(LEFTOVER_PREFIX)
            || is_generated_part(name);
        if !known || !t.is_ok_and(|t| t.is_file()) {
            n = n.saturating_add(1);
        }
    }
    n
}

type FailedParts = (FailedBucketStatus, FailedBucketStatus, u64, u64, u64);

fn failed_status(failed: &Path) -> Result<FailedParts, io::Error> {
    let mut blocked = FailedBucketStatus::default();
    let mut other = FailedBucketStatus::default();
    let (mut lo_n, mut lo_b, mut foreign) = (0u64, 0u64, 0u64);
    for (i, dir) in failed_dirs(failed).iter().enumerate() {
        let entries = match list_failed(dir) {
            Ok(e) => e,
            // A missing `failed/` is an error; a vanished `expired/` is just empty.
            Err(e) if i > 0 && e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        for e in entries {
            let b = match &e.reason {
                Some(r) => classify(Some(&r.error_code)),
                None => Bucket::Failed,
            };
            let slot = if b == Bucket::Blocked {
                &mut blocked
            } else {
                &mut other
            };
            slot.items = slot.items.saturating_add(1);
            slot.bytes = slot.bytes.saturating_add(e.size);
            if e.reason.is_none() {
                slot.unmanaged = slot.unmanaged.saturating_add(1);
            }
        }
        for (_, size) in list_leftovers(dir) {
            lo_n = lo_n.saturating_add(1);
            lo_b = lo_b.saturating_add(size);
        }
        foreign = foreign.saturating_add(count_foreign(dir, i == 0));
    }
    Ok((blocked, other, lo_n, lo_b, foreign))
}

/// Counts the three buckets. Bounded: directory listings only (stat + sidecar read per file),
/// no hashing.
///
/// # Errors
/// Database, blob store or `failed/` read failures.
pub async fn status(env: &CleanupEnv) -> Result<CleanupStatus, CleanupError> {
    let dir = env.failed_dir.clone();
    let fs_part = tokio::task::spawn_blocking(move || failed_status(&dir))
        .await
        .map_err(|e| join_err(&e))??;
    let (blocked, failed, leftovers, leftover_bytes, foreign_files) = fs_part;
    let rows = env.db.list_trash(MAX_TRASH_ROWS).await?;
    let blobs = env.store.trash_list(MAX_ENTRIES).await?;
    let quarantine = env.store.quarantine_list(MAX_ENTRIES).await?;
    let on_disk: std::collections::HashMap<[u8; 32], u64> =
        blobs.items.iter().map(|b| (b.sha.0, b.size)).collect();
    let mut t = TrashStatus {
        foreign: blobs.foreign.saturating_add(quarantine.foreign),
        leftovers,
        leftover_bytes,
        ..TrashStatus::default()
    };
    let mut recorded = HashSet::new();
    for r in &rows {
        t.releases = t.releases.saturating_add(1);
        t.release_bytes = t
            .release_bytes
            .saturating_add(on_disk.get(&r.sha256.0).copied().unwrap_or(0));
        recorded.insert(r.sha256.0);
    }
    t.unrecorded = blobs
        .items
        .iter()
        .filter(|b| !recorded.contains(&b.sha.0))
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    for q in &quarantine.items {
        t.quarantine = t.quarantine.saturating_add(1);
        t.quarantine_bytes = t.quarantine_bytes.saturating_add(q.size);
    }
    Ok(CleanupStatus {
        trash: t,
        blocked,
        failed,
        foreign_files,
    })
}

/// Streams `file` (at most `size + 1` bytes) into a SHA-256.
fn hash_open(file: File, size: u64) -> Option<Sha256> {
    let mut h = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut r = file.take(size.saturating_add(1));
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Some(Sha256(h.finalize().into()))
}

/// Result of one `failed/` file check.
enum Verdict {
    /// Remove it; identity captured from the verified descriptor.
    Remove(SourceIdent),
    /// Skip: not managed by nzbd.
    Unmanaged,
    /// Skip: a safety check refused it.
    Refused,
    /// Belongs to the other bucket.
    OtherBucket,
}

/// Decides one listed `failed/` file for a purge of `bucket` (`SECURITY_REVIEW` T081).
fn judge(dir: &Path, e: &FailedEntry, bucket: Bucket) -> Verdict {
    let Some(r) = &e.reason else {
        return Verdict::Unmanaged;
    };
    if classify(Some(&r.error_code)) != bucket {
        return Verdict::OtherBucket;
    }
    let path = dir.join(&e.name); // `e.name` came from the listing and matched is_failed_name
    let Ok((file, size)) = open_regular(&path, u64::MAX, None, Some(dir)) else {
        return Verdict::Refused;
    };
    let Ok(meta) = file.metadata() else {
        return Verdict::Refused;
    };
    let ident = SourceIdent::of(&meta);
    let intact = match &r.sha256 {
        Some(want) => hash_open(file, size).is_some_and(|got| &got.to_hex() == want),
        None => r.size == size,
    };
    if intact && ident.size() == size {
        Verdict::Remove(ident)
    } else {
        Verdict::Refused
    }
}

/// Purges one `failed/` bucket (blocking).
fn purge_failed_bucket(
    failed: &Path,
    bucket: Bucket,
    deadline: Instant,
    gate: Option<&PurgeGate>,
) -> PurgeReport {
    let mut rep = PurgeReport::new(bucket);
    let mut budget = MAX_PURGE_FILES;
    let mut handled: u64 = 0;
    for (i, dir) in failed_dirs(failed).into_iter().enumerate() {
        if bucket == Bucket::Failed {
            // Entries nzbd did not write are reported once, with the Failed bucket.
            rep.unmanaged = rep.unmanaged.saturating_add(count_foreign(&dir, i == 0));
        }
        let Ok(entries) = list_failed(&dir) else {
            rep.errors = rep.errors.saturating_add(1);
            continue;
        };
        for e in entries {
            // A file without sidecar is part of the Failed bucket (and never purged).
            let in_bucket = e.reason.as_ref().map_or(bucket == Bucket::Failed, |r| {
                classify(Some(&r.error_code)) == bucket
            });
            if !in_bucket {
                continue;
            }
            if budget == 0 || Instant::now() >= deadline || rep.aborted {
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            // Authority is re-checked before every batch, the first one included (SEC-060).
            if handled.is_multiple_of(PURGE_BATCH) && gate.is_some_and(|g| !g()) {
                rep.aborted = true;
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            handled = handled.saturating_add(1);
            budget -= 1;
            match judge(&dir, &e, bucket) {
                Verdict::Unmanaged => rep.unmanaged = rep.unmanaged.saturating_add(1),
                Verdict::OtherBucket => {}
                Verdict::Refused => rep.refused = rep.refused.saturating_add(1),
                Verdict::Remove(ident) => {
                    // Hashing a large file may have consumed the remaining time budget.
                    if Instant::now() >= deadline {
                        rep.remaining = rep.remaining.saturating_add(1);
                        continue;
                    }
                    match remove_if_unchanged(&dir.join(&e.name), &ident) {
                        Ok(true) => {
                            // The sidecar goes second: a crash in between leaves an orphan
                            // sidecar that startup recovery removes. It is only removed if it
                            // is a plain regular file.
                            let sc = dir.join(format!("{}{REASON_SUFFIX}", e.name));
                            if fs::symlink_metadata(&sc).is_ok_and(|m| m.file_type().is_file()) {
                                let _ = fs::remove_file(&sc);
                            }
                            // T141: the NFO that followed it into `failed/` is part of the purged item.
                            if let Some(stem) = e.name.strip_suffix(".nzb") {
                                let _ = crate::fsops::remove_twin(&dir, stem);
                            }
                            fsync_dir(&dir);
                            rep.removed = rep.removed.saturating_add(1);
                            rep.bytes = rep.bytes.saturating_add(ident.size());
                        }
                        Ok(false) => rep.refused = rep.refused.saturating_add(1),
                        Err(_) => rep.errors = rep.errors.saturating_add(1),
                    }
                }
            }
        }
    }
    rep
}

/// Removes provably redundant `.nzbd-trash.*` leftovers (blocking). `live` = digests of
/// indexed releases.
fn purge_leftovers(
    failed: &Path,
    live: &HashSet<Sha256>,
    deadline: Instant,
    gate: Option<&PurgeGate>,
    rep: &mut PurgeReport,
) {
    let mut handled: u64 = 0;
    for dir in failed_dirs(failed) {
        for (name, _) in list_leftovers(&dir) {
            if Instant::now() >= deadline || rep.aborted {
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            if handled.is_multiple_of(PURGE_BATCH) && gate.is_some_and(|g| !g()) {
                rep.aborted = true;
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            handled = handled.saturating_add(1);
            let path = dir.join(&name);
            let Ok(file) = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(&path)
            else {
                rep.refused = rep.refused.saturating_add(1);
                continue;
            };
            let Ok(meta) = file.metadata() else {
                rep.refused = rep.refused.saturating_add(1);
                continue;
            };
            if !meta.file_type().is_file() {
                rep.refused = rep.refused.saturating_add(1);
                continue;
            }
            let ident = SourceIdent::of(&meta);
            let size = meta.len();
            // A second name of the inode exists: removing this one loses nothing. Otherwise the
            // content must be an indexed release.
            let redundant =
                meta.nlink() >= 2 || hash_open(file, size).is_some_and(|d| live.contains(&d));
            if !redundant {
                // Possibly the only copy of something: startup recovery restores it visibly.
                rep.refused = rep.refused.saturating_add(1);
                continue;
            }
            if Instant::now() >= deadline {
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            match remove_if_unchanged(&path, &ident) {
                Ok(true) => {
                    rep.removed = rep.removed.saturating_add(1);
                    rep.bytes = rep.bytes.saturating_add(size);
                }
                Ok(false) => rep.refused = rep.refused.saturating_add(1),
                Err(_) => rep.errors = rep.errors.saturating_add(1),
            }
        }
        fsync_dir(&dir);
    }
}

/// Purges one bucket. `now` is unix seconds (quarantine age), `deadline` bounds the run.
///
/// # Errors
/// Database or blob store failures that prevented the run from starting; per-file problems
/// are counted in the report.
pub async fn purge(
    env: &CleanupEnv,
    bucket: Bucket,
    now: i64,
    deadline: Instant,
) -> Result<PurgeReport, CleanupError> {
    purge_gated(env, bucket, now, deadline, None).await
}

/// [`purge`] under an authority `gate` (T101b, SEC-060): the gate is consulted before every batch
/// of [`PURGE_BATCH`] items and before each phase; a refusal stops the run (`aborted`).
///
/// # Errors
/// As [`purge`].
pub async fn purge_gated(
    env: &CleanupEnv,
    bucket: Bucket,
    now: i64,
    deadline: Instant,
    gate: Option<PurgeGate>,
) -> Result<PurgeReport, CleanupError> {
    match bucket {
        Bucket::Blocked | Bucket::Failed => {
            let dir = env.failed_dir.clone();
            tokio::task::spawn_blocking(move || {
                purge_failed_bucket(&dir, bucket, deadline, gate.as_ref())
            })
            .await
            .map_err(|e| join_err(&e))
        }
        Bucket::Trash => purge_trash(env, now, deadline, gate).await,
    }
}

/// Runs the gate on a blocking thread (it may block on a database read).
async fn gate_open(gate: Option<&PurgeGate>) -> Result<bool, CleanupError> {
    let Some(g) = gate else {
        return Ok(true);
    };
    let g = std::sync::Arc::clone(g);
    tokio::task::spawn_blocking(move || g())
        .await
        .map_err(|e| join_err(&e))
}

async fn purge_trash(
    env: &CleanupEnv,
    now: i64,
    deadline: Instant,
    gate: Option<PurgeGate>,
) -> Result<PurgeReport, CleanupError> {
    let mut rep = PurgeReport::new(Bucket::Trash);
    // 1. Deleted releases: blob first (identity-checked), then the record.
    let rows = env.db.list_trash(MAX_TRASH_ROWS).await?;
    let mut handled: u64 = 0;
    for row in rows {
        if Instant::now() >= deadline || rep.aborted {
            rep.remaining = rep.remaining.saturating_add(1);
            continue;
        }
        if handled.is_multiple_of(PURGE_BATCH) && !gate_open(gate.as_ref()).await? {
            rep.aborted = true;
            rep.remaining = rep.remaining.saturating_add(1);
            continue;
        }
        handled = handled.saturating_add(1);
        if Instant::now() >= deadline {
            rep.remaining = rep.remaining.saturating_add(1);
            continue;
        }
        match env.store.trash_purge(&row.sha256).await {
            Ok(TrashPurge::Removed { bytes }) => {
                rep.bytes = rep.bytes.saturating_add(bytes);
            }
            // No blob any more: only the record is left to drop.
            Ok(TrashPurge::Absent) => {}
            Ok(TrashPurge::Refused) => {
                rep.refused = rep.refused.saturating_add(1);
                continue;
            }
            Err(_) => {
                rep.errors = rep.errors.saturating_add(1);
                continue;
            }
        }
        match env.db.purge_trash_record(row.id, now).await {
            Ok(_) => rep.removed = rep.removed.saturating_add(1),
            Err(_) => rep.errors = rep.errors.saturating_add(1),
        }
    }
    // 2. The store's quarantine, minimum age enforced.
    let quarantine_gate: Option<PurgeGate> = if rep.aborted {
        Some(Arc::new(|| false))
    } else {
        gate.clone()
    };
    let q = env
        .store
        .quarantine_purge_checked(
            now.saturating_sub(QUARANTINE_MIN_AGE_SECS),
            Some(deadline),
            quarantine_gate,
        )
        .await?;
    rep.removed = rep.removed.saturating_add(q.removed);
    rep.bytes = rep.bytes.saturating_add(q.bytes);
    rep.kept_recent = rep.kept_recent.saturating_add(q.kept_recent);
    rep.unmanaged = rep.unmanaged.saturating_add(q.skipped);
    rep.remaining = rep.remaining.saturating_add(q.remaining);
    rep.aborted = rep.aborted || q.aborted;
    // 3. Leftovers of a verified removal.
    let live = env.db.list_shas().await?;
    let dir = env.failed_dir.clone();
    let mut inner = PurgeReport::new(Bucket::Trash);
    inner.aborted = rep.aborted;
    let leftover_gate = gate.clone();
    let inner = tokio::task::spawn_blocking(move || {
        purge_leftovers(&dir, &live, deadline, leftover_gate.as_ref(), &mut inner);
        inner
    })
    .await
    .map_err(|e| join_err(&e))?;
    rep.removed = rep.removed.saturating_add(inner.removed);
    rep.bytes = rep.bytes.saturating_add(inner.bytes);
    rep.refused = rep.refused.saturating_add(inner.refused);
    rep.errors = rep.errors.saturating_add(inner.errors);
    rep.remaining = rep.remaining.saturating_add(inner.remaining);
    rep.aborted = rep.aborted || inner.aborted;
    Ok(rep)
}

/// Why a restore did not happen.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// No such trash record.
    #[error("no such deleted release")]
    NoSuchRelease,
    /// The record exists but its blob is gone (purged or lost).
    #[error("the NZB of this release is no longer in the trash")]
    BlobMissing,
    /// A release with this content is indexed again; the trash copy is redundant.
    #[error("this content is already indexed")]
    AlreadyIndexed,
    /// Storage or filesystem failure.
    #[error("{0}")]
    Cleanup(#[from] CleanupError),
}

/// Result of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// Name of the file now waiting in the watch folder.
    pub watch_name: String,
    /// First eight hex characters of the digest.
    pub sha8: String,
}

/// Restores deleted release `trash_id`: the NZB is written to the watch folder as
/// `restored-<sha8>[-N].nzb` (durable before anything else changes) and re-ingested through the
/// normal pipeline, which gives it a fresh release id and category. Then the trash record and
/// blob are dropped. A manual category override is not preserved.
///
/// # Errors
/// See [`RestoreError`].
pub async fn restore_to_watch(
    env: &CleanupEnv,
    watch_dir: &Path,
    trash_id: i64,
) -> Result<Restored, RestoreError> {
    let row = env
        .db
        .get_trash(trash_id)
        .await
        .map_err(CleanupError::from)?
        .ok_or(RestoreError::NoSuchRelease)?;
    if env
        .db
        .get_release_by_sha(&row.sha256.to_hex())
        .await
        .map_err(CleanupError::from)?
        .is_some()
    {
        return Err(RestoreError::AlreadyIndexed);
    }
    let bytes = match env.store.trash_read(&row.sha256).await {
        Ok(b) => b,
        Err(StoreError::NotFound) => return Err(RestoreError::BlobMissing),
        Err(e) => return Err(CleanupError::from(e).into()),
    };
    let sha = row.sha256;
    let short = sha8(&sha);
    let watch = watch_dir.to_path_buf();
    let stem = format!("restored-{short}");
    let name = tokio::task::spawn_blocking(move || write_restored(&watch, &stem, &bytes))
        .await
        .map_err(|e| join_err(&e))?
        .map_err(CleanupError::from)?;
    // The file is durable in watch/: only now drop the trash copy and its record.
    env.db
        .forget_trash(trash_id)
        .await
        .map_err(CleanupError::from)?;
    let _ = env.store.trash_purge(&sha).await;
    Ok(Restored {
        watch_name: name,
        sha8: short,
    })
}

/// Writes `bytes` to a hidden part file in `watch` (the scanner ignores hidden names), fsyncs
/// it, then publishes it under `<stem>[-N].nzb` without clobbering.
fn write_restored(watch: &Path, stem: &str, bytes: &[u8]) -> io::Result<String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let part = watch.join(format!(".{stem}.{}.part", unique_tag()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let res = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    let dest = match move_no_clobber(&part, watch, stem, None) {
        Ok(d) => d,
        Err(e) => {
            let _ = fs::remove_file(&part);
            return Err(e);
        }
    };
    Ok(dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trash_purge_propagates_quarantine_deadlines_and_authority_stops() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let backend = nzb_store::test_backend::TestStore::open(dir.path()).await;
        for policy in 0..3 {
            let root = dir.path().join(format!("store-{policy}"));
            let store = nzb_store::FsStore::open(&root).unwrap();
            let failed = dir.path().join(format!("failed-{policy}"));
            fs::create_dir(&failed).unwrap();
            let quarantine = root.join(".gc-trash");
            fs::create_dir(&quarantine).unwrap();
            let bytes = b"quarantined content";
            let sha = Sha256(Hasher::digest(bytes).into());
            let count = if policy == 2 { PURGE_BATCH + 3 } else { 1 };
            for counter in 0..count {
                fs::write(
                    quarantine.join(format!("{}.1.{counter}.trash", sha.to_hex())),
                    bytes,
                )
                .unwrap();
            }
            let env = CleanupEnv {
                db: backend.store.clone(),
                store: Arc::new(store),
                failed_dir: failed,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let gate: Option<PurgeGate> = match policy {
                0 => None,
                1 => Some(Arc::new(|| false)),
                _ => Some(Arc::new(move || {
                    observed.fetch_add(1, Ordering::SeqCst) == 0
                })),
            };
            let deadline = if policy == 0 {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(60)
            };
            let rep = purge_gated(
                &env,
                Bucket::Trash,
                QUARANTINE_MIN_AGE_SECS + 2,
                deadline,
                gate,
            )
            .await
            .unwrap();
            let removed = if policy == 2 { PURGE_BATCH } else { 0 };
            assert_eq!(rep.removed, removed, "policy {policy}");
            assert_eq!(rep.remaining, count - removed, "policy {policy}");
            assert_eq!(rep.aborted, policy != 0, "policy {policy}");
            assert_eq!(
                u64::try_from(fs::read_dir(&quarantine).unwrap().count()).unwrap(),
                count - removed
            );
            for entry in fs::read_dir(quarantine).unwrap() {
                assert_eq!(fs::read(entry.unwrap().path()).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn classification_table() {
        for code in [
            "NZB_DOCTYPE_FORBIDDEN",
            "NZB_NOT_UTF8",
            "FILE_TOO_LARGE",
            "INVALID_CATEGORY",
            "NZB_LIMIT_FILE_BYTES",
            "NZB_LIMIT_XML_DEPTH",
            "NZB_LIMIT_FILES",
            "NZB_LIMIT_SEGMENTS_PER_FILE",
            "NZB_LIMIT_TOTAL_SEGMENTS",
            "NZB_LIMIT_SEGMENT_BYTES",
            "NZB_LIMIT_TOTAL_BYTES",
            "NZB_LIMIT_SUBJECT_BYTES",
            "NZB_LIMIT_POSTER_BYTES",
            "NZB_LIMIT_GROUP_BYTES",
            "NZB_LIMIT_GROUPS_PER_FILE",
            "NZB_LIMIT_MESSAGE_ID_BYTES",
            "NZB_LIMIT_META_ENTRIES",
            "NZB_LIMIT_META_VALUE_BYTES",
        ] {
            assert_eq!(classify(Some(code)), Bucket::Blocked, "{code}");
        }
        for code in [
            "NZB_EMPTY",
            "NZB_TIMEOUT",
            "NZB_MALFORMED",
            "SOURCE_CHANGED",
            "SOURCE_UNREADABLE",
            "STORAGE_ERROR",
            "INTERNAL",
            "QUEUE_FULL",
            "SHUTTING_DOWN",
            // Unknown and near-miss codes are Failed, never Blocked.
            "SOMETHING_NEW",
            "",
            "nzb_limit_files",
            "NZB_LIMIT_",
            "NZB_LIMIT_x",
            "NZB_LIMITS",
            "FILE_TOO_LARGE ",
            "NZB_DOCTYPE_FORBIDDEN_",
        ] {
            assert_eq!(classify(Some(code)), Bucket::Failed, "{code:?}");
        }
        assert_eq!(classify(None), Bucket::Failed);
    }

    #[test]
    fn bucket_slugs_round_trip() {
        for b in Bucket::ALL {
            assert_eq!(Bucket::parse(b.slug()), Some(b));
        }
        for bad in ["", "Trash", "all", "trash ", "failed/", "../failed"] {
            assert_eq!(Bucket::parse(bad), None);
        }
    }
}
