//! Content-addressed NZB blob store (`NzbStore`) and its filesystem implementation (`FsStore`).
//!
//! Layout: `<root>/aa/bb/<sha256>.nzb` where `aa`/`bb` are the first two hex byte pairs of the
//! digest. Every path is derived from the validated [`Sha256`] newtype only (SEC-005); no
//! NZB-provided string ever reaches this module.
//!
//! Write protocol (SEC-008): create `<root>/.tmp/<unique>.tmp` (0600, `create_new`) -> write ->
//! `fsync(file)` -> `rename` into place -> `fsync(parent dir)`. A reader can therefore only ever
//! observe a complete blob under its final name; a crash leaves at most a stale file in `.tmp/`,
//! which is removed by [`FsStore::open`]. The temp directory lives inside the store root so that
//! `rename` is always same-filesystem and atomic.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use nzb_core::Sha256;
use sha2::{Digest, Sha256 as Hasher};

use crate::StoreError;

mod trash;

const TMP_DIR: &str = ".tmp";
/// GC quarantine (`SECURITY_REVIEW` T032 M2): reclaimed blobs are moved here, never unlinked.
const GC_TRASH_DIR: &str = ".gc-trash";
/// Quarantine of `nzbd store migrate --to db --finalize`: verified file copies are moved here
/// (never unlinked) once their content is safe in the database. Only an operator removes them.
pub const MIGRATED_DIR: &str = "migrated";
const EXT: &str = "nzb";

/// Result of [`NzbStore::put`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The blob was written by this call.
    Created,
    /// A blob with this SHA-256 was already present; nothing was written.
    AlreadyExists,
}

/// Storage for raw NZB bytes, addressed by SHA-256.
#[async_trait]
pub trait NzbStore: Send + Sync {
    /// Stores `bytes` under `sha`. Idempotent. Fails with `HashMismatch` if `bytes` do not hash to `sha`.
    async fn put(&self, sha: Sha256, bytes: &[u8]) -> Result<PutOutcome, StoreError>;
    /// Returns the stored bytes, or `NotFound`.
    async fn get(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError>;
    /// Whether a blob exists.
    async fn exists(&self, sha: &Sha256) -> Result<bool, StoreError>;
    /// Removes a blob. **GC only** — user NZBs are never deleted automatically. Missing blob is `Ok`.
    async fn delete(&self, sha: &Sha256) -> Result<(), StoreError>;
}

/// Outcome of [`FsStore::verify`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Blobs whose content hashes to their name.
    pub ok: u64,
    /// Blobs whose content does not match their address (never modified by verify).
    pub corrupt: Vec<Sha256>,
    /// Entries in the store that are not valid blobs (wrong name, wrong directory, symlink, ...).
    pub unexpected: u64,
    /// The pass stopped at its deadline before reaching every blob (database backend only).
    pub incomplete: bool,
}

/// Outcome of [`FsStore::gc`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Unreferenced blobs that were (or, with `dry_run`, would be) removed.
    pub removed: Vec<Sha256>,
    /// Blobs kept because they are referenced.
    pub kept: u64,
    /// Unreferenced blobs kept because they are newer than the grace cutoff.
    pub too_new: u64,
}

/// An unreferenced blob old enough for GC, with the timestamps used by the stale-database
/// heuristics of `nzbd store gc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcCandidate {
    /// Blob digest.
    pub sha: Sha256,
    /// Size in bytes.
    pub size: u64,
    /// Modification time (Unix seconds; `put` refreshes it).
    pub mtime: i64,
    /// Status-change time (Unix seconds). `cp -p`/rsync restores keep the old mtime but get a
    /// fresh ctime, which is how a restored store is recognised.
    pub ctime: i64,
}

/// Result of one GC removal attempt.
enum Removal {
    Removed,
    /// Re-adopted or referenced in the meantime; restored.
    Wanted,
    /// Already gone.
    Gone,
}

/// Crash points of the write protocol (fault injection hooks are compiled in tests only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    TmpCreated,
    Written,
    FileSynced,
    Renamed,
}

/// Default refusal threshold of [`FsStore::get`]: twice the hard `limits.max_file_bytes` ceiling
/// (64 MiB). A stored blob is one accepted NZB (<= `max_file_bytes`), so anything bigger was put
/// there by someone else; `nzbd` lowers it to `2 * limits.max_file_bytes` via
/// [`FsStore::set_max_blob_bytes`].
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 2 * 64 * 1024 * 1024;

struct Inner {
    root: PathBuf,
    counter: AtomicU64,
    max_blob_bytes: AtomicU64,
    #[cfg(test)]
    crash_at: std::sync::Mutex<Option<Step>>,
}

/// Filesystem-backed [`NzbStore`]. Cheap to clone.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for FsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsStore")
            .field("root", &self.inner.root)
            .finish()
    }
}

impl FsStore {
    /// Opens (creating if needed, mode 0700) the store at `root` and removes stale temp files
    /// left by a previous crash.
    ///
    /// # Errors
    /// I/O errors creating directories or cleaning `.tmp/`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let store = Self::open_passive(root)?;
        store.clean_tmp()?;
        Ok(store)
    }

    /// Like [`FsStore::open`] but **does not touch `.tmp/`**: use it for CLI commands and any
    /// second handle on a store that another process (`serve`) may be using, because cleaning
    /// would delete that process's in-flight `put` files and GC quarantine files
    /// (`SECURITY_REVIEW` T032 L1).
    ///
    /// # Errors
    /// I/O errors creating directories.
    pub fn open_passive(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        // The root itself is operator-configured and may legitimately be a symlink (bind
        // mounts, /data -> volume); everything below it must be a real directory.
        if !root.is_dir() {
            ensure_dir(&root)?;
        }
        ensure_dir(&root.join(TMP_DIR))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                counter: AtomicU64::new(0),
                max_blob_bytes: AtomicU64::new(DEFAULT_MAX_BLOB_BYTES),
                #[cfg(test)]
                crash_at: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Sets the size above which `get` refuses a blob with [`StoreError::Corrupt`] before
    /// reading it (T061 L-5; a tampered store must not be able to exhaust memory).
    pub fn set_max_blob_bytes(&self, max: u64) {
        self.inner.max_blob_bytes.store(max, Ordering::Relaxed);
    }

    /// Startup cleanup of `.tmp/`: stale `put` files are removed; a GC quarantine file
    /// (`gc-<sha>.<pid>.<n>.trash`, a blob whose removal was decided but not finished) is
    /// **restored** to its blob path when that is free and its content still hashes to its
    /// name (it may have been re-adopted by a racing `put`), and removed only when the blob
    /// is already back. Private on purpose: it would delete the temp files of in-flight
    /// `put`s, so it may only run from [`FsStore::open`], before the store is shared.
    fn clean_tmp(&self) -> Result<u64, StoreError> {
        let mut n = 0u64;
        for entry in fs::read_dir(self.inner.root.join(TMP_DIR))? {
            let entry = entry?;
            // remove_file does not follow symlinks; a directory here is foreign and left alone.
            if entry.file_type()?.is_dir() {
                continue;
            }
            if let Some(sha) = parse_gc_trash_name(&entry.file_name()) {
                let dest = match self.checked_blob_path(&sha) {
                    Ok(d) => d,
                    // A shard directory replaced by a symlink (or another non-directory): never
                    // restore through it, and do not let one foreign entry stop the store from
                    // opening (review 55). The scratch copy stays in `.tmp/` for the next start.
                    Err(StoreError::Corrupt) => continue,
                    Err(e) => return Err(e),
                };
                if is_regular(&dest) {
                    fs::remove_file(entry.path())?;
                } else if entry.file_type()?.is_file()
                    && hash_file(&entry.path()).is_ok_and(|h| h == sha)
                {
                    if let Some(parent) = dest.parent() {
                        if let Some(grand) = parent.parent() {
                            ensure_dir(grand)?;
                        }
                        ensure_dir(parent)?;
                    }
                    fs::rename(entry.path(), &dest)?;
                    if let Some(p) = dest.parent() {
                        sync_dir(p)?;
                    }
                } else {
                    // Unverifiable: keep it out of the way, but never delete it.
                    self.move_to_gc_trash(&entry.path(), &sha)?;
                }
                n = n.saturating_add(1);
                continue;
            }
            fs::remove_file(entry.path())?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    /// Moves `from` into the quarantine as `<sha>.<unix-ts>.trash`.
    fn move_to_gc_trash(&self, from: &Path, sha: &Sha256) -> Result<(), StoreError> {
        let dir = self.inner.root.join(GC_TRASH_DIR);
        ensure_dir(&dir)?;
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed);
        fs::rename(from, dir.join(format!("{}.{ts}.{n}.trash", sha.to_hex())))?;
        sync_dir(&dir)?;
        Ok(())
    }

    /// Moves the blob into `migrated/` as `<sha>.nzb` (`<sha>.<n>.nzb` when that name is taken):
    /// an atomic same-filesystem rename, never an unlink or an overwrite. Returns `false` when
    /// there was no blob. Used by `store migrate --finalize` after the content was verified in
    /// the database.
    ///
    /// # Errors
    /// I/O errors.
    pub fn move_to_migrated(&self, sha: &Sha256) -> Result<bool, StoreError> {
        let from = self.checked_blob_path(sha)?;
        if !is_regular(&from) {
            return Ok(false);
        }
        let dir = self.inner.root.join(MIGRATED_DIR);
        if ensure_dir(&dir)? {
            sync_dir(&self.inner.root)?;
        }
        let hex = sha.to_hex();
        let mut dest = dir.join(format!("{hex}.{EXT}"));
        let mut n = 0u32;
        // `hard_link` + unlink would be two steps; `rename` over a *free* name is one, so look for
        // a free name first. The probe/rename window only matters with two concurrent finalizers.
        while fs::symlink_metadata(&dest).is_ok() {
            n = n.saturating_add(1);
            dest = dir.join(format!("{hex}.{n}.{EXT}"));
        }
        match fs::rename(&from, &dest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        sync_dir(&dir)?;
        if let Some(p) = from.parent() {
            sync_dir(p)?;
        }
        Ok(true)
    }

    /// Entries of the GC quarantine as `(sha, unix ts, path)`.
    fn gc_trash_entries(&self) -> Result<Vec<(Sha256, i64, PathBuf)>, StoreError> {
        let dir = self.inner.root.join(GC_TRASH_DIR);
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e?;
            if !e.file_type()?.is_file() {
                continue;
            }
            let name = e.file_name();
            let mut parts = name.to_str().unwrap_or_default().split('.');
            let (Some(hex), Some(ts), Some(_n), Some("trash"), None) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                continue;
            };
            if let (Ok(sha), Ok(ts)) = (Sha256::from_hex(hex), ts.parse::<i64>()) {
                out.push((sha, ts, e.path()));
            }
        }
        out.sort_by(|a, b| a.2.cmp(&b.2));
        Ok(out)
    }

    /// Number of blobs in the GC quarantine.
    ///
    /// # Errors
    /// I/O errors.
    pub fn gc_trash_len(&self) -> Result<usize, StoreError> {
        Ok(self.gc_trash_entries()?.len())
    }

    /// Puts quarantined blobs back (those whose blob path is free and whose content still
    /// hashes to its name). Returns how many were restored.
    ///
    /// # Errors
    /// I/O errors.
    pub fn restore_gc_trash(&self) -> Result<usize, StoreError> {
        let mut n = 0usize;
        for (sha, _, path) in self.gc_trash_entries()? {
            let dest = self.checked_blob_path(&sha)?;
            // A blob that cannot be hashed is not verified, so it stays in quarantine.
            if is_regular(&dest) || !hash_file(&path).is_ok_and(|h| h == sha) {
                continue;
            }
            if let Some(parent) = dest.parent() {
                if let Some(grand) = parent.parent() {
                    ensure_dir(grand)?;
                }
                ensure_dir(parent)?;
            }
            // `rename` would replace a blob that appeared meanwhile; a hard link cannot.
            if fs::hard_link(&path, &dest).is_ok() {
                fs::remove_file(&path)?;
                if let Some(p) = dest.parent() {
                    sync_dir(p)?;
                }
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Permanently deletes quarantined blobs that were quarantined before `older_than`. This
    /// is the only place GC data is ever destroyed; it is never called at startup.
    ///
    /// # Errors
    /// I/O errors.
    pub fn purge_gc_trash(&self, older_than: SystemTime) -> Result<usize, StoreError> {
        let cutoff = older_than
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0);
        let mut n = 0usize;
        for (_, ts, path) in self.gc_trash_entries()? {
            if ts < cutoff {
                fs::remove_file(path)?;
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Unreferenced blobs older than `cutoff`, with their timestamps (what a non-dry
    /// [`FsStore::gc_checked`] would quarantine).
    ///
    /// # Errors
    /// I/O errors while walking.
    pub fn gc_candidates(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
    ) -> Result<Vec<GcCandidate>, StoreError> {
        use std::os::unix::fs::MetadataExt;
        let mut out = Vec::new();
        let mut unexpected = 0u64;
        self.walk(
            &mut |sha, path| {
                if referenced.contains(&sha) {
                    return Ok(());
                }
                let m = fs::metadata(path)?;
                if m.modified()? < cutoff {
                    out.push(GcCandidate {
                        sha,
                        size: m.len(),
                        mtime: m.mtime(),
                        ctime: m.ctime(),
                    });
                }
                Ok(())
            },
            &mut unexpected,
        )?;
        Ok(out)
    }

    /// Final path of a blob; derived from the digest only (charset `[0-9a-f]`).
    pub(crate) fn blob_path(&self, sha: &Sha256) -> PathBuf {
        let hex = sha.to_hex();
        let a = hex.get(0..2).unwrap_or_default();
        let b = hex.get(2..4).unwrap_or_default();
        self.inner.root.join(a).join(b).join(format!("{hex}.{EXT}"))
    }

    /// Refuses symbolic links in either shard directory, including the dedup/read paths
    /// that do not create directories. The operator-configured root may itself be a link.
    fn checked_blob_path(&self, sha: &Sha256) -> Result<PathBuf, StoreError> {
        let hex = sha.to_hex();
        let first = self.inner.root.join(hex.get(..2).unwrap_or_default());
        let second = first.join(hex.get(2..4).unwrap_or_default());
        for dir in [&first, &second] {
            match fs::symlink_metadata(dir) {
                Ok(m) if m.file_type().is_dir() => {}
                Ok(_) => return Err(StoreError::Corrupt),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(self.blob_path(sha))
    }

    #[cfg(test)]
    pub(crate) fn set_crash_point(&self, step: Option<Step>) {
        if let Ok(mut g) = self.inner.crash_at.lock() {
            *g = step;
        }
    }

    #[cfg(test)]
    fn crash(&self, step: Step) -> Result<(), StoreError> {
        let hit = self.inner.crash_at.lock().is_ok_and(|g| *g == Some(step));
        if hit {
            Err(StoreError::Injected)
        } else {
            Ok(())
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn crash(&self, _step: Step) -> Result<(), StoreError> {
        Ok(())
    }

    fn put_blocking(&self, sha: &Sha256, bytes: &[u8]) -> Result<PutOutcome, StoreError> {
        if digest(bytes) != *sha {
            return Err(StoreError::HashMismatch);
        }
        let dest = self.checked_blob_path(sha)?;
        if refresh_existing(&dest, sha, bytes.len())? {
            return Ok(PutOutcome::AlreadyExists);
        }
        let parent = dest
            .parent()
            .ok_or_else(|| std::io::Error::other("no parent"))?;
        let grand = parent
            .parent()
            .ok_or_else(|| std::io::Error::other("no parent"))?;
        if ensure_dir(grand)? {
            sync_dir(&self.inner.root)?;
        }
        if ensure_dir(parent)? {
            sync_dir(grand)?;
        }
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed);
        let tmp = self.inner.root.join(TMP_DIR).join(format!(
            "{}.{}.{n}.tmp",
            sha.to_hex(),
            std::process::id()
        ));
        let res = self.write_and_publish(&tmp, &dest, parent, bytes);
        if let Err(e) = &res {
            // A simulated crash must leave the tmp file exactly as a kill would.
            if !is_injected(e) {
                let _ = fs::remove_file(&tmp);
            }
        }
        res.map(|()| PutOutcome::Created)
    }

    fn write_and_publish(
        &self,
        tmp: &Path,
        dest: &Path,
        parent: &Path,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let mut f = open_new(tmp)?;
        self.crash(Step::TmpCreated)?;
        f.write_all(bytes)?;
        self.crash(Step::Written)?;
        f.sync_all()?;
        drop(f);
        self.crash(Step::FileSynced)?;
        fs::rename(tmp, dest)?;
        self.crash(Step::Renamed)?;
        sync_dir(parent)?;
        Ok(())
    }

    fn get_blocking(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
        let Some(mut f) = open_regular_nofollow(&self.checked_blob_path(sha)?, false)? else {
            return Err(StoreError::NotFound);
        };
        // Size cap before any read (T061 L-5), then a bounded read in case the file grows meanwhile.
        let max = self.inner.max_blob_bytes.load(Ordering::Relaxed);
        if f.metadata()?.len() > max {
            return Err(StoreError::Corrupt);
        }
        let mut v = Vec::new();
        (&mut f).take(max.saturating_add(1)).read_to_end(&mut v)?;
        if !u64::try_from(v.len()).is_ok_and(|n| n <= max) {
            return Err(StoreError::Corrupt);
        }
        // The blob is served to the user as-is: never hand out bytes that do not match the
        // address (bit rot, tampering) as if they were the original NZB.
        if digest(&v) != *sha {
            return Err(StoreError::Corrupt);
        }
        Ok(v)
    }

    fn delete_blocking(&self, sha: &Sha256) -> Result<(), StoreError> {
        let path = self.checked_blob_path(sha)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if let Some(p) = path.parent() {
            sync_dir(p)?;
        }
        Ok(())
    }

    /// Returns the subset of `shas` that has no blob on disk (the quick startup check: every
    /// blob referenced by a release row must exist).
    ///
    /// # Errors
    /// Never fails on a missing file; reserved for future backends.
    pub fn missing(
        &self,
        shas: impl IntoIterator<Item = Sha256>,
    ) -> Result<Vec<Sha256>, StoreError> {
        Ok(shas
            .into_iter()
            .filter(|s| !self.checked_blob_path(s).is_ok_and(|p| is_regular(&p)))
            .collect())
    }

    /// Walks the store and re-hashes every blob. Read-only: corrupt blobs are reported, never
    /// modified or removed.
    ///
    /// # Errors
    /// I/O errors while walking or reading.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut rep = VerifyReport::default();
        self.walk(
            &mut |sha, path| {
                match hash_file(path) {
                    Ok(d) if d == sha => rep.ok = rep.ok.saturating_add(1),
                    Ok(_) => rep.corrupt.push(sha),
                    Err(e) => return Err(e),
                }
                Ok(())
            },
            &mut rep.unexpected,
        )?;
        Ok(rep)
    }

    /// Quarantines (moves to `.gc-trash/`, see [`FsStore::purge_gc_trash`]) blobs not in
    /// `referenced` whose mtime is before `cutoff`. The cutoff is a grace
    /// period protecting a blob that `put` just wrote but whose row is not yet committed
    /// (`INGEST_SPEC`: store file exists before the DB row). With `dry_run` nothing is removed.
    ///
    /// # Errors
    /// I/O errors while walking or removing.
    pub fn gc(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StoreError> {
        self.gc_checked(referenced, cutoff, dry_run, &|_| true)
    }

    /// [`FsStore::gc`] with a last-moment veto. `still_unreferenced(sha)` is called for every
    /// blob right before it is removed (callers re-query the release table; get the full set with
    /// `SqliteDb::list_shas`) and must return `false` if a release now references the blob.
    ///
    /// Race safety (SEC-008): a dedup `put` may re-adopt an old unreferenced blob after the
    /// walk. `put` refreshes the blob's mtime, and GC first *renames* the blob into `.tmp/`
    /// (atomic), then re-checks mtime and `still_unreferenced`, and only then unlinks; if
    /// either check says the blob is wanted its live name is restored without overwriting.
    /// A `put` that arrives after the rename simply writes a fresh blob.
    ///
    /// # Errors
    /// I/O errors while walking or removing.
    pub fn gc_checked(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
        dry_run: bool,
        still_unreferenced: &dyn Fn(&Sha256) -> bool,
    ) -> Result<GcReport, StoreError> {
        let mut rep = GcReport::default();
        let mut unexpected = 0u64;
        let mut doomed: Vec<(Sha256, PathBuf)> = Vec::new();
        self.walk(
            &mut |sha, path| {
                if referenced.contains(&sha) {
                    rep.kept = rep.kept.saturating_add(1);
                } else if fs::metadata(path)?.modified()? < cutoff {
                    doomed.push((sha, path.to_path_buf()));
                } else {
                    rep.too_new = rep.too_new.saturating_add(1);
                }
                Ok(())
            },
            &mut unexpected,
        )?;
        for (sha, path) in doomed {
            if !dry_run {
                match self.remove_if_still_doomed(&sha, &path, cutoff, still_unreferenced)? {
                    Removal::Removed => {}
                    Removal::Wanted => {
                        rep.too_new = rep.too_new.saturating_add(1);
                        continue;
                    }
                    Removal::Gone => continue,
                }
            }
            rep.removed.push(sha);
        }
        Ok(rep)
    }

    /// Quarantine-then-verify removal; see [`FsStore::gc_checked`].
    fn remove_if_still_doomed(
        &self,
        sha: &Sha256,
        path: &Path,
        cutoff: SystemTime,
        still_unreferenced: &dyn Fn(&Sha256) -> bool,
    ) -> Result<Removal, StoreError> {
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed);
        let trash = self.inner.root.join(TMP_DIR).join(format!(
            "gc-{}.{}.{n}.trash",
            sha.to_hex(),
            std::process::id()
        ));
        match fs::rename(path, &trash) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Removal::Gone),
            Err(e) => return Err(e.into()),
        }
        // Decided only now that the blob is out of reach of concurrent `put`s.
        let old_enough = fs::symlink_metadata(&trash)
            .and_then(|m| m.modified())
            .is_ok_and(|m| m < cutoff);
        if !old_enough || !still_unreferenced(sha) {
            match fs::hard_link(&trash, path) {
                Ok(()) => fs::remove_file(&trash)?,
                // A racing put may have repaired corrupt bytes. Never overwrite its live
                // name with the old inode; preserve that inode in quarantine instead.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.move_to_gc_trash(&trash, sha)?;
                }
                // A filesystem without hard links (review 55): fall back to a rename over a
                // free name, like `backup_crypto::publish_no_clobber`. The check-then-rename
                // window is the same accepted one; a name already taken keeps the live blob.
                Err(e) if hard_link_unsupported(&e) => {
                    if fs::symlink_metadata(path).is_ok() {
                        self.move_to_gc_trash(&trash, sha)?;
                    } else {
                        fs::rename(&trash, path)?;
                    }
                }
                // Leave the scratch copy for startup recovery if restoration fails.
                Err(e) => return Err(e.into()),
            }
            if let Some(p) = path.parent() {
                sync_dir(p)?;
            }
            sync_dir(&self.inner.root.join(TMP_DIR))?;
            return Ok(Removal::Wanted);
        }
        // Quarantine, do not destroy: the blob may be the only copy of an NZB if the database
        // is stale (restored from a backup). `purge_gc_trash` is the only way it goes away.
        self.move_to_gc_trash(&trash, sha)?;
        if let Some(p) = path.parent() {
            sync_dir(p)?;
        }
        sync_dir(&self.inner.root.join(TMP_DIR))?;
        Ok(Removal::Removed)
    }

    /// Calls `f(sha, path)` for every well-formed blob; counts everything else in `unexpected`.
    /// Well-formed = regular file `aa/bb/<64 hex>.nzb` whose name matches its directories.
    fn walk(
        &self,
        f: &mut dyn FnMut(Sha256, &Path) -> Result<(), StoreError>,
        unexpected: &mut u64,
    ) -> Result<(), StoreError> {
        let bump = |u: &mut u64| *u = u.saturating_add(1);
        for e1 in fs::read_dir(&self.inner.root)? {
            let e1 = e1?;
            let name1 = e1.file_name();
            if name1 == TMP_DIR
                || name1 == GC_TRASH_DIR
                || name1 == MIGRATED_DIR
                || name1 == trash::TRASH_DIR
            {
                continue;
            }
            if !e1.file_type()?.is_dir() || !is_hex_pair(&name1) {
                bump(unexpected);
                continue;
            }
            for e2 in fs::read_dir(e1.path())? {
                let e2 = e2?;
                let name2 = e2.file_name();
                if !e2.file_type()?.is_dir() || !is_hex_pair(&name2) {
                    bump(unexpected);
                    continue;
                }
                for e3 in fs::read_dir(e2.path())? {
                    let e3 = e3?;
                    let path = e3.path();
                    let sha = e3
                        .file_type()?
                        .is_file()
                        .then(|| parse_blob_name(&e3.file_name()))
                        .flatten()
                        .filter(|s| self.blob_path(s) == path);
                    match sha {
                        Some(s) => f(s, &path)?,
                        None => bump(unexpected),
                    }
                }
            }
        }
        Ok(())
    }
}

fn join_err(e: &tokio::task::JoinError) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

#[async_trait]
impl NzbStore for FsStore {
    async fn put(&self, sha: Sha256, bytes: &[u8]) -> Result<PutOutcome, StoreError> {
        let this = self.clone();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || this.put_blocking(&sha, &bytes))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn get(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || this.get_blocking(&sha))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn exists(&self, sha: &Sha256) -> Result<bool, StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || {
            this.checked_blob_path(&sha).is_ok_and(|p| is_regular(&p))
        })
        .await
        .map_err(|e| join_err(&e))
    }

    async fn delete(&self, sha: &Sha256) -> Result<(), StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || this.delete_blocking(&sha))
            .await
            .map_err(|e| join_err(&e))?
    }
}

#[cfg(test)]
fn is_injected(e: &StoreError) -> bool {
    matches!(e, StoreError::Injected)
}
#[cfg(not(test))]
fn is_injected(_e: &StoreError) -> bool {
    false
}

pub(crate) fn digest(bytes: &[u8]) -> Sha256 {
    let mut h = Hasher::new();
    h.update(bytes);
    Sha256(h.finalize().into())
}

/// Opens `path` without following a symlink in the last component and returns the handle only
/// if it is a regular file (checked with `fstat` on the handle, so there is no check-then-open
/// window). `None` for a missing file, a symlink or a non-regular file.
fn open_regular_nofollow(path: &Path, write: bool) -> Result<Option<File>, StoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = OpenOptions::new();
    o.read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);
    match o.open(path) {
        Ok(f) => Ok(f.metadata()?.file_type().is_file().then_some(f)),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ELOOP) =>
        {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Dedup path of `put`: refresh only a verified blob. A damaged blob, including same-size
/// corruption, must be atomically repaired before the caller discards its incoming copy.
/// The refresh protects the blob from a concurrent GC for the grace period (SEC-008); the
/// re-check afterwards covers GC having quarantined it in between.
fn refresh_existing(dest: &Path, sha: &Sha256, len: usize) -> Result<bool, StoreError> {
    let Some(mut f) = open_regular_nofollow(dest, true)? else {
        return Ok(false);
    };
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    if f.metadata()?.len() != len || hash_reader((&mut f).take(len.saturating_add(1)))? != *sha {
        return Ok(false);
    }
    f.set_modified(SystemTime::now())?;
    drop(f);
    Ok(is_regular(dest))
}

fn hash_file(path: &Path) -> Result<Sha256, StoreError> {
    let Some(f) = open_regular_nofollow(path, false)? else {
        return Err(StoreError::NotFound);
    };
    hash_reader(f)
}

fn hash_reader(mut f: impl Read) -> Result<Sha256, StoreError> {
    let mut h = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(Sha256(h.finalize().into()))
}

/// Regular file, not following symlinks.
/// The `hard_link` errors of a filesystem that has no hard links (FAT, some FUSE and network
/// mounts), as opposed to a real failure.
pub(crate) fn hard_link_unsupported(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPERM | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

fn is_regular(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

fn is_hex_pair(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|s| {
        s.len() == 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `gc-<64 hex>.<pid>.<n>.trash` -> the digest.
fn parse_gc_trash_name(name: &std::ffi::OsStr) -> Option<Sha256> {
    let rest = name.to_str()?.strip_prefix("gc-")?;
    let (hex, tail) = rest.split_once('.')?;
    tail.strip_suffix(".trash")?;
    Sha256::from_hex(hex).ok()
}

fn parse_blob_name(name: &std::ffi::OsStr) -> Option<Sha256> {
    let stem = name.to_str()?.strip_suffix(".nzb")?;
    Sha256::from_hex(stem).ok()
}

/// Creates a directory with mode 0700 if absent; returns whether it was created.
fn ensure_dir(p: &Path) -> Result<bool, StoreError> {
    if fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
        return Ok(false);
    }
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    match b.create(p) {
        Ok(()) => Ok(true),
        // Lost a race with another creator: accept only a real directory, never a symlink to one.
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                && fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// Exclusive-create a 0600 file (never reuses or follows an existing path).
fn open_new(p: &Path) -> Result<File, StoreError> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(p)?)
}

/// Durably records directory entry changes.
fn sync_dir(p: &Path) -> Result<(), StoreError> {
    File::open(p)?.sync_all()?;
    Ok(())
}
