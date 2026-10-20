//! Trash area of the filesystem store (T081): `<root>/.trash/<sha256>.nzb`.
//!
//! A child module of `fs_store` so it can use the store's private helpers; everything here is
//! additive and does not change the `put`/`get`/`gc` protocols.
//!
//! Invariants:
//! * Every path is derived from a validated [`Sha256`] or from a directory listing filtered by
//!   an exact name grammar; no caller-provided string is joined to a path.
//! * Staging never moves the blob: it adds a hard link (or, on filesystems without links, a
//!   verified copy). The live name is dropped only afterwards ([`FsStore::trash_finish_blocking`]),
//!   through a rename into `.tmp/` and a re-check, like the GC protocol.
//! * Destroying anything goes through [`remove_verified`]: the file is opened without following
//!   symlinks and without blocking, must be a regular file with one link, and is unlinked only
//!   if it is still the very same inode after being renamed out of reach.

use std::fs::{self, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use nzb_core::Sha256;
use sha2::{Digest, Sha256 as Hasher};

use super::{
    EXT, FsStore, GC_TRASH_DIR, TMP_DIR, digest, ensure_dir, hash_file, is_regular, join_err,
    open_new, open_regular_nofollow, sync_dir,
};
use crate::StoreError;
use crate::trash::{
    QuarantineBlob, QuarantineListing, QuarantinePurge, StillUnreferenced, TrashBlob, TrashFinish,
    TrashListing, TrashPurge, TrashStore,
};

/// Name of the trash directory inside the store root.
pub const TRASH_DIR: &str = ".trash";
/// Safety bound for directory walks.
const MAX_ENTRIES: usize = 100_000;

/// Identity of an opened file: inode, size and mtime (`ctime` moves with renames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ident {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

fn ident(m: &Metadata) -> Ident {
    Ident {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
    }
}

/// Outcome of [`open_plain`].
enum Plain {
    Absent,
    /// Symlink, FIFO, directory or device.
    Refused,
    /// Regular file with more than one link (the metadata is of that file).
    Linked(Box<Metadata>),
    File(Box<Metadata>),
}

/// Opens `path` `O_NOFOLLOW|O_NONBLOCK`, checks through the descriptor that it is a regular
/// file with exactly one link, and returns its metadata. The handle itself is dropped: only
/// the identity is needed for the verified unlink.
fn open_plain(path: &Path) -> Result<Plain, StoreError> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Plain::Absent),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(Plain::Refused),
        Err(e) => return Err(e.into()),
    };
    let m = f.metadata()?;
    if !m.file_type().is_file() {
        return Ok(Plain::Refused);
    }
    if m.nlink() != 1 {
        return Ok(Plain::Linked(Box::new(m)));
    }
    Ok(Plain::File(Box::new(m)))
}

impl FsStore {
    fn trash_dir(&self) -> std::path::PathBuf {
        self.inner.root.join(TRASH_DIR)
    }

    fn trash_path(&self, sha: &Sha256) -> std::path::PathBuf {
        self.trash_dir().join(format!("{}.{EXT}", sha.to_hex()))
    }

    fn scratch_name(&self, what: &str, sha: &Sha256) -> std::path::PathBuf {
        let n = self.inner.counter.fetch_add(1, Ordering::Relaxed);
        self.inner.root.join(TMP_DIR).join(format!(
            "{what}-{}.{}.{n}.tmp",
            sha.to_hex(),
            std::process::id()
        ))
    }

    /// Unlinks `path` only if it is still the file whose metadata is `opened`.
    fn remove_verified(
        &self,
        path: &Path,
        opened: &Metadata,
        sha: &Sha256,
        needs_other_link: bool,
    ) -> Result<bool, StoreError> {
        let want = ident(opened);
        let Ok(now) = fs::symlink_metadata(path) else {
            return Ok(false);
        };
        if !now.file_type().is_file() || ident(&now) != want {
            return Ok(false);
        }
        let scratch = self.scratch_name("purge", sha);
        match fs::rename(path, &scratch) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        let moved = fs::symlink_metadata(&scratch)?;
        // `needs_other_link`: the name is only a second name of a live blob. If that other
        // name vanished meanwhile this would be the last copy: put it back.
        let sole = needs_other_link && moved.nlink() < 2;
        if moved.file_type().is_file() && ident(&moved) == want && !sole {
            fs::remove_file(&scratch)?;
            if let Some(p) = path.parent() {
                sync_dir(p)?;
            }
            return Ok(true);
        }
        // Someone swapped a different file in between the checks: put it back, never delete it.
        fs::hard_link(&scratch, path)?;
        fs::remove_file(&scratch)?;
        Ok(false)
    }

    fn trash_stage_blocking(&self, sha: &Sha256) -> Result<(), StoreError> {
        let live = self.checked_blob_path(sha)?;
        let Some(mut src) = open_regular_nofollow(&live, false)? else {
            return Err(StoreError::NotFound);
        };
        let dir = self.trash_dir();
        ensure_dir(&dir)?;
        let dest = self.trash_path(sha);
        match fs::hard_link(&live, &dest) {
            Ok(()) => {}
            // Idempotent: an earlier (crashed or repeated) delete already staged it.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            // No hard links on this filesystem: verified copy, published without clobbering.
            Err(_) => {
                let tmp = self.scratch_name("trash", sha);
                let res = (|| -> Result<(), StoreError> {
                    let mut out = open_new(&tmp)?;
                    let mut h = Hasher::new();
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = src.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        let chunk = buf.get(..n).unwrap_or_default();
                        h.update(chunk);
                        out.write_all(chunk)?;
                    }
                    out.sync_all()?;
                    if Sha256(h.finalize().into()) != *sha {
                        return Err(StoreError::Corrupt);
                    }
                    if is_regular(&dest) {
                        return Ok(());
                    }
                    fs::rename(&tmp, &dest)?;
                    Ok(())
                })();
                let _ = fs::remove_file(&tmp);
                res?;
            }
        }
        sync_dir(&dir)?;
        Ok(())
    }

    fn trash_finish_blocking(
        &self,
        sha: &Sha256,
        started_at: SystemTime,
        still_unreferenced: &(dyn Fn(&Sha256) -> bool + Send + Sync),
    ) -> Result<TrashFinish, StoreError> {
        let live = self.checked_blob_path(sha)?;
        let tpath = self.trash_path(sha);
        // The trash copy must exist and be a regular file before the live name may go.
        let tmeta = match fs::symlink_metadata(&tpath) {
            Ok(m) if m.file_type().is_file() => m,
            Ok(_) => return Err(StoreError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound);
            }
            Err(e) => return Err(e.into()),
        };
        let lmeta = match fs::symlink_metadata(&live) {
            Ok(m) if m.file_type().is_file() => m,
            Ok(_) => return Err(StoreError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TrashFinish::Gone),
            Err(e) => return Err(e.into()),
        };
        let same_inode = lmeta.dev() == tmeta.dev() && lmeta.ino() == tmeta.ino();
        // A different inode must be a good copy, otherwise dropping the live name could lose
        // the only intact one.
        if !same_inode && (lmeta.len() != tmeta.len() || hash_file(&tpath)? != *sha) {
            return Err(StoreError::Corrupt);
        }
        let scratch = self.scratch_name("trash", sha);
        match fs::rename(&live, &scratch) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TrashFinish::Gone),
            Err(e) => return Err(e.into()),
        }
        // Out of reach of `put` now. A dedup `put` that ran since the delete started refreshed
        // the mtime of this very inode and may not have inserted its release yet, so the
        // database cannot be trusted to know about it: keep the live name (a spare orphan at
        // worst, reclaimed by `store gc`). An unreadable mtime errs on the same side.
        let refreshed = fs::symlink_metadata(&scratch)
            .and_then(|m| m.modified())
            .map_or(true, |t| t >= started_at);
        // Ask the database one last time.
        if refreshed || !still_unreferenced(sha) {
            match fs::hard_link(&scratch, &live) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                // Cannot restore the name: keep the scratch file (startup cleanup removes it
                // later, the trash copy still holds the content) and report the failure.
                Err(e) => return Err(e.into()),
            }
            fs::remove_file(&scratch)?;
            if let Some(p) = live.parent() {
                sync_dir(p)?;
            }
            return Ok(TrashFinish::Kept);
        }
        fs::remove_file(&scratch)?;
        if let Some(p) = live.parent() {
            sync_dir(p)?;
        }
        Ok(TrashFinish::Removed)
    }

    fn trash_list_blocking(&self, limit: usize) -> Result<TrashListing, StoreError> {
        let rd = match fs::read_dir(self.trash_dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(TrashListing::default());
            }
            Err(e) => return Err(e.into()),
        };
        let mut out = TrashListing::default();
        for e in rd.take(MAX_ENTRIES) {
            let e = match e {
                Ok(e) => e,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            let sha = e
                .file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".nzb"))
                .and_then(|h| Sha256::from_hex(h).ok());
            // DirEntry metadata does not follow symlinks.
            let meta = e.metadata().ok().filter(|m| m.file_type().is_file());
            match (sha, meta) {
                (Some(sha), Some(m)) => out.items.push(TrashBlob { sha, size: m.len() }),
                _ => out.foreign = out.foreign.saturating_add(1),
            }
        }
        out.items.sort_by_key(|a| a.sha.0);
        out.items.truncate(limit);
        Ok(out)
    }

    fn trash_read_blocking(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
        let Some(mut f) = open_regular_nofollow(&self.trash_path(sha), false)? else {
            return Err(StoreError::NotFound);
        };
        let max = self.inner.max_blob_bytes.load(Ordering::Relaxed);
        if f.metadata()?.len() > max {
            return Err(StoreError::Corrupt);
        }
        let mut v = Vec::new();
        (&mut f).take(max.saturating_add(1)).read_to_end(&mut v)?;
        if !u64::try_from(v.len()).is_ok_and(|n| n <= max) || digest(&v) != *sha {
            return Err(StoreError::Corrupt);
        }
        Ok(v)
    }

    fn trash_purge_blocking(&self, sha: &Sha256) -> Result<TrashPurge, StoreError> {
        let path = self.trash_path(sha);
        match open_plain(&path)? {
            Plain::Absent => Ok(TrashPurge::Absent),
            Plain::Refused => Ok(TrashPurge::Refused),
            // The trash name is only a second name of the live blob of the same digest (a
            // delete whose `Kept` outcome left both names): it is just a name, drop it. Any
            // other extra link keeps the refusal.
            Plain::Linked(m) => {
                let live_same = m.nlink() == 2
                    && self
                        .checked_blob_path(sha)
                        .ok()
                        .and_then(|p| fs::symlink_metadata(p).ok())
                        .is_some_and(|l| {
                            l.file_type().is_file() && l.dev() == m.dev() && l.ino() == m.ino()
                        });
                if live_same && self.remove_verified(&path, &m, sha, true)? {
                    Ok(TrashPurge::Removed { bytes: m.len() })
                } else {
                    Ok(TrashPurge::Refused)
                }
            }
            Plain::File(m) => {
                if self.remove_verified(&path, &m, sha, false)? {
                    Ok(TrashPurge::Removed { bytes: m.len() })
                } else {
                    Ok(TrashPurge::Refused)
                }
            }
        }
    }

    fn quarantine_entries(
        &self,
        limit: usize,
    ) -> Result<(Vec<(QuarantineBlob, std::path::PathBuf)>, u64), StoreError> {
        let rd = match fs::read_dir(self.inner.root.join(GC_TRASH_DIR)) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e.into()),
        };
        let mut items = Vec::new();
        let mut foreign = 0u64;
        for e in rd.take(MAX_ENTRIES) {
            let e = match e {
                Ok(e) => e,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            let name = e.file_name();
            let mut parts = name.to_str().unwrap_or_default().split('.');
            let parsed = match (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) {
                (Some(hex), Some(ts), Some(n), Some("trash"), None)
                    if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    Sha256::from_hex(hex).ok().zip(ts.parse::<i64>().ok())
                }
                _ => None,
            };
            let meta = e.metadata().ok().filter(|m| m.file_type().is_file());
            match (parsed, meta) {
                (Some((sha, ts)), Some(m)) => items.push((
                    QuarantineBlob {
                        sha,
                        size: m.len(),
                        quarantined_at: ts,
                    },
                    e.path(),
                )),
                _ => foreign = foreign.saturating_add(1),
            }
        }
        items.sort_by(|a, b| a.1.cmp(&b.1));
        items.truncate(limit);
        Ok((items, foreign))
    }

    fn quarantine_purge_blocking(
        &self,
        older_than: i64,
        deadline: Option<Instant>,
        gate: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> Result<QuarantinePurge, StoreError> {
        let (items, foreign) = self.quarantine_entries(MAX_ENTRIES)?;
        let mut rep = QuarantinePurge {
            skipped: foreign,
            ..QuarantinePurge::default()
        };
        let mut handled = 0_u64;
        for (item, path) in items {
            if rep.aborted || deadline.is_some_and(|d| Instant::now() >= d) {
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            if handled.is_multiple_of(QuarantinePurge::BATCH_SIZE) && gate.is_some_and(|g| !g()) {
                rep.aborted = true;
                rep.remaining = rep.remaining.saturating_add(1);
                continue;
            }
            handled = handled.saturating_add(1);
            if item.quarantined_at >= older_than {
                rep.kept_recent = rep.kept_recent.saturating_add(1);
                continue;
            }
            match open_plain(&path)? {
                Plain::Absent => {}
                Plain::Refused | Plain::Linked(_) => rep.skipped = rep.skipped.saturating_add(1),
                Plain::File(m) => {
                    // The gate or filesystem checks may have taken the rest of the budget.
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        rep.remaining = rep.remaining.saturating_add(1);
                        continue;
                    }
                    if self.remove_verified(&path, &m, &item.sha, false)? {
                        rep.removed = rep.removed.saturating_add(1);
                        rep.bytes = rep.bytes.saturating_add(m.len());
                    } else {
                        rep.skipped = rep.skipped.saturating_add(1);
                    }
                }
            }
        }
        Ok(rep)
    }
}

#[async_trait]
impl TrashStore for FsStore {
    async fn trash_stage(&self, sha: &Sha256) -> Result<(), StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || this.trash_stage_blocking(&sha))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn trash_finish(
        &self,
        sha: &Sha256,
        started_at: SystemTime,
        still_unreferenced: StillUnreferenced,
    ) -> Result<TrashFinish, StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || {
            this.trash_finish_blocking(&sha, started_at, still_unreferenced.as_ref())
        })
        .await
        .map_err(|e| join_err(&e))?
    }

    async fn trash_list(&self, limit: usize) -> Result<TrashListing, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.trash_list_blocking(limit))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn trash_read(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || this.trash_read_blocking(&sha))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn trash_purge(&self, sha: &Sha256) -> Result<TrashPurge, StoreError> {
        let (this, sha) = (self.clone(), *sha);
        tokio::task::spawn_blocking(move || this.trash_purge_blocking(&sha))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn quarantine_list(&self, limit: usize) -> Result<QuarantineListing, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.quarantine_entries(limit)
                .map(|(items, foreign)| QuarantineListing {
                    items: items.into_iter().map(|(b, _)| b).collect(),
                    foreign,
                })
        })
        .await
        .map_err(|e| join_err(&e))?
    }

    async fn quarantine_purge_checked(
        &self,
        older_than: i64,
        deadline: Option<Instant>,
        gate: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Result<QuarantinePurge, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.quarantine_purge_blocking(older_than, deadline, gate.as_deref())
        })
        .await
        .map_err(|e| join_err(&e))?
    }
}
