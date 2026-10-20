//! `nzbd import <dir>` (T115, `docs/v3/MIGRATION.md` section 1): re-ingests a directory of NZB files (a 2.x
//! `data/store/`, an original `.nzb` collection) through the same pipeline, parser and limits as the watch folder.
//!
//! The source is **read only**: files are copied into the store by the pipeline, never moved, renamed or deleted,
//! whatever the outcome (an imported job has no path, so the pipeline's source handling cannot reach it). The walk
//! never follows a symbolic link and never turns a name into a path: every directory is opened relative to its parent
//! descriptor with `O_NOFOLLOW | O_DIRECTORY`, every entry is examined with `fstatat(AT_SYMLINK_NOFOLLOW)` and opened
//! with `openat(O_NOFOLLOW)`, and the opened descriptor must still be the regular file that was examined. Names are
//! display data only (sanitized for the log, Debug-escaped in reports). Symbolic links and special files are skipped
//! and reported; hidden entries (a 2.x store's `.tmp`, `.trash`, `.gc-trash`) and files not ending in `.nzb` are
//! ignored. The walk is bounded in depth and in the number of entries it looks at, and holds one descriptor per
//! level.
//!
//! Idempotent and resumable by digest: a re-run finds every file already indexed as a duplicate (no row, no log
//! line, the blob healed if it went missing), so an interrupted import is simply run again.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::error::IngestError;
use crate::pipeline::{ImportFile, IngestHandle, IngestOutcome, Job, OutcomeKind};

/// Default deepest directory level below the import root (a 2.x store is `aa/bb/<sha>.nzb`: level 2).
pub const DEFAULT_IMPORT_DEPTH: usize = 8;
/// Hard ceiling of `--max-depth`.
pub const MAX_IMPORT_DEPTH: usize = 32;
/// Default number of directory entries one run looks at (~1M releases with room to grow, D35).
pub const DEFAULT_IMPORT_ENTRIES: u64 = 5_000_000;
/// Hard ceiling of `--max-entries`.
pub const MAX_IMPORT_ENTRIES: u64 = 100_000_000;
/// Problem lines kept for the report (the counts are always complete).
pub const MAX_REPORTED: usize = 50;
/// Longest display name in a report line, in characters.
const MAX_SHOWN_CHARS: usize = 160;
/// Prepared files handed from the walk to the submitter at once (each holds one descriptor).
const WALK_CHANNEL: usize = 64;

/// Bounds of one import run.
#[derive(Debug, Clone, Copy)]
pub struct ImportLimits {
    /// Deepest directory level below the root that is entered (the root's own entries are level 0).
    pub max_depth: usize,
    /// Directory entries looked at before the walk stops (`entry_limit_hit`).
    pub max_entries: u64,
    /// Largest file accepted (`limits.max_file_bytes`; larger ones are skipped and reported).
    pub max_file_bytes: u64,
    /// Jobs submitted and not yet answered (at most the queue capacity, so the queue never refuses).
    pub max_in_flight: usize,
    /// Import files whose digest belongs to a release deleted from the library (`--include-deleted`); by default they
    /// are skipped and counted as `trashed` (review 38 L1).
    pub include_deleted: bool,
}

/// Why the walk skipped an entry it reports (ignored entries are only counted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    /// A symbolic link (never followed).
    Symlink,
    /// A FIFO, socket or device.
    Special,
    /// A directory below `max_depth`.
    TooDeep,
    /// Larger than `max_file_bytes`.
    TooLarge,
    /// Changed between the examination and the open, or could not be opened or listed.
    Unreadable,
}

impl SkipReason {
    /// Stable code for the report.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Symlink => "SYMLINK_SKIPPED",
            Self::Special => "SPECIAL_FILE_SKIPPED",
            Self::TooDeep => "TOO_DEEP",
            Self::TooLarge => "FILE_TOO_LARGE",
            Self::Unreadable => "SOURCE_UNREADABLE",
        }
    }
}

/// What one run did. Counts are complete; `problems` holds the first [`MAX_REPORTED`] lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// `.nzb` files handed to the pipeline.
    pub files: u64,
    /// New releases.
    pub imported: u64,
    /// Already in the library (nothing written).
    pub duplicates: u64,
    /// Deleted from the library (in the trash) and therefore not brought back (review 38 L1; `--include-deleted`).
    pub trashed: u64,
    /// Rejected or failed by the pipeline, by error code.
    pub failed: BTreeMap<&'static str, u64>,
    /// Skipped by the walk, by reason.
    pub skipped: BTreeMap<SkipReason, u64>,
    /// Hidden entries and files not ending in `.nzb` (not reported individually).
    pub ignored: u64,
    /// The walk stopped at `max_entries`; run again with a higher limit (nothing is imported twice).
    pub entry_limit_hit: bool,
    /// The run was interrupted (signal); run it again to finish.
    pub interrupted: bool,
    /// Times the import found the search index too far behind and waited (SEC-092 gate of a running server).
    pub index_waits: u64,
    /// Waiting for the search index right now (progress lines say so).
    pub waiting_for_index: bool,
    /// `(display name, code)` of the first problems.
    pub problems: Vec<(String, &'static str)>,
}

impl ImportReport {
    /// Files the pipeline did not accept.
    #[must_use]
    pub fn failed_total(&self) -> u64 {
        self.failed.values().copied().fold(0, u64::saturating_add)
    }

    /// Entries the walk skipped and reported.
    #[must_use]
    pub fn skipped_total(&self) -> u64 {
        self.skipped.values().copied().fold(0, u64::saturating_add)
    }

    /// Whether anything needs the operator's attention (exit code 2 of the CLI).
    #[must_use]
    pub fn has_problems(&self) -> bool {
        self.failed_total() > 0
            || self.skipped_total() > 0
            || self.trashed > 0
            || self.entry_limit_hit
    }

    fn problem(&mut self, name: &str, code: &'static str) {
        if self.problems.len() < MAX_REPORTED {
            self.problems.push((shown(name), code));
        }
    }
}

/// Why an import could not start.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The root is not a directory, is a symbolic link, or cannot be opened.
    #[error(
        "IMPORT_DIR_UNUSABLE: the import directory must be an existing directory and not a symbolic link"
    )]
    Root(#[source] std::io::Error),
    /// The opened root is, is inside, or contains a directory nzbd manages: decided on device and inode of the
    /// opened descriptor and its ancestors, so a symlink, a `..` spelling or a bind mount cannot hide it (review 38 L2).
    #[error(
        "IMPORT_DIR_OVERLAP: the import directory is, is inside or contains a directory nzbd manages (paths.*, the \
         index or state directory); import from a separate copy, e.g. the old data/store/ mounted read-only"
    )]
    Overlap,
}

/// What an import must respect besides its [`ImportLimits`].
#[derive(Debug, Clone, Default)]
pub struct ImportGuard {
    /// Directories nzbd manages (watch, store, failed, duplicates, tmp, backups, index, state, the SQLite database
    /// directory). Missing ones are ignored.
    pub managed: Vec<std::path::PathBuf>,
    /// The SEC-092 lag gate of a running `serve` (PostgreSQL): new files wait while it is paused (review 38 L4).
    pub lag_gate: Option<crate::runner::LagGate>,
    /// How often the gate is asked (and how long a paused import sleeps between asks); default 1 s.
    pub gate_every: Option<Duration>,
}

/// Device and inode of a directory.
type Ident = (u64, u64);

fn ident(fd: &OwnedFd) -> Option<Ident> {
    rustix::fs::fstat(fd).ok().map(|st| (st.st_dev, st.st_ino))
}

/// Identities of `start` and every ancestor up to `/`, through `openat(fd, "..")` (never a path).
fn chain(start: OwnedFd) -> Vec<Ident> {
    let mut out: Vec<Ident> = Vec::new();
    let mut fd = start;
    for _ in 0..4096 {
        let Some(id) = ident(&fd) else {
            break;
        };
        // `/..` is `/` itself: the chain ends where it repeats.
        if out.contains(&id) {
            break;
        }
        out.push(id);
        match rustix::fs::openat(
            &fd,
            c"..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(parent) => fd = parent,
            Err(_) => break,
        }
    }
    out
}

/// Refuses an opened root that is, is inside, or contains a managed directory (identity, not path).
fn check_overlap(root: &OwnedFd, managed: &[std::path::PathBuf]) -> Result<(), ImportError> {
    let Ok(dup) = rustix::io::dup(root) else {
        return Err(ImportError::Overlap);
    };
    let root_chain = chain(dup);
    let Some(root_id) = root_chain.first().copied() else {
        return Err(ImportError::Overlap);
    };
    for m in managed {
        // The managed paths come from the operator's configuration: following their symlinks is intended.
        let Ok(fd) = rustix::fs::open(
            m.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };
        let Some(mid) = ident(&fd) else {
            continue;
        };
        if root_chain.contains(&mid) || chain(fd).contains(&root_id) {
            return Err(ImportError::Overlap);
        }
    }
    Ok(())
}

/// The refusals of [`import_dir`] without importing anything (the CLI asks before it writes its audit row).
///
/// # Errors
/// [`ImportError::Root`], [`ImportError::Overlap`].
pub fn check_root(root: &Path, guard: &ImportGuard) -> Result<(), ImportError> {
    let fd = open_root(root)?;
    check_overlap(&fd, &guard.managed)
}

/// One item of the walk.
enum Walked {
    File(ImportFile, String),
    Skipped(String, SkipReason),
    Ignored,
    LimitHit,
}

/// Debug-escaped and capped: a hostile name cannot forge report or log lines.
fn shown(name: &str) -> String {
    let capped: String = name.chars().take(MAX_SHOWN_CHARS).collect();
    format!("{capped:?}")
}

fn lossy(name: &CStr) -> String {
    String::from_utf8_lossy(name.to_bytes()).into_owned()
}

fn is_nzb_name(name: &[u8]) -> bool {
    name.len() > 4
        && name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(b".nzb"))
}

/// Opens the import root: a real directory, never through a final symbolic link.
fn open_root(root: &Path) -> Result<OwnedFd, ImportError> {
    rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ImportError::Root(e.into()))
}

/// The bounded, no-follow walk (runs on a blocking thread). `emit` returns `false` to stop.
fn walk(
    root: OwnedFd,
    limits: ImportLimits,
    cancel: &AtomicBool,
    emit: &mut dyn FnMut(Walked) -> bool,
) {
    // One open directory per level: (listing, its descriptor, display prefix, level of its entries).
    let mut stack: Vec<(Dir, OwnedFd, String, usize)> = Vec::new();
    let Ok(d) = Dir::read_from(root.as_fd()) else {
        let _ = emit(Walked::Skipped(".".to_owned(), SkipReason::Unreadable));
        return;
    };
    stack.push((d, root, String::new(), 0));
    let mut seen: u64 = 0;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let Some(top) = stack.last_mut() else {
            return;
        };
        let entry = match top.0.next() {
            None => {
                stack.pop();
                continue;
            }
            Some(Err(_)) => {
                let shown_dir = if top.2.is_empty() {
                    ".".to_owned()
                } else {
                    top.2.clone()
                };
                stack.pop();
                if !emit(Walked::Skipped(shown_dir, SkipReason::Unreadable)) {
                    return;
                }
                continue;
            }
            Some(Ok(e)) => e,
        };
        let name = entry.file_name().to_owned();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        seen = seen.saturating_add(1);
        if seen > limits.max_entries {
            let _ = emit(Walked::LimitHit);
            return;
        }
        let display = if top.2.is_empty() {
            lossy(&name)
        } else {
            format!("{}/{}", top.2, lossy(&name))
        };
        // Hidden entries: a 2.x store's `.tmp`, `.trash` (deleted releases) and `.gc-trash`, editors' temp files.
        if bytes.first() == Some(&b'.') {
            if !emit(Walked::Ignored) {
                return;
            }
            continue;
        }
        let level = top.3;
        let examined = examine(&top.1, &name, &display, level, limits);
        match examined {
            Examined::Descend(child) => match Dir::read_from(child.as_fd()) {
                Ok(d) => stack.push((d, child, display, level.saturating_add(1))),
                Err(_) => {
                    if !emit(Walked::Skipped(display, SkipReason::Unreadable)) {
                        return;
                    }
                }
            },
            Examined::Emit(w) => {
                if !emit(w) {
                    return;
                }
            }
        }
    }
}

enum Examined {
    Descend(OwnedFd),
    Emit(Walked),
}

/// Looks at one entry relative to its directory descriptor: no path is ever built from the name.
fn examine(
    dir: &OwnedFd,
    name: &CStr,
    display: &str,
    level: usize,
    limits: ImportLimits,
) -> Examined {
    let skipped = |r| Examined::Emit(Walked::Skipped(display.to_owned(), r));
    let Ok(st) = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return skipped(SkipReason::Unreadable);
    };
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Symlink => skipped(SkipReason::Symlink),
        FileType::Directory => {
            if level >= limits.max_depth {
                return skipped(SkipReason::TooDeep);
            }
            match rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => Examined::Descend(fd),
                Err(_) => skipped(SkipReason::Unreadable),
            }
        }
        FileType::RegularFile => {
            if !is_nzb_name(name.to_bytes()) {
                return Examined::Emit(Walked::Ignored);
            }
            let size = u64::try_from(st.st_size).unwrap_or(u64::MAX);
            if size > limits.max_file_bytes {
                return skipped(SkipReason::TooLarge);
            }
            // NONBLOCK: a FIFO swapped in after the examination cannot hang the open.
            let Ok(fd) = rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY
                    | OFlags::CLOEXEC,
                Mode::empty(),
            ) else {
                return skipped(SkipReason::Unreadable);
            };
            // The descriptor must be the very regular file that was examined.
            let same = rustix::fs::fstat(&fd).is_ok_and(|now| {
                FileType::from_raw_mode(now.st_mode) == FileType::RegularFile
                    && now.st_dev == st.st_dev
                    && now.st_ino == st.st_ino
            });
            if !same {
                return skipped(SkipReason::Unreadable);
            }
            let file_name = nzb_core::sanitize_text(&lossy(name), 255);
            Examined::Emit(Walked::File(
                ImportFile {
                    file: File::from(fd),
                    size,
                    name: Some(file_name).filter(|n| !n.is_empty()),
                    include_deleted: limits.include_deleted,
                },
                display.to_owned(),
            ))
        }
        _ => skipped(SkipReason::Special),
    }
}

/// Imports every `.nzb` file below `root` through `handle` (a pipeline started with [`crate::Pipeline::spawn`]).
/// `progress` is called about every `progress_every` with the counts so far; setting `cancel` stops the walk, lets
/// the submitted jobs finish and returns the partial report (`interrupted`).
///
/// # Errors
/// [`ImportError::Root`] when the root cannot be opened as a directory without following a symbolic link;
/// [`ImportError::Overlap`] when it is, is inside or contains a directory nzbd manages (decided on the descriptor the
/// walk then uses).
pub async fn import_dir(
    root: &Path,
    limits: ImportLimits,
    handle: &IngestHandle,
    cancel: Arc<AtomicBool>,
    guard: &ImportGuard,
    progress_every: Duration,
    progress: &(dyn Fn(&ImportReport) + Send + Sync),
) -> Result<ImportReport, ImportError> {
    let root_fd = open_root(root)?;
    check_overlap(&root_fd, &guard.managed)?;
    let gate_every = guard.gate_every.unwrap_or(Duration::from_secs(1));
    let mut gate_checked: Option<Instant> = None;
    let limits = ImportLimits {
        max_depth: limits.max_depth.min(MAX_IMPORT_DEPTH),
        max_entries: limits.max_entries.min(MAX_IMPORT_ENTRIES),
        max_in_flight: limits.max_in_flight.max(1),
        ..limits
    };
    let (tx, mut rx) = mpsc::channel::<Walked>(WALK_CHANNEL);
    let walk_cancel = Arc::clone(&cancel);
    let walker = tokio::task::spawn_blocking(move || {
        walk(root_fd, limits, &walk_cancel, &mut |w| {
            tx.blocking_send(w).is_ok()
        });
    });
    let mut report = ImportReport::default();
    let mut running: JoinSet<(String, Result<IngestOutcome, IngestError>)> = JoinSet::new();
    let mut last = Instant::now();
    while let Some(item) = rx.recv().await {
        if cancel.load(Ordering::SeqCst) {
            report.interrupted = true;
            break;
        }
        match item {
            Walked::File(file, name) => {
                if let Some(g) = &guard.lag_gate
                    && gate_checked.is_none_or(|t| t.elapsed() >= gate_every)
                {
                    wait_for_index(g, &cancel, gate_every, &mut report, progress).await;
                    gate_checked = Some(Instant::now());
                    if cancel.load(Ordering::SeqCst) {
                        report.interrupted = true;
                        break;
                    }
                }
                report.files = report.files.saturating_add(1);
                while running.len() >= limits.max_in_flight {
                    if let Some(done) = running.join_next().await {
                        record(&mut report, done);
                    }
                }
                let h = handle.clone();
                running.spawn(async move {
                    let r = submit(&h, Job::import(file)).await;
                    (name, r)
                });
            }
            Walked::Skipped(name, reason) => {
                let n = report.skipped.entry(reason).or_insert(0);
                *n = n.saturating_add(1);
                report.problem(&name, reason.code());
            }
            Walked::Ignored => report.ignored = report.ignored.saturating_add(1),
            Walked::LimitHit => report.entry_limit_hit = true,
        }
        while let Some(done) = running.try_join_next() {
            record(&mut report, done);
        }
        if last.elapsed() >= progress_every {
            progress(&report);
            last = Instant::now();
        }
    }
    if cancel.load(Ordering::SeqCst) {
        report.interrupted = true;
    }
    // Stop the walk (if it is still running) and wait for every submitted job: each ends consistently.
    drop(rx);
    while let Some(done) = running.join_next().await {
        record(&mut report, done);
    }
    let _ = walker.await;
    Ok(report)
}

/// SEC-092 next to a running server: while its scanner is paused for the index lag the import waits too, instead of
/// adding outbox rows while the operator's watch folder stands still (review 38 L4).
async fn wait_for_index(
    gate: &crate::runner::LagGate,
    cancel: &AtomicBool,
    every: Duration,
    report: &mut ImportReport,
    progress: &(dyn Fn(&ImportReport) + Send + Sync),
) {
    while !gate.admit().await {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        report.index_waits = report.index_waits.saturating_add(1);
        if !report.waiting_for_index {
            report.waiting_for_index = true;
            progress(report);
        }
        tokio::time::sleep(every).await;
    }
    report.waiting_for_index = false;
}

/// Submits one job; the importer never has more jobs in flight than the queue holds, but another submitter (a running
/// pipeline shared with uploads) could fill it, so a full queue is waited out rather than counted as a failure.
async fn submit(handle: &IngestHandle, job: Job) -> Result<IngestOutcome, IngestError> {
    let mut job = Some(job);
    loop {
        let Some(j) = job.take() else {
            return Err(IngestError::Internal);
        };
        if handle.free_slots() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            job = Some(j);
            continue;
        }
        return handle.submit(j).await;
    }
}

fn record(
    report: &mut ImportReport,
    done: Result<(String, Result<IngestOutcome, IngestError>), tokio::task::JoinError>,
) {
    match done {
        Ok((_, Ok(o))) if o.kind == OutcomeKind::Ingested => {
            report.imported = report.imported.saturating_add(1);
        }
        Ok((_, Ok(_))) => report.duplicates = report.duplicates.saturating_add(1),
        Ok((name, Err(IngestError::Trashed))) => {
            report.trashed = report.trashed.saturating_add(1);
            report.problem(&name, IngestError::Trashed.code());
        }
        Ok((name, Err(e))) => {
            let n = report.failed.entry(e.code()).or_insert(0);
            *n = n.saturating_add(1);
            report.problem(&name, e.code());
        }
        Err(_) => {
            let n = report.failed.entry("INTERNAL").or_insert(0);
            *n = n.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn only_dot_nzb_names_qualify() {
        for ok in [&b"a.nzb"[..], b"A.NZB", b"x.Nzb", b"\xff\xfe.nzb"] {
            assert!(is_nzb_name(ok), "{ok:?}");
        }
        for no in [&b".nzb"[..], b"a.nzb.part", b"nzb", b"a.nz", b""] {
            assert!(!is_nzb_name(no), "{no:?}");
        }
    }

    #[test]
    fn shown_names_are_escaped_and_capped() {
        let s = shown("a\nb\u{1b}[31m\u{202e}");
        assert!(!s.contains('\n') && !s.contains('\u{1b}') && !s.contains('\u{202e}'));
        assert!(shown(&"x".repeat(1000)).chars().count() <= MAX_SHOWN_CHARS + 2);
    }
}
