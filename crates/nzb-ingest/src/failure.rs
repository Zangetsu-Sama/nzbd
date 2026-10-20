//! Failure handling (T032): the `reason.json` sidecar, listing, retry and retention of
//! `failed/` (`INGEST_SPEC` §F, D12, SEC-005/008).
//!
//! Invariants:
//! * Every name this module touches matches [`is_failed_name`]
//!   (`<UTC stamp>-<sha8|unknown>[-up][-N].nzb`), which the pipeline generates from a clock and
//!   a hash only. Names are **resolved by listing the directory**, never by joining user input
//!   (SEC-005).
//! * The sidecar is `<failed name>.reason.json`, written tmp + fsync + rename, mode 0600, and
//!   is written *after* the move: a crash in between leaves a failed file without a sidecar
//!   (listed with an unknown reason, never subject to retention), never a sidecar for a file
//!   that is not there.
//! * Retention deletes only files with a valid sidecar written by nzbd for exactly that file
//!   (and, when a digest is recorded, with matching content). Watch files, duplicates and any
//!   foreign file are never touched.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use nzb_core::sanitize_text;
use serde_json::{Value, json};
use sha2::{Digest, Sha256 as Hasher};

use crate::fsops::{SourceIdent, fsync_dir, move_no_clobber, unique_tag};
use crate::pipeline::CrashPoint;
use crate::scanner::open_regular;

/// Suffix of the sidecar next to a failed file.
pub const REASON_SUFFIX: &str = ".reason.json";
/// Format version written into every sidecar.
pub const REASON_VERSION: u32 = 1;
/// Value of `writer`: marks sidecars (and thus failed files) created by nzbd.
const WRITER: &str = "nzbd";
/// Sidecars are tiny; anything bigger is foreign.
const MAX_REASON_BYTES: u64 = 16 * 1024;
/// Bound on the sanitized message.
const MAX_MESSAGE_BYTES: usize = 200;
/// Bound on the sanitized source name.
const MAX_SOURCE_NAME_BYTES: usize = 255;
/// Safety bound for directory walks.
const MAX_ENTRIES: usize = 100_000;

/// Fault-injection hook: returns `true` when the "process dies" at that point.
pub(crate) type Hook<'a> = &'a dyn Fn(CrashPoint) -> bool;

/// No faults (production).
pub(crate) fn no_faults(_: CrashPoint) -> bool {
    false
}

pub(crate) fn crashed() -> io::Error {
    io::Error::other("injected crash")
}

/// Content of a `reason.json`. Strings are sanitized on construction; no paths, no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Stable error code (`IngestError::code`).
    pub error_code: String,
    /// Sanitized, bounded message.
    pub message: String,
    /// `watch`, `upload_ui` or `upload_api`.
    pub source: String,
    /// Original file name, sanitized (display only).
    pub source_name: Option<String>,
    /// Lowercase hex SHA-256 of the content, when it could be computed.
    pub sha256: Option<String>,
    /// Size of the failed file in bytes.
    pub size: u64,
    /// Unix seconds of the failure.
    pub at: i64,
    /// Number of earlier failures of the same content.
    pub retry_count: u32,
}

impl Reason {
    /// Builds a reason, sanitizing every free-text field.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // plain data record, one call site
    pub fn new(
        error_code: &str,
        message: &str,
        source: &str,
        source_name: Option<&str>,
        sha256: Option<String>,
        size: u64,
        at: i64,
        retry_count: u32,
    ) -> Self {
        Self {
            error_code: sanitize_text(error_code, 64),
            message: sanitize_text(message, MAX_MESSAGE_BYTES),
            source: sanitize_text(source, 32),
            source_name: source_name.map(|n| sanitize_text(n, MAX_SOURCE_NAME_BYTES)),
            sha256,
            size,
            at,
            retry_count,
        }
    }

    fn to_json(&self, file: &str) -> Value {
        json!({
            "version": REASON_VERSION,
            "writer": WRITER,
            "file": file,
            "error_code": self.error_code,
            "message": self.message,
            "source": self.source,
            "source_name": self.source_name,
            "sha256": self.sha256,
            "size": self.size,
            "at": self.at,
            "retry_count": self.retry_count,
        })
    }

    /// Parses a sidecar; `None` unless it is a version-1 file written by nzbd for `file`.
    fn from_json(v: &Value, file: &str) -> Option<Self> {
        if v.get("version")?.as_u64()? != u64::from(REASON_VERSION)
            || v.get("writer")?.as_str()? != WRITER
            || v.get("file")?.as_str()? != file
        {
            return None;
        }
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            error_code: text("error_code")?,
            message: text("message")?,
            source: text("source")?,
            source_name: text("source_name"),
            sha256: text("sha256"),
            size: v.get("size")?.as_u64()?,
            at: v.get("at")?.as_i64()?,
            retry_count: u32::try_from(v.get("retry_count")?.as_u64()?).ok()?,
        })
    }
}

/// True for the names the pipeline generates in `failed/`:
/// `YYYYMMDDTHHMMSSZ-<8 lowercase hex | unknown>[-up][-N].nzb` (N = 1..=9999).
#[must_use]
pub fn is_failed_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".nzb") else {
        return false;
    };
    let Some((stamp, rest)) = stem.split_once('-') else {
        return false;
    };
    let b = stamp.as_bytes();
    let stamp_ok = b.len() == 16
        && b.iter().enumerate().all(|(i, c)| match i {
            8 => *c == b'T',
            15 => *c == b'Z',
            _ => c.is_ascii_digit(),
        });
    if !stamp_ok {
        return false;
    }
    let (id, tail) = rest.split_once('-').unwrap_or((rest, ""));
    let id_ok = id == "unknown"
        || (id.len() == 8
            && id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    if !id_ok {
        return false;
    }
    let num = if tail == "up" {
        ""
    } else {
        tail.strip_prefix("up-").unwrap_or(tail)
    };
    if num.is_empty() {
        // "", "up" are fine; "up-" (trailing dash) is not.
        return !tail.ends_with('-');
    }
    num.len() <= 4 && num.bytes().all(|c| c.is_ascii_digit()) && !num.starts_with('0')
}

/// Name of the sidecar of a (validated) failed file.
fn sidecar_name(file: &str) -> String {
    format!("{file}{REASON_SUFFIX}")
}

/// Writes the sidecar for `file` (a name inside `dir`): tmp, fsync, rename, fsync dir.
pub(crate) fn write_reason(
    dir: &Path,
    file: &str,
    reason: &Reason,
    hook: Hook<'_>,
) -> io::Result<()> {
    if !is_failed_name(file) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad failed name",
        ));
    }
    let part = dir.join(format!(".{file}.reason.{}.part", unique_tag()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let body = serde_json::to_vec_pretty(&reason.to_json(file)).map_err(io::Error::other)?;
    let res = f.write_all(&body).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    if hook(CrashPoint::ReasonTmpWritten) {
        return Err(crashed());
    }
    if let Err(e) = fs::rename(&part, dir.join(sidecar_name(file))) {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    fsync_dir(dir);
    if hook(CrashPoint::AfterReason) {
        return Err(crashed());
    }
    Ok(())
}

/// Reads the sidecar of `file`. `None` if absent, a symlink, oversized, malformed, or not
/// written by nzbd for exactly this file.
#[must_use]
pub fn read_reason(dir: &Path, file: &str) -> Option<Reason> {
    if !is_failed_name(file) {
        return None;
    }
    let path = dir.join(sidecar_name(file));
    // Open first, judge through the descriptor: `O_NOFOLLOW` refuses a symlink and
    // `O_NONBLOCK` makes opening a swapped-in FIFO return at once instead of waiting for a
    // writer (T085-L3); the fstat then insists on a regular file.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_REASON_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_REASON_BYTES).read_to_end(&mut buf).ok()?;
    let v: Value = serde_json::from_slice(&buf).ok()?;
    Reason::from_json(&v, file)
}

/// One quarantined file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedEntry {
    /// File name (matches [`is_failed_name`]).
    pub name: String,
    /// Size on disk.
    pub size: u64,
    /// Sidecar content, if a valid one exists.
    pub reason: Option<Reason>,
}

/// Lists regular files in `dir` whose names match [`is_failed_name`], sorted by name.
/// Symlinks, directories, sidecars and foreign names are ignored.
///
/// # Errors
/// I/O errors reading the directory.
pub fn list_failed(dir: &Path) -> io::Result<Vec<FailedEntry>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir)?.take(MAX_ENTRIES) {
        let e = match e {
            Ok(e) => e,
            // Removed by a concurrent rotation/retry/retention (T032 L5).
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_failed_name(&name) {
            continue;
        }
        // `DirEntry::file_type` does not follow symlinks. An entry that vanished between
        // `read_dir` and these calls is skipped, not an error.
        let (is_file, size) = match e.file_type().and_then(|t| e.metadata().map(|m| (t, m))) {
            Ok((t, m)) => (t.is_file(), m.len()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if !is_file {
            continue;
        }
        let reason = read_reason(dir, &name);
        out.push(FailedEntry { name, size, reason });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// What to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryTarget {
    /// One file, by exact name.
    Name(String),
    /// Every listed file.
    All,
}

/// Result of [`retry`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetryReport {
    /// `(failed name, new name in watch/)`.
    pub moved: Vec<(String, String)>,
    /// `(failed name, error kind)` for files that could not be moved (left in `failed/`).
    pub errors: Vec<(String, String)>,
}

/// Moves failed file(s) back into `watch_dir` under a collision-free name
/// (`retry-<failed stem>[-N].nzb`) and removes the stale sidecar afterwards. Crash order: the
/// file is moved first (hard link, verified unlink; or copy across filesystems), the sidecar
/// goes last, so a crash leaves at worst an orphan sidecar, which startup recovery removes. If
/// a crash leaves both names of one inode, recovery drops the `failed/` name.
///
/// # Errors
/// `InvalidInput` for a name that is not a failed-file name, `NotFound` if the listing has no
/// such regular file, I/O errors listing. Per-file move errors are collected in the report.
pub fn retry(failed_dir: &Path, watch_dir: &Path, target: &RetryTarget) -> io::Result<RetryReport> {
    retry_with(failed_dir, watch_dir, target, &no_faults)
}

pub(crate) fn retry_with(
    failed_dir: &Path,
    watch_dir: &Path,
    target: &RetryTarget,
    hook: Hook<'_>,
) -> io::Result<RetryReport> {
    if let RetryTarget::Name(n) = target
        && !is_failed_name(n)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a failed-file name",
        ));
    }
    // Resolve by listing: the user's string is only ever compared, never joined.
    let listed = list_failed(failed_dir)?;
    let chosen: Vec<&FailedEntry> = match target {
        RetryTarget::All => listed.iter().collect(),
        RetryTarget::Name(n) => listed.iter().filter(|e| &e.name == n).collect(),
    };
    if chosen.is_empty() && matches!(target, RetryTarget::Name(_)) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no such failed file",
        ));
    }
    let mut rep = RetryReport::default();
    for entry in chosen {
        let stem = entry.name.strip_suffix(".nzb").unwrap_or(&entry.name);
        let src = failed_dir.join(&entry.name); // `entry.name` came from the listing
        match move_no_clobber(&src, watch_dir, &format!("retry-{stem}"), None) {
            Ok(dest) => {
                let new_name = dest
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if hook(CrashPoint::RetryAfterMove) {
                    return Err(crashed());
                }
                let _ = fs::remove_file(failed_dir.join(sidecar_name(&entry.name)));
                fsync_dir(failed_dir);
                retry_nfo(failed_dir, watch_dir, stem, &dest);
                rep.moved.push((entry.name.clone(), new_name));
            }
            Err(e) => rep
                .errors
                .push((entry.name.clone(), format!("{:?}", e.kind()))),
        }
    }
    Ok(rep)
}

/// T141: the NFO sidecar that followed a watch NZB into `failed/` (`<stem>.nfo`, `stem` from the listing) goes back
/// with it, exactly under the retried NZB's new stem (the NZB move never picks a stem whose `.nfo` is taken), so the
/// next ingest pairs them again. Any problem leaves it where it is.
fn retry_nfo(failed_dir: &Path, watch_dir: &Path, stem: &str, nzb_dest: &Path) {
    if let Some(new_stem) = nzb_dest.file_stem().and_then(|s| s.to_str()) {
        let _ = crate::fsops::carry_twin(failed_dir, stem, watch_dir, new_stem);
    }
}

/// `<generated failed stem>.nfo`: the NFO sidecar that followed its watch NZB into `failed/` (T141).
#[must_use]
pub fn is_failed_nfo_name(name: &str) -> bool {
    name.strip_suffix(".nfo")
        .is_some_and(|stem| is_failed_name(&format!("{stem}.nzb")))
}

/// Sub-directory of `failed/` that receives expired files. Never listed, rotated or expired
/// again; emptying it is a manual decision.
pub const EXPIRED_DIR: &str = "expired";

/// Result of [`apply_retention`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    /// Files (and sidecars) moved to `failed/expired/`.
    pub expired: u32,
    /// Files kept because they have no valid nzbd sidecar or fail the integrity check.
    pub skipped: u32,
}

/// Streams a verified regular file (opened `O_NOFOLLOW|O_NONBLOCK`, `nlink == 1`, checked via
/// `fstat`, so a FIFO or symlink swapped in cannot block or redirect us) and returns its
/// identity plus lowercase hex SHA-256.
pub(crate) fn hash_regular(path: &Path, root: &Path) -> Option<(SourceIdent, String)> {
    let (file, size) = open_regular(path, u64::MAX, None, Some(root)).ok()?;
    let ident = SourceIdent::of(&file.metadata().ok()?);
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
    Some((ident, nzb_core::Sha256(h.finalize().into()).to_hex()))
}

fn ensure_expired_dir(dir: &Path) -> io::Result<std::path::PathBuf> {
    let d = dir.join(EXPIRED_DIR);
    match fs::DirBuilder::new().mode(0o700).create(&d) {
        Ok(()) => fsync_dir(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // Never a symlink to somewhere else.
    if fs::symlink_metadata(&d)?.is_dir() {
        Ok(d)
    } else {
        Err(io::Error::other("failed/expired is not a directory"))
    }
}

/// D12 retention, conservative reading (`SECURITY_REVIEW` T032 L3): failed files older than
/// `days` (`0` = keep forever = no-op) are **moved**, with their sidecar, to `failed/expired/`
/// and are then out of sight of `list`, `retry`, rotation and retention. Nothing is deleted
/// (BETA: never delete a user's NZB); reclaiming disk space is manual.
///
/// Only files with a valid sidecar written by nzbd for that very file qualify; the content must
/// still match the recorded digest (or the recorded size, if none). Age is the sidecar's `at`,
/// not the mtime. The file is opened without following symlinks and without blocking, hashed
/// from that descriptor, and moved only if it is still the very same inode (identity-checked
/// hard link + verified unlink). Order: file first, sidecar second.
#[must_use]
pub fn apply_retention(dir: &Path, days: u32, now: i64) -> RetentionReport {
    let mut rep = RetentionReport::default();
    if days == 0 {
        return rep;
    }
    let max_age = i64::from(days).saturating_mul(86_400);
    let Ok(entries) = list_failed(dir) else {
        return rep;
    };
    let mut expired_dir = None;
    for e in entries {
        let Some(r) = e.reason else {
            rep.skipped = rep.skipped.saturating_add(1);
            continue;
        };
        if now.saturating_sub(r.at) < max_age {
            continue;
        }
        let path = dir.join(&e.name);
        let Some((ident, got)) = hash_regular(&path, dir) else {
            rep.skipped = rep.skipped.saturating_add(1);
            continue;
        };
        let intact = match &r.sha256 {
            Some(want) => &got == want,
            None => r.size == e.size,
        };
        if !intact {
            rep.skipped = rep.skipped.saturating_add(1);
            continue;
        }
        if expired_dir.is_none() {
            expired_dir = ensure_expired_dir(dir).ok();
        }
        let Some(xd) = &expired_dir else {
            rep.skipped = rep.skipped.saturating_add(1);
            continue;
        };
        let stem = e.name.strip_suffix(".nzb").unwrap_or(&e.name);
        let Ok(dest) = move_no_clobber(&path, xd, stem, Some(&ident)) else {
            rep.skipped = rep.skipped.saturating_add(1);
            continue;
        };
        if let Some(n) = dest.file_name().and_then(|n| n.to_str()) {
            let _ = fs::rename(dir.join(sidecar_name(&e.name)), xd.join(sidecar_name(n)));
            // T141: its NFO goes along, exactly under the new stem.
            if let Some(new_stem) = n.strip_suffix(".nzb") {
                let _ = crate::fsops::carry_twin(dir, stem, xd, new_stem);
            }
        }
        rep.expired = rep.expired.saturating_add(1);
    }
    if rep.expired > 0 {
        fsync_dir(dir);
    }
    rep
}

/// Removes sidecars whose failed file is gone (crash after a retry/rotation removed the file).
/// Only valid nzbd sidecars are removed. Returns the count.
pub(crate) fn remove_orphan_sidecars(dir: &Path) -> u32 {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut n = 0u32;
    for e in rd.flatten().take(MAX_ENTRIES) {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(file) = name.strip_suffix(REASON_SUFFIX) else {
            continue;
        };
        if read_reason(dir, file).is_none() {
            continue;
        }
        let gone = fs::symlink_metadata(dir.join(file))
            .is_err_and(|err| err.kind() == io::ErrorKind::NotFound);
        if gone && fs::remove_file(e.path()).is_ok() {
            n = n.saturating_add(1);
        }
    }
    n
}
