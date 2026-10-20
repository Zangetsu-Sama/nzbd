//! The NFO sidecar of a watch-folder NZB (T141, D41 amended, `INGEST_SPEC` §NFO sidecar, SEC-106).
//!
//! `Foo.Bar-GRP.nzb` may come with `Foo.Bar-GRP.nfo` in the same directory: same stem, byte for byte, and an `nfo`
//! extension in any letter case (like the `.nzb` one). The sidecar's name is built from the NZB's own directory entry
//! name (the scanner's walk, never anything inside the NZB): the stem plus one of the eight casings of `nfo`.
//!
//! Everything happens **relative to one directory descriptor** (review 54 L1): [`open_dir`] opens the NZB's parent
//! (`O_DIRECTORY|O_NOFOLLOW`) and proves, through that descriptor only, that it still holds the very NZB inode that
//! was read and that the watch root is one of its ancestors (`openat(fd, "..")`, never a path). The probe
//! (`fstatat(AT_SYMLINK_NOFOLLOW)`), the read (`openat(O_NOFOLLOW|O_NONBLOCK)`, the descriptor must be the examined
//! regular file with one link, read bounded by [`MAX_NFO_BYTES`] + 1, identity equal before and after), the verified
//! unlink and the move (`linkat` / `renameat`) all use that descriptor, so swapping a path component for a symbolic
//! link after the check cannot redirect any of them. A sidecar that was not examined this way is never touched; one
//! that is refused for any reason other than its size ([`Probe::Refused`]) stays where it is.
//!
//! Probing the eight names instead of listing the directory keeps a large watch folder cheap; two names of the same
//! inode (a case-insensitive filesystem such as a macOS bind mount) count once. Two NZBs differing only by the
//! extension case (`Pair.nzb`, `Pair.NZB`) make their common sidecar ambiguous (review 54 I1). Nothing here logs,
//! parses or decodes the bytes; a refusal is a stable code.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use nzb_core::MAX_NFO_BYTES;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;

use crate::fsops::{NFO_TRASH_PREFIX, unique_tag};

/// Ancestors examined when proving that the NZB's directory lies under the watch root (the scanner descends at most
/// 4 levels; a generous bound keeps the walk finite whatever happens).
const MAX_ANCESTORS: usize = 16;

/// The cap as the reader's `u64`.
fn cap() -> u64 {
    u64::try_from(MAX_NFO_BYTES).unwrap_or(u64::MAX)
}

/// Every letter-case spelling of a three-letter extension.
fn casings(ext: &'static str) -> impl Iterator<Item = String> {
    (0u8..8).map(move |mask| {
        ext.chars()
            .enumerate()
            .map(|(i, c)| {
                if mask & (1 << i) == 0 {
                    c
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect()
    })
}

/// Identity of a file for the move/unlink re-checks: inode, size and mtime (a rename or link advances only the
/// ctime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Id {
    dev: u64,
    ino: u64,
    size: i64,
    mtime: i128,
    mtime_nsec: i128,
}

impl Id {
    fn of(st: &Stat) -> Self {
        Self {
            dev: st.st_dev,
            ino: st.st_ino,
            size: st.st_size,
            mtime: i128::from(st.st_mtime),
            mtime_nsec: i128::from(st.st_mtime_nsec),
        }
    }
}

fn is_regular(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
}

/// The NZB's directory, opened and verified (see the module docs).
#[derive(Debug)]
pub(crate) struct Dir {
    fd: OwnedFd,
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

/// Opens the directory of the watch NZB `nzb` and proves that it still holds the inode `nzb_dev_ino` (the NZB that
/// was read) under `name`, and that `root` is one of its ancestors. Returns the directory and the NZB's entry name.
///
/// # Errors
/// A stable code: `NFO_CHANGED` (the NZB is not there any more), `NFO_OUTSIDE_ROOT`, `NFO_UNREADABLE`.
pub(crate) fn open_dir(
    nzb: &Path,
    nzb_dev_ino: (u64, u64),
    root: &Path,
) -> Result<(Dir, String), &'static str> {
    let (Some(parent), Some(name)) = (nzb.parent(), nzb.file_name().and_then(|n| n.to_str()))
    else {
        return Err("NFO_UNREADABLE");
    };
    let fd = rustix::fs::open(parent, dir_flags() | OFlags::NOFOLLOW, Mode::empty())
        .map_err(|_| "NFO_OUTSIDE_ROOT")?;
    let st = rustix::fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "NFO_CHANGED")?;
    if (st.st_dev, st.st_ino) != nzb_dev_ino {
        return Err("NFO_CHANGED");
    }
    // The watch root comes from the operator's configuration: following its own symlinks is intended.
    let watch_root =
        rustix::fs::open(root, dir_flags(), Mode::empty()).map_err(|_| "NFO_UNREADABLE")?;
    let root_st = rustix::fs::fstat(&watch_root).map_err(|_| "NFO_UNREADABLE")?;
    let root_id = (root_st.st_dev, root_st.st_ino);
    let mut cur = rustix::io::dup(&fd).map_err(|_| "NFO_UNREADABLE")?;
    let mut prev: Option<(u64, u64)> = None;
    for _ in 0..MAX_ANCESTORS {
        let st = rustix::fs::fstat(&cur).map_err(|_| "NFO_UNREADABLE")?;
        let id = (st.st_dev, st.st_ino);
        if id == root_id {
            return Ok((Dir { fd }, name.to_owned()));
        }
        // `/..` is `/` itself: the chain ended without meeting the root.
        if prev == Some(id) {
            break;
        }
        prev = Some(id);
        cur = rustix::fs::openat(&cur, c"..", dir_flags(), Mode::empty())
            .map_err(|_| "NFO_OUTSIDE_ROOT")?;
    }
    Err("NFO_OUTSIDE_ROOT")
}

/// What sits next to an NZB.
#[derive(Debug)]
enum Found {
    /// No entry with the NZB's stem and an `nfo` extension.
    None,
    /// Exactly one entry (of any type: a symlink or a directory is found, then refused).
    One(String, Stat),
    /// Two different NFO entries, or two different NZBs sharing the stem.
    Ambiguous,
}

/// Distinct inodes among the eight casings of `<stem>.<ext>` in `dir` (`fstatat`, nothing is followed).
fn entries(dir: &Dir, stem: &str, ext: &'static str) -> Vec<(String, Stat)> {
    let mut seen: Vec<(String, Stat)> = Vec::new();
    for e in casings(ext) {
        let name = format!("{stem}.{e}");
        let Ok(st) = rustix::fs::statat(&dir.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if !seen
            .iter()
            .any(|(_, s)| s.st_dev == st.st_dev && s.st_ino == st.st_ino)
        {
            seen.push((name, st));
        }
    }
    seen
}

fn find(dir: &Dir, nzb_name: &str) -> Found {
    let Some(stem) = Path::new(nzb_name).file_stem().and_then(|s| s.to_str()) else {
        return Found::None;
    };
    if stem.is_empty() {
        return Found::None;
    }
    let mut nfos = entries(dir, stem, "nfo");
    if nfos.is_empty() {
        return Found::None;
    }
    if nfos.len() > 1 || entries(dir, stem, "nzb").len() > 1 {
        return Found::Ambiguous;
    }
    nfos.pop()
        .map_or(Found::None, |(name, st)| Found::One(name, st))
}

/// A sidecar that was examined (and, unless refused for its size, read).
#[derive(Debug)]
pub(crate) struct Examined {
    /// Its entry name in [`Dir`].
    pub(crate) name: String,
    /// Identity of the examined (and read) file.
    pub(crate) id: Id,
    /// The bytes (1..=[`MAX_NFO_BYTES`]), or empty for an empty file; `None` when it was too large to read.
    pub(crate) bytes: Option<Vec<u8>>,
}

/// Result of [`probe`].
#[derive(Debug)]
pub(crate) enum Probe {
    /// No sidecar.
    Absent,
    /// Read and attachable.
    Ready(Examined),
    /// A regular, singly linked file that is not attachable because of its size (`NFO_EMPTY`, `NFO_TOO_LARGE`):
    /// it follows its NZB like an unattached one.
    Unattachable(Examined, &'static str),
    /// Not examined or not trusted: left where it is (stable code).
    Refused(&'static str),
}

/// Finds and reads the sidecar of the NZB `nzb_name` in `dir` (blocking).
pub(crate) fn probe(dir: &Dir, nzb_name: &str) -> Probe {
    let (name, st) = match find(dir, nzb_name) {
        Found::None => return Probe::Absent,
        Found::Ambiguous => return Probe::Refused("NFO_AMBIGUOUS"),
        Found::One(name, st) => (name, st),
    };
    if !is_regular(&st) {
        return Probe::Refused("NFO_NOT_REGULAR");
    }
    if st.st_nlink != 1 {
        return Probe::Refused("NFO_HARD_LINKED");
    }
    // NONBLOCK: a FIFO swapped in after the examination cannot hang the open.
    let fd = match rustix::fs::openat(
        &dir.fd,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Probe::Absent,
        Err(Errno::LOOP) => return Probe::Refused("NFO_NOT_REGULAR"),
        Err(_) => return Probe::Refused("NFO_UNREADABLE"),
    };
    let Ok(before) = rustix::fs::fstat(&fd) else {
        return Probe::Refused("NFO_UNREADABLE");
    };
    if !is_regular(&before) || before.st_dev != st.st_dev || before.st_ino != st.st_ino {
        return Probe::Refused("NFO_CHANGED");
    }
    if before.st_nlink != 1 {
        return Probe::Refused("NFO_HARD_LINKED");
    }
    let id = Id::of(&before);
    let size = u64::try_from(before.st_size).unwrap_or(u64::MAX);
    if size > cap() {
        let e = Examined {
            name,
            id,
            bytes: None,
        };
        return Probe::Unattachable(e, "NFO_TOO_LARGE");
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    if (&mut file)
        .take(cap().saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Probe::Refused("NFO_UNREADABLE");
    }
    let after = rustix::fs::fstat(&file).map(|s| Id::of(&s));
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if after.ok() != Some(id) || read != size {
        // Grew, shrank or was rewritten while it was read: nothing is trusted, nothing is moved.
        return Probe::Refused("NFO_CHANGED");
    }
    let empty = bytes.is_empty();
    let e = Examined {
        name,
        id,
        bytes: Some(bytes),
    };
    if empty {
        Probe::Unattachable(e, "NFO_EMPTY")
    } else {
        Probe::Ready(e)
    }
}

/// What [`remove`] or [`move_to`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Unlinked (its bytes are in the database).
    Removed,
    /// Moved to the destination.
    Moved,
    /// Left where it is, with the reason.
    Left(&'static str),
}

/// The entry `name` is still the examined file.
fn unchanged(dir: &Dir, name: &str, id: &Id) -> bool {
    rustix::fs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|st| is_regular(&st) && Id::of(&st) == *id)
}

/// Verified unlink relative to `dir`: rename to a hidden [`NFO_TRASH_PREFIX`] name, re-check the identity, unlink;
/// a file swapped in meanwhile is put back. `between` runs after the precheck (tests swap the file there).
pub(crate) fn remove(dir: &Dir, name: &str, id: &Id, between: impl FnOnce()) -> Outcome {
    if !unchanged(dir, name, id) {
        return Outcome::Left("NFO_CHANGED");
    }
    between();
    let trash = format!("{NFO_TRASH_PREFIX}{}", unique_tag());
    if rustix::fs::renameat_with(
        &dir.fd,
        name,
        &dir.fd,
        trash.as_str(),
        RenameFlags::NOREPLACE,
    )
    .is_err()
    {
        return Outcome::Left("NFO_IO");
    }
    if unchanged(dir, &trash, id) {
        if rustix::fs::unlinkat(&dir.fd, trash.as_str(), AtFlags::empty()).is_err() {
            return Outcome::Left("NFO_IO");
        }
        let _ = rustix::fs::fsync(&dir.fd);
        return Outcome::Removed;
    }
    // Someone replaced the file between the precheck and the rename: put it back. If yet another file appeared
    // meanwhile the link fails and the file stays under its hidden name (startup recovery moves it to failed/).
    if rustix::fs::linkat(&dir.fd, trash.as_str(), &dir.fd, name, AtFlags::empty()).is_ok() {
        let _ = rustix::fs::unlinkat(&dir.fd, trash.as_str(), AtFlags::empty());
    }
    Outcome::Left("NFO_CHANGED")
}

/// Moves the examined sidecar `name` into `dest_dir` as exactly `dest_name` (never a counter, never a replace,
/// review 54 L3): `linkat` relative to `dir`, the link re-checked against `id`, then the verified unlink of the
/// source name. Without hard links (another filesystem) the bytes that were read are written to a hidden part file
/// and published with `RENAME_NOREPLACE`; a file that was too large to read is never copied (review 54 I5).
pub(crate) fn move_to(
    dir: &Dir,
    e: &Examined,
    dest_dir: &Path,
    dest_name: &str,
    between: impl FnOnce(),
) -> Outcome {
    if !unchanged(dir, &e.name, &e.id) {
        return Outcome::Left("NFO_CHANGED");
    }
    let Ok(dest) = rustix::fs::open(dest_dir, dir_flags(), Mode::empty()) else {
        return Outcome::Left("NFO_IO");
    };
    let undo = |d: &OwnedFd| {
        let _ = rustix::fs::unlinkat(d, dest_name, AtFlags::empty());
        let _ = rustix::fs::fsync(d);
    };
    match rustix::fs::linkat(&dir.fd, e.name.as_str(), &dest, dest_name, AtFlags::empty()) {
        Ok(()) => {
            let linked = rustix::fs::statat(&dest, dest_name, AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|st| is_regular(&st) && Id::of(&st) == e.id);
            if !linked {
                undo(&dest);
                return Outcome::Left("NFO_CHANGED");
            }
        }
        Err(Errno::EXIST) => return Outcome::Left("NFO_DEST_TAKEN"),
        Err(_) => {
            let Some(bytes) = &e.bytes else {
                return Outcome::Left("NFO_NOT_COPIED");
            };
            if let Err(code) = copy_exact(&dest, bytes, dest_name) {
                return Outcome::Left(code);
            }
        }
    }
    let _ = rustix::fs::fsync(&dest);
    match remove(dir, &e.name, &e.id, between) {
        Outcome::Removed => Outcome::Moved,
        other => {
            // The source changed after the link: the copy under the new name is not that file any more.
            undo(&dest);
            other
        }
    }
}

/// Writes `bytes` to a hidden part file in `dest` (0600, fsync) and publishes it as exactly `dest_name`.
fn copy_exact(dest: &OwnedFd, bytes: &[u8], dest_name: &str) -> Result<(), &'static str> {
    let stem = dest_name.strip_suffix(".nfo").unwrap_or(dest_name);
    let part = format!(".{stem}.{}.part", unique_tag());
    let fd = rustix::fs::openat(
        dest,
        part.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| "NFO_IO")?;
    let mut f = File::from(fd);
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    let published = written.is_ok()
        && rustix::fs::renameat_with(dest, part.as_str(), dest, dest_name, RenameFlags::NOREPLACE)
            .is_ok();
    if published {
        return Ok(());
    }
    let taken = rustix::fs::statat(dest, dest_name, AtFlags::SYMLINK_NOFOLLOW).is_ok();
    let _ = rustix::fs::unlinkat(dest, part.as_str(), AtFlags::empty());
    Err(if taken { "NFO_DEST_TAKEN" } else { "NFO_IO" })
}

/// Bytes the sidecar of `nzb` may hold in memory (for the in-flight budget, an estimate by path): the size of the
/// largest `<stem>.<nfo casing>` regular file, at most the cap + 1.
pub(crate) fn size_hint(nzb: &Path) -> u64 {
    let (Some(dir), Some(stem)) = (nzb.parent(), nzb.file_stem().and_then(|s| s.to_str())) else {
        return 0;
    };
    casings("nfo")
        .filter_map(|e| std::fs::symlink_metadata(dir.join(format!("{stem}.{e}"))).ok())
        .filter(std::fs::Metadata::is_file)
        .map(|m| m.len().min(cap().saturating_add(1)))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    fn write(p: &Path, b: &[u8]) {
        fs::write(p, b).unwrap();
    }

    fn case_sensitive(dir: &Path) -> bool {
        write(&dir.join("probe.x"), b"1");
        let cs = fs::symlink_metadata(dir.join("PROBE.X")).is_err();
        fs::remove_file(dir.join("probe.x")).unwrap();
        cs
    }

    /// Opens the directory of `nzb` (which must exist) under `root`.
    fn dir_of(nzb: &Path, root: &Path) -> (Dir, String) {
        let m = fs::symlink_metadata(nzb).unwrap();
        open_dir(nzb, (m.dev(), m.ino()), root).unwrap()
    }

    fn probe_of(nzb: &Path, root: &Path) -> Probe {
        let (d, n) = dir_of(nzb, root);
        probe(&d, &n)
    }

    fn code(p: &Probe) -> &'static str {
        match p {
            Probe::Refused(c) | Probe::Unattachable(_, c) => c,
            Probe::Absent => "ABSENT",
            Probe::Ready(_) => "READY",
        }
    }

    #[test]
    fn eight_casings() {
        let all: Vec<String> = casings("nfo").collect();
        assert_eq!(all.len(), 8);
        for e in ["nfo", "NFO", "Nfo", "nFo", "nfO", "NFo", "NfO", "nFO"] {
            assert!(all.iter().any(|a| a == e), "{e}");
        }
    }

    #[test]
    fn same_stem_any_extension_case() {
        let d = tempfile::tempdir().unwrap();
        let nzb = d.path().join("Foo.Bar-GRP.nzb");
        write(&nzb, b"x");
        assert!(matches!(probe_of(&nzb, d.path()), Probe::Absent));
        write(&d.path().join("Foo.Bar-GRP.NfO"), b"art");
        match probe_of(&nzb, d.path()) {
            Probe::Ready(e) => {
                assert_eq!(e.bytes.as_deref(), Some(b"art".as_slice()));
                assert_eq!(e.name, "Foo.Bar-GRP.NfO");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stem_must_match_exactly() {
        let d = tempfile::tempdir().unwrap();
        let nzb = d.path().join("Foo.Bar-GRP.nzb");
        write(&nzb, b"x");
        for other in [
            "foo.bar-grp.nfo",
            "Foo.Bar-GRP2.nfo",
            "Foo.Bar.nfo",
            "Foo.Bar-GRP.nzb.nfo",
            "Foo.Bar-GRP .nfo",
            "Foo.Bar-GRP.nfo.txt",
        ] {
            write(&d.path().join(other), b"x");
        }
        if case_sensitive(d.path()) {
            assert!(matches!(probe_of(&nzb, d.path()), Probe::Absent));
        }
    }

    #[test]
    fn two_files_or_two_nzbs_are_ambiguous() {
        let d = tempfile::tempdir().unwrap();
        if !case_sensitive(d.path()) {
            return;
        }
        let nzb = d.path().join("Foo.nzb");
        write(&nzb, b"x");
        write(&d.path().join("Foo.nfo"), b"a");
        write(&d.path().join("Foo.NFO"), b"b");
        assert_eq!(code(&probe_of(&nzb, d.path())), "NFO_AMBIGUOUS");
        // Two names of one inode are one sidecar.
        fs::remove_file(d.path().join("Foo.NFO")).unwrap();
        fs::hard_link(d.path().join("Foo.nfo"), d.path().join("Foo.NFO")).unwrap();
        assert!(matches!(
            find(&dir_of(&nzb, d.path()).0, "Foo.nzb"),
            Found::One(..)
        ));
        // Review 54 I1: two NZBs sharing the stem never share the sidecar.
        write(&d.path().join("Pair.nzb"), b"1");
        write(&d.path().join("Pair.NZB"), b"2");
        write(&d.path().join("Pair.nfo"), b"art");
        for n in ["Pair.nzb", "Pair.NZB"] {
            assert_eq!(
                code(&probe_of(&d.path().join(n), d.path())),
                "NFO_AMBIGUOUS"
            );
        }
    }

    #[test]
    fn refusals_have_stable_codes() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let p = |name: &str| {
            let nzb = d.path().join(format!("{name}.nzb"));
            write(&nzb, b"x");
            probe_of(&nzb, d.path())
        };
        write(&d.path().join("empty.nfo"), b"");
        assert_eq!(code(&p("empty")), "NFO_EMPTY");
        write(&d.path().join("big.nfo"), &vec![b'x'; MAX_NFO_BYTES + 1]);
        let big = p("big");
        assert_eq!(code(&big), "NFO_TOO_LARGE");
        assert!(matches!(
            big,
            Probe::Unattachable(Examined { bytes: None, .. }, _)
        ));
        write(&outside.path().join("secret"), b"secret");
        std::os::unix::fs::symlink(outside.path().join("secret"), d.path().join("link.nfo"))
            .unwrap();
        assert_eq!(code(&p("link")), "NFO_NOT_REGULAR");
        fs::create_dir(d.path().join("dir.nfo")).unwrap();
        assert_eq!(code(&p("dir")), "NFO_NOT_REGULAR");
        write(&d.path().join("hl.nfo"), b"x");
        fs::hard_link(d.path().join("hl.nfo"), outside.path().join("hl2")).unwrap();
        assert_eq!(code(&p("hl")), "NFO_HARD_LINKED");
        // The maximum is accepted.
        write(&d.path().join("max.nfo"), &vec![b'y'; MAX_NFO_BYTES]);
        assert_eq!(code(&p("max")), "READY");
        assert_eq!(size_hint(&d.path().join("max.nzb")), cap());
        assert_eq!(
            size_hint(&d.path().join("big.nzb")),
            cap().saturating_add(1)
        );
        assert_eq!(size_hint(&d.path().join("none.nzb")), 0);
    }

    #[test]
    fn the_directory_must_hold_the_read_nzb_under_the_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sub = root.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let nzb = sub.join("A.nzb");
        write(&nzb, b"x");
        let m = fs::symlink_metadata(&nzb).unwrap();
        assert!(open_dir(&nzb, (m.dev(), m.ino()), root.path()).is_ok());
        // Another inode under that name.
        assert_eq!(
            open_dir(&nzb, (m.dev(), m.ino().wrapping_add(1)), root.path()).unwrap_err(),
            "NFO_CHANGED"
        );
        // The same inode, but the directory moved outside the root and a symlink took its place.
        fs::rename(&sub, outside.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("sub"), &sub).unwrap();
        assert_eq!(
            open_dir(&nzb, (m.dev(), m.ino()), root.path()).unwrap_err(),
            "NFO_OUTSIDE_ROOT"
        );
        // A real directory outside the root that holds the inode.
        let moved = outside.path().join("sub").join("A.nzb");
        assert_eq!(
            open_dir(&moved, (m.dev(), m.ino()), root.path()).unwrap_err(),
            "NFO_OUTSIDE_ROOT"
        );
    }

    #[test]
    fn moves_are_exact_and_removals_verified() {
        let root = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let nzb = root.path().join("A.nzb");
        write(&nzb, b"x");
        write(&root.path().join("A.nfo"), b"art");
        let (d, n) = dir_of(&nzb, root.path());
        let Probe::Ready(e) = probe(&d, &n) else {
            panic!("not ready")
        };
        // Taken: left in place, nothing replaced.
        write(&dest.path().join("X.nfo"), b"other");
        assert_eq!(
            move_to(&d, &e, dest.path(), "X.nfo", || {}),
            Outcome::Left("NFO_DEST_TAKEN")
        );
        assert_eq!(fs::read(dest.path().join("X.nfo")).unwrap(), b"other");
        assert!(root.path().join("A.nfo").exists());
        // Swapped between the precheck and the rename: the swapped-in file is put back, the link undone.
        let swap = || {
            fs::rename(root.path().join("A.nfo"), root.path().join("old")).unwrap();
            write(&root.path().join("A.nfo"), b"new art");
        };
        assert_eq!(
            move_to(&d, &e, dest.path(), "Y.nfo", swap),
            Outcome::Left("NFO_CHANGED")
        );
        assert_eq!(fs::read(root.path().join("A.nfo")).unwrap(), b"new art");
        assert!(!dest.path().join("Y.nfo").exists());
        // Changed since it was read: neither moved nor removed.
        assert_eq!(
            remove(&d, "A.nfo", &e.id, || {}),
            Outcome::Left("NFO_CHANGED")
        );
        let Probe::Ready(e2) = probe(&d, &n) else {
            panic!("not ready")
        };
        assert_eq!(
            move_to(&d, &e2, dest.path(), "Y.nfo", || {}),
            Outcome::Moved
        );
        assert_eq!(fs::read(dest.path().join("Y.nfo")).unwrap(), b"new art");
        assert!(!root.path().join("A.nfo").exists());
        // No trash or part names left behind.
        let left: Vec<String> = fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(left.iter().all(|n| !n.starts_with(".nzbd-")), "{left:?}");
    }

    #[test]
    fn copy_fallback_is_exact_and_bounded() {
        let dest = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(dest.path(), dir_flags(), Mode::empty()).unwrap();
        copy_exact(&fd, b"art", "Z.nfo").unwrap();
        assert_eq!(fs::read(dest.path().join("Z.nfo")).unwrap(), b"art");
        assert_eq!(
            copy_exact(&fd, b"two", "Z.nfo").unwrap_err(),
            "NFO_DEST_TAKEN"
        );
        assert_eq!(fs::read(dest.path().join("Z.nfo")).unwrap(), b"art");
        assert_eq!(
            fs::read_dir(dest.path()).unwrap().count(),
            1,
            "no part file left"
        );
    }
}
