//! Sorted-walk sidecars (`docs/v3/DATA_MODEL.md` 5.5, review L6 b): per segment and sort family, the
//! permutation of the segment's doc ids ordered by `(key, id)`, so a browse page is a binary search
//! plus a walk of about `k / selectivity` documents instead of a pass over every live document.
//!
//! * File: `<segment uuid>.<family>.sortperm` next to the segment, little-endian `u32` doc ids, exactly
//!   `4 x max_doc` bytes; written tmp + fsync + rename (+ directory fsync). Our code never memory-maps
//!   it (`memmap2` needs `unsafe`): it is read with a plain `std::fs::read`.
//! * Never trusted: before use the length must be `4 x max_doc`, every entry `< max_doc`, every doc id
//!   present exactly once, and the order must be the family's `(key, id, doc)` order (checked against
//!   the fast fields, `O(max_doc)` once per load). Anything else is discarded and rebuilt, never a panic.
//! * Lifecycle: built lazily on first use, cached per segment in memory, and after every commit the
//!   engine deletes sidecar files (and temporary leftovers) whose segment is not in the current
//!   `meta.json` (Tantivy's own garbage collection does not know these files).
//! * Ordering per family (ascending): date `(undated, posted, id)` (undated releases last), size
//!   `(size, id)`, title `(NOCASE title bytes, id)` (the bytes column's sorted ordinals).

use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use nzb_store::SortKey;
use tantivy::{DocId, SegmentReader};

use crate::collect::Columns;
use crate::error::SearchError;
use crate::schema::UNDATED;

/// One sidecar build or validation at a time, process-wide.
static BUILD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// File suffix of sidecars.
const SUFFIX: &str = ".sortperm";

/// The three sort families (each serves an ascending and a descending order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Posted date.
    Date,
    /// Total size.
    Size,
    /// Title (NOCASE).
    Title,
}

impl Family {
    /// Stable file-name part.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Date => "date",
            Self::Size => "size",
            Self::Title => "title",
        }
    }

    /// Family of a sort order.
    #[must_use]
    pub const fn of(sort: SortKey) -> Self {
        match sort {
            SortKey::DateDesc | SortKey::DateAsc => Self::Date,
            SortKey::SizeDesc | SortKey::SizeAsc => Self::Size,
            SortKey::TitleAsc | SortKey::TitleDesc => Self::Title,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "date" => Some(Self::Date),
            "size" => Some(Self::Size),
            "title" => Some(Self::Title),
            _ => None,
        }
    }
}

/// A validated permutation of one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Perm {
    /// Doc ids in ascending family order (deleted docs included; walks skip them).
    pub order: Vec<DocId>,
    /// Date family: index of the first undated doc in `order` (`order.len()` for other families).
    pub undated_from: usize,
}

/// Ascending family key of a doc: `(group, primary, id, doc)`. Group 1 holds the undated releases of
/// the date family (they close the sequence); the primary key is the order-preserving `u64` image of
/// `posted` (sign bit flipped), the size, or the title ordinal. The doc id breaks ties between copies of
/// one release id inside a segment (a deleted and a live copy), so the order is total and deterministic.
fn key(cols: &Columns, family: Family, doc: DocId) -> (u8, u64, i64, DocId) {
    let id = cols.id.first(doc).unwrap_or(0);
    match family {
        Family::Date => {
            let p = cols.posted.first(doc).unwrap_or(UNDATED);
            if p == UNDATED {
                (1, 0, id, doc)
            } else {
                (0, p.cast_unsigned() ^ (1 << 63), id, doc)
            }
        }
        Family::Size => (0, cols.size.first(doc).unwrap_or(0), id, doc),
        Family::Title => (0, cols.title_ord(doc), id, doc),
    }
}

fn undated_from(cols: &Columns, family: Family, order: &[DocId]) -> usize {
    if family != Family::Date {
        return order.len();
    }
    order.partition_point(|d| key(cols, family, *d).0 == 0)
}

/// Builds the permutation from the segment's fast fields, `O(max_doc log max_doc)` comparisons of keys
/// read from the columns. Memory is the result itself, 4 bytes per document (about 4 MB for a
/// 1M-document segment, 40 MB at 10M; review 32 M1): no key buffer is materialized.
pub(crate) fn build(cols: &Columns, family: Family, max_doc: DocId) -> Perm {
    let mut order: Vec<DocId> = (0..max_doc).collect();
    order.sort_unstable_by_key(|d| key(cols, family, *d));
    let undated_from = undated_from(cols, family, &order);
    Perm {
        order,
        undated_from,
    }
}

/// Strict decode + validation of a sidecar's bytes; `None` means "rebuild, do not trust".
pub(crate) fn validate(
    bytes: &[u8],
    cols: &Columns,
    family: Family,
    max_doc: DocId,
) -> Option<Perm> {
    let n = usize::try_from(max_doc).ok()?;
    if bytes.len() != n.checked_mul(4)? {
        return None;
    }
    let mut seen = vec![false; n];
    let mut order = Vec::with_capacity(n);
    let (chunks, rest) = bytes.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    for chunk in chunks {
        let d = u32::from_le_bytes(*chunk);
        let slot = seen.get_mut(usize::try_from(d).ok()?)?;
        if *slot {
            return None;
        }
        *slot = true;
        order.push(d);
    }
    let sorted = order
        .windows(2)
        .all(|w| matches!(w, [a, b] if key(cols, family, *a) < key(cols, family, *b)));
    if !sorted {
        return None;
    }
    let undated_from = undated_from(cols, family, &order);
    Some(Perm {
        order,
        undated_from,
    })
}

fn file_name(seg: &SegmentReader, family: Family) -> String {
    format!(
        "{}.{}{SUFFIX}",
        seg.segment_id().uuid_string(),
        family.name()
    )
}

/// The permutation of `seg` for `family`: read from `dir` and validated, else built (and written back
/// to `dir` when there is one; a failed write only costs a rebuild next time).
pub(crate) fn load_or_build(
    dir: Option<&Path>,
    seg: &SegmentReader,
    cols: &Columns,
    family: Family,
) -> Perm {
    let max_doc = seg.max_doc();
    let name = file_name(seg, family);
    // One build or validation at a time, process-wide (review 32 M1): never three permutations of one
    // big segment in memory together.
    let _one = BUILD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let want = u64::from(max_doc).saturating_mul(4);
    if let Some(dir) = dir
        // The length is checked before anything is read (review 32 I4).
        && fs::metadata(dir.join(&name)).is_ok_and(|m| m.is_file() && m.len() == want)
        && let Ok(bytes) = fs::read(dir.join(&name))
        && let Some(p) = validate(&bytes, cols, family, max_doc)
    {
        return p;
    }
    let p = build(cols, family, max_doc);
    if let Some(dir) = dir {
        let _ = write(dir, &name, &p.order);
    }
    p
}

fn write(dir: &Path, name: &str, order: &[DocId]) -> Result<(), SearchError> {
    // A unique temporary name per writer: two searches building the same sidecar never interleave.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.{n}.tmp"));
    let mut bytes = Vec::with_capacity(order.len().saturating_mul(4));
    for d in order {
        bytes.extend_from_slice(&d.to_le_bytes());
    }
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(name))?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// The segment uuid of a sidecar (or temporary sidecar) file name we wrote, `None` for any other file.
fn owner(name: &str) -> Option<&str> {
    let base = match name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) {
        // `.<uuid>.<family>.sortperm.<n>.tmp`
        Some(t) => {
            let (b, n) = t.rsplit_once('.')?;
            if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            b
        }
        None => name,
    };
    let rest = base.strip_suffix(SUFFIX)?;
    let (uuid, family) = rest.split_once('.')?;
    Family::parse(family)?;
    (uuid.len() == 32
        && uuid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(uuid)
}

/// Deletes sidecar files of segments not in `live` (uuid strings) and every temporary leftover.
/// Returns how many files were removed. Only names matching our exact pattern are touched.
///
/// # Errors
/// I/O errors listing the directory.
pub(crate) fn gc(dir: &Path, live: &HashSet<String>) -> Result<usize, SearchError> {
    let mut removed = 0usize;
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(uuid) = owner(name) else { continue };
        let temp = name.starts_with('.');
        if (temp || !live.contains(uuid))
            && e.file_type()?.is_file()
            && fs::remove_file(e.path()).is_ok()
        {
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}
