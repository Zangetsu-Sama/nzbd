//! The collect pass: one walk over the matching, alive documents of every segment that counts them
//! (exact total), counts them per category (facets) and keeps the top `k` by the sort order, optionally
//! only those after/before a keyset cursor. Driven by our own loop (not `Searcher::search`) so the
//! deadline is checked between segment scorer builds and every [`CHECK_EVERY`] documents, and a
//! count-only pass can stop at the count budget (`Total::AtLeast`, owner question Q1).
//!
//! The order is the 2.x total order of every `SortKey` (`DATA_MODEL` "every sort order the UI offers"):
//! date desc/asc with undated releases last in both and ids in the direction of the sort, size, and
//! title in SQLite `NOCASE` order (ASCII-lower-cased bytes). Within a segment a document's rank is a
//! tuple of integers (titles: the bytes column's sorted ordinal, doubled so that a cursor title absent
//! from the segment falls strictly between two ordinals); across segments the winners' titles are
//! compared by bytes.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BinaryHeap};

use nzb_store::SortKey;
use tantivy::columnar::{BytesColumn, Column};
use tantivy::query::{EnableScoring, Query};
use tantivy::{DocId, DocSet, Searcher, SegmentReader, TERMINATED};

use crate::analyzer::{MAX_TITLE_BYTES, cap_bytes, nocase};
use crate::clock::Deadline;
use crate::cursor::{CursorParts, CursorValue};
use crate::error::SearchError;
use crate::schema::{UNDATED, col};

/// Documents between two deadline checks.
pub const CHECK_EVERY: u64 = 65_536;

/// Which rows a pass keeps.
#[derive(Debug, Clone)]
pub(crate) enum PageMode {
    /// Count (and facets) only.
    CountOnly,
    /// The first `k` rows of the order.
    First(usize),
    /// The last `k` rows of the order (returned in sort order).
    Last(usize),
    /// The first `k` rows after the cursor.
    After(CursorParts, usize),
    /// The last `k` rows before the cursor (returned in sort order).
    Before(CursorParts, usize),
}

/// Result of a pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct Collected {
    /// Release ids in the sort order.
    pub ids: Vec<i64>,
    /// Matches counted (all of them, unless `cut`).
    pub total: u64,
    /// Matches per category id (only when asked).
    pub facets: BTreeMap<u32, u64>,
    /// The count stopped at the count budget (count-only passes only): `total` is a lower bound.
    pub cut: bool,
    /// Matching documents visited (work done, for the fuzz target's work bound).
    pub visited: u64,
}

/// Rank of a document inside one segment: (undated group, primary, tie-break). Smaller is earlier.
pub(crate) type SegRank = (u8, i128, i128);

/// Rank across segments: titles compare by bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Prim {
    Num(i128),
    Asc(Vec<u8>),
    Desc(Reverse<Vec<u8>>),
}

pub(crate) type GlobalRank = (u8, Prim, i128);

pub(crate) const fn desc(sort: SortKey) -> bool {
    matches!(
        sort,
        SortKey::DateDesc | SortKey::SizeDesc | SortKey::TitleDesc
    )
}

const fn signed(v: i128, desc: bool) -> i128 {
    if desc { v.saturating_neg() } else { v }
}

/// Fast-field columns of one segment.
pub(crate) struct Columns {
    pub id: Column<i64>,
    pub posted: Column<i64>,
    pub size: Column<u64>,
    pub cat: Column<u64>,
    pub title: Option<BytesColumn>,
}

impl Columns {
    pub(crate) fn open(seg: &SegmentReader) -> Result<Self, SearchError> {
        let ff = seg.fast_fields();
        Ok(Self {
            id: ff.i64(col::ID)?,
            posted: ff.i64(col::POSTED)?,
            size: ff.u64(col::SIZE)?,
            cat: ff.u64(col::CAT)?,
            title: ff.bytes(col::TITLE_SORT)?,
        })
    }

    pub(crate) fn title_ord(&self, doc: DocId) -> u64 {
        self.title
            .as_ref()
            .and_then(|c| c.ords().first(doc))
            .unwrap_or(0)
    }

    pub(crate) fn rank(&self, sort: SortKey, doc: DocId, id: i64) -> SegRank {
        let d = desc(sort);
        let tie = signed(i128::from(id), d);
        match sort {
            SortKey::DateDesc | SortKey::DateAsc => {
                let p = self.posted.first(doc).unwrap_or(UNDATED);
                if p == UNDATED {
                    (1, 0, tie)
                } else {
                    (0, signed(i128::from(p), d), tie)
                }
            }
            SortKey::SizeDesc | SortKey::SizeAsc => {
                let s = self.size.first(doc).unwrap_or(0);
                (0, signed(i128::from(s), d), tie)
            }
            SortKey::TitleAsc | SortKey::TitleDesc => {
                let ord = i128::from(self.title_ord(doc));
                (0, signed(ord.saturating_mul(2), d), tie)
            }
        }
    }

    /// The cursor's rank in this segment's rank space.
    pub(crate) fn cursor_rank(
        &self,
        sort: SortKey,
        c: &CursorParts,
    ) -> Result<SegRank, SearchError> {
        let d = desc(sort);
        let tie = signed(i128::from(c.id), d);
        Ok(match &c.key {
            CursorValue::Date(None) => (1, 0, tie),
            CursorValue::Date(Some(p)) => (0, signed(i128::from(*p), d), tie),
            CursorValue::Size(s) => (0, signed(i128::from(*s), d), tie),
            CursorValue::Title(t) => {
                let key = nocase(cap_bytes(t, MAX_TITLE_BYTES)).into_bytes();
                let (lb, exact) = self.lower_bound(&key)?;
                let lb = i128::from(lb).saturating_mul(2);
                let prim = if exact { lb } else { lb.saturating_sub(1) };
                (0, signed(prim, d), tie)
            }
        })
    }

    /// First ordinal whose bytes are `>= key`, and whether they are equal (binary search over the
    /// sorted dictionary of the bytes column; O(log terms) lookups).
    fn lower_bound(&self, key: &[u8]) -> Result<(u64, bool), SearchError> {
        let Some(col) = &self.title else {
            return Ok((0, false));
        };
        let n = u64::try_from(col.num_terms()).unwrap_or(u64::MAX);
        let (mut lo, mut hi) = (0u64, n);
        let mut buf = Vec::new();
        while lo < hi {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            buf.clear();
            col.ord_to_bytes(mid, &mut buf)?;
            if buf.as_slice() < key {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        let exact = lo < n && {
            buf.clear();
            col.ord_to_bytes(lo, &mut buf)? && buf.as_slice() == key
        };
        Ok((lo, exact))
    }

    pub(crate) fn global(
        &self,
        sort: SortKey,
        (g, p, t): SegRank,
        doc: DocId,
    ) -> Result<GlobalRank, SearchError> {
        let prim = match sort {
            SortKey::TitleAsc | SortKey::TitleDesc => {
                let mut buf = Vec::new();
                if let Some(col) = &self.title {
                    col.ord_to_bytes(self.title_ord(doc), &mut buf)?;
                }
                if desc(sort) {
                    Prim::Desc(Reverse(buf))
                } else {
                    Prim::Asc(buf)
                }
            }
            _ => Prim::Num(p),
        };
        Ok((g, prim, t))
    }
}

/// Sorts `winners` and drops all but its `k` smallest (or largest) ranks, when it holds more.
pub(crate) fn keep_best(winners: &mut Vec<(GlobalRank, i64)>, k: usize, largest: bool) {
    if winners.len() <= k {
        return;
    }
    winners.sort_by(|a, b| a.0.cmp(&b.0).then(Ordering::Equal));
    if largest {
        winners.drain(..winners.len().saturating_sub(k));
    } else {
        winners.truncate(k);
    }
}

/// Keeps the `k` smallest (or largest) ranks seen.
struct TopK {
    k: usize,
    largest: bool,
    small: BinaryHeap<(SegRank, DocId, i64)>,
    large: BinaryHeap<Reverse<(SegRank, DocId, i64)>>,
}

impl TopK {
    fn new(k: usize, largest: bool) -> Self {
        Self {
            k,
            largest,
            small: BinaryHeap::new(),
            large: BinaryHeap::new(),
        }
    }

    fn push(&mut self, item: (SegRank, DocId, i64)) {
        if self.k == 0 {
            return;
        }
        if self.largest {
            if self.large.len() < self.k {
                self.large.push(Reverse(item));
            } else if self.large.peek().is_some_and(|Reverse(min)| item > *min) {
                self.large.pop();
                self.large.push(Reverse(item));
            }
        } else if self.small.len() < self.k {
            self.small.push(item);
        } else if self.small.peek().is_some_and(|max| item < *max) {
            self.small.pop();
            self.small.push(item);
        }
    }

    fn into_vec(self) -> Vec<(SegRank, DocId, i64)> {
        if self.largest {
            self.large.into_iter().map(|Reverse(x)| x).collect()
        } else {
            self.small.into_vec()
        }
    }
}

/// Time limits of one pass.
pub(crate) struct Limits<'a> {
    /// Hard deadline: exceeding it fails the search.
    pub deadline: &'a Deadline,
    /// Count budget, for [`PageMode::CountOnly`] only: a page needs every match to be exact, so a page
    /// pass always counts everything (bounded by `deadline` alone).
    pub count_budget: Option<&'a Deadline>,
    /// Documents between two clock readings ([`CHECK_EVERY`]; tests use 1).
    pub check_every: u64,
}

/// Runs one pass of `query` over `searcher`.
///
/// # Errors
/// [`SearchError::Deadline`]; engine errors.
pub(crate) fn run(
    searcher: &Searcher,
    query: &dyn Query,
    sort: SortKey,
    mode: &PageMode,
    want_facets: bool,
    limits: &Limits<'_>,
) -> Result<Collected, SearchError> {
    let deadline = limits.deadline;
    let count_budget = limits.count_budget;
    let check_every = limits.check_every.max(1);
    let weight = query.weight(EnableScoring::disabled_from_searcher(searcher))?;
    let (k, largest, cursor, keep_after) = match mode {
        PageMode::CountOnly => (0, false, None, true),
        PageMode::First(k) => (*k, false, None, true),
        PageMode::Last(k) => (*k, true, None, true),
        PageMode::After(c, k) => (*k, false, Some(c), true),
        PageMode::Before(c, k) => (*k, true, Some(c), false),
    };
    let mut out = Collected::default();
    let mut winners: Vec<(GlobalRank, i64)> = Vec::new();
    let mut seen = 0u64;
    'segments: for seg in searcher.segment_readers() {
        deadline.check()?;
        let mut scorer = weight.scorer(seg, 1.0)?;
        let cols = Columns::open(seg)?;
        let bound = match cursor {
            Some(c) => Some(cols.cursor_rank(sort, c)?),
            None => None,
        };
        let alive = seg.alive_bitset();
        let mut top = TopK::new(k, largest);
        let mut doc = scorer.doc();
        while doc != TERMINATED {
            seen = seen.saturating_add(1);
            if seen.is_multiple_of(check_every) {
                deadline.check()?;
                if matches!(mode, PageMode::CountOnly)
                    && count_budget.is_some_and(Deadline::expired)
                {
                    out.cut = true;
                    break 'segments;
                }
            }
            if alive.is_none_or(|a| a.is_alive(doc)) {
                out.total = out.total.saturating_add(1);
                if want_facets {
                    let c = cols.cat.first(doc).and_then(|c| u32::try_from(c).ok());
                    if let Some(c) = c {
                        let e = out.facets.entry(c).or_insert(0);
                        *e = e.saturating_add(1);
                    }
                }
                if k > 0
                    && let Some(id) = cols.id.first(doc)
                {
                    let r = cols.rank(sort, doc, id);
                    let pass = bound.is_none_or(|b| if keep_after { r > b } else { r < b });
                    if pass {
                        top.push((r, doc, id));
                    }
                }
            }
            doc = scorer.advance();
        }
        for (i, (r, d, id)) in top.into_vec().into_iter().enumerate() {
            if u64::try_from(i).is_ok_and(|i| i.is_multiple_of(check_every)) {
                deadline.check()?;
            }
            winners.push((cols.global(sort, r, d)?, id));
        }
        // Keep only the global `k` best after each segment: memory stays O(k), not O(segments * k).
        keep_best(&mut winners, k, largest);
    }
    winners.sort_by(|a, b| a.0.cmp(&b.0).then(Ordering::Equal));
    let n = winners.len();
    let keep: Vec<i64> = if largest {
        winners
            .into_iter()
            .skip(n.saturating_sub(k))
            .map(|(_, id)| id)
            .collect()
    } else {
        winners.into_iter().take(k).map(|(_, id)| id).collect()
    };
    out.ids = keep;
    out.visited = seen;
    Ok(out)
}
