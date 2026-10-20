//! The sorted walk (PERFORMANCE v3 section 1): for listings without text, walk each segment's sidecar
//! permutation in the sort order from the start, the end or a keyset cursor (binary search), test each
//! document against the filters on fast-field columns, and k-way merge the segments. A page costs about
//! `segments x (log n + k / selectivity)` column reads instead of a pass over every match.
//!
//! Eligible: no text tokens and no flag filter (flags are posting lists, not columns). Totals come from
//! the per-segment category histograms when only categories and exclusions filter (exact, same
//! snapshot); otherwise from a count pass (exact on the 2.x path, budgeted on the v3 path, Q1).
//! Both paths are checked against each other by the tests (rows, order, totals).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use nzb_store::{SearchQuery, SortKey};
use tantivy::columnar::{Column, StrColumn};
use tantivy::{DocId, Searcher, SegmentReader};

use crate::analyzer::{cap_bytes, nocase};
use crate::clock::Deadline;
use crate::collect::{Columns, GlobalRank, PageMode, SegRank};
use crate::doc::MAX_KEYWORD_BYTES;
use crate::engine::{Engine, Histogram};
use crate::error::SearchError;
use crate::query::text_tokens;
use crate::request::SearchRequest;
use crate::schema::UNDATED;
use crate::sidecar::{Family, Perm};

/// Column-testable filters of a request.
#[derive(Debug, Clone, Default)]
pub(crate) struct WalkFilter {
    categories: BTreeSet<u32>,
    exclude: BTreeSet<u32>,
    posted: Option<(i64, i64)>,
    size: Option<(u64, u64)>,
    year: Option<u64>,
    added_by: Option<u64>,
    /// `(column name, exact value)` of raw keyword filters.
    keywords: Vec<(&'static str, String)>,
}

impl WalkFilter {
    /// The filters of `req` when it can be walked (no text, no flags).
    pub(crate) fn of(req: &SearchRequest) -> Option<Self> {
        let q: &SearchQuery = &req.query;
        // `ingested_since` (T127) has no sidecar: the collect path answers it.
        if !text_tokens(q.q.as_deref()).is_empty()
            || !q.flags.is_empty()
            || req.ingested_since.is_some()
        {
            return None;
        }
        let posted = (q.since.is_some() || q.until.is_some()).then(|| {
            (
                q.since.unwrap_or(i64::MIN).max(UNDATED.saturating_add(1)),
                q.until.unwrap_or(i64::MAX),
            )
        });
        let size = (q.min_bytes.is_some() || q.max_bytes.is_some())
            .then(|| (q.min_bytes.unwrap_or(0), q.max_bytes.unwrap_or(u64::MAX)));
        let mut keywords = Vec::new();
        let raw = |v: &str| cap_bytes(v, MAX_KEYWORD_BYTES).to_owned();
        if let Some(v) = &q.family {
            keywords.push(("family", raw(v)));
        }
        if let Some(v) = &q.resolution {
            keywords.push(("resolution", raw(v)));
        }
        if let Some(v) = &q.source {
            keywords.push(("source", raw(v)));
        }
        if let Some(v) = &q.group {
            keywords.push(("group", nocase(&raw(v))));
        }
        if let Some(v) = &req.source_label {
            keywords.push(("label", nocase(&raw(v))));
        }
        Some(Self {
            categories: q.categories.iter().copied().collect(),
            exclude: q.exclude_categories.iter().copied().collect(),
            posted,
            size,
            year: q.year.map(u64::from),
            // An impossible id (negative) matches nothing, as on the query path.
            added_by: req.added_by.map(|a| u64::try_from(a).unwrap_or(u64::MAX)),
            keywords,
        })
    }

    /// Only categories and exclusions filter: totals and facets come from the histograms.
    pub(crate) fn histogram_only(&self) -> bool {
        self.posted.is_none()
            && self.size.is_none()
            && self.year.is_none()
            && self.added_by.is_none()
            && self.keywords.is_empty()
    }

    fn category_ok(&self, cat: u32, parent: u32) -> bool {
        !self.exclude.contains(&cat)
            && (self.categories.is_empty()
                || self.categories.contains(&cat)
                || self.categories.contains(&parent))
    }
}

/// Matches, and matches per category, from the histograms of every segment (filter must be
/// [`WalkFilter::histogram_only`]).
///
/// # Errors
/// Engine errors.
pub(crate) fn histogram_counts(
    engine: &Engine,
    searcher: &Searcher,
    filter: &WalkFilter,
) -> Result<(u64, BTreeMap<u32, u64>), SearchError> {
    let mut total = 0u64;
    let mut per_cat = BTreeMap::new();
    for seg in searcher.segment_readers() {
        let h: std::sync::Arc<Histogram> = engine.histogram(seg)?;
        for ((cat, parent), n) in h.iter() {
            if filter.category_ok(*cat, *parent) {
                total = total.saturating_add(*n);
                let e = per_cat.entry(*cat).or_insert(0u64);
                *e = e.saturating_add(*n);
            }
        }
    }
    Ok((total, per_cat))
}

/// Per-segment filter state.
struct SegTest {
    cat: Column<u64>,
    parent: Option<Column<u64>>,
    posted: Column<i64>,
    size: Column<u64>,
    year: Option<Column<u64>>,
    added_by: Option<Column<u64>>,
    keywords: Vec<(StrColumn, u64)>,
    /// Some keyword value does not exist in this segment: nothing here can match.
    impossible: bool,
}

impl SegTest {
    fn open(seg: &SegmentReader, cols: &Columns, f: &WalkFilter) -> Result<Self, SearchError> {
        let ff = seg.fast_fields();
        let mut keywords = Vec::new();
        let mut impossible = false;
        for (name, value) in &f.keywords {
            match ff.str(name)? {
                Some(col) => match col.dictionary().term_ord(value.as_bytes())? {
                    Some(ord) => keywords.push((col, ord)),
                    None => impossible = true,
                },
                None => impossible = true,
            }
        }
        if (f.year.is_some() && ff.column_opt::<u64>("year")?.is_none())
            || (f.added_by.is_some() && ff.column_opt::<u64>("added_by")?.is_none())
        {
            impossible = true;
        }
        Ok(Self {
            cat: cols.cat.clone(),
            parent: ff.column_opt::<u64>("cat_parent")?,
            posted: cols.posted.clone(),
            size: cols.size.clone(),
            year: ff.column_opt::<u64>("year")?,
            added_by: ff.column_opt::<u64>("added_by")?,
            keywords,
            impossible,
        })
    }

    fn matches(&self, f: &WalkFilter, doc: DocId) -> bool {
        let to32 = |v: Option<u64>| v.and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
        let cat = to32(self.cat.first(doc));
        let parent = self.parent.as_ref().map_or(cat, |p| to32(p.first(doc)));
        if !f.category_ok(cat, parent) {
            return false;
        }
        if let Some((lo, hi)) = f.posted {
            let p = self.posted.first(doc).unwrap_or(UNDATED);
            if p == UNDATED || p < lo || p > hi {
                return false;
            }
        }
        if let Some((lo, hi)) = f.size {
            let s = self.size.first(doc).unwrap_or(0);
            if s < lo || s > hi {
                return false;
            }
        }
        if let Some(y) = f.year
            && self.year.as_ref().and_then(|c| c.first(doc)) != Some(y)
        {
            return false;
        }
        if let Some(a) = f.added_by
            && self.added_by.as_ref().and_then(|c| c.first(doc)) != Some(a)
        {
            return false;
        }
        self.keywords
            .iter()
            .all(|(col, ord)| col.ords().first(doc) == Some(*ord))
    }
}

/// The ascending-rank sequence of a segment for one sort order, over its family permutation.
struct Seq<'a> {
    perm: &'a Perm,
    sort: SortKey,
}

impl Seq<'_> {
    fn len(&self) -> usize {
        self.perm.order.len()
    }

    fn at(&self, i: usize) -> Option<DocId> {
        let o = &self.perm.order;
        let n = o.len();
        let idx = match self.sort {
            SortKey::DateAsc | SortKey::SizeAsc | SortKey::TitleAsc => Some(i),
            SortKey::SizeDesc | SortKey::TitleDesc => n.checked_sub(1)?.checked_sub(i),
            // Dated releases newest first, then undated ones by id descending.
            SortKey::DateDesc => {
                let d = self.perm.undated_from;
                if i < d {
                    d.checked_sub(1)?.checked_sub(i)
                } else {
                    n.checked_sub(1)?.checked_sub(i.checked_sub(d)?)
                }
            }
        }?;
        o.get(idx).copied()
    }

    /// First position whose rank is not `pred` (ranks are non-decreasing along the sequence).
    fn partition_point(&self, mut pred: impl FnMut(DocId) -> bool) -> usize {
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            if self.at(mid).is_some_and(&mut pred) {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        lo
    }
}

/// One segment's walk in one direction.
struct SegWalk<'a> {
    seg: &'a SegmentReader,
    cols: Columns,
    test: SegTest,
    perm: std::sync::Arc<Perm>,
    sort: SortKey,
    /// Next position (forward) or one past it (backward).
    pos: usize,
    forward: bool,
}

impl SegWalk<'_> {
    /// The next matching live document, or `None` at the end of the sequence.
    fn next(
        &mut self,
        f: &WalkFilter,
        steps: &mut u64,
        limits: &WalkLimits<'_>,
    ) -> Result<Option<(SegRank, DocId, i64)>, SearchError> {
        if self.test.impossible {
            return Ok(None);
        }
        let seq = Seq {
            perm: &self.perm,
            sort: self.sort,
        };
        let alive = self.seg.alive_bitset();
        loop {
            let i = if self.forward {
                if self.pos >= seq.len() {
                    return Ok(None);
                }
                let i = self.pos;
                self.pos = self.pos.saturating_add(1);
                i
            } else {
                let Some(i) = self.pos.checked_sub(1) else {
                    return Ok(None);
                };
                self.pos = i;
                i
            };
            *steps = steps.saturating_add(1);
            if steps.is_multiple_of(limits.check_every) {
                limits.deadline.check()?;
            }
            let Some(doc) = seq.at(i) else {
                return Ok(None);
            };
            if alive.is_some_and(|a| !a.is_alive(doc)) || !self.test.matches(f, doc) {
                continue;
            }
            let Some(id) = self.cols.id.first(doc) else {
                continue;
            };
            return Ok(Some((self.cols.rank(self.sort, doc, id), doc, id)));
        }
    }
}

/// The merge heap of one direction.
enum Merge {
    Forward(BinaryHeap<Reverse<(GlobalRank, usize, i64)>>),
    Backward(BinaryHeap<(GlobalRank, usize, i64)>),
}

impl Merge {
    fn new(forward: bool) -> Self {
        if forward {
            Self::Forward(BinaryHeap::new())
        } else {
            Self::Backward(BinaryHeap::new())
        }
    }

    fn push(&mut self, g: GlobalRank, seg: usize, id: i64) {
        match self {
            Self::Forward(h) => h.push(Reverse((g, seg, id))),
            Self::Backward(h) => h.push((g, seg, id)),
        }
    }

    fn pop(&mut self) -> Option<(usize, i64)> {
        match self {
            Self::Forward(h) => h.pop().map(|Reverse((_, s, id))| (s, id)),
            Self::Backward(h) => h.pop().map(|(_, s, id)| (s, id)),
        }
    }
}

/// Time limits of a walk.
pub(crate) struct WalkLimits<'a> {
    pub deadline: &'a Deadline,
    pub check_every: u64,
}

/// The ids of one page by sorted walk (`mode` as in the collect pass; never `CountOnly`); `None` when
/// a segment's sidecar is not loaded (the caller collects). Also returns the documents walked.
///
/// # Errors
/// [`SearchError::Deadline`]; engine errors.
pub(crate) fn walk(
    engine: &Engine,
    searcher: &Searcher,
    sort: SortKey,
    mode: &PageMode,
    filter: &WalkFilter,
    limits: &WalkLimits<'_>,
) -> Result<Option<(Vec<i64>, u64)>, SearchError> {
    let (k, forward, cursor) = match mode {
        PageMode::CountOnly => return Ok(Some((Vec::new(), 0))),
        PageMode::First(k) => (*k, true, None),
        PageMode::Last(k) => (*k, false, None),
        PageMode::After(c, k) => (*k, true, Some(c)),
        PageMode::Before(c, k) => (*k, false, Some(c)),
    };
    if k == 0 {
        return Ok(Some((Vec::new(), 0)));
    }
    let family = Family::of(sort);
    let mut walks: Vec<SegWalk<'_>> = Vec::new();
    for seg in searcher.segment_readers() {
        limits.deadline.check()?;
        let cols = Columns::open(seg)?;
        let test = SegTest::open(seg, &cols, filter)?;
        // Never built here (review 32 M1): a sidecar that is not loaded means "collect instead".
        let Some(perm) = engine.sidecar_ready(seg, family) else {
            return Ok(None);
        };
        let start = {
            let seq = Seq { perm: &perm, sort };
            let rank = |d: DocId| cols.rank(sort, d, cols.id.first(d).unwrap_or(0));
            match cursor {
                None if forward => 0,
                None => seq.len(),
                Some(c) => {
                    let bound = cols.cursor_rank(sort, c)?;
                    if forward {
                        seq.partition_point(|d| rank(d) <= bound)
                    } else {
                        seq.partition_point(|d| rank(d) < bound)
                    }
                }
            }
        };
        walks.push(SegWalk {
            seg,
            cols,
            test,
            perm,
            sort,
            pos: start,
            forward,
        });
    }
    // k-way merge: smallest global rank first going forward, largest first going backward.
    let mut steps = 0u64;
    let mut heap = Merge::new(forward);
    for (i, w) in walks.iter_mut().enumerate() {
        if let Some((r, doc, id)) = w.next(filter, &mut steps, limits)? {
            heap.push(w.cols.global(sort, r, doc)?, i, id);
        }
    }
    let mut out = Vec::with_capacity(k);
    while out.len() < k {
        let Some((i, id)) = heap.pop() else { break };
        out.push(id);
        if let Some(w) = walks.get_mut(i)
            && let Some((r, doc, id)) = w.next(filter, &mut steps, limits)?
        {
            heap.push(w.cols.global(sort, r, doc)?, i, id);
        }
    }
    if !forward {
        out.reverse();
    }
    Ok(Some((out, steps)))
}

/// Rough number of matches of a walkable filter, for the planner: the category histograms bound it,
/// and so does the rarest keyword/year/uploader term (document frequency, deletes included).
///
/// # Errors
/// Engine errors.
pub(crate) fn estimate(
    engine: &Engine,
    searcher: &Searcher,
    filter: &WalkFilter,
) -> Result<u64, SearchError> {
    let (by_cat, _) = histogram_counts(engine, searcher, filter)?;
    let f = engine.fields();
    let mut est = by_cat;
    let mut terms = Vec::new();
    if let Some(y) = filter.year {
        terms.push(tantivy::Term::from_field_u64(f.year, y));
    }
    if let Some(a) = filter.added_by {
        terms.push(tantivy::Term::from_field_u64(f.added_by, a));
    }
    for (name, value) in &filter.keywords {
        let field = match *name {
            "family" => f.family,
            "resolution" => f.resolution,
            "source" => f.source,
            "group" => f.group,
            _ => f.label,
        };
        terms.push(tantivy::Term::from_field_text(field, value));
    }
    for t in &terms {
        est = est.min(searcher.doc_freq(t)?);
    }
    Ok(est)
}
