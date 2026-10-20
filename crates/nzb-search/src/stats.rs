//! Library statistics for the Statistics page (T132): bounded aggregations over the FAST columns of the index.
//!
//! Each section is one pass over the **visible** documents: the query is built by [`crate::query::build`] from a
//! request that carries only the caller's exclusion set, so hidden categories are the same `MustNot` clause as in the
//! release list (SEC-090) and a release in a hidden category changes no number, not even the list of group names.
//! The pass is our own loop (like [`crate::collect`]), so the search deadline is checked between segments and every
//! `check_every` documents (SEC-095), and every section runs in its own search slot: one that runs out of time
//! fails alone and the page shows the others.
//!
//! Output is bounded: at most [`MAX_TOP`] ranked values per list, at most [`MAX_MONTHS`] month buckets and
//! [`MAX_RECENT`] "added since" counters. Values are index keywords (already sanitized display data, capped at
//! [`crate::doc::MAX_KEYWORD_BYTES`]); the web layer escapes them.

use std::collections::HashMap;

use nzb_store::SearchQuery;
use tantivy::columnar::{Column, StrColumn};
use tantivy::query::EnableScoring;
use tantivy::{DocId, DocSet, SegmentReader, TERMINATED};

use crate::clock::Deadline;
use crate::engine::Engine;
use crate::error::SearchError;
use crate::query::{self, Budgets, Expand};
use crate::request::SearchRequest;

/// Most values of one ranked list (top groups, top years, resolutions, sources, families).
pub const MAX_TOP: usize = 25;
/// Most month buckets of the timeline.
pub const MAX_MONTHS: usize = 36;
/// Most "added since" counters.
pub const MAX_RECENT: usize = 4;
/// Most distinct values one list keeps counting (review 47 M1): group names come from uploads, so their number is
/// only bounded by the library. Beyond this, values not yet seen are not counted and the list says so
/// ([`Ranked::capped`]); the memory of a pass stays bounded whatever the library holds.
pub const MAX_DISTINCT_VALUES: usize = 100_000;
/// Dictionary terms resolved between two deadline checks when a segment's counts are merged.
const MERGE_CHECK_EVERY: u64 = 4_096;
/// Most distinct ordinals buffered before merging visible counts into the bounded value map.
const MAX_ORDINAL_COUNTERS: usize = 4_096;

/// What the Statistics page asks for. Every value is chosen by the server (never request text) and clamped here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsRequest {
    /// The caller's hidden category ids (instance rule plus the caller's preference, see
    /// [`crate::request::exclusion_set`]): excluded from every number.
    pub exclude: Vec<u32>,
    /// Release groups listed (at most [`MAX_TOP`]).
    pub top_groups: usize,
    /// Years listed (at most [`MAX_TOP`]).
    pub top_years: usize,
    /// Ascending month boundaries in Unix seconds: bucket `i` counts releases ingested in
    /// `[month_bounds[i], month_bounds[i + 1])`. At most [`MAX_MONTHS`] + 1 boundaries are used.
    pub month_bounds: Vec<i64>,
    /// "Added since" thresholds in Unix seconds: one count per threshold of releases ingested at or after it
    /// (at most [`MAX_RECENT`]).
    pub recent_since: Vec<i64>,
}

/// A ranked list of keyword values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ranked {
    /// `(value, releases)`, most releases first, ties by value ascending; at most the requested length.
    pub top: Vec<(String, u64)>,
    /// Releases without a value ("Unknown", "no group").
    pub without: u64,
    /// Distinct values seen (the list may be shorter); a lower bound when [`Ranked::capped`].
    pub distinct: u64,
    /// Releases counted (visible releases in the snapshot).
    pub total: u64,
    /// More than [`MAX_DISTINCT_VALUES`] distinct values: releases with a value first seen after the cap were not
    /// counted, so `distinct` is "at least" and the list may miss a value that only became large later.
    pub capped: bool,
}

/// Resolution, source, family and year breakdown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QualityStats {
    /// By scene resolution.
    pub resolution: Ranked,
    /// By scene source.
    pub source: Ranked,
    /// By scene family (`tv`, `anime`, `movie`, `music`; none = unknown).
    pub family: Ranked,
    /// Top years by releases (the values are decimal years).
    pub year: Ranked,
}

/// Releases ingested over time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineStats {
    /// Releases per month bucket, in the order of [`StatsRequest::month_bounds`] (one fewer than the boundaries).
    pub months: Vec<u64>,
    /// Releases ingested at or after each [`StatsRequest::recent_since`] threshold, same order.
    pub recent: Vec<u64>,
    /// Releases counted.
    pub total: u64,
}

/// The three engine sections of the Statistics page, each computed (or failed) on its own.
#[derive(Debug)]
pub struct LibraryStats {
    /// Top release groups and the releases without a group.
    pub groups: Result<Ranked, SearchError>,
    /// Quality breakdown.
    pub quality: Result<QualityStats, SearchError>,
    /// Releases over time.
    pub timeline: Result<TimelineStats, SearchError>,
}

impl LibraryStats {
    /// Every section failed with the same condition (no index, no aggregation support).
    #[must_use]
    pub fn unavailable(reason: &'static str) -> Self {
        Self {
            groups: Err(SearchError::NotServable(reason)),
            quality: Err(SearchError::NotServable(reason)),
            timeline: Err(SearchError::NotServable(reason)),
        }
    }
}

/// One aggregation over the matching documents of each segment.
trait Agg {
    /// Opens the columns of `seg`.
    fn open(&mut self, seg: &SegmentReader) -> Result<(), SearchError>;
    /// Counts one alive matching document of the open segment.
    fn doc(&mut self, doc: DocId, deadline: &Deadline, check_every: u64)
    -> Result<(), SearchError>;
    /// Folds the open segment into the totals, checking `deadline` while doing so.
    fn close(&mut self, deadline: &Deadline, check_every: u64) -> Result<(), SearchError>;
}

/// Runs `aggs` over the visible documents of `engine` (hidden categories excluded by the query), checking
/// `deadline` between segments and every `check_every` documents. Returns the documents counted.
fn scan(
    engine: &Engine,
    exclude: &[u32],
    deadline: &Deadline,
    check_every: u64,
    aggs: &mut [&mut dyn Agg],
) -> Result<u64, SearchError> {
    let searcher = engine.searcher();
    let req = SearchRequest {
        query: SearchQuery {
            exclude_categories: exclude.to_vec(),
            ..SearchQuery::default()
        },
        ..SearchRequest::default()
    };
    // No text: the build is the anchor plus the exclusion `MustNot`, exactly the release list's filter.
    let built = query::build(
        &searcher,
        engine.fields(),
        &req,
        Expand::default(),
        Budgets::default(),
        deadline,
    )?;
    let weight = built
        .query
        .weight(EnableScoring::disabled_from_searcher(&searcher))?;
    let check_every = check_every.max(1);
    let mut seen = 0u64;
    let mut counted = 0u64;
    for seg in searcher.segment_readers() {
        deadline.check()?;
        let mut scorer = weight.scorer(seg, 1.0)?;
        for a in aggs.iter_mut() {
            a.open(seg)?;
        }
        let alive = seg.alive_bitset();
        let mut doc = scorer.doc();
        while doc != TERMINATED {
            seen = seen.saturating_add(1);
            if seen.is_multiple_of(check_every) {
                deadline.check()?;
            }
            if alive.is_none_or(|a| a.is_alive(doc)) {
                counted = counted.saturating_add(1);
                for a in aggs.iter_mut() {
                    a.doc(doc, deadline, check_every)?;
                }
            }
            doc = scorer.advance();
        }
        for a in aggs.iter_mut() {
            a.close(deadline, check_every)?;
        }
    }
    Ok(counted)
}

/// Counts one keyword column in bounded batches of visible term ordinals, then merges by value.
struct StrCount {
    column: &'static str,
    col: Option<StrColumn>,
    per_ord: HashMap<u64, u64>,
    without: u64,
    by_value: HashMap<String, u64>,
    cap: usize,
    capped: bool,
    #[cfg(test)]
    peak_ordinal_capacity: usize,
}

impl StrCount {
    fn new(column: &'static str) -> Self {
        Self {
            column,
            col: None,
            per_ord: HashMap::new(),
            without: 0,
            by_value: HashMap::new(),
            cap: MAX_DISTINCT_VALUES,
            capped: false,
            #[cfg(test)]
            peak_ordinal_capacity: 0,
        }
    }

    /// With a smaller distinct-value cap (tests).
    #[cfg(test)]
    fn with_cap(column: &'static str, cap: usize) -> Self {
        Self {
            cap,
            ..Self::new(column)
        }
    }

    fn ranked(self, top: usize, total: u64) -> Ranked {
        let distinct = u64::try_from(self.by_value.len()).unwrap_or(u64::MAX);
        let mut all: Vec<(String, u64)> = self.by_value.into_iter().collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        all.truncate(top.min(MAX_TOP));
        Ranked {
            top: all,
            without: self.without,
            distinct,
            total,
            capped: self.capped,
        }
    }

    fn flush(&mut self, deadline: &Deadline, check_every: u64) -> Result<(), SearchError> {
        let Some(col) = self.col.as_ref() else {
            return Ok(());
        };
        // Only visible ordinals are buffered. Sorting and resolving this batch never scales with
        // the segment dictionary; a full batch is flushed even once the global value cap is reached,
        // so groups already retained still receive all of their subsequent counts.
        let mut counts: Vec<(u64, u64)> = self.per_ord.drain().collect();
        counts.sort_unstable_by_key(|(ord, _)| *ord);
        let by_value = &mut self.by_value;
        let cap = self.cap;
        let capped = &mut self.capped;
        let every = usize::try_from(check_every.clamp(1, MERGE_CHECK_EVERY)).unwrap_or(1);
        let mut ords = Vec::with_capacity(every.min(counts.len()));
        // Tantivy's dictionary callback cannot stop early: use bounded ascending batches with
        // deadline checks, including when a flush is triggered in the middle of a segment.
        for chunk in counts.chunks(every) {
            if chunk.len() == every {
                deadline.check()?;
            }
            ords.clear();
            ords.extend(chunk.iter().map(|(ord, _)| *ord));
            let mut values = chunk.iter().map(|(_, n)| *n);
            col.dictionary().sorted_ords_to_term_cb(&ords, |bytes| {
                let n = values.next().unwrap_or(0);
                // Keyword values are UTF-8; invalid values are skipped, never reinterpreted.
                let Ok(v) = std::str::from_utf8(bytes) else {
                    return;
                };
                if let Some(slot) = by_value.get_mut(v) {
                    *slot = slot.saturating_add(n);
                } else if by_value.len() < cap {
                    by_value.insert(v.to_owned(), n);
                } else {
                    *capped = true;
                }
            })?;
        }
        Ok(())
    }
}

impl Agg for StrCount {
    fn open(&mut self, seg: &SegmentReader) -> Result<(), SearchError> {
        self.col = seg.fast_fields().str(self.column)?;
        self.per_ord.clear();
        Ok(())
    }

    fn doc(
        &mut self,
        doc: DocId,
        deadline: &Deadline,
        check_every: u64,
    ) -> Result<(), SearchError> {
        let Some(ord) = self.col.as_ref().and_then(|c| c.ords().first(doc)) else {
            self.without = self.without.saturating_add(1);
            return Ok(());
        };
        if let Some(n) = self.per_ord.get_mut(&ord) {
            *n = n.saturating_add(1);
            return Ok(());
        }
        if self.per_ord.len() >= self.cap.clamp(1, MAX_ORDINAL_COUNTERS) {
            self.flush(deadline, check_every)?;
        }
        self.per_ord.insert(ord, 1);
        #[cfg(test)]
        {
            self.peak_ordinal_capacity = self.peak_ordinal_capacity.max(self.per_ord.capacity());
        }
        Ok(())
    }

    fn close(&mut self, deadline: &Deadline, check_every: u64) -> Result<(), SearchError> {
        self.flush(deadline, check_every)?;
        self.col = None;
        Ok(())
    }
}

/// Counts the values of the `year` column.
#[derive(Default)]
struct YearCount {
    col: Option<Column<u64>>,
    without: u64,
    by_year: HashMap<u64, u64>,
    capped: bool,
}

impl Agg for YearCount {
    fn open(&mut self, seg: &SegmentReader) -> Result<(), SearchError> {
        self.col = Some(seg.fast_fields().u64("year")?);
        Ok(())
    }

    fn doc(
        &mut self,
        doc: DocId,
        _deadline: &Deadline,
        _check_every: u64,
    ) -> Result<(), SearchError> {
        match self.col.as_ref().and_then(|c| c.first(doc)) {
            Some(y) => {
                if let Some(slot) = self.by_year.get_mut(&y) {
                    *slot = slot.saturating_add(1);
                } else if self.by_year.len() < MAX_DISTINCT_VALUES {
                    self.by_year.insert(y, 1);
                } else {
                    self.capped = true;
                }
            }
            None => self.without = self.without.saturating_add(1),
        }
        Ok(())
    }

    fn close(&mut self, _deadline: &Deadline, _check_every: u64) -> Result<(), SearchError> {
        self.col = None;
        Ok(())
    }
}

impl YearCount {
    fn ranked(self, top: usize, total: u64) -> Ranked {
        let distinct = u64::try_from(self.by_year.len()).unwrap_or(u64::MAX);
        let mut all: Vec<(u64, u64)> = self.by_year.into_iter().collect();
        // Most releases first; ties: the newer year first.
        all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        all.truncate(top.min(MAX_TOP));
        Ranked {
            top: all.into_iter().map(|(y, n)| (y.to_string(), n)).collect(),
            without: self.without,
            distinct,
            total,
            capped: self.capped,
        }
    }
}

/// Buckets the `added` (ingest time) column.
struct AddedCount {
    col: Option<Column<i64>>,
    bounds: Vec<i64>,
    months: Vec<u64>,
    since: Vec<i64>,
    recent: Vec<u64>,
}

impl Agg for AddedCount {
    fn open(&mut self, seg: &SegmentReader) -> Result<(), SearchError> {
        self.col = Some(seg.fast_fields().i64("added")?);
        Ok(())
    }

    fn doc(
        &mut self,
        doc: DocId,
        _deadline: &Deadline,
        _check_every: u64,
    ) -> Result<(), SearchError> {
        let Some(t) = self.col.as_ref().and_then(|c| c.first(doc)) else {
            return Ok(());
        };
        // Bucket i holds [bounds[i], bounds[i + 1]): the number of boundaries <= t, minus one.
        let after = self.bounds.partition_point(|b| *b <= t);
        if after > 0
            && let Some(slot) = self.months.get_mut(after.saturating_sub(1))
        {
            *slot = slot.saturating_add(1);
        }
        for (s, n) in self.since.iter().zip(self.recent.iter_mut()) {
            if t >= *s {
                *n = n.saturating_add(1);
            }
        }
        Ok(())
    }

    fn close(&mut self, _deadline: &Deadline, _check_every: u64) -> Result<(), SearchError> {
        self.col = None;
        Ok(())
    }
}

/// Top release groups (ASCII lower-cased keywords) and the releases without a group.
///
/// # Errors
/// [`SearchError::Deadline`]; engine errors.
pub(crate) fn groups(
    engine: &Engine,
    req: &StatsRequest,
    deadline: &Deadline,
    check_every: u64,
) -> Result<Ranked, SearchError> {
    let mut g = StrCount::new("group");
    let total = scan(engine, &req.exclude, deadline, check_every, &mut [&mut g])?;
    Ok(g.ranked(req.top_groups, total))
}

/// [`groups`] with a smaller distinct-value cap, returning the values held in memory at the end (tests).
#[cfg(test)]
pub(crate) fn groups_with_cap(
    engine: &Engine,
    req: &StatsRequest,
    deadline: &Deadline,
    check_every: u64,
    cap: usize,
) -> Result<(Ranked, usize), SearchError> {
    let mut g = StrCount::with_cap("group", cap);
    let total = scan(engine, &req.exclude, deadline, check_every, &mut [&mut g])?;
    let held = g.by_value.len();
    Ok((g.ranked(req.top_groups, total), held))
}

/// Includes the peak allocated ordinal-counter capacity, not just the final distinct-value map (tests).
#[cfg(test)]
pub(crate) fn groups_with_cap_and_ordinal_capacity(
    engine: &Engine,
    req: &StatsRequest,
    deadline: &Deadline,
    check_every: u64,
    cap: usize,
) -> Result<(Ranked, usize), SearchError> {
    let mut g = StrCount::with_cap("group", cap);
    let total = scan(engine, &req.exclude, deadline, check_every, &mut [&mut g])?;
    let capacity = g.peak_ordinal_capacity;
    Ok((g.ranked(req.top_groups, total), capacity))
}

/// Resolution, source, family and top years in one pass.
///
/// # Errors
/// [`SearchError::Deadline`]; engine errors.
pub(crate) fn quality(
    engine: &Engine,
    req: &StatsRequest,
    deadline: &Deadline,
    check_every: u64,
) -> Result<QualityStats, SearchError> {
    let mut res = StrCount::new("resolution");
    let mut src = StrCount::new("source");
    let mut fam = StrCount::new("family");
    let mut year = YearCount::default();
    let total = scan(
        engine,
        &req.exclude,
        deadline,
        check_every,
        &mut [&mut res, &mut src, &mut fam, &mut year],
    )?;
    Ok(QualityStats {
        resolution: res.ranked(MAX_TOP, total),
        source: src.ranked(MAX_TOP, total),
        family: fam.ranked(MAX_TOP, total),
        year: year.ranked(req.top_years, total),
    })
}

/// Releases per month bucket and "added since" counters.
///
/// # Errors
/// [`SearchError::Deadline`]; engine errors.
pub(crate) fn timeline(
    engine: &Engine,
    req: &StatsRequest,
    deadline: &Deadline,
    check_every: u64,
) -> Result<TimelineStats, SearchError> {
    let mut bounds: Vec<i64> = req
        .month_bounds
        .iter()
        .copied()
        .take(MAX_MONTHS.saturating_add(1))
        .collect();
    // A boundary list that is not ascending would put releases in the wrong bucket: keep the ascending prefix.
    let ascending = bounds
        .windows(2)
        .take_while(|w| matches!(w, [a, b] if a < b))
        .count();
    bounds.truncate(ascending.saturating_add(1).min(bounds.len()));
    let buckets = bounds.len().saturating_sub(1);
    let since: Vec<i64> = req.recent_since.iter().copied().take(MAX_RECENT).collect();
    let mut added = AddedCount {
        col: None,
        months: vec![0; buckets],
        bounds,
        recent: vec![0; since.len()],
        since,
    };
    let total = scan(
        engine,
        &req.exclude,
        deadline,
        check_every,
        &mut [&mut added],
    )?;
    Ok(TimelineStats {
        months: added.months,
        recent: added.recent,
        total,
    })
}
