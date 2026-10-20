//! Hostile request -> Tantivy [`Query`], built by our code only (SEC-089, `docs/v3/DATA_MODEL.md` 5.3).
//!
//! * Text is cut to [`MAX_Q_CHARS`] characters and analyzed by the indexing analyzer; at most
//!   [`MAX_Q_TOKENS`] tokens are kept. Every operator or syntax character is a separator, so no input
//!   can reach a query language (there is none: Tantivy's parser and regex queries are banned by lint).
//! * Each token must match (`Must`) in `title`, `files`, `poster` or `source_name` (`Should`): the 2.x FTS5 AND,
//!   plus the `.nzb` file name and release group text of T131.
//! * Prefix (last token, >= 3 chars) and fuzzy (tokens >= 5 chars, distance 1, at most 4 tokens)
//!   candidates are enumerated **here**, from each segment's term dictionary, before any weight exists
//!   (review M6): at most [`MAX_DICT_ENTRIES_PER_SEGMENT`] entries visited per token, field and segment;
//!   the union across segments keeps at most `expansion_terms_max` terms per token and field (exact
//!   length first, then rarest); the summed document frequency of the whole query stays within
//!   `expansion_postings_budget`, else the token falls back to its exact term and the page says
//!   "search narrowed". The result is a term set of bounded posting volume; no automaton is handed to
//!   Tantivy. The deadline is checked per segment. Expanded terms never leave this module except as
//!   counts (review I2: dictionaries still hold terms of trashed and hidden releases). With category
//!   exclusions, bounded posting checks admit only terms occurring in live, visible documents and
//!   rank them by visible frequency. Raw posting frequencies still bound decoding work. Dictionary
//!   and visibility-check caps may omit alternatives; the UI uses a corpus-independent notice for
//!   excluded-category searches rather than exposing which hidden dictionary caused a cap.
//! * Filters are typed: category ids (a parent also matches its direct children), the exclusion set as
//!   `MustNot` (hidden categories never count anywhere, SEC-090), ranges on fast fields, raw terms.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::OnceLock;

use levenshtein_automata::{DFA, Distance, LevenshteinAutomatonBuilder, SINK_STATE};
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, RangeQuery, TermQuery, TermSetQuery};
use tantivy::schema::{Field, IndexRecordOption};
use tantivy::{DocSet, Searcher, SegmentReader, TERMINATED, Term};
use tantivy_fst::Automaton;

use crate::analyzer::{analyze, cap_bytes, nocase};
use crate::clock::Deadline;
use crate::config::{
    FUZZY_MIN_CHARS, MAX_DICT_ENTRIES_PER_SEGMENT, MAX_FUZZY_TOKENS, MAX_Q_CHARS, MAX_Q_TOKENS,
    PREFIX_MIN_CHARS,
};
use crate::doc::{MAX_KEYWORD_BYTES, flag_terms};
use crate::error::SearchError;
use crate::request::SearchRequest;
use crate::schema::{Fields, UNDATED, col};

/// Posting visits allowed when checking expansion visibility, across all fields and tokens.
/// The caller shares this budget with a possible fuzzy fallback; ordinary searches without
/// exclusions do not need this additional scan.
pub const MAX_VISIBILITY_POSTINGS: u64 = 1_000_000;

/// Which expansions a build may run (decided by the caller from the match mode and `[search]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Expand {
    /// Prefix candidates for the last token.
    pub prefix: bool,
    /// Fuzzy (distance 1) candidates.
    pub fuzzy: bool,
}

/// Budgets of one build (from `[search]`, already clamped).
#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    /// Distinct expanded terms per token and field across segments.
    pub terms_max: usize,
    /// Summed document frequency of all expansions of the query.
    pub postings: u64,
    /// Dictionary entries visited per token, field and segment.
    pub dict_entries: usize,
    /// Posting visits for category visibility across the whole build, including all fields/tokens.
    pub visibility_postings: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            terms_max: crate::config::MAX_EXPANSION_TERMS,
            postings: 5_000_000,
            dict_entries: MAX_DICT_ENTRIES_PER_SEGMENT,
            visibility_postings: MAX_VISIBILITY_POSTINGS,
        }
    }
}

/// A built query.
pub struct Built {
    /// The query (always a `BooleanQuery` with at least one positive clause).
    pub query: Box<dyn Query>,
    /// The text produced at least one token.
    pub has_text: bool,
    /// An expansion was cut by a budget (fixed "search narrowed" notice).
    pub narrowed: bool,
    /// What the expansion did, in counts only (tests, diagnostics; never the terms).
    pub stats: ExpansionStats,
    /// The expanded terms per token, test-only (they are never displayed, review I2).
    #[cfg(test)]
    pub(crate) expanded: Vec<Vec<(Field, Vec<Vec<u8>>)>>,
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built")
            .field("has_text", &self.has_text)
            .field("narrowed", &self.narrowed)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Expansion counters of one build.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpansionStats {
    /// Query tokens after analysis and caps.
    pub tokens: usize,
    /// Tokens that got expansion candidates.
    pub expanded_tokens: usize,
    /// Largest number of dictionary entries visited for one token, field and segment.
    pub max_dict_visits: usize,
    /// Largest number of terms (exact + expansions) used for one token and field.
    pub max_terms_per_field: usize,
    /// Summed document frequency of the expansions kept.
    pub postings: u64,
    /// Posting visits used to check live-document category visibility (not a public UI counter).
    pub visibility_postings: u64,
}

/// The analyzed tokens of the request text (capped).
#[must_use]
pub fn text_tokens(q: Option<&str>) -> Vec<String> {
    let Some(q) = q else { return Vec::new() };
    let capped: String = q.chars().take(MAX_Q_CHARS).collect();
    analyze(&capped, MAX_Q_TOKENS)
}

/// Builds the query of `req` against the dictionaries of `searcher`.
///
/// # Errors
/// [`SearchError::Deadline`] when the deadline passes during expansion; engine errors reading a term
/// dictionary.
pub fn build(
    searcher: &Searcher,
    f: &Fields,
    req: &SearchRequest,
    expand: Expand,
    budgets: Budgets,
    deadline: &Deadline,
) -> Result<Built, SearchError> {
    let q = &req.query;
    let tokens = text_tokens(q.q.as_deref());
    let mut must: Vec<Box<dyn Query>> = Vec::new();
    let mut must_not: Vec<Box<dyn Query>> = Vec::new();
    let mut stats = ExpansionStats {
        tokens: tokens.len(),
        ..ExpansionStats::default()
    };
    let mut narrowed = false;
    let visibility_limit = budgets
        .visibility_postings
        .min(MAX_VISIBILITY_POSTINGS)
        .min(budgets.postings);
    let mut expansion = ExpansionContext {
        searcher,
        budgets,
        deadline,
        exclude: &req.query.exclude_categories,
        visibility_left: visibility_limit,
    };
    #[cfg(test)]
    let mut expanded_terms = Vec::new();

    let text_fields = [f.title, f.files, f.poster, f.source_name];
    let mut used_postings = 0u64;
    let last = tokens.len().saturating_sub(1);
    let mut fuzzy_tokens = 0usize;
    for (i, tok) in tokens.iter().enumerate() {
        let chars = tok.chars().count();
        let want_prefix = expand.prefix && i == last && chars >= PREFIX_MIN_CHARS;
        let want_fuzzy =
            expand.fuzzy && chars >= FUZZY_MIN_CHARS && fuzzy_tokens < MAX_FUZZY_TOKENS;
        if want_fuzzy {
            fuzzy_tokens = fuzzy_tokens.saturating_add(1);
        }
        let mut per_field: Vec<(Field, Vec<Vec<u8>>)> = Vec::with_capacity(text_fields.len());
        if want_prefix || want_fuzzy {
            stats.expanded_tokens = stats.expanded_tokens.saturating_add(1);
            let mut token_cost = 0u64;
            let mut cut = false;
            for field in text_fields {
                let mut cands = Candidates::default();
                if want_prefix {
                    collect_candidates(&mut expansion, field, tok, Kind::Prefix, &mut cands)?;
                }
                if want_fuzzy {
                    collect_candidates(&mut expansion, field, tok, Kind::Fuzzy, &mut cands)?;
                }
                stats.max_dict_visits = stats.max_dict_visits.max(cands.max_visits);
                let (chosen, over) = select(cands.terms, tok, budgets.terms_max);
                cut |= over || cands.truncated;
                let cost = if expansion.exclude.is_empty() {
                    chosen.iter().map(|(_, df)| *df).sum::<u64>()
                } else {
                    raw_posting_cost(searcher, field, &chosen, deadline)?
                };
                token_cost = token_cost.saturating_add(cost);
                per_field.push((field, chosen.into_iter().map(|(t, _)| t).collect()));
            }
            if used_postings.saturating_add(token_cost) > budgets.postings {
                // Over the query's posting budget: this token matches its exact term only.
                narrowed = true;
                per_field.clear();
            } else {
                used_postings = used_postings.saturating_add(token_cost);
                narrowed |= cut;
            }
        }
        must.push(token_clause(tok, &text_fields, &per_field, &mut stats));
        #[cfg(test)]
        expanded_terms.push(per_field);
    }
    stats.postings = used_postings;
    stats.visibility_postings = visibility_limit.saturating_sub(expansion.visibility_left);

    push_filters(f, req, &mut must, &mut must_not);

    let mut clauses: Vec<(Occur, Box<dyn Query>)> =
        Vec::with_capacity(must.len().saturating_add(2));
    if must.is_empty() {
        // A boolean query with only exclusions matches nothing in Tantivy: anchor it on all docs.
        clauses.push((Occur::Must, Box::new(AllQuery)));
    }
    clauses.extend(must.into_iter().map(|q| (Occur::Must, q)));
    clauses.extend(must_not.into_iter().map(|q| (Occur::MustNot, q)));
    Ok(Built {
        query: Box::new(BooleanQuery::new(clauses)),
        has_text: !tokens.is_empty(),
        narrowed,
        stats,
        #[cfg(test)]
        expanded: expanded_terms,
    })
}

/// `Should` over the text fields of the exact term (lazy) and, per field, the kept expansions.
fn token_clause(
    tok: &str,
    text_fields: &[Field],
    per_field: &[(Field, Vec<Vec<u8>>)],
    stats: &mut ExpansionStats,
) -> Box<dyn Query> {
    let mut alternatives: Vec<(Occur, Box<dyn Query>)> =
        Vec::with_capacity(text_fields.len().saturating_mul(2));
    for &field in text_fields {
        // The exact term stays a lazy `TermQuery`, walked by the collector with deadline checks;
        // only the budgeted expansions form a term set, whose weight decodes its postings eagerly
        // (review 32 L2).
        alternatives.push((
            Occur::Should,
            Box::new(TermQuery::new(
                Term::from_field_text(field, tok),
                IndexRecordOption::Basic,
            )),
        ));
        let extra = per_field
            .iter()
            .find(|(fl, _)| *fl == field)
            .map_or(&[][..], |(_, e)| e.as_slice());
        stats.max_terms_per_field = stats.max_terms_per_field.max(extra.len().saturating_add(1));
        if !extra.is_empty() {
            alternatives.push((Occur::Should, term_set(field, extra)));
        }
    }
    Box::new(BooleanQuery::new(alternatives))
}

fn term_set(field: Field, terms: &[Vec<u8>]) -> Box<dyn Query> {
    // Dictionary keys of text fields are UTF-8 (they come from analyzed tokens); anything else is
    // skipped rather than reinterpreted.
    let mut terms: Vec<Term> = terms
        .iter()
        .filter_map(|t| std::str::from_utf8(t).ok())
        .map(|t| Term::from_field_text(field, t))
        .collect();
    if terms.len() == 1
        && let Some(t) = terms.pop()
    {
        return Box::new(TermQuery::new(t, IndexRecordOption::Basic));
    }
    Box::new(TermSetQuery::new(terms))
}

/// Lazy term queries for a few terms (categories with their children, the XXX exclusion), a term set
/// beyond: a `TermSetQuery` decodes every posting into a bitset when its scorer is built (review 32 L2).
fn any_of(terms: Vec<Term>) -> Box<dyn Query> {
    const LAZY_UP_TO: usize = 64;
    if terms.len() > LAZY_UP_TO {
        return Box::new(TermSetQuery::new(terms));
    }
    Box::new(BooleanQuery::new(
        terms
            .into_iter()
            .map(|t| (Occur::Should, term_query(t)))
            .collect(),
    ))
}

/// Typed filters (`DATA_MODEL` v3 5.3). Never fails: every value is bound as a term or a range bound.
fn push_filters(
    f: &Fields,
    req: &SearchRequest,
    must: &mut Vec<Box<dyn Query>>,
    must_not: &mut Vec<Box<dyn Query>>,
) {
    let q = &req.query;
    if !q.categories.is_empty() {
        let ids = || q.categories.iter().map(|c| u64::from(*c));
        let mut any: Vec<Term> = ids().map(|c| Term::from_field_u64(f.cat, c)).collect();
        any.extend(ids().map(|c| Term::from_field_u64(f.cat_parent, c)));
        must.push(any_of(any));
    }
    if !q.exclude_categories.is_empty() {
        must_not.push(any_of(
            q.exclude_categories
                .iter()
                .map(|c| Term::from_field_u64(f.cat, u64::from(*c)))
                .collect(),
        ));
    }
    // Dates: the undated sentinel lies below every range (2.x: `posted_at >= x` is false for NULL).
    if q.since.is_some() || q.until.is_some() {
        let lo = q.since.unwrap_or(i64::MIN).max(UNDATED.saturating_add(1));
        let hi = q.until.map_or(Bound::Unbounded, |u| {
            Bound::Included(Term::from_field_i64(f.posted, u))
        });
        must.push(Box::new(RangeQuery::new(
            Bound::Included(Term::from_field_i64(f.posted, lo)),
            hi,
        )));
    }
    if q.min_bytes.is_some() || q.max_bytes.is_some() {
        let lo = q.min_bytes.unwrap_or(0);
        let hi = q.max_bytes.map_or(Bound::Unbounded, |m| {
            Bound::Included(Term::from_field_u64(f.size, m))
        });
        must.push(Box::new(RangeQuery::new(
            Bound::Included(Term::from_field_u64(f.size, lo)),
            hi,
        )));
    }
    for name in flag_terms(q.flags) {
        must.push(term_query(Term::from_field_text(f.flag, name)));
    }
    let keyword = |field: Field, v: &str, fold: bool| {
        let v = cap_bytes(v, MAX_KEYWORD_BYTES);
        let v = if fold { nocase(v) } else { v.to_owned() };
        term_query(Term::from_field_text(field, &v))
    };
    if let Some(v) = &q.family {
        must.push(keyword(f.family, v, false));
    }
    if let Some(v) = &q.resolution {
        must.push(keyword(f.resolution, v, false));
    }
    if let Some(v) = &q.source {
        must.push(keyword(f.source, v, false));
    }
    if let Some(v) = &q.group {
        must.push(keyword(f.group, v, true));
    }
    if let Some(v) = &req.source_label {
        must.push(keyword(f.label, v, true));
    }
    if let Some(y) = q.year {
        must.push(term_query(Term::from_field_u64(f.year, u64::from(y))));
    }
    if let Some(t) = req.ingested_since {
        // `added` is a fast-only column: the range runs on the column, not on an inverted index (T127). Inclusive
        // (review 42 I2): `ingested_at` has one-second resolution, so a release ingested in the second of the visit is
        // counted once more rather than never.
        must.push(Box::new(RangeQuery::new(
            Bound::Included(Term::from_field_i64(f.added, t)),
            Bound::Unbounded,
        )));
    }
    if let Some(a) = req.added_by {
        // An id that cannot exist matches nothing (never "no filter").
        let a = u64::try_from(a).unwrap_or(u64::MAX);
        must.push(term_query(Term::from_field_u64(f.added_by, a)));
    }
}

fn term_query(t: Term) -> Box<dyn Query> {
    Box::new(TermQuery::new(t, IndexRecordOption::Basic))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Prefix,
    Fuzzy,
}

/// Candidate terms of one token and field, unioned across segments (document frequencies summed).
#[derive(Default)]
struct Candidates {
    terms: BTreeMap<Vec<u8>, u64>,
    /// Some segment had more matching entries than the visit budget.
    truncated: bool,
    max_visits: usize,
}

/// One request-wide allowance; never replenish it for another token, field or segment.
struct ExpansionContext<'a> {
    searcher: &'a Searcher,
    budgets: Budgets,
    deadline: &'a Deadline,
    exclude: &'a [u32],
    visibility_left: u64,
}

fn levenshtein() -> &'static LevenshteinAutomatonBuilder {
    static BUILDER: OnceLock<LevenshteinAutomatonBuilder> = OnceLock::new();
    BUILDER.get_or_init(|| LevenshteinAutomatonBuilder::new(1, true))
}

/// Our own DFA adapter for the term dictionary walk (Tantivy keeps its one crate-private).
struct Dfa(DFA);

impl Automaton for Dfa {
    type State = u32;

    fn start(&self) -> u32 {
        self.0.initial_state()
    }

    fn is_match(&self, state: &u32) -> bool {
        matches!(self.0.distance(*state), Distance::Exact(_))
    }

    fn can_match(&self, state: &u32) -> bool {
        *state != SINK_STATE
    }

    fn accept(&self, state: &u32, byte: u8) -> u32 {
        self.0.transition(*state, byte)
    }
}

fn collect_candidates(
    ctx: &mut ExpansionContext<'_>,
    field: Field,
    token: &str,
    kind: Kind,
    out: &mut Candidates,
) -> Result<(), SearchError> {
    let searcher = ctx.searcher;
    for seg in searcher.segment_readers() {
        ctx.deadline.check()?;
        let inverted = seg.inverted_index(field)?;
        let dict = inverted.terms();
        let categories = (!ctx.exclude.is_empty())
            .then(|| seg.fast_fields().u64(col::CAT))
            .transpose()?;
        let mut visits = 0usize;
        let mut stream = match kind {
            Kind::Prefix => Stream::Range(dict.range().ge(token.as_bytes()).into_stream()?),
            Kind::Fuzzy => Stream::Dfa(
                dict.search(Dfa(levenshtein().build_dfa(token)))
                    .into_stream()?,
            ),
        };
        while let Some((key, df)) = stream.next() {
            if kind == Kind::Prefix && !key.starts_with(token.as_bytes()) {
                break;
            }
            if visits >= ctx.budgets.dict_entries {
                out.truncated = true;
                break;
            }
            visits = visits.saturating_add(1);
            if visits.is_multiple_of(1024) {
                ctx.deadline.check()?;
            }
            // The exact term stays lazy and must never spend the expansion work budget.
            if key == token.as_bytes() {
                continue;
            }
            let df = if let Some(categories) = &categories {
                let Some(df) = visible_frequency(ctx, seg, categories, field, key, df)? else {
                    out.truncated = true;
                    continue;
                };
                df
            } else {
                u64::from(df)
            };
            if df == 0 {
                continue;
            }
            let e = out.terms.entry(key.to_vec()).or_insert(0);
            *e = e.saturating_add(df);
        }
        out.max_visits = out.max_visits.max(visits);
    }
    Ok(())
}

/// Count only live, visible postings, admitting a complete term scan only when the remaining
/// allowance covers its raw frequency. Oversized terms are skipped, never scanned without a bound.
fn visible_frequency(
    ctx: &mut ExpansionContext<'_>,
    seg: &SegmentReader,
    categories: &tantivy::columnar::Column<u64>,
    field: Field,
    key: &[u8],
    raw_df: u32,
) -> Result<Option<u64>, SearchError> {
    if u64::from(raw_df) > ctx.visibility_left {
        return Ok(None);
    }
    let Ok(text) = std::str::from_utf8(key) else {
        return Ok(Some(0));
    };
    let term = Term::from_field_text(field, text);
    let Some(mut postings) = seg
        .inverted_index(field)?
        .read_postings(&term, IndexRecordOption::Basic)?
    else {
        return Ok(Some(0));
    };
    let alive = seg.alive_bitset();
    let mut visible = 0u64;
    let mut doc = postings.doc();
    while doc != TERMINATED {
        // Also enforce the bound while reading: do not rely solely on dictionary metadata.
        if ctx.visibility_left == 0 {
            return Ok(None);
        }
        ctx.visibility_left -= 1;
        if ctx.visibility_left.is_multiple_of(1024) {
            ctx.deadline.check()?;
        }
        if alive.is_none_or(|a| a.is_alive(doc))
            && categories
                .first(doc)
                .and_then(|c| u32::try_from(c).ok())
                .is_some_and(|c| !ctx.exclude.contains(&c))
        {
            visible = visible.saturating_add(1);
        }
        doc = postings.advance();
    }
    Ok(Some(visible))
}

/// A selected term can also occur in excluded documents or beyond a dictionary visit cap. Its raw
/// frequency across every segment, rather than its visible frequency, bounds term-set decoding.
fn raw_posting_cost(
    searcher: &Searcher,
    field: Field,
    chosen: &[(Vec<u8>, u64)],
    deadline: &Deadline,
) -> Result<u64, SearchError> {
    if chosen.is_empty() {
        return Ok(0);
    }
    let mut total = 0u64;
    for seg in searcher.segment_readers() {
        deadline.check()?;
        let inverted = seg.inverted_index(field)?;
        for (key, _) in chosen {
            if let Ok(text) = std::str::from_utf8(key) {
                total = total.saturating_add(u64::from(
                    inverted.doc_freq(&Term::from_field_text(field, text))?,
                ));
            }
        }
    }
    Ok(total)
}

/// The two dictionary walks behind one `next`.
enum Stream<'a> {
    Range(tantivy::termdict::TermStreamer<'a>),
    Dfa(tantivy::termdict::TermStreamer<'a, Dfa>),
}

impl Stream<'_> {
    fn next(&mut self) -> Option<(&[u8], u32)> {
        match self {
            Self::Range(s) => s.next().map(|(k, v)| (k, v.doc_freq)),
            Self::Dfa(s) => s.next().map(|(k, v)| (k, v.doc_freq)),
        }
    }
}

/// The expansions to use: at most `max - 1` candidates besides the token itself (which is always
/// queried, so a token and field never use more than `max` terms): the exact-length ones first, then
/// the rarest, then byte order (stable). Returns whether candidates were left out.
fn select(terms: BTreeMap<Vec<u8>, u64>, token: &str, max: usize) -> (Vec<(Vec<u8>, u64)>, bool) {
    let max = max.saturating_sub(1);
    let mut v: Vec<(Vec<u8>, u64)> = terms
        .into_iter()
        .filter(|(t, _)| t.as_slice() != token.as_bytes())
        .collect();
    v.sort_by(|a, b| {
        (a.0.len() != token.len())
            .cmp(&(b.0.len() != token.len()))
            .then(a.1.cmp(&b.1))
            .then(a.0.cmp(&b.0))
    });
    let over = v.len() > max;
    v.truncate(max);
    (v, over)
}
