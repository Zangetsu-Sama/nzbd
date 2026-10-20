//! `GET /`: the release index (`docs/UI_SPEC.md`): search, filters, sort and keyset pagination.
//!
//! Works without JavaScript: the filter form is a plain GET form, sorting and paging are links,
//! and the whole state lives in the query string.
//!
//! Paging. Previous/Next links carry a cursor (`after=` / `before=`: the sort key and id of the row
//! at the page edge, opaque hex), so a page costs the same at any depth and does not shift when
//! releases are added or removed between two requests. `page=` stays: it is the number shown
//! (advisory next to a cursor, authoritative without one) and the jump-to-page / last-page path, which
//! is an offset query. A malformed cursor is a `400 BAD_QUERY` like any other bad parameter.
//!
//! v3 search contract (T123, ARCHITECTURE v3 3.5): the listing goes through [`SearchIndexV3`] with prefix matching
//! on the last word and the fuzzy fallback for a text query without an exact hit (D35 Q5), totals that may be a
//! lower bound ("more than n", Q1), numbered (offset) pages capped by the engine at 100,000 rows (Q2: a page beyond
//! the cap that is not near the end is the uniform `400 BAD_QUERY`; keyset neighbours avoid that offset cap).
//! Page numbers remain bounded by [`MAX_PAGE`], so Last is unavailable when the real last page exceeds it.
//! While no index generation is servable, the bounded degraded browse is used. Every condition is a fixed English
//! notice; expanded or approximate terms are never shown (review 30 I2).
//!
//! Every query parameter is untrusted. [`parse_params`] turns the raw query into an
//! [`IndexParams`] made only of validated values (allowlists, bounded integers, taxonomy
//! lookups, length caps); anything invalid is rejected with the uniform `BAD_QUERY` error and
//! unknown parameters are ignored. Pagination and sort links are rebuilt from the validated
//! struct and percent-encoded, never from the raw query string. All text reaches HTML through
//! askama's auto-escaping.

use nzb_store::prelude::*;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use nzb_core::{ReleaseFlags, Taxonomy};
use nzb_search::degraded::{self, DegradedPage, DegradedRequest};
use nzb_search::request::{MatchMode, SearchRequest, Total};
use nzb_search::{SearchError, SearchIndexV3};
use nzb_store::{
    CategorySource, LogOutcome, PageCursor, ReleaseRow, SearchQuery, SeekDir, SortKey, Store,
    StoreError,
};
use tokio::sync::Mutex;

use crate::SEGMENT_HEALTH_CHECK_AVAILABLE;
use crate::assets::Layout;
use crate::auth::{SessionCtx, SystemWallClock, WallClock};
use crate::csrf;
use crate::error::ApiError;

/// Default releases per page (`docs/UI_SPEC.md`); each account may choose 25, 50 or 100 (T133,
/// [`nzb_store::ReleasePageSize`]).
pub const PAGE_SIZE: u32 = 50;
/// Highest page number accepted.
pub const MAX_PAGE: u32 = 100_000;
/// Longest accepted search text, in characters.
pub const MAX_Q_CHARS: usize = 200;
/// Longest accepted release-group filter, in characters.
pub const MAX_GROUP_CHARS: usize = 64;
/// Largest accepted size bound, in MiB (1 PiB).
const MAX_MIB: u64 = 1 << 30;
/// Longest original file name shown under a title.
pub const MAX_SOURCE_NAME_BYTES: usize = 255;

pub(crate) const FAMILIES: &[&str] = &["tv", "anime", "movie", "music", "game"];

/// The one display label of a scene family (dropdown, filter chip, badges, release page, statistics): `tv` is an
/// acronym. Values, query parameters and stored data stay lowercase; an unknown family is shown as stored.
pub(crate) fn family_label(v: &str) -> String {
    match v {
        "tv" => "TV".to_owned(),
        "anime" => "Anime".to_owned(),
        "movie" => "Movie".to_owned(),
        "music" => "Music".to_owned(),
        "game" => "Game".to_owned(),
        other => other.to_owned(),
    }
}
pub(crate) const RESOLUTIONS: &[&str] = &["480p", "576p", "720p", "1080p", "2160p"];
pub(crate) const SOURCES: &[&str] = &[
    "CAM",
    "TS",
    "TC",
    "SCR",
    "R5",
    "HDTV",
    "PDTV",
    "SDTV",
    "DVDRip",
    "DVD",
    "WEBRip",
    "WEBDL",
    "BDRip",
    "BluRay",
    "Remux",
    "UHDBluRay",
    "CompleteBluray",
];

/// Shared handler state (the index page and the saved searches, T127).
#[derive(Clone)]
pub(crate) struct IndexState<S> {
    pub(crate) db: Store,
    /// The search engine (T091, T123): listing and search go through [`SearchIndexV3`] only.
    pub(crate) search: S,
    pub(crate) taxonomy: Arc<Taxonomy>,
    stats: Arc<Mutex<Option<StatsEntry>>>,
    /// The Statistics page cache (T132): per hidden set, single-flight.
    pub(crate) library: Arc<crate::stats::LibraryCache>,
    /// Wall clock for ages and the saved-search visit times (tests pass a manual one).
    pub(crate) clock: Arc<dyn WallClock>,
    /// Per-account budget of `POST /page-size` (T133, [`crate::page_size`]).
    pub(crate) page_size_saves: Arc<crate::ratelimit::KeyedLimiter<i64>>,
}

/// The single cached tile computation (bounded: one entry, never grows).
struct StatsEntry {
    at: std::time::Instant,
    /// The hidden-category set the numbers exclude; a different set is a different entry.
    hidden: Vec<u32>,
    stats: Stats,
}

/// How long the library totals are reused. v3: the totals are one O(categories) read of `category_stats` on both
/// backends (exact, maintained in the transaction of every change), so they are not cached across requests; the
/// lock still makes concurrent requests share one computation (single-flight).
const STATS_TTL: std::time::Duration = std::time::Duration::ZERO;
/// Rows in the "Latest ingests" timeline.
const TIMELINE_ROWS: u32 = 6;

/// Library-wide numbers for the stat tiles above the search card (T129; a summary line in 3.1).
#[derive(Clone, Copy)]
struct Stats {
    releases: u64,
    segments: u64,
    bytes: u64,
    incomplete: u64,
}

/// One "Latest ingests" entry.
struct Tick {
    /// Closed-set marker class: `ok`, `info` or `bad`.
    class: &'static str,
    /// Outcome text (colour is never the only signal).
    label: &'static str,
    name: String,
    ago: String,
    href: Option<String>,
}

/// `just now` / `2 minutes ago`, built from [`short_age`] so every place words ages the same way (timeline, the
/// Posted column and the release page, T124 U9).
pub(crate) fn ago_text(secs: i64) -> String {
    if secs < JUST_NOW_SECS {
        "just now".to_owned()
    } else {
        format!("{} ago", short_age(secs))
    }
}

/// Ages below this many seconds read `just now`.
const JUST_NOW_SECS: i64 = 5;

/// Segment total for the stat tile: thousands separators below one million, then `1.2M` / `3.4B`.
fn compact_count(n: u64) -> String {
    fn unit(n: u64, div: u64, suffix: &str) -> String {
        let tenths = n.saturating_mul(10) / div;
        format!("{}.{}{suffix}", tenths / 10, tenths % 10)
    }
    if n >= 1_000_000_000 {
        unit(n, 1_000_000_000, "B")
    } else if n >= 1_000_000 {
        unit(n, 1_000_000, "M")
    } else {
        compact_count_exact(n)
    }
}

/// Routes of the index page with the search engine (the Tantivy index in production; pass them as the
/// `session_routes` of [`crate::router_with_auth`], merged with the other UI routes). Generic (not `dyn`): the engine is picked once at start-up
/// and `SearchIndex` uses native async methods, which are not dyn-compatible.
pub fn routes_with<S: SearchIndexV3 + Clone + Send + Sync + 'static>(
    db: Store,
    search: S,
    taxonomy: Arc<Taxonomy>,
) -> Router {
    routes_with_clock(db, search, taxonomy, Arc::new(SystemWallClock))
}

/// [`routes_with`] with an explicit wall clock (tests). Also mounts the saved-search routes (T127), which share the
/// index state: they re-validate through the same parser and count through the same engine.
pub fn routes_with_clock<S: SearchIndexV3 + Clone + Send + Sync + 'static>(
    db: Store,
    search: S,
    taxonomy: Arc<Taxonomy>,
    clock: Arc<dyn WallClock>,
) -> Router {
    Router::new()
        .route("/", get(index::<S>))
        .route(
            "/search/saved",
            get(crate::saved::list_page::<S>).post(crate::saved::create::<S>),
        )
        .route("/search/saved/{id}", get(crate::saved::open::<S>))
        .route("/search/saved/{id}/rename", post(crate::saved::rename::<S>))
        .route("/search/saved/{id}/delete", post(crate::saved::delete::<S>))
        .route("/page-size", post(crate::page_size::post::<S>))
        .route("/stats", get(crate::stats::page::<S>))
        .with_state(IndexState {
            db,
            search,
            taxonomy,
            stats: Arc::new(Mutex::new(None)),
            page_size_saves: crate::page_size::limiter(&clock),
            library: Arc::default(),
            clock,
        })
}

/// Validated index parameters. Only values that passed [`parse_params`] live here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexParams {
    /// Search text (length-capped, may contain anything; only ever bound or escaped).
    pub q: Option<String>,
    /// Resolved category id.
    pub category: Option<u16>,
    /// `YYYY-MM-DD` lower date bound (validated calendar date).
    pub from: Option<String>,
    /// `YYYY-MM-DD` upper date bound.
    pub to: Option<String>,
    /// Minimum size in MiB.
    pub min_mib: Option<u64>,
    /// Maximum size in MiB.
    pub max_mib: Option<u64>,
    /// Only incomplete releases.
    pub incomplete: bool,
    /// Only releases with par2 files.
    pub par2: bool,
    /// Only obfuscated releases.
    pub obfuscated: bool,
    /// Scene family (allowlisted).
    pub family: Option<&'static str>,
    /// Scene resolution (allowlisted).
    pub resolution: Option<&'static str>,
    /// Scene source (allowlisted).
    pub source: Option<&'static str>,
    /// Scene year.
    pub year: Option<u32>,
    /// Release group.
    pub group: Option<String>,
    /// Sort order.
    pub sort: SortKey,
    /// 1-based page. With a cursor it only numbers the page shown.
    pub page: u32,
    /// Keyset position (`after=` / `before=`), decoded for the sort above.
    pub cursor: Option<(SeekDir, PageCursor)>,
    /// Degraded browse only (`dbefore=<release id>`): continue below this id (the last row shown). Ignored
    /// while the index serves.
    pub degraded_before: Option<i64>,
}

const SORTS: &[(&str, SortKey)] = &[
    ("date_desc", SortKey::DateDesc),
    ("date_asc", SortKey::DateAsc),
    ("size_desc", SortKey::SizeDesc),
    ("size_asc", SortKey::SizeAsc),
    ("title_asc", SortKey::TitleAsc),
    ("title_desc", SortKey::TitleDesc),
];

fn sort_name(s: SortKey) -> &'static str {
    SORTS
        .iter()
        .find(|(_, k)| *k == s)
        .map_or("date_desc", |(n, _)| n)
}

/// Marker for a rejected query (the handler answers `400 BAD_QUERY`).
#[derive(Debug, PartialEq, Eq)]
pub struct BadQuery;

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn pick(list: &'static [&'static str], v: &str) -> Result<&'static str, BadQuery> {
    list.iter().find(|x| **x == v).copied().ok_or(BadQuery)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
#[allow(clippy::many_single_char_names)]
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
#[allow(clippy::many_single_char_names)]
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Strict `YYYY-MM-DD` (years 1970..=2100) to the Unix time of 00:00:00 UTC that day.
#[allow(clippy::many_single_char_names)]
pub(crate) fn parse_date(s: &str) -> Result<i64, BadQuery> {
    let b = s.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return Err(BadQuery);
    }
    let num = |r: std::ops::Range<usize>| -> Result<i64, BadQuery> {
        let part = s.get(r).ok_or(BadQuery)?;
        if !all_digits(part) {
            return Err(BadQuery);
        }
        part.parse::<i64>().map_err(|_| BadQuery)
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1970..=2100).contains(&y) || !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return Err(BadQuery);
    }
    Ok(days_from_civil(y, m, d) * 86_400)
}

fn flag(form: &[(String, String)], name: &str) -> Result<bool, BadQuery> {
    match csrf::form_get(form, name) {
        None | Some("" | "0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(BadQuery),
    }
}

/// Validates the raw query string. Blank values count as absent (an HTML form submits every
/// field); unknown parameters are ignored; the first occurrence of a parameter wins.
///
/// # Errors
/// [`BadQuery`] when any known parameter is malformed or out of range.
pub fn parse_params(raw: Option<&str>, tax: &Taxonomy) -> Result<IndexParams, BadQuery> {
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    let get = |n: &str| csrf::form_get(&form, n).filter(|v| !v.is_empty());
    let mut p = IndexParams {
        page: 1,
        ..IndexParams::default()
    };
    if let Some(v) = get("q") {
        let v = v.trim();
        if v.chars().count() > MAX_Q_CHARS || v.chars().any(char::is_control) {
            return Err(BadQuery);
        }
        // Text without a single letter or digit searches nothing (the analyzer keeps letter/digit
        // runs only): treat it as an absent filter instead of showing "filtered" with everything listed.
        p.q = Some(invisible_stripped(v)).filter(|v| v.chars().any(char::is_alphanumeric));
    }
    if let Some(v) = get("cat") {
        p.category = Some(tax.resolve(v).ok_or(BadQuery)?);
    }
    if let Some(v) = get("from") {
        parse_date(v)?;
        p.from = Some(v.to_owned());
    }
    if let Some(v) = get("to") {
        parse_date(v)?;
        p.to = Some(v.to_owned());
    }
    for (name, slot) in [("min_mib", &mut p.min_mib), ("max_mib", &mut p.max_mib)] {
        if let Some(v) = get(name) {
            if v.len() > 10 || !all_digits(v) {
                return Err(BadQuery);
            }
            let n: u64 = v.parse().map_err(|_| BadQuery)?;
            if n > MAX_MIB {
                return Err(BadQuery);
            }
            *slot = Some(n);
        }
    }
    p.incomplete = flag(&form, "incomplete")?;
    p.par2 = flag(&form, "par2")?;
    p.obfuscated = flag(&form, "obfuscated")?;
    if let Some(v) = get("family") {
        p.family = Some(pick(FAMILIES, v)?);
    }
    if let Some(v) = get("res") {
        p.resolution = Some(pick(RESOLUTIONS, v)?);
    }
    if let Some(v) = get("source") {
        p.source = Some(pick(SOURCES, v)?);
    }
    if let Some(v) = get("year") {
        if v.len() != 4 || !all_digits(v) {
            return Err(BadQuery);
        }
        let y: u32 = v.parse().map_err(|_| BadQuery)?;
        if !(1900..=2100).contains(&y) {
            return Err(BadQuery);
        }
        p.year = Some(y);
    }
    if let Some(v) = get("group") {
        let v = v.trim();
        if v.chars().count() > MAX_GROUP_CHARS || v.chars().any(char::is_control) {
            return Err(BadQuery);
        }
        p.group = Some(invisible_stripped(v)).filter(|v| !v.is_empty());
    }
    if let Some(v) = get("sort") {
        p.sort = SORTS
            .iter()
            .find(|(n, _)| *n == v)
            .map(|(_, k)| *k)
            .ok_or(BadQuery)?;
    }
    if let Some(v) = get("page") {
        if v.len() > 6 || !all_digits(v) {
            return Err(BadQuery);
        }
        let n: u32 = v.parse().map_err(|_| BadQuery)?;
        if !(1..=MAX_PAGE).contains(&n) {
            return Err(BadQuery);
        }
        p.page = n;
    }
    if let Some(v) = get("dbefore") {
        if v.len() > 15 || !all_digits(v) {
            return Err(BadQuery);
        }
        let id: i64 = v.parse().map_err(|_| BadQuery)?;
        if id < 1 {
            return Err(BadQuery);
        }
        p.degraded_before = Some(id);
    }
    // Cursors are decoded last: they are only meaningful for the sort order just parsed.
    p.cursor = match (get("after"), get("before")) {
        (None, None) => None,
        (Some(c), None) => Some((SeekDir::After, decode_cursor(c, p.sort)?)),
        (None, Some(c)) => Some((SeekDir::Before, decode_cursor(c, p.sort)?)),
        (Some(_), Some(_)) => return Err(BadQuery),
    };
    Ok(p)
}

/// `q` / `group` without bidi controls and invisible format characters (review 42 I4): the text is echoed in the
/// form, the filter chips and a saved search's summary, so an RLO or a zero-width space must not reorder or hide
/// what the account sees. Uses the shared sanitizer (`nzb_core::sanitize_text`: the same set ingest strips from
/// titles, so a query still matches what was indexed; ZWJ/ZWNJ stay, as in titles), which also collapses whitespace
/// and applies NFC. Control characters were refused before this point. The byte cap only bounds the work: the input
/// is already at most 200 characters.
fn invisible_stripped(v: &str) -> String {
    nzb_core::sanitize_text(v, MAX_Q_CHARS.saturating_mul(4))
}

fn decode_cursor(raw: &str, sort: SortKey) -> Result<PageCursor, BadQuery> {
    PageCursor::decode(raw, sort).map_err(|_| BadQuery)
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
pub(crate) fn pct_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(char::from(b));
        } else {
            // Writing to a String cannot fail.
            let _ = std::fmt::Write::write_fmt(&mut o, format_args!("%{b:02X}"));
        }
    }
    o
}

impl IndexParams {
    pub(crate) fn is_filtered(&self) -> bool {
        self.q.is_some()
            || self.category.is_some()
            || self.from.is_some()
            || self.to.is_some()
            || self.min_mib.is_some()
            || self.max_mib.is_some()
            || self.incomplete
            || self.par2
            || self.obfuscated
            || self.family.is_some()
            || self.resolution.is_some()
            || self.source.is_some()
            || self.year.is_some()
            || self.group.is_some()
    }

    /// True when a filter that lives in the collapsed "More filters" block is active.
    fn any_secondary(&self) -> bool {
        self.family.is_some()
            || self.resolution.is_some()
            || self.source.is_some()
            || self.year.is_some()
            || self.group.is_some()
            || self.from.is_some()
            || self.to.is_some()
            || self.min_mib.is_some()
            || self.max_mib.is_some()
            || self.obfuscated
            || self.par2
    }

    /// Active-filter chips. Each link is rebuilt from the validated struct minus one filter
    /// (never from the raw query); the label text is escaped by the template.
    pub(crate) fn chips(&self, tax: &Taxonomy) -> Vec<Chip> {
        let mut out = Vec::new();
        let mut add = |label: String, f: &dyn Fn(&mut IndexParams)| {
            let mut c = self.clone();
            f(&mut c);
            out.push(Chip {
                label,
                href: c.href(tax, c.sort, 1, true),
            });
        };
        if let Some(v) = &self.q {
            add(format!("Search: {v}"), &|c| c.q = None);
        }
        if let Some(cat) = self.category.and_then(|c| tax.get(c)) {
            add(format!("Category: {}", cat.name), &|c| c.category = None);
        }
        if let Some(v) = self.family {
            add(format!("Family: {}", family_label(v)), &|c| c.family = None);
        }
        if let Some(v) = self.resolution {
            add(format!("Resolution: {v}"), &|c| c.resolution = None);
        }
        if let Some(v) = self.source {
            add(format!("Source: {v}"), &|c| c.source = None);
        }
        if let Some(v) = self.year {
            add(format!("Year: {v}"), &|c| c.year = None);
        }
        if let Some(v) = &self.group {
            add(format!("Group: {v}"), &|c| c.group = None);
        }
        if let Some(v) = &self.from {
            add(format!("From: {v}"), &|c| c.from = None);
        }
        if let Some(v) = &self.to {
            add(format!("To: {v}"), &|c| c.to = None);
        }
        if let Some(v) = self.min_mib {
            add(format!("Min size: {v} MiB"), &|c| c.min_mib = None);
        }
        if let Some(v) = self.max_mib {
            add(format!("Max size: {v} MiB"), &|c| c.max_mib = None);
        }
        for (on, label) in [
            (self.incomplete, "Incomplete only"),
            (self.par2, "Has par2"),
            (self.obfuscated, "Obfuscated only"),
        ] {
            if on {
                add(label.to_owned(), &|c| match label {
                    "Incomplete only" => c.incomplete = false,
                    "Has par2" => c.par2 = false,
                    _ => c.obfuscated = false,
                });
            }
        }
        out
    }

    /// The canonical parameter pairs of these filters (raw values, not encoded) plus `sort` when it is not the
    /// default. Built only from validated values; defaults are omitted. This is also the stored form of a saved
    /// search (T127, `crate::saved`): exactly these names, read back through [`parse_params`].
    pub(crate) fn canonical_pairs(
        &self,
        tax: &Taxonomy,
        sort: SortKey,
        with_filters: bool,
    ) -> Vec<(&'static str, String)> {
        let mut pairs: Vec<(&'static str, String)> = Vec::new();
        if with_filters {
            if let Some(v) = &self.q {
                pairs.push(("q", v.clone()));
            }
            if let Some(slug) = self
                .category
                .and_then(|c| tax.get(c))
                .map(|c| c.slug.as_str())
            {
                pairs.push(("cat", slug.to_owned()));
            }
            if let Some(v) = &self.from {
                pairs.push(("from", v.clone()));
            }
            if let Some(v) = &self.to {
                pairs.push(("to", v.clone()));
            }
            if let Some(v) = self.min_mib {
                pairs.push(("min_mib", v.to_string()));
            }
            if let Some(v) = self.max_mib {
                pairs.push(("max_mib", v.to_string()));
            }
            for (name, on) in [
                ("incomplete", self.incomplete),
                ("par2", self.par2),
                ("obfuscated", self.obfuscated),
            ] {
                if on {
                    pairs.push((name, "1".to_owned()));
                }
            }
            if let Some(v) = self.family {
                pairs.push(("family", v.to_owned()));
            }
            if let Some(v) = self.resolution {
                pairs.push(("res", v.to_owned()));
            }
            if let Some(v) = self.source {
                pairs.push(("source", v.to_owned()));
            }
            if let Some(v) = self.year {
                pairs.push(("year", v.to_string()));
            }
            if let Some(v) = &self.group {
                pairs.push(("group", v.clone()));
            }
        }
        if sort != SortKey::DateDesc {
            pairs.push(("sort", sort_name(sort).to_owned()));
        }
        pairs
    }

    /// Canonical href for these parameters with `sort`/`page` overridden. Built only from
    /// validated values ([`IndexParams::canonical_pairs`], percent-encoded); defaults are omitted. When
    /// `with_filters` is false only sort is kept.
    pub(crate) fn href(
        &self,
        tax: &Taxonomy,
        sort: SortKey,
        page: u32,
        with_filters: bool,
    ) -> String {
        let mut pairs: Vec<(&str, String)> = self
            .canonical_pairs(tax, sort, with_filters)
            .into_iter()
            .map(|(k, v)| (k, pct_encode(&v)))
            .collect();
        if page > 1 {
            pairs.push(("page", page.to_string()));
        }
        if pairs.is_empty() {
            return "/".to_owned();
        }
        let body = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("/?{body}")
    }

    /// A paging link: [`IndexParams::href`] for `page` plus the cursor of the row at the edge of the
    /// page being left. Without a cursor to encode (empty page, key too long for one) it is the plain
    /// page-number link, which always works.
    fn page_href(&self, tax: &Taxonomy, page: u32, at: Option<(SeekDir, &ReleaseRow)>) -> String {
        let base = self.href(tax, self.sort, page, true);
        let Some((dir, row)) = at else {
            return base;
        };
        let Some(cursor) = PageCursor::for_row(self.sort, row).encode() else {
            return base;
        };
        let name = match dir {
            SeekDir::After => "after",
            SeekDir::Before => "before",
        };
        let sep = if base.contains('?') { '&' } else { '?' };
        // Lowercase hex: nothing to percent-encode.
        format!("{base}{sep}{name}={cursor}")
    }

    /// The search for these parameters with `per_page` rows per page (an allowlisted size, T133).
    pub(crate) fn to_search(&self, per_page: u32) -> Result<SearchQuery, BadQuery> {
        let mut flags = ReleaseFlags::EMPTY;
        if self.incomplete {
            flags |= ReleaseFlags::INCOMPLETE;
        }
        if self.par2 {
            flags |= ReleaseFlags::HAS_PAR2;
        }
        if self.obfuscated {
            flags |= ReleaseFlags::OBFUSCATED;
        }
        let mib = |v: u64| v.checked_mul(1 << 20).ok_or(BadQuery);
        Ok(SearchQuery {
            q: self.q.clone(),
            categories: self.category.map(u32::from).into_iter().collect(),
            exclude_categories: Vec::new(),
            since: self.from.as_deref().map(parse_date).transpose()?,
            until: self
                .to
                .as_deref()
                .map(parse_date)
                .transpose()?
                .map(|t| t + 86_399),
            min_bytes: self.min_mib.map(mib).transpose()?,
            max_bytes: self.max_mib.map(mib).transpose()?,
            flags,
            family: self.family.map(str::to_owned),
            resolution: self.resolution.map(str::to_owned),
            source: self.source.map(str::to_owned),
            year: self.year,
            group: self.group.clone(),
            sort: self.sort,
            offset: self.page.saturating_sub(1).saturating_mul(per_page),
            limit: per_page,
        })
    }
}

/// `1.5 GiB` style size (binary units, one decimal, integer math).
#[must_use]
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut unit = 0usize;
    let mut tenths = u128::from(n) * 10;
    while tenths >= 10 * 1024 && unit < 4 {
        tenths /= 1024;
        unit += 1;
    }
    let label = UNITS.get(unit).copied().unwrap_or("TiB");
    format!("{}.{} {label}", tenths / 10, tenths % 10)
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp.
#[must_use]
pub fn format_date(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM:SS UTC` for a Unix timestamp (tooltip text; integer input only).
fn format_datetime_utc(secs: i64) -> String {
    let rem = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02}:{:02} UTC",
        format_date(secs),
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Age with the unit spelled out: `12 seconds`, `1 minute`, `2 hours`, `5 days`, `4 months`,
/// `2 years` (singular for exactly 1). Future timestamps (clock skew) read as `0 seconds`.
fn short_age(secs: i64) -> String {
    let s = secs.max(0);
    let (n, unit, one) = if s < 60 {
        (s, "seconds", "second")
    } else if s < 3600 {
        (s / 60, "minutes", "minute")
    } else if s < 86_400 {
        (s / 3600, "hours", "hour")
    } else if s < 86_400 * 60 {
        (s / 86_400, "days", "day")
    } else if s < 86_400 * 730 {
        (s / (86_400 * 30), "months", "month")
    } else {
        (s / (86_400 * 365), "years", "year")
    };
    format!("{n} {}", if n == 1 { one } else { unit })
}

pub(crate) struct Choice {
    pub(crate) value: String,
    pub(crate) label: String,
    pub(crate) selected: bool,
}

fn family_choices(current: Option<&str>) -> Vec<Choice> {
    FAMILIES
        .iter()
        .map(|v| Choice {
            value: (*v).to_owned(),
            label: family_label(v),
            selected: current == Some(*v),
        })
        .collect()
}

fn choices(list: &[&str], current: Option<&str>) -> Vec<Choice> {
    list.iter()
        .map(|v| Choice {
            value: (*v).to_owned(),
            label: (*v).to_owned(),
            selected: current == Some(*v),
        })
        .collect()
}

struct SortHead {
    label: &'static str,
    href: String,
    aria: &'static str,
}

struct Row {
    id: i64,
    title: String,
    /// The original file name, only when it says more than the title (T124 U1).
    source_name: Option<String>,
    /// Relative age (`3 minutes ago`), generated from an integer timestamp.
    posted: String,
    /// `YYYY-MM-DD` (UTC) after the age (T124 U9); empty when the posting date is unknown.
    posted_date: String,
    /// Exact UTC date-time for the cell tooltip, generated from an integer timestamp only.
    posted_title: String,
    category: String,
    category_source: &'static str,
    category_source_class: &'static str,
    /// The category-source badge is drawn only when it is informative: Fallback or Manual (T124 U4).
    category_badge: bool,
    size: String,
    files: u32,
    flags: Vec<FlagView>,
    /// The release has a live NFO (T144): an "NFO" badge; filled by one page-wide lookup, not per row.
    has_nfo: bool,
    scene: Vec<String>,
    /// Media source from scene info (`WEB`, `BluRay`, ...); display data.
    scene_source: Option<String>,
    /// Free-text source label given at upload (sanitized again at render time); `None` = `-`.
    source_label: Option<String>,
    /// How the NZB arrived (fixed label: `Watch folder`, `Upload`, `API`); `None` = unknown.
    origin: Option<&'static str>,
    /// `title` attribute of the one-line Source cell (T124 U3): the full label and the origin; escaped by askama.
    source_title: String,
    /// Predefined CSS width class (`w0`..`w100`, steps of 5) for the completeness meter.
    meter_class: String,
    /// `ok`, `warn` or `bad` fill colour class of the meter.
    meter_state: &'static str,
    /// Accessible text of the meter, for example `Complete: 97%`.
    meter_label: String,
    /// Completeness percent for the second line of the size cell.
    meter_pct: u64,
}

/// A status badge: a fixed CSS state class plus the (trusted, generated) label text.
pub(crate) struct FlagView {
    pub(crate) class: &'static str,
    pub(crate) text: String,
}

/// Slug of the top-level taxonomy ancestor of `cat` (empty when no category filter is active).
fn top_level_slug(tax: &Taxonomy, cat: Option<u16>) -> String {
    let mut cur = cat.and_then(|c| tax.get(c));
    // Depth is tiny (parents precede children); bound the walk anyway.
    for _ in 0..8 {
        match cur.and_then(|c| c.parent) {
            Some(pid) => cur = tax.get(pid),
            None => break,
        }
    }
    cur.map(|c| c.slug.clone()).unwrap_or_default()
}

/// Slug of the selected category itself (empty for none / unknown id).
fn selected_slug(tax: &Taxonomy, cat: Option<u16>) -> String {
    cat.and_then(|c| tax.get(c))
        .map(|c| c.slug.clone())
        .unwrap_or_default()
}

/// Releases per top-level category for the sidebar (T124 U14), from the exact per-category totals the store keeps
/// (`category_stats`, both backends, no schema change). Every category in `hidden` (the instance's `ui.show_xxx`
/// set plus the caller's own "Hide XXX for me") is left out before summing, so a count never reveals a hidden release.
pub(crate) fn browse_counts(
    tax: &Taxonomy,
    totals: &[(u32, u64)],
    hidden: &[u16],
) -> std::collections::HashMap<u16, u64> {
    let mut out = std::collections::HashMap::new();
    for (cat, n) in totals {
        let Ok(id) = u16::try_from(*cat) else {
            continue;
        };
        if hidden.contains(&id) {
            continue;
        }
        // The count of a category covers its whole subtree, so a release counts for itself and every ancestor.
        let mut cur = tax.get(id);
        for _ in 0..8 {
            let Some(c) = cur else { break };
            let slot = out.entry(c.id).or_insert(0_u64);
            *slot = slot.saturating_add(*n);
            cur = c.parent.and_then(|p| tax.get(p));
        }
    }
    out
}

/// Colour class for a flag label. Labels come from [`flag_labels`] (fixed text), never from the
/// NZB; the class is a closed set so no data reaches an attribute.
fn flag_class(text: &str) -> &'static str {
    if text.starts_with("Incomplete") || text.starts_with("Contains executable") {
        "bad"
    } else if text.starts_with("Par2") {
        "info"
    } else {
        "warn"
    }
}

pub(crate) fn flag_views(labels: Vec<String>) -> Vec<FlagView> {
    labels
        .into_iter()
        .map(|text| FlagView {
            class: flag_class(&text),
            text,
        })
        .collect()
}

/// Completeness as a whole percent (floored, so 100 only when nothing is missing) and its
/// CSS width class in steps of 5.
pub(crate) fn meter(present: u64, missing: u64, health: bool) -> (u64, String, &'static str) {
    // Without a real health check the gap-derived percentage is not availability: show full.
    let missing = if health { missing } else { 0 };
    let total = u128::from(present) + u128::from(missing);
    let pct = if total == 0 || missing == 0 {
        100
    } else {
        u64::try_from(u128::from(present) * 100 / total).unwrap_or(0)
    };
    let state = if missing == 0 {
        "ok"
    } else if pct >= 90 {
        "warn"
    } else {
        "bad"
    };
    (pct, format!("w{}", pct / 5 * 5), state)
}

/// Badge class for how a category was decided.
pub(crate) fn category_source_class(s: CategorySource) -> &'static str {
    match s {
        CategorySource::Scene => "src-scene",
        CategorySource::Upload => "src-upload",
        CategorySource::Meta => "src-meta",
        CategorySource::Fallback => "src-fallback",
        CategorySource::Manual => "src-manual",
    }
}

/// One removable active-filter chip.
pub(crate) struct Chip {
    pub(crate) label: String,
    href: String,
}

pub(crate) fn category_source_label(s: CategorySource) -> &'static str {
    match s {
        CategorySource::Scene => "Scene",
        CategorySource::Upload => "Upload",
        CategorySource::Meta => "Meta",
        CategorySource::Fallback => "Fallback",
        CategorySource::Manual => "Manual",
    }
}

/// Status badges as plain text. Repairability is always labelled an estimate: par2 block counts
/// come from untrusted file names (`docs/UI_SPEC.md`).
pub(crate) fn flag_labels(r: &ReleaseRow, health: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut f = r.flags;
    // T148: a manual category is the owner's choice, so a stale fallback bit (rows overridden before
    // the store cleared it) must not show "Uncategorized".
    if r.category_overridden || r.category_source == CategorySource::Manual {
        f = ReleaseFlags::from_bits_truncate(f.bits() & !ReleaseFlags::UNCATEGORIZED.bits());
    }
    // Incomplete/Repairability derive from gaps in the NZB's own numbering, not from a news
    // server check; hidden until `SEGMENT_HEALTH_CHECK_AVAILABLE` (the stored flag is untouched).
    if health && f.contains(ReleaseFlags::INCOMPLETE) {
        let n = r.missing_segment_count;
        let s = if n == 1 { "segment" } else { "segments" };
        out.push(format!("Incomplete: {n} {s} missing"));
        out.push(if r.par2_blocks == 0 {
            "Repairability (estimate): no recovery data".to_owned()
        } else if n <= r.par2_blocks {
            "Repairability (estimate): may be repairable".to_owned()
        } else {
            "Repairability (estimate): unlikely".to_owned()
        });
    }
    for (flag, text) in [
        (ReleaseFlags::OBFUSCATED, "Obfuscated"),
        (ReleaseFlags::HAS_EXECUTABLE, "Contains executable"),
        (ReleaseFlags::MULTIVOLUME_GAP, "Missing volume"),
        (ReleaseFlags::PASSWORD_HINT, "Password hint"),
        (ReleaseFlags::HAS_PAR2, "Par2"),
        (ReleaseFlags::UNCATEGORIZED, "Uncategorized"),
    ] {
        if f.contains(flag) {
            out.push(text.to_owned());
        }
    }
    out
}

fn scene_parts(r: &ReleaseRow) -> Vec<String> {
    let s = &r.scene;
    let mut v = Vec::new();
    if let Some(x) = &s.family {
        v.push(family_label(x));
    }
    if let Some(x) = &s.resolution {
        v.push(x.clone());
    }
    if let Some(x) = s.year {
        v.push(x.to_string());
    }
    if let Some(x) = &s.group {
        v.push(format!("Group {x}"));
    }
    v
}

/// True when the original file name only repeats the title: the title itself, or the title plus `.nzb` (any case).
/// Such a name line is noise under the title (T124 U1); a name that differs (an obfuscated upload, a renamed file)
/// is still shown.
pub(crate) fn file_name_repeats_title(title: &str, name: &str) -> bool {
    let stem = match name
        .len()
        .checked_sub(4)
        .and_then(|i| name.get(i..).map(|ext| (i, ext)))
    {
        Some((i, ext)) if ext.eq_ignore_ascii_case(".nzb") => name.get(..i).unwrap_or(name),
        _ => name,
    };
    stem == title
}

/// The sanitized original file name, or `None` when it is empty or only repeats the title. `title` is the stored
/// (raw) title: it is cleaned here exactly like the name, so the index and the release page take the same decision
/// even for a title with control or bidi characters (`SECURITY_REVIEW.md` 40 I2).
pub(crate) fn shown_file_name(title: &str, raw: Option<&str>) -> Option<String> {
    let title = nzb_core::sanitize_text(title, MAX_SOURCE_NAME_BYTES);
    // Defence in depth: ingest sanitizes too, but older rows and other writers may not.
    raw.map(|n| nzb_core::sanitize_text(n, MAX_SOURCE_NAME_BYTES))
        .filter(|n| !n.is_empty() && !file_name_repeats_title(&title, n))
}

/// Whether the category-source badge says something: only a fallback or a manual choice (T124 U4). "Scene" on
/// almost every row was noise; the release page still names the source for every release.
pub(crate) const fn category_badge_informative(s: CategorySource) -> bool {
    matches!(s, CategorySource::Fallback | CategorySource::Manual)
}

fn to_row(r: &ReleaseRow, tax: &Taxonomy, now: i64, health: bool) -> Row {
    let category = u16::try_from(r.category_id)
        .ok()
        .and_then(|id| tax.get(id))
        .map_or_else(|| "Unknown".to_owned(), |c| c.name.replace('/', " > "));
    let m = meter(r.segment_count, r.missing_segment_count, health);
    // Defence in depth like source_name: the store sanitizes, older rows/writers may not.
    let source_label = r
        .source_label
        .as_deref()
        .and_then(nzb_store::clean_source_label);
    let origin = r.origin.map(nzb_store::IngestOrigin::label);
    let source_title = match (&source_label, origin) {
        (Some(l), Some(o)) => format!("{l} (added via {o})"),
        (Some(l), None) => l.clone(),
        (None, Some(o)) => format!("Added via {o}"),
        (None, None) => String::new(),
    };
    Row {
        id: r.id,
        // Cleaned like the release page's title (defence in depth: ingest sanitizes, older rows/other writers may
        // not), so both pages show and compare the same text (SECURITY_REVIEW 40 I2).
        title: nzb_core::sanitize_text(&r.title, MAX_SOURCE_NAME_BYTES),
        source_name: shown_file_name(&r.title, r.source_name.as_deref()),
        posted: r
            .posted_at
            .map_or_else(|| "-".to_owned(), |t| ago_text(now.saturating_sub(t))),
        posted_date: r.posted_at.map_or_else(String::new, format_date),
        posted_title: r.posted_at.map_or_else(String::new, format_datetime_utc),
        category,
        category_source: category_source_label(r.category_source),
        category_source_class: category_source_class(r.category_source),
        category_badge: category_badge_informative(r.category_source),
        size: human_bytes(r.total_bytes),
        files: r.file_count,
        flags: flag_views(flag_labels(r, health)),
        has_nfo: false,
        scene: scene_parts(r),
        scene_source: r.scene.source.clone().filter(|x| !x.is_empty()),
        source_label,
        origin,
        source_title,
        meter_class: m.1,
        meter_state: m.2,
        meter_label: format!("Complete: {}%", m.0),
        meter_pct: m.0,
    }
}

#[derive(Template)]
#[template(path = "index.html")]
#[allow(clippy::struct_excessive_bools)] // independent display flags of one template
struct IndexPage {
    layout: Layout,
    p: IndexParams,
    filtered: bool,
    categories: Vec<Choice>,
    families: Vec<Choice>,
    resolutions: Vec<Choice>,
    sources: Vec<Choice>,
    title_head: SortHead,
    date_head: SortHead,
    size_head: SortHead,
    rows: Vec<Row>,
    /// Show the Incomplete tile and filter checkbox (only with a real health check).
    show_incomplete: bool,
    total: u64,
    first: u64,
    last: u64,
    page: u32,
    pages: u64,
    prev_href: Option<String>,
    next_href: Option<String>,
    first_href: String,
    last_href: Option<String>,
    clear_href: String,
    sort_value: &'static str,
    chips: Vec<Chip>,
    more_open: bool,
    stats: Option<StatsView>,
    ticks: Vec<Tick>,
    /// Checkbox column and the bulk action bar (T119; every role since T130, which added the bulk
    /// download). Always `Some`; an `Option` so the template keeps its T119 shape. Cosmetic: the
    /// bulk routes are enforced by the access gate.
    bulk: Option<BulkBar>,
    /// The total is a lower bound (the count stopped at `search.count_budget_ms`): "more than n", no
    /// page count and no Last link (T123, D35 Q1).
    approx: bool,
    /// The page count is known (exact total, not degraded): "page N of M". Last also needs a supported page number.
    pages_known: bool,
    /// The total with thousands separators (the status line).
    total_text: String,
    /// Fixed notices above the results (T123); never contain request or index text.
    notices: Vec<Notice>,
    /// Degraded browse (no servable index): the newest-first list with its own status line.
    degraded: bool,
    /// The hidden fields of the "Save this search" form (T127): the canonical filter pairs, escaped by askama.
    save_fields: Vec<(&'static str, String)>,
    /// The "Per page" control under the table (T133): the allowlisted sizes with the account's choice selected. The
    /// form re-sends `save_fields` (the same validated filters and sort) so the listing comes back on page 1.
    per_page_choices: Vec<Choice>,
}

/// One fixed notice above the results.
struct Notice {
    /// `info` (information) or `warn` (something is not available): a closed set of CSS classes.
    class: &'static str,
    text: String,
}

impl Notice {
    fn info(text: impl Into<String>) -> Self {
        Self {
            class: "info",
            text: text.into(),
        }
    }
}

/// Search narrowed: an expansion (prefix or fuzzy) was cut by its budget (review M6). Fixed text: the
/// expanded terms are never shown (review 30 I2).
pub const NOTICE_NARROWED: &str = "Search narrowed: a word matched too many index terms, so only part \
of them was searched. Type more of the word for complete results.";
/// With exclusions, a shared dictionary's actual cap event must not become a hidden-content signal.
/// This describes the request's bounded matching policy without claiming a truncation occurred.
pub const NOTICE_BOUNDED: &str = "Prefix and approximate matches use a limited set of alternatives. \
Use more specific search terms if a result is missing.";
/// The fuzzy fallback produced the page (no exact hit, D35 Q5). The approximate terms are never shown.
pub const NOTICE_APPROXIMATE: &str = "No exact matches. Showing approximate matches.";
/// Degraded browse (ARCHITECTURE v3 3.3).
pub const NOTICE_DEGRADED: &str = "The search index is being rebuilt. Until it is ready this list shows \
the newest releases only; search, sorting and filters other than category are not available.";
/// Degraded browse with a search, sort or filter other than category.
pub const NOTICE_DEGRADED_FILTERS: &str =
    "Search, sorting and filters other than category are available after the rebuild.";
/// Degraded browse of a category too small for the bounded walk.
pub const NOTICE_DEGRADED_CATEGORY: &str = "This category is available after the rebuild.";
/// Degraded browse that stopped at its row budget.
pub const NOTICE_DEGRADED_MORE: &str = "More releases are listed after the rebuild.";
/// An exact total can exceed the range of page numbers accepted by the UI.
const NOTICE_PAGE_LIMIT: &str = "The last page is beyond the supported page range. Narrow your search or filters to reach the end of the results.";

/// "More than n" notice (D35 Q1): `n` is the engine's lower bound, formatted with separators.
fn notice_more_than(n: u64) -> String {
    format!(
        "More than {} releases match. Counting all of them would take too long, so the number is a lower bound.",
        compact_count_exact(n)
    )
}

/// `123,456` (thousands separators; never the `1.2M` short form, a lower bound must stay exact).
pub(crate) fn compact_count_exact(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && digits.len().saturating_sub(i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// What the bulk action bar offers to the caller's role.
struct BulkBar {
    /// The category and source edits (admin only since D40, like `delete`).
    edit: bool,
    /// The delete button (admin).
    delete: bool,
    /// Most releases one bulk action may address.
    max: usize,
}

struct StatsView {
    releases: String,
    segments: String,
    size: String,
    incomplete: String,
}

impl<S: SearchIndexV3> IndexState<S> {
    /// Cached library totals. The lock is held during the refresh, so concurrent requests share
    /// one refresh (single-flight). A failing query hides the stat tiles instead of failing the page.
    async fn stats(&self, hidden: &[u32]) -> Option<Stats> {
        let mut guard = self.stats.lock().await;
        if let Some(e) = guard.as_ref()
            && e.at.elapsed() < STATS_TTL
            && e.hidden == hidden
        {
            return Some(e.stats);
        }
        let totals = self.db.release_totals_excluding(hidden).await.ok()?;
        // The Incomplete tile is not rendered while there is no real availability check
        // (SEGMENT_HEALTH_CHECK_AVAILABLE), and the count is a scan of every release row (no index
        // covers `flags`): 0.2-0.5 s at 1 M releases (T087), so it is only paid when it is shown.
        let incomplete = if SEGMENT_HEALTH_CHECK_AVAILABLE {
            self.search
                .search(&SearchQuery {
                    flags: ReleaseFlags::INCOMPLETE,
                    exclude_categories: hidden.to_vec(),
                    limit: 1,
                    ..SearchQuery::default()
                })
                .await
                .ok()?
                .total
        } else {
            0
        };
        let s = Stats {
            releases: totals.releases,
            segments: totals.segments,
            bytes: totals.bytes,
            incomplete,
        };
        *guard = Some(StatsEntry {
            at: std::time::Instant::now(),
            hidden: hidden.to_vec(),
            stats: s,
        });
        Some(s)
    }

    async fn ticks(&self, hidden: &[u32]) -> Vec<Tick> {
        let now = self.clock.now_secs();
        let rows = self
            .db
            .list_ingest_log_excluding(TIMELINE_ROWS, hidden)
            .await
            .unwrap_or_default();
        rows.iter()
            .map(|r| {
                let (class, label) = match r.outcome {
                    LogOutcome::Ok => ("ok", "Added"),
                    LogOutcome::Duplicate => ("info", "Duplicate"),
                    LogOutcome::Failed => ("bad", "Failed"),
                };
                let name = r
                    .source_name
                    .as_deref()
                    .map(|n| nzb_core::sanitize_text(n, MAX_SOURCE_NAME_BYTES))
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "(unnamed)".to_owned());
                Tick {
                    class,
                    label,
                    name,
                    ago: ago_text(now.saturating_sub(r.ts)),
                    href: r.release_id.map(|id| format!("/release/{id}")),
                }
            })
            .collect()
    }
}

fn head(
    label: &'static str,
    asc: SortKey,
    desc: SortKey,
    default_desc: bool,
    p: &IndexParams,
    tax: &Taxonomy,
) -> SortHead {
    let (aria, next) = if p.sort == asc {
        ("ascending", desc)
    } else if p.sort == desc {
        ("descending", asc)
    } else {
        ("none", if default_desc { desc } else { asc })
    };
    SortHead {
        label,
        href: p.href(tax, next, 1, true),
        aria,
    }
}

/// `<select>` options for the taxonomy, without the `hidden` category ids.
pub(crate) fn category_choices(
    tax: &Taxonomy,
    current: Option<u16>,
    hidden: &[u16],
) -> Vec<Choice> {
    tax.display_order()
        .into_iter()
        .filter(|c| !hidden.contains(&c.id))
        .map(|c| Choice {
            value: c.slug.clone(),
            label: if c.parent.is_some() {
                format!("\u{a0}\u{a0}{}", c.name)
            } else {
                c.name.clone()
            },
            selected: current == Some(c.id),
        })
        .collect()
}

/// The Previous and Next links. Which neighbours exist: by offset the page count says (or, with a lower-bound
/// total, the engine's `has_more`); next to a cursor the side that was travelled says (one row over-fetched) and the
/// side that was left is taken to exist (a click on it that finds nothing renders the empty-page notice).
fn pager_links(
    p: &IndexParams,
    tax: &Taxonomy,
    items: &[ReleaseRow],
    has_more: bool,
    pages: Option<u64>,
) -> (Option<String>, Option<String>) {
    let (has_prev, has_next) = match &p.cursor {
        None => (
            p.page > 1,
            pages.map_or(has_more, |n| u64::from(p.page) < n),
        ),
        Some((SeekDir::After, _)) => (p.page > 1, has_more),
        Some((SeekDir::Before, _)) => (has_more, !items.is_empty()),
    };
    let prev_page = p.page.saturating_sub(1).max(1);
    let next_page = p.page.saturating_add(1).min(MAX_PAGE);
    let prev =
        has_prev.then(|| p.page_href(tax, prev_page, items.first().map(|r| (SeekDir::Before, r))));
    let next = (has_next && p.page < MAX_PAGE)
        .then(|| p.page_href(tax, next_page, items.last().map(|r| (SeekDir::After, r))));
    (prev, next)
}

/// One listing, whatever produced it (the index or the degraded browse).
struct Listing {
    items: Vec<ReleaseRow>,
    total: u64,
    approx: bool,
    has_more: bool,
    notices: Vec<Notice>,
    degraded: bool,
    /// Degraded browse: the `dbefore` id of the next page.
    degraded_next: Option<i64>,
}

/// Why the index could not answer.
enum ListError {
    /// No servable generation: serve the degraded browse.
    Degraded,
    /// An offset page beyond `search.max_offset` that is not near the end, or a foreign cursor: `400 BAD_QUERY`.
    BadQuery,
    /// Anything else (busy and deadline become the uniform `503 BUSY` through the store's busy note).
    Failed(StoreError),
}

impl From<SearchError> for ListError {
    fn from(e: SearchError) -> Self {
        match e {
            SearchError::NotServable(_) => Self::Degraded,
            SearchError::OutOfRange(_) => Self::BadQuery,
            // `StoreError::from` notes busy/deadline for the uniform 503 (SEC-095).
            other => Self::Failed(StoreError::from(other)),
        }
    }
}

/// The index listing of `req` (offset page or keyset page).
async fn search_listing<S: SearchIndexV3>(
    search: &S,
    req: &SearchRequest,
    cursor: Option<&(SeekDir, PageCursor)>,
) -> Result<Listing, ListError> {
    let page = match cursor {
        None => search.search_page(req).await?,
        Some((dir, at)) => search.search_keyset_page(req, *dir, at).await?,
    };
    let (total, approx) = match page.total {
        Total::Exact(n) => (n, false),
        Total::AtLeast(n) => (n, true),
    };
    let mut notices = Vec::new();
    // Only over rows actually shown: a later page or a stale cursor past the end shows none (review 37 L1).
    if page.fuzzy_fallback && !page.items.is_empty() {
        notices.push(Notice::info(NOTICE_APPROXIMATE));
    }
    if !req.query.exclude_categories.is_empty() && page.expansion_bounded {
        notices.push(Notice::info(NOTICE_BOUNDED));
    } else if req.query.exclude_categories.is_empty() && page.narrowed {
        notices.push(Notice::info(NOTICE_NARROWED));
    }
    if approx {
        notices.push(Notice::info(notice_more_than(total)));
    }
    Ok(Listing {
        items: page.items,
        total,
        approx,
        has_more: page.has_more,
        notices,
        degraded: false,
        degraded_next: None,
    })
}

/// The bounded degraded browse (ARCHITECTURE v3 3.3, review L5): newest first, category only.
async fn degraded_listing(
    db: &Store,
    tax: &Taxonomy,
    p: &IndexParams,
    hidden: &[u32],
    per_page: u32,
) -> Result<Listing, StoreError> {
    let mut notices = vec![Notice {
        class: "warn",
        text: NOTICE_DEGRADED.to_owned(),
    }];
    let mut only_category = p.clone();
    only_category.category = None;
    if only_category.is_filtered() || p.sort != SortKey::DateDesc {
        notices.push(Notice::info(NOTICE_DEGRADED_FILTERS));
        return Ok(Listing {
            items: Vec::new(),
            total: 0,
            approx: false,
            has_more: false,
            notices,
            degraded: true,
            degraded_next: None,
        });
    }
    let req = DegradedRequest {
        categories: p.category.map(u32::from).into_iter().collect(),
        exclude_categories: hidden.to_vec(),
        before: p.degraded_before,
        limit: per_page,
    };
    let page = degraded::browse(db, tax, &req)
        .await
        .map_err(StoreError::from)?;
    Ok(match page {
        DegradedPage::CategoryUnavailable => {
            notices.push(Notice::info(NOTICE_DEGRADED_CATEGORY));
            Listing {
                items: Vec::new(),
                total: 0,
                approx: false,
                has_more: false,
                notices,
                degraded: true,
                degraded_next: None,
            }
        }
        DegradedPage::Page {
            items,
            total,
            next_before,
            budget_exhausted,
        } => {
            if budget_exhausted {
                notices.push(Notice::info(NOTICE_DEGRADED_MORE));
            }
            Listing {
                items,
                total,
                approx: false,
                has_more: next_before.is_some(),
                notices,
                degraded: true,
                degraded_next: next_before,
            }
        }
    })
}

#[allow(clippy::too_many_lines)] // one view assembly; splitting it would only move the field list
async fn index<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    uri: Uri,
) -> Response {
    let tax = st.taxonomy.as_ref();
    let bad_query = || ApiError::new(StatusCode::BAD_REQUEST, "BAD_QUERY").into_response();
    let Ok(p) = parse_params(uri.query(), tax) else {
        return bad_query();
    };
    // A hidden category (`ui.show_xxx = false`, or the caller's "Hide XXX for me") is answered like an
    // unknown `cat` value: the same strict BAD_QUERY path, so the response does not tell it from a typo.
    if p.category
        .is_some_and(|c| sess.hidden_categories.contains(&c))
    {
        return bad_query();
    }
    let hidden = sess.hidden_ids();
    // The account's choice (T133): always an allowlisted size, read with the session.
    let per_page = sess.prefs.page_size_releases.get();
    let Ok(mut query) = p.to_search(per_page) else {
        return bad_query();
    };
    query.exclude_categories.clone_from(&hidden);
    let offset = query.offset;
    let req = SearchRequest {
        query,
        // The server's choice (D35 Q5): prefix on the last word; the engine adds the fuzzy fallback for a
        // text query with no exact hit (`search.fuzzy = "fallback"`).
        match_mode: MatchMode::Prefix,
        ..SearchRequest::default()
    };
    let listed = match search_listing(&st.search, &req, p.cursor.as_ref()).await {
        Ok(l) => Ok(l),
        Err(ListError::Degraded) => degraded_listing(&st.db, tax, &p, &hidden, per_page).await,
        Err(ListError::BadQuery) => return bad_query(),
        Err(ListError::Failed(e)) => Err(e),
    };
    let mut listing = match listed {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "index search failed");
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response();
        }
    };
    let now = st.clock.now_secs();
    let mut rows: Vec<Row> = listing
        .items
        .iter()
        .map(|r| to_row(r, tax, now, SEGMENT_HEALTH_CHECK_AVAILABLE))
        .collect();
    // NFO badges (T144): one lookup for the whole page (search, keyset and degraded paths alike). The ids are the
    // rows this caller may already see; a failed lookup only drops the badges, never the page.
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    match st.db.releases_with_nfo(&ids).await {
        Ok(with) => {
            for r in &mut rows {
                r.has_nfo = with.contains(&r.id);
            }
        }
        Err(e) => tracing::warn!(error = %e, "nfo badge lookup failed"),
    }
    let pages_known = !listing.approx && !listing.degraded;
    let mut pages = listing.total.div_ceil(u64::from(per_page));
    if p.cursor.is_some() || listing.degraded {
        // A cursor page's number is advisory: after concurrent deletes it can exceed the page count.
        pages = pages.max(u64::from(p.page));
    }
    let last_page = u32::try_from(pages.max(1))
        .ok()
        .filter(|page| *page <= MAX_PAGE);
    if pages_known && last_page.is_none() {
        listing.notices.push(Notice::info(NOTICE_PAGE_LIMIT));
    }
    // A degraded page is numbered by the page parameter (advisory, like a cursor page).
    let start = if listing.degraded {
        p.page.saturating_sub(1).saturating_mul(per_page)
    } else {
        offset
    };
    let first = if rows.is_empty() {
        0
    } else {
        u64::from(start) + 1
    };
    let last = u64::from(start) + u64::try_from(rows.len()).unwrap_or(0);
    let (prev_href, next_href) = if listing.degraded {
        let next = listing.degraded_next.map(|id| {
            let mut c = p.clone();
            c.cursor = None;
            let base = c.href(
                tax,
                SortKey::DateDesc,
                p.page.saturating_add(1).min(MAX_PAGE),
                true,
            );
            let sep = if base.contains('?') { '&' } else { '?' };
            format!("{base}{sep}dbefore={id}")
        });
        (None, next)
    } else {
        pager_links(
            &p,
            tax,
            &listing.items,
            listing.has_more,
            pages_known.then_some(pages),
        )
    };
    let stats = st.stats(&hidden).await.map(|s| StatsView {
        releases: compact_count_exact(s.releases),
        segments: compact_count(s.segments),
        size: human_bytes(s.bytes),
        incomplete: s.incomplete.to_string(),
    });
    // Filtered listings do not show the timeline, so do not query the ingest log for them.
    let ticks = if p.is_filtered() {
        Vec::new()
    } else {
        st.ticks(&hidden).await
    };
    // Sidebar counts (T124 U14): one O(categories) read; a failure only drops the numbers, never the page.
    let counts = st
        .db
        .category_totals()
        .await
        .ok()
        .map(|t| browse_counts(tax, &t, &sess.hidden_categories));
    // Saved searches with their "N new" badges (T127): bounded by their own time budget, never fail the page.
    let saved = crate::saved::sidebar_links(&st, &sess).await;
    let view = IndexPage {
        stats,
        ticks,
        layout: {
            let mut l = Layout::for_session("Index", &sess);
            l.browse_cur = top_level_slug(tax, p.category);
            l.browse_sel = selected_slug(tax, p.category);
            if let Some(c) = &counts {
                l.with_browse_counts(|id| compact_count_exact(c.get(&id).copied().unwrap_or(0)));
            }
            l.saved_section = true;
            l.saved = saved;
            l
        },
        save_fields: p.canonical_pairs(tax, p.sort, true),
        per_page_choices: crate::page_size::choices(nzb_store::ReleasePageSize::CHOICES, per_page),
        filtered: p.is_filtered(),
        categories: category_choices(tax, p.category, &sess.hidden_categories),
        families: family_choices(p.family),
        resolutions: choices(RESOLUTIONS, p.resolution),
        sources: choices(SOURCES, p.source),
        title_head: head(
            "Title",
            SortKey::TitleAsc,
            SortKey::TitleDesc,
            false,
            &p,
            tax,
        ),
        date_head: head("Posted", SortKey::DateAsc, SortKey::DateDesc, true, &p, tax),
        size_head: head("Size", SortKey::SizeAsc, SortKey::SizeDesc, true, &p, tax),
        rows,
        total: listing.total,
        first,
        last,
        page: p.page,
        pages,
        prev_href,
        next_href,
        first_href: p.href(tax, p.sort, 1, true),
        last_href: last_page.map(|page| p.href(tax, p.sort, page, true)),
        show_incomplete: SEGMENT_HEALTH_CHECK_AVAILABLE,
        chips: p.chips(tax),
        more_open: p.any_secondary(),
        clear_href: p.href(tax, p.sort, 1, false),
        sort_value: sort_name(p.sort),
        // Every role may download (T130), so every role gets the checkboxes; the edits and the
        // delete stay role-gated.
        bulk: Some(BulkBar {
            edit: sess.role >= nzb_store::Role::Admin,
            delete: sess.role >= nzb_store::Role::Admin,
            max: nzb_store::MAX_BULK_IDS,
        }),
        approx: listing.approx,
        total_text: compact_count_exact(listing.total),
        pages_known,
        notices: listing.notices,
        degraded: listing.degraded,
        p,
    };
    match view.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "index render failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tax() -> Taxonomy {
        Taxonomy::builtin().unwrap()
    }

    #[test]
    fn short_age_is_compact() {
        assert_eq!(short_age(1), "1 second");
        assert_eq!(short_age(12), "12 seconds");
        assert_eq!(short_age(60), "1 minute");
        assert_eq!(short_age(180), "3 minutes");
        assert_eq!(short_age(3600), "1 hour");
        assert_eq!(short_age(7200), "2 hours");
        assert_eq!(short_age(86_400), "1 day");
        assert_eq!(short_age(5 * 86_400), "5 days");
        assert_eq!(short_age(60 * 86_400), "2 months");
        assert_eq!(short_age(30 * 86_400 * 4), "4 months");
        assert_eq!(short_age(730 * 86_400), "2 years");
        assert_eq!(short_age(-5), "0 seconds");
    }

    #[test]
    fn ago_text_spells_units_out() {
        assert_eq!(ago_text(2), "just now");
        assert_eq!(ago_text(120), "2 minutes ago");
        assert_eq!(ago_text(3600), "1 hour ago");
    }

    #[test]
    fn compact_count_formats() {
        assert_eq!(compact_count(0), "0");
        assert_eq!(compact_count(999), "999");
        assert_eq!(compact_count(1_000), "1,000");
        assert_eq!(compact_count(123_456), "123,456");
        assert_eq!(compact_count(1_234_567), "1.2M");
        assert_eq!(compact_count(3_400_000_000), "3.4B");
    }

    #[test]
    fn dates_roundtrip_and_validate() {
        assert_eq!(parse_date("1970-01-01"), Ok(0));
        assert_eq!(parse_date("2000-02-29"), Ok(951_782_400));
        assert!(parse_date("2001-02-29").is_err());
        assert!(parse_date("2001-13-01").is_err());
        assert!(parse_date("1969-12-31").is_err());
        assert!(parse_date("2101-01-01").is_err());
        assert!(parse_date("2001-1-01x").is_err());
        assert!(parse_date("+001-01-01").is_err());
        assert_eq!(format_date(951_782_400), "2000-02-29");
        assert_eq!(format_date(-1), "1969-12-31");
    }

    #[test]
    fn sizes_are_human() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(u64::MAX).split(' ').nth(1), Some("TiB"));
    }

    #[test]
    fn params_are_strict() {
        let t = tax();
        let ok = parse_params(Some("q=a&cat=tv.hd&year=2020&page=3&sort=size_asc"), &t).unwrap();
        assert_eq!(ok.page, 3);
        assert_eq!(ok.year, Some(2020));
        assert!(ok.category.is_some());
        for bad in [
            "cat=nope",
            "cat=%27%20OR%201%3D1",
            "year=20x0",
            "year=1800",
            "page=0",
            "page=100001",
            "page=-1",
            "sort=title%3B",
            "family=Movie",
            "res=1080",
            "min_mib=99999999999",
            "incomplete=yes",
            "from=2020-02-30",
        ] {
            assert!(parse_params(Some(bad), &t).is_err(), "{bad}");
        }
        // Blank form fields and unknown params are ignored.
        let blank = parse_params(Some("q=&cat=&year=&foo=bar&page="), &t).unwrap();
        assert_eq!(
            blank,
            IndexParams {
                page: 1,
                ..IndexParams::default()
            }
        );
        // First occurrence wins.
        assert_eq!(parse_params(Some("page=2&page=9"), &t).unwrap().page, 2);
    }

    #[test]
    fn sec_020_query_text_drops_bidi_and_invisible_format_characters() {
        let t = tax();
        // RLO, LRI/PDI, ZWSP, LRM, BOM, word joiner in q and group: stripped, the visible text stays.
        let p = parse_params(
            Some(
                "q=Mat%E2%80%AErix%E2%81%A6%20Re%E2%80%8Bloaded%E2%81%A9%E2%80%8E&group=GR%EF%BB%BFP%E2%81%A0",
            ),
            &t,
        )
        .unwrap();
        assert_eq!(p.q.as_deref(), Some("Matrix Reloaded"));
        assert_eq!(p.group.as_deref(), Some("GRP"));
        // Only invisible characters: no filter at all.
        let p = parse_params(Some("q=%E2%80%AE%E2%80%8B&group=%E2%81%A6"), &t).unwrap();
        assert_eq!((p.q, p.group), (None, None));
        // Ordinary Unicode text is untouched (accents, CJK, Cyrillic, Arabic letters, ZWNJ inside a word).
        for text in ["Amélie", "東京物語", "Сталкер", "سلام", "می\u{200c}خواهم"]
        {
            let raw = format!("q={}&group={}", pct_encode(text), pct_encode(text));
            let p = parse_params(Some(&raw), &t).unwrap();
            assert_eq!(p.q.as_deref(), Some(text), "{text}");
            assert_eq!(p.group.as_deref(), Some(text), "{text}");
        }
        // Control characters are still refused, not stripped.
        assert!(parse_params(Some("q=a%07b"), &t).is_err());
        assert!(parse_params(Some("group=a%00b"), &t).is_err());
    }

    #[test]
    fn href_is_canonical_and_encoded() {
        let t = tax();
        let p = parse_params(Some("q=a%26b%3D%22%3Cx%3E&group=A+B&foo=1&page=2"), &t).unwrap();
        let h = p.href(&t, SortKey::DateDesc, 3, true);
        assert_eq!(h, "/?q=a%26b%3D%22%3Cx%3E&group=A%20B&page=3");
        assert_eq!(p.href(&t, SortKey::DateDesc, 1, false), "/");
    }

    fn damaged_row() -> ReleaseRow {
        ReleaseRow {
            id: 1,
            sha256: nzb_core::Sha256([0; 32]),
            title: "t".to_owned(),
            category_id: 0,
            category_overridden: false,
            category_source: CategorySource::Fallback,
            posted_at: None,
            ingested_at: 0,
            total_bytes: 0,
            poster: None,
            file_count: 1,
            segment_count: 97,
            missing_segment_count: 3,
            par2_blocks: 5,
            flags: ReleaseFlags::INCOMPLETE,
            nzb_size_bytes: 0,
            source_name: None,
            source_label: None,
            origin: None,
            meta_json: None,
            scene: nzb_store::SceneColumns::default(),
        }
    }

    #[test]
    fn t148_uncategorized_badge_only_for_the_untouched_fallback() {
        let mut r = damaged_row();
        r.flags = ReleaseFlags::UNCATEGORIZED;
        assert_eq!(flag_labels(&r, false), vec!["Uncategorized".to_owned()]);
        r.category_overridden = true;
        r.category_source = CategorySource::Manual;
        assert_eq!(flag_labels(&r, false).len(), 0);
        r.category_overridden = false;
        assert_eq!(flag_labels(&r, false).len(), 0);
        r.category_source = CategorySource::Fallback;
        r.category_overridden = true;
        assert_eq!(flag_labels(&r, false).len(), 0);
    }

    #[test]
    fn health_switch_controls_gap_derived_badges_and_meter() {
        let r = damaged_row();
        // Switch on: the original behaviour.
        let on = flag_labels(&r, true);
        assert!(on.contains(&"Incomplete: 3 segments missing".to_owned()));
        assert!(on.iter().any(|l| l.starts_with("Repairability (estimate)")));
        assert_eq!(meter(97, 3, true).0, 97);
        assert_eq!(to_row(&r, &tax(), 0, true).meter_pct, 97);
        // Switch off: no gap-derived badge, full flat meter, stored row untouched.
        assert_eq!(flag_labels(&r, false).len(), 0);
        assert_eq!(meter(97, 3, false), (100, "w100".to_owned(), "ok"));
        let row = to_row(&r, &tax(), 0, false);
        assert_eq!(row.meter_pct, 100);
        assert_eq!(row.meter_state, "ok");
        assert!(row.flags.is_empty());
        assert_eq!(r.missing_segment_count, 3);
    }
}

#[cfg(test)]
mod hb6_regressions {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use nzb_search::request::SearchPage;
    use nzb_store::{KeysetPage, Page, SearchDoc, SearchIndex};
    use tower::ServiceExt as _;

    const LIMIT_NOTICE: &str = "The last page is beyond the supported page range.";

    /// Only the search seam is synthetic: real routing, extraction, view assembly and Askama rendering
    /// consume a large total with at most one page of rows. This also runs against the unfixed handler.
    #[derive(Clone)]
    struct LargeListing {
        total: Total,
        seen: Arc<std::sync::Mutex<Vec<SearchQuery>>>,
        narrowed: bool,
        expansion_bounded: bool,
    }

    impl LargeListing {
        fn page(&self, req: &SearchRequest) -> SearchPage {
            self.seen.lock().unwrap().push(req.query.clone());
            let count = self
                .total
                .value()
                .saturating_sub(u64::from(req.query.offset))
                .min(u64::from(req.query.limit));
            let items = (0..count)
                .map(|i| ReleaseRow {
                    id: i64::from(req.query.offset) + i64::try_from(i).unwrap() + 1,
                    sha256: nzb_core::Sha256([0; 32]),
                    title: format!("Listing fixture {i}"),
                    category_id: 5040,
                    category_overridden: false,
                    category_source: CategorySource::Fallback,
                    posted_at: Some(1_700_000_000),
                    ingested_at: 1_700_000_000,
                    total_bytes: 2 << 20,
                    poster: None,
                    file_count: 1,
                    segment_count: 1,
                    missing_segment_count: 0,
                    par2_blocks: 0,
                    flags: ReleaseFlags::EMPTY,
                    nzb_size_bytes: 100,
                    source_name: None,
                    source_label: None,
                    origin: None,
                    meta_json: None,
                    scene: nzb_store::SceneColumns::default(),
                })
                .collect();
            SearchPage {
                items,
                total: self.total,
                has_more: u64::from(req.query.offset).saturating_add(count) < self.total.value(),
                limit: req.query.limit,
                facets: Vec::new(),
                narrowed: self.narrowed,
                expansion_bounded: self.expansion_bounded,
                fuzzy_fallback: false,
                dropped: 0,
            }
        }
    }

    impl SearchIndex for LargeListing {
        fn search(
            &self,
            _: &SearchQuery,
        ) -> impl Future<Output = Result<Page<ReleaseRow>, StoreError>> {
            std::future::ready(Err(StoreError::OutOfRange("unexpected legacy search")))
        }

        fn search_keyset(
            &self,
            _: &SearchQuery,
            _: SeekDir,
            _: &PageCursor,
        ) -> impl Future<Output = Result<KeysetPage, StoreError>> {
            std::future::ready(Err(StoreError::OutOfRange("unexpected legacy search")))
        }

        fn count(&self, _: &SearchQuery) -> impl Future<Output = Result<u64, StoreError>> {
            std::future::ready(Ok(self.total.value()))
        }

        fn upsert(&self, _: &SearchDoc<'_>) -> impl Future<Output = Result<(), StoreError>> {
            std::future::ready(Err(StoreError::OutOfRange("read-only listing fixture")))
        }

        fn remove(&self, _: i64) -> impl Future<Output = Result<(), StoreError>> {
            std::future::ready(Err(StoreError::OutOfRange("read-only listing fixture")))
        }
    }

    impl SearchIndexV3 for LargeListing {
        fn search_page(
            &self,
            req: &SearchRequest,
        ) -> impl Future<Output = Result<SearchPage, SearchError>> {
            std::future::ready(Ok(self.page(req)))
        }

        fn search_keyset_page(
            &self,
            req: &SearchRequest,
            _: SeekDir,
            _: &PageCursor,
        ) -> impl Future<Output = Result<SearchPage, SearchError>> {
            std::future::ready(Ok(self.page(req)))
        }

        fn count_total(
            &self,
            _: &SearchRequest,
        ) -> impl Future<Output = Result<Total, SearchError>> {
            std::future::ready(Ok(self.total))
        }
    }

    fn listing_app(db: Store, search: LargeListing, per_page: u32) -> Router {
        let sess = SessionCtx {
            user_id: 1,
            stage: nzb_store::SessionStage::Active,
            csrf_token: String::new(),
            hidden_categories: Arc::from([]),
            prefs: nzb_store::UserPrefs {
                page_size_releases: nzb_store::ReleasePageSize::new(per_page).unwrap(),
                ..nzb_store::UserPrefs::default()
            },
            role: nzb_store::Role::Viewer,
            username: "listing-reader".to_owned(),
            display_name: "Listing reader".to_owned(),
            enroll_proven: false,
            multi_user: false,
            id_hash: [0; 32],
            last_seen_at: 0,
            created_at: 0,
            library_gen: Arc::default(),
        };
        routes_with_clock(
            db,
            search,
            Arc::new(Taxonomy::builtin().unwrap()),
            Arc::new(crate::auth::ManualWallClock::new(1_700_000_001)),
        )
        .layer(Extension(sess))
    }

    async fn html(app: &Router, uri: &str) -> String {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "listing URI: {uri}");
        String::from_utf8(
            to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    /// Read the actual navigation links, not the view's private fields. Returned URLs can be followed
    /// as an ordinary browser would, without needing JavaScript or generating a large search index.
    fn pager_links_in(body: &str) -> Vec<(&str, String)> {
        let pager = body
            .split_once("<nav class=\"pager\"")
            .and_then(|(_, rest)| rest.split_once("</nav>"))
            .map_or("", |(nav, _)| nav);
        pager
            .split("<a ")
            .skip(1)
            .filter_map(|link| {
                let (attrs, rest) = link.split_once('>')?;
                let (label, _) = rest.split_once("</a>")?;
                let href = attrs.split_once("href=\"")?.1.split_once('"')?.0;
                // Askama escapes ampersands numerically; a browser decodes both forms.
                Some((label, href.replace("&#38;", "&").replace("&amp;", "&")))
            })
            .collect()
    }

    #[tokio::test]
    async fn hidden_search_notices_do_not_disclose_dictionary_cap_events() {
        for narrowed in [false, true] {
            let mut search = LargeListing {
                total: Total::Exact(0),
                seen: Arc::default(),
                narrowed,
                expansion_bounded: true,
            };
            let mut req = SearchRequest {
                query: SearchQuery {
                    q: Some("par".into()),
                    exclude_categories: vec![6000],
                    ..SearchQuery::default()
                },
                match_mode: MatchMode::Prefix,
                ..SearchRequest::default()
            };
            let listing = search_listing(&search, &req, None).await.ok().unwrap();
            assert_eq!(listing.items.len(), 0);
            assert_eq!(
                listing
                    .notices
                    .iter()
                    .map(|n| n.text.as_str())
                    .collect::<Vec<_>>(),
                [NOTICE_BOUNDED]
            );
            // Ordinary unfiltered searches retain the actual truncation notice.
            req.query.exclude_categories.clear();
            let listing = search_listing(&search, &req, None).await.ok().unwrap();
            assert_eq!(listing.notices.len(), usize::from(narrowed));
            assert!(listing.notices.iter().all(|n| n.text == NOTICE_NARROWED));
            // The engine's corpus-independent flag is false for exact/no-text/off queries.
            req.query.exclude_categories = vec![6000];
            search.expansion_bounded = false;
            search.narrowed = false;
            for (q, mode) in [(None, MatchMode::Prefix), (Some("par"), MatchMode::Exact)] {
                req.query.q = q.map(str::to_owned);
                req.match_mode = mode;
                let listing = search_listing(&search, &req, None).await.ok().unwrap();
                assert!(listing.notices.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn last_page_outside_the_accepted_range_is_not_linked() {
        let dir = tempfile::tempdir().unwrap();
        let db = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let tax = Taxonomy::builtin().unwrap();
        for per_page in nzb_store::ReleasePageSize::CHOICES {
            for total in [u64::from(MAX_PAGE) * u64::from(*per_page) + 1, u64::MAX] {
                let search = LargeListing {
                    total: Total::Exact(total),
                    seen: Arc::default(),
                    narrowed: false,
                    expansion_bounded: false,
                };
                let app = listing_app(db.store.clone(), search, *per_page);
                let body = html(&app, "/?q=alpha&sort=size_asc&min_mib=1").await;
                let links = pager_links_in(&body);
                assert!(
                    links.iter().all(|(label, _)| *label != "Last"),
                    "Last must not link to an unsupported page: total={total}, size={per_page}"
                );
                assert!(body.contains(LIMIT_NOTICE));
                assert!(body.contains("Narrow your search or filters"));
                assert!(body.contains(&compact_count_exact(total)));
                let (_, next) = links.iter().find(|(label, _)| *label == "Next").unwrap();
                let p = parse_params(next.split_once('?').map(|(_, q)| q), &tax).unwrap();
                assert_eq!(p.q.as_deref(), Some("alpha"));
                assert_eq!(p.sort, SortKey::SizeAsc);
                assert_eq!(p.min_mib, Some(1));
                assert_eq!(p.page, 2);
                assert!(
                    p.cursor.is_some(),
                    "Next must retain its bounded keyset path"
                );
                let next_body = html(&app, next).await;
                assert!(
                    pager_links_in(&next_body)
                        .iter()
                        .any(|(label, _)| *label == "Previous")
                );
                assert!(next_body.contains(LIMIT_NOTICE));
            }
        }
    }

    #[tokio::test]
    async fn last_page_at_the_limit_still_roundtrips_with_filters() {
        let dir = tempfile::tempdir().unwrap();
        let db = nzb_store::test_backend::TestStore::open(dir.path()).await;
        for per_page in nzb_store::ReleasePageSize::CHOICES {
            let search = LargeListing {
                total: Total::Exact(u64::from(MAX_PAGE) * u64::from(*per_page)),
                seen: Arc::default(),
                narrowed: false,
                expansion_bounded: false,
            };
            let seen = Arc::clone(&search.seen);
            let app = listing_app(db.store.clone(), search, *per_page);
            let body = html(
                &app,
                "/?cat=tv.hd&from=2020-01-01&to=2024-02-29&sort=size_desc&max_mib=8",
            )
            .await;
            assert!(!body.contains(LIMIT_NOTICE));
            let links = pager_links_in(&body);
            let (_, last) = links.iter().find(|(label, _)| *label == "Last").unwrap();
            let body = html(&app, last).await;
            assert!(body.contains("Page 100000 of 100000"));
            assert!(
                !pager_links_in(&body)
                    .iter()
                    .any(|(label, _)| matches!(*label, "Last" | "Next"))
            );
            let requests = seen.lock().unwrap();
            let first = requests.first().unwrap();
            let last = requests.last().unwrap();
            assert_eq!(last.offset, (MAX_PAGE - 1) * per_page);
            assert_eq!(last.limit, *per_page);
            assert_eq!(last.categories, first.categories);
            assert_eq!(last.since, first.since);
            assert_eq!(last.until, first.until);
            assert_eq!(last.sort, first.sort);
            assert_eq!(last.max_bytes, first.max_bytes);
        }
    }

    #[tokio::test]
    async fn inexact_or_empty_listings_do_not_claim_an_unreachable_last_page() {
        let dir = tempfile::tempdir().unwrap();
        let db = nzb_store::test_backend::TestStore::open(dir.path()).await;
        for total in [Total::AtLeast(u64::MAX), Total::Exact(0)] {
            let app = listing_app(
                db.store.clone(),
                LargeListing {
                    total,
                    seen: Arc::default(),
                    narrowed: false,
                    expansion_bounded: false,
                },
                25,
            );
            let body = html(&app, "/").await;
            assert!(!body.contains(LIMIT_NOTICE));
            assert!(
                !pager_links_in(&body)
                    .iter()
                    .any(|(label, _)| *label == "Last")
            );
            assert_eq!(
                body.contains("more than"),
                matches!(total, Total::AtLeast(_))
            );
        }
    }
}
