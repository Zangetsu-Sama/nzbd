//! Release detail and NZB explorer (`docs/UI_SPEC.md`, T046).
//!
//! Routes (all behind the active-session gate; the POST additionally behind CSRF):
//! - `GET /release/{id}`: summary card, files table with segment bars (paginated files);
//! - `GET /release/{id}/file/{idx}/segments`: paginated segment listing for one file;
//! - `GET /release/{id}/raw`: sanitized `text/plain` rendering of head/meta and the first files;
//! - `GET /release/{id}/download`, `POST /release/{id}/download/selected`: full and partial NZB
//!   downloads ([`crate::download`]);
//! - `POST /releases/bulk/download`: the ticked releases as one zip ([`crate::bulk_download`]);
//! - `POST /release/{id}/category`: manual category override;
//! - `POST /release/{id}/source`: edit (or clear) the free-text source label.
//!
//! # Cost model
//! The summary and files table are served from the database only (D15: per-file aggregates and
//! missing ranges are stored). The segment listing and the raw view re-read the stored NZB
//! (hash-verified by the store) and parse it on demand: `list_segments` makes two streaming
//! passes over the document, so a request costs O(NZB size) CPU and one NZB-sized buffer,
//! independent of the page size. Those requests run in `spawn_blocking` under the parser's
//! limits and deadline and share a small permit pool ([`MAX_CONCURRENT_PARSES`]); when it is
//! exhausted the request is refused with `503 BUSY` instead of queueing hostile work.
//!
//! # Untrusted data
//! Subjects, file names, posters, groups and message-ids come from NZBs. They reach HTML only
//! through askama's auto-escaping, are sanitized again here (defence in depth), and are never
//! used as paths, header values or in URLs. URLs are built from validated integers only.
//! The raw view is `text/plain` with `nosniff`, never HTML.

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use nzb_core::{FileKind, Limits, NzbError, SystemClock, Taxonomy, sanitize_text};
use nzb_store::{CategorySource, NzbStore, ReleaseFile, ReleaseRow, Store, StoreError};
use tokio::sync::Semaphore;

use crate::SEGMENT_HEALTH_CHECK_AVAILABLE;
use crate::assets::Layout;
use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::index::{
    Choice, FlagView, category_choices, category_source_class, category_source_label, flag_labels,
    flag_views, human_bytes, meter,
};

/// Default files per page of the files table; each account may choose 50, 100, 250 or 500 (T133,
/// [`nzb_store::FilePageSize`]).
pub const FILES_PER_PAGE: usize = 100;
/// Highest files-table page number accepted (larger is `400 BAD_QUERY`). The parser ceiling is 20 000 files, 400 pages
/// at the smallest size of 50, so this never cuts a release short; a number past the release's last page shows the
/// last page.
pub const MAX_FILE_PAGE: u32 = 1_000;
/// Default segments per page.
pub const DEFAULT_SEGMENT_LIMIT: u32 = 100;
/// Highest segments per page (the parser's own cap).
pub const MAX_SEGMENT_LIMIT: u32 = nzb_core::MAX_PAGE_LIMIT;
/// Highest segment offset accepted (parser ceiling is 200 000 segments per file).
pub const MAX_SEGMENT_OFFSET: u32 = 1_000_000;
/// Concurrent on-demand NZB parses (segment pages and raw views) before answering `503 BUSY`.
pub const MAX_CONCURRENT_PARSES: usize = 2;
/// Cells of one segment bar (a constant keeps pages small and needs no inline style).
pub const BAR_CELLS: u64 = 50;
/// Missing ranges spelled out per file in the table; the rest is summarised.
const SHOWN_RANGES: usize = 12;
/// Missing ranges read back from the database per file (the parser records at most 256).
const MAX_RANGES_READ: usize = 256;
/// Longest display name of a file or poster.
const MAX_NAME_BYTES: usize = 255;
/// Files listed by the raw view.
pub const RAW_MAX_FILES: usize = 200;
/// Hard cap of the raw view body.
pub const RAW_MAX_BYTES: usize = 256 * 1024;
/// Groups listed in the summary.
const MAX_GROUPS_SHOWN: usize = 20;

/// Everything the release routes need.
#[derive(Clone)]
pub struct ReleaseDeps {
    /// Database handle.
    pub db: Store,
    /// Category taxonomy (override validation, names).
    pub taxonomy: Arc<Taxonomy>,
    /// Blob store holding the original NZBs.
    pub store: Arc<dyn NzbStore>,
    /// Parser limits (same as ingest, including the deadline).
    pub limits: Limits,
    /// Wall clock for audit rows.
    pub clock: Arc<dyn WallClock>,
    /// Upper bound for the deadline of one on-demand parse; set just below the request timeout
    /// so the blocking thread cannot outlive the response.
    pub max_parse: Duration,
}

#[derive(Clone)]
pub(crate) struct St {
    pub(crate) deps: ReleaseDeps,
    permits: Arc<Semaphore>,
    /// Permits for whole-blob reads by the download route (separate from the parse pool).
    pub(crate) downloads: Arc<Semaphore>,
    /// The partial download's own pool, taken in addition to `downloads` (review 43 M1).
    pub(crate) partials: Arc<Semaphore>,
    /// The bulk download's pool, running accounts and budget (T130), on top of `downloads`.
    pub(crate) bulk: Arc<crate::bulk_download::BulkState>,
}

/// Routes of the release pages; merge them with the other UI routes and pass the result as the
/// `session_routes` of [`crate::router_with_auth`].
pub fn routes(deps: ReleaseDeps) -> Router {
    routes_with_bulk(deps, crate::bulk_download::BulkLimits::default())
}

/// [`routes`] with explicit bulk download limits (tests shrink its times; production uses the
/// defaults through [`routes`]).
pub fn routes_with_bulk(deps: ReleaseDeps, bulk: crate::bulk_download::BulkLimits) -> Router {
    let st = St {
        bulk: Arc::new(crate::bulk_download::BulkState::new(
            bulk,
            Arc::clone(&deps.clock),
        )),
        deps,
        permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PARSES)),
        downloads: Arc::new(Semaphore::new(crate::download::MAX_CONCURRENT_DOWNLOADS)),
        partials: Arc::new(Semaphore::new(
            crate::download::MAX_CONCURRENT_PARTIAL_DOWNLOADS,
        )),
    };
    Router::new()
        .route("/release/{id}", get(detail))
        .route("/release/{id}/file/{idx}/segments", get(segments))
        .route("/release/{id}/raw", get(raw))
        .route("/release/{id}/download", get(crate::download::download))
        .route(
            "/release/{id}/download/selected",
            post(crate::download::download_selected),
        )
        // T130: the ticked releases of the result list as one zip; mounted here because it
        // shares the download permit pool.
        .route(
            "/releases/bulk/download",
            post(crate::bulk_download::download_bulk),
        )
        .route("/release/{id}/category", post(set_category))
        .route("/release/{id}/source", post(set_source))
        // T140: the NFO viewer, its raw download and the admin's remove.
        .route("/release/{id}/nfo", get(crate::nfo::page))
        .route("/release/{id}/nfo/download", get(crate::nfo::download))
        .route("/release/{id}/nfo/delete", post(crate::nfo::delete))
        .with_state(st)
}

// ---------------------------------------------------------------------------------------------
// Small helpers

pub(crate) fn fail(status: StatusCode, code: &'static str) -> Response {
    ApiError::new(status, code).into_response()
}

pub(crate) fn not_found() -> Response {
    fail(StatusCode::NOT_FOUND, "NOT_FOUND")
}

pub(crate) fn internal() -> Response {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Strict release id: 1-15 ASCII digits, positive. Anything else is a plain 404.
pub(crate) fn parse_id(s: &str) -> Option<i64> {
    if s.len() > 15 || !all_digits(s) {
        return None;
    }
    s.parse::<i64>().ok().filter(|n| *n > 0)
}

/// Strict file index: 1-5 ASCII digits.
fn parse_idx(s: &str) -> Option<u32> {
    if s.len() > 5 || !all_digits(s) {
        return None;
    }
    s.parse::<u32>().ok()
}

fn clean(s: &str) -> String {
    sanitize_text(s, MAX_NAME_BYTES)
}

/// `YYYY-MM-DD HH:MM` (UTC).
fn format_datetime(secs: i64) -> String {
    let rem = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02} UTC",
        crate::index::format_date(secs),
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// `12 months ago (2025-10-09 23:25 UTC)`: the spelled-out age first, the exact time after it (T124 U9).
fn age_and_datetime(secs: i64, now: i64) -> String {
    format!(
        "{} ({})",
        crate::index::ago_text(now.saturating_sub(secs)),
        format_datetime(secs)
    )
}

/// Style of the Alerts panel (T124 U8), a closed set of CSS classes: `bad` when a badge is a problem, `warn` when
/// one asks for attention, `info` when the badges are informational only (for example Par2).
fn alert_level(flags: &[FlagView]) -> &'static str {
    if flags.iter().any(|f| f.class == "bad") {
        "bad"
    } else if flags.iter().any(|f| f.class == "warn") {
        "warn"
    } else {
        "info"
    }
}

/// Missing ranges as stored by ingest: `[[a,b],...]` or `{"ranges":[...],"more":true}`.
/// Malformed content yields no ranges (the page still renders).
fn parse_ranges(json: Option<&str>) -> (Vec<(u32, u32)>, bool) {
    let Some(text) = json else {
        return (Vec::new(), false);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return (Vec::new(), false);
    };
    let (list, more) = match &v {
        serde_json::Value::Array(a) => (Some(a), false),
        serde_json::Value::Object(o) => (
            o.get("ranges").and_then(serde_json::Value::as_array),
            o.get("more")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        ),
        _ => (None, false),
    };
    let mut out = Vec::new();
    for item in list.into_iter().flatten().take(MAX_RANGES_READ) {
        let pair = item.as_array().filter(|p| p.len() == 2);
        let lo = pair
            .and_then(|p| p.first())
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let hi = pair
            .and_then(|p| p.get(1))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        if let (Some(lo), Some(hi)) = (lo, hi)
            && lo >= 1
            && hi >= lo
        {
            out.push((lo, hi));
        }
    }
    (out, more)
}

fn parse_string_list(json: Option<&str>, max: usize) -> Vec<String> {
    let Some(text) = json else {
        return Vec::new();
    };
    let Ok(serde_json::Value::Array(a)) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    a.iter()
        .filter_map(serde_json::Value::as_str)
        .map(clean)
        .filter(|s| !s.is_empty())
        .take(max)
        .collect()
}

/// Number of segments covered by `ranges`, clipped to `1..=total`.
fn missing_total(ranges: &[(u32, u32)]) -> u64 {
    ranges.iter().fold(0_u64, |acc, (lo, hi)| {
        acc.saturating_add(u64::from(*hi) - u64::from(*lo) + 1)
    })
}

/// Segment slots a file's bar spans: the declared total, or present + known-missing segments.
fn bar_slots(declared: Option<u32>, present: u32, ranges: &[(u32, u32)]) -> u64 {
    declared.map_or_else(
        || u64::from(present).saturating_add(missing_total(ranges)),
        u64::from,
    )
}

/// CSS class per bar cell: `ok` (all present), `part` (some missing) or `gap` (all missing).
/// Cell `b` of `n` covers slots `(b*total/n, (b+1)*total/n]` (1-based segment numbers).
#[must_use]
pub fn bar_cells(total: u64, ranges: &[(u32, u32)]) -> Vec<&'static str> {
    let n = total.min(BAR_CELLS);
    (0..n)
        .map(|b| {
            // total <= u32::MAX * ... fits u128 trivially; n >= 1 inside the loop.
            let lo = u64::try_from(u128::from(b) * u128::from(total) / u128::from(n)).unwrap_or(0);
            let hi =
                u64::try_from(u128::from(b + 1) * u128::from(total) / u128::from(n)).unwrap_or(0);
            let size = hi.saturating_sub(lo);
            let missing = ranges.iter().fold(0_u64, |acc, (a, z)| {
                let from = u64::from(*a).max(lo + 1);
                let to = u64::from(*z).min(hi);
                acc + if to >= from { to - from + 1 } else { 0 }
            });
            if missing == 0 {
                "ok"
            } else if missing >= size {
                "gap"
            } else {
                "part"
            }
        })
        .collect()
}

fn ranges_text(ranges: &[(u32, u32)]) -> String {
    let mut s = String::new();
    for (i, (lo, hi)) in ranges.iter().take(SHOWN_RANGES).enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        // Writing to a String cannot fail.
        let _ = if lo == hi {
            write!(s, "{lo}")
        } else {
            write!(s, "{lo}-{hi}")
        };
    }
    s
}

// ---------------------------------------------------------------------------------------------
// Detail page

struct FileView {
    idx: u32,
    name: String,
    /// Fixed display label from [`kind_label`], never the stored text.
    kind: &'static str,
    /// Closed-set CSS class for the kind badge (`k-video`, ...), never the stored text.
    kind_class: &'static str,
    /// True when segments are missing: the row is highlighted.
    has_gap: bool,
    size: String,
    /// Segment count cell: `max/max` without a health check, else `present/declared`.
    segs: String,
    ranges: String,
    more_ranges: String,
    missing: u64,
    cells: Vec<&'static str>,
    bar_label: String,
}

struct SceneItem {
    label: &'static str,
    value: String,
}

#[derive(Template)]
#[template(path = "release.html")]
#[allow(clippy::struct_excessive_bools)] // independent display flags of one template
struct DetailPage {
    layout: Layout,
    id: i64,
    title: String,
    source_name: Option<String>,
    /// Free-text upload source (sanitized again here); `None` renders `-`.
    source_label: Option<String>,
    /// Current label for the edit form (same value as `source_label`, empty when none).
    source_edit: String,
    /// How the NZB arrived (fixed label); `None` = unknown.
    origin: Option<&'static str>,
    /// "Added by": the uploader's display handle (never the login name), "Deleted account",
    /// "Watch folder" or "Before accounts". Plain, escaped text for every role.
    added_by: String,
    /// Only admins edit the shared metadata of a release (D26 c, restricted by D40).
    can_edit: bool,
    /// Only admins delete.
    can_delete: bool,
    category: String,
    category_source: &'static str,
    category_source_class: &'static str,
    overridden: bool,
    categories: Vec<Choice>,
    posted: String,
    ingested: String,
    size: String,
    nzb_size: String,
    poster: Option<String>,
    file_count: u32,
    segment_count: u64,
    /// True when gap-derived counts may be shown as availability ([`SEGMENT_HEALTH_CHECK_AVAILABLE`]).
    health: bool,
    missing_segments: u64,
    completeness: String,
    meter_class: String,
    meter_state: &'static str,
    flags: Vec<FlagView>,
    /// `bad`, `warn` or `info` (closed set) for the Alerts panel.
    alert_level: &'static str,
    scene: Vec<SceneItem>,
    groups: Vec<String>,
    files: Vec<FileView>,
    /// A file of this page has gaps: the Completeness column is drawn (T124 U10), bars only on those rows.
    any_gap: bool,
    page: u32,
    pages: u64,
    first: usize,
    last: usize,
    total_files: usize,
    prev_href: Option<String>,
    next_href: Option<String>,
    /// The "Per page" control under the files table (T133): the allowlisted sizes with the account's choice selected.
    per_page_choices: Vec<Choice>,
    /// The release's NFO, decoded (T140); `None` when it has none.
    nfo: Option<crate::nfo::NfoView>,
}

fn completeness(present: u64, missing: u64) -> String {
    let total = u128::from(present) + u128::from(missing);
    if total == 0 {
        return "100.0%".to_owned();
    }
    let tenths = u128::from(present) * 1000 / total;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

fn scene_items(r: &ReleaseRow) -> Vec<SceneItem> {
    let s = &r.scene;
    let mut v = Vec::new();
    let mut add = |label: &'static str, value: Option<String>| {
        if let Some(value) = value.map(|x| clean(&x)).filter(|x| !x.is_empty()) {
            v.push(SceneItem { label, value });
        }
    };
    add(
        "Family",
        s.family.as_deref().map(crate::index::family_label),
    );
    add("Year", s.year.map(|y| y.to_string()));
    add("Season", s.season.map(|y| y.to_string()));
    add("Episode", s.episode.map(|y| y.to_string()));
    add("Resolution", s.resolution.clone());
    add("Media source", s.source.clone());
    add("Codec", s.codec.clone());
    add("Release group", s.group.clone());
    let langs = parse_string_list(s.languages_json.as_deref(), 16);
    add("Languages", (!langs.is_empty()).then(|| langs.join(", ")));
    v
}

/// Parses the stored kind text (`FileKind::as_str`); anything unknown is `Other`.
fn parse_kind(kind: &str) -> FileKind {
    match kind {
        "video" => FileKind::Video,
        "audio" => FileKind::Audio,
        "archive" => FileKind::Archive,
        "par2" => FileKind::Par2,
        "nfo" => FileKind::Nfo,
        "sfv" => FileKind::Sfv,
        "subtitle" => FileKind::Subtitle,
        "image" => FileKind::Image,
        "nzb" => FileKind::Nzb,
        "executable" => FileKind::Executable,
        _ => FileKind::Other,
    }
}

/// Display label of a file kind (fixed text). A file the NZB or its name does not positively
/// identify (`Other`: unknown extension, no name, obfuscated) is a `Part` of the release. Display
/// only: the stored kind and the parser are unchanged.
#[must_use]
pub const fn kind_label(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Video => "Video",
        FileKind::Audio => "Audio",
        FileKind::Archive => "Archive",
        FileKind::Par2 => "Par2",
        FileKind::Nfo => "NFO",
        FileKind::Sfv => "SFV",
        FileKind::Subtitle => "Subtitle",
        FileKind::Image => "Image",
        FileKind::Nzb => "NZB",
        FileKind::Executable => "Executable",
        FileKind::Other => "Part",
    }
}

/// Maps a kind to a closed set of CSS classes.
const fn kind_class(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Video => "k-video",
        FileKind::Audio => "k-audio",
        FileKind::Archive => "k-archive",
        FileKind::Par2 => "k-par2",
        FileKind::Nfo => "k-nfo",
        FileKind::Sfv => "k-sfv",
        FileKind::Subtitle => "k-subtitle",
        FileKind::Image => "k-image",
        FileKind::Nzb => "k-nzb",
        FileKind::Executable => "k-executable",
        FileKind::Other => "k-part",
    }
}

/// Per-file segment count text. Without a health check it is `max/max` with
/// `max = max(present, declared)`: gaps in the NZB's numbering are not news-server availability.
fn segments_text(present: u32, declared: Option<u32>, health: bool) -> String {
    if health {
        let d = declared.map_or_else(|| "?".to_owned(), |d| d.to_string());
        format!("{present}/{d}")
    } else {
        let max = present.max(declared.unwrap_or(0));
        format!("{max}/{max}")
    }
}

fn file_view(f: &ReleaseFile, health: bool) -> FileView {
    let kind = parse_kind(&f.kind);
    let (ranges, more) = parse_ranges(f.missing_ranges.as_deref());
    let slots = bar_slots(f.declared_segments, f.segment_count, &ranges);
    let missing = missing_total(&ranges);
    let name = f
        .filename
        .as_deref()
        .map(clean)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| clean(&f.subject));
    let mut more_ranges = String::new();
    if ranges.len() > SHOWN_RANGES {
        let extra = ranges.len() - SHOWN_RANGES;
        let _ = write!(more_ranges, "and {extra} more range(s)");
    }
    if more {
        if !more_ranges.is_empty() {
            more_ranges.push_str("; ");
        }
        more_ranges.push_str("list truncated, more gaps exist");
    }
    let bar_label = if missing == 0 && !more {
        "No missing segments".to_owned()
    } else {
        format!(
            "{missing} of {slots} segments missing{}",
            if more { " (at least)" } else { "" }
        )
    };
    FileView {
        idx: f.idx,
        name,
        kind: kind_label(kind),
        kind_class: kind_class(kind),
        has_gap: missing > 0 || more,
        size: human_bytes(f.bytes),
        segs: segments_text(f.segment_count, f.declared_segments, health),
        ranges: ranges_text(&ranges),
        more_ranges,
        missing,
        cells: bar_cells(slots, &ranges),
        bar_label,
    }
}

/// Files-table page parameter: `page` (digits, 1..=[`MAX_FILE_PAGE`]); unknown parameters are
/// ignored, blank counts as absent.
fn parse_file_page(query: Option<&str>) -> Result<u32, ()> {
    let form = csrf::parse_form(query.unwrap_or_default().as_bytes());
    match csrf::form_get(&form, "page").filter(|v| !v.is_empty()) {
        None => Ok(1),
        Some(v) if v.len() <= 4 && all_digits(v) => {
            let n: u32 = v.parse().map_err(|_| ())?;
            if (1..=MAX_FILE_PAGE).contains(&n) {
                Ok(n)
            } else {
                Err(())
            }
        }
        Some(_) => Err(()),
    }
}

// One linear page-assembly function; splitting it would only move the field list around.
#[allow(clippy::too_many_lines)]
async fn detail(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path(id): Path<String>,
    uri: Uri,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let Ok(page) = parse_file_page(uri.query()) else {
        return fail(StatusCode::BAD_REQUEST, "BAD_QUERY");
    };
    let db = &st.deps.db;
    let row = match db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => r,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    };
    let tax = st.deps.taxonomy.as_ref();
    let total_files = usize::try_from(row.file_count).unwrap_or(usize::MAX);
    // The account's choice (T133): always an allowlisted size, read with the session. The partial-download form
    // holds at most this many `file` fields, within its `file_count + 8` field cap (`download::parse_selection`).
    let per_page = sess.prefs.page_size_files.get();
    let per = usize::try_from(per_page).unwrap_or(FILES_PER_PAGE);
    let pages = total_files.div_ceil(per).max(1);
    // A page past the last one (an old link after a larger page size was chosen) shows the last page (review 48 I4).
    let page = page
        .min(u32::try_from(pages).unwrap_or(MAX_FILE_PAGE))
        .max(1);
    let start = usize::try_from(page)
        .unwrap_or(1)
        .saturating_sub(1)
        .saturating_mul(per);
    // Only the requested page of file rows is read (SQL LIMIT/OFFSET), never all of them.
    let shown = match db
        .list_files_page(id, u32::try_from(start).unwrap_or(u32::MAX), per_page)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "file listing failed");
            return internal();
        }
    };
    let groups: Vec<String> = match db
        .list_release_groups(id, u32::try_from(MAX_GROUPS_SHOWN).unwrap_or(20))
        .await
    {
        Ok(g) => g
            .iter()
            .map(|g| clean(g))
            .filter(|g| !g.is_empty())
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "group listing failed");
            return internal();
        }
    };
    let href = |p: usize| {
        if p <= 1 {
            format!("/release/{id}")
        } else {
            format!("/release/{id}?page={p}")
        }
    };
    let cur = usize::try_from(page).unwrap_or(1);
    let health = SEGMENT_HEALTH_CHECK_AVAILABLE;
    let missing_shown = if health { row.missing_segment_count } else { 0 };
    let m = meter(row.segment_count, missing_shown, health);
    let source_label = row
        .source_label
        .as_deref()
        .and_then(nzb_store::clean_source_label);
    let added_by = match db.release_attribution(id).await {
        Ok(Some(a)) if a.deleted => "Deleted account".to_owned(),
        Ok(Some(a)) => match a.handle {
            // The handle is a non-login display name (the store resolves a NULL to `user-<id>`);
            // askama escapes it.
            Some(h) => clean(&h),
            None if row.origin == Some(nzb_store::IngestOrigin::Watch) => "Watch folder".to_owned(),
            None => "Before accounts".to_owned(),
        },
        Ok(None) => "Before accounts".to_owned(),
        Err(e) => {
            tracing::error!(error = %e, "attribution lookup failed");
            return internal();
        }
    };
    let nfo = match db.release_nfo(id).await {
        Ok(n) => n.map(|n| crate::nfo::NfoView::decode(&n.bytes, None).0),
        Err(e) => {
            tracing::error!(error = %e, "nfo lookup failed");
            return internal();
        }
    };
    let now = st.deps.clock.now_secs();
    let files: Vec<FileView> = shown.iter().map(|f| file_view(f, health)).collect();
    let flags = flag_views(flag_labels(&row, health));
    let view = DetailPage {
        layout: Layout::for_session("Release", &sess),
        id,
        title: clean(&row.title),
        source_name: crate::index::shown_file_name(&row.title, row.source_name.as_deref()),
        source_label: source_label.clone(),
        source_edit: source_label.unwrap_or_default(),
        origin: row.origin.map(nzb_store::IngestOrigin::label),
        added_by,
        // Two independent cosmetic flags (the routes are enforced by the access gate): the edit forms follow
        // `can_edit` (admin, D40), the Danger zone with Delete release follows `can_delete` (admin) alone. The template
        // renders the Edit panel when either is set, so delete visibility never depends on the edit flag
        // (SECURITY_REVIEW 40 L1).
        can_edit: sess.role >= nzb_store::Role::Admin,
        can_delete: sess.role >= nzb_store::Role::Admin,
        category: u16::try_from(row.category_id)
            .ok()
            .and_then(|c| tax.get(c))
            .map_or_else(|| "Unknown".to_owned(), |c| c.name.clone()),
        category_source: category_source_label(row.category_source),
        category_source_class: category_source_class(row.category_source),
        overridden: row.category_overridden || row.category_source == CategorySource::Manual,
        categories: category_choices(
            tax,
            u16::try_from(row.category_id).ok(),
            &sess.hidden_categories,
        ),
        posted: row
            .posted_at
            .map_or_else(|| "-".to_owned(), |t| age_and_datetime(t, now)),
        ingested: age_and_datetime(row.ingested_at, now),
        size: human_bytes(row.total_bytes),
        nzb_size: human_bytes(row.nzb_size_bytes),
        poster: row.poster.as_deref().map(clean).filter(|p| !p.is_empty()),
        file_count: row.file_count,
        segment_count: row.segment_count,
        health,
        missing_segments: missing_shown,
        completeness: completeness(row.segment_count, missing_shown),
        meter_class: m.1,
        meter_state: m.2,
        alert_level: alert_level(&flags),
        flags,
        scene: scene_items(&row),
        groups,
        any_gap: files.iter().any(|f| f.has_gap),
        files,
        page,
        pages: u64::try_from(pages).unwrap_or(1),
        first: if shown.is_empty() { 0 } else { start + 1 },
        last: start + shown.len(),
        total_files,
        prev_href: (cur > 1).then(|| href(cur - 1)),
        next_href: (cur < pages).then(|| href(cur + 1)),
        per_page_choices: crate::page_size::choices(nzb_store::FilePageSize::CHOICES, per_page),
        nfo,
    };
    render(&view)
}

fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "release render failed");
            internal()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// On-demand parsing

/// Loads the stored NZB and runs `work` on it in `spawn_blocking`, holding one parse permit.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
async fn with_nzb<T, F>(st: &St, row: &ReleaseRow, work: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&[u8], &Limits, &SystemClock) -> Result<T, NzbError> + Send + 'static,
{
    enum Failure {
        Blob(&'static str),
        Parse(NzbError),
        Panic,
    }
    let permit = Arc::clone(&st.permits).try_acquire_owned().map_err(|_| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
            .retry_after(1)
            .into_response()
    })?;
    let mut limits = st.deps.limits;
    // The blocking parse must not outlive the response by much: cap its deadline to the
    // request timeout (minus a margin) configured by the caller.
    limits.parse_deadline = limits.parse_deadline.min(st.deps.max_parse);
    let (store, sha) = (Arc::clone(&st.deps.store), row.sha256);
    // The detached task owns the permit through BOTH the blob read and the parse, so a client
    // disconnect or request timeout (which drops this handler future) cannot release it while
    // the I/O or the blocking thread is still running.
    let task = tokio::spawn(async move {
        let _permit = permit;
        let bytes = store.get(&sha).await.map_err(|e| {
            Failure::Blob(match e {
                StoreError::NotFound => "missing",
                StoreError::Corrupt => "corrupt",
                _ => "io",
            })
        })?;
        tokio::task::spawn_blocking(move || {
            let clock = SystemClock::new();
            work(&bytes, &limits, &clock)
        })
        .await
        .map_err(|_| Failure::Panic)?
        .map_err(Failure::Parse)
    });
    match task.await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(Failure::Blob(class))) => {
            // Admin-visible, content-free: release id and the error class only.
            tracing::error!(release_id = row.id, class, "stored NZB unavailable");
            Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UNAVAILABLE"))
        }
        Ok(Err(Failure::Parse(NzbError::Timeout))) => {
            Err(fail(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT"))
        }
        Ok(Err(Failure::Parse(e))) => {
            tracing::error!(
                release_id = row.id,
                code = e.code(),
                "stored NZB unparseable"
            );
            Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "NZB_UNREADABLE"))
        }
        Ok(Err(Failure::Panic)) | Err(_) => Err(internal()),
    }
}

// ---------------------------------------------------------------------------------------------
// Segment listing

struct SegRow {
    gap: Option<String>,
    number: u32,
    bytes: u64,
    message_id: String,
}

#[derive(Template)]
#[template(path = "segments_fragment.html")]
struct SegmentsFragment {
    idx: u32,
    total: u32,
    first: u32,
    last: u32,
    rows: Vec<SegRow>,
    prev_href: Option<String>,
    next_href: Option<String>,
}

#[derive(Template)]
#[template(path = "segments.html")]
struct SegmentsPage {
    layout: Layout,
    id: i64,
    idx: u32,
    title: String,
    name: String,
    /// Segment count text ([`segments_text`]).
    segs: String,
    declared: String,
    health: bool,
    ranges: String,
    more_ranges: String,
    // Fields of `segments_fragment.html`, which is included into this page's scope.
    total: u32,
    first: u32,
    last: u32,
    rows: Vec<SegRow>,
    prev_href: Option<String>,
    next_href: Option<String>,
}

/// Validated `offset`/`limit`.
fn parse_segment_params(query: Option<&str>) -> Result<(u32, u32), ()> {
    let form = csrf::parse_form(query.unwrap_or_default().as_bytes());
    let get = |n: &str| csrf::form_get(&form, n).filter(|v| !v.is_empty());
    let offset = match get("offset") {
        None => 0,
        Some(v) if v.len() <= 7 && all_digits(v) => v.parse::<u32>().map_err(|_| ())?,
        Some(_) => return Err(()),
    };
    let limit = match get("limit") {
        None => DEFAULT_SEGMENT_LIMIT,
        Some(v) if v.len() <= 3 && all_digits(v) => v.parse::<u32>().map_err(|_| ())?,
        Some(_) => return Err(()),
    };
    if offset > MAX_SEGMENT_OFFSET || !(1..=MAX_SEGMENT_LIMIT).contains(&limit) {
        return Err(());
    }
    Ok((offset, limit))
}

fn segments_href(id: i64, idx: u32, offset: u32, limit: u32) -> String {
    if limit == DEFAULT_SEGMENT_LIMIT {
        format!("/release/{id}/file/{idx}/segments?offset={offset}")
    } else {
        format!("/release/{id}/file/{idx}/segments?offset={offset}&limit={limit}")
    }
}

// One linear handler (lookup, parse, gap rows, render); splitting it would only move fields.
#[allow(clippy::too_many_lines)]
async fn segments(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path((id, idx)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    // HEAD would run the full on-demand parse only to discard the body.
    if method == Method::HEAD {
        return fail(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED");
    }
    let (Some(id), Some(idx)) = (parse_id(&id), parse_idx(&idx)) else {
        return not_found();
    };
    let Ok((offset, limit)) = parse_segment_params(uri.query()) else {
        return fail(StatusCode::BAD_REQUEST, "BAD_QUERY");
    };
    let db = &st.deps.db;
    let row = match db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => r,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    };
    // One indexed lookup instead of loading every file row of the release.
    let file = match db.get_file(id, idx).await {
        Ok(Some(f)) => f,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "file lookup failed");
            return internal();
        }
    };
    let file = &file;
    let page = match with_nzb(&st, &row, move |bytes, limits, clock| {
        nzb_core::list_segments(bytes, limits, clock, idx, offset, limit)
    })
    .await
    {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let mut rows = Vec::with_capacity(page.items.len());
    let mut prev = offset_anchor(offset);
    for s in &page.items {
        let gap = prev.and_then(|p| {
            (s.number > p.saturating_add(1)).then(|| {
                let (a, b) = (p + 1, s.number - 1);
                if a == b {
                    format!("Missing segment {a}")
                } else {
                    format!("Missing segments {a}-{b}")
                }
            })
        });
        prev = Some(s.number);
        rows.push(SegRow {
            gap,
            number: s.number,
            bytes: s.bytes,
            message_id: s.message_id.clone(),
        });
    }
    let shown = u32::try_from(rows.len()).unwrap_or(0);
    let next = offset.saturating_add(limit);
    let frag = SegmentsFragment {
        idx,
        total: page.total,
        first: if shown == 0 { 0 } else { offset + 1 },
        last: offset.saturating_add(shown),
        rows,
        prev_href: (offset > 0)
            .then(|| segments_href(id, idx, offset.saturating_sub(limit), limit)),
        next_href: (next < page.total).then(|| segments_href(id, idx, next, limit)),
    };
    // HTMX partial (when the script is vendored); the plain page works without any JS.
    // A history restore (back button after a pushed URL) expects the whole page, so it is not
    // a partial even though htmx sends `HX-Request: true` with it.
    let hx_true = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "true")
    };
    let partial = hx_true("hx-request") && !hx_true("hx-history-restore-request");
    let mut resp = if partial {
        render(&frag)
    } else {
        let (ranges, _) = parse_ranges(file.missing_ranges.as_deref());
        let health = SEGMENT_HEALTH_CHECK_AVAILABLE;
        let fv = file_view(file, health);
        render(&SegmentsPage {
            layout: Layout::for_session("Segments", &sess),
            id,
            idx,
            title: clean(&row.title),
            name: fv.name,
            segs: fv.segs,
            declared: file
                .declared_segments
                .map_or_else(|| "?".to_owned(), |d| d.to_string()),
            health,
            ranges: ranges_text(&ranges),
            more_ranges: fv.more_ranges,
            total: frag.total,
            first: frag.first,
            last: frag.last,
            rows: frag.rows,
            prev_href: frag.prev_href,
            next_href: frag.next_href,
        })
    };
    resp.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("HX-Request, HX-History-Restore-Request"),
    );
    resp
}

/// Segment number that precedes the first row of a page: only page one has a known anchor (0),
/// so a gap before the very first segment is shown there and nowhere else.
const fn offset_anchor(offset: u32) -> Option<u32> {
    if offset == 0 { Some(0) } else { None }
}

// ---------------------------------------------------------------------------------------------
// Raw view

fn raw_text(id: i64, parsed: &nzb_core::ParsedNzb) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# release {id}");
    let _ = writeln!(
        out,
        "# files {} segments {} bytes {} duplicate_segments {}",
        parsed.files.len(),
        parsed.segment_count,
        parsed.total_bytes,
        parsed.duplicate_segments
    );
    let _ = writeln!(out, "\n[meta]");
    if parsed.meta.is_empty() {
        let _ = writeln!(out, "(none)");
    }
    for m in &parsed.meta {
        let _ = writeln!(out, "{}: {}", clean(&m.kind), clean(&m.value));
    }
    let _ = writeln!(
        out,
        "\n[files] first {} of {}",
        parsed.files.len().min(RAW_MAX_FILES),
        parsed.files.len()
    );
    for f in parsed.files.iter().take(RAW_MAX_FILES) {
        let ranges = ranges_text(&f.missing_ranges);
        let _ = writeln!(
            out,
            "file {}\n  subject: {}\n  poster: {}\n  groups: {}\n  bytes: {}\n  segments: {} declared: {}\n  missing: {}{}",
            f.idx,
            clean(&f.subject),
            f.poster.as_deref().map_or_else(String::new, clean),
            f.groups
                .iter()
                .map(|g| clean(g))
                .collect::<Vec<_>>()
                .join(", "),
            f.bytes,
            f.segment_count,
            f.declared_segments
                .map_or_else(|| "?".to_owned(), |d| d.to_string()),
            if ranges.is_empty() { "-" } else { &ranges },
            if f.missing_truncated {
                " (truncated)"
            } else {
                ""
            },
        );
        if out.len() >= RAW_MAX_BYTES {
            break;
        }
    }
    if out.len() > RAW_MAX_BYTES {
        let mut cut = RAW_MAX_BYTES;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n(truncated)\n");
    }
    out
}

async fn raw(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    method: Method,
    Path(id): Path<String>,
) -> Response {
    if method == Method::HEAD {
        return fail(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED");
    }
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let row = match st.deps.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => r,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    };
    let parsed = match with_nzb(&st, &row, |bytes, limits, clock| {
        nzb_core::parse(bytes, limits, clock)
    })
    .await
    {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let body = raw_text(id, &parsed);
    let mut resp = Response::new(axum::body::Body::from(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // Inline on purpose (no Content-Disposition): this is a view, not a download (SEC-030 is
    // the separate download route). `nosniff` and the CSP come from the global header layer.
    resp
}

// ---------------------------------------------------------------------------------------------
// Category override

async fn set_category(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    // CSRF (origin + synchronizer token) was verified by the session gate, which also restored
    // the body for us.
    let form = csrf::parse_form(&body);
    let Some(cat) = csrf::form_get(&form, "category").and_then(|v| st.deps.taxonomy.resolve(v))
    else {
        return fail(StatusCode::BAD_REQUEST, "INVALID_CATEGORY");
    };
    // A hidden target is as unknown as a typo; a hidden release does not exist (uniform 404).
    if sess.hides_category(u32::from(cat)) {
        return fail(StatusCode::BAD_REQUEST, "INVALID_CATEGORY");
    }
    match st.deps.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => {}
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    }
    // The writer re-validates the actor (live, enabled, admin) and writes the audit row
    // with the editing account and the old and new category in the same transaction (I-3).
    match st
        .deps
        .db
        .set_category_as(
            &sess.actor(),
            id,
            u32::from(cat),
            Some(&ip.to_string()),
            st.deps.clock.now_secs(),
        )
        .await
    {
        // The Statistics cache must not keep counting the release in its old category (review 47 L2).
        Ok(_) => sess.library_gen.note_change(st.deps.clock.now_secs()),
        // A role lost between the gate and the write is the uniform refusal.
        Err(StoreError::NotFound | StoreError::Account(_)) => return not_found(),
        Err(StoreError::UnknownCategory) => {
            return fail(StatusCode::BAD_REQUEST, "INVALID_CATEGORY");
        }
        Err(e) => {
            tracing::error!(error = %e, "category override failed");
            return internal();
        }
    }
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    // The id was validated as digits and re-formatted, so the header value is always valid.
    if let Ok(v) = HeaderValue::from_str(&format!("/release/{id}")) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

// ---------------------------------------------------------------------------------------------
// Source label edit

/// Longest raw `source` value accepted; the stored label is cut to 64 bytes after sanitizing.
const MAX_SOURCE_FORM_BYTES: usize = 512;

async fn set_source(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    // CSRF (origin + synchronizer token) was verified by the session gate.
    let form = csrf::parse_form(&body);
    // The field must be present (a blank value clears the label); anything over the cap is
    // refused instead of silently truncated, like the upload form's text parts.
    let Some(raw) = csrf::form_get(&form, "source").filter(|v| v.len() <= MAX_SOURCE_FORM_BYTES)
    else {
        return fail(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    };
    // A hidden release does not exist (uniform 404).
    match st.deps.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => {}
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    }
    // Audit row (actor, old and new label as JSON, so a vandalised edit can be reverted) is
    // written by the store in the same transaction as the edit.
    match st
        .deps
        .db
        .set_source_label_as(
            &sess.actor(),
            id,
            Some(raw),
            Some(&ip.to_string()),
            st.deps.clock.now_secs(),
        )
        .await
    {
        Ok(_) => {}
        Err(StoreError::NotFound | StoreError::Account(_)) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "source label update failed");
            return internal();
        }
    }
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(&format!("/release/{id}")) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::assert_is_empty)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_strict() {
        assert_eq!(parse_id("7"), Some(7));
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            "1a",
            " 1",
            "1 ",
            "9999999999999999",
            "１",
            "0x1",
            "1.0",
            "%31",
        ] {
            assert_eq!(parse_id(bad), None, "{bad:?}");
        }
        assert_eq!(parse_idx("0"), Some(0));
        assert_eq!(parse_idx("123456"), None);
    }

    #[test]
    fn ranges_parse_both_shapes_and_ignore_garbage() {
        assert_eq!(
            parse_ranges(Some("[[3,3],[6,57]]")),
            (vec![(3, 3), (6, 57)], false)
        );
        assert_eq!(
            parse_ranges(Some("{\"ranges\":[[1,2]],\"more\":true}")),
            (vec![(1, 2)], true)
        );
        for bad in [
            "",
            "null",
            "[[0,1]]",
            "[[5,2]]",
            "[[1]]",
            "[\"a\"]",
            "{\"x\":1}",
            "[[1,99999999999]]",
        ] {
            assert_eq!(parse_ranges(Some(bad)).0, Vec::new(), "{bad}");
        }
        assert_eq!(parse_ranges(None), (Vec::new(), false));
    }

    #[test]
    fn bar_marks_gaps_in_the_right_cells() {
        // 100 slots, 50 cells of 2 slots: slots 3..=4 missing => cell 1 is a gap.
        let c = bar_cells(100, &[(3, 4)]);
        assert_eq!(c.len(), 50);
        assert_eq!(c[0], "ok");
        assert_eq!(c[1], "gap");
        assert_eq!(c[2], "ok");
        // One slot of a two-slot cell missing => partial.
        assert_eq!(bar_cells(100, &[(3, 3)])[1], "part");
        // Fewer slots than cells: one cell per slot.
        let c = bar_cells(3, &[(2, 2)]);
        assert_eq!(c, vec!["ok", "gap", "ok"]);
        // Range beyond the total is clipped, empty file has no cells.
        assert_eq!(bar_cells(2, &[(2, 99)]), vec!["ok", "gap"]);
        assert!(bar_cells(0, &[]).is_empty());
        // Whole file missing.
        assert!(bar_cells(1000, &[(1, 1000)]).iter().all(|c| *c == "gap"));
    }

    #[test]
    fn completeness_is_integer_math() {
        assert_eq!(completeness(0, 0), "100.0%");
        assert_eq!(completeness(1, 2), "33.3%");
        assert_eq!(completeness(u64::MAX, 0), "100.0%");
    }

    #[test]
    fn segment_params_are_bounded() {
        assert_eq!(parse_segment_params(None), Ok((0, 100)));
        assert_eq!(
            parse_segment_params(Some("offset=200&limit=500")),
            Ok((200, 500))
        );
        for bad in [
            "limit=0",
            "limit=501",
            "offset=-1",
            "offset=x",
            "limit=1e2",
            "offset=1000001",
            "offset=99999999",
        ] {
            assert!(parse_segment_params(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn kind_label_maps_every_variant() {
        let all = [
            (FileKind::Video, "Video"),
            (FileKind::Audio, "Audio"),
            (FileKind::Archive, "Archive"),
            (FileKind::Par2, "Par2"),
            (FileKind::Nfo, "NFO"),
            (FileKind::Sfv, "SFV"),
            (FileKind::Subtitle, "Subtitle"),
            (FileKind::Image, "Image"),
            (FileKind::Nzb, "NZB"),
            (FileKind::Executable, "Executable"),
            (FileKind::Other, "Part"),
        ];
        for (k, label) in all {
            assert_eq!(kind_label(k), label);
            // The stored text round-trips, so the display label follows the stored kind.
            assert_eq!(parse_kind(k.as_str()), k);
        }
        // Unknown stored text is treated as Other, hence a Part with its own class.
        assert_eq!(kind_label(parse_kind("whatever")), "Part");
        assert_eq!(kind_class(FileKind::Other), "k-part");
    }

    #[test]
    fn segment_counts_are_max_on_max_without_health_check() {
        // Switch off: max(present, declared) on both sides.
        assert_eq!(segments_text(25, Some(28), false), "28/28");
        assert_eq!(segments_text(30, Some(28), false), "30/30");
        assert_eq!(segments_text(28, None, false), "28/28");
        // Switch on: the original present/declared form.
        assert_eq!(segments_text(25, Some(28), true), "25/28");
        assert_eq!(segments_text(28, None, true), "28/?");
    }
}
