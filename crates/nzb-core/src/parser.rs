//! Streaming NZB parser (`PARSER_SPEC` §Parsing rules).
//!
//! The input is hostile. The parser never builds a DOM: it walks `quick-xml` events once, keeps
//! only per-file scalars plus one bitset of seen segment numbers (dropped when the file ends), and
//! never retains message-ids in [`parse`]. Every limit in [`Limits`] is enforced, text is
//! length-checked on the *raw* form before it is unescaped and sanitized (SEC-002, SEC-004),
//! every DOCTYPE except the plain `nzb` one (see `doctype`) and every entity other than the
//! five predefined ones and numeric references is rejected (SEC-001), and a wall-clock deadline is checked every
//! [`DEADLINE_CHECK_INTERVAL`] events (SEC-003).

mod doctype;

use crate::error::{LimitName, NzbError};
use crate::limits::{DEADLINE_CHECK_INTERVAL, Limits};
use crate::sanitize::sanitize_text;
use crate::subject::parse_subject;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 2000-01-01T00:00:00Z: earlier file dates are treated as unknown.
const MIN_VALID_DATE: i64 = 946_684_800;
/// Dates up to one day in the future are tolerated (clock skew).
const MAX_FUTURE_SKEW_SECS: i64 = 86_400;
/// Missing ranges recorded per file (`FileInfo::missing_ranges` cap).
pub const MAX_MISSING_RANGES: usize = 256;
/// Hard cap of rows returned by [`list_segments`].
pub const MAX_PAGE_LIMIT: u32 = 500;
/// Longest accepted `<meta type="...">` value (sanitized and truncated to this many bytes).
const META_KIND_BYTES: usize = 64;
/// Allowance for surrounding whitespace in element text before the trimmed length is checked.
const TEXT_WS_SLACK: usize = 64;
/// Longest entity/char-reference name accepted between `&` and `;`.
const MAX_ENTITY_NAME: usize = 10;

/// Time source for the parse deadline and for date clamping (injected for deterministic tests).
pub trait Clock {
    /// Time elapsed since the parse started (monotonic).
    fn elapsed(&self) -> Duration;
    /// Current wall-clock time, Unix seconds.
    fn now_unix(&self) -> i64;
}

/// [`Clock`] backed by the system clocks. Create one per parse.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Starts the deadline clock now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

/// A `<meta type="..">value</meta>` entry (both parts sanitized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaEntry {
    /// The `type` attribute.
    pub kind: String,
    /// The element text.
    pub value: String,
}

/// One `<file>` as seen by the parser (all strings sanitized, display-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFile {
    /// Zero-based index in document order.
    pub idx: u32,
    /// Sanitized subject.
    pub subject: String,
    /// Sanitized poster, if non-empty.
    pub poster: Option<String>,
    /// Post time (Unix seconds) if present and within the valid range.
    pub posted_at: Option<i64>,
    /// Sum of the bytes of distinct segments.
    pub bytes: u64,
    /// Distinct segments.
    pub segment_count: u32,
    /// Segments dropped because their number was already seen.
    pub duplicate_segments: u32,
    /// Total `m` of the subject's `(n/m)` counter (see `parse_subject`), if valid.
    pub declared_segments: Option<u32>,
    /// Missing segment ranges (inclusive), at most [`MAX_MISSING_RANGES`].
    pub missing_ranges: Vec<(u32, u32)>,
    /// More missing ranges existed than were recorded.
    pub missing_truncated: bool,
    /// Sanitized newsgroups.
    pub groups: Vec<String>,
}

/// Result of [`parse`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedNzb {
    /// `<head><meta>` entries.
    pub meta: Vec<MetaEntry>,
    /// Files in document order.
    pub files: Vec<ParsedFile>,
    /// Sum of all distinct segment bytes.
    pub total_bytes: u64,
    /// Distinct segments in the whole NZB.
    pub segment_count: u64,
    /// Duplicate segments dropped in the whole NZB.
    pub duplicate_segments: u64,
}

/// One row of [`list_segments`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentEntry {
    /// Segment number (>= 1).
    pub number: u32,
    /// Segment size in bytes.
    pub bytes: u64,
    /// Sanitized message-id (escape at render time).
    pub message_id: String,
}

/// One selected `<file>` of [`extract_files`]: the same summary [`parse`] produces for it plus
/// every `<segment>` in document order, duplicates included (all strings sanitized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetFile {
    /// What [`parse`] reports for this file (`idx` is its index in the original document).
    pub file: ParsedFile,
    /// Every segment element of the file, in document order, duplicate numbers kept.
    pub segments: Vec<SegmentEntry>,
}

/// Result of [`extract_files`]: the head metas and the selected files, in document order.
/// The input of [`crate::write_nzb`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NzbSubset {
    /// `<head><meta>` entries, as [`parse`] reports them.
    pub meta: Vec<MetaEntry>,
    /// The selected files in document order.
    pub files: Vec<SubsetFile>,
}

/// Result of [`list_segments`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentPage {
    /// Requested rows, ascending by number.
    pub items: Vec<SegmentEntry>,
    /// Distinct segments in the file (for pagination).
    pub total: u32,
}

fn malformed(reason: &'static str) -> NzbError {
    NzbError::Malformed { reason }
}

const fn limit(which: LimitName) -> NzbError {
    NzbError::LimitExceeded { which }
}

fn lim(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Parses `input` once, enforcing every limit.
///
/// # Errors
/// [`NzbError`]: `DoctypeForbidden`, `NotUtf8`, `Empty`, `LimitExceeded`, `Timeout`, `Malformed`.
pub fn parse(input: &[u8], limits: &Limits, clock: &dyn Clock) -> Result<ParsedNzb, NzbError> {
    Ok(run(input, limits, clock, Mode::Full)?.parsed)
}

/// Returns up to `limit` (max [`MAX_PAGE_LIMIT`]) segments of file `file_idx`, ascending by
/// number, skipping the first `offset` distinct segments. Other files are skipped cheaply.
///
/// Runs the same reader and limits as [`parse`]; the first pass finds which numbers exist, the
/// second pass reads the message-ids of only the requested window, so memory stays bounded by the
/// page size no matter how large the file is.
///
/// # Errors
/// As [`parse`]; additionally `Malformed` if `file_idx` does not exist.
pub fn list_segments(
    input: &[u8],
    limits: &Limits,
    clock: &dyn Clock,
    file_idx: u32,
    offset: u32,
    limit: u32,
) -> Result<SegmentPage, NzbError> {
    let want = limit.min(MAX_PAGE_LIMIT);
    let pass1 = run(
        input,
        limits,
        clock,
        Mode::Target {
            idx: file_idx,
            window: None,
        },
    )?;
    if !pass1.target_found {
        return Err(malformed("file index out of range"));
    }
    let total = pass1.target_distinct;
    let (mut lo, mut hi) = (None, None);
    let mut rank: u32 = 0;
    let end = offset.saturating_add(want);
    for n in set_numbers(&pass1.target_bits) {
        if rank >= offset && rank < end {
            lo = lo.or(Some(n));
            hi = Some(n);
        }
        rank = rank.saturating_add(1);
        if rank >= end {
            break;
        }
    }
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Ok(SegmentPage {
            items: Vec::new(),
            total,
        });
    };
    drop(pass1);
    let pass2 = run(
        input,
        limits,
        clock,
        Mode::Target {
            idx: file_idx,
            window: Some((lo, hi)),
        },
    )?;
    let items = pass2
        .target_entries
        .into_iter()
        .map(|(number, (bytes, message_id))| SegmentEntry {
            number,
            bytes,
            message_id,
        })
        .collect();
    Ok(SegmentPage { items, total })
}

/// Extracts the head metas and the files whose zero-based indices are in `selected` (any order,
/// duplicates ignored) with all their groups and segments, for a partial download (T125).
///
/// Same reader, limits and deadline as [`parse`]; files that are not selected are skipped like in
/// [`list_segments`] (no attribute parsing, no segment work). Message-ids are kept for the
/// selected files only, so memory is bounded by the selected part of the (already size-capped)
/// input.
///
/// # Errors
/// As [`parse`]; additionally `Malformed` if `selected` is empty or names an index the document
/// does not have.
pub fn extract_files(
    input: &[u8],
    limits: &Limits,
    clock: &dyn Clock,
    selected: &[u32],
) -> Result<NzbSubset, NzbError> {
    let mut select = selected.to_vec();
    select.sort_unstable();
    select.dedup();
    if select.is_empty() {
        return Err(malformed("no file selected"));
    }
    let want = select.len();
    let out = run_with(input, limits, clock, Mode::Subset, select)?;
    if out.parsed.files.len() != want || out.subset_segments.len() != want {
        return Err(malformed("file index out of range"));
    }
    let files = out
        .parsed
        .files
        .into_iter()
        .zip(out.subset_segments)
        .map(|(file, segments)| SubsetFile { file, segments })
        .collect();
    Ok(NzbSubset {
        meta: out.parsed.meta,
        files,
    })
}

// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Mode {
    Full,
    /// Files listed in `Engine::select` only, with every segment (see [`extract_files`]).
    Subset,
    Target {
        idx: u32,
        /// `None`: only record which numbers exist. `Some((lo, hi))`: collect entries in range.
        window: Option<(u32, u32)>,
    },
}

#[derive(Default)]
struct Output {
    parsed: ParsedNzb,
    target_found: bool,
    target_bits: Vec<u64>,
    target_distinct: u32,
    target_entries: BTreeMap<u32, (u64, String)>,
    /// [`Mode::Subset`]: the segments of each selected file, parallel to `parsed.files`.
    subset_segments: Vec<Vec<SegmentEntry>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Root,
    Head,
    Meta,
    File,
    Groups,
    Group,
    Segments,
    Segment,
    Other,
}

fn child_kind(parent: Kind, name: &str) -> Kind {
    match (parent, name) {
        (Kind::Root, "head") => Kind::Head,
        (Kind::Root, "file") => Kind::File,
        (Kind::Head, "meta") => Kind::Meta,
        (Kind::File, "groups") => Kind::Groups,
        (Kind::File, "segments") => Kind::Segments,
        (Kind::Groups, "group") => Kind::Group,
        (Kind::Segments, "segment") => Kind::Segment,
        _ => Kind::Other,
    }
}

struct FileState {
    idx: u32,
    subject: String,
    poster: Option<String>,
    date: Option<i64>,
    groups: Vec<String>,
    groups_seen: u32,
    segments_seen: u32,
    bits: Vec<u64>,
    max_number: u32,
    distinct: u32,
    dups: u32,
    bytes: u64,
}

struct SegState {
    number: u32,
    bytes: u64,
    first: bool,
}

struct Capture {
    kind: Kind,
    cap: usize,
    which: LimitName,
    buf: String,
}

struct Engine<'a> {
    limits: &'a Limits,
    mode: Mode,
    now: i64,
    stack: Vec<Kind>,
    events: u32,
    root_closed: bool,
    files_seen: u32,
    segments_total: u64,
    meta_seen: u32,
    file: Option<FileState>,
    seg: Option<SegState>,
    meta_kind: String,
    capture: Option<Capture>,
    out: Output,
    /// [`Mode::Subset`]: sorted, de-duplicated indices of the files to keep.
    select: Vec<u32>,
    /// [`Mode::Subset`]: segments of the current selected file, in document order.
    subset_segs: Vec<SegmentEntry>,
}

/// XML reader configured for the strict NZB profile (no trimming, no lenient end-tag handling).
fn strict_reader(text: &str) -> Reader<&[u8]> {
    let mut reader = Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = true;
    cfg.allow_unmatched_ends = false;
    cfg.allow_dangling_amp = false;
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);
    reader
}

impl<'a> Engine<'a> {
    fn new(limits: &'a Limits, mode: Mode, now: i64) -> Self {
        let depth_cap = lim(limits.max_xml_depth).min(64);
        Self {
            limits,
            mode,
            now,
            stack: Vec::with_capacity(depth_cap),
            events: 0,
            root_closed: false,
            files_seen: 0,
            segments_total: 0,
            meta_seen: 0,
            file: None,
            seg: None,
            meta_kind: String::new(),
            capture: None,
            out: Output::default(),
            select: Vec::new(),
            subset_segs: Vec::new(),
        }
    }
}

fn run(input: &[u8], limits: &Limits, clock: &dyn Clock, mode: Mode) -> Result<Output, NzbError> {
    run_with(input, limits, clock, mode, Vec::new())
}

fn run_with(
    input: &[u8],
    limits: &Limits,
    clock: &dyn Clock,
    mode: Mode,
    select: Vec<u32>,
) -> Result<Output, NzbError> {
    // Whatever the caller built, no bound may exceed the code-level ceiling (SEC-002).
    let limits = &limits.clamped_to_ceilings();
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > limits.max_file_bytes {
        return Err(limit(LimitName::FileBytes));
    }
    if input.is_empty() {
        return Err(NzbError::Empty);
    }
    // Validating the whole input up front also rejects UTF-16 and gzip before any XML runs.
    let text = std::str::from_utf8(input).map_err(|_| NzbError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = strict_reader(text);
    let mut eng = Engine::new(limits, mode, clock.now_unix());
    eng.select = select;
    // Prolog state for the one DOCTYPE allowed: before the root, once, after only the XML
    // declaration, comments and whitespace. `prolog_content` turns true with the first event
    // that is not whitespace (so the XML declaration is only accepted before anything else).
    let mut doctype_seen = false;
    let mut prolog_pi = false;
    let mut prolog_content = false;
    loop {
        let start_pos = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        eng.events = eng.events.wrapping_add(1);
        if eng.events.is_multiple_of(DEADLINE_CHECK_INTERVAL)
            && clock.elapsed() >= limits.parse_deadline
        {
            return Err(NzbError::Timeout);
        }
        let Ok(ev) = reader.read_event() else {
            // An unterminated or otherwise broken declaration is a DOCTYPE problem, not
            // generic malformed XML (the stable error code tells the user why).
            let rest = text.as_bytes().get(start_pos..).unwrap_or(&[]);
            let head = rest.get(..9).unwrap_or(&[]);
            return Err(if head.eq_ignore_ascii_case(b"<!DOCTYPE") {
                NzbError::DoctypeForbidden
            } else {
                malformed("invalid XML")
            });
        };
        match ev {
            Event::Eof => break,
            Event::DocType(_) => {
                // Validate the raw declaration (keyword case included), not quick-xml's view of
                // it. The identifiers are ignored: nothing here resolves, fetches or stores them.
                let end_pos = usize::try_from(reader.buffer_position()).unwrap_or(0);
                let raw = text.as_bytes().get(start_pos..end_pos).unwrap_or(&[]);
                if doctype_seen
                    || prolog_pi
                    || !eng.in_prolog()
                    || !doctype::is_plain_nzb_doctype(raw)
                {
                    return Err(NzbError::DoctypeForbidden);
                }
                doctype_seen = true;
                prolog_content = true;
            }
            Event::Start(e) => {
                prolog_content = true;
                eng.open(&e, false)?;
            }
            Event::Empty(e) => {
                prolog_content = true;
                eng.open(&e, true)?;
            }
            Event::End(_) => eng.close()?,
            Event::Text(t) => {
                // Outside the root only XML whitespace, comments and processing instructions
                // are legal. Check the epilog too: trailing garbage must not be stored and
                // served as a valid NZB just because its preceding root was well-formed.
                let chunk: &str = &t;
                if eng.stack.is_empty() && !chunk.chars().all(is_xml_space) {
                    return Err(malformed("text outside the root element"));
                }
                eng.text(chunk)?;
            }
            Event::CData(c) => {
                if eng.stack.is_empty() {
                    return Err(malformed("CDATA outside the root element"));
                }
                eng.text(&c)?;
            }
            Event::GeneralRef(r) => {
                if eng.stack.is_empty() {
                    return Err(malformed("reference outside the root element"));
                }
                let c = resolve_entity(&r)?;
                let mut tmp = [0u8; 4];
                eng.text(c.encode_utf8(&mut tmp))?;
            }
            Event::PI(_) => {
                // A processing instruction on either side of the DOCTYPE is a DOCTYPE-rule
                // violation (symmetric); without a DOCTYPE it stays inert and ignored.
                if doctype_seen && eng.in_prolog() {
                    return Err(NzbError::DoctypeForbidden);
                }
                prolog_pi = true;
                prolog_content = true;
            }
            Event::Comment(_) => prolog_content = true,
            Event::Decl(_) => {
                // The XML declaration is only legal as the very first thing (a BOM and
                // whitespace aside); anywhere else it is malformed, not silently ignored.
                if prolog_content || !eng.in_prolog() {
                    return Err(malformed("misplaced XML declaration"));
                }
                prolog_content = true;
            }
        }
    }
    finish(eng, clock, limits)
}

/// End-of-document checks shared by every mode.
fn finish(eng: Engine<'_>, clock: &dyn Clock, limits: &Limits) -> Result<Output, NzbError> {
    // Documents with fewer than DEADLINE_CHECK_INTERVAL events never hit the in-loop check.
    if clock.elapsed() >= limits.parse_deadline {
        return Err(NzbError::Timeout);
    }
    if !eng.stack.is_empty() {
        return Err(malformed("unexpected end of document"));
    }
    if eng.files_seen == 0 {
        return Err(NzbError::Empty);
    }
    Ok(eng.out)
}

/// XML `S` production: space, TAB, CR, LF.
const fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

impl Engine<'_> {
    /// True before the root element has started: only the declaration, DOCTYPE, comments and
    /// whitespace may appear.
    fn in_prolog(&self) -> bool {
        self.stack.is_empty() && !self.root_closed
    }

    fn open(&mut self, e: &BytesStart<'_>, empty: bool) -> Result<(), NzbError> {
        let depth = self.stack.len().saturating_add(1);
        if depth > lim(self.limits.max_xml_depth) {
            return Err(limit(LimitName::XmlDepth));
        }
        let name = e.local_name();
        let kind = match self.stack.last() {
            None => {
                if self.root_closed {
                    return Err(malformed("multiple root elements"));
                }
                if name.as_ref() != "nzb" {
                    return Err(NzbError::Empty);
                }
                Kind::Root
            }
            Some(&p) => child_kind(p, name.as_ref()),
        };
        match kind {
            Kind::File => self.start_file(e)?,
            Kind::Segment => self.start_segment(e)?,
            Kind::Group if self.file.is_some() => {
                self.begin_capture(
                    Kind::Group,
                    lim(self.limits.max_group_bytes),
                    LimitName::GroupBytes,
                );
                self.count_group()?;
            }
            Kind::Meta if matches!(self.mode, Mode::Full | Mode::Subset) => self.start_meta(e)?,
            _ => {}
        }
        if empty {
            self.finish(kind)?;
            if kind == Kind::Root {
                self.root_closed = true;
            }
        } else {
            self.stack.push(kind);
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), NzbError> {
        let kind = self.stack.pop().ok_or(malformed("unbalanced end tag"))?;
        self.finish(kind)?;
        if self.stack.is_empty() {
            self.root_closed = true;
        }
        Ok(())
    }

    fn begin_capture(&mut self, kind: Kind, cap: usize, which: LimitName) {
        self.capture = Some(Capture {
            kind,
            cap,
            which,
            buf: String::new(),
        });
    }

    fn text(&mut self, chunk: &str) -> Result<(), NzbError> {
        if let Some(c) = &mut self.capture
            && self.stack.last() == Some(&c.kind)
        {
            // Raw cap first: never buffer more than the limit (plus whitespace slack).
            if c.buf.len().saturating_add(chunk.len()) > c.cap.saturating_add(TEXT_WS_SLACK) {
                return Err(limit(c.which));
            }
            c.buf.push_str(chunk);
        }
        Ok(())
    }

    /// Takes the captured text, trimmed and length-checked.
    fn take_capture(&mut self, kind: Kind) -> Result<Option<String>, NzbError> {
        match self.capture.take() {
            Some(c) if c.kind == kind => {
                let t = c.buf.trim();
                if t.len() > c.cap {
                    return Err(limit(c.which));
                }
                Ok(Some(t.to_owned()))
            }
            other => {
                self.capture = other;
                Ok(None)
            }
        }
    }

    fn start_file(&mut self, e: &BytesStart<'_>) -> Result<(), NzbError> {
        self.files_seen = self.files_seen.saturating_add(1);
        if self.files_seen > self.limits.max_files {
            return Err(limit(LimitName::Files));
        }
        let idx = self.files_seen.saturating_sub(1);
        let skipped = match self.mode {
            Mode::Target { idx: want, .. } => want != idx,
            Mode::Subset => self.select.binary_search(&idx).is_err(),
            Mode::Full => false,
        };
        if skipped {
            return Ok(()); // skipped file: no attribute parsing, no segment work
        }
        let mut st = FileState {
            idx,
            subject: String::new(),
            poster: None,
            date: None,
            groups: Vec::new(),
            groups_seen: 0,
            segments_seen: 0,
            bits: Vec::new(),
            max_number: 0,
            distinct: 0,
            dups: 0,
            bytes: 0,
        };
        for a in e.attributes() {
            let a = a.map_err(|_| malformed("bad attribute"))?;
            match a.key.as_ref() {
                "subject" => {
                    st.subject = attr_text(
                        &a.value,
                        self.limits.max_subject_bytes,
                        LimitName::SubjectBytes,
                    )?;
                }
                "poster" => {
                    let p = attr_text(
                        &a.value,
                        self.limits.max_poster_bytes,
                        LimitName::PosterBytes,
                    )?;
                    let p = sanitize_text(&p, lim(self.limits.max_poster_bytes));
                    st.poster = (!p.is_empty()).then_some(p);
                }
                "date" => st.date = parse_date(&a.value, self.now),
                _ => {}
            }
        }
        st.subject = sanitize_text(&st.subject, lim(self.limits.max_subject_bytes));
        self.file = Some(st);
        Ok(())
    }

    fn count_group(&mut self) -> Result<(), NzbError> {
        if let Some(f) = &mut self.file {
            f.groups_seen = f.groups_seen.saturating_add(1);
            if f.groups_seen > self.limits.max_groups_per_file {
                return Err(limit(LimitName::GroupsPerFile));
            }
        }
        Ok(())
    }

    fn start_meta(&mut self, e: &BytesStart<'_>) -> Result<(), NzbError> {
        self.meta_seen = self.meta_seen.saturating_add(1);
        if self.meta_seen > self.limits.max_meta_entries {
            return Err(limit(LimitName::MetaEntries));
        }
        self.meta_kind.clear();
        for a in e.attributes() {
            let a = a.map_err(|_| malformed("bad attribute"))?;
            if a.key.as_ref() == "type" {
                let k = attr_text(
                    &a.value,
                    self.limits.max_meta_value_bytes,
                    LimitName::MetaValueBytes,
                )?;
                self.meta_kind = sanitize_text(&k, META_KIND_BYTES);
            }
        }
        self.begin_capture(
            Kind::Meta,
            lim(self.limits.max_meta_value_bytes),
            LimitName::MetaValueBytes,
        );
        Ok(())
    }

    fn start_segment(&mut self, e: &BytesStart<'_>) -> Result<(), NzbError> {
        let max_segments = self.limits.max_segments_per_file;
        let Some(f) = &mut self.file else {
            return Ok(()); // segment of a skipped file
        };
        let (mut number, mut bytes) = (None, None);
        for a in e.attributes() {
            let a = a.map_err(|_| malformed("bad attribute"))?;
            match a.key.as_ref() {
                "number" => {
                    number =
                        Some(parse_digits_u64(&a.value).ok_or(malformed("bad segment number"))?);
                }
                "bytes" => {
                    bytes = Some(parse_digits_u64(&a.value).ok_or(malformed("bad segment bytes"))?);
                }
                _ => {}
            }
        }
        let number = number.ok_or(malformed("segment without number"))?;
        let bytes = bytes.ok_or(malformed("segment without bytes"))?;
        if number == 0 {
            return Err(malformed("segment number is zero"));
        }
        let number = u32::try_from(number)
            .ok()
            .filter(|n| *n <= max_segments)
            .ok_or(limit(LimitName::SegmentsPerFile))?;
        if bytes > self.limits.max_segment_bytes {
            return Err(limit(LimitName::SegmentBytes));
        }
        // The per-file bound covers every element, not only distinct segment numbers.
        f.segments_seen = f.segments_seen.saturating_add(1);
        if f.segments_seen > max_segments {
            return Err(limit(LimitName::SegmentsPerFile));
        }
        // Count every segment element (duplicates included) so duplicates cannot buy unbounded work.
        self.segments_total = self.segments_total.saturating_add(1);
        if self.segments_total > u64::from(self.limits.max_total_segments) {
            return Err(limit(LimitName::TotalSegments));
        }
        let first = !test_and_set(&mut f.bits, number)?;
        f.max_number = f.max_number.max(number);
        if first {
            f.distinct = f.distinct.saturating_add(1);
            f.bytes = f
                .bytes
                .checked_add(bytes)
                .ok_or(limit(LimitName::TotalBytes))?;
            self.out.parsed.total_bytes = self
                .out
                .parsed
                .total_bytes
                .checked_add(bytes)
                .filter(|t| *t <= self.limits.max_total_bytes)
                .ok_or(limit(LimitName::TotalBytes))?;
            self.out.parsed.segment_count = self.out.parsed.segment_count.saturating_add(1);
        } else {
            f.dups = f.dups.saturating_add(1);
            self.out.parsed.duplicate_segments =
                self.out.parsed.duplicate_segments.saturating_add(1);
        }
        self.seg = Some(SegState {
            number,
            bytes,
            first,
        });
        self.begin_capture(
            Kind::Segment,
            lim(self.limits.max_message_id_bytes),
            LimitName::MessageIdBytes,
        );
        Ok(())
    }

    fn finish(&mut self, kind: Kind) -> Result<(), NzbError> {
        match kind {
            Kind::Segment => {
                if let Some(id) = self.take_capture(Kind::Segment)?
                    && let Some(seg) = self.seg.take()
                {
                    match self.mode {
                        Mode::Target {
                            window: Some((lo, hi)),
                            ..
                        } if seg.first && (lo..=hi).contains(&seg.number) => {
                            let id = sanitize_text(&id, lim(self.limits.max_message_id_bytes));
                            self.out.target_entries.insert(seg.number, (seg.bytes, id));
                        }
                        Mode::Subset if self.file.is_some() => {
                            // Duplicates included: the subset keeps the file exactly as parsed.
                            let id = sanitize_text(&id, lim(self.limits.max_message_id_bytes));
                            self.subset_segs.push(SegmentEntry {
                                number: seg.number,
                                bytes: seg.bytes,
                                message_id: id,
                            });
                        }
                        _ => {}
                    }
                }
                self.seg = None;
            }
            Kind::Group => {
                if let Some(g) = self.take_capture(Kind::Group)?
                    && let Some(f) = &mut self.file
                {
                    f.groups
                        .push(sanitize_text(&g, lim(self.limits.max_group_bytes)));
                }
            }
            Kind::Meta => {
                if let Some(v) = self.take_capture(Kind::Meta)? {
                    let value = sanitize_text(&v, lim(self.limits.max_meta_value_bytes));
                    let kind = std::mem::take(&mut self.meta_kind);
                    self.out.parsed.meta.push(MetaEntry { kind, value });
                }
            }
            Kind::File => self.finish_file(),
            Kind::Root | Kind::Head | Kind::Groups | Kind::Segments | Kind::Other => {}
        }
        Ok(())
    }

    fn finish_file(&mut self) {
        let Some(f) = self.file.take() else {
            return;
        };
        // `parse_subject` is the single source of truth for the `(n/m)` counter (any form).
        let declared = parse_subject(&f.subject, self.limits).declared_segments;
        let upper = declared.unwrap_or(f.max_number);
        let (missing_ranges, missing_truncated) = missing_ranges(&f.bits, upper);
        if let Mode::Target { idx, .. } = self.mode
            && idx == f.idx
        {
            self.out.target_found = true;
            self.out.target_distinct = f.distinct;
            self.out.target_bits = f.bits;
            return;
        }
        if matches!(self.mode, Mode::Subset) {
            self.out
                .subset_segments
                .push(std::mem::take(&mut self.subset_segs));
        }
        self.out.parsed.files.push(ParsedFile {
            idx: f.idx,
            subject: f.subject,
            poster: f.poster,
            posted_at: f.date,
            bytes: f.bytes,
            segment_count: f.distinct,
            duplicate_segments: f.dups,
            declared_segments: declared,
            missing_ranges,
            missing_truncated,
            groups: f.groups,
        });
    }
}

// ---------------------------------------------------------------------------------------------

fn parse_digits_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

fn parse_date(raw: &str, now: i64) -> Option<i64> {
    if raw.len() > 12 {
        return None;
    }
    let v = i64::try_from(parse_digits_u64(raw.trim())?).ok()?;
    let max = now.saturating_add(MAX_FUTURE_SKEW_SECS);
    (MIN_VALID_DATE..=max).contains(&v).then_some(v)
}

/// Raw-length check, then unescape. The cap applies to the raw (escaped) form.
fn attr_text(raw: &str, max: u32, which: LimitName) -> Result<String, NzbError> {
    if raw.len() > lim(max) {
        return Err(limit(which));
    }
    unescape(raw)
}

/// Resolves the five predefined entities and numeric character references; rejects the rest.
fn resolve_entity(name: &str) -> Result<char, NzbError> {
    if name.len() > MAX_ENTITY_NAME {
        return Err(malformed("unsupported entity"));
    }
    match name {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => {
            let digits = name
                .strip_prefix('#')
                .ok_or(malformed("unsupported entity"))?;
            let n = match digits.strip_prefix('x') {
                Some(h) if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    u32::from_str_radix(h, 16).ok()
                }
                None if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                    digits.parse::<u32>().ok()
                }
                _ => None,
            };
            n.filter(|n| *n != 0)
                .and_then(char::from_u32)
                .ok_or(malformed("invalid character reference"))
        }
    }
}

fn unescape(raw: &str) -> Result<String, NzbError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find('&') {
        out.push_str(rest.get(..pos).unwrap_or_default());
        let after = rest.get(pos.saturating_add(1)..).unwrap_or_default();
        let semi = after.find(';').ok_or(malformed("unterminated entity"))?;
        out.push(resolve_entity(after.get(..semi).unwrap_or_default())?);
        rest = after.get(semi.saturating_add(1)..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}

/// Sets bit `n`; returns whether it was already set. Memory: at most `n / 8` bytes, and `n` was
/// bounded by `max_segments_per_file` by the caller.
fn test_and_set(bits: &mut Vec<u64>, n: u32) -> Result<bool, NzbError> {
    let w = usize::try_from(n >> 6).map_err(|_| malformed("segment number out of range"))?;
    if bits.len() <= w {
        bits.resize(w.saturating_add(1), 0);
    }
    let word = bits
        .get_mut(w)
        .ok_or(malformed("segment number out of range"))?;
    let mask = 1u64 << (n & 63);
    let was = *word & mask != 0;
    *word |= mask;
    Ok(was)
}

fn word_at(bits: &[u64], n: u32) -> u64 {
    usize::try_from(n >> 6)
        .ok()
        .and_then(|w| bits.get(w))
        .copied()
        .unwrap_or(0)
}

fn is_set(bits: &[u64], n: u32) -> bool {
    word_at(bits, n) & (1u64 << (n & 63)) != 0
}

/// Ascending numbers whose bit is set.
fn set_numbers(bits: &[u64]) -> impl Iterator<Item = u32> + '_ {
    bits.iter().enumerate().flat_map(|(w, &word)| {
        let base = u32::try_from(w).unwrap_or(u32::MAX).saturating_mul(64);
        (0..64u32).filter_map(move |b| (word & (1u64 << b) != 0).then_some(base.saturating_add(b)))
    })
}

/// Inclusive ranges of numbers in `1..=upper` that are not set; at most [`MAX_MISSING_RANGES`].
fn missing_ranges(bits: &[u64], upper: u32) -> (Vec<(u32, u32)>, bool) {
    let mut out: Vec<(u32, u32)> = Vec::new();
    let mut run: Option<u32> = None;
    let mut n: u32 = 1;
    while n <= upper {
        let aligned = n.trailing_zeros() >= 6;
        let (step_end, all_set, all_clear) = if aligned && n.saturating_add(63) <= upper {
            let w = word_at(bits, n);
            (n.saturating_add(63), w == u64::MAX, w == 0)
        } else {
            let s = is_set(bits, n);
            (n, s, !s)
        };
        if all_set {
            if let Some(start) = run.take()
                && !push_range(&mut out, start, n.saturating_sub(1))
            {
                return (out, true);
            }
        } else if all_clear {
            run.get_or_insert(n);
        } else {
            // Mixed word: walk it bit by bit.
            for m in n..=step_end {
                if is_set(bits, m) {
                    if let Some(start) = run.take()
                        && !push_range(&mut out, start, m.saturating_sub(1))
                    {
                        return (out, true);
                    }
                } else {
                    run.get_or_insert(m);
                }
            }
        }
        n = step_end.saturating_add(1);
    }
    if let Some(start) = run
        && !push_range(&mut out, start, upper)
    {
        return (out, true);
    }
    (out, false)
}

/// Returns `false` (and records nothing) if the cap is already reached.
fn push_range(out: &mut Vec<(u32, u32)>, a: u32, b: u32) -> bool {
    if out.len() >= MAX_MISSING_RANGES {
        return false;
    }
    out.push((a, b));
    true
}

#[cfg(test)]
mod tests;
