//! `GET /release/{id}/download` (SEC-030, T047): serves the stored NZB bytes unchanged.
//! `POST /release/{id}/download/selected` (T125): an NZB holding only the ticked files.
//!
//! The route sits behind the active-session gate. The blob comes from the store, which verifies
//! its SHA-256 on read (`StoreError::Corrupt` otherwise), so the bytes sent are the bytes
//! ingested. Whole-blob reads (up to the 64 MiB upload cap) are limited to
//! [`MAX_CONCURRENT_DOWNLOADS`] at a time; further requests get `503 BUSY` instead of queueing
//! memory. The permit is owned by the response body ([`PermitBody`]) and released only when the
//! body is finished or dropped, so a slow reader keeps counting against the pool. An independent
//! watchdog frees the blob and permits after [`SEND_DEADLINE`] even when socket backpressure
//! stops polling the body; the next body poll reports an error and aborts the response.
//! The audit row is best-effort: written before the bytes are sent, and a failed write is only
//! logged. The per-IP download rate class (30/min) is applied by the middleware by path.
//!
//! # Partial download (T125)
//! The form posts repeated `file=<idx>` fields (session gate + CSRF like every POST, viewer and
//! up like the full download, same per-IP and per-account download budgets, same permit pool and
//! send deadline). The selection is validated against the release's file count before any blob
//! is read: none -> `400 NO_FILES_SELECTED`; a duplicate, non-numeric or out-of-range index, or
//! more `file` fields than the release has files -> `400 BAD_FILE_INDEX`. The output is never a
//! byte range of the stored document: the verified blob is parsed again by the hardened parser
//! ([`nzb_core::extract_files`], under the parse deadline, in `spawn_blocking`) and written by
//! the escaping serializer ([`nzb_core::write_nzb`]). The stored NZB is never modified.
//! Memory (review 43 M1): partial downloads also take a permit of their own one-permit pool
//! ([`MAX_CONCURRENT_PARTIAL_DOWNLOADS`]); the blob is dropped before serializing; the output is
//! sized exactly and capped at the parser's `max_file_bytes` (`413 PARTIAL_TOO_LARGE`), so it is
//! never larger than an NZB nzbd itself accepts. Audit event [`DOWNLOAD_SELECTED_EVENT`].
//!
//! # Untrusted data
//! The release title comes from the NZB and may contain anything. It never reaches a header
//! raw: [`safe_filename`] maps it through the allowlist `[A-Za-z0-9._-]` (everything else
//! becomes `_`), so the header value is plain ASCII without quotes, separators or control bytes.

use nzb_store::prelude::*;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body::{Body, Frame};
use nzb_core::{NzbError, SystemClock, extract_files, write_nzb};
use nzb_store::StoreError;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;

use crate::auth::SessionCtx;
use crate::ctx::ClientIp;
use crate::release::{St, fail, internal, not_found, parse_id};

/// Concurrent whole-blob reads before answering `503 BUSY` (2 x 64 MiB worst case in memory).
pub const MAX_CONCURRENT_DOWNLOADS: usize = 2;
/// Concurrent partial downloads (T125, review 43 M1), on top of the shared download pool: a partial
/// download holds the blob plus its parsed subset (up to about 3.5 x `max_file_bytes` at peak),
/// so at most one runs at a time; the other shared permit stays free for a full download.
pub const MAX_CONCURRENT_PARTIAL_DOWNLOADS: usize = 1;
/// Audit event of the full download (an `ID_EVENTS` entry of the store: attributed by user id).
pub const DOWNLOAD_EVENT: &str = "download";
/// Audit event of the partial download (an `ID_EVENTS` entry of the store, review 43 M2).
pub const DOWNLOAD_SELECTED_EVENT: &str = "download_selected";
/// Total time one download may take to send (reader included) before the body is aborted.
pub const SEND_DEADLINE: Duration = Duration::from_secs(120);
/// Size of one body frame; small frames keep hyper's write buffer (and our permit) honest.
const FRAME_BYTES: usize = 64 * 1024;
/// Longest file name stem (before `.nzb`).
pub const MAX_STEM_CHARS: usize = 120;
/// Media type of the download.
pub const CONTENT_TYPE: &str = "application/x-nzb";

/// Builds the download file name for a release: the title restricted to `[A-Za-z0-9._-]`
/// (other characters, including spaces, become `_`), runs of `_`/`.` collapsed, leading and
/// trailing `.`/`_`/`-` trimmed (so it never starts with a dot and has no `..`), at most
/// [`MAX_STEM_CHARS`] before the `.nzb` suffix. Titles without any alphanumeric character
/// fall back to `release-<id>.nzb`.
#[must_use]
pub fn safe_filename(title: &str, id: i64) -> String {
    let mut stem = String::new();
    let mut last_sep = true; // suppresses leading separators
    for ch in title.chars() {
        let c = if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
            ch
        } else {
            '_'
        };
        if c == '_' || c == '.' {
            // Collapse any run of `_`/`.` into its first member.
            if !last_sep {
                stem.push(c);
                last_sep = true;
            }
        } else {
            stem.push(c);
            last_sep = false;
        }
        if stem.len() >= MAX_STEM_CHARS.saturating_mul(2) {
            break;
        }
    }
    // `stem` is pure ASCII here, so byte and char counts agree.
    stem.truncate(MAX_STEM_CHARS);
    // Trim, then strip trailing `.nzb` (any number, so the result is a fixed point), trim again.
    let trim = |s: &str| s.trim_matches(|c| matches!(c, '.' | '_' | '-')).to_owned();
    let mut stem = trim(&stem);
    while stem.len() >= 4 && stem.to_ascii_lowercase().ends_with(".nzb") {
        stem.truncate(stem.len() - 4);
        stem = trim(&stem);
    }
    if !stem.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return format!("release-{id}.nzb");
    }
    // Legacy Windows treats these as devices whatever the extension.
    let base = stem.split('.').next().unwrap_or_default();
    if is_reserved_device_name(base) {
        return format!("release-{id}-{stem}.nzb");
    }
    format!("{stem}.nzb")
}

/// File name of a partial download: the [`safe_filename`] stem plus `-partial.nzb` (same
/// allowlist, so still plain ASCII without quotes or separators).
#[must_use]
pub fn partial_filename(title: &str, id: i64) -> String {
    let full = safe_filename(title, id);
    let stem = full.strip_suffix(".nzb").unwrap_or(&full);
    format!("{stem}-partial.nzb")
}

fn is_reserved_device_name(base: &str) -> bool {
    let up = base.to_ascii_uppercase();
    matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (up.len() == 4
            && (up.starts_with("COM") || up.starts_with("LPT"))
            && up
                .as_bytes()
                .get(3)
                .is_some_and(|d| (b'1'..=b'9').contains(d)))
}

/// RFC 5987 `attr-char` percent-encoding of `s`.
fn pct_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+.^_`|~-".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `Content-Disposition` value for `name` (an already sanitized file name).
#[must_use]
pub fn content_disposition(name: &str) -> String {
    format!(
        "attachment; filename=\"{name}\"; filename*=UTF-8''{}",
        pct_encode(name)
    )
}

/// Shared with the watchdog so a consumer that stops polling cannot keep the blob or permits.
struct DownloadBuffer {
    data: Vec<u8>,
    pos: usize,
    expired: bool,
    /// The shared download permit and, for a partial download, its own permit as well.
    permits: Vec<OwnedSemaphorePermit>,
}

impl DownloadBuffer {
    fn release(&mut self) {
        // Clearing a Vec retains its allocation; replace it to return the whole blob's memory.
        self.data = Vec::new();
        self.permits.clear();
    }
}

/// Response body that owns the download permits and an independent total-send watchdog.
///
/// Each frame copies at most [`FRAME_BYTES`], so a frame retained by hyper cannot retain the
/// original (up to 64 MiB) allocation after the deadline. The watchdog drops that allocation
/// and all permits even if backpressure prevents any further body polls.
pub struct PermitBody {
    buffer: Arc<Mutex<DownloadBuffer>>,
    len: usize,
    expires: tokio::time::Instant,
    watchdog: JoinHandle<()>,
}

impl PermitBody {
    /// Wraps `data`; `permit` is released when the body ends or is dropped.
    #[must_use]
    pub fn new(data: Vec<u8>, permit: OwnedSemaphorePermit, deadline: Duration) -> Self {
        let len = data.len();
        let buffer = Arc::new(Mutex::new(DownloadBuffer {
            data,
            pos: 0,
            expired: false,
            permits: vec![permit],
        }));
        let weak = Arc::downgrade(&buffer);
        let expires = tokio::time::Instant::now() + deadline;
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep_until(expires).await;
            if let Some(buffer) = weak.upgrade() {
                let mut state = buffer.lock().unwrap_or_else(PoisonError::into_inner);
                state.expired |= state.pos < state.data.len();
                state.release();
            }
        });
        Self {
            buffer,
            len,
            expires,
            watchdog,
        }
    }

    /// Also holds `permit` until the body ends or is dropped.
    #[must_use]
    pub fn with_extra_permit(self, permit: OwnedSemaphorePermit) -> Self {
        let mut state = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.expired && !state.permits.is_empty() {
            state.permits.push(permit);
        }
        drop(state);
        self
    }
}

impl Drop for PermitBody {
    fn drop(&mut self) {
        // A completed or disconnected response needs no timer. The weak reference in the task
        // cannot extend the buffer's lifetime even if the task has not observed its abort yet.
        self.watchdog.abort();
    }
}

/// The send deadline elapsed.
#[derive(Debug)]
pub struct SendDeadline;

impl std::fmt::Display for SendDeadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("download deadline exceeded")
    }
}

impl std::error::Error for SendDeadline {}

impl Body for PermitBody {
    type Data = Bytes;
    type Error = SendDeadline;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, SendDeadline>>> {
        let mut state = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        // The consumer may poll before the expired watchdog is scheduled (including a zero
        // deadline); never emit another frame while waiting for the timer task to catch up.
        if tokio::time::Instant::now() >= self.expires && state.pos < state.data.len() {
            state.expired = true;
            state.release();
        }
        if state.expired {
            return Poll::Ready(Some(Err(SendDeadline)));
        }
        if state.pos >= state.data.len() {
            state.release();
            self.watchdog.abort();
            return Poll::Ready(None);
        }
        let end = state.pos.saturating_add(FRAME_BYTES).min(state.data.len());
        let chunk = Bytes::copy_from_slice(state.data.get(state.pos..end).unwrap_or_default());
        state.pos = end;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        let state = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        !state.expired && state.pos >= state.data.len()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let state = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        http_body::SizeHint::with_exact(
            u64::try_from(self.len.saturating_sub(state.pos)).unwrap_or(0),
        )
    }
}

pub(crate) async fn download(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    method: Method,
    Path(id): Path<String>,
) -> Response {
    // Consistent with the other read routes: HEAD would read the whole blob to discard it.
    if method == Method::HEAD {
        let mut resp = fail(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED");
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET"));
        return resp;
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
    let Ok(permit) = Arc::clone(&st.downloads).try_acquire_owned() else {
        return crate::error::ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
            .retry_after(1)
            .into_response();
    };
    // The detached task owns the permit for the whole read, so a client disconnect cannot
    // release it while the I/O is still running; on success the permit moves into the body.
    let (store, sha) = (Arc::clone(&st.deps.store), row.sha256);
    let read = tokio::spawn(async move { store.get(&sha).await.map(|b| (b, permit)) });
    let (bytes, permit) = match read.await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            let class = match e {
                StoreError::NotFound => "missing",
                StoreError::Corrupt => "corrupt",
                _ => "io",
            };
            // Admin-visible and content-free: release id and error class only.
            tracing::error!(release_id = id, class, "stored NZB unavailable");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UNAVAILABLE");
        }
        Err(_) => return internal(),
    };

    let name = safe_filename(&row.title, id);
    let detail = format!("release={id}");
    audit(&st, &sess, ip, DOWNLOAD_EVENT, &detail).await;
    attachment(PermitBody::new(bytes, permit, SEND_DEADLINE), &name)
}

/// Best-effort audit row for a download: written before the bytes are sent; a failure is only
/// logged (the download itself is not refused).
pub(crate) async fn audit(st: &St, sess: &SessionCtx, ip: IpAddr, event: &str, detail: &str) {
    let actor = format!("user:{}", sess.user_id);
    if let Err(e) = st
        .deps
        .db
        .audit_event(
            st.deps.clock.now_secs(),
            Some(&actor),
            event,
            Some(detail),
            Some(&ip.to_string()),
        )
        .await
    {
        tracing::error!(error = %e, "audit write failed");
    }
}

/// The SEC-030 attachment response for `body` named `name` (an already sanitized file name).
/// The body owns its permits until it is finished or dropped and must be sent within its
/// deadline ([`SEND_DEADLINE`]).
fn attachment(body: PermitBody, name: &str) -> Response {
    let (Ok(cd), Ok(len)) = (
        HeaderValue::from_str(&content_disposition(name)),
        HeaderValue::from_str(&body.len.to_string()),
    ) else {
        return internal();
    };
    let mut resp = Response::new(axum::body::Body::new(body));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    h.insert(header::CONTENT_DISPOSITION, cd);
    h.insert(header::CONTENT_LENGTH, len);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Longest accepted `file` value (the parser ceiling is 20 000 files: five digits).
const MAX_INDEX_DIGITS: usize = 5;
/// Form fields tolerated besides the `file` fields (the CSRF token, a named button, slack).
const EXTRA_FORM_FIELDS: usize = 8;

/// Why a partial-download selection was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SelectionError {
    /// No `file` field at all (`NO_FILES_SELECTED`).
    Empty,
    /// A duplicate, non-numeric or out-of-range index, or more fields than files
    /// (`BAD_FILE_INDEX`).
    BadIndex,
}

/// Validates the `file` fields of a partial-download form body against a release of
/// `file_count` files and returns the indices in ascending (document) order. Other fields are
/// ignored; a body with more fields than `file_count` plus a few is refused, never truncated.
///
/// # Errors
/// [`SelectionError`] as described on its variants.
pub fn parse_selection(body: &[u8], file_count: u32) -> Result<Vec<u32>, SelectionError> {
    let files = usize::try_from(file_count).unwrap_or(usize::MAX);
    let Some(form) = crate::csrf::parse_form_strict(body, files.saturating_add(EXTRA_FORM_FIELDS))
    else {
        return Err(SelectionError::BadIndex);
    };
    let values: Vec<&str> = crate::csrf::form_all(&form, "file").collect();
    if values.is_empty() {
        return Err(SelectionError::Empty);
    }
    if values.len() > files {
        return Err(SelectionError::BadIndex);
    }
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if v.is_empty() || v.len() > MAX_INDEX_DIGITS || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SelectionError::BadIndex);
        }
        let idx: u32 = v.parse().map_err(|_| SelectionError::BadIndex)?;
        if idx >= file_count {
            return Err(SelectionError::BadIndex);
        }
        out.push(idx);
    }
    out.sort_unstable();
    let before = out.len();
    out.dedup();
    if out.len() != before {
        return Err(SelectionError::BadIndex);
    }
    Ok(out)
}

/// `POST /release/{id}/download/selected` (T125): see the module documentation.
pub(crate) async fn download_selected(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    enum Failure {
        Blob(&'static str),
        Parse(NzbError),
        TooLarge,
        Panic,
    }
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    // Unknown and hidden releases first: the uniform 404 never depends on the form.
    let row = match st.deps.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => r,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    };
    // CSRF (Origin + synchronizer token) was verified by the session gate, which restored the
    // body. The selection is checked before any blob is read.
    let selected = match parse_selection(&body, row.file_count) {
        Ok(s) => s,
        Err(SelectionError::Empty) => return fail(StatusCode::BAD_REQUEST, "NO_FILES_SELECTED"),
        Err(SelectionError::BadIndex) => return fail(StatusCode::BAD_REQUEST, "BAD_FILE_INDEX"),
    };
    // Its own one-permit pool first (review 43 M1), then a permit of the shared download pool.
    let busy = || {
        crate::error::ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
            .retry_after(1)
            .into_response()
    };
    let Ok(partial) = Arc::clone(&st.partials).try_acquire_owned() else {
        return busy();
    };
    let Ok(permit) = Arc::clone(&st.downloads).try_acquire_owned() else {
        return busy();
    };
    let mut limits = st.deps.limits;
    // The blocking parse must not outlive the response by much (same cap as the explorer).
    limits.parse_deadline = limits.parse_deadline.min(st.deps.max_parse);
    let count = selected.len();
    let (store, sha) = (Arc::clone(&st.deps.store), row.sha256);
    // As for the full download, the detached task owns the permit through the read AND the
    // parse, so a client disconnect cannot release it while work is still running; on success
    // the permit moves into the body.
    let task = tokio::spawn(async move {
        let bytes = store.get(&sha).await.map_err(|e| {
            Failure::Blob(match e {
                StoreError::NotFound => "missing",
                StoreError::Corrupt => "corrupt",
                _ => "io",
            })
        })?;
        let out = tokio::task::spawn_blocking(move || {
            let clock = SystemClock::new();
            let subset =
                extract_files(&bytes, &limits, &clock, &selected).map_err(Failure::Parse)?;
            // Peak memory (review 43 M1): the blob is not needed once parsed.
            drop(bytes);
            // Parsed values only, written by the escaping serializer: never input bytes. The cap
            // keeps the result within what our own parser accepts; the buffer is sized exactly.
            let cap = limits.clamped_to_ceilings().max_file_bytes;
            write_nzb(&subset, cap)
                .map(String::into_bytes)
                .map_err(|_| Failure::TooLarge)
        })
        .await
        .map_err(|_| Failure::Panic)??;
        Ok::<_, Failure>((out, permit, partial))
    });
    let (out, permit, partial) = match task.await {
        Ok(Ok(v)) => v,
        Ok(Err(Failure::Blob(class))) => {
            // Admin-visible and content-free: release id and error class only.
            tracing::error!(release_id = id, class, "stored NZB unavailable");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UNAVAILABLE");
        }
        Ok(Err(Failure::Parse(NzbError::Timeout))) => {
            return fail(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT");
        }
        Ok(Err(Failure::Parse(e))) => {
            tracing::error!(release_id = id, code = e.code(), "stored NZB unparseable");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "NZB_UNREADABLE");
        }
        Ok(Err(Failure::TooLarge)) => {
            tracing::warn!(release_id = id, "partial NZB over the size cap");
            return fail(StatusCode::PAYLOAD_TOO_LARGE, "PARTIAL_TOO_LARGE");
        }
        Ok(Err(Failure::Panic)) | Err(_) => return internal(),
    };
    let name = partial_filename(&row.title, id);
    let detail = format!("release={id} files={count}");
    audit(&st, &sess, ip, DOWNLOAD_SELECTED_EVENT, &detail).await;
    attachment(
        PermitBody::new(out, permit, SEND_DEADLINE).with_extra_permit(partial),
        &name,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn sec_030_filename_allowlist_table() {
        let long = "a".repeat(500);
        let cases: &[(&str, &str)] = &[
            ("Show.S01E02.1080p-GRP", "Show.S01E02.1080p-GRP.nzb"),
            ("My Movie (2020)", "My_Movie_2020.nzb"),
            ("x.nzb", "x.nzb"),
            ("x.NZB", "x.nzb"),
            ("a\r\nSet-Cookie: x=1", "a_Set-Cookie_x_1.nzb"),
            ("a\"; filename=\"evil.exe", "a_filename_evil.exe.nzb"),
            ("a;b\\c/d", "a_b_c_d.nzb"),
            ("../../etc/passwd", "etc_passwd.nzb"),
            ("..", "release-7.nzb"),
            (".hidden", "hidden.nzb"),
            ("a\0b", "a_b.nzb"),
            ("a\u{202e}fdp.exe", "a_fdp.exe.nzb"),
            ("", "release-7.nzb"),
            ("   ", "release-7.nzb"),
            ("\u{65e5}\u{672c}\u{8a9e}", "release-7.nzb"),
            ("---", "release-7.nzb"),
            ("caf\u{e9}", "caf.nzb"),
            ("a...b___c", "a.b_c.nzb"),
            ("a.nzb.", "a.nzb"),
            ("x.nzb.nzb", "x.nzb"),
            ("CON", "release-7-CON.nzb"),
            ("nul.x", "release-7-nul.x.nzb"),
            ("Com1", "release-7-Com1.nzb"),
            ("lpt9.txt", "release-7-lpt9.txt.nzb"),
            ("COM10", "COM10.nzb"),
            ("CONSOLE", "CONSOLE.nzb"),
            ("aux.nzb", "release-7-aux.nzb"),
        ];
        for (input, want) in cases {
            assert_eq!(&safe_filename(input, 7), want, "input {input:?}");
        }
        let n = safe_filename(&long, 7);
        assert_eq!(n.len(), MAX_STEM_CHARS + 4);
        assert!(n.ends_with(".nzb"));
        // Property: output is always plain allowlisted ASCII, never starts with '.', no "..".
        for input in cases.iter().map(|c| c.0).chain([long.as_str()]) {
            let n = safe_filename(input, 7);
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "{n}"
            );
            assert!(!n.starts_with('.') && !n.contains(".."), "{n}");
        }
    }

    #[test]
    fn sec_030_safe_filename_is_idempotent() {
        // Deterministic pseudo-random strings over an alphabet heavy in separators.
        let alphabet: Vec<char> = "ab.-_ nNzZbB/\\\"CONcomLPT19\u{e9}\0".chars().collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..3000 {
            let mut s = String::new();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = usize::try_from(x % 40).unwrap();
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let n = u64::try_from(alphabet.len()).unwrap();
                s.push(alphabet[usize::try_from(x % n).unwrap()]);
            }
            let once = safe_filename(&s, 7);
            assert_eq!(safe_filename(&once, 7), once, "input {s:?}");
        }
    }

    #[tokio::test]
    async fn sec_030_permit_body_releases_on_end_drop_and_deadline() {
        use http_body_util::BodyExt;
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(1));
        let take = || Arc::clone(&sem).try_acquire_owned().unwrap();
        // Finished body returns the permit and yields the exact bytes.
        let data = vec![7_u8; FRAME_BYTES * 2 + 5];
        let body = PermitBody::new(data.clone(), take(), Duration::from_secs(30));
        assert_eq!(sem.available_permits(), 0);
        let got = body.collect().await.unwrap().to_bytes();
        assert_eq!(got.as_ref(), data.as_slice());
        assert_eq!(sem.available_permits(), 1);
        // Dropped without polling.
        let body = PermitBody::new(data.clone(), take(), Duration::from_secs(30));
        assert_eq!(sem.available_permits(), 0);
        drop(body);
        assert_eq!(sem.available_permits(), 1);
        // Deadline: a reader that stalls after the first frame is cut off.
        let mut body = PermitBody::new(data, take(), Duration::from_millis(50));
        assert!(body.frame().await.unwrap().is_ok());
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn download_deadline_reclaims_permits_without_body_polling() {
        use http_body_util::BodyExt;
        use tokio::sync::Semaphore;

        let shared = Arc::new(Semaphore::new(1));
        let partial = Arc::new(Semaphore::new(1));
        let data = vec![7_u8; FRAME_BYTES * 3];
        let source_ptr = data.as_ptr();
        let mut body = PermitBody::new(
            data,
            Arc::clone(&shared).try_acquire_owned().unwrap(),
            Duration::from_millis(20),
        )
        .with_extra_permit(Arc::clone(&partial).try_acquire_owned().unwrap());
        // Keep the emitted frame alive, like hyper's socket buffer under backpressure.
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.len(), FRAME_BYTES);
        assert_ne!(first.as_ptr(), source_ptr, "frame retains the whole blob");
        // Do not poll the body again: the deadline must act independently of its consumer.
        let reclaimed = tokio::time::timeout(Duration::from_secs(2), shared.acquire()).await;
        assert!(
            reclaimed.is_ok(),
            "stalled body retained its download permit"
        );
        drop(reclaimed.unwrap().unwrap());
        assert_eq!(partial.available_permits(), 1);
        assert_eq!(body.buffer.lock().unwrap().data.capacity(), 0);
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(first.as_ref(), vec![7_u8; FRAME_BYTES].as_slice());
    }

    #[tokio::test]
    async fn download_zero_deadline_refuses_before_watchdog_is_scheduled() {
        use http_body_util::BodyExt;
        use tokio::sync::Semaphore;

        let sem = Arc::new(Semaphore::new(1));
        let mut body = PermitBody::new(
            vec![1; FRAME_BYTES],
            Arc::clone(&sem).try_acquire_owned().unwrap(),
            Duration::ZERO,
        );
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(sem.available_permits(), 1);
        assert_eq!(body.buffer.lock().unwrap().data.capacity(), 0);
        assert!(
            !body.is_end_stream(),
            "an expired stream must report its error"
        );
    }

    #[tokio::test]
    async fn download_completed_body_remains_finished_after_watchdog() {
        use http_body_util::BodyExt;
        use tokio::sync::Semaphore;

        let sem = Arc::new(Semaphore::new(1));
        let mut body = PermitBody::new(
            vec![1; 3],
            Arc::clone(&sem).try_acquire_owned().unwrap(),
            Duration::from_millis(20),
        );
        assert_eq!(body.size_hint().exact(), Some(3));
        assert!(body.frame().await.unwrap().is_ok());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        let reclaimed = tokio::time::timeout(Duration::from_secs(2), sem.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(reclaimed);
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
        assert_eq!(body.buffer.lock().unwrap().data.capacity(), 0);
    }

    #[test]
    fn sec_030_partial_filename_uses_the_same_allowlist() {
        assert_eq!(
            partial_filename("My Movie (2020)", 7),
            "My_Movie_2020-partial.nzb"
        );
        assert_eq!(partial_filename("x.nzb", 7), "x-partial.nzb");
        assert_eq!(partial_filename("", 7), "release-7-partial.nzb");
        assert_eq!(partial_filename("CON", 7), "release-7-CON-partial.nzb");
        let long = "a".repeat(500);
        for t in [
            "a\r\nSet-Cookie: x=1",
            "a\"; filename=\"evil.exe",
            "../../etc/passwd",
            "\u{202e}gpj.exe",
            long.as_str(),
        ] {
            let n = partial_filename(t, 7);
            assert!(n.ends_with("-partial.nzb"), "{n}");
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "{n}"
            );
            assert!(!n.starts_with('.') && !n.contains(".."), "{n}");
        }
    }

    #[test]
    fn sec_030_selection_parser_table() {
        let ok: &[(&str, &[u32])] = &[
            ("file=0", &[0]),
            ("csrf_token=x&file=2&file=0", &[0, 2]),
            ("file=00002&other=1", &[2]),
        ];
        for (body, want) in ok {
            assert_eq!(
                parse_selection(body.as_bytes(), 3).unwrap(),
                *want,
                "{body}"
            );
        }
        assert_eq!(parse_selection(b"", 3), Err(SelectionError::Empty));
        assert_eq!(
            parse_selection(b"csrf_token=x", 3),
            Err(SelectionError::Empty)
        );
        assert_eq!(parse_selection(b"file=0", 0), Err(SelectionError::BadIndex));
        for body in [
            "file=",
            "file=a",
            "file=-1",
            "file=+1",
            "file=3",
            "file=123456",
            "file=0&file=0",
            "file=0&file=1&file=2&file=2",
        ] {
            assert_eq!(
                parse_selection(body.as_bytes(), 3),
                Err(SelectionError::BadIndex),
                "{body}"
            );
        }
        // More fields than files plus slack: refused, never truncated.
        let many = ["x=1"; 3 + EXTRA_FORM_FIELDS + 1].join("&");
        assert_eq!(
            parse_selection(format!("file=0&{many}").as_bytes(), 3),
            Err(SelectionError::BadIndex)
        );
    }

    #[test]
    fn sec_030_content_disposition_shape() {
        assert_eq!(
            content_disposition("a.nzb"),
            "attachment; filename=\"a.nzb\"; filename*=UTF-8''a.nzb"
        );
        assert_eq!(pct_encode("a b\"\u{e9}"), "a%20b%22%C3%A9");
    }
}
