//! Upload pipeline integration (T051): `POST /api/v1/nzb` (API key) and `GET/POST /upload` (UI).
//!
//! # Data flow (SEC-035)
//! The request body is streamed chunk by chunk into a staging file in `paths.tmp`, named with
//! [`nzb_ingest::staging_name`] (never derived from any input), created `O_EXCL`, mode 0600. The
//! per-file cap (`max_file_bytes`) is enforced on the stream itself, before every write, so no
//! more than the cap is ever buffered or written; `Content-Length` is only an early hint. The
//! file is fsynced, then ownership passes to the ingest pipeline as `Payload::Staged`
//! (the same pipeline, limits, dedup and crash-safety as the watch folder). Until that hand-over a
//! drop guard removes the file, so a client that disconnects mid-upload leaves nothing behind;
//! if the whole process dies, startup recovery removes `nzbd-upload-*` leftovers.
//!
//! # Untrusted data
//! Part names, filenames and headers are display data only: sanitized, capped, never used as
//! paths. API responses carry only `{status, id, sha256}` (SEC-036); the UI results page shows
//! the sanitized file name through askama's auto-escaping.
//!
//! # NFO files (T140, D41)
//! An `.nfo` sent with the NZBs (UI: a `file` part whose name ends in `.nfo`, or an `nfo` part; API: one `nfo`
//! part) is read into memory, at most [`nzb_core::MAX_NFO_BYTES`], never staged and never charged as an NZB. Once the
//! NZBs of the request are processed each NFO pairs with the NZB of the same file stem (or with the only NZB of a
//! request holding exactly one of each) and is attached by the store, which re-checks who may attach (D41 b). The
//! bytes are display data only: never logged, never echoed, never in a header.
//!
//! # CSRF for the HTML form
//! A plain `<form>` cannot set headers, so the session gate defers the check to this module
//! ([`DeferredCsrf`]): the `csrf_token` part must arrive and match before the first file part is
//! read.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use askama::Template;
use axum::Router;
use axum::extract::multipart::{Field, Multipart};
use axum::extract::{DefaultBodyLimit, Extension, FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use http_body_util::BodyExt as _;
use nzb_core::{Taxonomy, sanitize_text};
use nzb_ingest::{IngestError, IngestHandle, IngestOutcome, Job, OutcomeKind, Payload};
use nzb_store::{
    AuditRepo as _, LibraryRepo as _, LogSource, NfoAttach, Store, StoreError, Uploader,
};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::apikey::ApiKeyCtx;
use crate::assets::Layout;
use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::index::{Choice, category_choices};
use crate::login::html;
use crate::ratelimit::{Clock, Decision, IpUploadBucket, SystemClock};
use crate::session::DeferredCsrf;
use crate::upload_guard::{
    DEFAULT_UPLOADS_PER_MIN, Meter, Metered, StorageGuard, UploadLimiter, chain_has_limit,
};

/// Most files accepted in one UI request (SEC-035).
pub const MAX_FILES_PER_REQUEST: usize = 20;
/// Most `.nfo` parts read in one UI request (T140); further ones are reported, not read into memory.
pub const MAX_NFO_PER_REQUEST: usize = 20;
/// Most multipart parts of any kind accepted in one UI request (files, `csrf_token`, `category`,
/// `source`, unknown parts): bounds CPU spent on part framing (`SECURITY_REVIEW` T051 L3).
pub const MAX_UI_PARTS: usize = 64;
/// Most multipart parts accepted by the API (`source`, `category`, `csrf_token`, one `file`).
pub const MAX_API_PARTS: usize = 8;
/// Uploads (API and UI together) processed at the same time; beyond it `503 BUSY` (T051 M1).
pub const DEFAULT_UPLOAD_CONCURRENCY: usize = 4;
/// Longest accepted `category` / `csrf_token` text part.
const MAX_TEXT_PART_BYTES: usize = 256;
/// Longest display name kept for a file.
const MAX_NAME_BYTES: usize = 255;
/// `Retry-After` for a full ingest queue or a busy upload slot.
const QUEUE_RETRY_SECS: u64 = 5;
/// `Retry-After` for a volume below its free-space floor.
const STORAGE_RETRY_SECS: u64 = 60;
/// Shown code of a file the request ran out of time for.
const NOT_PROCESSED: &str = "NOT_PROCESSED";

/// Everything the upload routes need.
#[derive(Clone)]
pub struct UploadDeps {
    /// Submit side of the ingest queue.
    pub ingest: IngestHandle,
    /// Category taxonomy (hint validation, form select).
    pub taxonomy: Arc<Taxonomy>,
    /// `paths.tmp`: where uploads are staged.
    pub staging_dir: PathBuf,
    /// Hard cap for one NZB.
    pub max_file_bytes: u64,
    /// Upper bound for the ingest reply wait of one file. The wait actually used is the smaller
    /// of this and what is left of [`UploadDeps::request_budget`] (`SECURITY_REVIEW` T051 L2).
    pub reply_timeout: Duration,
    /// Total time one upload request may take (the `upload_timeout` of the limits layer).
    pub request_budget: Duration,
    /// Time kept in reserve at the end of the budget to render the answer.
    pub deadline_margin: Duration,
    /// Per-API-key and per-session buckets (SEC-029).
    pub limiter: Arc<UploadLimiter>,
    /// Upload concurrency slots shared by API and UI (T051 M1).
    pub slots: Arc<Semaphore>,
    /// Free-space guard (T051 M2); `None` disables it (tests, `nzb-web` stand-alone).
    pub storage: Option<Arc<StorageGuard>>,
    /// Audit sink for `nzb_upload*` rows (T138) and the database the NFOs are attached in (T140); `None` writes
    /// no audit row and attaches no NFO (stand-alone tests).
    pub audit: Option<(Store, Arc<dyn WallClock>)>,
}

impl UploadDeps {
    /// Deps with the default limits: 30 uploads/min per key and per session, 4 concurrent
    /// uploads, reply wait capped at 25 s of a 60 s request budget, no storage guard.
    #[must_use]
    pub fn new(
        ingest: IngestHandle,
        taxonomy: Arc<Taxonomy>,
        staging_dir: PathBuf,
        max_file_bytes: u64,
    ) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        Self {
            ingest,
            taxonomy,
            staging_dir,
            max_file_bytes,
            reply_timeout: Duration::from_secs(25),
            request_budget: Duration::from_secs(60),
            deadline_margin: Duration::from_secs(5),
            limiter: Arc::new(UploadLimiter::new(
                DEFAULT_UPLOADS_PER_MIN,
                DEFAULT_UPLOADS_PER_MIN,
                &clock,
            )),
            slots: Arc::new(Semaphore::new(DEFAULT_UPLOAD_CONCURRENCY)),
            storage: None,
            audit: None,
        }
    }

    /// Enables the T138 upload audit trail (`nzb_upload`, `nzb_upload_dup`, `nzb_upload_reject`).
    #[must_use]
    pub fn with_audit(mut self, db: Store, clock: Arc<dyn WallClock>) -> Self {
        self.audit = Some((db, clock));
        self
    }

    /// Writes the audit row of one finished ingest job. Called only after the job's reply, i.e.
    /// after its transaction committed, so a crashed ingest leaves no false "uploaded" row.
    /// Best effort: a failed write is logged, never fails the upload. `detail` holds only
    /// server-generated values, the key id and the sanitized source label; never a secret.
    async fn audit_upload(
        &self,
        who: Who,
        result: &Result<IngestOutcome, (Rejected, &'static str)>,
        size: u64,
        key: Option<i64>,
        label: Option<&str>,
    ) {
        let Some((db, clock)) = self.audit.as_ref() else {
            return;
        };
        let via = if who.ui { "ui" } else { "api" };
        let key_part = key.map_or_else(String::new, |k| format!(" key={k}"));
        let label_part = label.map_or_else(String::new, |l| format!(" label={l}"));
        let (event, detail) = match result {
            Ok(o) => {
                let sha: String = o.sha256.to_hex().chars().take(12).collect();
                let event = match o.kind {
                    OutcomeKind::Ingested => "nzb_upload",
                    OutcomeKind::Duplicate => "nzb_upload_dup",
                };
                (
                    event,
                    format!(
                        "release={} sha12={sha} size={size} via={via}{key_part}{label_part}",
                        o.release_id
                    ),
                )
            }
            // UNAUTHORIZED: the account/key was refused inside the insert transaction, nothing to
            // attribute (the key gate audits its own refusals). TIMEOUT: the reply wait ran out;
            // the job may still commit, so the outcome is unknown and no row is claimed either
            // way (a late commit would otherwise contradict a reject).
            Err((_, "UNAUTHORIZED" | "TIMEOUT")) => return,
            // Stable reason code only: never the NZB's own strings.
            Err((_, code)) => (
                "nzb_upload_reject",
                format!("reason={code} size={size} via={via}{key_part}"),
            ),
        };
        let actor = match (who.user, key) {
            (Some(u), _) => format!("user:{u}"),
            (None, Some(k)) => format!("apikey:{k}"),
            (None, None) => return,
        };
        let ip = who.ip.map(|i| i.to_string());
        if let Err(e) = db
            .audit_event(
                clock.now_secs(),
                Some(&actor),
                event,
                Some(&detail),
                ip.as_deref(),
            )
            .await
        {
            tracing::error!(error = %e, "audit write failed");
        }
    }

    /// How long the ingest reply of the next file may be awaited at `deadline`.
    fn reply_wait(&self, deadline: Instant) -> Duration {
        deadline
            .saturating_duration_since(Instant::now())
            .saturating_sub(self.deadline_margin)
            .min(self.reply_timeout)
    }

    /// Takes an upload slot; the permit lives as long as the request future, so a cancelled or
    /// panicking handler releases it.
    fn slot(&self) -> Result<OwnedSemaphorePermit, Rejected> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| BUSY)
    }

    fn has_room(&self) -> bool {
        self.storage.as_ref().is_none_or(|g| g.has_room())
    }
}

/// `GET /upload` and `POST /upload` (merge into the session routes).
pub fn ui_routes(deps: UploadDeps) -> Router {
    Router::new()
        .route(
            "/upload",
            get(form_page)
                .post(ui_post)
                // The limits middleware enforces the real ceiling on the stream; axum's 2 MiB
                // default would otherwise cut every legitimate upload.
                .layer(DefaultBodyLimit::disable()),
        )
        .with_state(deps)
}

/// The `POST /api/v1/nzb` handler; wrap it with the API-key gate (`router_with_upload`).
pub fn api_route(deps: UploadDeps) -> MethodRouter {
    post(api_post)
        .layer(DefaultBodyLimit::disable())
        .with_state(deps)
}

// ---------------------------------------------------------------------------------------------
// Staging

/// Why staging failed.
#[derive(Debug)]
enum StageError {
    TooLarge,
    /// The request body ended in error (client abort, ceiling, malformed framing).
    Body {
        limit: bool,
    },
    Io,
}

/// A staging file under construction. Removed on drop unless [`Staging::release`]d.
struct Staging {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    written: u64,
    max: u64,
    armed: bool,
}

impl Staging {
    async fn create(dir: &Path, max: u64) -> Result<Self, StageError> {
        // `create_new` (O_EXCL) never follows a pre-planted symlink; the name is generated.
        for _ in 0..4 {
            let path = dir.join(nzb_ingest::staging_name());
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            match opts.open(&path).await {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        written: 0,
                        max,
                        armed: true,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    tracing::error!(error = %e.kind(), "cannot create upload staging file");
                    return Err(StageError::Io);
                }
            }
        }
        Err(StageError::Io)
    }

    /// Appends `chunk`, refusing before the write if it would exceed the cap.
    async fn push(&mut self, chunk: &[u8]) -> Result<(), StageError> {
        let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let total = self.written.saturating_add(len);
        if total > self.max {
            return Err(StageError::TooLarge);
        }
        let Some(file) = self.file.as_mut() else {
            return Err(StageError::Io);
        };
        file.write_all(chunk).await.map_err(|e| {
            tracing::error!(error = %e.kind(), "upload staging write failed");
            StageError::Io
        })?;
        self.written = total;
        Ok(())
    }

    /// Flushes and fsyncs. The file is still owned (and removed on drop) by `self`.
    async fn finish(&mut self) -> Result<(), StageError> {
        let Some(mut file) = self.file.take() else {
            return Err(StageError::Io);
        };
        let r = async {
            file.flush().await?;
            file.sync_all().await
        }
        .await;
        r.map_err(|e| {
            tracing::error!(error = %e.kind(), "upload staging fsync failed");
            StageError::Io
        })
    }

    /// Hands the path to the pipeline, which owns the file from now on.
    fn release(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.armed {
            // Client went away, cap exceeded, error: nothing half-written may stay visible.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Whether `e` (or anything in its source chain) is the body-size ceiling of the limits layer.
fn is_limit(e: &(dyn std::error::Error + 'static)) -> bool {
    chain_has_limit(e)
}

// ---------------------------------------------------------------------------------------------
// Outcomes

/// A refusal with the status and stable code to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rejected {
    status: StatusCode,
    code: &'static str,
    retry_after: Option<u64>,
}

impl Rejected {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after: None,
        }
    }

    fn response(self) -> Response {
        let mut e = ApiError::new(self.status, self.code);
        if let Some(s) = self.retry_after {
            e = e.retry_after(s);
        }
        e.into_response()
    }
}

const TOO_LARGE: Rejected = Rejected::new(StatusCode::PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE");
const BAD_REQUEST: Rejected = Rejected::new(StatusCode::BAD_REQUEST, "BAD_REQUEST");
const INTERNAL: Rejected = Rejected::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL");
const TIMEOUT: Rejected = Rejected::new(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT");
const INVALID_CATEGORY: Rejected = Rejected::new(StatusCode::BAD_REQUEST, "INVALID_CATEGORY");
const CSRF_REJECTED: Rejected = Rejected::new(StatusCode::FORBIDDEN, "CSRF_REJECTED");
const UNSUPPORTED: Rejected =
    Rejected::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");
/// The API key (or its owner) is no longer usable: the uniform 401 of the key gate.
const UNAUTHORIZED: Rejected = Rejected::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
/// The uploading account lost its role (or was disabled) while the form streamed: the uniform
/// 404 of a refused role, whatever was committed before it (SEC-060, L5).
const REFUSED_ACCOUNT: Rejected = Rejected::new(StatusCode::NOT_FOUND, "NOT_FOUND");
/// No upload slot (or a full ingest queue): `503 BUSY` + `Retry-After`.
const BUSY: Rejected = Rejected {
    status: StatusCode::SERVICE_UNAVAILABLE,
    code: "BUSY",
    retry_after: Some(QUEUE_RETRY_SECS),
};
/// A volume is below its free-space floor (T051 M2). 507 is the status that names exactly this
/// condition; the code is stable and the body uniform. Not in the `UI_SPEC` table before T052.
const INSUFFICIENT_STORAGE: Rejected = Rejected {
    status: StatusCode::INSUFFICIENT_STORAGE,
    code: "INSUFFICIENT_STORAGE",
    retry_after: Some(STORAGE_RETRY_SECS),
};

/// SEC-029 per-key / per-session limit: uniform `429 RATE_LIMITED` + `Retry-After`.
const fn rate_limited(retry_after_secs: u64) -> Rejected {
    Rejected {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "RATE_LIMITED",
        retry_after: Some(retry_after_secs),
    }
}

impl From<StageError> for Rejected {
    fn from(e: StageError) -> Self {
        match e {
            StageError::TooLarge | StageError::Body { limit: true } => TOO_LARGE,
            StageError::Body { limit: false } => BAD_REQUEST,
            StageError::Io => INTERNAL,
        }
    }
}

/// The `UI_SPEC` §Upload API response table for pipeline errors. The returned `shown` code is
/// the pipeline's own stable code (used by the results page); the HTTP code is the table's.
fn map_ingest(e: &IngestError) -> Rejected {
    match e {
        IngestError::FileTooLarge => TOO_LARGE,
        IngestError::Parse(p) => Rejected::new(StatusCode::UNPROCESSABLE_ENTITY, p.code()),
        IngestError::InvalidCategory => INVALID_CATEGORY,
        IngestError::QueueFull | IngestError::ShuttingDown => BUSY,
        // Only produced when the key or account was re-validated inside the insert transaction.
        IngestError::UploaderRefused => UNAUTHORIZED,
        // `Trashed` is `nzbd import` only (review 38 L1) and never produced for an upload.
        IngestError::SourceChanged
        | IngestError::SourceUnreadable
        | IngestError::Storage(_)
        | IngestError::Trashed
        | IngestError::Internal => INTERNAL,
    }
}

/// Account and client address behind an upload, for its audit row.
#[derive(Clone, Copy)]
struct Who {
    /// Session user (UI) or API key owner.
    user: Option<i64>,
    ip: Option<IpAddr>,
    ui: bool,
}

/// Who submitted a file: the log source, the API key id and the attribution the store
/// re-validates inside the insert transaction (N9).
#[derive(Clone, Copy)]
struct Origin {
    source: LogSource,
    key: Option<i64>,
    uploader: Uploader,
    who: Who,
}

/// Hands a finished staging file to the pipeline and waits for the reply.
async fn run_ingest(
    deps: &UploadDeps,
    deadline: Instant,
    staged: Staging,
    origin: Origin,
    name: Option<String>,
    hint: Option<String>,
    label: Option<String>,
) -> Result<IngestOutcome, (Rejected, &'static str)> {
    let Origin {
        source,
        key,
        uploader,
        who,
    } = origin;
    // Wait for the reply only for what is left of the request budget (T051 L2); without time
    // for even a short wait the file is not submitted (the drop guard removes it).
    let wait = deps.reply_wait(deadline);
    if wait.is_zero() {
        return Err((TIMEOUT, NOT_PROCESSED));
    }
    // From here the pipeline owns the file (removes it, or moves it to `failed/`). No await
    // sits between the release and the first poll of `submit`.
    let size = staged.written;
    let audit_label = label.clone();
    let job = Job::upload(source, Payload::Staged(staged.release()))
        .with_source_name(name)
        .with_hint(hint)
        .with_source_label(label)
        .with_api_key(key)
        .with_uploader(uploader);
    let result = match tokio::time::timeout(wait, deps.ingest.submit(job)).await {
        Ok(Ok(o)) => Ok(o),
        Ok(Err(e)) => {
            if matches!(e, IngestError::Storage(_) | IngestError::Internal) {
                tracing::error!(code = e.code(), "upload ingest failed");
            }
            Err((map_ingest(&e), e.code()))
        }
        Err(_) => {
            tracing::warn!("upload ingest reply timed out");
            Err((TIMEOUT, "TIMEOUT"))
        }
    };
    deps.audit_upload(who, &result, size, key, audit_label.as_deref())
        .await;
    result
}

/// Bucket key of an account's upload budget: a hash of the id with its own domain, so it can
/// never collide with the session-id hashes of the 1.x buckets.
fn account_key(user_id: i64) -> [u8; 32] {
    let mut msg = b"nzbd/upload-account/v1\0".to_vec();
    msg.extend_from_slice(&user_id.to_be_bytes());
    crate::crypto::sha256(&msg)
}

/// Bucket key of an account's API upload budget (all keys of one owner): its own hash domain, so
/// the API budget and the UI form's budget of the same account stay independent.
fn owner_api_bucket(user_id: i64) -> [u8; 32] {
    let mut msg = b"nzbd/upload-owner-api/v1\0".to_vec();
    msg.extend_from_slice(&user_id.to_be_bytes());
    crate::crypto::sha256(&msg)
}

fn clean_name(raw: &str) -> Option<String> {
    // Display only: keep the last path-looking component so a browser that sends a full path
    // shows the file name; never used to open anything.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let n = sanitize_text(base, MAX_NAME_BYTES);
    (!n.is_empty()).then_some(n)
}

/// Resolves a category hint through the taxonomy (empty / blank = no hint). The pipeline
/// resolves again; doing it here refuses an unknown value before any byte is staged. A category
/// hidden from the caller is as unknown as a typo (same rule as changing a release's category).
fn resolve_hint(tax: &Taxonomy, hidden: &[u16], raw: &str) -> Result<Option<String>, Rejected> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let id = tax.resolve(t).ok_or(INVALID_CATEGORY)?;
    if hidden.contains(&id) {
        return Err(INVALID_CATEGORY);
    }
    Ok(Some(id.to_string()))
}

/// Validates and sanitizes a free-text source label (`source` form part, `X-Source` header).
///
/// Raw input over [`MAX_TEXT_PART_BYTES`] is refused with the uniform `BAD_REQUEST` (like every
/// other oversized text part) before anything is staged; shorter input is run through
/// `sanitize_text` and cut to 64 bytes, and "nothing left" means no label. The value is never
/// echoed back in any response.
fn parse_label(raw: &[u8]) -> Result<Option<String>, Rejected> {
    if raw.len() > MAX_TEXT_PART_BYTES {
        return Err(BAD_REQUEST);
    }
    let t = std::str::from_utf8(raw).map_err(|_| BAD_REQUEST)?;
    Ok(nzb_store::clean_source_label(t))
}

fn base_mime(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
}

// ---------------------------------------------------------------------------------------------
// Multipart

/// What the multipart reader is serving.
enum Mode {
    Api {
        key: Option<i64>,
        owner: Option<i64>,
        ip: Option<IpAddr>,
        hint: Option<String>,
        label: Option<String>,
    },
    Ui {
        /// Token the `csrf_token` part must equal; `None` when the header already proved it.
        expect_csrf: Option<String>,
        /// Per-account bucket key (SEC-029, T101: sessions of one account share one budget).
        account_bucket: [u8; 32],
        /// The actual session hash, revalidated by the ingest transaction after reading the body.
        id_hash: [u8; 32],
        user_id: i64,
        client: Option<IpAddr>,
        /// Per-IP upload bucket; the rate-limit layer already spent the request's first token,
        /// so file 1 is covered and each further file spends one more (T083).
        ip: Option<IpUploadBucket>,
        /// Categories hidden from this caller (instance rule plus preference).
        hidden: Arc<[u16]>,
    },
}

/// One processed file part (or, with `nfo_only`, an NFO that did not pair with any NZB).
struct Item {
    name: Option<String>,
    result: Result<IngestOutcome, (Rejected, &'static str)>,
    /// What happened to the NFO paired with this NZB (T140).
    nfo: Option<NfoResult>,
    /// A row of its own for an NFO without an NZB; `result` is unused then.
    nfo_only: bool,
}

impl Item {
    const fn file(
        name: Option<String>,
        result: Result<IngestOutcome, (Rejected, &'static str)>,
    ) -> Self {
        Self {
            name,
            result,
            nfo: None,
            nfo_only: false,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// NFO (T140)

/// An `.nfo` part, held in memory until the NZBs of the request are processed.
struct NfoPart {
    name: Option<String>,
    /// The bytes, or the stable code of why they were not kept.
    bytes: Result<Vec<u8>, &'static str>,
}

/// What happened to one NFO: shown on the results page and, as a code, in the API answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NfoResult {
    Attached,
    /// The release already has an NFO; it was kept.
    Present,
    /// Not attached, with a stable code.
    Refused(&'static str),
}

impl NfoResult {
    const fn code(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Present => "present",
            Self::Refused(c) => c,
        }
    }

    const fn class(self) -> &'static str {
        match self {
            Self::Attached => "ok",
            Self::Present => "info",
            Self::Refused(_) => "bad",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::Attached => "NFO attached.",
            Self::Present => "The release already has an NFO; it was kept.",
            Self::Refused("NFO_TOO_LARGE") => "NFO not attached: larger than 256 KiB.",
            Self::Refused("NFO_EMPTY") => "NFO not attached: the file is empty.",
            Self::Refused("NFO_TOO_MANY") => "NFO not attached: too many NFO files in one upload.",
            Self::Refused("NFO_UNPAIRED") => {
                "NFO not attached: no NZB with the same name in this upload."
            }
            Self::Refused("NFO_EXTRA") => {
                "NFO not attached: another NFO already pairs with this NZB."
            }
            Self::Refused("NFO_NZB_REJECTED") => "NFO not attached: its NZB was not stored.",
            Self::Refused("NFO_FORBIDDEN") => {
                "NFO not attached: only the uploader of the release or an admin can add one."
            }
            Self::Refused(_) => "NFO not attached: an internal error occurred.",
        }
    }
}

/// Whether a submitted file name is an NFO (`*.nfo`, any case).
fn is_nfo_name(name: &str) -> bool {
    name.len() > 4
        && name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(".nfo"))
}

/// The pairing key of a file name: everything before the last `.`, ASCII-lower-cased.
fn stem_key(name: &str) -> String {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    stem.to_ascii_lowercase()
}

/// Where each NFO goes: `Ok(i)` = the NZB at index `i`, `Err(code)` = not paired. With exactly one NZB and one NFO
/// they pair whatever their names; otherwise by stem, the first NFO of a stem winning.
fn pair_nfos(nzbs: &[Option<&str>], nfos: &[Option<&str>]) -> Vec<Result<usize, &'static str>> {
    if nzbs.len() == 1 && nfos.len() == 1 {
        return vec![Ok(0)];
    }
    let keys: Vec<Option<String>> = nzbs.iter().map(|n| n.map(stem_key)).collect();
    let mut taken = vec![false; nzbs.len()];
    nfos.iter()
        .map(|nfo| {
            let Some(want) = nfo.map(stem_key) else {
                return Err("NFO_UNPAIRED");
            };
            let Some(i) = keys
                .iter()
                .position(|k| k.as_deref() == Some(want.as_str()))
            else {
                return Err("NFO_UNPAIRED");
            };
            match taken.get_mut(i) {
                Some(t) if !*t => {
                    *t = true;
                    Ok(i)
                }
                _ => Err("NFO_EXTRA"),
            }
        })
        .collect()
}

/// Reads an NFO part into memory (at most [`nzb_core::MAX_NFO_BYTES`]; a larger one is drained and refused).
async fn read_nfo(field: &mut Field<'_>, meter: &Meter, keep: bool) -> Result<NfoPart, Rejected> {
    let name = field.file_name().and_then(clean_name);
    let mut buf: Vec<u8> = Vec::new();
    let mut code: Option<&'static str> = (!keep).then_some("NFO_TOO_MANY");
    loop {
        match field.chunk().await {
            Ok(Some(c)) => {
                meter.consumed(c.len());
                if code.is_some() {
                    continue;
                }
                if buf.len().saturating_add(c.len()) > nzb_core::MAX_NFO_BYTES {
                    code = Some("NFO_TOO_LARGE");
                    buf = Vec::new();
                } else {
                    buf.extend_from_slice(&c);
                }
            }
            Ok(None) => break,
            Err(e) => return Err(mp_err(&e, meter)),
        }
    }
    let bytes = match code {
        Some(c) => Err(c),
        None if buf.is_empty() => Err("NFO_EMPTY"),
        None => Ok(buf),
    };
    Ok(NfoPart { name, bytes })
}

/// Attaches one NFO to the release its NZB produced; the store decides who may (D41 b).
async fn attach_nfo(
    deps: &UploadDeps,
    uploader: &Uploader,
    who: Who,
    o: &IngestOutcome,
    bytes: &[u8],
) -> NfoResult {
    let Some((db, clock)) = deps.audit.as_ref() else {
        return NfoResult::Refused("NFO_INTERNAL");
    };
    let ip = who.ip.map(|i| i.to_string());
    match db
        .attach_nfo_as(
            uploader,
            o.release_id,
            &o.sha256,
            bytes,
            clock.now_secs(),
            ip.as_deref(),
        )
        .await
    {
        Ok(NfoAttach::Attached) => NfoResult::Attached,
        Ok(NfoAttach::AlreadyPresent) => NfoResult::Present,
        Err(StoreError::Account(_)) => NfoResult::Refused("NFO_FORBIDDEN"),
        // The release went away (deleted) between its commit and this attach.
        Err(StoreError::NotFound) => NfoResult::Refused("NFO_NZB_REJECTED"),
        Err(e) => {
            tracing::error!(error = %e, "nfo attach failed");
            NfoResult::Refused("NFO_INTERNAL")
        }
    }
}

/// Pairs the held NFOs with the processed NZBs and attaches them. Unpaired NFOs become rows of their own when
/// `orphan_rows` (the UI); the API reports only the NFO of its single file.
async fn settle_nfos(
    deps: &UploadDeps,
    who: Option<(Uploader, Who)>,
    items: &mut Vec<Item>,
    nfos: Vec<NfoPart>,
    orphan_rows: bool,
) {
    if nfos.is_empty() {
        return;
    }
    let pairs = {
        let nzb_names: Vec<Option<&str>> = items.iter().map(|i| i.name.as_deref()).collect();
        let nfo_names: Vec<Option<&str>> = nfos.iter().map(|n| n.name.as_deref()).collect();
        pair_nfos(&nzb_names, &nfo_names)
    };
    let mut orphans = Vec::new();
    for (nfo, pair) in nfos.into_iter().zip(pairs) {
        let target = pair.ok().and_then(|i| items.get(i).map(|item| (i, item)));
        let result = match (&nfo.bytes, target, who.as_ref()) {
            (_, None, _) => {
                orphans.push((
                    nfo.name,
                    NfoResult::Refused(pair.err().unwrap_or("NFO_UNPAIRED")),
                ));
                continue;
            }
            (Err(code), Some(_), _) => NfoResult::Refused(code),
            (Ok(_), Some((_, item)), _) if item.result.is_err() => {
                NfoResult::Refused("NFO_NZB_REJECTED")
            }
            (Ok(bytes), Some((_, item)), Some((uploader, w))) => match &item.result {
                Ok(o) => attach_nfo(deps, uploader, *w, o, bytes).await,
                Err(_) => NfoResult::Refused("NFO_NZB_REJECTED"),
            },
            (Ok(_), Some(_), None) => NfoResult::Refused("NFO_INTERNAL"),
        };
        if let Some((i, _)) = target
            && let Some(item) = items.get_mut(i)
        {
            item.nfo = Some(result);
        }
    }
    if orphan_rows {
        for (name, r) in orphans {
            items.push(Item {
                name,
                result: Err((BAD_REQUEST, r.code())),
                nfo: Some(r),
                nfo_only: true,
            });
        }
    }
}

async fn read_small(field: &mut Field<'_>, meter: &Meter) -> Result<String, Rejected> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match field.chunk().await {
            Ok(Some(c)) => {
                meter.consumed(c.len());
                if buf.len().saturating_add(c.len()) > MAX_TEXT_PART_BYTES {
                    return Err(BAD_REQUEST);
                }
                buf.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(e) => return Err(mp_err(&e, meter)),
        }
    }
    String::from_utf8(buf).map_err(|_| BAD_REQUEST)
}

fn mp_err(e: &axum::extract::multipart::MultipartError, meter: &Meter) -> Rejected {
    if meter.limit_hit() || is_limit(e) {
        TOO_LARGE
    } else {
        BAD_REQUEST
    }
}

async fn stage_field(
    deps: &UploadDeps,
    meter: &Meter,
    field: &mut Field<'_>,
) -> Result<Staging, Rejected> {
    let mut st = Staging::create(&deps.staging_dir, deps.max_file_bytes).await?;
    loop {
        match field.chunk().await {
            Ok(Some(c)) => {
                st.push(&c).await?;
                meter.consumed(c.len());
            }
            Ok(None) => break,
            Err(e) => return Err(mp_err(&e, meter)),
        }
    }
    st.finish().await?;
    Ok(st)
}

/// Opens the multipart parser behind the framing meter (T051 M1).
async fn open_multipart(req: Request) -> Result<(Multipart, Arc<Meter>), Rejected> {
    let meter = Arc::new(Meter::default());
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(
        parts,
        axum::body::Body::new(Metered::new(body, Arc::clone(&meter))),
    );
    let mp = Multipart::from_request(req, &())
        .await
        .map_err(|_| BAD_REQUEST)?;
    Ok((mp, meter))
}

/// Ends a UI request that cannot continue: with results already collected the problem becomes
/// the final row of the page (nothing processed is discarded, `SECURITY_REVIEW` T051 L1); with
/// none, the whole request fails with the error's own status.
fn stop_here(
    ui: bool,
    items: &mut Vec<Item>,
    name: Option<String>,
    r: Rejected,
    shown: &'static str,
) -> Result<(), Rejected> {
    if ui && !items.is_empty() {
        items.push(Item::file(name, Err((r, shown))));
        Ok(())
    } else {
        Err(r)
    }
}

/// Per-file accounting of a UI request (UI only; the API spent its key token before parsing).
struct Charges {
    session: [u8; 32],
    ip: Option<IpUploadBucket>,
    /// The rate-limit layer's per-request IP token pays for the first charged file.
    ip_first_free: bool,
}

/// Spends one token of the per-IP bucket (from the second file on) and one of the session
/// bucket for the file being read.
fn charge(deps: &UploadDeps, charges: &mut Charges) -> Option<Rejected> {
    if std::mem::take(&mut charges.ip_first_free) {
        // Covered by the request-level token.
    } else if let Some(Decision::Deny { retry_after_secs }) =
        charges.ip.as_ref().map(IpUploadBucket::charge)
    {
        return Some(rate_limited(retry_after_secs));
    }
    match deps.limiter.check_session(charges.session) {
        Decision::Deny { retry_after_secs } => Some(rate_limited(retry_after_secs)),
        Decision::Allow => None,
    }
}

/// Reads the whole multipart body. Parts must come in the order `csrf_token`, `category`,
/// `file`...; the CSRF token is checked before the first file part is read.
async fn read_multipart(
    deps: &UploadDeps,
    mp: Multipart,
    meter: &Meter,
    mode: Mode,
    deadline: Instant,
) -> Result<Vec<Item>, Rejected> {
    let ui = matches!(mode, Mode::Ui { .. });
    let mut out = Collected::default();
    let r = read_parts(deps, mp, meter, mode, deadline, &mut out).await;
    let Collected {
        mut items,
        nfos,
        who,
    } = out;
    match r {
        Ok(()) => {
            settle_nfos(deps, who, &mut items, nfos, ui).await;
            Ok(items)
        }
        // A late framing error (bad boundary, part cap, ceiling) after finished files. A refused
        // account is never folded into a results page.
        Err(r) if ui && !items.is_empty() && r != REFUSED_ACCOUNT => {
            settle_nfos(deps, who, &mut items, nfos, ui).await;
            items.push(Item::file(Some("(request)".to_owned()), Err((r, r.code))));
            Ok(items)
        }
        Err(r) => Err(r),
    }
}

/// What [`read_parts`] collected, also when it stopped early.
#[derive(Default)]
struct Collected {
    items: Vec<Item>,
    /// NFO parts, attached once the NZBs are processed (T140).
    nfos: Vec<NfoPart>,
    /// Who the NFOs are attached as (the request's uploader).
    who: Option<(Uploader, Who)>,
}

#[allow(clippy::too_many_lines)]
async fn read_parts(
    deps: &UploadDeps,
    mut mp: Multipart,
    meter: &Meter,
    mode: Mode,
    deadline: Instant,
    out: &mut Collected,
) -> Result<(), Rejected> {
    let Collected { items, nfos, who } = out;
    // Hiding categories is a UI display rule; API ingestion still accepts every taxonomy id.
    let mut hidden: Arc<[u16]> = Arc::from(Vec::new());
    let (api, mut hint, mut label, mut csrf_pending, mut charges, ui_actor, audit_user, audit_ip) =
        match mode {
            Mode::Api {
                key,
                owner,
                ip,
                hint,
                label,
            } => (Some(key), hint, label, None, None, None, owner, ip),
            Mode::Ui {
                expect_csrf,
                account_bucket,
                id_hash,
                user_id,
                client,
                ip,
                hidden: h,
            } => {
                hidden = h;
                (
                    None,
                    None,
                    None,
                    expect_csrf,
                    Some(Charges {
                        session: account_bucket,
                        ip,
                        ip_first_free: true,
                    }),
                    Some((user_id, id_hash)),
                    Some(user_id),
                    client,
                )
            }
        };
    let ui = api.is_none();
    let source = if ui {
        LogSource::UploadUi
    } else {
        LogSource::UploadApi
    };
    let max_parts = if ui { MAX_UI_PARTS } else { MAX_API_PARTS };
    let origin = Origin {
        source,
        key: api.flatten(),
        uploader: match (api.flatten(), ui_actor) {
            (Some(k), _) => Uploader::ApiKey(k),
            (None, Some((user_id, id_hash))) => Uploader::Session { user_id, id_hash },
            (None, None) => Uploader::Unattributed,
        },
        who: Who {
            user: audit_user,
            ip: audit_ip,
            ui,
        },
    };
    *who = Some((origin.uploader, origin.who));
    let mut files_seen = 0_usize;
    let mut parts_seen = 0_usize;
    // API: the single file is staged first and ingested only when the whole body parsed, so a
    // second `file` part (or any later framing error) is refused before anything is ingested
    // (T051 L1).
    let mut pending: Option<(Staging, Option<String>)> = None;
    loop {
        let mut field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Err(mp_err(&e, meter)),
        };
        parts_seen = parts_seen.saturating_add(1);
        if parts_seen > max_parts {
            return Err(BAD_REQUEST);
        }
        meter.part();
        let part = field.name().unwrap_or_default().to_owned();
        match part.as_str() {
            "csrf_token" => {
                let text = read_small(&mut field, meter).await?;
                if let Some(expected) = csrf_pending.as_deref() {
                    if !csrf::token_matches(expected, &text) {
                        return Err(CSRF_REJECTED);
                    }
                    csrf_pending = None;
                }
            }
            "category" => {
                if files_seen > 0 {
                    return Err(BAD_REQUEST);
                }
                let text = read_small(&mut field, meter).await?;
                // A form field overrides nothing: an `X-Category` header is the API alternative.
                hint = resolve_hint(&deps.taxonomy, &hidden, &text)?;
            }
            "source" => {
                // Like `category`: must precede the files; applies to every file of the request.
                if files_seen > 0 {
                    return Err(BAD_REQUEST);
                }
                let text = read_small(&mut field, meter).await?;
                label = parse_label(text.as_bytes())?;
            }
            "nfo" => {
                if csrf_pending.is_some() {
                    return Err(CSRF_REJECTED);
                }
                // The API takes one NFO for its one file.
                if !ui && !nfos.is_empty() {
                    return Err(UNSUPPORTED);
                }
                let keep = nfos.len() < MAX_NFO_PER_REQUEST;
                let part = read_nfo(&mut field, meter, keep).await?;
                // The empty `nfo` input of a form without a selection.
                if part.name.is_none() && part.bytes == Err("NFO_EMPTY") {
                    continue;
                }
                nfos.push(part);
            }
            "file" => {
                if csrf_pending.is_some() {
                    return Err(CSRF_REJECTED);
                }
                // An `.nfo` chosen in the form's file input with its NZB (T140): held, not ingested.
                if ui
                    && field
                        .file_name()
                        .and_then(clean_name)
                        .is_some_and(|n| is_nfo_name(&n))
                {
                    let keep = nfos.len() < MAX_NFO_PER_REQUEST;
                    nfos.push(read_nfo(&mut field, meter, keep).await?);
                    continue;
                }
                if files_seen >= MAX_FILES_PER_REQUEST || (!ui && files_seen >= 1) {
                    return Err(if ui { BAD_REQUEST } else { UNSUPPORTED });
                }
                files_seen = files_seen.saturating_add(1);
                let name = field.file_name().and_then(clean_name);
                if ui {
                    // Out of time for another file: stop and report it as not processed.
                    if deps.reply_wait(deadline).is_zero() {
                        return stop_here(ui, items, name, TIMEOUT, NOT_PROCESSED);
                    }
                    if !deps.has_room() {
                        return stop_here(
                            ui,
                            items,
                            name,
                            INSUFFICIENT_STORAGE,
                            INSUFFICIENT_STORAGE.code,
                        );
                    }
                    // SEC-029: every UI file part spends one token of the session and one of
                    // the client address. A part without a file name may be the empty file
                    // input of a form without a selection (skipped below); it is charged once
                    // its size is known.
                    if name.is_some()
                        && let Some(c) = charges.as_mut()
                        && let Some(r) = charge(deps, c)
                    {
                        return stop_here(ui, items, name, r, r.code);
                    }
                }
                let staged = match stage_field(deps, meter, &mut field).await {
                    Ok(s) => s,
                    Err(r) => return stop_here(ui, items, name, r, r.code),
                };
                if ui {
                    // An empty file input (no file chosen) is submitted as an empty part with no
                    // file name: skip it quietly.
                    if staged.written == 0 && name.is_none() {
                        continue;
                    }
                    if name.is_none()
                        && let Some(c) = charges.as_mut()
                        && let Some(r) = charge(deps, c)
                    {
                        return stop_here(ui, items, name, r, r.code);
                    }
                    let result = run_ingest(
                        deps,
                        deadline,
                        staged,
                        origin,
                        name.clone(),
                        hint.clone(),
                        label.clone(),
                    )
                    .await;
                    // The store re-validated the account inside the insert transaction (the role
                    // is re-read before EVERY file part is committed): a refusal drops the
                    // remaining parts unread and the answer is the uniform 404.
                    if matches!(&result, Err((_, code)) if *code == "UNAUTHORIZED") {
                        return Err(REFUSED_ACCOUNT);
                    }
                    items.push(Item::file(name, result));
                } else {
                    pending = Some((staged, name));
                }
            }
            _ => return Err(if ui { BAD_REQUEST } else { UNSUPPORTED }),
        }
    }
    if csrf_pending.is_some() {
        return Err(CSRF_REJECTED);
    }
    if let Some((staged, name)) = pending {
        let result = run_ingest(deps, deadline, staged, origin, name.clone(), hint, label).await;
        items.push(Item::file(name, result));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// API

fn json(status: StatusCode, body: String) -> Response {
    let mut r = Response::new(axum::body::Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// `{status,id,sha256}` and, when the request carried an NFO, its stable `nfo` code (SEC-036 as amended by T140).
/// All values are server-generated.
fn outcome_json(o: &IngestOutcome, nfo: Option<NfoResult>) -> Response {
    let (status, label) = match o.kind {
        OutcomeKind::Ingested => (StatusCode::CREATED, "created"),
        OutcomeKind::Duplicate => (StatusCode::OK, "duplicate"),
    };
    json(
        status,
        format!(
            "{{\"status\":\"{label}\",\"id\":{},\"sha256\":\"{}\"{}}}",
            o.release_id,
            o.sha256.to_hex(),
            nfo.map_or_else(String::new, |n| format!(",\"nfo\":\"{}\"", n.code()))
        ),
    )
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
}

async fn api_post(State(deps): State<UploadDeps>, req: Request) -> Response {
    // Only reachable behind the API-key gate; without its context nothing is processed.
    let Some(ctx) = req.extensions().get::<ApiKeyCtx>().copied() else {
        return ApiError::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED").into_response();
    };
    let key = ctx.id;
    // SEC-029: the per-key token is spent after authentication and before any body byte is read.
    // A request the key's owner makes counts here even if it fails later; unauthenticated
    // requests never get this far (they only count in the per-IP bucket). The key's own stored
    // budget can only lower the instance budget (T103).
    if let Decision::Deny { retry_after_secs } = deps.limiter.check_key(key, ctx.rate_per_min) {
        return rate_limited(retry_after_secs).response();
    }
    // T103: one account budget for ALL keys of the owner (separate from the UI form's bucket), so
    // ten keys of one account do not multiply it.
    if let Some(owner) = ctx.owner_id
        && let Decision::Deny { retry_after_secs } =
            deps.limiter.check_session(owner_api_bucket(owner))
    {
        return rate_limited(retry_after_secs).response();
    }
    // Held until the response is complete, also when the future is cancelled or panics.
    let _slot = match deps.slot() {
        Ok(p) => p,
        Err(r) => return r.response(),
    };
    if !deps.has_room() {
        return INSUFFICIENT_STORAGE.response();
    }
    let deadline = Instant::now() + deps.request_budget;
    let ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    match api_inner(&deps, Some(key), (ctx.owner_id, ip), deadline, req).await {
        Ok(r) => r,
        Err(r) => r.response(),
    }
}

async fn api_inner(
    deps: &UploadDeps,
    key: Option<i64>,
    (owner, ip): (Option<i64>, Option<IpAddr>),
    deadline: Instant,
    req: Request,
) -> Result<Response, Rejected> {
    let reject = |r: Rejected| r;
    // Hint first: an unknown category is refused before a byte is staged.
    let hint = match req.headers().get("x-category") {
        None => None,
        Some(v) => match v.to_str() {
            Ok(t) => resolve_hint(&deps.taxonomy, &[], t).map_err(reject)?,
            Err(_) => return Err(reject(INVALID_CATEGORY)),
        },
    };
    let label = match req.headers().get("x-source") {
        None => None,
        Some(v) => parse_label(v.as_bytes()).map_err(reject)?,
    };
    let mime = base_mime(req.headers());
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    match mime.as_deref() {
        Some("multipart/form-data") => {
            let (mp, meter) = open_multipart(req).await?;
            let mut items = read_multipart(
                deps,
                mp,
                &meter,
                Mode::Api {
                    key,
                    owner,
                    ip,
                    hint,
                    label,
                },
                deadline,
            )
            .await
            .map_err(reject)?;
            match (items.pop(), items.is_empty()) {
                (Some(item), true) => match item.result {
                    Ok(o) => Ok(outcome_json(&o, item.nfo)),
                    Err((r, _)) => Err(reject(r)),
                },
                // No `file` part at all.
                _ => Err(reject(BAD_REQUEST)),
            }
        }
        None
        | Some("application/x-nzb" | "application/xml" | "text/xml" | "application/octet-stream") =>
        {
            if declared.is_some_and(|n| n > deps.max_file_bytes) {
                return Err(reject(TOO_LARGE));
            }
            let name = header_text(req.headers(), "x-source-name")
                .or_else(|| header_text(req.headers(), "x-filename"))
                .as_deref()
                .and_then(clean_name);
            let mut staged = Staging::create(&deps.staging_dir, deps.max_file_bytes)
                .await
                .map_err(|e| reject(e.into()))?;
            let mut body = req.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| {
                    reject(
                        StageError::Body {
                            limit: is_limit(&e),
                        }
                        .into(),
                    )
                })?;
                if let Ok(data) = frame.into_data() {
                    staged.push(&data).await.map_err(|e| reject(e.into()))?;
                }
            }
            staged.finish().await.map_err(|e| reject(e.into()))?;
            let origin = Origin {
                source: LogSource::UploadApi,
                key,
                uploader: key.map_or(Uploader::Unattributed, Uploader::ApiKey),
                who: Who {
                    user: owner,
                    ip,
                    ui: false,
                },
            };
            match run_ingest(deps, deadline, staged, origin, name, hint, label).await {
                Ok(o) => Ok(outcome_json(&o, None)),
                Err((r, _)) => Err(reject(r)),
            }
        }
        Some(_) => Err(reject(UNSUPPORTED)),
    }
}

// ---------------------------------------------------------------------------------------------
// UI

#[derive(Template)]
#[template(path = "upload.html")]
struct FormPage {
    layout: Layout,
    csrf_token: String,
    categories: Vec<Choice>,
    max_files: usize,
    max_mib: u64,
}

struct ResultRow {
    name: String,
    status: &'static str,
    /// Closed-set badge class: `ok`, `info` or `bad`.
    status_class: &'static str,
    release_id: Option<i64>,
    code: &'static str,
    reason: &'static str,
    /// The NFO note of the row (T140); empty when the row had none.
    nfo: &'static str,
    /// Closed-set badge class of the NFO note: `ok`, `info` or `bad`.
    nfo_class: &'static str,
}

#[derive(Template)]
#[template(path = "upload_result.html")]
struct ResultPage {
    layout: Layout,
    rows: Vec<ResultRow>,
}

async fn form_page(
    State(deps): State<UploadDeps>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    let page = FormPage {
        layout: Layout::for_session("Upload", &sess),
        csrf_token: sess.csrf_token,
        categories: category_choices(&deps.taxonomy, None, &sess.hidden_categories),
        max_files: MAX_FILES_PER_REQUEST,
        max_mib: deps.max_file_bytes / (1024 * 1024),
    };
    match page.render() {
        Ok(body) => html(StatusCode::OK, body),
        Err(e) => {
            tracing::error!(error = %e, "upload form render failed");
            INTERNAL.response()
        }
    }
}

/// Short neutral text for a stable code (never request-derived).
fn reason_for(code: &str) -> &'static str {
    match code {
        "FILE_TOO_LARGE" => "The file is larger than the allowed size.",
        "INVALID_CATEGORY" => "The category does not exist.",
        "TIMEOUT" => "Processing took too long; check the index before retrying.",
        "BUSY" => "The server is busy. Try again shortly.",
        "RATE_LIMITED" => {
            "Upload rate limit reached. This file and any after it were not processed; try again in a minute."
        }
        NOT_PROCESSED => {
            "The request ran out of time. This file and any after it were not processed; upload them again."
        }
        "INSUFFICIENT_STORAGE" => {
            "The server is low on disk space. This file and any after it were not processed."
        }
        "INTERNAL" | "STORAGE_ERROR" | "SOURCE_CHANGED" | "SOURCE_UNREADABLE" => {
            "An internal error occurred."
        }
        c if c.starts_with("NZB_") => "The file is not an acceptable NZB.",
        _ => "The file was rejected.",
    }
}

fn row(item: Item, sess: &SessionCtx) -> ResultRow {
    let name = item.name.unwrap_or_else(|| "(unnamed)".to_owned());
    let (nfo, nfo_class) = item.nfo.map_or(("", ""), |n| (n.text(), n.class()));
    if item.nfo_only {
        return ResultRow {
            name,
            status: "NFO not attached",
            status_class: "bad",
            release_id: None,
            code: item.nfo.map_or("", NfoResult::code),
            reason: nfo,
            nfo: "",
            nfo_class: "",
        };
    }
    match item.result {
        Ok(o) => ResultRow {
            name,
            status: match o.kind {
                OutcomeKind::Ingested => "Created",
                OutcomeKind::Duplicate => "Duplicate",
            },
            status_class: match o.kind {
                OutcomeKind::Ingested => "ok",
                OutcomeKind::Duplicate => "info",
            },
            // A release in a hidden category (`ui.show_xxx = false`) is stored but neither linked
            // nor named here; the link would be a 404 anyway.
            release_id: (!sess.hides_category(o.category_id)).then_some(o.release_id),
            code: "",
            reason: if sess.hides_category(o.category_id) {
                "Stored. This release is not displayed in the UI."
            } else {
                ""
            },
            nfo,
            nfo_class,
        },
        Err((r, shown)) => {
            // Stop rows have their own code and wording; everything else maps the HTTP-level code.
            let stop = matches!(
                shown,
                "RATE_LIMITED" | NOT_PROCESSED | "INSUFFICIENT_STORAGE"
            );
            ResultRow {
                name,
                status: match shown {
                    "RATE_LIMITED" => "Rate limited",
                    NOT_PROCESSED => "Not processed",
                    _ => "Rejected",
                },
                status_class: "bad",
                release_id: None,
                code: shown,
                reason: reason_for(if stop { shown } else { r.code }),
                nfo,
                nfo_class,
            }
        }
    }
}

async fn ui_post(
    State(deps): State<UploadDeps>,
    Extension(sess): Extension<SessionCtx>,
    req: Request,
) -> Response {
    let expect_csrf = req
        .extensions()
        .get::<DeferredCsrf>()
        .map(|d| d.expected.clone());
    let ip = req.extensions().get::<IpUploadBucket>().cloned();
    let client_ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    if base_mime(req.headers()).as_deref() != Some("multipart/form-data") {
        return UNSUPPORTED.response();
    }
    // Held until the response is complete, also when the future is cancelled or panics.
    let _slot = match deps.slot() {
        Ok(p) => p,
        Err(r) => return r.response(),
    };
    let deadline = Instant::now() + deps.request_budget;
    let (mp, meter) = match open_multipart(req).await {
        Ok(x) => x,
        Err(r) => return r.response(),
    };
    let mode = Mode::Ui {
        expect_csrf,
        account_bucket: account_key(sess.user_id),
        id_hash: sess.id_hash,
        user_id: sess.user_id,
        client: client_ip,
        ip,
        hidden: Arc::clone(&sess.hidden_categories),
    };
    let items = match read_multipart(&deps, mp, &meter, mode, deadline).await {
        Ok(i) => i,
        Err(r) => return r.response(),
    };
    let page = ResultPage {
        layout: Layout::for_session("Upload results", &sess),
        rows: items.into_iter().map(|i| row(i, &sess)).collect(),
    };
    match page.render() {
        Ok(body) => html(StatusCode::OK, body),
        Err(e) => {
            tracing::error!(error = %e, "upload result render failed");
            INTERNAL.response()
        }
    }
}

#[cfg(test)]
mod nfo_pairing_tests {
    use super::{is_nfo_name, pair_nfos, stem_key};

    #[test]
    fn nfo_names_and_stems() {
        assert!(is_nfo_name("a.nfo") && is_nfo_name("A.NFO") && is_nfo_name("x.y.Nfo"));
        assert!(
            !is_nfo_name(".nfo")
                && !is_nfo_name("a.nzb")
                && !is_nfo_name("nfo")
                && !is_nfo_name("a.nfo.nzb")
        );
        assert_eq!(stem_key("Show.S01E01.NZB"), "show.s01e01");
        assert_eq!(stem_key("noext"), "noext");
    }

    #[test]
    fn one_of_each_pairs_whatever_the_names() {
        assert_eq!(pair_nfos(&[Some("a.nzb")], &[Some("b.nfo")]), vec![Ok(0)]);
        assert_eq!(pair_nfos(&[None], &[None]), vec![Ok(0)]);
    }

    #[test]
    fn several_pair_by_stem_first_wins() {
        let nzbs = [Some("A.nzb"), Some("B.nzb"), None];
        let nfos = [
            Some("b.nfo"),
            Some("a.NFO"),
            Some("B.nfo"),
            Some("c.nfo"),
            None,
        ];
        assert_eq!(
            pair_nfos(&nzbs, &nfos),
            vec![
                Ok(1),
                Ok(0),
                Err("NFO_EXTRA"),
                Err("NFO_UNPAIRED"),
                Err("NFO_UNPAIRED")
            ]
        );
        // No NZB at all: nothing pairs.
        assert_eq!(pair_nfos(&[], &[Some("a.nfo")]), vec![Err("NFO_UNPAIRED")]);
    }
}

#[cfg(test)]
mod hint_tests {
    use super::resolve_hint;
    use nzb_core::{Taxonomy, XXX_CATEGORY};

    #[test]
    fn a_hidden_category_is_refused_as_a_hint_like_an_unknown_one() {
        let tax = Taxonomy::builtin().unwrap_or_else(|e| panic!("{e}"));
        let hidden = tax.subtree_ids(XXX_CATEGORY);
        assert!(resolve_hint(&tax, &[], "6000").is_ok_and(|h| h.as_deref() == Some("6000")));
        assert!(resolve_hint(&tax, &hidden, "6000").is_err());
        assert!(resolve_hint(&tax, &hidden, "6010").is_err());
        assert!(resolve_hint(&tax, &hidden, "nope").is_err());
        assert!(resolve_hint(&tax, &hidden, "  ").is_ok_and(|h| h.is_none()));
    }
}

#[cfg(test)]
mod session_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::Request;
    use futures_util::{StreamExt as _, stream};
    use nzb_ingest::{DuplicatesAction, Pipeline, PipelineConfig};
    use nzb_store::prelude::*;
    use nzb_store::{AccountPolicy, FsStore, NewAccount, SessionStage};
    use nzb_testkit::{FileSpec, NzbBuilder};
    use tokio::sync::oneshot;
    use tower::ServiceExt as _;

    use crate::auth::{AuthConfig, AuthState, ClientMeta, ManualWallClock};

    struct IngestClock(Arc<ManualWallClock>);

    impl nzb_ingest::WallClock for IngestClock {
        fn now_unix(&self) -> i64 {
            self.0.now_secs()
        }
    }

    #[derive(Clone, Copy)]
    enum DuringBody {
        Logout,
        Expire,
        KeepSession,
        ApiAfterLogout,
    }

    /// The first body chunk has passed the real session/CSRF gate before `waiting` fires. The
    /// complete NZB and closing boundary remain unavailable until the caller explicitly resumes.
    fn suspended_body(bytes: &[u8]) -> (Body, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let middle = bytes.len() / 2;
        let mut head = b"--upload-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n".to_vec();
        head.extend_from_slice(&bytes[..middle]);
        let mut tail = bytes[middle..].to_vec();
        tail.extend_from_slice(b"\r\n--upload-test--\r\n");
        let (waiting, reached) = oneshot::channel();
        let (resume, paused) = oneshot::channel();
        let first = stream::iter([Ok::<_, std::io::Error>(Bytes::from(head))]);
        let rest = stream::once(async move {
            let _ = waiting.send(());
            paused
                .await
                .map_err(|_| std::io::Error::other("upload test cancelled"))?;
            Ok::<_, std::io::Error>(Bytes::from(tail))
        });
        (Body::from_stream(first.chain(rest)), reached, resume)
    }

    fn authenticated_request(path: &str, cookie: &str, csrf: &str) -> axum::http::request::Builder {
        Request::post(path)
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf)
    }

    #[tokio::test]
    async fn sec_036_ui_upload_rechecks_session_after_suspended_body() {
        let dir = tempfile::tempdir().unwrap();
        let test_store = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = test_store.store.clone();
        let user_id = db
            .create_account_operator(
                &NewAccount {
                    username: "uploader",
                    password_hash: "unused-test-hash",
                    role: None,
                },
                AccountPolicy::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        let clock = Arc::new(ManualWallClock::new(1_700_000_000));
        let auth = AuthState::new(
            db.clone(),
            AuthConfig {
                idle_secs: 10,
                insecure_cookies: true,
                ..AuthConfig::default()
            },
            clock.clone(),
        )
        .await
        .unwrap();
        let mkdir = |name: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).unwrap();
            path
        };
        let staging = mkdir("tmp");
        let pipeline = Pipeline::new(
            PipelineConfig {
                limits: nzb_core::Limits::default(),
                watch_dir: mkdir("watch"),
                failed_dir: mkdir("failed"),
                duplicates_dir: mkdir("duplicates"),
                duplicates_action: DuplicatesAction::Move,
                category_from_subfolder: false,
                failed_uploads_max_files: 0,
                failed_uploads_max_bytes: 0,
            },
            db.clone(),
            Arc::new(FsStore::open(mkdir("store")).unwrap()),
            Arc::new(IngestClock(Arc::clone(&clock))),
        )
        .unwrap();
        let (handle, workers) = pipeline.spawn_workers(1);
        let deps = UploadDeps::new(
            handle,
            Arc::new(Taxonomy::builtin().unwrap()),
            staging.clone(),
            64 * 1024,
        )
        .with_audit(db.clone(), clock.clone());
        let app = crate::router_with_upload(
            &crate::WebConfig {
                insecure_cookies: true,
                ..crate::WebConfig::default()
            },
            &auth,
            ui_routes(deps.clone()),
            Some(api_route(deps)),
        );
        let (_, api_key) = crate::apikey::issue(
            &db,
            "upload control",
            clock.now_secs(),
            nzb_store::Actor {
                name: "cli",
                ip: None,
            },
        )
        .await
        .unwrap();
        let mut accepted = 0;
        for (n, action) in [
            DuringBody::Logout,
            DuringBody::Expire,
            DuringBody::KeepSession,
            DuringBody::ApiAfterLogout,
        ]
        .into_iter()
        .enumerate()
        {
            let (set_cookie, csrf) = auth
                .start_session_full(user_id, SessionStage::Active, &ClientMeta::default(), None)
                .await
                .unwrap();
            let cookie = set_cookie.to_str().unwrap().split(';').next().unwrap();
            let api = matches!(action, DuringBody::ApiAfterLogout);
            let bytes = NzbBuilder::new()
                .file(FileSpec::new(&format!("\"upload.{n}.mkv\" yEnc (1/2)")).segments(2))
                .build();
            let sha = crate::crypto::hex(&crate::crypto::sha256(&bytes));
            let (body, reached, resume) = suspended_body(&bytes);
            let mut request =
                authenticated_request(if api { "/api/v1/nzb" } else { "/upload" }, cookie, &csrf)
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=upload-test",
                    );
            if api {
                request = request.header("x-api-key", api_key.secret.as_str());
            }
            let router = app.clone();
            let request = request.body(body).unwrap();
            let upload = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
            tokio::time::timeout(Duration::from_secs(5), reached)
                .await
                .unwrap()
                .unwrap();
            assert!(
                !upload.is_finished(),
                "the incomplete body must still be pending"
            );
            assert!(db.get_release_by_sha(&sha).await.unwrap().is_none());
            match action {
                DuringBody::Logout | DuringBody::ApiAfterLogout => {
                    let response = app
                        .clone()
                        .oneshot(
                            authenticated_request("/logout", cookie, &csrf)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::SEE_OTHER);
                    let mut headers = HeaderMap::new();
                    headers.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
                    assert!(auth.peek_session(&headers).await.unwrap().is_none());
                }
                DuringBody::Expire => clock.advance(10),
                DuringBody::KeepSession => {}
            }
            resume.send(()).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(10), upload)
                .await
                .unwrap()
                .unwrap();
            let refused = matches!(action, DuringBody::Logout | DuringBody::Expire);
            assert_eq!(
                response.status(),
                if refused {
                    StatusCode::NOT_FOUND
                } else if api {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                "case {n}"
            );
            let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(!body.contains(api_key.secret.as_str()));
            let row = db.get_release_by_sha(&sha).await.unwrap();
            if refused {
                assert!(row.is_none(), "a refused upload must not publish a release");
            } else {
                accepted += 1;
                let attribution = db
                    .release_attribution(row.unwrap().id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(attribution.added_by, Some(user_id));
            }
            assert_eq!(
                test_store.i64("SELECT count(*) FROM release").await,
                accepted
            );
            assert_eq!(
                test_store
                    .i64("SELECT count(*) FROM release WHERE added_by IS NOT NULL")
                    .await,
                accepted
            );
            assert_eq!(
                test_store.i64("SELECT count(*) FROM search_outbox").await,
                accepted
            );
            assert_eq!(
                test_store.i64("SELECT count(*) FROM ingest_log").await,
                accepted
            );
            assert_eq!(
                test_store
                    .i64("SELECT count(*) FROM audit_log WHERE event = 'nzb_upload'")
                    .await,
                accepted
            );
            assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
        }
        drop(app);
        for worker in workers {
            tokio::time::timeout(Duration::from_secs(5), worker)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
