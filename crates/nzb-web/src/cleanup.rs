//! Delete release, trash and the admin **Cleanup** panel (T081, `docs/UI_SPEC.md`).
//!
//! Routes (all behind the active-session gate, which also enforces Origin and CSRF on POSTs;
//! the POSTs use the strict "login" rate class):
//!
//! * `GET/POST /release/{id}/delete`: confirmation page / delete. The POST needs the typed word
//!   `DELETE` plus the current password and a fresh TOTP code (one verdict transaction shared
//!   with login, so wrong attempts count toward the lockout). The release is moved to
//!   `release_trash` in one transaction (with its audit row) and its blob to the store's trash
//!   area, where it is restorable (`nzbd trash restore`) until purged.
//! * `GET /admin/cleanup`: counts and sizes of the three buckets (Trash, Blocked, Failed),
//!   cached 15 s behind a single-flight collection permit.
//! * `GET/POST /admin/cleanup/purge/{bucket}`: confirmation page / purge of one bucket. Needs the
//!   typed bucket name plus password and TOTP. The purge runs in an owned task holding a
//!   one-permit semaphore under a deadline, followed by a cooldown; the audit row (bucket,
//!   count, bytes, skipped; no names) is written by that task, so it exists even if the client
//!   disconnects.
//!
//! The file operations and their safety rules live in `nzb_ingest::cleanup`.
//!
//! Hidden releases (`ui.show_xxx = false`) answer the uniform 404 on the delete URLs. The panel
//! is an operator view like `/admin`: counts and sizes only, never titles or names.

use nzb_store::prelude::*;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use nzb_core::{Sha256, Taxonomy, sanitize_text};
use nzb_ingest::cleanup::{self, Bucket, CleanupEnv, CleanupStatus, PurgeReport};
use nzb_store::{StoreError, TrashFinish};
use tokio::sync::Semaphore;

use crate::account::{fmt_utc, reauth};
use crate::assets::Layout;
use crate::auth::{AuthState, SessionCtx, WallClock};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::index::human_bytes;
use crate::release::{not_found, parse_id};
use crate::session::see_other;

/// Seconds the bucket counts are reused.
pub const CACHE_SECS: i64 = 15;
/// Deadline of the count walk.
const STATUS_DEADLINE: Duration = Duration::from_secs(10);
/// Hard deadline of one purge run (checked between files).
pub const PURGE_DEADLINE: Duration = Duration::from_secs(120);
/// Minimum seconds between two purges.
pub const PURGE_COOLDOWN_SECS: i64 = 30;
/// How long the POST handler waits for the result before redirecting to the panel.
pub const PURGE_WAIT: Duration = Duration::from_secs(8);
/// The word that confirms deleting a release.
pub const DELETE_WORD: &str = "DELETE";
/// Shown when the release (or bulk selection) is no longer what the confirmation page showed.
pub(crate) const CHANGED: &str =
    "This release changed since you opened this page; review it again.";
/// Fields of the delete and purge forms that must occur at most once (T119 review I1).
pub(crate) const DELETE_SINGLETONS: &[&str] =
    &["confirm", "current_password", "code", "sha", "sel"];
/// Shown for any failed re-authentication: one text only.
pub(crate) const REAUTH_FAILED: &str = "Verification failed";

/// Everything the cleanup routes need.
#[derive(Clone)]
pub struct CleanupDeps {
    /// Database, trash-capable blob store and `failed/` directory.
    pub env: CleanupEnv,
    /// Wall clock (deterministic in tests).
    pub clock: Arc<dyn WallClock>,
    /// Category taxonomy (names on the confirmation page).
    pub taxonomy: Arc<Taxonomy>,
    /// Deadline of one purge run.
    pub deadline: Duration,
    /// Minimum seconds between two purges.
    pub cooldown_secs: i64,
    /// How long the purge POST waits for its result.
    pub wait: Duration,
    /// Test hook: called right before the acting admin is re-validated for each batch of a
    /// running purge (`sec_060_purge_rechecks_actor_before_each_batch`). `None` in production.
    pub on_batch: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl CleanupDeps {
    /// Deps with the production limits.
    #[must_use]
    pub fn new(env: CleanupEnv, clock: Arc<dyn WallClock>, taxonomy: Arc<Taxonomy>) -> Self {
        Self {
            env,
            clock,
            taxonomy,
            deadline: PURGE_DEADLINE,
            cooldown_secs: PURGE_COOLDOWN_SECS,
            wait: PURGE_WAIT,
            on_batch: None,
        }
    }
}

#[derive(Default)]
struct CachedStatus {
    value: Option<(i64, Option<CleanupStatus>)>,
    generation: u64,
}

#[derive(Clone, Copy)]
struct LastPurge {
    at: i64,
    /// None means the operation failed; partial removal counts are not known.
    report: Option<PurgeReport>,
}

#[derive(Clone)]
struct St {
    deps: CleanupDeps,
    auth: AuthState,
    cache: Arc<Mutex<CachedStatus>>,
    status_permit: Arc<Semaphore>,
    permit: Arc<Semaphore>,
    last: Arc<Mutex<Option<LastPurge>>>,
}

/// Publish a terminal result before releasing the purge permit, including unwinding. A
/// failed operation may have removed some files, so its result cannot claim zero removals.
struct PurgeCompletion {
    state: St,
    report: Option<PurgeReport>,
}

impl Drop for PurgeCompletion {
    fn drop(&mut self) {
        self.state.forget_cache();
        self.state.set_last(LastPurge {
            at: self.state.deps.clock.now_secs(),
            report: self.report,
        });
    }
}

impl St {
    fn last(&self) -> Option<LastPurge> {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_last(&self, v: LastPurge) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(v);
    }

    /// A response deadline never cancels a started filesystem walk. Concurrent requests do
    /// not queue refresh tasks; they return unknown until the sole collector finishes.
    async fn status(&self) -> Option<CleanupStatus> {
        let (generation, permit) = {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((at, value)) = cache.value
                && (0..CACHE_SECS).contains(&self.deps.clock.now_secs().saturating_sub(at))
            {
                return value;
            }
            let permit = Arc::clone(&self.status_permit).try_acquire_owned().ok()?;
            (cache.generation, permit)
        };
        let this = self.clone();
        let job = tokio::spawn(async move {
            let _permit = permit;
            let value = cleanup::status(&this.deps.env).await.ok();
            let mut cache = this.cache.lock().unwrap_or_else(PoisonError::into_inner);
            // A purge may finish while the walk is in progress. Neither its caller nor the
            // cache may receive counts collected before that invalidation.
            if cache.generation != generation {
                return None;
            }
            cache.value = Some((this.deps.clock.now_secs(), value));
            value
        });
        tokio::time::timeout(STATUS_DEADLINE, job)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    }

    fn forget_cache(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.generation = cache.generation.wrapping_add(1);
        cache.value = None;
    }
}

/// Routes of the delete flow and the Cleanup panel; merge them into the `session_routes` of
/// [`crate::router_with_auth`].
pub fn routes(auth: &AuthState, deps: CleanupDeps) -> Router {
    Router::new()
        .route("/release/{id}/delete", get(get_delete).post(post_delete))
        .route("/admin/cleanup", get(panel))
        .route(
            "/admin/cleanup/purge/{bucket}",
            get(get_purge).post(post_purge),
        )
        .with_state(St {
            deps,
            auth: auth.clone(),
            cache: Arc::new(Mutex::new(CachedStatus::default())),
            status_permit: Arc::new(Semaphore::new(1)),
            permit: Arc::new(Semaphore::new(1)),
            last: Arc::new(Mutex::new(None)),
        })
}

fn internal() -> Response {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
}

fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "cleanup render failed");
            internal()
        }
    }
}

fn actor(sess: &SessionCtx) -> String {
    format!("user:{}", sess.user_id)
}

// ---------------------------------------------------------------------------------------------
// Delete release

#[derive(Template)]
#[template(path = "release_delete.html")]
struct DeletePage {
    layout: Layout,
    id: i64,
    title: String,
    category: String,
    size: String,
    nzb_size: String,
    file_count: u32,
    /// Digest of the release as shown (the public GUID); posted back and compared (T119 M1).
    sha: String,
    word: &'static str,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "release_deleted.html")]
struct DeletedPage {
    layout: Layout,
    title: String,
    trash_id: i64,
    restorable: bool,
}

/// Loads the release for the delete pages: a hidden release is as unknown as a missing one.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
async fn load(st: &St, sess: &SessionCtx, id: i64) -> Result<nzb_store::ReleaseRow, Response> {
    match st.deps.env.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => Ok(r),
        Ok(_) => Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            Err(internal())
        }
    }
}

fn delete_page(
    st: &St,
    sess: &SessionCtx,
    row: &nzb_store::ReleaseRow,
    error: Option<&'static str>,
) -> DeletePage {
    let category = u16::try_from(row.category_id)
        .ok()
        .and_then(|c| st.deps.taxonomy.get(c))
        .map_or_else(|| "Unknown".to_owned(), |c| c.name.clone());
    DeletePage {
        layout: Layout::for_session("Delete release", sess),
        id: row.id,
        title: sanitize_text(&row.title, 255),
        category,
        size: human_bytes(row.total_bytes),
        nzb_size: human_bytes(row.nzb_size_bytes),
        file_count: row.file_count,
        sha: row.sha256.to_hex(),
        word: DELETE_WORD,
        error,
    }
}

async fn get_delete(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    match load(&st, &sess, id).await {
        Ok(row) => render(&delete_page(&st, &sess, &row, None)),
        Err(r) => r,
    }
}

async fn post_delete(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    // Existence and visibility first: a hidden release answers the uniform 404 without
    // touching the re-authentication counters.
    let row = match load(&st, &sess, id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let form = csrf::parse_form(&body);
    if !csrf::singletons_ok(&form, DELETE_SINGLETONS) {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response();
    }
    // Bound to what the admin saw (T119 review M1): the confirmation page posts back the digest it
    // showed, and the release must still have it. Ids are reusable rowids, so a release deleted
    // and replaced by a different NZB since the page was opened fails here, before the typed word
    // and before re-authentication (nothing is consumed); the page is shown again with the current
    // release and a notice. A missing or malformed digest is the same mismatch.
    if csrf::form_get(&form, "sha") != Some(row.sha256.to_hex().as_str()) {
        return render(&delete_page(&st, &sess, &row, Some(CHANGED)));
    }
    // Input-only check before re-authentication: it must not burn the user's TOTP step.
    if csrf::form_get(&form, "confirm").map(str::trim) != Some(DELETE_WORD) {
        return render(&delete_page(
            &st,
            &sess,
            &row,
            Some("Type the word DELETE exactly to confirm."),
        ));
    }
    let ip_text = ip.to_string();
    match reauth(&st.auth, &sess, &ip_text, "release_delete", &form).await {
        Ok(true) => {}
        Ok(false) => {
            return render(&delete_page(&st, &sess, &row, Some(REAUTH_FAILED)));
        }
        Err(r) => return r,
    }
    let now = st.deps.clock.now_secs();
    // `row.sha256` equals the digest the confirmation page showed (checked above); `trash_one`
    // re-checks it inside the move transaction, which closes the window after this load.
    match trash_one(
        &st.deps.env,
        &sess.actor(),
        id,
        row.sha256,
        now,
        Some(&ip_text),
    )
    .await
    {
        Ok(Trashed {
            row: trashed,
            staged,
        }) => {
            sess.library_gen.note_change(now);
            render(&DeletedPage {
                layout: Layout::for_session("Release deleted", &sess),
                title: sanitize_text(&trashed.title, 255),
                trash_id: trashed.id,
                restorable: staged,
            })
        }
        // A role lost between the gate and the write is the uniform refusal.
        Err(TrashError::Gone | TrashError::Refused) => not_found(),
        Err(TrashError::Failed) => internal(),
    }
}

/// Outcome of a successful [`trash_one`].
pub(crate) struct Trashed {
    /// The `release_trash` row (trash id for `nzbd trash restore`).
    pub(crate) row: nzb_store::TrashRow,
    /// True when the blob was moved to the trash area; false when the store had none.
    pub(crate) staged: bool,
}

/// Why [`trash_one`] did not delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrashError {
    /// The release no longer exists, or its id now names a different NZB: nothing changed.
    Gone,
    /// The acting account is no longer a live, enabled admin (re-validated in the transaction).
    Refused,
    /// A store or database error (logged): the release is still in the index.
    Failed,
}

/// The delete protocol for one release, shared by the single and the bulk delete (T081, T119):
/// stage a second name for the blob in the trash area, move the row (with its audit row) in one
/// transaction that re-validates the admin and re-checks the digest, then drop the live name
/// unless the same bytes were re-ingested meanwhile. A crash between the steps leaves a spare link
/// or an orphan blob, never a lost NZB.
pub(crate) async fn trash_one(
    env: &CleanupEnv,
    actor: &nzb_store::AccountActor,
    id: i64,
    sha: Sha256,
    now: i64,
    ip: Option<&str>,
) -> Result<Trashed, TrashError> {
    // 0. Look before staging, so no trash copy of a digest we are not deleting is created; the
    // move below re-checks the digest inside its transaction.
    match env.db.get_release(id).await {
        Ok(Some(r)) if r.sha256 == sha => {}
        Ok(_) => return Err(TrashError::Gone),
        Err(e) => {
            tracing::error!(error = %e, "release lookup before delete failed");
            return Err(TrashError::Failed);
        }
    }
    // 1. Second name for the blob in the trash area (live blob untouched). A release whose
    // blob is already missing can still be deleted (nothing to keep).
    // Wall-clock start of the delete (not the injectable clock: it is compared with file mtimes).
    let started_at = std::time::SystemTime::now();
    let staged = match env.store.trash_stage(&sha).await {
        Ok(()) => true,
        Err(StoreError::NotFound) => false,
        Err(e) => {
            tracing::error!(error = %e, "trash staging failed");
            return Err(TrashError::Failed);
        }
    };
    // 2. One transaction: row, files, FTS entry -> release_trash, plus the audit row. The store
    // re-validates the actor (live, enabled admin) inside the transaction and records
    // `deleted_by` and the audit identity there.
    let trashed = match env
        .db
        .trash_release_checked_as(actor, id, &sha, now, ip)
        .await
    {
        Ok(t) => t,
        Err(StoreError::NotFound) => return Err(TrashError::Gone),
        Err(StoreError::Account(_)) => return Err(TrashError::Refused),
        Err(e) => {
            tracing::error!(error = %e, "release delete failed");
            return Err(TrashError::Failed);
        }
    };
    // 3. Drop the live name unless the same bytes were re-ingested in the meantime. A failure
    // here only leaves an orphan blob (reclaimed by `store gc`); the delete itself is done.
    if staged {
        let handle = tokio::runtime::Handle::current();
        let db = env.db.clone();
        let unref: nzb_store::StillUnreferenced = Arc::new(move |s: &Sha256| {
            // Runs on a blocking thread; a database error keeps the blob.
            matches!(
                handle.block_on(db.get_release_by_sha(&s.to_hex())),
                Ok(None)
            )
        });
        match env.store.trash_finish(&sha, started_at, unref).await {
            Ok(TrashFinish::Removed | TrashFinish::Gone | TrashFinish::Kept) => {}
            Err(e) => tracing::error!(error = %e, "live blob removal after delete failed"),
        }
    }
    Ok(Trashed {
        row: trashed,
        staged,
    })
}

// ---------------------------------------------------------------------------------------------
// Cleanup panel

struct BucketView {
    slug: &'static str,
    name: &'static str,
    what: &'static str,
    items: u64,
    size: String,
    lines: Vec<String>,
}

#[derive(Template)]
#[template(path = "cleanup.html")]
struct PanelPage {
    layout: Layout,
    known: bool,
    notice: &'static str,
    buckets: Vec<BucketView>,
    foreign: u64,
    last: Option<LastView>,
    quarantine_days: i64,
}

struct LastView {
    at: String,
    bucket: &'static str,
    removed: u64,
    bytes: String,
    skipped: u64,
}

fn name_of(b: Bucket) -> &'static str {
    match b {
        Bucket::Trash => "Trash",
        Bucket::Blocked => "Blocked",
        Bucket::Failed => "Failed",
    }
}

fn what_of(b: Bucket) -> &'static str {
    match b {
        Bucket::Trash => {
            "Deleted releases (restorable until purged), blobs that the store garbage collector set aside, and leftover files of an interrupted removal."
        }
        Bucket::Blocked => {
            "Files in the failed folder that were rejected by policy or as hostile input: forbidden DOCTYPE, not UTF-8, a parser limit, too large, or an invalid category."
        }
        Bucket::Failed => {
            "All other files in the failed folder (including the expired subfolder): empty or malformed NZBs, timeouts, read or storage errors, and files without a reason record."
        }
    }
}

fn buckets(s: &CleanupStatus) -> Vec<BucketView> {
    let t = &s.trash;
    let failed_lines = |f: &cleanup::FailedBucketStatus| {
        let mut v = Vec::new();
        if f.unmanaged > 0 {
            v.push(format!(
                "{} without a valid reason record: counted, never purged.",
                f.unmanaged
            ));
        }
        v
    };
    let mut trash_lines = vec![
        format!(
            "{} deleted release(s), {}",
            t.releases,
            human_bytes(t.release_bytes)
        ),
        format!(
            "{} quarantined blob(s) from store gc, {}",
            t.quarantine,
            human_bytes(t.quarantine_bytes)
        ),
        format!(
            "{} leftover file(s), {}",
            t.leftovers,
            human_bytes(t.leftover_bytes)
        ),
    ];
    if t.unrecorded > 0 {
        trash_lines.push(format!(
            "{} trash file(s) without a record: counted, never purged.",
            t.unrecorded
        ));
    }
    vec![
        BucketView {
            slug: Bucket::Trash.slug(),
            name: name_of(Bucket::Trash),
            what: what_of(Bucket::Trash),
            items: t.items(),
            size: human_bytes(t.bytes()),
            lines: trash_lines,
        },
        BucketView {
            slug: Bucket::Blocked.slug(),
            name: name_of(Bucket::Blocked),
            what: what_of(Bucket::Blocked),
            items: s.blocked.items,
            size: human_bytes(s.blocked.bytes),
            lines: failed_lines(&s.blocked),
        },
        BucketView {
            slug: Bucket::Failed.slug(),
            name: name_of(Bucket::Failed),
            what: what_of(Bucket::Failed),
            items: s.failed.items,
            size: human_bytes(s.failed.bytes),
            lines: failed_lines(&s.failed),
        },
    ]
}

/// Fixed notice for the `?purge=` redirect marker; the query value is never echoed.
fn notice(st: &St, raw: Option<&str>) -> &'static str {
    if st.permit.available_permits() == 0 {
        return "The purge is still running. Reload this page in a moment to see the result.";
    }
    if let Some(last) = st.last() {
        match last.report {
            None => {
                return "The last purge failed. Some items may already have been removed. See the server log before retrying.";
            }
            Some(report) if report.aborted => {
                return "The last purge stopped because authorization changed. Some items may already have been removed.";
            }
            Some(report) if report.errors > 0 || report.remaining > 0 => {
                return "The last purge did not finish every item. Review the counts and server log before retrying.";
            }
            Some(_) => {}
        }
    }
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    match csrf::form_get(&form, "purge") {
        Some("started" | "busy") => "No purge is currently running.",
        Some("wait") => "A purge finished moments ago. Try again in a few seconds.",
        _ => "",
    }
}

fn last_view(l: LastPurge) -> Option<LastView> {
    let report = l.report?;
    Some(LastView {
        at: fmt_utc(l.at),
        bucket: name_of(report.bucket),
        removed: report.removed,
        bytes: human_bytes(report.bytes),
        skipped: report.skipped(),
    })
}

async fn panel(State(st): State<St>, Extension(sess): Extension<SessionCtx>, uri: Uri) -> Response {
    let status = st.status().await;
    let view = PanelPage {
        layout: Layout::for_session("Cleanup", &sess),
        known: status.is_some(),
        notice: notice(&st, uri.query()),
        buckets: status.as_ref().map(buckets).unwrap_or_default(),
        foreign: status.map_or(0, |s| s.foreign_files),
        last: st.last().and_then(last_view),
        quarantine_days: cleanup::QUARANTINE_MIN_AGE_SECS / 86_400,
    };
    render(&view)
}

// ---------------------------------------------------------------------------------------------
// Purge

#[derive(Template)]
#[template(path = "cleanup_purge.html")]
struct PurgePage {
    layout: Layout,
    slug: &'static str,
    name: &'static str,
    what: &'static str,
    known: bool,
    items: u64,
    size: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "cleanup_result.html")]
struct ResultPage {
    layout: Layout,
    name: &'static str,
    removed: u64,
    bytes: String,
    unmanaged: u64,
    refused: u64,
    kept_recent: u64,
    remaining: u64,
    errors: u64,
}

fn result_page(sess: &SessionCtx, r: &PurgeReport) -> ResultPage {
    ResultPage {
        layout: Layout::for_session("Purge result", sess),
        name: name_of(r.bucket),
        removed: r.removed,
        bytes: human_bytes(r.bytes),
        unmanaged: r.unmanaged,
        refused: r.refused,
        kept_recent: r.kept_recent,
        remaining: r.remaining,
        errors: r.errors,
    }
}

async fn purge_page(
    st: &St,
    sess: &SessionCtx,
    bucket: Bucket,
    error: Option<&'static str>,
) -> Response {
    let status = st.status().await;
    let (items, size) = status
        .as_ref()
        .map_or((0, String::new()), |s| match bucket {
            Bucket::Trash => (s.trash.items(), human_bytes(s.trash.bytes())),
            Bucket::Blocked => (s.blocked.items, human_bytes(s.blocked.bytes)),
            Bucket::Failed => (s.failed.items, human_bytes(s.failed.bytes)),
        });
    render(&PurgePage {
        layout: Layout::for_session("Purge", sess),
        slug: bucket.slug(),
        name: name_of(bucket),
        what: what_of(bucket),
        known: status.is_some(),
        items,
        size,
        error,
    })
}

async fn get_purge(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path(slug): Path<String>,
) -> Response {
    let Some(bucket) = Bucket::parse(&slug) else {
        return not_found();
    };
    purge_page(&st, &sess, bucket, None).await
}

#[allow(clippy::too_many_lines)] // one confirmed, re-authenticated action; the steps are its contract
async fn post_purge(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(slug): Path<String>,
    body: Bytes,
) -> Response {
    let Some(bucket) = Bucket::parse(&slug) else {
        return not_found();
    };
    let form = csrf::parse_form(&body);
    if !csrf::singletons_ok(&form, DELETE_SINGLETONS) {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response();
    }
    // Input-only checks first: they must not burn the user's TOTP step.
    if csrf::form_get(&form, "confirm").map(str::trim) != Some(bucket.slug()) {
        return purge_page(
            &st,
            &sess,
            bucket,
            Some("Type the name of the bucket exactly to confirm."),
        )
        .await;
    }
    let now = st.deps.clock.now_secs();
    if st.permit.available_permits() == 0 {
        return see_other("/admin/cleanup?purge=busy", None);
    }
    if let Some(l) = st.last()
        && (0..st.deps.cooldown_secs).contains(&now.saturating_sub(l.at))
    {
        return see_other("/admin/cleanup?purge=wait", None);
    }
    let ip_text = ip.to_string();
    match reauth(&st.auth, &sess, &ip_text, "cleanup_purge", &form).await {
        Ok(true) => {}
        Ok(false) => return purge_page(&st, &sess, bucket, Some(REAUTH_FAILED)).await,
        Err(r) => return r,
    }
    // One purge at a time, also across sessions; the permit is held by the owned task.
    let Ok(permit) = Arc::clone(&st.permit).try_acquire_owned() else {
        return see_other("/admin/cleanup?purge=busy", None);
    };
    // Another purge may have completed while password/MFA verification was pending. The
    // permit serializes this final cooldown check with publication of that purge's result.
    if let Some(last) = st.last()
        && (0..st.deps.cooldown_secs).contains(&st.deps.clock.now_secs().saturating_sub(last.at))
    {
        return see_other("/admin/cleanup?purge=wait", None);
    }
    let task_st = st.clone();
    let actor = actor(&sess);
    // Check the initiating session as well as the account before every batch: logout,
    // expiry, disabling or demotion stops an already running purge at the next batch.
    let gate = purge_gate(
        st.deps.env.db.clone(),
        sess.user_id,
        sess.id_hash,
        Arc::clone(&st.deps.clock),
        st.deps.on_batch.clone(),
    );
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut completion = PurgeCompletion {
            state: task_st.clone(),
            report: None,
        };
        let started = task_st.deps.clock.now_secs();
        let deadline = Instant::now() + task_st.deps.deadline;
        let env = task_st.deps.env.clone();
        let report = match cleanup::purge_gated(&env, bucket, started, deadline, Some(gate)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "purge failed");
                return None;
            }
        };
        let mut detail = format!(
            "bucket={} count={} bytes={} skipped={}",
            bucket.slug(),
            report.removed,
            report.bytes,
            report.skipped()
        );
        if report.aborted {
            detail.push_str(" aborted=1");
        }
        if let Err(e) = env
            .db
            .audit_event(
                task_st.deps.clock.now_secs(),
                Some(&actor),
                "cleanup_purge",
                Some(&detail),
                Some(&ip_text),
            )
            .await
        {
            tracing::error!(error = %e, "audit write failed");
        }
        completion.report = Some(report);
        Some(report)
    });
    match tokio::time::timeout(st.deps.wait, job).await {
        // The actor lost its authority mid-run: the uniform refusal, not a results page.
        Ok(Ok(Some(report))) if report.aborted => not_found(),
        Ok(Ok(Some(report))) => render(&result_page(&sess, &report)),
        Ok(_) => internal(),
        // Still running: the task continues on its own and the panel shows the result later.
        Err(_) => see_other("/admin/cleanup?purge=started", None),
    }
}

fn purge_gate(
    db: nzb_store::Store,
    uid: i64,
    id_hash: [u8; 32],
    clock: Arc<dyn WallClock>,
    hook: Option<Arc<dyn Fn() + Send + Sync>>,
) -> cleanup::PurgeGate {
    let handle = tokio::runtime::Handle::current();
    Arc::new(move || {
        if let Some(h) = &hook {
            h();
        }
        matches!(
            handle.block_on(db.session_actor(&id_hash, clock.now_secs())),
            Ok(Some(a)) if a.user_id == uid
                && a.role == nzb_store::Role::Admin
                && a.stage == nzb_store::SessionStage::Active
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::auth::ManualWallClock;
    use nzb_store::{NewAccount, NewSession, Role, SessionStage};

    async fn check(gate: &cleanup::PurgeGate) -> bool {
        let gate = Arc::clone(gate);
        tokio::task::spawn_blocking(move || gate()).await.unwrap()
    }

    #[tokio::test]
    async fn sec_060_purge_requires_live_initiating_session_before_each_batch() {
        const NOW: i64 = 3_000;
        let dir = tempfile::tempdir().unwrap();
        let test_store = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = test_store.store.clone();
        let uid = db
            .create_account_operator(
                &NewAccount {
                    username: "root",
                    password_hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
                    role: Some(Role::Admin),
                },
                crate::auth::AuthConfig::default().account_policy(),
                NOW,
            )
            .await
            .unwrap();
        let mut session = NewSession {
            id_hash: [71; 32],
            user_id: uid,
            stage: SessionStage::Active,
            csrf_token: [72; 32],
            now: NOW,
            expires_at: NOW + 10,
            ip: None,
            user_agent: None,
        };
        db.insert_session(&session, 5).await.unwrap();
        let clock = Arc::new(ManualWallClock::new(NOW));
        let gate = purge_gate(db.clone(), uid, session.id_hash, clock.clone(), None);
        assert!(check(&gate).await);
        assert!(db.delete_session(&session.id_hash).await.unwrap());
        assert!(db.get_account(uid).await.unwrap().unwrap().is_enabled());
        assert!(!check(&gate).await, "logout must stop the next purge batch");

        session.stage = SessionStage::PendingMfa;
        db.insert_session(&session, 5).await.unwrap();
        assert!(
            !check(&gate).await,
            "an incomplete MFA session is insufficient"
        );
        assert!(db.delete_session(&session.id_hash).await.unwrap());
        session.stage = SessionStage::Active;
        db.insert_session(&session, 5).await.unwrap();
        assert!(check(&gate).await);
        clock.advance(10);
        assert!(
            !check(&gate).await,
            "expiry equality must stop the next batch"
        );

        session.id_hash = [73; 32];
        session.now = NOW + 10;
        session.expires_at = NOW + 20;
        db.insert_session(&session, 5).await.unwrap();
        assert!(
            !check(&gate).await,
            "a replacement login cannot revive the old purge"
        );
        let replacement = purge_gate(db, uid, session.id_hash, clock, None);
        assert!(check(&replacement).await);
    }
}

#[cfg(test)]
mod cleanup_regressions {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::too_many_lines,
        clippy::panic
    )]

    use std::future::{Future as _, poll_fn};
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::SystemTime;

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use nzb_store::{
        FsStore, NzbStore, PutOutcome, QuarantineListing, QuarantinePurge, StillUnreferenced,
        TrashBlob, TrashListing, TrashPurge, TrashStore,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{AuthConfig, ClientMeta, ManualWallClock};
    use crate::totp;

    const NOW: i64 = 3_000;
    const PASSWORD: &str = "Cleanup-Test-Password-42";
    const SECRET: &[u8] = b"12345678901234567890";
    const PRIVATE_ERROR: &str = "private storage path /secret/token";

    struct BlockingState {
        gate: (Mutex<bool>, Condvar),
        started: Semaphore,
        calls: AtomicUsize,
    }

    /// Real blocking work, released on assertion failure too; no cancellable async-only mock.
    struct BlockingProbe(Arc<BlockingState>);

    impl BlockingProbe {
        fn new() -> Self {
            Self(Arc::new(BlockingState {
                gate: (Mutex::new(false), Condvar::new()),
                started: Semaphore::new(0),
                calls: AtomicUsize::new(0),
            }))
        }

        async fn started(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.0.started.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }

        fn release(&self) {
            let (lock, ready) = &self.0.gate;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
            ready.notify_all();
        }
    }

    impl Drop for BlockingProbe {
        fn drop(&mut self) {
            self.release();
        }
    }

    impl BlockingState {
        async fn run(self: Arc<Self>) {
            tokio::task::spawn_blocking(move || {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.started.add_permits(1);
                let (lock, ready) = &self.gate;
                let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
                let (guard, timeout) = ready
                    .wait_timeout_while(guard, Duration::from_secs(15), |released| !*released)
                    .unwrap_or_else(PoisonError::into_inner);
                assert!(
                    !timeout.timed_out() && *guard,
                    "test must release its blocking worker"
                );
            })
            .await
            .unwrap();
        }
    }

    struct ControlledStore {
        inner: FsStore,
        status_gate: Option<Arc<BlockingState>>,
        purge_gate: Option<Arc<BlockingState>>,
        purge_end: AtomicU8,
        listed_items: AtomicU8,
        status_calls: AtomicUsize,
        purge_calls: AtomicUsize,
    }

    #[async_trait]
    impl NzbStore for ControlledStore {
        async fn put(&self, sha: Sha256, bytes: &[u8]) -> Result<PutOutcome, StoreError> {
            self.inner.put(sha, bytes).await
        }
        async fn get(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
            self.inner.get(sha).await
        }
        async fn exists(&self, sha: &Sha256) -> Result<bool, StoreError> {
            self.inner.exists(sha).await
        }
        async fn delete(&self, sha: &Sha256) -> Result<(), StoreError> {
            self.inner.delete(sha).await
        }
    }

    #[async_trait]
    impl TrashStore for ControlledStore {
        async fn trash_stage(&self, sha: &Sha256) -> Result<(), StoreError> {
            self.inner.trash_stage(sha).await
        }
        async fn trash_finish(
            &self,
            sha: &Sha256,
            at: SystemTime,
            check: StillUnreferenced,
        ) -> Result<TrashFinish, StoreError> {
            self.inner.trash_finish(sha, at, check).await
        }
        async fn trash_list(&self, limit: usize) -> Result<TrashListing, StoreError> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            let listed_items = self.listed_items.load(Ordering::SeqCst);
            if let Some(gate) = &self.status_gate {
                Arc::clone(gate).run().await;
            }
            let mut list = self.inner.trash_list(limit).await?;
            list.items = (0..listed_items)
                .map(|n| TrashBlob {
                    sha: Sha256([n; 32]),
                    size: 12,
                })
                .collect();
            Ok(list)
        }
        async fn trash_read(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
            self.inner.trash_read(sha).await
        }
        async fn trash_purge(&self, sha: &Sha256) -> Result<TrashPurge, StoreError> {
            self.inner.trash_purge(sha).await
        }
        async fn quarantine_list(&self, limit: usize) -> Result<QuarantineListing, StoreError> {
            self.inner.quarantine_list(limit).await
        }
        async fn quarantine_purge_checked(
            &self,
            older_than: i64,
            deadline: Option<Instant>,
            gate: Option<cleanup::PurgeGate>,
        ) -> Result<QuarantinePurge, StoreError> {
            self.purge_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(probe) = &self.purge_gate {
                Arc::clone(probe).run().await;
            }
            match self.purge_end.load(Ordering::SeqCst) {
                1 => return Err(std::io::Error::other(PRIVATE_ERROR).into()),
                2 => panic!("injected purge task panic"),
                _ => {}
            }
            self.listed_items.store(9, Ordering::SeqCst);
            self.inner
                .quarantine_purge_checked(older_than, deadline, gate)
                .await
        }
    }

    struct Fixture {
        app: Router,
        auth: AuthState,
        cookie: String,
        csrf: String,
        clock: Arc<ManualWallClock>,
        store: Arc<ControlledStore>,
        _database: nzb_store::test_backend::TestStore,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        async fn new(
            status: Option<&BlockingProbe>,
            purge: Option<&BlockingProbe>,
            purge_end: u8,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let database = nzb_store::test_backend::TestStore::open(dir.path()).await;
            let db = database.store.clone();
            let clock = Arc::new(ManualWallClock::new(NOW));
            let key = Arc::new(totp::TotpKey::from_slice(&[9; 32]).unwrap());
            let cfg = AuthConfig {
                insecure_cookies: true,
                multi_user: true,
                verify_concurrency: 2,
                totp_key: Some(key.clone()),
                ..AuthConfig::default()
            };
            let hash = crate::password::hash_password(PASSWORD).unwrap();
            let uid = db
                .create_account_operator(
                    &nzb_store::NewAccount {
                        username: "cleanup-admin",
                        password_hash: &hash,
                        role: Some(nzb_store::Role::Admin),
                    },
                    cfg.account_policy(),
                    NOW - 60,
                )
                .await
                .unwrap();
            let token = [7; 32];
            let sealed = totp::seal(&key, uid, SECRET).unwrap();
            assert!(
                db.set_enrollment_token_for(uid, &token, NOW + 600, NOW - 60)
                    .await
                    .unwrap()
            );
            assert!(
                db.store_pending_totp(uid, &sealed, false)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                db.confirm_totp_enrollment(
                    uid,
                    &sealed,
                    Some(token),
                    Some(98),
                    &[],
                    None,
                    NOW - 60
                )
                .await
                .unwrap()
            );
            let auth = AuthState::new(db.clone(), cfg, clock.clone())
                .await
                .unwrap();
            let (cookie, csrf) = auth
                .start_session_full(
                    uid,
                    nzb_store::SessionStage::Active,
                    &ClientMeta::default(),
                    None,
                )
                .await
                .unwrap();
            let cookie = cookie
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let store = Arc::new(ControlledStore {
                inner: FsStore::open(dir.path().join("store")).unwrap(),
                status_gate: status.map(|p| Arc::clone(&p.0)),
                purge_gate: purge.map(|p| Arc::clone(&p.0)),
                purge_end: AtomicU8::new(purge_end),
                listed_items: AtomicU8::new(7),
                status_calls: AtomicUsize::new(0),
                purge_calls: AtomicUsize::new(0),
            });
            let failed_dir = dir.path().join("failed");
            std::fs::create_dir(&failed_dir).unwrap();
            let mut deps = CleanupDeps::new(
                CleanupEnv {
                    db,
                    store: store.clone(),
                    failed_dir,
                },
                clock.clone(),
                Arc::new(Taxonomy::builtin().unwrap()),
            );
            deps.wait = Duration::from_millis(20);
            let app = crate::router_with_auth(
                &crate::WebConfig {
                    insecure_cookies: true,
                    ..crate::WebConfig::default()
                },
                &auth,
                routes(&auth, deps),
            );
            Self {
                app,
                auth,
                cookie,
                csrf,
                clock,
                store,
                _database: database,
                _directory: dir,
            }
        }

        fn request(&self, path: &str, form: Option<String>) -> Request<Body> {
            let builder = if form.is_some() {
                Request::post(path)
            } else {
                Request::get(path)
            };
            builder
                .header("host", "localhost")
                .header("origin", "http://localhost")
                .header("accept", "text/html")
                .header("cookie", &self.cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(form.map_or_else(Body::empty, Body::from))
                .unwrap()
        }

        fn purge_request(&self) -> Request<Body> {
            let code = totp::code_at(SECRET, self.clock.now_secs() / totp::STEP_SECS).unwrap();
            self.request(
                "/admin/cleanup/purge/trash",
                Some(format!(
                    "csrf_token={}&confirm=trash&current_password={PASSWORD}&code={code}",
                    self.csrf
                )),
            )
        }

        async fn get(&self, path: &str) -> String {
            let response = self
                .app
                .clone()
                .oneshot(self.request(path, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            html(response).await
        }

        async fn second_admin(&self) -> (String, String) {
            let db = self.auth.db();
            let hash = crate::password::hash_password(PASSWORD).unwrap();
            let uid = db
                .create_account_operator(
                    &nzb_store::NewAccount {
                        username: "second-admin",
                        password_hash: &hash,
                        role: Some(nzb_store::Role::Admin),
                    },
                    self.auth.config().account_policy(),
                    NOW - 60,
                )
                .await
                .unwrap();
            let token = [8; 32];
            let sealed = totp::seal(self.auth.totp_key().unwrap(), uid, SECRET).unwrap();
            assert!(
                db.set_enrollment_token_for(uid, &token, NOW + 600, NOW - 60)
                    .await
                    .unwrap()
            );
            assert!(
                db.store_pending_totp(uid, &sealed, false)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                db.confirm_totp_enrollment(
                    uid,
                    &sealed,
                    Some(token),
                    Some(98),
                    &[],
                    None,
                    NOW - 60
                )
                .await
                .unwrap()
            );
            let (cookie, csrf) = self
                .auth
                .start_session_full(
                    uid,
                    nzb_store::SessionStage::Active,
                    &ClientMeta::default(),
                    None,
                )
                .await
                .unwrap();
            (
                cookie
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
                csrf,
            )
        }
    }

    async fn html(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 256 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    async fn status_lifetime(cancel: bool) {
        let probe = BlockingProbe::new();
        let fixture = Fixture::new(Some(&probe), None, 0).await;
        let mut first = Some(tokio::spawn(
            fixture
                .app
                .clone()
                .oneshot(fixture.request("/admin/cleanup", None)),
        ));
        probe.started().await;
        if cancel {
            let first = first.take().unwrap();
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
        }
        tokio::time::pause();
        tokio::time::advance(STATUS_DEADLINE + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        if !cancel {
            let response = tokio::time::timeout(Duration::from_secs(2), first.take().unwrap())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(html(response).await.contains("counts are unavailable"));
        }
        fixture.clock.advance(CACHE_SECS + 1);
        let next = tokio::spawn(
            fixture
                .app
                .clone()
                .oneshot(fixture.request("/admin/cleanup", None)),
        );
        let overlapping =
            tokio::time::timeout(Duration::from_millis(200), probe.0.started.acquire())
                .await
                .is_ok();
        // Release before asserting, so a red run cannot leave a blocking thread parked.
        probe.release();
        let response = tokio::time::timeout(Duration::from_secs(3), next)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            !overlapping && probe.0.calls.load(Ordering::SeqCst) == 1,
            "cleanup timeout released single-flight while blocking storage work was still running"
        );
        assert!(html(response).await.contains("counts are unavailable"));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !fixture
                    .get("/admin/cleanup")
                    .await
                    .contains("counts are unavailable")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 1);
        fixture.clock.advance(CACHE_SECS - 1);
        fixture.get("/admin/cleanup").await;
        assert_eq!(
            probe.0.calls.load(Ordering::SeqCst),
            1,
            "cache TTL starts at completion"
        );
        fixture.clock.advance(2);
        fixture.get("/admin/cleanup").await;
        assert_eq!(probe.0.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn status_timeout_keeps_started_blocking_worker_owned() {
        status_lifetime(false).await;
    }

    #[tokio::test]
    async fn status_client_cancellation_keeps_started_blocking_worker_owned() {
        status_lifetime(true).await;
    }

    async fn delayed_failure(end: u8) {
        let probe = BlockingProbe::new();
        let fixture = Fixture::new(None, Some(&probe), end).await;
        let post = tokio::spawn(fixture.app.clone().oneshot(fixture.purge_request()));
        probe.started().await;
        let response = tokio::time::timeout(Duration::from_secs(3), post)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(location, "/admin/cleanup?purge=started");
        assert!(fixture.get(&location).await.contains("still running"));
        probe.release();
        let mut terminal = String::new();
        for _ in 0..100 {
            terminal = fixture.get(&location).await;
            if !terminal.contains("still running") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            terminal.contains("last purge failed") && !terminal.contains("still running"),
            "completed purge failure must replace the running redirect notice"
        );
        assert!(terminal.contains("Some items may already have been removed"));
        assert!(
            !terminal.contains(PRIVATE_ERROR) && !terminal.contains("injected purge task panic")
        );
        assert!(
            fixture
                .get("/admin/cleanup")
                .await
                .contains("last purge failed")
        );
        // A terminal error starts the same cooldown and releases the permit; a later retry works.
        let retry = fixture
            .app
            .clone()
            .oneshot(fixture.purge_request())
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            retry.headers().get("location").unwrap(),
            "/admin/cleanup?purge=wait"
        );
        fixture.clock.advance(PURGE_COOLDOWN_SECS + 1);
        fixture.store.purge_end.store(0, Ordering::SeqCst);
        let response = fixture
            .app
            .clone()
            .oneshot(fixture.purge_request())
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::SEE_OTHER
        ));
        // Wait for the retry's own result: between the redirect and the owned task recording its state the page
        // can show neither "still running" nor a result, and the counts may still be the cached ones (seen in the
        // gate, T143).
        let page = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let page = fixture.get(&location).await;
                if !page.contains("still running")
                    && page.contains("Last purge (")
                    && page.contains("9 trash file(s) without a record")
                {
                    break page;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!page.contains("still running") && !page.contains("last purge failed"));
        assert!(page.contains("Last purge (") && page.contains("9 trash file(s) without a record"));
    }

    #[tokio::test]
    async fn failed_purge_after_redirect_has_terminal_ui_state() {
        delayed_failure(1).await;
    }

    #[tokio::test]
    async fn panicking_purge_after_redirect_has_terminal_ui_state() {
        delayed_failure(2).await;
    }

    #[tokio::test]
    async fn purge_completion_invalidates_in_flight_counts_without_waiting() {
        let probe = BlockingProbe::new();
        let fixture = Fixture::new(Some(&probe), None, 0).await;
        let scan = tokio::spawn(
            fixture
                .app
                .clone()
                .oneshot(fixture.request("/admin/cleanup", None)),
        );
        probe.started().await;
        let response = fixture
            .app
            .clone()
            .oneshot(fixture.purge_request())
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::SEE_OTHER
        ));
        // Completion remains observable even if database/audit work outlasted the POST wait.
        // Neither publication nor the panel may wait for the unrelated collector's lock.
        let terminal = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let page = fixture.get("/admin/cleanup?purge=started").await;
                if page.contains("Last purge (") && !page.contains("still running") {
                    break page;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        probe.release();
        assert!(
            terminal.is_ok(),
            "completed purge must remain observable while status storage work is blocked"
        );
        let response = tokio::time::timeout(Duration::from_secs(3), scan)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let old = html(response).await;
        assert!(
            old.contains("counts are unavailable")
                && !old.contains("7 trash file(s) without a record"),
            "a purge must invalidate the in-flight result for both its caller and the cache"
        );
        let fresh = fixture.get("/admin/cleanup").await;
        assert!(
            fresh.contains("9 trash file(s) without a record")
                && !fresh.contains("7 trash file(s) without a record")
        );
        assert!(!fresh.contains("still running"));
        assert_eq!(fixture.store.status_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_reauthentication_rechecks_purge_cooldown() {
        let fixture = Fixture::new(None, None, 0).await;
        let (cookie, csrf) = fixture.second_admin().await;
        let code = totp::code_at(SECRET, NOW / totp::STEP_SECS).unwrap();
        let mut request = fixture.request(
            "/admin/cleanup/purge/trash",
            Some(format!(
                "csrf_token={csrf}&confirm=trash&current_password={PASSWORD}&code={code}"
            )),
        );
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
        let held = Arc::clone(&fixture.auth.0.verify_slots)
            .acquire_many_owned(2)
            .await
            .unwrap();
        let mut delayed = Box::pin(fixture.app.clone().oneshot(request));
        // Poll the real HTTP/reauth future only until it has passed the initial cooldown
        // check and queued for Argon2. Keeping it unpolled then fixes the interleaving.
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| {
                assert!(
                    delayed.as_mut().poll(cx).is_pending(),
                    "second admin must await password verification"
                );
                if fixture.auth.0.verify_waiting.load(Ordering::SeqCst) == 1 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();
        drop(held);

        // The delayed waiter reserves one slot. The other lets the first administrator
        // finish a real reauthenticated purge while the second HTTP future stays paused.
        let first = fixture
            .app
            .clone()
            .oneshot(fixture.purge_request())
            .await
            .unwrap();
        assert!(matches!(
            first.status(),
            StatusCode::OK | StatusCode::SEE_OTHER
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let page = fixture.get("/admin/cleanup?purge=started").await;
                // The parent has an independently broken running notice; its terminal
                // report still proves the first purge completed before we resume B.
                if page.contains("Last purge (") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.store.purge_calls.load(Ordering::SeqCst), 1);

        let second = tokio::time::timeout(Duration::from_secs(3), delayed)
            .await
            .unwrap()
            .unwrap();
        assert!(
            second.status() == StatusCode::SEE_OTHER
                && second
                    .headers()
                    .get("location")
                    .is_some_and(|v| v == "/admin/cleanup?purge=wait"),
            "a purge completed during reauthentication must enforce its cooldown"
        );
        assert_eq!(fixture.store.purge_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.auth.verify_runs(),
            2,
            "both administrators really reauthenticated"
        );
    }
}
