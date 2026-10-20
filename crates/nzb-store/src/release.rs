//! Release repository: insert, getters, category override, delete. Listing and search are the Tantivy index's
//! (`nzb-search`, both backends); every change reaches it through the outbox written by the release triggers.
//!
//! All SQL is static text with bound parameters (SEC-088); NZB-derived text only ever reaches SQLite as a bound
//! value.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use nzb_core::{Analysis, FileInfo, ReleaseFlags, Sha256, sanitize_text};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite};

use crate::attribution::{Uploader, resolve_uploader};
use crate::ingest_log::{IngestLogEntry, LogOutcome, LogSource, insert_log_row};
use crate::{SqliteDb, StoreError};

macro_rules! file_cols_sql {
    () => {
        "idx, subject, filename, kind, poster, posted_at, bytes, segment_count, \
     declared_segments, missing_ranges, groups"
    };
}

mod keyset;
pub use keyset::{CursorError, KeysetPage, MAX_CURSOR_CHARS, PageCursor, SeekDir};

/// Maximum page size accepted by [`SqliteDb::search`].
pub const MAX_LIMIT: u32 = 100;
/// Longest stored `source_label`, in bytes.
pub const MAX_SOURCE_LABEL_BYTES: usize = 64;

/// Sanitizes a submitter-supplied source label; empty after sanitizing means "no label".
#[must_use]
pub fn clean_source_label(raw: &str) -> Option<String> {
    let t = sanitize_text(raw, MAX_SOURCE_LABEL_BYTES);
    if t.is_empty() { None } else { Some(t) }
}

/// How a release entered the index (`release.origin`); display data only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOrigin {
    /// Watch folder.
    Watch,
    /// UI upload form.
    Upload,
    /// `POST /api/v1/nzb`.
    Api,
}

impl IngestOrigin {
    /// Stable database form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Upload => "upload",
            Self::Api => "api",
        }
    }

    /// Fixed English label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Watch => "Watch folder",
            Self::Upload => "Upload",
            Self::Api => "API",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "watch" => Some(Self::Watch),
            "upload" => Some(Self::Upload),
            "api" => Some(Self::Api),
            _ => None,
        }
    }

    /// Origin of a release created from an ingest-log source.
    #[must_use]
    pub const fn from_log_source(s: LogSource) -> Self {
        match s {
            LogSource::Watch => Self::Watch,
            LogSource::UploadUi => Self::Upload,
            LogSource::UploadApi => Self::Api,
        }
    }
}

/// How the category of a release was decided (`release.category_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategorySource {
    /// Scene rules matched.
    Scene,
    /// Category supplied at submission (API header, UI dropdown, sub-folder).
    Upload,
    /// NZB `<meta type="category">`.
    Meta,
    /// Fallback (8010).
    Fallback,
    /// Manual override from the UI.
    Manual,
}

impl CategorySource {
    /// Stable database form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scene => "scene",
            Self::Upload => "upload",
            Self::Meta => "meta",
            Self::Fallback => "fallback",
            Self::Manual => "manual",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scene" => Self::Scene,
            "upload" => Self::Upload,
            "meta" => Self::Meta,
            "fallback" => Self::Fallback,
            "manual" => Self::Manual,
            _ => return None,
        })
    }
}

/// Denormalized scene columns (`scene_*`). All strings must already be sanitized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SceneColumns {
    /// `tv|anime|movie|music`.
    pub family: Option<String>,
    /// Release year.
    pub year: Option<u32>,
    /// Season number.
    pub season: Option<u32>,
    /// Episode number.
    pub episode: Option<u32>,
    /// e.g. `1080p`.
    pub resolution: Option<String>,
    /// e.g. `BluRay`.
    pub source: Option<String>,
    /// e.g. `x264`.
    pub codec: Option<String>,
    /// Release group.
    pub group: Option<String>,
    /// JSON array of languages.
    pub languages_json: Option<String>,
    /// Full `SceneInfo` as JSON.
    pub json: Option<String>,
}

/// Everything needed to insert a release besides the [`Analysis`].
#[derive(Debug, Clone)]
pub struct NewRelease<'a> {
    /// Parser output (files, title, flags, hash).
    pub analysis: &'a Analysis,
    /// Size of the raw NZB in bytes.
    pub nzb_size_bytes: u64,
    /// Original filename, display only.
    pub source_name: Option<&'a str>,
    /// Free-text origin chosen by the submitter (`torrent`, `personal archive`, ...). Untrusted:
    /// sanitized and capped at [`MAX_SOURCE_LABEL_BYTES`] by the store; empty after sanitizing
    /// becomes NULL. Borrowed like `source_name` (the store owns the sanitizing, not the caller).
    pub source_label: Option<&'a str>,
    /// Chosen category id (must exist in the taxonomy).
    pub category_id: u32,
    /// How the category was chosen.
    pub category_source: CategorySource,
    /// Sanitized, capped meta entries as JSON.
    pub meta_json: Option<&'a str>,
    /// Scene columns.
    pub scene: SceneColumns,
    /// Ingest time, Unix seconds (injected clock).
    pub ingested_at: i64,
}

/// A release row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRow {
    /// Row id.
    pub id: i64,
    /// Content hash (public GUID).
    pub sha256: Sha256,
    /// Display title.
    pub title: String,
    /// Category id.
    pub category_id: u32,
    /// True after a manual override.
    pub category_overridden: bool,
    /// How the category was decided.
    pub category_source: CategorySource,
    /// Newest file date.
    pub posted_at: Option<i64>,
    /// Ingest time.
    pub ingested_at: i64,
    /// Total payload bytes.
    pub total_bytes: u64,
    /// Main poster.
    pub poster: Option<String>,
    /// Number of files.
    pub file_count: u32,
    /// Number of segments.
    pub segment_count: u64,
    /// Missing segments (lower bound when ranges were truncated).
    pub missing_segment_count: u64,
    /// Par2 blocks.
    pub par2_blocks: u64,
    /// Flags.
    pub flags: ReleaseFlags,
    /// Raw NZB size.
    pub nzb_size_bytes: u64,
    /// Original filename.
    pub source_name: Option<String>,
    /// Free-text origin given at upload (sanitized, at most 64 bytes); `None` for watch-folder files.
    pub source_label: Option<String>,
    /// How the release entered the index; `None` when unknown (no log entry to derive it from).
    pub origin: Option<IngestOrigin>,
    /// Meta JSON.
    pub meta_json: Option<String>,
    /// Scene columns.
    pub scene: SceneColumns,
}

/// A stored file row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFile {
    /// Position in the NZB.
    pub idx: u32,
    /// Subject.
    pub subject: String,
    /// Filename.
    pub filename: Option<String>,
    /// `FileKind` name.
    pub kind: String,
    /// Poster.
    pub poster: Option<String>,
    /// Post time.
    pub posted_at: Option<i64>,
    /// Bytes.
    pub bytes: u64,
    /// Distinct segments.
    pub segment_count: u32,
    /// Declared segments.
    pub declared_segments: Option<u32>,
    /// Missing ranges JSON: `[[a,b],...]`, or `{"ranges":[...],"more":true}` when truncated.
    pub missing_ranges: Option<String>,
    /// Groups JSON array.
    pub groups: Option<String>,
}

/// Sort order for [`SqliteDb::search`]. Ties are broken by id in the direction of the sort (newest first for
/// the descending orders, oldest first for the ascending ones) for stable pagination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortKey {
    /// Posted date, newest first (default).
    #[default]
    DateDesc,
    /// Posted date, oldest first.
    DateAsc,
    /// Size, largest first.
    SizeDesc,
    /// Size, smallest first.
    SizeAsc,
    /// Title A to Z.
    TitleAsc,
    /// Title Z to A.
    TitleDesc,
}

/// Search parameters. Every field is optional and combined with AND.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// Free text (analyzed by the search index; never SQL).
    pub q: Option<String>,
    /// Category ids; a parent id also matches its children.
    pub categories: Vec<u32>,
    /// Category ids whose releases are never returned or counted (exact ids: the caller passes
    /// a parent together with its children). Applied in SQL, so `total` and pagination stay
    /// consistent; used by the `ui.show_xxx = false` display rule.
    pub exclude_categories: Vec<u32>,
    /// Posted at or after (Unix seconds).
    pub since: Option<i64>,
    /// Posted at or before (Unix seconds).
    pub until: Option<i64>,
    /// Minimum total bytes.
    pub min_bytes: Option<u64>,
    /// Maximum total bytes.
    pub max_bytes: Option<u64>,
    /// All of these flags must be set.
    pub flags: ReleaseFlags,
    /// Scene family.
    pub family: Option<String>,
    /// Scene resolution.
    pub resolution: Option<String>,
    /// Scene source.
    pub source: Option<String>,
    /// Scene year.
    pub year: Option<u32>,
    /// Release group (case-insensitive).
    pub group: Option<String>,
    /// Sort order.
    pub sort: SortKey,
    /// Rows to skip.
    pub offset: u32,
    /// Page size, clamped to `1..=100`.
    pub limit: u32,
}

/// One page of results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// Rows of this page.
    pub items: Vec<T>,
    /// Total rows matching the filters.
    pub total: u64,
    /// Offset used.
    pub offset: u32,
    /// Effective (clamped) limit.
    pub limit: u32,
}

pub(crate) fn to_i64(v: u64, what: &'static str) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn file_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<ReleaseFile, StoreError> {
    Ok(ReleaseFile {
        idx: from_i64(r.try_get("idx")?, "idx")?,
        subject: r.try_get("subject")?,
        filename: r.try_get("filename")?,
        kind: r.try_get("kind")?,
        poster: r.try_get("poster")?,
        posted_at: r.try_get("posted_at")?,
        bytes: from_i64(r.try_get("bytes")?, "bytes")?,
        segment_count: from_i64(r.try_get("segment_count")?, "segment_count")?,
        declared_segments: opt_u32(r.try_get("declared_segments")?, "declared")?,
        missing_ranges: r.try_get("missing_ranges")?,
        groups: r.try_get("groups")?,
    })
}

fn from_i64<T: TryFrom<i64>>(v: i64, what: &'static str) -> Result<T, StoreError> {
    T::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn opt_u32(v: Option<i64>, what: &'static str) -> Result<Option<u32>, StoreError> {
    v.map(|x| from_i64(x, what)).transpose()
}

pub(crate) fn release_from_row(row: &SqliteRow) -> Result<ReleaseRow, StoreError> {
    let sha: Vec<u8> = row.try_get("sha256")?;
    let sha: [u8; 32] = sha
        .try_into()
        .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
    let src: String = row.try_get("category_source")?;
    Ok(ReleaseRow {
        id: row.try_get("id")?,
        sha256: Sha256(sha),
        title: row.try_get("title")?,
        category_id: from_i64(row.try_get("category_id")?, "category_id")?,
        category_overridden: row.try_get::<i64, _>("category_overridden")? != 0,
        category_source: CategorySource::parse(&src)
            .ok_or(StoreError::OutOfRange("category_source"))?,
        posted_at: row.try_get("posted_at")?,
        ingested_at: row.try_get("ingested_at")?,
        total_bytes: from_i64(row.try_get("total_bytes")?, "total_bytes")?,
        poster: row.try_get("poster")?,
        file_count: from_i64(row.try_get("file_count")?, "file_count")?,
        segment_count: from_i64(row.try_get("segment_count")?, "segment_count")?,
        missing_segment_count: from_i64(row.try_get("missing_segment_count")?, "missing")?,
        par2_blocks: from_i64(row.try_get("par2_blocks")?, "par2_blocks")?,
        flags: ReleaseFlags::from_bits_truncate(from_i64(row.try_get("flags")?, "flags")?),
        nzb_size_bytes: from_i64(row.try_get("nzb_size_bytes")?, "nzb_size_bytes")?,
        source_name: row.try_get("source_name")?,
        source_label: row.try_get("source_label")?,
        // An unknown stored value (the CHECK prevents it) degrades to "unknown", never an error.
        origin: row
            .try_get::<Option<String>, _>("origin")?
            .as_deref()
            .and_then(IngestOrigin::parse),
        meta_json: row.try_get("meta_json")?,
        scene: SceneColumns {
            family: row.try_get("scene_family")?,
            year: opt_u32(row.try_get("scene_year")?, "scene_year")?,
            season: opt_u32(row.try_get("scene_season")?, "scene_season")?,
            episode: opt_u32(row.try_get("scene_episode")?, "scene_episode")?,
            resolution: row.try_get("scene_resolution")?,
            source: row.try_get("scene_source")?,
            codec: row.try_get("scene_codec")?,
            group: row.try_get("scene_group")?,
            languages_json: row.try_get("scene_languages")?,
            json: row.try_get("scene_json")?,
        },
    })
}

/// Missing segments of a file: the larger of the recorded ranges and the gap to the declared
/// total (ranges are capped at 256 entries, so they can understate).
pub(crate) fn file_missing(f: &FileInfo) -> u64 {
    let ranges = f.missing_ranges.iter().fold(0u64, |s, (lo, hi)| {
        s.saturating_add(u64::from(hi.saturating_sub(*lo)).saturating_add(1))
    });
    let declared = f
        .declared_segments
        .map_or(0, |d| u64::from(d.saturating_sub(f.segment_count)));
    ranges.max(declared)
}

pub(crate) fn missing_ranges_json(f: &FileInfo) -> Result<Option<String>, StoreError> {
    if f.missing_ranges.is_empty() && !f.missing_truncated {
        return Ok(None);
    }
    let json_err = |_| StoreError::OutOfRange("missing_ranges json");
    let s = if f.missing_truncated {
        serde_json::to_string(&serde_json::json!({ "ranges": f.missing_ranges, "more": true }))
    } else {
        serde_json::to_string(&f.missing_ranges)
    };
    s.map(Some).map_err(json_err)
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

fn is_fk_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation)
}

async fn insert_file(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    release_id: i64,
    f: &FileInfo,
) -> Result<(), StoreError> {
    let groups = if f.groups.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&f.groups).map_err(|_| StoreError::OutOfRange("groups json"))?)
    };
    sqlx::query(
        "INSERT INTO nzb_file (release_id, idx, subject, filename, kind, poster, \
         posted_at, bytes, segment_count, declared_segments, missing_ranges, groups) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(release_id)
    .bind(i64::from(f.idx))
    .bind(&f.subject)
    .bind(f.filename.as_deref())
    .bind(f.kind.as_str())
    .bind(f.poster.as_deref())
    .bind(f.posted_at)
    .bind(to_i64(f.bytes, "file bytes")?)
    .bind(i64::from(f.segment_count))
    .bind(f.declared_segments.map(i64::from))
    .bind(missing_ranges_json(f)?)
    .bind(groups)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// One job of an ingest commit group ([`SqliteDb::insert_release_group`], `PgDb::insert_release_group`).
#[derive(Debug, Clone)]
pub struct GroupItem<'a> {
    /// The release to insert.
    pub new: NewRelease<'a>,
    /// Its `ingest_log` row, written in the same transaction (outcome forced to `ok`).
    pub log: IngestLogEntry<'a>,
    /// Who submitted it; re-validated inside the group transaction (N9).
    pub uploader: Uploader,
}

/// What a commit group did with one job (same order as the items).
#[derive(Debug)]
pub enum GroupOutcome {
    /// Committed with this release id (the blob was durable before, the source may go now).
    Inserted(i64),
    /// The digest is already indexed (or appears earlier in the same group): nothing written for this job.
    Duplicate,
    /// Not attempted: the writer hold cap was reached (SQLite). Re-submit it in a later group.
    Deferred,
    /// This job alone failed (refused uploader, unknown category, value out of range); nothing written for it.
    Failed(StoreError),
}

/// Most jobs in one commit group (`ingest.group_max_jobs` is clamped to it).
pub const MAX_GROUP_JOBS: usize = 1024;

/// Errors that belong to one job of a group (the others carry on); anything else fails the whole group.
pub(crate) fn job_scoped(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::UnknownCategory
            | StoreError::OutOfRange(_)
            | StoreError::Account(_)
            | StoreError::Duplicate
    )
}

pub(crate) fn check_group(items: &[GroupItem<'_>]) -> Result<(), StoreError> {
    if items.len() > MAX_GROUP_JOBS {
        return Err(StoreError::OutOfRange("commit group size"));
    }
    Ok(())
}

/// Uploader verdicts of one group transaction (a group holds few distinct uploaders; a linear scan is enough).
#[derive(Default)]
pub(crate) struct UploaderCache(Vec<(Uploader, i64, Result<Option<i64>, crate::AccountError>)>);

impl UploaderCache {
    pub(crate) fn get(
        &self,
        u: &Uploader,
        now: i64,
    ) -> Option<Result<Option<i64>, crate::AccountError>> {
        self.0
            .iter()
            .find(|(k, at, _)| k == u && *at == now)
            .map(|(_, _, v)| *v)
    }

    pub(crate) fn put(
        &mut self,
        u: Uploader,
        now: i64,
        v: Result<Option<i64>, crate::AccountError>,
    ) {
        self.0.push((u, now, v));
    }
}

/// Inserts one release row, its files and (when given) its `ingest_log(ok)` row inside `tx`. `Ok(None)` when the
/// digest already exists (`ON CONFLICT DO NOTHING`: the unique index arbitrates, no error, nothing written).
async fn insert_release_row(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    new: &NewRelease<'_>,
    log: Option<&IngestLogEntry<'_>>,
    added_by: Option<i64>,
) -> Result<Option<i64>, StoreError> {
    let a = new.analysis;
    let s = &new.scene;
    let missing = a
        .files
        .iter()
        .fold(0u64, |n, f| n.saturating_add(file_missing(f)));
    let label = new.source_label.and_then(clean_source_label);
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO release (sha256, title, category_id, category_overridden, posted_at, \
         ingested_at, total_bytes, poster, file_count, segment_count, missing_segment_count, \
         par2_blocks, flags, nzb_size_bytes, source_name, source_label, meta_json, category_source, \
         scene_family, scene_year, scene_season, scene_episode, scene_resolution, \
         scene_source, scene_codec, scene_group, scene_languages, scene_json, origin, added_by) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (sha256) DO NOTHING RETURNING id",
    )
    .bind(a.sha256.0.to_vec())
    .bind(&a.title)
    .bind(i64::from(new.category_id))
    .bind(a.posted_at)
    .bind(new.ingested_at)
    .bind(to_i64(a.total_bytes, "total_bytes")?)
    .bind(a.poster.as_deref())
    .bind(i64::from(a.file_count))
    .bind(to_i64(a.segment_count, "segment_count")?)
    .bind(to_i64(missing, "missing_segments")?)
    .bind(to_i64(a.par2_blocks, "par2_blocks")?)
    .bind(i64::from(a.flags.bits()))
    .bind(to_i64(new.nzb_size_bytes, "nzb_size_bytes")?)
    .bind(new.source_name)
    .bind(label.as_deref())
    .bind(new.meta_json)
    .bind(new.category_source.as_str())
    .bind(s.family.as_deref())
    .bind(s.year.map(i64::from))
    .bind(s.season.map(i64::from))
    .bind(s.episode.map(i64::from))
    .bind(s.resolution.as_deref())
    .bind(s.source.as_deref())
    .bind(s.codec.as_deref())
    .bind(s.group.as_deref())
    .bind(s.languages_json.as_deref())
    .bind(s.json.as_deref())
    // Only the logged (pipeline) path knows how the NZB arrived.
    .bind(log.map(|l| IngestOrigin::from_log_source(l.source).as_str()))
    .bind(added_by)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            StoreError::Duplicate
        } else if is_fk_violation(&e) {
            StoreError::UnknownCategory
        } else {
            StoreError::Db(e)
        }
    })?;
    let Some(id) = id else {
        return Ok(None);
    };
    for f in &a.files {
        insert_file(tx, id, f).await?;
    }
    if let Some(log) = log {
        let mut ok = *log;
        ok.outcome = LogOutcome::Ok;
        insert_log_row(tx, &ok, Some(id), added_by).await?;
    }
    Ok(Some(id))
}

impl SqliteDb {
    /// Insert a release and its files in one transaction (the outbox row is written by the release trigger).
    ///
    /// # Errors
    /// [`StoreError::Duplicate`] if the SHA-256 exists; [`StoreError::UnknownCategory`] if the
    /// category is not in the taxonomy. On any error nothing is written.
    pub async fn insert_release(&self, new: &NewRelease<'_>) -> Result<i64, StoreError> {
        self.insert_release_inner(new, None, &Uploader::Unattributed)
            .await
    }

    /// Like [`SqliteDb::insert_release`], and writes the `ingest_log` row (outcome `ok`, linked to
    /// the new release) in the **same transaction** (`INGEST_SPEC` step 6): the log never claims
    /// success for a release that was not committed, and vice versa. The entry's outcome is
    /// forced to `ok`.
    ///
    /// # Errors
    /// As [`SqliteDb::insert_release`]; nothing is written on error.
    pub async fn insert_release_logged(
        &self,
        new: &NewRelease<'_>,
        log: &IngestLogEntry<'_>,
    ) -> Result<i64, StoreError> {
        self.insert_release_inner(new, Some(log), &Uploader::Unattributed)
            .await
    }

    pub(crate) async fn insert_release_inner(
        &self,
        new: &NewRelease<'_>,
        log: Option<&IngestLogEntry<'_>>,
        uploader: &Uploader,
    ) -> Result<i64, StoreError> {
        // BEGIN IMMEDIATE: the uploader re-check and the insert are one atomic decision (N9).
        let mut tx = self.begin_immediate().await?;
        let added_by = resolve_uploader(&mut tx, uploader, new.ingested_at).await?;
        let id = insert_release_row(&mut tx, new, log, added_by)
            .await?
            .ok_or(StoreError::Duplicate)?;
        tx.commit().await?;
        self.bump_release_epoch();
        Ok(id)
    }

    /// One ingest **commit group** (ARCHITECTURE v3 5, T114): the jobs of `items` in one writer transaction, each
    /// job inside its own savepoint so a job that fails (refused uploader, unknown category, value out of range)
    /// leaves the others intact. The uploader of every job is re-validated inside the transaction (N9).
    ///
    /// **Writer hold cap (review 34 L5):** SQLite has one writer, shared with logins, revocations and every account
    /// write. Once the transaction has held the writer for `hold`, the remaining jobs are answered
    /// [`GroupOutcome::Deferred`] (nothing written for them) and the transaction commits; the caller re-submits them
    /// in its next group, after waiting writers had their turn. The first job always runs, so a group always makes
    /// progress.
    ///
    /// # Errors
    /// Database failures that are not about one job (I/O, busy timeout): nothing is written then. More than
    /// [`crate::MAX_GROUP_JOBS`] items: [`StoreError::OutOfRange`].
    pub async fn insert_release_group(
        &self,
        items: &[GroupItem<'_>],
        hold: Duration,
    ) -> Result<Vec<GroupOutcome>, StoreError> {
        check_group(items)?;
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.begin_immediate().await?;
        // The hold is counted from the moment the writer is ours, not from the wait for it.
        let writer_since = Instant::now();
        let mut out = Vec::with_capacity(items.len());
        let mut uploaders = UploaderCache::default();
        let mut inserted = false;
        for (i, it) in items.iter().enumerate() {
            if i > 0 && writer_since.elapsed() >= hold {
                out.push(GroupOutcome::Deferred);
                continue;
            }
            let added_by = if let Some(r) = uploaders.get(&it.uploader, it.new.ingested_at) {
                r
            } else {
                let r = match resolve_uploader(&mut tx, &it.uploader, it.new.ingested_at).await {
                    Ok(v) => Ok(v),
                    Err(StoreError::Account(a)) => Err(a),
                    Err(e) => return Err(e),
                };
                uploaders.put(it.uploader, it.new.ingested_at, r);
                r
            };
            let added_by = match added_by {
                Ok(v) => v,
                Err(a) => {
                    out.push(GroupOutcome::Failed(StoreError::Account(a)));
                    continue;
                }
            };
            // A savepoint per job: a failing job is rolled back alone.
            let mut sp = sqlx::Acquire::begin(&mut tx).await?;
            match insert_release_row(&mut sp, &it.new, Some(&it.log), added_by).await {
                Ok(Some(id)) => {
                    sp.commit().await?;
                    inserted = true;
                    out.push(GroupOutcome::Inserted(id));
                }
                Ok(None) => {
                    sp.rollback().await?;
                    out.push(GroupOutcome::Duplicate);
                }
                Err(e) if job_scoped(&e) => {
                    sp.rollback().await?;
                    out.push(GroupOutcome::Failed(e));
                }
                Err(e) => return Err(e),
            }
        }
        tx.commit().await?;
        if inserted {
            self.bump_release_epoch();
        }
        Ok(out)
    }

    /// Fetch a release by id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_release(&self, id: i64) -> Result<Option<ReleaseRow>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            sqlite_release_cols!(),
            " FROM release r WHERE r.id = ?"
        ))
        .bind(id)
        .fetch_optional(self.readers())
        .await?;
        row.as_ref().map(release_from_row).transpose()
    }

    /// Fetch a release by hex SHA-256. Malformed hex yields `None` (never reaches SQL).
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_release_by_sha(&self, hex: &str) -> Result<Option<ReleaseRow>, StoreError> {
        let Ok(sha) = Sha256::from_hex(hex) else {
            return Ok(None);
        };
        let row = sqlx::query(concat!(
            "SELECT ",
            sqlite_release_cols!(),
            " FROM release r WHERE r.sha256 = ?"
        ))
        .bind(sha.0.to_vec())
        .fetch_optional(self.readers())
        .await?;
        row.as_ref().map(release_from_row).transpose()
    }

    /// `ingested_at` of the newest release row (`None` for an empty database): the highest id, like
    /// Postgres (same seam answer whatever the clock did; the GC consumer errs on the safe side).
    ///
    /// # Errors
    /// Database errors.
    pub async fn newest_ingested_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT ingested_at FROM release ORDER BY id DESC LIMIT 1")
                .fetch_optional(self.readers())
                .await?,
        )
    }

    /// SHA-256 of every release row: the referenced set for `FsStore::gc`. Read it as late as
    /// possible before collecting, and pass `gc_checked` a per-blob re-check as well.
    ///
    /// # Errors
    /// Database errors, or a stored digest with the wrong length.
    pub async fn list_shas(&self) -> Result<HashSet<Sha256>, StoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sha256 FROM release")
            .fetch_all(self.readers())
            .await?;
        rows.into_iter()
            .map(|v| {
                <[u8; 32]>::try_from(v)
                    .map(Sha256)
                    .map_err(|_| StoreError::OutOfRange("sha256 length"))
            })
            .collect()
    }

    /// Files of a release in NZB order (all of them; prefer [`SqliteDb::list_files_page`] in the UI).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_files(&self, release_id: i64) -> Result<Vec<ReleaseFile>, StoreError> {
        self.list_files_page(release_id, 0, u32::MAX).await
    }

    /// `limit` files of a release starting at row `offset`, in NZB order (SQL `LIMIT/OFFSET`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_files_page(
        &self,
        release_id: i64,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ReleaseFile>, StoreError> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            file_cols_sql!(),
            " FROM nzb_file WHERE release_id = ? ORDER BY idx LIMIT ? OFFSET ?"
        ))
        .bind(release_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.readers())
        .await?;
        rows.iter().map(file_from_row).collect()
    }

    /// One file of a release by its index.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_file(
        &self,
        release_id: i64,
        idx: u32,
    ) -> Result<Option<ReleaseFile>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            file_cols_sql!(),
            " FROM nzb_file WHERE release_id = ? AND idx = ?"
        ))
        .bind(release_id)
        .bind(i64::from(idx))
        .fetch_optional(self.readers())
        .await?;
        row.as_ref().map(file_from_row).transpose()
    }

    /// Up to `limit` distinct newsgroups across all files of a release, sorted.
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_release_groups(
        &self,
        release_id: i64,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        // `json_valid` guards rows whose column is not JSON; they contribute no groups.
        let rows = sqlx::query(
            "SELECT DISTINCT j.value AS g FROM nzb_file f, \
             json_each(CASE WHEN json_valid(f.groups) THEN f.groups ELSE '[]' END) j \
             WHERE f.release_id = ? AND j.type = 'text' ORDER BY g LIMIT ?",
        )
        .bind(release_id)
        .bind(i64::from(limit))
        .fetch_all(self.readers())
        .await?;
        rows.iter()
            .map(|r| r.try_get("g").map_err(StoreError::from))
            .collect()
    }

    /// Manually set the category (marks `category_overridden` and source `manual`).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown release, [`StoreError::UnknownCategory`] for an
    /// unknown category.
    pub async fn set_category(&self, id: i64, category_id: u32) -> Result<(), StoreError> {
        let res = sqlx::query(
            "UPDATE release SET category_id = ?, category_overridden = 1, \
             category_source = 'manual', flags = flags & ~512 WHERE id = ?",
        )
        .bind(i64::from(category_id))
        .bind(id)
        .execute(self.writer())
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                StoreError::UnknownCategory
            } else {
                StoreError::Db(e)
            }
        })?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        self.bump_release_epoch();
        Ok(())
    }

    /// Delete a release with its files (cascade) in one transaction (the outbox row is written by the trigger).
    /// Ingest-log rows keep existing with `release_id` set to NULL.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the release does not exist.
    pub async fn delete_release(&self, id: i64) -> Result<(), StoreError> {
        let mut tx = self.writer().begin().await?;
        // A hard delete (operator/test path) takes the NFO with it (T140).
        sqlx::query(
            "DELETE FROM release_nfo WHERE sha256 = (SELECT sha256 FROM release WHERE id = ?)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        let res = sqlx::query("DELETE FROM release WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        self.bump_release_epoch();
        Ok(())
    }
}
