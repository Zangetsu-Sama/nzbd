//! Releases, files, attribution, trash and category statistics on Postgres (T112; 2.x `release.rs`,
//! `attribution.rs`, `trash.rs`; `DATA_MODEL` v3 sections 3.1, 7; ARCHITECTURE v3 sections 3.1, 6).
//!
//! Every transaction that creates a release, changes an indexed field of one or removes one also writes, in the SAME
//! transaction, one `search_outbox` row per release (payload-free: the indexer reads the current state, SEC-092), the
//! `category_stats` deltas (exact tiles without a scan) and, for edits, bumps `release.index_version`. Locks follow the
//! global order: the acting account then session rows `FOR SHARE` (re-validation, N9), release rows `FOR UPDATE` in ascending id,
//! `category_stats` rows in ascending category id, the audit chain state last (`audit_append`).
//!
//! Listing, sorting, text search and counts are not here: they belong to the search index (T113, `nzb-search`); this
//! module offers [`PgDb::hydrate`] (rows by id, with the visibility re-check) and the bounded degraded browse.

use std::collections::HashSet;

use nzb_core::{FileInfo, ReleaseFlags, Sha256};
use serde_json::json;
use sqlx::{PgConnection, Row};

use crate::StoreError;
use crate::account::{AccountActor, AccountError, AuditActor, Role};
use crate::attribution::{ReleaseAttribution, TrashActor, Uploader, key_usable};
use crate::ingest_log::{IngestLogEntry, LogOutcome};
use crate::pg::PgDb;
use crate::pg::account::{write_audit, write_audit_legacy};
use crate::pg::ingest_log::{insert_log_row, insert_log_rows};
use crate::release::{
    CategorySource, GroupItem, GroupOutcome, IngestOrigin, NewRelease, ReleaseFile, ReleaseRow,
    SceneColumns, UploaderCache, check_group, clean_source_label, file_missing,
    missing_ranges_json, to_i64,
};
use crate::trash::TrashRow;

/// Width of one `nzb_file` partition (mirrors `nzbd.ensure_file_partitions`).
const SPAN: i64 = crate::pg::FILE_PARTITION_SPAN;
/// The writer makes sure the next partition exists once an id comes this close to the covered bound.
const HEADROOM: i64 = 1_000_000;
pub use crate::search_source::{DEGRADED_SCAN_BUDGET, DegradedPage};

/// Release columns read by every row decoder (a macro so complete statements stay compile-time literals, SEC-088).
macro_rules! release_cols {
    () => {
        "r.id, r.sha256, r.title, r.category_id, r.category_overridden, r.category_source, r.posted_at, \
         r.ingested_at, r.total_bytes, r.poster, r.file_count, r.segment_count, r.missing_segment_count, \
         r.par2_blocks, r.flags, r.nzb_size_bytes, r.source_name, r.source_label, r.origin, r.meta_json, \
         r.scene_family, r.scene_year, r.scene_season, r.scene_episode, r.scene_resolution, r.scene_source, \
         r.scene_codec, r.scene_group, r.scene_languages, r.scene_json"
    };
}

pub(crate) use release_cols;

macro_rules! file_cols {
    () => {
        "idx, subject, filename, kind, poster, posted_at, bytes, segment_count, declared_segments, \
         missing_ranges, groups"
    };
}

macro_rules! trash_cols {
    () => {
        "id, original_id, sha256, title, category_id, total_bytes, nzb_size_bytes, file_count, source_name, \
         ingested_at, deleted_at"
    };
}

fn nonneg<T: TryFrom<i64>>(v: i64, what: &'static str) -> Result<T, StoreError> {
    T::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn u32_of(v: i32, what: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn opt_u32_of(v: Option<i32>, what: &'static str) -> Result<Option<u32>, StoreError> {
    v.map(|x| u32_of(x, what)).transpose()
}

fn sha_of(v: Vec<u8>) -> Result<Sha256, StoreError> {
    <[u8; 32]>::try_from(v)
        .map(Sha256)
        .map_err(|_| StoreError::OutOfRange("sha256 length"))
}

pub(crate) fn release_from_row(row: &sqlx::postgres::PgRow) -> Result<ReleaseRow, StoreError> {
    let src: String = row.try_get("category_source")?;
    Ok(ReleaseRow {
        id: row.try_get("id")?,
        sha256: sha_of(row.try_get("sha256")?)?,
        title: row.try_get("title")?,
        category_id: u32_of(row.try_get("category_id")?, "category_id")?,
        category_overridden: row.try_get("category_overridden")?,
        category_source: CategorySource::parse(&src)
            .ok_or(StoreError::OutOfRange("category_source"))?,
        posted_at: row.try_get("posted_at")?,
        ingested_at: row.try_get("ingested_at")?,
        total_bytes: nonneg(row.try_get("total_bytes")?, "total_bytes")?,
        poster: row.try_get("poster")?,
        file_count: u32_of(row.try_get("file_count")?, "file_count")?,
        segment_count: nonneg(row.try_get("segment_count")?, "segment_count")?,
        missing_segment_count: nonneg(row.try_get("missing_segment_count")?, "missing")?,
        par2_blocks: nonneg(row.try_get("par2_blocks")?, "par2_blocks")?,
        flags: ReleaseFlags::from_bits_truncate(u32_of(row.try_get("flags")?, "flags")?),
        nzb_size_bytes: nonneg(row.try_get("nzb_size_bytes")?, "nzb_size_bytes")?,
        source_name: row.try_get("source_name")?,
        source_label: row.try_get("source_label")?,
        origin: row
            .try_get::<Option<String>, _>("origin")?
            .as_deref()
            .and_then(IngestOrigin::parse),
        meta_json: row.try_get("meta_json")?,
        scene: SceneColumns {
            family: row.try_get("scene_family")?,
            year: row
                .try_get::<Option<i16>, _>("scene_year")?
                .map(|y| u32::try_from(y).map_err(|_| StoreError::OutOfRange("scene_year")))
                .transpose()?,
            season: opt_u32_of(row.try_get("scene_season")?, "scene_season")?,
            episode: opt_u32_of(row.try_get("scene_episode")?, "scene_episode")?,
            resolution: row.try_get("scene_resolution")?,
            source: row.try_get("scene_source")?,
            codec: row.try_get("scene_codec")?,
            group: row.try_get("scene_group")?,
            languages_json: row.try_get("scene_languages")?,
            json: row.try_get("scene_json")?,
        },
        // v3 keeps NZB blobs on the filesystem only (D33 c).
    })
}

fn file_from_row(r: &sqlx::postgres::PgRow) -> Result<ReleaseFile, StoreError> {
    Ok(ReleaseFile {
        idx: u32_of(r.try_get("idx")?, "idx")?,
        subject: r.try_get("subject")?,
        filename: r.try_get("filename")?,
        kind: r.try_get("kind")?,
        poster: r.try_get("poster")?,
        posted_at: r.try_get("posted_at")?,
        bytes: nonneg(r.try_get("bytes")?, "bytes")?,
        segment_count: u32_of(r.try_get("segment_count")?, "segment_count")?,
        declared_segments: opt_u32_of(r.try_get("declared_segments")?, "declared")?,
        missing_ranges: r.try_get("missing_ranges")?,
        groups: r.try_get("groups")?,
    })
}

fn trash_from_row(row: &sqlx::postgres::PgRow) -> Result<TrashRow, StoreError> {
    Ok(TrashRow {
        id: row.try_get("id")?,
        original_id: row.try_get("original_id")?,
        sha256: sha_of(row.try_get("sha256")?)?,
        title: row.try_get("title")?,
        category_id: u32_of(row.try_get("category_id")?, "category_id")?,
        total_bytes: nonneg(row.try_get("total_bytes")?, "total_bytes")?,
        nzb_size_bytes: nonneg(row.try_get("nzb_size_bytes")?, "nzb_size_bytes")?,
        file_count: u32_of(row.try_get("file_count")?, "file_count")?,
        source_name: row.try_get("source_name")?,
        ingested_at: row.try_get("ingested_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

fn is_fk_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation)
}

fn cat_i32(category_id: u32) -> Result<i32, StoreError> {
    i32::try_from(category_id).map_err(|_| StoreError::UnknownCategory)
}

/// One change of the per-category totals.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StatDelta {
    pub(crate) category: i32,
    pub(crate) releases: i64,
    pub(crate) files: i64,
    pub(crate) segments: i64,
    pub(crate) bytes: i64,
}

impl StatDelta {
    fn of(category: i32, file_count: i64, segments: i64, bytes: i64, sign: i64) -> Self {
        Self {
            category,
            releases: sign,
            files: file_count.saturating_mul(sign),
            segments: segments.saturating_mul(sign),
            bytes: bytes.saturating_mul(sign),
        }
    }
}

/// Applies `deltas` to `category_stats`: merged per category, rows locked in ascending category id first (lock order
/// 3 of ARCHITECTURE v3 section 6, so two writers never wait on each other in opposite orders), then one array-bound
/// `UPDATE`.
pub(crate) async fn apply_stats(
    conn: &mut PgConnection,
    deltas: &[StatDelta],
) -> Result<(), StoreError> {
    let mut merged: Vec<StatDelta> = Vec::new();
    for d in deltas {
        if let Some(m) = merged.iter_mut().find(|m| m.category == d.category) {
            m.releases = m.releases.saturating_add(d.releases);
            m.files = m.files.saturating_add(d.files);
            m.segments = m.segments.saturating_add(d.segments);
            m.bytes = m.bytes.saturating_add(d.bytes);
        } else {
            merged.push(*d);
        }
    }
    merged.retain(|d| d.releases != 0 || d.files != 0 || d.segments != 0 || d.bytes != 0);
    if merged.is_empty() {
        return Ok(());
    }
    merged.sort_by_key(|d| d.category);
    let cats: Vec<i32> = merged.iter().map(|d| d.category).collect();
    sqlx::query(
        "SELECT category_id FROM category_stats WHERE category_id = ANY($1) ORDER BY category_id FOR UPDATE",
    )
    .bind(&cats)
    .fetch_all(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE category_stats c SET releases = c.releases + d.r, files = c.files + d.f, \
         segments = c.segments + d.s, bytes = c.bytes + d.b \
         FROM unnest($1::integer[], $2::bigint[], $3::bigint[], $4::bigint[], $5::bigint[]) AS d(cat, r, f, s, b) \
         WHERE c.category_id = d.cat",
    )
    .bind(&cats)
    .bind(merged.iter().map(|d| d.releases).collect::<Vec<_>>())
    .bind(merged.iter().map(|d| d.files).collect::<Vec<_>>())
    .bind(merged.iter().map(|d| d.segments).collect::<Vec<_>>())
    .bind(merged.iter().map(|d| d.bytes).collect::<Vec<_>>())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Announces changed (or removed) releases to the search indexer: one payload-free outbox row each, in the caller's
/// transaction (ARCHITECTURE v3 section 3.1, SEC-092). `enqueued_at` is the database clock (the lag metric's).
pub(crate) async fn enqueue_outbox(conn: &mut PgConnection, ids: &[i64]) -> Result<(), StoreError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO search_outbox (release_id, enqueued_at) SELECT u, nzbd.db_clock() FROM unnest($1::bigint[]) AS u",
    )
    .bind(ids)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Re-validates an acting account INSIDE the transaction and holds a share lock on its row until the commit, so a
/// concurrent disable/demotion waits for this edit (and an edit after it sees the new state). The role is the
/// database's.
pub(crate) async fn require_actor_share(
    conn: &mut PgConnection,
    actor_id: i64,
    min: Role,
) -> Result<crate::account::Subject, StoreError> {
    let row = sqlx::query(
        "SELECT id, username, role, disabled_at FROM account WHERE id = $1 AND deleted_at IS NULL FOR SHARE",
    )
    .bind(actor_id)
    .fetch_optional(&mut *conn)
    .await?;
    let s = row
        .map(|r| -> Result<crate::account::Subject, StoreError> {
            Ok(crate::account::Subject {
                id: r.try_get("id")?,
                role: crate::account::role_from(&r.try_get::<String, _>("role")?)?,
                username: r.try_get("username")?,
                disabled: r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
            })
        })
        .transpose()?;
    match s {
        Some(s) if !s.disabled && s.role >= min => Ok(s),
        _ => Err(AccountError::Forbidden.into()),
    }
}

/// Locks the account before its browser session, keeping revocation serialized with the mutation.
/// A missing session is reserved for trusted operator/internal callers.
pub(crate) async fn require_session_actor_share(
    conn: &mut PgConnection,
    actor: &AccountActor,
    min: Role,
    now: i64,
) -> Result<crate::account::Subject, StoreError> {
    let account = require_actor_share(conn, actor.user_id, min).await?;
    if let Some(hash) = &actor.session
        && !crate::pg::auth::session_is_live(conn, hash, actor.user_id, now).await?
    {
        return Err(AccountError::Forbidden.into());
    }
    Ok(account)
}

/// Validates the uploader inside `conn` and returns the account to record (`None` = unattributed). The key row and
/// its owner's row are share-locked until the commit (N9 on Postgres: a concurrent revoke or disable waits for this
/// upload, and an upload after it is refused).
///
/// # Errors
/// [`AccountError::Forbidden`], [`AccountError::KeyRefused`].
pub(crate) async fn resolve_uploader(
    conn: &mut PgConnection,
    uploader: &Uploader,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    match *uploader {
        Uploader::Unattributed => Ok(None),
        Uploader::Account(id) => {
            let a = require_actor_share(conn, id, Role::Uploader).await?;
            Ok(Some(a.id))
        }
        Uploader::Session { user_id, id_hash } => {
            let a = require_actor_share(conn, user_id, Role::Uploader).await?;
            if !crate::pg::auth::session_is_live(conn, &id_hash, user_id, now).await? {
                return Err(AccountError::Forbidden.into());
            }
            Ok(Some(a.id))
        }
        Uploader::ApiKey(key_id) => {
            let row = sqlx::query(
                "SELECT k.owner_id, k.scope, u.role, u.disabled_at, u.deleted_at FROM api_key k \
                 JOIN account u ON u.id = k.owner_id \
                 WHERE k.id = $1 AND k.revoked_at IS NULL FOR SHARE OF k, u",
            )
            .bind(key_id)
            .fetch_optional(&mut *conn)
            .await?;
            let Some(r) = row else {
                return Err(AccountError::KeyRefused.into());
            };
            let owner: Option<i64> = r.try_get("owner_id")?;
            let role: Option<String> = r.try_get("role")?;
            let scope: String = r.try_get("scope")?;
            let usable = key_usable(
                &scope,
                role.as_deref(),
                r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
                r.try_get::<Option<i64>, _>("deleted_at")?.is_some(),
            );
            match owner {
                Some(id) if usable => Ok(Some(id)),
                _ => Err(AccountError::KeyRefused.into()),
            }
        }
    }
}

/// Inserts every file of a release with one array-bound statement (no per-row round trip, no SQL built from data).
async fn insert_files(
    conn: &mut PgConnection,
    release_id: i64,
    files: &[FileInfo],
) -> Result<(), StoreError> {
    let rows: Vec<(i64, &FileInfo)> = files.iter().map(|f| (release_id, f)).collect();
    insert_file_rows(conn, &rows).await
}

/// Inserts file rows of one or several releases (a commit group) with one array-bound statement.
async fn insert_file_rows(
    conn: &mut PgConnection,
    rows: &[(i64, &FileInfo)],
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let n = rows.len();
    let mut release = Vec::with_capacity(n);
    let mut idx = Vec::with_capacity(n);
    let mut subject = Vec::with_capacity(n);
    let mut filename: Vec<Option<String>> = Vec::with_capacity(n);
    let mut kind = Vec::with_capacity(n);
    let mut poster: Vec<Option<String>> = Vec::with_capacity(n);
    let mut posted_at: Vec<Option<i64>> = Vec::with_capacity(n);
    let mut bytes = Vec::with_capacity(n);
    let mut segs = Vec::with_capacity(n);
    let mut declared: Vec<Option<i32>> = Vec::with_capacity(n);
    let mut missing: Vec<Option<String>> = Vec::with_capacity(n);
    let mut groups: Vec<Option<String>> = Vec::with_capacity(n);
    for (release_id, f) in rows {
        release.push(*release_id);
        idx.push(i32::try_from(f.idx).map_err(|_| StoreError::OutOfRange("file idx"))?);
        subject.push(f.subject.clone());
        filename.push(f.filename.clone());
        kind.push(f.kind.as_str().to_owned());
        poster.push(f.poster.clone());
        posted_at.push(f.posted_at);
        bytes.push(to_i64(f.bytes, "file bytes")?);
        segs.push(
            i32::try_from(f.segment_count).map_err(|_| StoreError::OutOfRange("segment_count"))?,
        );
        declared.push(
            f.declared_segments
                .map(i32::try_from)
                .transpose()
                .map_err(|_| StoreError::OutOfRange("declared_segments"))?,
        );
        missing.push(missing_ranges_json(f)?);
        groups.push(if f.groups.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&f.groups)
                    .map_err(|_| StoreError::OutOfRange("groups json"))?,
            )
        });
    }
    sqlx::query(
        "INSERT INTO nzb_file (release_id, idx, subject, filename, kind, poster, posted_at, bytes, segment_count, \
         declared_segments, missing_ranges, groups) \
         SELECT * FROM unnest($1::bigint[], $2::integer[], $3::text[], $4::text[], $5::text[], $6::text[], \
         $7::bigint[], $8::bigint[], $9::integer[], $10::integer[], $11::text[], $12::text[])",
    )
    .bind(&release)
    .bind(&idx)
    .bind(&subject)
    .bind(&filename)
    .bind(&kind)
    .bind(&poster)
    .bind(&posted_at)
    .bind(&bytes)
    .bind(&segs)
    .bind(&declared)
    .bind(&missing)
    .bind(&groups)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The column arrays of a group's release rows (one entry per job, bound as typed arrays, SEC-088).
#[derive(Default)]
struct ReleaseArrays {
    sha: Vec<Vec<u8>>,
    title: Vec<String>,
    category: Vec<i32>,
    posted_at: Vec<Option<i64>>,
    ingested_at: Vec<i64>,
    total_bytes: Vec<i64>,
    poster: Vec<Option<String>>,
    file_count: Vec<i32>,
    segment_count: Vec<i64>,
    missing: Vec<i64>,
    par2: Vec<i64>,
    flags: Vec<i32>,
    nzb_size: Vec<i64>,
    source_name: Vec<Option<String>>,
    source_label: Vec<Option<String>>,
    meta_json: Vec<Option<String>>,
    category_source: Vec<String>,
    family: Vec<Option<String>>,
    year: Vec<Option<i16>>,
    season: Vec<Option<i32>>,
    episode: Vec<Option<i32>>,
    resolution: Vec<Option<String>>,
    scene_source: Vec<Option<String>>,
    codec: Vec<Option<String>>,
    group: Vec<Option<String>>,
    languages: Vec<Option<String>>,
    scene_json: Vec<Option<String>>,
    origin: Vec<Option<String>>,
    added_by: Vec<Option<i64>>,
}

impl ReleaseArrays {
    /// Converts one job (every range check of the single-row insert; an error belongs to that job).
    fn push(&mut self, it: &GroupItem<'_>, added_by: Option<i64>) -> Result<(), StoreError> {
        let new = &it.new;
        let a = new.analysis;
        let s = &new.scene;
        let missing = a
            .files
            .iter()
            .fold(0u64, |n, f| n.saturating_add(file_missing(f)));
        // Convert everything first, push afterwards: a conversion error must not leave the arrays ragged.
        let category = cat_i32(new.category_id)?;
        let total = to_i64(a.total_bytes, "total_bytes")?;
        let file_count =
            i32::try_from(a.file_count).map_err(|_| StoreError::OutOfRange("file_count"))?;
        let segments = to_i64(a.segment_count, "segment_count")?;
        let missing = to_i64(missing, "missing_segments")?;
        let par2 = to_i64(a.par2_blocks, "par2_blocks")?;
        let flags = i32::try_from(a.flags.bits()).map_err(|_| StoreError::OutOfRange("flags"))?;
        let size = to_i64(new.nzb_size_bytes, "nzb_size_bytes")?;
        let year = s
            .year
            .map(i16::try_from)
            .transpose()
            .map_err(|_| StoreError::OutOfRange("scene_year"))?;
        let season = s
            .season
            .map(i32::try_from)
            .transpose()
            .map_err(|_| StoreError::OutOfRange("scene_season"))?;
        let episode = s
            .episode
            .map(i32::try_from)
            .transpose()
            .map_err(|_| StoreError::OutOfRange("scene_episode"))?;
        self.sha.push(a.sha256.0.to_vec());
        self.title.push(a.title.clone());
        self.category.push(category);
        self.posted_at.push(a.posted_at);
        self.ingested_at.push(new.ingested_at);
        self.total_bytes.push(total);
        self.poster.push(a.poster.clone());
        self.file_count.push(file_count);
        self.segment_count.push(segments);
        self.missing.push(missing);
        self.par2.push(par2);
        self.flags.push(flags);
        self.nzb_size.push(size);
        self.source_name.push(new.source_name.map(str::to_owned));
        self.source_label
            .push(new.source_label.and_then(clean_source_label));
        self.meta_json.push(new.meta_json.map(str::to_owned));
        self.category_source
            .push(new.category_source.as_str().to_owned());
        self.family.push(s.family.clone());
        self.year.push(year);
        self.season.push(season);
        self.episode.push(episode);
        self.resolution.push(s.resolution.clone());
        self.scene_source.push(s.source.clone());
        self.codec.push(s.codec.clone());
        self.group.push(s.group.clone());
        self.languages.push(s.languages_json.clone());
        self.scene_json.push(s.json.clone());
        self.origin.push(Some(
            IngestOrigin::from_log_source(it.log.source)
                .as_str()
                .to_owned(),
        ));
        self.added_by.push(added_by);
        Ok(())
    }
}

/// Exclusive upper bound of the ids covered after `ensure_file_partitions(id)` (partitions `0..=ceil(id/span)`).
fn covered_upper(id: i64) -> i64 {
    id.saturating_add(SPAN.saturating_sub(1))
        .checked_div(SPAN)
        .unwrap_or(0)
        .saturating_add(1)
        .saturating_mul(SPAN)
}

/// The file insert found no partition for its release id (`23514`, "no partition of relation ... found for row").
fn is_missing_partition(e: &StoreError) -> bool {
    match e {
        StoreError::Db(sqlx::Error::Database(d)) => {
            d.code().as_deref() == Some("23514") && d.message().contains("no partition of relation")
        }
        _ => false,
    }
}

/// The visible-or-not decision shared by hydration and the by-id paths.
fn excluded(category_id: u32, exclude: &[u32]) -> bool {
    exclude.contains(&category_id)
}

impl PgDb {
    /// Inserts a release and its files in one transaction.
    ///
    /// # Errors
    /// [`StoreError::Duplicate`] if the SHA-256 exists; [`StoreError::UnknownCategory`]; nothing is written on error.
    pub async fn insert_release(&self, new: &NewRelease<'_>) -> Result<i64, StoreError> {
        self.insert_release_inner(new, None, &Uploader::Unattributed)
            .await
    }

    /// Like [`PgDb::insert_release`], writing the `ingest_log` row (outcome forced to `ok`) in the same transaction
    /// (`INGEST_SPEC` step 6).
    ///
    /// # Errors
    /// As [`PgDb::insert_release`].
    pub async fn insert_release_logged(
        &self,
        new: &NewRelease<'_>,
        log: &IngestLogEntry<'_>,
    ) -> Result<i64, StoreError> {
        self.insert_release_inner(new, Some(log), &Uploader::Unattributed)
            .await
    }

    /// [`PgDb::insert_release_logged`] recording the uploader after re-validating it in the transaction (N9).
    ///
    /// # Errors
    /// As [`PgDb::insert_release`]; [`AccountError::Forbidden`] / [`AccountError::KeyRefused`].
    pub async fn insert_release_as(
        &self,
        new: &NewRelease<'_>,
        log: Option<&IngestLogEntry<'_>>,
        uploader: &Uploader,
    ) -> Result<i64, StoreError> {
        self.insert_release_inner(new, log, uploader).await
    }

    /// Partition upkeep happens BEFORE the insert transaction, in its own short transaction (`SECURITY_REVIEW` 31 M1):
    /// creating a partition needs a lock on `release` that an in-flight ingest holds, so it must never run inside a
    /// transaction that already wrote to `release`. A missing partition (the sequence jumped past the headroom, e.g.
    /// another process inserted a million releases) makes the file insert fail cleanly; the partitions are then
    /// created and the whole insert is retried once.
    pub(crate) async fn insert_release_inner(
        &self,
        new: &NewRelease<'_>,
        log: Option<&IngestLogEntry<'_>>,
        uploader: &Uploader,
    ) -> Result<i64, StoreError> {
        let upper = self.partition_upper();
        if upper == 0 || self.last_release_id().saturating_add(HEADROOM) >= upper {
            self.ensure_file_partitions_ahead().await?;
        }
        match self.insert_release_once(new, log, uploader).await {
            Err(e) if is_missing_partition(&e) => {
                self.ensure_file_partitions_ahead().await?;
                self.insert_release_once(new, log, uploader).await
            }
            other => other,
        }
    }

    /// One ingest **commit group** (ARCHITECTURE v3 5, T114) in one transaction on the `ingest` pool: (a) every
    /// distinct uploader re-validated and share-locked until the commit (N9; a refused one fails just its jobs),
    /// (b) one array-bound `INSERT ... SELECT FROM unnest(...) WITH ORDINALITY ... ORDER BY ord ON CONFLICT (sha256)
    /// DO NOTHING RETURNING` for the release rows (the unique index arbitrates races; rows explicitly in digest order,
    /// so two concurrent groups take the index entries in the same order, review 38 I2), (c) the file rows, `category_stats`, outbox and `ingest_log` rows with one
    /// statement each, (d) `COMMIT` (`synchronous_commit = on`). `hold` is not used: Postgres writers run in
    /// parallel and every connection has its `statement_timeout`.
    ///
    /// A job whose values do not convert (out of range) fails alone before anything is sent. Any database error
    /// fails the whole group and nothing is written; the caller retries its jobs one by one.
    ///
    /// # Errors
    /// Database failures (nothing written); more than [`crate::MAX_GROUP_JOBS`] items: [`StoreError::OutOfRange`].
    pub async fn insert_release_group(
        &self,
        items: &[GroupItem<'_>],
        hold: std::time::Duration,
    ) -> Result<Vec<GroupOutcome>, StoreError> {
        let _ = hold;
        check_group(items)?;
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let upper = self.partition_upper();
        if upper == 0 || self.last_release_id().saturating_add(HEADROOM) >= upper {
            self.ensure_file_partitions_ahead().await?;
        }
        match self.insert_group_once(items).await {
            Err(e) if is_missing_partition(&e) => {
                self.ensure_file_partitions_ahead().await?;
                self.insert_group_once(items).await
            }
            other => other,
        }
    }

    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    async fn insert_group_once(
        &self,
        items: &[GroupItem<'_>],
    ) -> Result<Vec<GroupOutcome>, StoreError> {
        let mut out: Vec<Option<GroupOutcome>> = items.iter().map(|_| None).collect();
        let mut added_by: Vec<Option<i64>> = vec![None; items.len()];
        let mut tx = self.ingest().begin().await?;
        // (a) Uploaders, share-locked until the commit (lock order 1 before anything else).
        let mut uploaders = UploaderCache::default();
        for (i, it) in items.iter().enumerate() {
            let verdict = if let Some(v) = uploaders.get(&it.uploader, it.new.ingested_at) {
                v
            } else {
                let v = match resolve_uploader(&mut tx, &it.uploader, it.new.ingested_at).await {
                    Ok(v) => Ok(v),
                    Err(StoreError::Account(a)) => Err(a),
                    Err(e) => return Err(e),
                };
                uploaders.put(it.uploader, it.new.ingested_at, v);
                v
            };
            match verdict {
                Ok(v) => {
                    if let Some(slot) = added_by.get_mut(i) {
                        *slot = v;
                    }
                }
                Err(a) => {
                    if let Some(slot) = out.get_mut(i) {
                        *slot = Some(GroupOutcome::Failed(StoreError::Account(a)));
                    }
                }
            }
        }
        // An unknown category fails its job alone, as on SQLite (seam rule c), instead of the whole statement.
        let mut cats: Vec<i32> = items
            .iter()
            .filter_map(|it| i32::try_from(it.new.category_id).ok())
            .collect();
        cats.sort_unstable();
        cats.dedup();
        let known: Vec<i32> = sqlx::query_scalar("SELECT id FROM category WHERE id = ANY($1)")
            .bind(&cats)
            .fetch_all(&mut *tx)
            .await?;
        for (i, it) in items.iter().enumerate() {
            let ok = i32::try_from(it.new.category_id).is_ok_and(|c| known.contains(&c));
            if let Some(slot) = out.get_mut(i).filter(|s| s.is_none() && !ok) {
                *slot = Some(GroupOutcome::Failed(StoreError::UnknownCategory));
            }
        }
        // (b) Candidates in digest order; a digest seen earlier in the group is a duplicate of that job.
        let mut order: Vec<usize> = (0..items.len())
            .filter(|i| out.get(*i).is_some_and(Option::is_none))
            .collect();
        order.sort_by_key(|i| items.get(*i).map(|it| it.new.analysis.sha256.0));
        let mut arrays = ReleaseArrays::default();
        let mut sent: Vec<usize> = Vec::with_capacity(order.len());
        let mut last_sha: Option<[u8; 32]> = None;
        for i in order {
            let (Some(it), Some(by)) = (items.get(i), added_by.get(i).copied()) else {
                continue;
            };
            let sha = it.new.analysis.sha256.0;
            if last_sha == Some(sha) {
                if let Some(slot) = out.get_mut(i) {
                    *slot = Some(GroupOutcome::Duplicate);
                }
                continue;
            }
            match arrays.push(it, by) {
                Ok(()) => {
                    last_sha = Some(sha);
                    sent.push(i);
                }
                Err(e) => {
                    if let Some(slot) = out.get_mut(i) {
                        *slot = Some(GroupOutcome::Failed(e));
                    }
                }
            }
        }
        let returned: Vec<(i64, Vec<u8>)> = if sent.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                "INSERT INTO release (sha256, title, category_id, category_overridden, posted_at, ingested_at, \
                 total_bytes, poster, file_count, segment_count, missing_segment_count, par2_blocks, flags, \
                 nzb_size_bytes, source_name, source_label, meta_json, category_source, scene_family, scene_year, \
                 scene_season, scene_episode, scene_resolution, scene_source, scene_codec, scene_group, \
                 scene_languages, scene_json, origin, added_by) \
                 SELECT sha, title, cat, false, posted, ingested, total, poster, nfiles, segs, missing, par2, \
                 flags, size, sname, slabel, meta, csrc, fam, yr, season, ep, res, src, codec, grp, langs, \
                 sjson, origin, added_by \
                 FROM unnest($1::bytea[], $2::text[], $3::integer[], $4::bigint[], $5::bigint[], $6::bigint[], \
                 $7::text[], $8::integer[], $9::bigint[], $10::bigint[], $11::bigint[], $12::integer[], \
                 $13::bigint[], $14::text[], $15::text[], $16::text[], $17::text[], $18::text[], $19::smallint[], \
                 $20::integer[], $21::integer[], $22::text[], $23::text[], $24::text[], $25::text[], $26::text[], \
                 $27::text[], $28::text[], $29::bigint[]) WITH ORDINALITY \
                 AS u(sha, title, cat, posted, ingested, total, poster, nfiles, segs, missing, par2, flags, size, \
                 sname, slabel, meta, csrc, fam, yr, season, ep, res, src, codec, grp, langs, sjson, origin, \
                 added_by, ord) \
                 ORDER BY ord \
                 ON CONFLICT (sha256) DO NOTHING RETURNING id, sha256",
            )
            .bind(&arrays.sha)
            .bind(&arrays.title)
            .bind(&arrays.category)
            .bind(&arrays.posted_at)
            .bind(&arrays.ingested_at)
            .bind(&arrays.total_bytes)
            .bind(&arrays.poster)
            .bind(&arrays.file_count)
            .bind(&arrays.segment_count)
            .bind(&arrays.missing)
            .bind(&arrays.par2)
            .bind(&arrays.flags)
            .bind(&arrays.nzb_size)
            .bind(&arrays.source_name)
            .bind(&arrays.source_label)
            .bind(&arrays.meta_json)
            .bind(&arrays.category_source)
            .bind(&arrays.family)
            .bind(&arrays.year)
            .bind(&arrays.season)
            .bind(&arrays.episode)
            .bind(&arrays.resolution)
            .bind(&arrays.scene_source)
            .bind(&arrays.codec)
            .bind(&arrays.group)
            .bind(&arrays.languages)
            .bind(&arrays.scene_json)
            .bind(&arrays.origin)
            .bind(&arrays.added_by)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                if is_fk_violation(&e) {
                    StoreError::UnknownCategory
                } else {
                    StoreError::Db(e)
                }
            })?
        };
        // (c) Files, stats, outbox and log rows of the jobs that got a row.
        let mut files: Vec<(i64, &FileInfo)> = Vec::new();
        let mut deltas = Vec::new();
        let mut ids = Vec::new();
        let mut logs = Vec::new();
        for i in sent {
            let (Some(it), Some(by)) = (items.get(i), added_by.get(i).copied()) else {
                continue;
            };
            let a = it.new.analysis;
            let id = returned
                .iter()
                .find(|(_, sha)| sha.as_slice() == a.sha256.0.as_slice())
                .map(|(id, _)| *id);
            let Some(id) = id else {
                if let Some(slot) = out.get_mut(i) {
                    *slot = Some(GroupOutcome::Duplicate);
                }
                continue;
            };
            files.extend(a.files.iter().map(|f| (id, f)));
            deltas.push(StatDelta::of(
                cat_i32(it.new.category_id)?,
                i64::from(a.file_count),
                to_i64(a.segment_count, "segment_count")?,
                to_i64(a.total_bytes, "total_bytes")?,
                1,
            ));
            ids.push(id);
            let mut ok = it.log;
            ok.outcome = LogOutcome::Ok;
            logs.push((ok, Some(id), by));
            if let Some(slot) = out.get_mut(i) {
                *slot = Some(GroupOutcome::Inserted(id));
            }
        }
        insert_file_rows(&mut tx, &files).await?;
        apply_stats(&mut tx, &deltas).await?;
        enqueue_outbox(&mut tx, &ids).await?;
        insert_log_rows(&mut tx, &logs).await?;
        tx.commit().await?;
        if let Some(max) = ids.iter().max() {
            self.note_release_id(*max);
        }
        Ok(out
            .into_iter()
            .map(|o| o.unwrap_or(GroupOutcome::Deferred))
            .collect())
    }

    /// Makes sure `nzb_file` partitions cover the release sequence plus [`HEADROOM`] and the next 10M-id span (its own
    /// short transaction; the daily maintenance calls it too, so the boundary is normally crossed with the partition
    /// already in place). Returns the number of partitions created.
    ///
    /// # Errors
    /// Database errors; `PARTITION_INDEX_OUT_OF_RANGE` beyond partition 999999.
    pub async fn ensure_file_partitions_ahead(&self) -> Result<u32, StoreError> {
        let (last, created): (i64, i32) = sqlx::query_as(
            "SELECT s.last, nzbd.ensure_file_partitions(s.last + $1) \
             FROM (SELECT CASE WHEN is_called THEN last_value ELSE 0 END AS last FROM nzbd.release_id_seq) s",
        )
        .bind(HEADROOM)
        .fetch_one(self.ingest())
        .await?;
        self.note_partitions_upto(covered_upper(last.saturating_add(HEADROOM)));
        Ok(u32::try_from(created).unwrap_or(0))
    }

    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    async fn insert_release_once(
        &self,
        new: &NewRelease<'_>,
        log: Option<&IngestLogEntry<'_>>,
        uploader: &Uploader,
    ) -> Result<i64, StoreError> {
        let a = new.analysis;
        let s = &new.scene;
        let missing = a
            .files
            .iter()
            .fold(0u64, |n, f| n.saturating_add(file_missing(f)));
        let label = new.source_label.and_then(clean_source_label);
        let category = cat_i32(new.category_id)?;
        let mut tx = self.ingest().begin().await?;
        let added_by = resolve_uploader(&mut tx, uploader, new.ingested_at).await?;
        // The unique index arbitrates concurrent ingests of the same bytes: no error, no aborted transaction.
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO release (sha256, title, category_id, category_overridden, posted_at, ingested_at, \
             total_bytes, poster, file_count, segment_count, missing_segment_count, par2_blocks, flags, \
             nzb_size_bytes, source_name, source_label, meta_json, category_source, scene_family, scene_year, \
             scene_season, scene_episode, scene_resolution, scene_source, scene_codec, scene_group, \
             scene_languages, scene_json, origin, added_by) \
             VALUES ($1, $2, $3, false, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, \
             $20, $21, $22, $23, $24, $25, $26, $27, $28, $29) \
             ON CONFLICT (sha256) DO NOTHING RETURNING id",
        )
        .bind(a.sha256.0.to_vec())
        .bind(&a.title)
        .bind(category)
        .bind(a.posted_at)
        .bind(new.ingested_at)
        .bind(to_i64(a.total_bytes, "total_bytes")?)
        .bind(a.poster.as_deref())
        .bind(i32::try_from(a.file_count).map_err(|_| StoreError::OutOfRange("file_count"))?)
        .bind(to_i64(a.segment_count, "segment_count")?)
        .bind(to_i64(missing, "missing_segments")?)
        .bind(to_i64(a.par2_blocks, "par2_blocks")?)
        .bind(i32::try_from(a.flags.bits()).map_err(|_| StoreError::OutOfRange("flags"))?)
        .bind(to_i64(new.nzb_size_bytes, "nzb_size_bytes")?)
        .bind(new.source_name)
        .bind(label.as_deref())
        .bind(new.meta_json)
        .bind(new.category_source.as_str())
        .bind(s.family.as_deref())
        .bind(
            s.year
                .map(i16::try_from)
                .transpose()
                .map_err(|_| StoreError::OutOfRange("scene_year"))?,
        )
        .bind(
            s.season
                .map(i32::try_from)
                .transpose()
                .map_err(|_| StoreError::OutOfRange("scene_season"))?,
        )
        .bind(
            s.episode
                .map(i32::try_from)
                .transpose()
                .map_err(|_| StoreError::OutOfRange("scene_episode"))?,
        )
        .bind(s.resolution.as_deref())
        .bind(s.source.as_deref())
        .bind(s.codec.as_deref())
        .bind(s.group.as_deref())
        .bind(s.languages_json.as_deref())
        .bind(s.json.as_deref())
        .bind(log.map(|l| IngestOrigin::from_log_source(l.source).as_str()))
        .bind(added_by)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                StoreError::UnknownCategory
            } else if is_unique_violation(&e) {
                StoreError::Duplicate
            } else {
                StoreError::Db(e)
            }
        })?;
        let Some(id) = id else {
            return Err(StoreError::Duplicate);
        };
        insert_files(&mut tx, id, &a.files).await?;
        apply_stats(
            &mut tx,
            &[StatDelta::of(
                category,
                i64::from(a.file_count),
                to_i64(a.segment_count, "segment_count")?,
                to_i64(a.total_bytes, "total_bytes")?,
                1,
            )],
        )
        .await?;
        enqueue_outbox(&mut tx, &[id]).await?;
        if let Some(log) = log {
            let mut ok = *log;
            ok.outcome = LogOutcome::Ok;
            insert_log_row(&mut tx, &ok, Some(id), added_by).await?;
        }
        tx.commit().await?;
        self.note_release_id(id);
        Ok(id)
    }

    /// Appends an `ingest_log` row (duplicate/failed outcome) attributed to `uploader`, without gating.
    ///
    /// # Errors
    /// Database failure.
    pub async fn log_ingest_as(
        &self,
        e: &IngestLogEntry<'_>,
        release_id: Option<i64>,
        uploader: &Uploader,
    ) -> Result<(), StoreError> {
        let mut tx = self.ingest().begin().await?;
        let user = match *uploader {
            Uploader::Unattributed => None,
            Uploader::Account(id) | Uploader::Session { user_id: id, .. } => Some(id),
            Uploader::ApiKey(key) => {
                sqlx::query_scalar::<_, Option<i64>>("SELECT owner_id FROM api_key WHERE id = $1")
                    .bind(key)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten()
            }
        };
        insert_log_row(&mut tx, e, release_id, user).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Re-validates `uploader` without writing anything (the duplicate answer must not leak to a revoked key, N9).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`] / [`AccountError::KeyRefused`]; database failure.
    pub async fn validate_uploader(&self, uploader: &Uploader, now: i64) -> Result<(), StoreError> {
        if matches!(uploader, Uploader::Unattributed) {
            return Ok(());
        }
        let mut tx = self.ingest().begin().await?;
        resolve_uploader(&mut tx, uploader, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A release by id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_release(&self, id: i64) -> Result<Option<ReleaseRow>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            release_cols!(),
            " FROM release r WHERE r.id = $1"
        ))
        .bind(id)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(release_from_row).transpose()
    }

    /// A release by hex SHA-256; malformed hex is `None` (never reaches SQL).
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_release_by_sha(&self, hex: &str) -> Result<Option<ReleaseRow>, StoreError> {
        let Ok(sha) = Sha256::from_hex(hex) else {
            return Ok(None);
        };
        let row = sqlx::query(concat!(
            "SELECT ",
            release_cols!(),
            " FROM release r WHERE r.sha256 = $1"
        ))
        .bind(sha.0.to_vec())
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(release_from_row).transpose()
    }

    /// Hydration for the search index (ARCHITECTURE v3 section 3.4): the rows of `ids` in the order given, one
    /// primary-key statement; ids that no longer exist and rows whose CURRENT category is in `exclude` are dropped
    /// (SEC-090: the index may lag, the display rule never does).
    ///
    /// # Errors
    /// Database errors.
    pub async fn hydrate(
        &self,
        ids: &[i64],
        exclude: &[u32],
    ) -> Result<Vec<ReleaseRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(concat!(
            "SELECT ",
            release_cols!(),
            " FROM release r WHERE r.id = ANY($1)"
        ))
        .bind(ids)
        .fetch_all(self.web())
        .await?;
        let mut found: Vec<ReleaseRow> = rows
            .iter()
            .map(release_from_row)
            .collect::<Result<_, _>>()?;
        found.retain(|r| !excluded(r.category_id, exclude));
        let mut out = Vec::with_capacity(found.len());
        for id in ids {
            if let Some(pos) = found.iter().position(|r| r.id == *id) {
                out.push(found.swap_remove(pos));
            }
        }
        Ok(out)
    }

    /// Degraded listing while the index is unavailable (ARCHITECTURE v3 section 3.3, review L5): newest first by
    /// primary key below `before` (exclusive), restricted to `categories` (empty = all; a parent id is passed
    /// together with its children by the caller) and outside `exclude`, walking at most [`DEGRADED_SCAN_BUDGET`]
    /// primary-key entries per request.
    ///
    /// # Errors
    /// Database errors.
    pub async fn degraded_browse(
        &self,
        before: Option<i64>,
        categories: &[u32],
        exclude: &[u32],
        limit: u32,
    ) -> Result<DegradedPage, StoreError> {
        let limit = i64::from(limit.clamp(1, crate::MAX_LIMIT));
        let cats: Vec<i32> = categories
            .iter()
            .filter_map(|c| i32::try_from(*c).ok())
            .collect();
        let excl: Vec<i32> = exclude
            .iter()
            .filter_map(|c| i32::try_from(*c).ok())
            .collect();
        let rows = sqlx::query(concat!(
            "WITH walk AS (SELECT id, category_id FROM release WHERE id < $1 ORDER BY id DESC LIMIT $2) \
             SELECT ",
            release_cols!(),
            " FROM release r JOIN walk w ON w.id = r.id \
             WHERE (cardinality($3::integer[]) = 0 OR w.category_id = ANY($3)) \
               AND NOT (w.category_id = ANY($4)) \
             ORDER BY r.id DESC LIMIT $5"
        ))
        .bind(before.unwrap_or(i64::MAX))
        .bind(DEGRADED_SCAN_BUDGET)
        .bind(&cats)
        .bind(&excl)
        .bind(limit)
        .fetch_all(self.web())
        .await?;
        let items: Vec<ReleaseRow> = rows
            .iter()
            .map(release_from_row)
            .collect::<Result<_, _>>()?;
        let full = i64::try_from(items.len()).unwrap_or(i64::MAX) >= limit;
        if full {
            let next_before = items.last().map(|r| r.id);
            return Ok(DegradedPage {
                items,
                next_before,
                budget_exhausted: false,
            });
        }
        // Not full: either the walk reached the end of the table or the budget stopped it. Only then is the walk
        // summarized (the same bounded index walk again, no table access).
        let (scanned, low): (i64, Option<i64>) = sqlx::query_as(
            "SELECT count(*), min(id) FROM (SELECT id FROM release WHERE id < $1 ORDER BY id DESC LIMIT $2) w",
        )
        .bind(before.unwrap_or(i64::MAX))
        .bind(DEGRADED_SCAN_BUDGET)
        .fetch_one(self.web())
        .await?;
        let budget_exhausted = scanned >= DEGRADED_SCAN_BUDGET;
        let next_before = if budget_exhausted { low } else { None };
        Ok(DegradedPage {
            items,
            next_before,
            budget_exhausted,
        })
    }

    /// `ingested_at` of the newest release (by id: ids and ingest times grow together; the BRIN index of
    /// `ingested_at` is for ranges, a `MAX` would scan).
    ///
    /// # Errors
    /// Database errors.
    pub async fn newest_ingested_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT ingested_at FROM release ORDER BY id DESC LIMIT 1")
                .fetch_optional(self.background())
                .await?,
        )
    }

    /// SHA-256 of every release (the referenced set of `FsStore::gc`; a full scan, maintenance only).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_shas(&self) -> Result<HashSet<Sha256>, StoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sha256 FROM release")
            .fetch_all(self.background())
            .await?;
        rows.into_iter().map(sha_of).collect()
    }

    /// Files of a release in NZB order (all of them).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_files(&self, release_id: i64) -> Result<Vec<ReleaseFile>, StoreError> {
        self.list_files_page(release_id, 0, u32::MAX).await
    }

    /// `limit` files of a release from row `offset`, in NZB order.
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
            file_cols!(),
            " FROM nzb_file WHERE release_id = $1 ORDER BY idx LIMIT $2 OFFSET $3"
        ))
        .bind(release_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(self.web())
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
        let Ok(idx) = i32::try_from(idx) else {
            return Ok(None);
        };
        let row = sqlx::query(concat!(
            "SELECT ",
            file_cols!(),
            " FROM nzb_file WHERE release_id = $1 AND idx = $2"
        ))
        .bind(release_id)
        .bind(idx)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(file_from_row).transpose()
    }

    /// Up to `limit` distinct newsgroups across the files of a release, sorted (byte order, the C collation).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_release_groups(
        &self,
        release_id: i64,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT e #>> '{}' AS g FROM nzb_file f, \
             LATERAL jsonb_array_elements(CASE WHEN f.groups IS JSON ARRAY THEN f.groups::jsonb \
             ELSE '[]'::jsonb END) AS e \
             WHERE f.release_id = $1 AND jsonb_typeof(e) = 'string' ORDER BY g LIMIT $2",
        )
        .bind(release_id)
        .bind(i64::from(limit))
        .fetch_all(self.web())
        .await?;
        Ok(rows)
    }

    /// Locks release `id` and returns `(category_id, file_count, segment_count, total_bytes)`.
    async fn lock_release(
        conn: &mut PgConnection,
        id: i64,
    ) -> Result<Option<(i32, i64, i64, i64)>, StoreError> {
        let row = sqlx::query(
            "SELECT category_id, file_count, segment_count, total_bytes FROM release WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(|r| {
            Ok((
                r.try_get::<i32, _>("category_id")?,
                i64::from(r.try_get::<i32, _>("file_count")?),
                r.try_get::<i64, _>("segment_count")?,
                r.try_get::<i64, _>("total_bytes")?,
            ))
        })
        .transpose()
    }

    /// Moves one locked release to `category` (marks it manual), with the stats deltas and the outbox row.
    async fn move_category(
        conn: &mut PgConnection,
        id: i64,
        old: (i32, i64, i64, i64),
        category: i32,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE release SET category_id = $2, category_overridden = true, category_source = 'manual', flags = flags & ~512, \
             index_version = index_version + 1 WHERE id = $1",
        )
        .bind(id)
        .bind(category)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                StoreError::UnknownCategory
            } else {
                StoreError::Db(e)
            }
        })?;
        let (cat, files, segs, bytes) = old;
        apply_stats(
            conn,
            &[
                StatDelta::of(cat, files, segs, bytes, -1),
                StatDelta::of(category, files, segs, bytes, 1),
            ],
        )
        .await?;
        enqueue_outbox(conn, &[id]).await
    }

    /// Manually sets the category (legacy, unattributed).
    ///
    /// # Errors
    /// [`StoreError::NotFound`], [`StoreError::UnknownCategory`].
    pub async fn set_category(&self, id: i64, category_id: u32) -> Result<(), StoreError> {
        let category = cat_i32(category_id)?;
        let mut tx = self.web().begin().await?;
        let old = Self::lock_release(&mut tx, id)
            .await?
            .ok_or(StoreError::NotFound)?;
        Self::move_category(&mut tx, id, old, category).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Manual category override by an admin (D26 c, D40). Audit `category_override` with the old and new category.
    /// Returns the old category id.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`StoreError::NotFound`], [`StoreError::UnknownCategory`].
    pub async fn set_category_as(
        &self,
        actor: &AccountActor,
        release_id: i64,
        category_id: u32,
        ip: Option<&str>,
        now: i64,
    ) -> Result<u32, StoreError> {
        let category = cat_i32(category_id)?;
        let mut tx = self.web().begin().await?;
        let a = require_session_actor_share(&mut tx, actor, Role::Admin, now).await?;
        let old = Self::lock_release(&mut tx, release_id)
            .await?
            .ok_or(StoreError::NotFound)?;
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM category WHERE id = $1")
            .bind(category)
            .fetch_one(&mut *tx)
            .await?;
        if known == 0 {
            return Err(StoreError::UnknownCategory);
        }
        Self::move_category(&mut tx, release_id, old, category).await?;
        let detail = format!("release={release_id} old={} new={category_id}", old.0);
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "category_override",
            Some(&detail),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        u32::try_from(old.0).map_err(|_| StoreError::OutOfRange("category_id"))
    }

    /// Sets or clears the source label of any release (admin, D40). Audit `source_label_edit` (JSON with the old
    /// and the new value). Returns the stored value.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`StoreError::NotFound`].
    pub async fn set_source_label_as(
        &self,
        actor: &AccountActor,
        release_id: i64,
        label: Option<&str>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        let clean = label.and_then(clean_source_label);
        let mut tx = self.web().begin().await?;
        let a = require_session_actor_share(&mut tx, actor, Role::Admin, now).await?;
        let old: Option<String> =
            sqlx::query_scalar("SELECT source_label FROM release WHERE id = $1 FOR UPDATE")
                .bind(release_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
        sqlx::query(
            "UPDATE release SET source_label = $2, index_version = index_version + 1 WHERE id = $1",
        )
        .bind(release_id)
        .bind(clean.as_deref())
        .execute(&mut *tx)
        .await?;
        enqueue_outbox(&mut tx, &[release_id]).await?;
        let detail = json!({"release": release_id, "old": old, "new": clean}).to_string();
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "source_label_edit",
            Some(&detail),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(clean)
    }

    /// Deletes a release with its files (cascade) in one transaction (operator/test path; the UI trashes).
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn delete_release(&self, id: i64) -> Result<(), StoreError> {
        let mut tx = self.web().begin().await?;
        let old = Self::lock_release(&mut tx, id)
            .await?
            .ok_or(StoreError::NotFound)?;
        // A hard delete (operator/test path) takes the NFO with it (T140).
        sqlx::query(
            "DELETE FROM release_nfo WHERE sha256 = (SELECT sha256 FROM release WHERE id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM release WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let (cat, files, segs, bytes) = old;
        apply_stats(&mut tx, &[StatDelta::of(cat, files, segs, bytes, -1)]).await?;
        enqueue_outbox(&mut tx, &[id]).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Moves release `id` into `release_trash` with the audit row (legacy actor text).
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn trash_release(
        &self,
        id: i64,
        now: i64,
        actor: &str,
        ip: Option<&str>,
    ) -> Result<TrashRow, StoreError> {
        self.trash_release_inner(id, None, now, ip, TrashActor::Text(actor))
            .await
    }

    /// Moves a release to the trash on an ADMIN's authority (SEC-050 v2).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`StoreError::NotFound`].
    pub async fn trash_release_as(
        &self,
        actor: &AccountActor,
        id: i64,
        now: i64,
        ip: Option<&str>,
    ) -> Result<TrashRow, StoreError> {
        self.trash_release_inner(id, None, now, ip, TrashActor::Account(actor))
            .await
    }

    /// Like [`PgDb::trash_release_as`], but only while the release still has the digest the admin confirmed (T119;
    /// ids are never reused in v3 except after restoring an older backup, so the binding stays).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`]; [`StoreError::NotFound`] when gone or re-used with another digest.
    pub async fn trash_release_checked_as(
        &self,
        actor: &AccountActor,
        id: i64,
        expected: &Sha256,
        now: i64,
        ip: Option<&str>,
    ) -> Result<TrashRow, StoreError> {
        self.trash_release_inner(id, Some(expected), now, ip, TrashActor::Account(actor))
            .await
    }

    /// The trash transaction: release row locked, moved into `release_trash` (one row per digest), files cascade,
    /// stats and outbox updated, audit row last.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    pub(crate) async fn trash_release_inner(
        &self,
        id: i64,
        expected: Option<&Sha256>,
        now: i64,
        ip: Option<&str>,
        actor: TrashActor<'_>,
    ) -> Result<TrashRow, StoreError> {
        let mut tx = self.web().begin().await?;
        let (who, deleted_by) = match actor {
            TrashActor::Account(actor) => {
                let a = require_session_actor_share(&mut tx, actor, Role::Admin, now).await?;
                (
                    Some(AuditActor::account(a.id, a.role, &a.username)),
                    Some(a.id),
                )
            }
            TrashActor::Text(_) => (None, None),
        };
        let Some(row) = sqlx::query(
            "SELECT id, sha256, title, category_id, total_bytes, nzb_size_bytes, file_count, segment_count, \
             source_name, ingested_at, added_by FROM release \
             WHERE id = $1 AND ($2::bytea IS NULL OR sha256 = $2) FOR UPDATE",
        )
        .bind(id)
        .bind(expected.map(|s| s.0.to_vec()))
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Err(StoreError::NotFound);
        };
        let sha: Vec<u8> = row.try_get("sha256")?;
        let digest = sha_of(sha.clone())?;
        let category: i32 = row.try_get("category_id")?;
        let file_count: i32 = row.try_get("file_count")?;
        let total_bytes: i64 = row.try_get("total_bytes")?;
        let segments: i64 = row.try_get("segment_count")?;
        let trash_id: i64 = sqlx::query_scalar(
            "INSERT INTO release_trash (original_id, sha256, title, category_id, total_bytes, nzb_size_bytes, \
             file_count, source_name, ingested_at, deleted_at, added_by, deleted_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (sha256) DO UPDATE SET original_id = excluded.original_id, title = excluded.title, \
               category_id = excluded.category_id, total_bytes = excluded.total_bytes, \
               nzb_size_bytes = excluded.nzb_size_bytes, file_count = excluded.file_count, \
               source_name = excluded.source_name, ingested_at = excluded.ingested_at, \
               deleted_at = excluded.deleted_at, added_by = excluded.added_by, deleted_by = excluded.deleted_by \
             RETURNING id",
        )
        .bind(id)
        .bind(&sha)
        .bind(row.try_get::<String, _>("title")?)
        .bind(category)
        .bind(total_bytes)
        .bind(row.try_get::<i64, _>("nzb_size_bytes")?)
        .bind(file_count)
        .bind(row.try_get::<Option<String>, _>("source_name")?)
        .bind(row.try_get::<i64, _>("ingested_at")?)
        .bind(now)
        .bind(row.try_get::<Option<i64>, _>("added_by")?)
        .bind(deleted_by)
        .fetch_one(&mut *tx)
        .await?;
        crate::pg::nfo::hide_for_trash(&mut tx, &sha, now).await?;
        // `nzb_file` goes with the release (ON DELETE CASCADE); ingest_log keeps the id (readers check existence).
        sqlx::query("DELETE FROM release WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        apply_stats(
            &mut tx,
            &[StatDelta::of(
                category,
                i64::from(file_count),
                segments,
                total_bytes,
                -1,
            )],
        )
        .await?;
        enqueue_outbox(&mut tx, &[id]).await?;
        let out = sqlx::query(concat!(
            "SELECT ",
            trash_cols!(),
            " FROM release_trash WHERE id = $1"
        ))
        .bind(trash_id)
        .fetch_one(&mut *tx)
        .await?;
        let out = trash_from_row(&out)?;
        let detail = crate::trash::delete_detail(
            id,
            &digest,
            row.try_get::<Option<i64>, _>("added_by")?,
            &row.try_get::<String, _>("title")?,
        );
        match (&who, actor) {
            (Some(w), _) => {
                write_audit(&mut tx, w, now, "release_delete", Some(&detail), ip, None).await?;
            }
            (None, TrashActor::Text(text)) => {
                write_audit_legacy(
                    &mut tx,
                    now,
                    Some(text),
                    "release_delete",
                    Some(&detail),
                    ip,
                )
                .await?;
            }
            (None, TrashActor::Account(_)) => {}
        }
        tx.commit().await?;
        Ok(out)
    }

    /// Newest-first deleted releases (at most `limit`, capped at 10 000).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_trash(&self, limit: u32) -> Result<Vec<TrashRow>, StoreError> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            trash_cols!(),
            " FROM release_trash ORDER BY deleted_at DESC, id DESC LIMIT $1"
        ))
        .bind(i64::from(limit.min(10_000)))
        .fetch_all(self.web())
        .await?;
        rows.iter().map(trash_from_row).collect()
    }

    /// One deleted release by trash id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_trash(&self, id: i64) -> Result<Option<TrashRow>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            trash_cols!(),
            " FROM release_trash WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(trash_from_row).transpose()
    }

    /// Whether a deleted release with this digest is in the trash (one probe of the unique index; review 38 L1).
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_is_trashed(&self, sha: &Sha256) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM release_trash WHERE sha256 = $1)",
        )
        .bind(sha.0.to_vec())
        .fetch_one(self.ingest())
        .await?)
    }

    /// Digests of every deleted release.
    ///
    /// # Errors
    /// Database errors.
    pub async fn trash_shas(&self) -> Result<HashSet<Sha256>, StoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sha256 FROM release_trash")
            .fetch_all(self.background())
            .await?;
        rows.into_iter().map(sha_of).collect()
    }

    /// Removes the trash record with this id (the purge of a trash bucket, SEC-051). Returns whether it existed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn forget_trash(&self, id: i64) -> Result<bool, StoreError> {
        let mut tx = self.web().begin().await?;
        let sha: Option<Vec<u8>> =
            sqlx::query_scalar("DELETE FROM release_trash WHERE id = $1 RETURNING sha256")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(sha) = sha else {
            return Ok(false);
        };
        // The restore: the NFO is shown again once the NZB is re-ingested (T140).
        sqlx::query(
            "UPDATE release_nfo SET trashed_at = NULL, restored_at = extract(epoch FROM now())::bigint \
             WHERE sha256 = $1 AND trashed_at IS NOT NULL",
        )
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The uploader of a release as the detail page shows it; `None` when the release does not exist.
    ///
    /// # Errors
    /// Database failure.
    pub async fn release_attribution(
        &self,
        release_id: i64,
    ) -> Result<Option<ReleaseAttribution>, StoreError> {
        let row = sqlx::query(
            "SELECT r.added_by, u.display_name, u.deleted_at FROM release r \
             LEFT JOIN account u ON u.id = r.added_by WHERE r.id = $1",
        )
        .bind(release_id)
        .fetch_optional(self.web())
        .await?;
        row.map(|r| {
            let added_by: Option<i64> = r.try_get("added_by")?;
            let name: Option<String> = r.try_get("display_name")?;
            Ok(ReleaseAttribution {
                added_by,
                handle: added_by.map(|id| name.unwrap_or_else(|| crate::default_handle(id))),
                deleted: r.try_get::<Option<i64>, _>("deleted_at")?.is_some(),
            })
        })
        .transpose()
    }

    /// Announces releases to the search indexer without changing them (the `SearchIndex::upsert`/`remove`
    /// reconciliation hook and `nzbd search verify --repair`, ARCHITECTURE v3 section 3.5). Ids are not checked: a
    /// row for a vanished id makes the indexer delete its document.
    ///
    /// # Errors
    /// Database errors.
    pub async fn enqueue_reindex(&self, ids: &[i64]) -> Result<(), StoreError> {
        let mut tx = self.background().begin().await?;
        enqueue_outbox(&mut tx, ids).await?;
        tx.commit().await?;
        Ok(())
    }
}
