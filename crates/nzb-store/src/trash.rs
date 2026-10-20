//! Deleted releases (T081): the `release_trash` repository and the [`TrashStore`] extension of
//! the blob store.
//!
//! A deleted release is **moved** out of `release`/`nzb_file` into `release_trash`
//! in one transaction (so every list, search, tile, explorer and download query is correct
//! without a `deleted` filter), and its blob is moved into the store's trash area, from where
//! it is restorable until the owner purges it. Nothing in this module runs by itself: deleting
//! and purging are explicit, re-authenticated user actions (BETA rule: never delete a user's NZB
//! automatically).
//!
//! Crash order of a delete (`nzb-web::cleanup`): `trash_stage` (a second name for the blob)
//! -> [`SqliteDb::trash_release`] (one transaction, includes the audit row) -> `trash_finish` (drop
//! the live name). A crash after the first step leaves a spare link; after the second, an
//! orphan live blob that `store gc` quarantines like any other orphan. Never a lost NZB.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use nzb_core::Sha256;
use sqlx::Row;

use crate::account::{AuditActor, Role, require_session_actor, write_audit};
use crate::attribution::TrashActor;
use crate::fs_store::NzbStore;
use crate::{SqliteDb, StoreError};

macro_rules! trash_cols_sql {
    () => {
        "id, original_id, sha256, title, category_id, total_bytes, \
    nzb_size_bytes, file_count, source_name, ingested_at, deleted_at"
    };
}

/// A deleted release as kept in `release_trash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashRow {
    /// Trash id (stable handle for `nzbd trash restore`).
    pub id: i64,
    /// Id the release had before it was deleted (audit correlation only).
    pub original_id: i64,
    /// Content address; names the blob in the trash area.
    pub sha256: Sha256,
    /// Sanitized title (display only).
    pub title: String,
    /// Category id at deletion time.
    pub category_id: u32,
    /// Payload bytes.
    pub total_bytes: u64,
    /// Size of the NZB document.
    pub nzb_size_bytes: u64,
    /// Number of files.
    pub file_count: u32,
    /// Original file name (display only).
    pub source_name: Option<String>,
    /// Unix seconds the release was first ingested.
    pub ingested_at: i64,
    /// Unix seconds of the deletion.
    pub deleted_at: i64,
}

/// First eight hex characters of a digest: the only form of it that goes into audit rows.
#[must_use]
pub fn sha8(sha: &Sha256) -> String {
    sha.to_hex().chars().take(8).collect()
}

/// Audit detail of a `release_delete`: ids, digest prefix, original uploader and the title, so
/// "X deleted Y's upload" survives the row's removal (T138). The title is display data from an
/// NZB: sanitized and cut to 80 bytes, and placed last because it may contain spaces.
pub(crate) fn delete_detail(id: i64, sha: &Sha256, added_by: Option<i64>, title: &str) -> String {
    let by = added_by.map_or_else(|| "none".to_owned(), |u| format!("user:{u}"));
    format!(
        "release={id} sha8={} added_by={by} title={}",
        sha8(sha),
        nzb_core::sanitize_text(title, 80)
    )
}

fn trash_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<TrashRow, StoreError> {
    let sha: Vec<u8> = row.try_get("sha256")?;
    let sha: [u8; 32] = sha
        .try_into()
        .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
    let u = |name: &'static str| -> Result<u64, StoreError> {
        u64::try_from(row.try_get::<i64, _>(name)?).map_err(|_| StoreError::OutOfRange(name))
    };
    Ok(TrashRow {
        id: row.try_get("id")?,
        original_id: row.try_get("original_id")?,
        sha256: Sha256(sha),
        title: row.try_get("title")?,
        category_id: u32::try_from(row.try_get::<i64, _>("category_id")?)
            .map_err(|_| StoreError::OutOfRange("category_id"))?,
        total_bytes: u("total_bytes")?,
        nzb_size_bytes: u("nzb_size_bytes")?,
        file_count: u32::try_from(u("file_count")?)
            .map_err(|_| StoreError::OutOfRange("file_count"))?,
        source_name: row.try_get("source_name")?,
        ingested_at: row.try_get("ingested_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

impl SqliteDb {
    /// Moves release `id` (row, files, FTS entry) into `release_trash` and writes the audit
    /// row, all in one transaction. The sha is free again afterwards: re-ingesting the same
    /// bytes creates a fresh release. If the same content was trashed before, its trash row is
    /// replaced (one trash row per digest).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the release does not exist; nothing is written on error.
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

    /// The transaction behind [`SqliteDb::trash_release`], [`SqliteDb::trash_release_as`] and
    /// [`SqliteDb::trash_release_checked_as`]. With `expected`, the release must still have that digest:
    /// `release.id` is a plain rowid that SQLite reuses after the highest row is deleted, so an id
    /// alone can name a different NZB than the one the user confirmed (T119, review L1 of the 1.x
    /// bulk branch). A mismatch is [`StoreError::NotFound`] with nothing written.
    pub(crate) async fn trash_release_inner(
        &self,
        id: i64,
        expected: Option<&Sha256>,
        now: i64,
        ip: Option<&str>,
        actor: TrashActor<'_>,
    ) -> Result<TrashRow, StoreError> {
        let mut tx = self.begin_immediate().await?;
        // An account actor is validated first (admin, live, enabled): a refused role reads nothing.
        let (who, deleted_by) = match actor {
            TrashActor::Account(actor) => {
                let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
                (
                    Some(AuditActor::account(a.id, a.role, &a.username)),
                    Some(a.id),
                )
            }
            TrashActor::Text(_) => (None, None),
        };
        let Some(row) = sqlx::query(
            "SELECT id, sha256, title, category_id, total_bytes, nzb_size_bytes, file_count, \
             source_name, ingested_at, added_by FROM release \
             WHERE id = ?1 AND (?2 IS NULL OR sha256 = ?2)",
        )
        .bind(id)
        .bind(expected.map(|s| s.0.to_vec()))
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Err(StoreError::NotFound);
        };
        let sha: Vec<u8> = row.try_get("sha256")?;
        let digest = <[u8; 32]>::try_from(sha.as_slice())
            .map(Sha256)
            .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
        let trash_id: i64 = sqlx::query_scalar(
            "INSERT INTO release_trash (original_id, sha256, title, category_id, total_bytes, \
             nzb_size_bytes, file_count, source_name, ingested_at, deleted_at, added_by, deleted_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
             ON CONFLICT(sha256) DO UPDATE SET original_id = excluded.original_id, \
               title = excluded.title, category_id = excluded.category_id, \
               total_bytes = excluded.total_bytes, nzb_size_bytes = excluded.nzb_size_bytes, \
               file_count = excluded.file_count, source_name = excluded.source_name, \
               ingested_at = excluded.ingested_at, deleted_at = excluded.deleted_at, \
               added_by = excluded.added_by, deleted_by = excluded.deleted_by \
             RETURNING id",
        )
        .bind(id)
        .bind(&sha)
        .bind(row.try_get::<String, _>("title")?)
        .bind(row.try_get::<i64, _>("category_id")?)
        .bind(row.try_get::<i64, _>("total_bytes")?)
        .bind(row.try_get::<i64, _>("nzb_size_bytes")?)
        .bind(row.try_get::<i64, _>("file_count")?)
        .bind(row.try_get::<Option<String>, _>("source_name")?)
        .bind(row.try_get::<i64, _>("ingested_at")?)
        .bind(now)
        .bind(row.try_get::<Option<i64>, _>("added_by")?)
        .bind(deleted_by)
        .fetch_one(&mut *tx)
        .await?;
        crate::nfo::hide_for_trash(&mut tx, &sha, now).await?;
        // `nzb_file` goes with the release (ON DELETE CASCADE); ingest_log keeps its rows with
        // `release_id` set to NULL.
        sqlx::query("DELETE FROM release WHERE id = ?1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let detail = delete_detail(
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
                crate::account::write_audit_legacy(
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
        let out = sqlx::query(concat!(
            "SELECT ",
            trash_cols_sql!(),
            " FROM release_trash WHERE id = ?1"
        ))
        .bind(trash_id)
        .fetch_one(&mut *tx)
        .await?;
        let out = trash_from_row(&out)?;
        tx.commit().await?;
        self.bump_release_epoch();
        Ok(out)
    }

    /// Newest-first listing of deleted releases, at most `limit` (capped at 10 000).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_trash(&self, limit: u32) -> Result<Vec<TrashRow>, StoreError> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            trash_cols_sql!(),
            " FROM release_trash ORDER BY deleted_at DESC, id DESC LIMIT ?1"
        ))
        .bind(i64::from(limit.min(10_000)))
        .fetch_all(self.readers())
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
            trash_cols_sql!(),
            " FROM release_trash WHERE id = ?1"
        ))
        .bind(id)
        .fetch_optional(self.readers())
        .await?;
        row.as_ref().map(trash_from_row).transpose()
    }

    /// Whether a deleted release with this digest is in the trash (one probe of the unique index; `nzbd import`
    /// does not bring deleted releases back, review 38 L1).
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_is_trashed(&self, sha: &Sha256) -> Result<bool, StoreError> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM release_trash WHERE sha256 = ?1")
                .bind(sha.0.to_vec())
                .fetch_one(self.readers())
                .await?
                > 0,
        )
    }

    /// Digests of every deleted release (the set of trash blobs that have a record).
    ///
    /// # Errors
    /// Database errors, or a stored digest with the wrong length.
    pub async fn trash_shas(&self) -> Result<HashSet<Sha256>, StoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sha256 FROM release_trash")
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

    /// Removes the trash record with this id. Returns whether a row existed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn forget_trash(&self, id: i64) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let sha: Option<Vec<u8>> =
            sqlx::query_scalar("DELETE FROM release_trash WHERE id = ?1 RETURNING sha256")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(sha) = sha else {
            return Ok(false);
        };
        // The restore: the NFO is shown again once the NZB is re-ingested (T140).
        sqlx::query(
            "UPDATE release_nfo SET trashed_at = NULL, restored_at = unixepoch() \
             WHERE sha256 = ?1 AND trashed_at IS NOT NULL",
        )
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}

/// A blob in the trash area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrashBlob {
    /// Content address.
    pub sha: Sha256,
    /// Size in bytes.
    pub size: u64,
}

/// Listing of the trash area.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrashListing {
    /// Well-formed `<sha256>.nzb` regular files, sorted by digest.
    pub items: Vec<TrashBlob>,
    /// Any other entry (never touched, never counted as trash).
    pub foreign: u64,
}

/// A file in the store's internal quarantine (`.gc-trash`, blobs `store gc` took out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineBlob {
    /// Content address.
    pub sha: Sha256,
    /// Size in bytes.
    pub size: u64,
    /// Unix seconds it was quarantined.
    pub quarantined_at: i64,
}

/// Listing of the quarantine: managed entries and the number of foreign names/files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineListing {
    /// Entries with a name written by the store.
    pub items: Vec<QuarantineBlob>,
    /// Anything else in the directory (never touched).
    pub foreign: u64,
}

/// What a quarantine purge did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuarantinePurge {
    /// Files removed.
    pub removed: u64,
    /// Bytes of the removed files.
    pub bytes: u64,
    /// Entries younger than the cut-off (kept).
    pub kept_recent: u64,
    /// Entries refused by the safety checks (symlink, hard-linked, swapped, not regular) and
    /// foreign names.
    pub skipped: u64,
    /// Managed files left because the deadline or authority gate stopped the purge.
    pub remaining: u64,
    /// The authority gate refused; no subsequent file was removed.
    pub aborted: bool,
}

impl QuarantinePurge {
    /// Maximum number of managed entries between authority checks.
    pub const BATCH_SIZE: u64 = 50;
}

/// Result of [`TrashStore::trash_purge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashPurge {
    /// The blob was removed.
    Removed {
        /// Size of the removed blob.
        bytes: u64,
    },
    /// There was no blob.
    Absent,
    /// The entry exists but is not a plain regular file with one link (symlink, FIFO, hard
    /// link, swapped during the check); it was left alone.
    Refused,
}

/// Result of [`TrashStore::trash_finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashFinish {
    /// The live blob name was removed; the trash copy remains.
    Removed,
    /// A release references the digest again (re-ingest raced the delete): the live blob stays.
    Kept,
    /// There was no live blob any more.
    Gone,
}

/// Re-check callback: `true` when no release references the digest. Called on a blocking
/// thread right before the live blob is dropped; a database error must answer `false`.
pub type StillUnreferenced = Arc<dyn Fn(&Sha256) -> bool + Send + Sync>;

/// Trash area of a blob store. Implemented by [`crate::FsStore`] (`store/.trash/<sha>.nzb`); a
/// database-backed store implements the same contract (a `trashed_at` marker on the blob row).
///
/// Contract: nothing here destroys data except `trash_purge` and `quarantine_purge`, which
/// are only called from explicit, confirmed user actions.
#[async_trait]
pub trait TrashStore: NzbStore {
    /// Makes a verified second copy/name of the live blob in the trash area (idempotent). The
    /// live blob stays. `NotFound` when there is no live blob.
    async fn trash_stage(&self, sha: &Sha256) -> Result<(), StoreError>;

    /// Drops the live name of a staged blob. Refuses (`NotFound`) when the trash copy is
    /// missing. Re-checks `still_unreferenced` after taking the blob out of reach of `put`.
    ///
    /// `started_at` is the wall-clock time the delete began. A live blob whose mtime is not
    /// older than it was refreshed by a dedup `put` (a re-ingest of the same bytes) that may not
    /// have inserted its release yet, so the live name is kept (`Kept`), never dropped.
    async fn trash_finish(
        &self,
        sha: &Sha256,
        started_at: SystemTime,
        still_unreferenced: StillUnreferenced,
    ) -> Result<TrashFinish, StoreError>;

    /// Blobs in the trash area, sorted by digest, at most `limit`.
    async fn trash_list(&self, limit: usize) -> Result<TrashListing, StoreError>;

    /// Hash-verified bytes of a trash blob (`NotFound` / `Corrupt`).
    async fn trash_read(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError>;

    /// Permanently removes one trash blob (identity-checked unlink).
    async fn trash_purge(&self, sha: &Sha256) -> Result<TrashPurge, StoreError>;

    /// The store's internal quarantine, if it has one (empty otherwise).
    async fn quarantine_list(&self, limit: usize) -> Result<QuarantineListing, StoreError>;

    /// Removes quarantined files whose quarantine time is before `older_than` (unix seconds).
    async fn quarantine_purge(&self, older_than: i64) -> Result<QuarantinePurge, StoreError> {
        self.quarantine_purge_checked(older_than, None, None).await
    }

    /// A bounded purge: check the deadline before removal and the authority gate on a blocking
    /// thread before every [`QuarantinePurge::BATCH_SIZE`] entries, including the first batch.
    /// A false gate stops the run; implementations must not fall back to an unchecked purge.
    async fn quarantine_purge_checked(
        &self,
        older_than: i64,
        deadline: Option<Instant>,
        gate: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Result<QuarantinePurge, StoreError>;
}
