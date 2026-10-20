//! The NFO of a release (T140, D41): raw bytes in `release_nfo`, keyed by the release's NZB digest.
//!
//! Keying by digest instead of `release.id` lets a deleted release keep its NFO while it is in the trash (a
//! restore re-ingests the same digest and finds it again); [`SqliteDb::purge_trash_record`] deletes it with the
//! trash record. The bytes are display data only: nothing here decodes, parses or logs them.
//!
//! Who may attach (D41 b), re-checked inside the writing transaction: an admin, or the release's own uploader, and
//! only while the release has none. Nobody replaces an NFO through an upload; an admin removes it first.

use nzb_core::Sha256;
use serde_json::json;
use sqlx::Row;

use crate::account::{
    AccountActor, AccountError, AuditActor, Role, load_live, require_actor, write_audit,
};
use crate::attribution::{Uploader, resolve_uploader};
use crate::trash::sha8;
use crate::{SqliteDb, StoreError};

/// Largest NFO the database accepts (the `release_nfo.bytes` CHECK; `nzb_core::MAX_NFO_BYTES`).
pub const MAX_NFO_STORED_BYTES: usize = 256 * 1024;

/// How long a restored NFO waits for its NZB to be ingested again before the trash purge sweeps it (review 49 L1).
pub(crate) const RESTORE_GRACE_SECS: i64 = 24 * 60 * 60;

/// Hides the NFO of a release that moves to the trash (in the trash transaction; review 49 M1).
pub(crate) async fn hide_for_trash(
    conn: &mut sqlx::SqliteConnection,
    sha: &[u8],
    now: i64,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE release_nfo SET trashed_at = ?2 WHERE sha256 = ?1")
        .bind(sha)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The stored NFO of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseNfo {
    /// The raw bytes as uploaded (hostile display data).
    pub bytes: Vec<u8>,
    /// Unix seconds it was attached.
    pub added_at: i64,
    /// The account that attached it; `None` once unknown.
    pub added_by: Option<i64>,
}

/// Result of an attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfoAttach {
    /// Stored by this call (audit `nfo_attach` written).
    Attached,
    /// The release already has an NFO; nothing was written.
    AlreadyPresent,
}

/// `{release, sha, bytes}` (+ `key` for an API key): server values only, never NFO content.
pub(crate) fn attach_detail(release_id: i64, sha: &Sha256, len: usize, key: Option<i64>) -> String {
    match key {
        Some(k) => json!({"release": release_id, "sha": sha8(sha), "bytes": len, "key": k}),
        None => json!({"release": release_id, "sha": sha8(sha), "bytes": len}),
    }
    .to_string()
}

/// `{release, sha, bytes, source: "watch"}` of a watch-folder sidecar (T141): server values only.
pub(crate) fn watch_attach_detail(release_id: i64, sha: &Sha256, len: usize) -> String {
    json!({"release": release_id, "sha": sha8(sha), "bytes": len, "source": "watch"}).to_string()
}

/// The upsert of every attach: a new row, or the replacement of an NFO hidden by the trash (review 49 M1); a shown
/// NFO is never replaced (D41 b).
pub(crate) const ATTACH_UPSERT_SQLITE: &str = "INSERT INTO release_nfo (sha256, bytes, added_at, added_by) VALUES (?1, ?2, ?3, ?4) \
     ON CONFLICT(sha256) DO UPDATE SET bytes = excluded.bytes, added_at = excluded.added_at, \
     added_by = excluded.added_by, trashed_at = NULL, restored_at = NULL \
     WHERE release_nfo.trashed_at IS NOT NULL";

/// The size rule of the `release_nfo.bytes` CHECK, applied before any statement runs.
pub(crate) fn check_size(bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_NFO_STORED_BYTES {
        return Err(StoreError::OutOfRange("nfo size"));
    }
    Ok(())
}

pub(crate) const fn key_of(uploader: &Uploader) -> Option<i64> {
    match *uploader {
        Uploader::ApiKey(k) => Some(k),
        Uploader::Account(_) | Uploader::Session { .. } | Uploader::Unattributed => None,
    }
}

/// Most ids [`SqliteDb::releases_with_nfo`] accepts (the largest page is 100; this is a defensive bound).
pub const MAX_NFO_LOOKUP_IDS: usize = 1000;

impl SqliteDb {
    /// Which of `ids` have a live (not trashed) NFO: one query for a whole index page (T144), not one per row.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for more than [`MAX_NFO_LOOKUP_IDS`] ids; database failure.
    pub async fn releases_with_nfo(
        &self,
        ids: &[i64],
    ) -> Result<std::collections::HashSet<i64>, StoreError> {
        if ids.len() > MAX_NFO_LOOKUP_IDS {
            return Err(StoreError::OutOfRange("nfo id list"));
        }
        if ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        // One bound text parameter (a JSON array of integers), expanded by json_each: no string-built SQL.
        let list = serde_json::to_string(ids).map_err(|_| StoreError::OutOfRange("nfo id list"))?;
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT r.id FROM release r JOIN release_nfo n ON n.sha256 = r.sha256 \
             WHERE n.trashed_at IS NULL AND r.id IN (SELECT value FROM json_each(?1))",
        )
        .bind(list)
        .fetch_all(self.readers())
        .await?;
        Ok(found.into_iter().collect())
    }

    /// The NFO of release `release_id`, if it has one.
    ///
    /// # Errors
    /// Database failure.
    pub async fn release_nfo(&self, release_id: i64) -> Result<Option<ReleaseNfo>, StoreError> {
        let row = sqlx::query(
            "SELECT n.bytes, n.added_at, n.added_by FROM release r \
             JOIN release_nfo n ON n.sha256 = r.sha256 WHERE r.id = ?1 AND n.trashed_at IS NULL",
        )
        .bind(release_id)
        .fetch_optional(self.readers())
        .await?;
        row.map(|r| {
            Ok(ReleaseNfo {
                bytes: r.try_get("bytes")?,
                added_at: r.try_get("added_at")?,
                added_by: r.try_get("added_by")?,
            })
        })
        .transpose()
    }

    /// Attaches `bytes` as the NFO of release `release_id`, which must still have the digest `expected` (ids are
    /// reusable rowids). The uploader is re-validated like an upload (live, enabled, at least uploader; a key must be
    /// live with a usable owner) and must be an admin or the release's own uploader. Audit `nfo_attach`.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`] / [`AccountError::KeyRefused`] (nothing written), [`StoreError::NotFound`] (no
    /// release with that id and digest), [`StoreError::OutOfRange`] (empty or over 256 KiB).
    pub async fn attach_nfo_as(
        &self,
        uploader: &Uploader,
        release_id: i64,
        expected: &Sha256,
        bytes: &[u8],
        now: i64,
        ip: Option<&str>,
    ) -> Result<NfoAttach, StoreError> {
        check_size(bytes)?;
        let mut tx = self.begin_immediate().await?;
        let Some(uid) = resolve_uploader(&mut tx, uploader, now).await? else {
            return Err(AccountError::Forbidden.into());
        };
        let Some(a) = load_live(&mut tx, uid).await? else {
            return Err(AccountError::Forbidden.into());
        };
        let added_by: Option<i64> =
            sqlx::query_scalar("SELECT added_by FROM release WHERE id = ?1 AND sha256 = ?2")
                .bind(release_id)
                .bind(expected.0.to_vec())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
        if a.role < Role::Admin && added_by != Some(a.id) {
            return Err(AccountError::Forbidden.into());
        }
        let inserted = sqlx::query(ATTACH_UPSERT_SQLITE)
            .bind(expected.0.to_vec())
            .bind(bytes)
            .bind(now)
            .bind(a.id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if inserted == 0 {
            return Ok(NfoAttach::AlreadyPresent);
        }
        let detail = attach_detail(release_id, expected, bytes.len(), key_of(uploader));
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "nfo_attach",
            Some(&detail),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(NfoAttach::Attached)
    }

    /// Attaches the watch-folder sidecar `bytes` (T141, D41 amended) as the NFO of release `release_id`, which must
    /// still have the digest `expected`. The watch folder is the operator's own input and unattributed (D38), so
    /// there is no account to re-check: the process attaches (`added_by` NULL, audit `nfo_attach` by the `system`
    /// actor with `"source":"watch"`), under the same rule as an upload, only while the release has none (a shown NFO
    /// is never replaced; one hidden by the trash is).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] (no release with that id and digest), [`StoreError::OutOfRange`] (empty or over
    /// 256 KiB); nothing is written on an error.
    pub async fn attach_watch_nfo(
        &self,
        release_id: i64,
        expected: &Sha256,
        bytes: &[u8],
        now: i64,
    ) -> Result<NfoAttach, StoreError> {
        check_size(bytes)?;
        let mut tx = self.begin_immediate().await?;
        let found: Option<i64> =
            sqlx::query_scalar("SELECT id FROM release WHERE id = ?1 AND sha256 = ?2")
                .bind(release_id)
                .bind(expected.0.to_vec())
                .fetch_optional(&mut *tx)
                .await?;
        if found.is_none() {
            return Err(StoreError::NotFound);
        }
        let inserted = sqlx::query(ATTACH_UPSERT_SQLITE)
            .bind(expected.0.to_vec())
            .bind(bytes)
            .bind(now)
            .bind(None::<i64>)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if inserted == 0 {
            return Ok(NfoAttach::AlreadyPresent);
        }
        let detail = watch_attach_detail(release_id, expected, bytes.len());
        write_audit(
            &mut tx,
            &AuditActor::system(),
            now,
            "nfo_attach",
            Some(&detail),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(NfoAttach::Attached)
    }

    /// Removes the NFO of release `release_id` (admin). Audit `nfo_remove` when one was removed. Returns whether
    /// there was one.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`StoreError::NotFound`] (no such release).
    pub async fn remove_nfo_as(
        &self,
        actor: &AccountActor,
        release_id: i64,
        now: i64,
        ip: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let a = require_actor(&mut tx, actor.user_id, Role::Admin).await?;
        let sha: Vec<u8> = sqlx::query_scalar("SELECT sha256 FROM release WHERE id = ?1")
            .bind(release_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let digest = <[u8; 32]>::try_from(sha.as_slice())
            .map(Sha256)
            .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
        let len: Option<i64> =
            sqlx::query_scalar("DELETE FROM release_nfo WHERE sha256 = ?1 AND trashed_at IS NULL RETURNING length(bytes)")
                .bind(&sha)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(len) = len else {
            return Ok(false);
        };
        let detail = json!({"release": release_id, "sha": sha8(&digest), "bytes": len}).to_string();
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "nfo_remove",
            Some(&detail),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Removes the trash record `id` and, unless a live release has the same digest again, its NFO, in one
    /// transaction (the trash purge; a restore uses [`SqliteDb::forget_trash`] and keeps the NFO). Returns whether a
    /// record existed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_trash_record(&self, id: i64, now: i64) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let sha: Option<Vec<u8>> =
            sqlx::query_scalar("DELETE FROM release_trash WHERE id = ?1 RETURNING sha256")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(sha) = sha else {
            return Ok(false);
        };
        sqlx::query("DELETE FROM release_nfo WHERE sha256 = ?1 AND trashed_at IS NOT NULL")
            .bind(&sha)
            .execute(&mut *tx)
            .await?;
        // Review 49 L1: an NFO whose trash entry was restored a day ago while its NZB never came back.
        sqlx::query(
            "DELETE FROM release_nfo WHERE trashed_at IS NULL AND restored_at < ?1 \
             AND NOT EXISTS (SELECT 1 FROM release r WHERE r.sha256 = release_nfo.sha256)",
        )
        .bind(now.saturating_sub(RESTORE_GRACE_SECS))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}
