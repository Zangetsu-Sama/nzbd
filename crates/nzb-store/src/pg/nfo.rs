//! The NFO of a release on Postgres (T140, D41); same rules as the SQLite twin in `crate::nfo`.

use nzb_core::Sha256;
use serde_json::json;
use sqlx::Row;

use crate::StoreError;
use crate::account::{AccountActor, AccountError, AuditActor, Role};
use crate::attribution::Uploader;
use crate::nfo::{
    NfoAttach, RESTORE_GRACE_SECS, ReleaseNfo, attach_detail, check_size, key_of,
    watch_attach_detail,
};
use crate::pg::PgDb;
use crate::pg::account::write_audit;
use crate::pg::release::{require_actor_share, resolve_uploader};
use crate::trash::sha8;

/// See `crate::nfo::ATTACH_UPSERT_SQLITE`.
const ATTACH_UPSERT_PG: &str = "INSERT INTO release_nfo (sha256, bytes, added_at, added_by) VALUES ($1, $2, $3, $4) \
     ON CONFLICT (sha256) DO UPDATE SET bytes = excluded.bytes, added_at = excluded.added_at, \
     added_by = excluded.added_by, trashed_at = NULL, restored_at = NULL \
     WHERE release_nfo.trashed_at IS NOT NULL";

/// See `crate::nfo::hide_for_trash`.
pub(crate) async fn hide_for_trash(
    conn: &mut sqlx::PgConnection,
    sha: &[u8],
    now: i64,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE release_nfo SET trashed_at = $2 WHERE sha256 = $1")
        .bind(sha)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

impl PgDb {
    /// See `SqliteDb::releases_with_nfo`.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for more than `MAX_NFO_LOOKUP_IDS` ids; database failure.
    pub async fn releases_with_nfo(
        &self,
        ids: &[i64],
    ) -> Result<std::collections::HashSet<i64>, StoreError> {
        if ids.len() > crate::nfo::MAX_NFO_LOOKUP_IDS {
            return Err(StoreError::OutOfRange("nfo id list"));
        }
        if ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT r.id FROM release r JOIN release_nfo n ON n.sha256 = r.sha256 \
             WHERE n.trashed_at IS NULL AND r.id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(self.web())
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
             JOIN release_nfo n ON n.sha256 = r.sha256 WHERE r.id = $1 AND n.trashed_at IS NULL",
        )
        .bind(release_id)
        .fetch_optional(self.web())
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

    /// See `SqliteDb::attach_nfo_as`. The uploader rows and the release row are share-locked until the commit, so a
    /// concurrent disable, revoke or delete waits for this attach.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`] / [`AccountError::KeyRefused`], [`StoreError::NotFound`], [`StoreError::OutOfRange`].
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
        let mut tx = self.web().begin().await?;
        let Some(uid) = resolve_uploader(&mut tx, uploader, now).await? else {
            return Err(AccountError::Forbidden.into());
        };
        let a = require_actor_share(&mut tx, uid, Role::Uploader).await?;
        let added_by: Option<i64> = sqlx::query_scalar(
            "SELECT added_by FROM release WHERE id = $1 AND sha256 = $2 FOR SHARE",
        )
        .bind(release_id)
        .bind(expected.0.to_vec())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        if a.role < Role::Admin && added_by != Some(a.id) {
            return Err(AccountError::Forbidden.into());
        }
        let inserted = sqlx::query(ATTACH_UPSERT_PG)
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

    /// See `SqliteDb::attach_watch_nfo`. Runs on the `ingest` pool (the watch folder's own writer); the release row is
    /// share-locked until the commit, so a concurrent delete waits for this attach.
    ///
    /// # Errors
    /// [`StoreError::NotFound`], [`StoreError::OutOfRange`].
    pub async fn attach_watch_nfo(
        &self,
        release_id: i64,
        expected: &Sha256,
        bytes: &[u8],
        now: i64,
    ) -> Result<NfoAttach, StoreError> {
        check_size(bytes)?;
        let mut tx = self.ingest().begin().await?;
        let found: Option<i64> =
            sqlx::query_scalar("SELECT id FROM release WHERE id = $1 AND sha256 = $2 FOR SHARE")
                .bind(release_id)
                .bind(expected.0.to_vec())
                .fetch_optional(&mut *tx)
                .await?;
        if found.is_none() {
            return Err(StoreError::NotFound);
        }
        let inserted = sqlx::query(ATTACH_UPSERT_PG)
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

    /// See `SqliteDb::remove_nfo_as`.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`StoreError::NotFound`].
    pub async fn remove_nfo_as(
        &self,
        actor: &AccountActor,
        release_id: i64,
        now: i64,
        ip: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.web().begin().await?;
        let a = require_actor_share(&mut tx, actor.user_id, Role::Admin).await?;
        let sha: Vec<u8> = sqlx::query_scalar("SELECT sha256 FROM release WHERE id = $1 FOR SHARE")
            .bind(release_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let digest = <[u8; 32]>::try_from(sha.as_slice())
            .map(Sha256)
            .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
        let len: Option<i32> = sqlx::query_scalar(
            "DELETE FROM release_nfo WHERE sha256 = $1 AND trashed_at IS NULL RETURNING octet_length(bytes)",
        )
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

    /// See `SqliteDb::purge_trash_record`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_trash_record(&self, id: i64, now: i64) -> Result<bool, StoreError> {
        let mut tx = self.web().begin().await?;
        let sha: Option<Vec<u8>> =
            sqlx::query_scalar("DELETE FROM release_trash WHERE id = $1 RETURNING sha256")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(sha) = sha else {
            return Ok(false);
        };
        sqlx::query("DELETE FROM release_nfo WHERE sha256 = $1 AND trashed_at IS NOT NULL")
            .bind(&sha)
            .execute(&mut *tx)
            .await?;
        // Review 49 L1: an NFO whose trash entry was restored a day ago while its NZB never came back.
        sqlx::query(
            "DELETE FROM release_nfo WHERE trashed_at IS NULL AND restored_at < $1 \
             AND NOT EXISTS (SELECT 1 FROM release r WHERE r.sha256 = release_nfo.sha256)",
        )
        .bind(now.saturating_sub(RESTORE_GRACE_SECS))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}
