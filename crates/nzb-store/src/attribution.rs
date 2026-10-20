//! Attribution of library changes (T101a; SEC-067, SEC-036 owner clause, SEC-050 v2).
//!
//! `release.added_by`, `ingest_log.user_id`, `release_trash.deleted_by` and the audit actor always come
//! from a session actor or the owner of an API key, re-validated INSIDE the transaction that writes the
//! row (N9): a key revoked, or an owner disabled/demoted, while an upload body streamed is refused and
//! nothing is written. No function here takes an attribution from request data.

use serde_json::json;
use sqlx::{Row, SqliteConnection};

use crate::account::{
    AccountActor, AccountError, AuditActor, Role, require_actor, require_session_actor, write_audit,
};
use crate::ingest_log::{IngestLogEntry, insert_log_row};
use crate::{NewRelease, SqliteDb, StoreError, TrashRow};

/// Who submitted an NZB.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Uploader {
    /// Watch folder, operator CLI or pre-2.0 callers: `added_by` stays NULL.
    Unattributed,
    /// A trusted operator/internal account; re-validated in the transaction.
    Account(i64),
    /// A UI uploader/admin; both account and browser session are re-validated in the transaction.
    Session {
        /// Account captured from the authenticated session.
        user_id: i64,
        /// SHA-256 of the browser session id, never the raw cookie.
        id_hash: [u8; 32],
    },
    /// An upload API key (by key id); the key and its owner are re-validated in the transaction.
    ApiKey(i64),
}

impl std::fmt::Debug for Uploader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unattributed => f.write_str("Unattributed"),
            Self::Account(id) => f.debug_tuple("Account").field(id).finish(),
            Self::ApiKey(id) => f.debug_tuple("ApiKey").field(id).finish(),
            Self::Session { user_id, .. } => f
                .debug_struct("Session")
                .field("user_id", user_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Validates the uploader inside `conn` and returns the account to record (`None` = unattributed).
///
/// # Errors
/// [`AccountError::Forbidden`] (account no longer a live enabled uploader/admin),
/// [`AccountError::KeyRefused`] (key revoked/unknown or its owner unusable).
pub(crate) async fn resolve_uploader(
    conn: &mut SqliteConnection,
    uploader: &Uploader,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    match *uploader {
        Uploader::Unattributed => Ok(None),
        Uploader::Account(id) => {
            let a = require_actor(conn, id, Role::Uploader).await?;
            Ok(Some(a.id))
        }
        Uploader::Session { user_id, id_hash } => {
            let a = require_actor(conn, user_id, Role::Uploader).await?;
            if !crate::auth::session_is_live(conn, &id_hash, user_id, now).await? {
                return Err(AccountError::Forbidden.into());
            }
            Ok(Some(a.id))
        }
        Uploader::ApiKey(key_id) => {
            let row = sqlx::query(
                "SELECT k.owner_id, k.scope, u.role, u.disabled_at, u.deleted_at FROM api_key k \
                 LEFT JOIN account u ON u.id = k.owner_id \
                 WHERE k.id = ?1 AND k.revoked_at IS NULL",
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

/// Whether a key row may submit an NZB: scope `upload`, owner enabled, live and uploader or admin.
/// Pure so the scope rule is testable without a row that the table CHECK would refuse (N9, T1).
pub(crate) fn key_usable(
    scope: &str,
    owner_role: Option<&str>,
    disabled: bool,
    deleted: bool,
) -> bool {
    scope == crate::SCOPE_UPLOAD
        && !disabled
        && !deleted
        && owner_role
            .and_then(Role::parse)
            .is_some_and(|r| r >= Role::Uploader)
}

#[cfg(test)]
mod key_usable_tests {
    use super::key_usable;

    #[test]
    fn sec_036_ingest_transaction_requires_the_upload_scope() {
        assert!(key_usable("upload", Some("uploader"), false, false));
        assert!(key_usable("upload", Some("admin"), false, false));
        assert!(!key_usable("read", Some("admin"), false, false));
        assert!(!key_usable("", Some("admin"), false, false));
        assert!(!key_usable("upload", Some("viewer"), false, false));
        // The pre-D40 name is not a role any more.
        assert!(!key_usable("upload", Some("member"), false, false));
        assert!(!key_usable("upload", None, false, false));
        assert!(!key_usable("upload", Some("uploader"), true, false));
        assert!(!key_usable("upload", Some("uploader"), false, true));
    }
}

/// Attribution of a release as shown on the detail page (handle, never the login name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAttribution {
    /// Uploading account, `None` = "Before accounts" / watch folder.
    pub added_by: Option<i64>,
    /// The uploader's display handle (`user-<id>` for NULL), `None` when unattributed.
    pub handle: Option<String>,
    /// True when the uploading account has been tombstoned ("Deleted account").
    pub deleted: bool,
}

impl SqliteDb {
    /// Inserts a release with its files and FTS row (and the `ingest_log` row when `log` is given) in
    /// one transaction, recording the uploader (`release.added_by`, `ingest_log.user_id`) after
    /// re-validating it in that transaction.
    ///
    /// # Errors
    /// As [`SqliteDb::insert_release_logged`]; [`AccountError::Forbidden`] / [`AccountError::KeyRefused`]
    /// when the uploader is no longer usable (nothing is written).
    pub async fn insert_release_as(
        &self,
        new: &NewRelease<'_>,
        log: Option<&IngestLogEntry<'_>>,
        uploader: &Uploader,
    ) -> Result<i64, StoreError> {
        self.insert_release_inner(new, log, uploader).await
    }

    /// Appends an `ingest_log` row (duplicate/failed outcome) attributed to `uploader`. No gating: a
    /// refused or duplicate upload is still worth a row.
    ///
    /// # Errors
    /// Database failure.
    pub async fn log_ingest_as(
        &self,
        e: &IngestLogEntry<'_>,
        release_id: Option<i64>,
        uploader: &Uploader,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_immediate().await?;
        let user = match *uploader {
            Uploader::Unattributed => None,
            Uploader::Account(id) | Uploader::Session { user_id: id, .. } => Some(id),
            Uploader::ApiKey(key) => {
                sqlx::query_scalar::<_, Option<i64>>("SELECT owner_id FROM api_key WHERE id = ?1")
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

    /// Re-validates `uploader` without writing anything (T101b): the ingest pipeline calls it before
    /// answering "duplicate" so a key revoked, or an owner disabled, while a body streamed learns
    /// nothing about the library either (N9).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`] / [`AccountError::KeyRefused`]; database failure.
    pub async fn validate_uploader(&self, uploader: &Uploader, now: i64) -> Result<(), StoreError> {
        if matches!(uploader, Uploader::Unattributed) {
            return Ok(());
        }
        let mut tx = self.begin_immediate().await?;
        resolve_uploader(&mut tx, uploader, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Manual category override by an admin (D26 c, D40: any release). Audit `category_override` with
    /// the actor and the old and new category (I-3). Returns the old category id.
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
        let mut tx = self.begin_immediate().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let old: i64 = sqlx::query_scalar("SELECT category_id FROM release WHERE id = ?1")
            .bind(release_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM category WHERE id = ?1")
            .bind(i64::from(category_id))
            .fetch_one(&mut *tx)
            .await?;
        if known == 0 {
            return Err(StoreError::UnknownCategory);
        }
        sqlx::query(
            "UPDATE release SET category_id = ?2, category_overridden = 1, \
             category_source = 'manual', flags = flags & ~512 WHERE id = ?1",
        )
        .bind(release_id)
        .bind(i64::from(category_id))
        .execute(&mut *tx)
        .await?;
        let detail = format!("release={release_id} old={old} new={category_id}");
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
        self.bump_release_epoch();
        u32::try_from(old).map_err(|_| StoreError::OutOfRange("category_id"))
    }

    /// Sets or clears the source label of any release (admin, D40). Audit `source_label_edit` with the
    /// actor and the old and new value as a JSON object (the labels are hostile text, so they are
    /// serialized, not concatenated). Returns the stored value.
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
        let clean = label.and_then(crate::clean_source_label);
        let mut tx = self.begin_immediate().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let old: Option<String> =
            sqlx::query_scalar("SELECT source_label FROM release WHERE id = ?1")
                .bind(release_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
        sqlx::query("UPDATE release SET source_label = ?2 WHERE id = ?1")
            .bind(release_id)
            .bind(clean.as_deref())
            .execute(&mut *tx)
            .await?;
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

    /// Moves a release to the trash on an ADMIN's authority (SEC-050 v2): the actor is re-validated in
    /// the transaction, `release_trash.deleted_by`/`added_by` are recorded and the `release_delete` audit
    /// row carries actor id, kind and role. Uploaders and viewers are refused with
    /// [`AccountError::Forbidden`] before anything is read.
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

    /// Like [`SqliteDb::trash_release_as`], but only while the release still has the digest the admin
    /// confirmed (ids are reusable rowids). Used by the single and the bulk delete (T119).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`]; [`StoreError::NotFound`] when the release is gone **or** now has
    /// another digest (nothing is written then).
    pub async fn trash_release_checked_as(
        &self,
        actor: &AccountActor,
        id: i64,
        expected: &nzb_core::Sha256,
        now: i64,
        ip: Option<&str>,
    ) -> Result<TrashRow, StoreError> {
        self.trash_release_inner(id, Some(expected), now, ip, TrashActor::Account(actor))
            .await
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
             LEFT JOIN account u ON u.id = r.added_by WHERE r.id = ?1",
        )
        .bind(release_id)
        .fetch_optional(self.readers())
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
}

/// Who trashes a release.
#[derive(Clone, Copy)]
pub(crate) enum TrashActor<'a> {
    /// Legacy caller-supplied actor text (1.x `trash_release`); no attribution columns.
    Text(&'a str),
    /// A re-validated admin account and, for browser requests, its current session.
    Account(&'a AccountActor),
}
