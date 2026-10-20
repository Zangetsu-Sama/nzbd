//! Per-account preferences on Postgres (T120, T133; same rules as the SQLite module `pref`): own account only, actor
//! re-validated under the account-domain lock, one `pref_change keys=...` audit row per change. Partial saves
//! (`patch_user_prefs`, `set_page_size`) apply to the row as read under that lock, so concurrent saves of different
//! fields never revert each other (T133 review 48 L1).

//! Account-id mutation methods are for trusted internal callers; HTTP handlers use the `*_as`
//! methods, which bind the transaction to the authenticated session as well as its account.

use sqlx::Row;

use crate::StoreError;
use crate::account::{AccountActor, AuditActor, Role};
use crate::pg::PgDb;
use crate::pg::account::{require_actor, require_session_actor, write_audit};
use crate::pref::{PREF_CHANGE_EVENT, PageSize, PrefColumns, PrefsPatch, UserPrefs};

/// Decodes one optional Postgres `user_pref` row (`SELECT hide_xxx, theme, page_size_releases, page_size_files`).
fn pg_prefs(row: Option<sqlx::postgres::PgRow>) -> Result<UserPrefs, StoreError> {
    let Some(r) = row else {
        return Ok(UserPrefs::default());
    };
    let theme: String = r.try_get("theme")?;
    UserPrefs::from_columns(PrefColumns {
        hide_xxx: Some(r.try_get("hide_xxx")?),
        theme: Some(&theme),
        page_size_releases: Some(r.try_get("page_size_releases")?),
        page_size_files: Some(r.try_get("page_size_files")?),
    })
}

/// Single-column upserts of one page size; the column is chosen by the [`PageSize`] variant, never by request text.
const PG_SET_RELEASES: &str = "INSERT INTO user_pref (account_id, page_size_releases, updated_at) VALUES ($1, $2, $3) \
     ON CONFLICT (account_id) DO UPDATE SET page_size_releases = EXCLUDED.page_size_releases, \
     updated_at = EXCLUDED.updated_at";
const PG_SET_FILES: &str = "INSERT INTO user_pref (account_id, page_size_files, updated_at) VALUES ($1, $2, $3) \
     ON CONFLICT (account_id) DO UPDATE SET page_size_files = EXCLUDED.page_size_files, \
     updated_at = EXCLUDED.updated_at";

impl PgDb {
    /// The stored preferences of `account_id` (defaults when there is no row).
    ///
    /// # Errors
    /// Database failure.
    pub async fn user_prefs(&self, account_id: i64) -> Result<UserPrefs, StoreError> {
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(self.web())
        .await?;
        pg_prefs(row)
    }

    /// Stores the caller's OWN preferences (see the SQLite twin). Returns whether anything changed.
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn set_user_prefs(
        &self,
        actor_id: i64,
        prefs: UserPrefs,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs(actor_id, PrefsPatch::all(prefs), ip, now)
            .await
    }

    /// Applies `patch` to the caller's OWN preferences as read under the account-domain lock (see the SQLite twin).
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn patch_user_prefs(
        &self,
        actor_id: i64,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs_inner(actor_id, None, patch, ip, now)
            .await
    }

    /// Session-bound form of [`Self::patch_user_prefs`]; rechecks the session in the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn patch_user_prefs_as(
        &self,
        actor: &AccountActor,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs_inner(actor.user_id, Some(actor), patch, ip, now)
            .await
    }

    async fn patch_user_prefs_inner(
        &self,
        actor_id: i64,
        actor: Option<&AccountActor>,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_account().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, actor_id, Role::Viewer).await?,
        };
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = $1",
        )
        .bind(s.id)
        .fetch_optional(&mut *tx)
        .await?;
        let old = pg_prefs(row)?;
        let prefs = patch.applied_to(old);
        let Some(detail) = prefs.change_detail(old) else {
            return Ok(false);
        };
        sqlx::query(
            "INSERT INTO user_pref (account_id, hide_xxx, theme, page_size_releases, page_size_files, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (account_id) DO UPDATE SET hide_xxx = EXCLUDED.hide_xxx, theme = EXCLUDED.theme, \
             page_size_releases = EXCLUDED.page_size_releases, page_size_files = EXCLUDED.page_size_files, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind(s.id)
        .bind(prefs.hide_xxx)
        .bind(prefs.theme.as_str())
        .bind(prefs.page_size_releases.column())
        .bind(prefs.page_size_files.column())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let who = AuditActor::account(s.id, s.role, &s.username);
        write_audit(
            &mut tx,
            &who,
            now,
            PREF_CHANGE_EVENT,
            Some(&detail),
            ip,
            Some(s.id),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Stores ONE page size, writing only that column (see the SQLite twin).
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn set_page_size(
        &self,
        actor_id: i64,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.set_page_size_inner(actor_id, None, size, ip, now)
            .await
    }

    /// Session-bound form of [`Self::set_page_size`]; rechecks the session in the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn set_page_size_as(
        &self,
        actor: &AccountActor,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.set_page_size_inner(actor.user_id, Some(actor), size, ip, now)
            .await
    }

    async fn set_page_size_inner(
        &self,
        actor_id: i64,
        actor: Option<&AccountActor>,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_account().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, actor_id, Role::Viewer).await?,
        };
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = $1",
        )
        .bind(s.id)
        .fetch_optional(&mut *tx)
        .await?;
        let old = pg_prefs(row)?;
        let Some(detail) = size.applied_to(old).change_detail(old) else {
            return Ok(false);
        };
        let query = match size {
            PageSize::Releases(n) => sqlx::query(PG_SET_RELEASES).bind(s.id).bind(n.column()),
            PageSize::Files(n) => sqlx::query(PG_SET_FILES).bind(s.id).bind(n.column()),
        };
        query.bind(now).execute(&mut *tx).await?;
        let who = AuditActor::account(s.id, s.role, &s.username);
        write_audit(
            &mut tx,
            &who,
            now,
            PREF_CHANGE_EVENT,
            Some(&detail),
            ip,
            Some(s.id),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}
