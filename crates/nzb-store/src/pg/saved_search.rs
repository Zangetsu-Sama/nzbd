//! Saved searches on Postgres (T127; same rules as the SQLite module `saved_search`): owner-scoped on every call,
//! actor re-validated and the limit/uniqueness checked under the account-domain lock, `UNIQUE` as the backstop.

//! Account-id mutation methods are for trusted internal callers. Session-backed handlers use `*_as`,
//! which also reject a revoked, expired, pending, or foreign session inside the same transaction.

use sqlx::Row;

use crate::StoreError;
use crate::account::{AccountActor, Role};
use crate::pg::PgDb;
use crate::pg::account::{require_actor, require_session_actor};
use crate::saved_search::{
    MAX_SAVED_SEARCHES, SavedSearch, SavedSearchError, check_filters, check_name,
};

fn from_row(r: &sqlx::postgres::PgRow) -> Result<SavedSearch, StoreError> {
    Ok(SavedSearch {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        filters: r.try_get("filters")?,
        created_at: r.try_get("created_at")?,
        last_seen_at: r.try_get("last_seen_at")?,
    })
}

/// A unique violation of the per-account name constraint (only reachable if the lock were bypassed).
fn duplicate_or(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(d) = &e
        && d.constraint() == Some("saved_search_name_per_account")
    {
        return SavedSearchError::Duplicate.into();
    }
    e.into()
}

impl PgDb {
    /// The saved searches of `account_id`, by name (see the SQLite twin).
    ///
    /// # Errors
    /// Database failure.
    pub async fn saved_searches(&self, account_id: i64) -> Result<Vec<SavedSearch>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, filters, created_at, last_seen_at FROM saved_search \
             WHERE account_id = $1 ORDER BY name, id",
        )
        .bind(account_id)
        .fetch_all(self.web())
        .await?;
        rows.iter().map(from_row).collect()
    }

    /// Saves a search for the caller (see the SQLite twin).
    ///
    /// # Errors
    /// As the SQLite twin.
    pub async fn create_saved_search(
        &self,
        account_id: i64,
        name: &str,
        filters: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        self.create_saved_search_inner(account_id, None, name, filters, now)
            .await
    }

    /// Session-bound form of [`Self::create_saved_search`]; checks the session inside the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn create_saved_search_as(
        &self,
        actor: &AccountActor,
        name: &str,
        filters: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        self.create_saved_search_inner(actor.user_id, Some(actor), name, filters, now)
            .await
    }

    async fn create_saved_search_inner(
        &self,
        account_id: i64,
        actor: Option<&AccountActor>,
        name: &str,
        filters: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        check_name(name)?;
        check_filters(filters)?;
        let mut tx = self.begin_account().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let (n, same): (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE name = $2) FROM saved_search WHERE account_id = $1",
        )
        .bind(s.id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        if same > 0 {
            return Err(SavedSearchError::Duplicate.into());
        }
        if n >= MAX_SAVED_SEARCHES {
            return Err(SavedSearchError::Limit.into());
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO saved_search (account_id, name, filters, created_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $4) RETURNING id",
        )
        .bind(s.id)
        .bind(name)
        .bind(filters)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(duplicate_or)?;
        tx.commit().await?;
        Ok(id)
    }

    /// Renames one of the caller's saved searches (see the SQLite twin).
    ///
    /// # Errors
    /// As the SQLite twin.
    pub async fn rename_saved_search(
        &self,
        account_id: i64,
        id: i64,
        name: &str,
    ) -> Result<(), StoreError> {
        self.rename_saved_search_inner(account_id, None, id, name, 0)
            .await
    }

    /// Session-bound form of [`Self::rename_saved_search`]; checks the session inside the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn rename_saved_search_as(
        &self,
        actor: &AccountActor,
        id: i64,
        name: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.rename_saved_search_inner(actor.user_id, Some(actor), id, name, now)
            .await
    }

    async fn rename_saved_search_inner(
        &self,
        account_id: i64,
        actor: Option<&AccountActor>,
        id: i64,
        name: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        check_name(name)?;
        let mut tx = self.begin_account().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let current: Option<String> =
            sqlx::query_scalar("SELECT name FROM saved_search WHERE id = $1 AND account_id = $2")
                .bind(id)
                .bind(s.id)
                .fetch_optional(&mut *tx)
                .await?;
        match current {
            None => return Err(StoreError::NotFound),
            Some(c) if c == name => return Ok(()),
            Some(_) => {}
        }
        let taken: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM saved_search WHERE account_id = $1 AND name = $2",
        )
        .bind(s.id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        if taken > 0 {
            return Err(SavedSearchError::Duplicate.into());
        }
        sqlx::query("UPDATE saved_search SET name = $3 WHERE id = $1 AND account_id = $2")
            .bind(id)
            .bind(s.id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(duplicate_or)?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes one of the caller's saved searches (see the SQLite twin).
    ///
    /// # Errors
    /// As the SQLite twin.
    pub async fn delete_saved_search(&self, account_id: i64, id: i64) -> Result<(), StoreError> {
        self.delete_saved_search_inner(account_id, None, id, 0)
            .await
    }

    /// Session-bound form of [`Self::delete_saved_search`]; checks the session inside the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn delete_saved_search_as(
        &self,
        actor: &AccountActor,
        id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.delete_saved_search_inner(actor.user_id, Some(actor), id, now)
            .await
    }

    async fn delete_saved_search_inner(
        &self,
        account_id: i64,
        actor: Option<&AccountActor>,
        id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let n = sqlx::query("DELETE FROM saved_search WHERE id = $1 AND account_id = $2")
            .bind(id)
            .bind(s.id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Opens one of the caller's saved searches: `last_seen_at = greatest(last_seen_at, now)`, returning the row as it
    /// was before (see the SQLite twin). One statement: the CTE reads the old row, the update sets the new value.
    ///
    /// # Errors
    /// Database failure.
    pub async fn open_saved_search(
        &self,
        account_id: i64,
        id: i64,
        now: i64,
    ) -> Result<Option<SavedSearch>, StoreError> {
        self.open_saved_search_inner(account_id, None, id, now)
            .await
    }

    /// Session-bound form of [`Self::open_saved_search`]; checks the session inside the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn open_saved_search_as(
        &self,
        actor: &AccountActor,
        id: i64,
        now: i64,
    ) -> Result<Option<SavedSearch>, StoreError> {
        self.open_saved_search_inner(actor.user_id, Some(actor), id, now)
            .await
    }

    async fn open_saved_search_inner(
        &self,
        account_id: i64,
        actor: Option<&AccountActor>,
        id: i64,
        now: i64,
    ) -> Result<Option<SavedSearch>, StoreError> {
        let mut tx = self.begin_account().await?;
        if let Some(a) = actor {
            require_session_actor(&mut tx, a, Role::Viewer, now).await?;
        }
        let row = sqlx::query(
            "WITH old AS (SELECT id, name, filters, created_at, last_seen_at FROM saved_search \
                          WHERE id = $1 AND account_id = $2 FOR UPDATE), \
                  upd AS (UPDATE saved_search s SET last_seen_at = greatest(s.last_seen_at, $3) \
                          FROM old WHERE s.id = old.id) \
             SELECT id, name, filters, created_at, last_seen_at FROM old",
        )
        .bind(id)
        .bind(account_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let found = row.as_ref().map(from_row).transpose()?;
        tx.commit().await?;
        Ok(found)
    }
}
