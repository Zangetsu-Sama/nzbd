//! Saved searches (T127, D38; `DATA_MODEL` v3 3.2a `saved_search`): private per account, at most
//! [`MAX_SAVED_SEARCHES`] per account, names unique per account.
//!
//! The stored form is the **validated, structured filter set** of the index page: a JSON object of index parameter
//! names to canonical values. The store only checks that it is a small JSON object of strings; its meaning belongs to
//! the web layer, which writes it from validated parameters and re-validates it through the index parser on every use.
//! It is never search-engine syntax and never a URL.
//!
//! Every call is scoped by the caller's own account id: there is no cross-account read (no admin view). A row of
//! another account is indistinguishable from a missing one ([`StoreError::NotFound`]), so the web layer answers both
//! with the uniform 404. Writes re-validate the actor (live, enabled) inside the transaction; the count limit and the
//! name uniqueness are checked in the same transaction (SQLite: the single writer under `BEGIN IMMEDIATE`; Postgres:
//! the account-domain lock), with the `UNIQUE` constraint as the backstop. Rows are deleted with the account
//! (tombstone). Saved searches are not audited: they are private display state, like the theme value.

//! Account-id mutation methods are for trusted internal callers. Session-backed handlers use `*_as`,
//! which also reject a revoked, expired, pending, or foreign session inside the same transaction.

use sqlx::Row;

use crate::account::{AccountActor, Role, require_actor, require_session_actor};
use crate::{SqliteDb, StoreError};

/// Most saved searches one account may keep (`SAVED_SEARCH_LIMIT` beyond it).
pub const MAX_SAVED_SEARCHES: i64 = 25;
/// Longest name, in characters (after sanitizing).
pub const MAX_SAVED_SEARCH_NAME_CHARS: usize = 60;
/// Largest stored filter set, in bytes of its JSON text.
pub const MAX_SAVED_SEARCH_FILTER_BYTES: usize = 2048;

/// A refused saved-search rule. [`SavedSearchError::code`] is what clients see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SavedSearchError {
    /// The account already keeps [`MAX_SAVED_SEARCHES`].
    #[error("saved search limit reached")]
    Limit,
    /// The account already has a saved search of that name.
    #[error("duplicate saved search name")]
    Duplicate,
    /// The name is empty or too long after sanitizing, or is not in its sanitized form.
    #[error("invalid saved search name")]
    InvalidName,
    /// The filter set is not a small JSON object of strings.
    #[error("invalid saved search filters")]
    InvalidFilters,
}

impl SavedSearchError {
    /// Stable client code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Limit => "SAVED_SEARCH_LIMIT",
            Self::Duplicate => "SAVED_SEARCH_DUPLICATE",
            Self::InvalidName => "SAVED_SEARCH_NAME",
            Self::InvalidFilters => "BAD_QUERY",
        }
    }
}

impl From<SavedSearchError> for StoreError {
    fn from(e: SavedSearchError) -> Self {
        Self::SavedSearch(e)
    }
}

/// One saved search of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSearch {
    /// Row id (the `/search/saved/{id}` parameter; owner-scoped on every use).
    pub id: i64,
    /// Display name chosen by the account (sanitized; escaped on output).
    pub name: String,
    /// The validated filter set as a JSON object (see the module docs).
    pub filters: String,
    /// Creation time (Unix seconds).
    pub created_at: i64,
    /// When the account last opened it (creation counts as opening); releases ingested after it are "new".
    pub last_seen_at: i64,
}

/// The cleaned form of a user-supplied name: control, bidi and invisible format characters removed, whitespace runs
/// collapsed, trimmed (`nzb_core::sanitize_text`); `None` when the result is empty or longer than
/// [`MAX_SAVED_SEARCH_NAME_CHARS`] characters (refused, never truncated).
#[must_use]
pub fn clean_saved_search_name(raw: &str) -> Option<String> {
    // The byte cap only bounds the work; anything near it is far beyond the character limit and refused below.
    let s = nzb_core::sanitize_text(raw, MAX_SAVED_SEARCH_NAME_CHARS.saturating_mul(8));
    let n = s.chars().count();
    (1..=MAX_SAVED_SEARCH_NAME_CHARS).contains(&n).then_some(s)
}

/// The store's own check of a name: it must already be in its cleaned form.
pub(crate) fn check_name(name: &str) -> Result<(), SavedSearchError> {
    match clean_saved_search_name(name) {
        Some(c) if c == name => Ok(()),
        _ => Err(SavedSearchError::InvalidName),
    }
}

/// The store's own check of a filter set: a JSON object of string values within the size cap.
pub(crate) fn check_filters(filters: &str) -> Result<(), SavedSearchError> {
    if filters.len() > MAX_SAVED_SEARCH_FILTER_BYTES {
        return Err(SavedSearchError::InvalidFilters);
    }
    match serde_json::from_str::<serde_json::Value>(filters) {
        Ok(serde_json::Value::Object(m)) if m.values().all(serde_json::Value::is_string) => Ok(()),
        _ => Err(SavedSearchError::InvalidFilters),
    }
}

fn from_row(r: &sqlx::sqlite::SqliteRow) -> Result<SavedSearch, StoreError> {
    Ok(SavedSearch {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        filters: r.try_get("filters")?,
        created_at: r.try_get("created_at")?,
        last_seen_at: r.try_get("last_seen_at")?,
    })
}

impl SqliteDb {
    /// The saved searches of `account_id`, by name.
    ///
    /// # Errors
    /// Database failure.
    pub async fn saved_searches(&self, account_id: i64) -> Result<Vec<SavedSearch>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, filters, created_at, last_seen_at FROM saved_search \
             WHERE account_id = ?1 ORDER BY name, id",
        )
        .bind(account_id)
        .fetch_all(self.readers())
        .await?;
        rows.iter().map(from_row).collect()
    }

    /// Saves a search for the caller (any role, own account). Returns the new id.
    ///
    /// # Errors
    /// [`SavedSearchError::InvalidName`] / [`SavedSearchError::InvalidFilters`] for values the web layer should have
    /// cleaned; [`SavedSearchError::Limit`] at [`MAX_SAVED_SEARCHES`]; [`SavedSearchError::Duplicate`] for a name the
    /// account already uses; [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
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
        let mut tx = self.begin_immediate().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let (n, same): (i64, i64) = sqlx::query_as(
            "SELECT count(*), coalesce(sum(name = ?2), 0) FROM saved_search WHERE account_id = ?1",
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
             VALUES (?1, ?2, ?3, ?4, ?4) RETURNING id",
        )
        .bind(s.id)
        .bind(name)
        .bind(filters)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Renames one of the caller's saved searches (same name: no change, no error).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when `id` is not one of the caller's; [`SavedSearchError::InvalidName`];
    /// [`SavedSearchError::Duplicate`]; [`crate::AccountError::Forbidden`]; database failure.
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
        let mut tx = self.begin_immediate().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let current: Option<String> =
            sqlx::query_scalar("SELECT name FROM saved_search WHERE id = ?1 AND account_id = ?2")
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
            "SELECT count(*) FROM saved_search WHERE account_id = ?1 AND name = ?2",
        )
        .bind(s.id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        if taken > 0 {
            return Err(SavedSearchError::Duplicate.into());
        }
        sqlx::query("UPDATE saved_search SET name = ?3 WHERE id = ?1 AND account_id = ?2")
            .bind(id)
            .bind(s.id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes one of the caller's saved searches.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when `id` is not one of the caller's; [`crate::AccountError::Forbidden`]; database
    /// failure.
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
        let mut tx = self.begin_immediate().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, account_id, Role::Viewer).await?,
        };
        let n = sqlx::query("DELETE FROM saved_search WHERE id = ?1 AND account_id = ?2")
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

    /// Opens one of the caller's saved searches: sets `last_seen_at = now` and returns the row as it was BEFORE (so
    /// the caller still knows the previous visit). `None` when `id` is not one of the caller's.
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
        let mut tx = self.begin_immediate().await?;
        if let Some(a) = actor {
            require_session_actor(&mut tx, a, Role::Viewer, now).await?;
        }
        let row = sqlx::query(
            "SELECT id, name, filters, created_at, last_seen_at FROM saved_search \
             WHERE id = ?1 AND account_id = ?2",
        )
        .bind(id)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let found = from_row(&row)?;
        // Never backwards (a clock step back must not resurrect "new" releases the account already saw).
        sqlx::query(
            "UPDATE saved_search SET last_seen_at = max(last_seen_at, ?3) WHERE id = ?1 AND account_id = ?2",
        )
        .bind(id)
        .bind(account_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(found))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_and_bounded() {
        assert_eq!(
            clean_saved_search_name("  Movies \t 1080p "),
            Some("Movies 1080p".into())
        );
        assert_eq!(
            clean_saved_search_name("a\u{202e}b\u{0}c"),
            Some("abc".into())
        );
        assert_eq!(clean_saved_search_name(""), None);
        assert_eq!(clean_saved_search_name(" \u{200b} "), None);
        let sixty = "é".repeat(60);
        assert_eq!(clean_saved_search_name(&sixty), Some(sixty.clone()));
        assert_eq!(clean_saved_search_name(&"é".repeat(61)), None);
        assert_eq!(clean_saved_search_name(&"x".repeat(5000)), None);
        assert!(check_name("Movies").is_ok());
        assert_eq!(check_name(" Movies"), Err(SavedSearchError::InvalidName));
    }

    #[test]
    fn filters_must_be_a_small_object_of_strings() {
        assert!(check_filters("{}").is_ok());
        assert!(check_filters(r#"{"q":"x","cat":"tv"}"#).is_ok());
        for bad in ["[]", "\"q\"", "{\"q\":1}", "{\"q\":{}}", "not json", ""] {
            assert_eq!(
                check_filters(bad),
                Err(SavedSearchError::InvalidFilters),
                "{bad}"
            );
        }
        let big = format!(r#"{{"q":"{}"}}"#, "x".repeat(MAX_SAVED_SEARCH_FILTER_BYTES));
        assert_eq!(check_filters(&big), Err(SavedSearchError::InvalidFilters));
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(SavedSearchError::Limit.code(), "SAVED_SEARCH_LIMIT");
        assert_eq!(SavedSearchError::Duplicate.code(), "SAVED_SEARCH_DUPLICATE");
        assert_eq!(SavedSearchError::InvalidName.code(), "SAVED_SEARCH_NAME");
    }
}
