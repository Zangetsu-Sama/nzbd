//! Bulk actions on a selection of releases (T119, the 2.x port of the 1.x bulk branch; fulfils T073
//! "bulk category edit").
//!
//! Every function takes a list of release ids and applies to the **whole** selection or to none of
//! it:
//!
//! * the list is de-duplicated and capped at [`MAX_BULK_IDS`];
//! * each id must exist **and** be visible to the caller (its category must not be in `hidden`,
//!   the `ui.show_xxx` rule); otherwise the call fails with [`StoreError::NotFound`] and writes
//!   nothing, so a caller cannot tell a hidden release from an unknown one, and no partial effect
//!   exists;
//! * edits re-validate the acting account (live, enabled, admin: D40) and run in one writer
//!   transaction together with their audit rows: one row per release in exactly the format of the
//!   single-release edit (`category_override release=<id> old=<old> new=<new>`, `source_label_edit`
//!   JSON with old and new label), so vandalism can be undone release by release (review I-3), plus
//!   one summary row (`bulk_edit_category` / `bulk_edit_source`, counts only).
//!
//! Deleting is not here: the web layer runs the single-delete trash protocol per release with
//! [`SqliteDb::trash_release_checked_as`] and writes the `bulk_delete` summary through
//! [`SqliteDb::audit_entry`].
//!
//! Ids are bound as one JSON array parameter and expanded by SQLite's `json_each`; no SQL is built
//! from them.

use nzb_core::Sha256;
use serde_json::json;
use sqlx::{Row, SqliteConnection};

use crate::account::{AccountActor, AuditActor, Role, require_session_actor, write_audit};
use crate::{SqliteDb, StoreError, clean_source_label};

/// Most releases one bulk request may address (two index pages of 50).
pub const MAX_BULK_IDS: usize = 100;

/// The few columns a bulk action needs (and the delete confirmation page shows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkItem {
    /// Release id.
    pub id: i64,
    /// Content address of the NZB blob (binds a delete to what was confirmed).
    pub sha256: Sha256,
    /// Stored (sanitized at ingest) title: display data only.
    pub title: String,
    /// Category id.
    pub category_id: u32,
    /// Current source label (display data only).
    pub source_label: Option<String>,
    /// Payload bytes.
    pub total_bytes: u64,
}

/// Sorted, de-duplicated copy of `ids`; `None` when it is empty, has a non-positive id or is
/// longer than [`MAX_BULK_IDS`] after de-duplication.
fn normalize(ids: &[i64]) -> Option<Vec<i64>> {
    let mut v = ids.to_vec();
    v.sort_unstable();
    v.dedup();
    if v.is_empty() || v.len() > MAX_BULK_IDS || v.first().is_some_and(|f| *f <= 0) {
        return None;
    }
    Some(v)
}

/// `[1,2,3]` for the `json_each` parameter (integers only, so no escaping is involved).
fn json_ids(ids: &[i64]) -> String {
    let parts: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", parts.join(","))
}

fn item_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<BulkItem, StoreError> {
    let sha: Vec<u8> = row.try_get("sha256")?;
    let sha: [u8; 32] = sha
        .try_into()
        .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
    Ok(BulkItem {
        id: row.try_get("id")?,
        sha256: Sha256(sha),
        title: row.try_get("title")?,
        category_id: u32::try_from(row.try_get::<i64, _>("category_id")?)
            .map_err(|_| StoreError::OutOfRange("category_id"))?,
        source_label: row.try_get("source_label")?,
        total_bytes: u64::try_from(row.try_get::<i64, _>("total_bytes")?)
            .map_err(|_| StoreError::OutOfRange("total_bytes"))?,
    })
}

const ITEM_SQL: &str = "SELECT id, sha256, title, category_id, source_label, total_bytes \
     FROM release WHERE id IN (SELECT value FROM json_each(?1)) ORDER BY id";

fn is_hidden(hidden: &[u16], category_id: u32) -> bool {
    u16::try_from(category_id).is_ok_and(|c| hidden.contains(&c))
}

/// Loads the (normalized) selection on `conn` and applies the all-or-nothing visibility rule.
async fn load_visible(
    conn: &mut SqliteConnection,
    ids: &[i64],
    hidden: &[u16],
) -> Result<Vec<BulkItem>, StoreError> {
    let rows = sqlx::query(ITEM_SQL)
        .bind(json_ids(ids))
        .fetch_all(&mut *conn)
        .await?;
    let items: Vec<BulkItem> = rows
        .iter()
        .map(item_from_row)
        .collect::<Result<_, StoreError>>()?;
    if items.len() != ids.len() || items.iter().any(|i| is_hidden(hidden, i.category_id)) {
        return Err(StoreError::NotFound);
    }
    Ok(items)
}

impl SqliteDb {
    /// The selection as [`BulkItem`]s in id order, de-duplicated. Fails with
    /// [`StoreError::NotFound`] unless **every** id exists and is visible (see the module docs).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] (also for an empty, oversized or non-positive selection) or a
    /// database error.
    pub async fn bulk_items(
        &self,
        ids: &[i64],
        hidden: &[u16],
    ) -> Result<Vec<BulkItem>, StoreError> {
        let ids = normalize(ids).ok_or(StoreError::NotFound)?;
        let mut conn = self.readers().acquire().await?;
        load_visible(&mut conn, &ids, hidden).await
    }

    /// Sets the category of every release of the selection (marks it manual, like
    /// [`SqliteDb::set_category_as`]) in one transaction: the actor is re-validated first (an
    /// admin, D40; any release), then one `category_override` row per release with the old and
    /// the new category and one `bulk_edit_category count=<n> new=<id>` summary row. Returns the
    /// number of releases changed.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`](crate::AccountError::Forbidden) (nothing read),
    /// [`StoreError::NotFound`] unless every id exists and is visible,
    /// [`StoreError::UnknownCategory`] for an unknown or hidden target category; nothing is
    /// written on error.
    pub async fn bulk_set_category_as(
        &self,
        actor: &AccountActor,
        ids: &[i64],
        category_id: u32,
        hidden: &[u16],
        ip: Option<&str>,
        now: i64,
    ) -> Result<usize, StoreError> {
        if is_hidden(hidden, category_id) {
            return Err(StoreError::UnknownCategory);
        }
        let ids = normalize(ids).ok_or(StoreError::NotFound)?;
        let mut tx = self.begin_immediate().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let items = load_visible(&mut tx, &ids, hidden).await?;
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM category WHERE id = ?1")
            .bind(i64::from(category_id))
            .fetch_one(&mut *tx)
            .await?;
        if known == 0 {
            return Err(StoreError::UnknownCategory);
        }
        sqlx::query(
            "UPDATE release SET category_id = ?1, category_overridden = 1, \
             category_source = 'manual', flags = flags & ~512 WHERE id IN (SELECT value FROM json_each(?2))",
        )
        .bind(i64::from(category_id))
        .bind(json_ids(&ids))
        .execute(&mut *tx)
        .await?;
        let who = AuditActor::account(a.id, a.role, &a.username);
        for item in &items {
            let detail = format!(
                "release={} old={} new={category_id}",
                item.id, item.category_id
            );
            write_audit(
                &mut tx,
                &who,
                now,
                "category_override",
                Some(&detail),
                ip,
                None,
            )
            .await?;
        }
        let summary = format!("count={} new={category_id}", items.len());
        write_audit(
            &mut tx,
            &who,
            now,
            "bulk_edit_category",
            Some(&summary),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        self.bump_release_epoch();
        Ok(items.len())
    }

    /// Sets (or, blank, clears) the source label of every release of the selection in one
    /// transaction: actor re-validated first (admin, D40), then one `source_label_edit` row
    /// per release (JSON with the old and the new label, like [`SqliteDb::set_source_label_as`]) and one
    /// `bulk_edit_source count=<n>` summary row. Returns the number of releases changed and the
    /// stored label.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`](crate::AccountError::Forbidden),
    /// [`StoreError::NotFound`] unless every id exists and is visible; nothing is written on
    /// error.
    pub async fn bulk_set_source_label_as(
        &self,
        actor: &AccountActor,
        ids: &[i64],
        label: &str,
        hidden: &[u16],
        ip: Option<&str>,
        now: i64,
    ) -> Result<(usize, Option<String>), StoreError> {
        let ids = normalize(ids).ok_or(StoreError::NotFound)?;
        let clean = clean_source_label(label);
        let mut tx = self.begin_immediate().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let items = load_visible(&mut tx, &ids, hidden).await?;
        sqlx::query(
            "UPDATE release SET source_label = ?1 WHERE id IN (SELECT value FROM json_each(?2))",
        )
        .bind(clean.as_deref())
        .bind(json_ids(&ids))
        .execute(&mut *tx)
        .await?;
        let who = AuditActor::account(a.id, a.role, &a.username);
        for item in &items {
            // The labels are hostile text: serialized, never concatenated.
            let detail =
                json!({"release": item.id, "old": item.source_label, "new": clean}).to_string();
            write_audit(
                &mut tx,
                &who,
                now,
                "source_label_edit",
                Some(&detail),
                ip,
                None,
            )
            .await?;
        }
        let summary = format!("count={}", items.len());
        write_audit(
            &mut tx,
            &who,
            now,
            "bulk_edit_source",
            Some(&summary),
            ip,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok((items.len(), clean))
    }
}
