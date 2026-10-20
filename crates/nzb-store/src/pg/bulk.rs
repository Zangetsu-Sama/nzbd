//! Bulk actions on a selection of releases on Postgres (T119 on v3; 2.x `bulk.rs`, SEC-099).
//!
//! Same rules as 2.x: the list is de-duplicated and capped at [`MAX_BULK_IDS`], every id must exist and be visible or
//! the call fails with [`StoreError::NotFound`] writing nothing, the actor is re-validated in the transaction, one audit
//! row per release (old and new value) plus one summary row. v3: the ids are bound as ONE `bigint[]` parameter
//! (`= ANY($1)`, replacing `json_each`), the rows are locked `FOR UPDATE` in ascending id order before anything is
//! changed (lock order 2), the category totals move in the same transaction and every changed release gets an
//! outbox row.

use nzb_core::Sha256;
use serde_json::json;
use sqlx::{PgConnection, Row};

use crate::account::{AccountActor, AuditActor, Role};
use crate::bulk::{BulkItem, MAX_BULK_IDS};
use crate::pg::PgDb;
use crate::pg::account::write_audit;
use crate::pg::release::{StatDelta, apply_stats, enqueue_outbox, require_session_actor_share};
use crate::{StoreError, clean_source_label};

/// Sorted, de-duplicated copy of `ids`; `None` when empty, oversized or with a non-positive id.
fn normalize(ids: &[i64]) -> Option<Vec<i64>> {
    let mut v = ids.to_vec();
    v.sort_unstable();
    v.dedup();
    if v.is_empty() || v.len() > MAX_BULK_IDS || v.first().is_some_and(|f| *f <= 0) {
        return None;
    }
    Some(v)
}

fn is_hidden(hidden: &[u16], category_id: u32) -> bool {
    u16::try_from(category_id).is_ok_and(|c| hidden.contains(&c))
}

/// A selected row with what the totals need.
struct Locked {
    item: BulkItem,
    file_count: i64,
    segments: i64,
}

fn locked_from_row(row: &sqlx::postgres::PgRow) -> Result<Locked, StoreError> {
    let sha: Vec<u8> = row.try_get("sha256")?;
    let sha: [u8; 32] = sha
        .try_into()
        .map_err(|_| StoreError::OutOfRange("sha256 length"))?;
    Ok(Locked {
        item: BulkItem {
            id: row.try_get("id")?,
            sha256: Sha256(sha),
            title: row.try_get("title")?,
            category_id: u32::try_from(row.try_get::<i32, _>("category_id")?)
                .map_err(|_| StoreError::OutOfRange("category_id"))?,
            source_label: row.try_get("source_label")?,
            total_bytes: u64::try_from(row.try_get::<i64, _>("total_bytes")?)
                .map_err(|_| StoreError::OutOfRange("total_bytes"))?,
        },
        file_count: i64::from(row.try_get::<i32, _>("file_count")?),
        segments: row.try_get("segment_count")?,
    })
}

/// Loads the (normalized) selection, locking the rows in ascending id order when `lock` is set, and applies the
/// all-or-nothing visibility rule.
async fn load_visible(
    conn: &mut PgConnection,
    ids: &[i64],
    hidden: &[u16],
    lock: bool,
) -> Result<Vec<Locked>, StoreError> {
    let rows = if lock {
        sqlx::query(
            "SELECT id, sha256, title, category_id, source_label, total_bytes, file_count, segment_count \
             FROM release WHERE id = ANY($1) ORDER BY id FOR UPDATE",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "SELECT id, sha256, title, category_id, source_label, total_bytes, file_count, segment_count \
             FROM release WHERE id = ANY($1) ORDER BY id",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?
    };
    let items: Vec<Locked> = rows
        .iter()
        .map(locked_from_row)
        .collect::<Result<_, StoreError>>()?;
    if items.len() != ids.len() || items.iter().any(|i| is_hidden(hidden, i.item.category_id)) {
        return Err(StoreError::NotFound);
    }
    Ok(items)
}

impl PgDb {
    /// The selection as [`BulkItem`]s in id order (all-or-nothing visibility).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] (also for an empty, oversized or non-positive selection) or a database error.
    pub async fn bulk_items(
        &self,
        ids: &[i64],
        hidden: &[u16],
    ) -> Result<Vec<BulkItem>, StoreError> {
        let ids = normalize(ids).ok_or(StoreError::NotFound)?;
        let mut conn = self.web().acquire().await?;
        Ok(load_visible(&mut conn, &ids, hidden, false)
            .await?
            .into_iter()
            .map(|l| l.item)
            .collect())
    }

    /// Sets the category of every release of the selection (marks it manual) in one transaction. Returns the number
    /// of releases changed.
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`], [`StoreError::NotFound`], [`StoreError::UnknownCategory`]; nothing is
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
        let category = i32::try_from(category_id).map_err(|_| StoreError::UnknownCategory)?;
        let ids = normalize(ids).ok_or(StoreError::NotFound)?;
        let mut tx = self.web().begin().await?;
        let a = require_session_actor_share(&mut tx, actor, Role::Admin, now).await?;
        let items = load_visible(&mut tx, &ids, hidden, true).await?;
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM category WHERE id = $1")
            .bind(category)
            .fetch_one(&mut *tx)
            .await?;
        if known == 0 {
            return Err(StoreError::UnknownCategory);
        }
        sqlx::query(
            "UPDATE release SET category_id = $1, category_overridden = true, category_source = 'manual', flags = flags & ~512, \
             index_version = index_version + 1 WHERE id = ANY($2)",
        )
        .bind(category)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
        let mut deltas = Vec::with_capacity(items.len().saturating_mul(2));
        for l in &items {
            let old = i32::try_from(l.item.category_id)
                .map_err(|_| StoreError::OutOfRange("category_id"))?;
            let bytes = i64::try_from(l.item.total_bytes)
                .map_err(|_| StoreError::OutOfRange("total_bytes"))?;
            deltas.push(StatDelta {
                category: old,
                releases: -1,
                files: l.file_count.saturating_neg(),
                segments: l.segments.saturating_neg(),
                bytes: bytes.saturating_neg(),
            });
            deltas.push(StatDelta {
                category,
                releases: 1,
                files: l.file_count,
                segments: l.segments,
                bytes,
            });
        }
        apply_stats(&mut tx, &deltas).await?;
        enqueue_outbox(&mut tx, &ids).await?;
        let who = AuditActor::account(a.id, a.role, &a.username);
        for l in &items {
            let detail = format!(
                "release={} old={} new={category_id}",
                l.item.id, l.item.category_id
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
        Ok(items.len())
    }

    /// Sets (or, blank, clears) the source label of every release of the selection in one transaction. Returns the
    /// number of releases changed and the stored label.
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`], [`StoreError::NotFound`]; nothing is written on error.
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
        let mut tx = self.web().begin().await?;
        let a = require_session_actor_share(&mut tx, actor, Role::Admin, now).await?;
        let items = load_visible(&mut tx, &ids, hidden, true).await?;
        sqlx::query(
            "UPDATE release SET source_label = $1, index_version = index_version + 1 WHERE id = ANY($2)",
        )
        .bind(clean.as_deref())
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
        enqueue_outbox(&mut tx, &ids).await?;
        let who = AuditActor::account(a.id, a.role, &a.username);
        for l in &items {
            // The labels are hostile text: serialized, never concatenated.
            let detail =
                json!({"release": l.item.id, "old": l.item.source_label, "new": clean}).to_string();
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
