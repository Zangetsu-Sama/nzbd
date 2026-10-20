//! `ingest_log` writer. All values are bound parameters; free-text fields are capped here so a
//! hostile file name or parser message cannot bloat the table.

use nzb_core::{Sha256, sanitize_text};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, Transaction};

use crate::{SqliteDb, StoreError};

/// Cap for `source_name` (display data).
const MAX_SOURCE_NAME_BYTES: usize = 255;
/// Cap for `detail`.
const MAX_DETAIL_BYTES: usize = 1024;

/// Where a submission came from (`ingest_log.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// Watch folder.
    Watch,
    /// UI upload form.
    UploadUi,
    /// `POST /api/v1/nzb`.
    UploadApi,
}

impl LogSource {
    /// Database form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::UploadUi => "upload_ui",
            Self::UploadApi => "upload_api",
        }
    }
}

/// Result recorded in `ingest_log.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOutcome {
    /// New release stored.
    Ok,
    /// Same SHA-256 already indexed.
    Duplicate,
    /// Rejected; the source is kept.
    Failed,
}

impl LogOutcome {
    /// Database form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Duplicate => "duplicate",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ok" => Self::Ok,
            "duplicate" => Self::Duplicate,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// One `ingest_log` row to write.
#[derive(Debug, Clone, Copy)]
pub struct IngestLogEntry<'a> {
    /// Unix seconds (injected clock).
    pub ts: i64,
    /// Origin.
    pub source: LogSource,
    /// API key row, for `upload_api`.
    pub api_key_id: Option<i64>,
    /// Original file name (display only).
    pub source_name: Option<&'a str>,
    /// Content hash, when known.
    pub sha256: Option<Sha256>,
    /// Outcome.
    pub outcome: LogOutcome,
    /// Stable error code for `failed`.
    pub error_code: Option<&'a str>,
    /// Short free text (e.g. hint disagreement). Never secrets.
    pub detail: Option<&'a str>,
}

/// A stored `ingest_log` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestLogRow {
    /// Row id.
    pub id: i64,
    /// Unix seconds.
    pub ts: i64,
    /// Origin (database form).
    pub source: String,
    /// Display name.
    pub source_name: Option<String>,
    /// Hash.
    pub sha256: Option<Sha256>,
    /// Outcome.
    pub outcome: LogOutcome,
    /// Error code.
    pub error_code: Option<String>,
    /// Detail.
    pub detail: Option<String>,
    /// Linked release.
    pub release_id: Option<i64>,
}

pub(crate) async fn insert_log_row(
    tx: &mut Transaction<'_, Sqlite>,
    e: &IngestLogEntry<'_>,
    release_id: Option<i64>,
    user_id: Option<i64>,
) -> Result<(), StoreError> {
    let name = e
        .source_name
        .map(|n| sanitize_text(n, MAX_SOURCE_NAME_BYTES));
    let detail = e.detail.map(|d| sanitize_text(d, MAX_DETAIL_BYTES));
    sqlx::query(
        "INSERT INTO ingest_log (ts, source, api_key_id, source_name, sha256, outcome, \
         error_code, detail, release_id, account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.ts)
    .bind(e.source.as_str())
    .bind(e.api_key_id)
    .bind(name)
    .bind(e.sha256.map(|s| s.0.to_vec()))
    .bind(e.outcome.as_str())
    .bind(e.error_code)
    .bind(detail)
    .bind(release_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn log_row(r: &SqliteRow) -> Result<IngestLogRow, StoreError> {
    let sha: Option<Vec<u8>> = r.try_get("sha256")?;
    let outcome: String = r.try_get("outcome")?;
    Ok(IngestLogRow {
        id: r.try_get("id")?,
        ts: r.try_get("ts")?,
        source: r.try_get("source")?,
        source_name: r.try_get("source_name")?,
        sha256: sha.and_then(|v| <[u8; 32]>::try_from(v).ok().map(Sha256)),
        outcome: LogOutcome::parse(&outcome).ok_or(StoreError::OutOfRange("ingest_log.outcome"))?,
        error_code: r.try_get("error_code")?,
        detail: r.try_get("detail")?,
        release_id: r.try_get("release_id")?,
    })
}

impl SqliteDb {
    /// Append one `ingest_log` row (duplicate / failed outcomes; `ok` rows are written together
    /// with the release by [`SqliteDb::insert_release_logged`]).
    ///
    /// # Errors
    /// Database errors.
    pub async fn log_ingest(
        &self,
        e: &IngestLogEntry<'_>,
        release_id: Option<i64>,
    ) -> Result<(), StoreError> {
        let mut tx = self.writer().begin().await?;
        insert_log_row(&mut tx, e, release_id, None).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Number of `failed` log rows recorded for `sha` (the retry count of a quarantined file:
    /// failures that happened before the one being written now).
    ///
    /// # Errors
    /// Database errors.
    pub async fn count_failed_for_sha(&self, sha: &Sha256) -> Result<u32, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ingest_log WHERE sha256 = ? AND outcome = 'failed'",
        )
        .bind(sha.0.to_vec())
        .fetch_one(self.readers())
        .await?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Newest-first `ingest_log` rows (at most `limit`, capped at 500).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_ingest_log(&self, limit: u32) -> Result<Vec<IngestLogRow>, StoreError> {
        self.ingest_log_page(limit, 0).await
    }

    /// Newest-first `ingest_log` rows, `limit` (capped at 500) rows after skipping `offset`.
    /// Served by the `ingest_ts` index; the cost is bounded by `offset + limit`, so callers cap
    /// the offset.
    ///
    /// # Errors
    /// Database errors.
    pub async fn ingest_log_page(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<IngestLogRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, ts, source, source_name, sha256, outcome, error_code, detail, release_id \
             FROM ingest_log ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        )
        .bind(i64::from(limit.min(500)))
        .bind(i64::from(offset))
        .fetch_all(self.readers())
        .await?;
        rows.iter().map(log_row).collect()
    }

    /// Release, file and byte totals for the admin page. Full scan of `release`, so callers
    /// cache the result.
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_totals(&self) -> Result<ReleaseTotals, StoreError> {
        self.release_totals_excluding(&[]).await
    }

    /// Like [`SqliteDb::release_totals`] but ignoring releases whose category id is in `exclude`
    /// (display rule `ui.show_xxx = false`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_totals_excluding(
        &self,
        exclude: &[u32],
    ) -> Result<ReleaseTotals, StoreError> {
        // Exact and O(categories): `category_stats` is maintained by the release triggers in the transaction of every
        // change (the same source as the Postgres backend).
        let row = sqlx::query(
            "SELECT coalesce(sum(releases), 0) AS n, coalesce(sum(files), 0) AS f, \
             coalesce(sum(segments), 0) AS sg, coalesce(sum(bytes), 0) AS b FROM category_stats \
             WHERE category_id NOT IN (SELECT value FROM json_each(?1))",
        )
        .bind(json_u32s(exclude))
        .fetch_one(self.readers())
        .await?;
        let conv = |v: i64| u64::try_from(v).unwrap_or(0);
        Ok(ReleaseTotals {
            releases: conv(row.try_get("n")?),
            files: conv(row.try_get("f")?),
            segments: conv(row.try_get("sg")?),
            bytes: conv(row.try_get("b")?),
        })
    }

    /// Releases and bytes of every category with at least one release, ascending id (exact, O(categories): the
    /// `category_stats` rows the release triggers maintain). The caller drops hidden categories (T132).
    ///
    /// # Errors
    /// Database errors.
    pub async fn category_stats_list(&self) -> Result<Vec<CategoryTotals>, StoreError> {
        let rows: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT category_id, releases, bytes FROM category_stats WHERE releases > 0 ORDER BY category_id",
        )
        .fetch_all(self.readers())
        .await?;
        rows.into_iter()
            .map(|(c, n, b)| {
                Ok(CategoryTotals {
                    category_id: u32::try_from(c)
                        .map_err(|_| StoreError::OutOfRange("category_id"))?,
                    releases: u64::try_from(n).map_err(|_| StoreError::OutOfRange("releases"))?,
                    bytes: u64::try_from(b).map_err(|_| StoreError::OutOfRange("bytes"))?,
                })
            })
            .collect()
    }

    /// Newest-first `ingest_log` rows (at most `limit`, capped at 500) that do not belong to a
    /// release whose category id is in `exclude`. A row belongs to such a release when its
    /// `release_id` or its `sha256` matches one, including retained trash metadata. With exclusions,
    /// rows whose former category can no longer be established are omitted; failures without any
    /// release identity remain visible. The unfiltered operator log retains every row.
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_ingest_log_excluding(
        &self,
        limit: u32,
        exclude: &[u32],
    ) -> Result<Vec<IngestLogRow>, StoreError> {
        if exclude.is_empty() {
            return self.list_ingest_log(limit).await;
        }
        // Correlated NOT EXISTS, probed per row of the newest-first walk (primary key / unique sha256 index): the
        // former `NOT IN (SELECT ... WHERE category_id IN (hidden))` materialised every hidden release's id and
        // sha256 first, which cost ~50 ms on every page at 1 M releases with 18,000 of them hidden (T087).
        let rows = sqlx::query(
            "SELECT l.id, l.ts, l.source, l.source_name, l.sha256, l.outcome, l.error_code, l.detail, l.release_id \
             FROM ingest_log l WHERE NOT EXISTS (SELECT 1 FROM release r WHERE r.id = l.release_id \
             AND +r.category_id IN (SELECT value FROM json_each(?1))) \
             AND NOT EXISTS (SELECT 1 FROM release r WHERE r.sha256 = l.sha256 \
             AND +r.category_id IN (SELECT value FROM json_each(?1))) \
             AND NOT EXISTS (SELECT 1 FROM release_trash t WHERE t.sha256 = l.sha256 \
             AND +t.category_id IN (SELECT value FROM json_each(?1))) \
             AND ((l.release_id IS NULL AND l.sha256 IS NULL AND l.outcome = 'failed') \
             OR EXISTS (SELECT 1 FROM release r WHERE r.id = l.release_id) \
             OR EXISTS (SELECT 1 FROM release r WHERE r.sha256 = l.sha256) \
             OR EXISTS (SELECT 1 FROM release_trash t WHERE t.sha256 = l.sha256)) \
             ORDER BY l.ts DESC, l.id DESC LIMIT ?2",
        )
        .bind(json_u32s(exclude))
        .bind(i64::from(limit.min(500)))
        .fetch_all(self.readers())
        .await?;
        rows.iter().map(log_row).collect()
    }

    /// Which of `ids` are releases whose category id is in `exclude` (at most 500 ids are
    /// considered). Lets the operator views drop links that would answer 404.
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_ids_in_categories(
        &self,
        ids: &[i64],
        exclude: &[u32],
    ) -> Result<std::collections::HashSet<i64>, StoreError> {
        if ids.is_empty() || exclude.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let some: Vec<i64> = ids.iter().take(500).copied().collect();
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM release WHERE id IN (SELECT value FROM json_each(?1)) \
             AND category_id IN (SELECT value FROM json_each(?2))",
        )
        .bind(json_i64s(&some))
        .bind(json_u32s(exclude))
        .fetch_all(self.readers())
        .await?;
        Ok(found.into_iter().collect())
    }

    /// Time of the newest `ok` ingest log row, if any.
    ///
    /// # Errors
    /// Database errors.
    pub async fn last_ok_ingest_ts(&self) -> Result<Option<i64>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT ts FROM ingest_log WHERE outcome = 'ok' ORDER BY ts DESC LIMIT 1",
        )
        .fetch_optional(self.readers())
        .await?)
    }

    /// Cheap reader round trip for the admin health row.
    ///
    /// # Errors
    /// Database errors.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let _: i64 = sqlx::query_scalar("SELECT 1")
            .fetch_one(self.readers())
            .await?;
        Ok(())
    }
}

/// Aggregates over `release`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReleaseTotals {
    /// Number of releases.
    pub releases: u64,
    /// Sum of file counts.
    pub files: u64,
    /// Sum of segment counts.
    pub segments: u64,
    /// Sum of payload bytes.
    pub bytes: u64,
}

/// Releases and payload bytes of one category, from `category_stats` (the Statistics page, T132).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoryTotals {
    /// Category id.
    pub category_id: u32,
    /// Number of releases.
    pub releases: u64,
    /// Sum of payload bytes.
    pub bytes: u64,
}

/// `[1,2,3]` for a `json_each` parameter (integers only, no escaping involved).
fn json_u32s(ids: &[u32]) -> String {
    let parts: Vec<String> = ids.iter().map(u32::to_string).collect();
    format!("[{}]", parts.join(","))
}

/// `[1,2,3]` for a `json_each` parameter (integers only, no escaping involved).
fn json_i64s(ids: &[i64]) -> String {
    let parts: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", parts.join(","))
}
