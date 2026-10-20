//! `ingest_log` on Postgres (T112; 2.x `ingest_log.rs`) and the library totals read from `category_stats`.
//!
//! The log is partitioned by month (`DATA_MODEL` v3 section 3.3) and keeps plain `release_id` / `api_key_id` integers
//! instead of 2.x's `ON DELETE SET NULL`: readers report a `release_id` only while the release exists, which is what
//! 2.x returned after a trash.

use nzb_core::{Sha256, sanitize_text};
use sqlx::{PgConnection, Row};

use crate::StoreError;
use crate::ingest_log::{CategoryTotals, IngestLogEntry, IngestLogRow, LogOutcome, ReleaseTotals};
use crate::pg::PgDb;

/// Cap for `source_name` (display data; 2.x value).
const MAX_SOURCE_NAME_BYTES: usize = 255;
/// Cap for `detail` (2.x value).
const MAX_DETAIL_BYTES: usize = 1024;
/// Most rows one log page returns.
const MAX_PAGE: u32 = 500;

macro_rules! log_cols {
    () => {
        "l.id, l.ts, l.source, l.source_name, l.sha256, l.outcome, l.error_code, l.detail, \
         CASE WHEN EXISTS (SELECT 1 FROM release x WHERE x.id = l.release_id) THEN l.release_id END AS release_id"
    };
}

pub(crate) async fn insert_log_row(
    conn: &mut PgConnection,
    e: &IngestLogEntry<'_>,
    release_id: Option<i64>,
    account_id: Option<i64>,
) -> Result<(), StoreError> {
    let name = e
        .source_name
        .map(|n| sanitize_text(n, MAX_SOURCE_NAME_BYTES));
    let detail = e.detail.map(|d| sanitize_text(d, MAX_DETAIL_BYTES));
    sqlx::query(
        "INSERT INTO ingest_log (ts, source, api_key_id, source_name, sha256, outcome, error_code, detail, \
         release_id, account_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
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
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Several `ingest_log` rows with one array-bound statement (a commit group, T114). Each row is
/// `(entry, release_id, account_id)`; values are sanitized exactly like [`insert_log_row`].
pub(crate) async fn insert_log_rows(
    conn: &mut PgConnection,
    rows: &[(IngestLogEntry<'_>, Option<i64>, Option<i64>)],
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut ts = Vec::with_capacity(rows.len());
    let mut source = Vec::with_capacity(rows.len());
    let mut key: Vec<Option<i64>> = Vec::with_capacity(rows.len());
    let mut name: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut sha: Vec<Option<Vec<u8>>> = Vec::with_capacity(rows.len());
    let mut outcome = Vec::with_capacity(rows.len());
    let mut code: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut detail: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut release: Vec<Option<i64>> = Vec::with_capacity(rows.len());
    let mut account: Vec<Option<i64>> = Vec::with_capacity(rows.len());
    for (e, release_id, account_id) in rows {
        ts.push(e.ts);
        source.push(e.source.as_str().to_owned());
        key.push(e.api_key_id);
        name.push(
            e.source_name
                .map(|n| sanitize_text(n, MAX_SOURCE_NAME_BYTES)),
        );
        sha.push(e.sha256.map(|s| s.0.to_vec()));
        outcome.push(e.outcome.as_str().to_owned());
        code.push(e.error_code.map(str::to_owned));
        detail.push(e.detail.map(|d| sanitize_text(d, MAX_DETAIL_BYTES)));
        release.push(*release_id);
        account.push(*account_id);
    }
    sqlx::query(
        "INSERT INTO ingest_log (ts, source, api_key_id, source_name, sha256, outcome, error_code, detail, \
         release_id, account_id) \
         SELECT * FROM unnest($1::bigint[], $2::text[], $3::bigint[], $4::text[], $5::bytea[], $6::text[], \
         $7::text[], $8::text[], $9::bigint[], $10::bigint[])",
    )
    .bind(&ts)
    .bind(&source)
    .bind(&key)
    .bind(&name)
    .bind(&sha)
    .bind(&outcome)
    .bind(&code)
    .bind(&detail)
    .bind(&release)
    .bind(&account)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn log_row(r: &sqlx::postgres::PgRow) -> Result<IngestLogRow, StoreError> {
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

fn ids_i32(ids: &[u32]) -> Vec<i32> {
    ids.iter().filter_map(|c| i32::try_from(*c).ok()).collect()
}

impl PgDb {
    /// Appends one `ingest_log` row (duplicate/failed outcomes; `ok` rows are written with the release).
    ///
    /// # Errors
    /// Database errors.
    pub async fn log_ingest(
        &self,
        e: &IngestLogEntry<'_>,
        release_id: Option<i64>,
    ) -> Result<(), StoreError> {
        let mut conn = self.ingest().acquire().await?;
        insert_log_row(&mut conn, e, release_id, None).await
    }

    /// Number of `failed` rows recorded for `sha` (partial index `ingest_log_failed_sha`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn count_failed_for_sha(&self, sha: &Sha256) -> Result<u32, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ingest_log WHERE sha256 = $1 AND outcome = 'failed'",
        )
        .bind(sha.0.to_vec())
        .fetch_one(self.ingest())
        .await?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Newest-first rows (at most `limit`, capped at 500).
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_ingest_log(&self, limit: u32) -> Result<Vec<IngestLogRow>, StoreError> {
        self.ingest_log_page(limit, 0).await
    }

    /// Newest-first rows, `limit` (capped at 500) after skipping `offset`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn ingest_log_page(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<IngestLogRow>, StoreError> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            log_cols!(),
            " FROM ingest_log l ORDER BY l.ts DESC, l.id DESC LIMIT $1 OFFSET $2"
        ))
        .bind(i64::from(limit.min(MAX_PAGE)))
        .bind(i64::from(offset))
        .fetch_all(self.web())
        .await?;
        rows.iter().map(log_row).collect()
    }

    /// Library totals (releases, files, segments, bytes): a sum over `category_stats`, exact and O(categories).
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_totals(&self) -> Result<ReleaseTotals, StoreError> {
        self.release_totals_excluding(&[]).await
    }

    /// Like [`PgDb::release_totals`] without the categories in `exclude` (`ui.show_xxx = false`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn release_totals_excluding(
        &self,
        exclude: &[u32],
    ) -> Result<ReleaseTotals, StoreError> {
        let row = sqlx::query(
            "SELECT coalesce(sum(releases), 0)::bigint AS n, coalesce(sum(files), 0)::bigint AS f, \
             coalesce(sum(segments), 0)::bigint AS sg, coalesce(sum(bytes), 0)::bigint AS b \
             FROM category_stats WHERE NOT (category_id = ANY($1))",
        )
        .bind(ids_i32(exclude))
        .fetch_one(self.web())
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
    /// `category_stats` rows maintained in the transaction of every change). The caller drops hidden categories (T132).
    ///
    /// # Errors
    /// Database errors.
    pub async fn category_stats_list(&self) -> Result<Vec<CategoryTotals>, StoreError> {
        let rows: Vec<(i32, i64, i64)> = sqlx::query_as(
            "SELECT category_id, releases, bytes FROM category_stats WHERE releases > 0 ORDER BY category_id",
        )
        .fetch_all(self.web())
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

    /// Newest-first rows that do not belong to a release whose category is in `exclude` (by `release_id` or by
    /// `sha256`), including retained trash metadata. With exclusions, a former release whose category
    /// is no longer known is omitted; failures without a release identity remain visible.
    /// The unfiltered operator log retains every row. Probes use primary-key and digest indexes.
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
        let rows = sqlx::query(concat!(
            "SELECT ",
            log_cols!(),
            " FROM ingest_log l \
             WHERE NOT EXISTS (SELECT 1 FROM release r WHERE r.id = l.release_id AND r.category_id = ANY($1)) \
               AND NOT EXISTS (SELECT 1 FROM release r WHERE r.sha256 = l.sha256 AND r.category_id = ANY($1)) \
               AND NOT EXISTS (SELECT 1 FROM release_trash t WHERE t.sha256 = l.sha256 AND t.category_id = ANY($1)) \
               AND ((l.release_id IS NULL AND l.sha256 IS NULL AND l.outcome = 'failed') \
                 OR EXISTS (SELECT 1 FROM release r WHERE r.id = l.release_id) \
                 OR EXISTS (SELECT 1 FROM release r WHERE r.sha256 = l.sha256) \
                 OR EXISTS (SELECT 1 FROM release_trash t WHERE t.sha256 = l.sha256)) \
             ORDER BY l.ts DESC, l.id DESC LIMIT $2"
        ))
        .bind(ids_i32(exclude))
        .bind(i64::from(limit.min(MAX_PAGE)))
        .fetch_all(self.web())
        .await?;
        rows.iter().map(log_row).collect()
    }

    /// Which of `ids` (at most 500 considered) are releases whose category is in `exclude`.
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
        let ids: Vec<i64> = ids.iter().take(500).copied().collect();
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM release WHERE id = ANY($1) AND category_id = ANY($2)",
        )
        .bind(&ids)
        .bind(ids_i32(exclude))
        .fetch_all(self.web())
        .await?;
        Ok(found.into_iter().collect())
    }

    /// Time of the newest `ok` row, if any.
    ///
    /// # Errors
    /// Database errors.
    pub async fn last_ok_ingest_ts(&self) -> Result<Option<i64>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT ts FROM ingest_log WHERE outcome = 'ok' ORDER BY ts DESC, id DESC LIMIT 1",
        )
        .fetch_optional(self.web())
        .await?)
    }

    /// Cheap round trip on the `web` pool (health row).
    ///
    /// # Errors
    /// Database errors.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let _: i32 = sqlx::query_scalar("SELECT 1").fetch_one(self.web()).await?;
        Ok(())
    }
}
