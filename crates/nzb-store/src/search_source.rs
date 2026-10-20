//! The store side of the search index (ARCHITECTURE v3 3.1-3.5, 13.1; T122): what the indexer, the hydrator and the
//! degraded browse read from the source of truth, on both backends. `nzb-search` adapts these methods to its
//! `IndexSource`, `Hydrator` and `DegradedSource` traits on [`crate::Store`] (one adapter, error mapping in one place);
//! the types here carry no Tantivy type.
//!
//! **Size contract (review 32 M2):** a document's file-name text is cut in SQL before it is materialized: a bounded
//! subquery (`ORDER BY idx LIMIT n`) is aggregated and the aggregate cut with `substr` (SQLite) / `left` (Postgres).
//! Both count **characters**, so the SQL cut bounds a row at `4 * max_file_bytes`; every row is then cut to
//! `max_file_bytes` bytes ([`cut_utf8`]) as it is read from the row stream, before the next row is fetched, so a batch
//! never holds more than its byte budget (one row of transient slack).

use std::collections::BTreeSet;

use futures_util::TryStreamExt as _;
use sqlx::Row as _;

use crate::release::{ReleaseRow, release_from_row};
use crate::{SqliteDb, StoreError};

/// Most primary-key entries one degraded-mode page may walk (review L5, SEC-095).
pub const DEGRADED_SCAN_BUDGET: i64 = 200_000;

/// One page of the degraded (index unavailable) listing: newest first by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedPage {
    /// Rows, newest first.
    pub items: Vec<ReleaseRow>,
    /// Cursor for the next page (`id` to continue below), `None` at the end.
    pub next_before: Option<i64>,
    /// The per-request scan budget stopped the walk before the page was full ("more after the rebuild").
    pub budget_exhausted: bool,
}

/// One outbox row (`search_outbox`): no payload by design (SEC-092).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutboxEntry {
    /// Sequence number (never reused on either backend).
    pub seq: i64,
    /// Release the change was about (may no longer exist: a removal).
    pub release_id: i64,
}

/// How far the search index is behind the database (ARCHITECTURE v3 3.2 "Lag and backpressure", T114).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxLag {
    /// Outbox depth as the span of its sequence (`max(seq) - min(seq) + 1`, two primary-key probes; an upper bound
    /// of the row count, 0 when empty).
    pub depth: u64,
    /// Age in seconds of the oldest outbox row by the database clock (0 when empty).
    pub lag_secs: u64,
}

impl OutboxLag {
    pub(crate) fn from_row(span: i64, age: i64) -> Self {
        Self {
            depth: u64::try_from(span).unwrap_or(0),
            lag_secs: u64::try_from(age).unwrap_or(0),
        }
    }
}

/// The current state of one release as the indexer needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRow {
    /// The release row.
    pub release: ReleaseRow,
    /// File names in file order, separated by one space, at most the requested byte budget.
    pub files: String,
    /// Direct parent of the category (the category itself when it has none).
    pub category_parent: u32,
    /// `release.index_version` (both backends bump it on every change; `nzbd search verify` compares it).
    pub version: u64,
    /// Uploader account id.
    pub added_by: Option<i64>,
}

/// `search_state` plus the outbox sequence position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchSourceState {
    /// Index epoch (rotated by restores).
    pub epoch: [u8; 16],
    /// Highest outbox sequence number ever handed out (0 = none).
    pub outbox_last_seq: i64,
    /// A rebuild is in progress (outbox deletes copy their ids into `search_replay`).
    pub replay: bool,
    /// `nzbd search rebuild` asked for a rebuild.
    pub rebuild_requested: bool,
    /// Generation activated by the last finished rebuild (0 = none).
    pub finished_generation: u64,
}

/// `s` cut to at most `max` bytes at a character boundary (never splits a UTF-8 sequence).
#[must_use]
pub fn cut_utf8(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        s.truncate(end);
    }
    s
}

/// File rows aggregated per document: every name contributes at least one character plus a separator.
pub(crate) fn file_rows_for(max_file_bytes: usize) -> i64 {
    i64::try_from(max_file_bytes / 2 + 1).unwrap_or(i64::MAX)
}

pub(crate) fn sql_len(max_file_bytes: usize) -> i64 {
    i64::try_from(max_file_bytes).unwrap_or(i64::MAX)
}

/// Text bytes a document contributes to a batch budget.
pub(crate) fn doc_bytes(r: &IndexRow) -> usize {
    r.release
        .title
        .len()
        .saturating_add(r.release.poster.as_deref().map_or(0, str::len))
        // T131: the `.nzb` file name and the group appended to it (plus a separator) are indexed text too.
        .saturating_add(r.release.source_name.as_deref().map_or(0, str::len))
        .saturating_add(
            r.release
                .scene
                .group
                .as_deref()
                .map_or(0, |g| g.len().saturating_add(1)),
        )
        .saturating_add(r.files.len())
}

fn json_ids(ids: &[i64]) -> String {
    let parts: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", parts.join(","))
}

fn u32_of(v: i64, what: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn index_row(row: &sqlx::sqlite::SqliteRow, max_file_bytes: usize) -> Result<IndexRow, StoreError> {
    Ok(IndexRow {
        release: release_from_row(row)?,
        files: cut_utf8(
            row.try_get::<Option<String>, _>("files")?
                .unwrap_or_default(),
            max_file_bytes,
        ),
        category_parent: u32_of(row.try_get("cat_parent")?, "category parent")?,
        // Review 35 L4: the real counter, so `nzbd search verify` sees a stale document on SQLite too.
        version: u64::try_from(row.try_get::<i64, _>("index_version")?)
            .map_err(|_| StoreError::OutOfRange("index_version"))?,
        added_by: row.try_get("added_by")?,
    })
}

/// The document columns: the release, its uploader, the category parent and the bounded file-name aggregate
/// (`?2` characters at most, of at most `?3` file rows).
macro_rules! sqlite_index_select {
    () => {
        concat!(
            "SELECT ",
            sqlite_release_cols!(),
            ", r.added_by, r.index_version, coalesce(c.parent_id, r.category_id) AS cat_parent, \
             (SELECT substr(group_concat(f.filename, ' ' ORDER BY f.idx), 1, ?2) \
                FROM (SELECT filename, idx FROM nzb_file \
                       WHERE release_id = r.id AND filename IS NOT NULL ORDER BY idx LIMIT ?3) f) AS files \
             FROM release r LEFT JOIN category c ON c.id = r.category_id "
        )
    };
}

impl SqliteDb {
    /// Outbox depth and the age of its oldest row (index lag), by the database clock.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_outbox_lag(&self) -> Result<OutboxLag, StoreError> {
        let (span, age): (i64, i64) = sqlx::query_as(
            "SELECT coalesce((SELECT max(seq) FROM search_outbox) - (SELECT min(seq) FROM search_outbox) + 1, 0), \
             coalesce(unixepoch() - (SELECT enqueued_at FROM search_outbox ORDER BY seq LIMIT 1), 0)",
        )
        .fetch_one(self.readers())
        .await?;
        Ok(OutboxLag::from_row(span, age))
    }

    /// The oldest `limit` outbox rows, ascending sequence.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_outbox_read(&self, limit: usize) -> Result<Vec<OutboxEntry>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT seq, release_id FROM search_outbox ORDER BY seq LIMIT ?1")
                .bind(limit)
                .fetch_all(self.readers())
                .await?;
        Ok(rows
            .into_iter()
            .map(|(seq, release_id)| OutboxEntry { seq, release_id })
            .collect())
    }

    /// The current documents of `ids` in one read snapshot (absent ids are skipped), file names cut to
    /// `max_file_bytes` bytes (module docs).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_index_load(
        &self,
        ids: &[i64],
        max_file_bytes: usize,
    ) -> Result<Vec<IndexRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.readers().acquire().await?;
        let mut rows = sqlx::query(concat!(
            sqlite_index_select!(),
            "WHERE r.id IN (SELECT value FROM json_each(?1)) ORDER BY r.id"
        ))
        .bind(json_ids(ids))
        .bind(sql_len(max_file_bytes))
        .bind(file_rows_for(max_file_bytes))
        .fetch(&mut *conn);
        let mut out = Vec::new();
        while let Some(row) = rows.try_next().await? {
            out.push(index_row(&row, max_file_bytes)?);
        }
        Ok(out)
    }

    /// Documents with `id > after_id`, ascending, at most `limit`, stopping once their text reaches `max_bytes`
    /// (at least one is returned while any remains).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_index_scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
        max_file_bytes: usize,
    ) -> Result<Vec<IndexRow>, StoreError> {
        let mut conn = self.readers().acquire().await?;
        let mut rows = sqlx::query(concat!(
            sqlite_index_select!(),
            "WHERE r.id > ?1 ORDER BY r.id LIMIT ?4"
        ))
        .bind(after_id)
        .bind(sql_len(max_file_bytes))
        .bind(file_rows_for(max_file_bytes))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch(&mut *conn);
        let mut out = Vec::new();
        let mut bytes = 0_usize;
        while let Some(row) = rows.try_next().await? {
            let r = index_row(&row, max_file_bytes)?;
            bytes = bytes.saturating_add(doc_bytes(&r));
            out.push(r);
            if bytes >= max_bytes {
                break;
            }
        }
        Ok(out)
    }

    /// One transaction: deletes exactly the outbox rows `seqs` and, when `search_state.replay` (read inside this
    /// transaction, review 30 L6 a) is set, records `ids` in `search_replay`.
    ///
    /// # Errors
    /// Database errors (nothing changes; the rows are applied again, idempotently).
    pub async fn search_outbox_consume(&self, seqs: &[i64], ids: &[i64]) -> Result<(), StoreError> {
        let mut tx = self.begin_immediate().await?;
        let replay: i64 = sqlx::query_scalar("SELECT replay FROM search_state WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;
        if replay != 0 {
            sqlx::query(
                "INSERT INTO search_replay (release_id) SELECT value FROM json_each(?1) WHERE true \
                 ON CONFLICT(release_id) DO NOTHING",
            )
            .bind(json_ids(ids))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM search_outbox WHERE seq IN (SELECT value FROM json_each(?1))")
            .bind(json_ids(seqs))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records a release the indexer could not index (fixed error code, never a message).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_quarantine(&self, release_id: i64, code: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO search_quarantine (release_id, error_code, at) VALUES (?1, ?2, unixepoch()) \
             ON CONFLICT(release_id) DO NOTHING",
        )
        .bind(release_id)
        .bind(code)
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// Epoch, outbox position, replay and rebuild flags.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_source_state(&self) -> Result<SearchSourceState, StoreError> {
        let row = sqlx::query(
            "SELECT epoch, replay, rebuild_requested_at, rebuild_generation, \
             coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'search_outbox'), 0) AS last_seq \
             FROM search_state WHERE id = 1",
        )
        .fetch_one(self.readers())
        .await?;
        let epoch: Vec<u8> = row.try_get("epoch")?;
        Ok(SearchSourceState {
            epoch: <[u8; 16]>::try_from(epoch)
                .map_err(|_| StoreError::OutOfRange("search epoch"))?,
            outbox_last_seq: row.try_get("last_seq")?,
            replay: row.try_get::<i64, _>("replay")? != 0,
            rebuild_requested: row
                .try_get::<Option<i64>, _>("rebuild_requested_at")?
                .is_some(),
            finished_generation: u64::try_from(row.try_get::<i64, _>("rebuild_generation")?)
                .map_err(|_| StoreError::OutOfRange("rebuild generation"))?,
        })
    }

    /// Sets the replay flag and commits, before a rebuild scan reads anything.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_begin_rebuild(&self) -> Result<(), StoreError> {
        sqlx::query("UPDATE search_state SET replay = 1 WHERE id = 1")
            .execute(self.writer())
            .await?;
        Ok(())
    }

    /// Ids in `search_replay` above `after_id`, ascending, at most `limit`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_replay_ids(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<i64>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT release_id FROM search_replay WHERE release_id > ?1 ORDER BY release_id LIMIT ?2",
        )
        .bind(after_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(self.readers())
        .await?)
    }

    /// One transaction: clears replay and the rebuild request, records `generation`, empties `search_replay`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_finish_rebuild(&self, generation: u64) -> Result<(), StoreError> {
        let g = i64::try_from(generation).map_err(|_| StoreError::OutOfRange("generation"))?;
        let mut tx = self.begin_immediate().await?;
        sqlx::query(
            "UPDATE search_state SET replay = 0, rebuild_requested_at = NULL, rebuild_generation = ?1 \
             WHERE id = 1",
        )
        .bind(g)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM search_replay")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// `nzbd search rebuild`: asks the indexer of the running `serve` for a rebuild.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_request_rebuild(&self, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE search_state SET rebuild_requested_at = coalesce(rebuild_requested_at, ?1) WHERE id = 1",
        )
        .bind(now)
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// Announces `ids` to the indexer without changing them: one outbox row each.
    ///
    /// # Errors
    /// Database errors.
    pub async fn enqueue_reindex(&self, ids: &[i64]) -> Result<(), StoreError> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO search_outbox (release_id, enqueued_at) \
             SELECT value, unixepoch() FROM json_each(?1)",
        )
        .bind(json_ids(ids))
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// The index epoch (`search_state.epoch`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_epoch(&self) -> Result<Vec<u8>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT epoch FROM search_state WHERE id = 1")
                .fetch_one(self.readers())
                .await?,
        )
    }

    /// The current rows of `ids` in the order given; ids that no longer exist and rows whose **current** category is
    /// in `exclude` are dropped (hydration re-check, SEC-090).
    ///
    /// # Errors
    /// Database errors.
    pub async fn hydrate(
        &self,
        ids: &[i64],
        exclude: &[u32],
    ) -> Result<Vec<ReleaseRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(concat!(
            "SELECT ",
            sqlite_release_cols!(),
            " FROM release r WHERE r.id IN (SELECT value FROM json_each(?1))"
        ))
        .bind(json_ids(ids))
        .fetch_all(self.readers())
        .await?;
        let mut found: Vec<ReleaseRow> = rows
            .iter()
            .map(release_from_row)
            .collect::<Result<_, _>>()?;
        found.retain(|r| !exclude.contains(&r.category_id));
        let mut out = Vec::with_capacity(found.len());
        for id in ids {
            if let Some(pos) = found.iter().position(|r| r.id == *id) {
                out.push(found.swap_remove(pos));
            }
        }
        Ok(out)
    }

    /// Degraded listing while the index is unavailable: newest first by id below `before`, restricted to
    /// `categories` (empty = all) and outside `exclude`, walking at most [`DEGRADED_SCAN_BUDGET`] primary-key entries.
    ///
    /// # Errors
    /// Database errors.
    pub async fn degraded_browse(
        &self,
        before: Option<i64>,
        categories: &[u32],
        exclude: &[u32],
        limit: u32,
    ) -> Result<DegradedPage, StoreError> {
        let limit = i64::from(limit.clamp(1, crate::MAX_LIMIT));
        let cats: Vec<i64> = categories.iter().map(|c| i64::from(*c)).collect();
        let excl: Vec<i64> = exclude.iter().map(|c| i64::from(*c)).collect();
        let before = before.unwrap_or(i64::MAX);
        let rows = sqlx::query(concat!(
            "WITH walk AS (SELECT id, category_id FROM release WHERE id < ?1 ORDER BY id DESC LIMIT ?2) \
             SELECT ",
            sqlite_release_cols!(),
            " FROM release r JOIN walk w ON w.id = r.id \
             WHERE (json_array_length(?3) = 0 OR w.category_id IN (SELECT value FROM json_each(?3))) \
               AND w.category_id NOT IN (SELECT value FROM json_each(?4)) \
             ORDER BY r.id DESC LIMIT ?5"
        ))
        .bind(before)
        .bind(DEGRADED_SCAN_BUDGET)
        .bind(json_ids(&cats))
        .bind(json_ids(&excl))
        .bind(limit)
        .fetch_all(self.readers())
        .await?;
        let items: Vec<ReleaseRow> = rows
            .iter()
            .map(release_from_row)
            .collect::<Result<_, _>>()?;
        if i64::try_from(items.len()).unwrap_or(i64::MAX) >= limit {
            let next_before = items.last().map(|r| r.id);
            return Ok(DegradedPage {
                items,
                next_before,
                budget_exhausted: false,
            });
        }
        let (scanned, low): (i64, Option<i64>) = sqlx::query_as(
            "SELECT count(*), min(id) FROM (SELECT id FROM release WHERE id < ?1 ORDER BY id DESC LIMIT ?2)",
        )
        .bind(before)
        .bind(DEGRADED_SCAN_BUDGET)
        .fetch_one(self.readers())
        .await?;
        let budget_exhausted = scanned >= DEGRADED_SCAN_BUDGET;
        Ok(DegradedPage {
            items,
            next_before: if budget_exhausted { low } else { None },
            budget_exhausted,
        })
    }

    /// `(category id, releases)` of every category with at least one release (exact, from `category_stats`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn category_totals(&self) -> Result<Vec<(u32, u64)>, StoreError> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT category_id, releases FROM category_stats WHERE releases > 0 ORDER BY category_id",
        )
        .fetch_all(self.readers())
        .await?;
        rows.into_iter()
            .map(|(c, n)| {
                Ok((
                    u32_of(c, "category_id")?,
                    u64::try_from(n).map_err(|_| StoreError::OutOfRange("releases"))?,
                ))
            })
            .collect()
    }

    /// Release ids present in the outbox or quarantine, for `nzbd search status` (bounded by `limit`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_quarantined(&self, limit: u32) -> Result<BTreeSet<i64>, StoreError> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT release_id FROM search_quarantine ORDER BY release_id LIMIT ?1",
        )
        .bind(i64::from(limit))
        .fetch_all(self.readers())
        .await?;
        Ok(ids.into_iter().collect())
    }
}
