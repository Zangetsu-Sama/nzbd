//! Audit appends on Postgres (T112; `DATA_MODEL` v3 section 3.4, SEC-080, SEC-093).
//!
//! The application never inserts into `audit_log` (it has no grant): every row goes through the SECURITY DEFINER
//! function `nzbd.audit_append`, which picks the chain class by event name, locks the class state row `FOR UPDATE`
//! (serial across every connection and process until the caller commits), computes the 2.x chain hash in SQL and moves
//! the head. Callers append LAST in their transaction (lock order, ARCHITECTURE v3 section 6).

use sqlx::{PgConnection, Row};

use crate::StoreError;
use crate::audit_chain::{
    AuditAnchor, AuditContent, AuditExportRow, ChainBreak, ChainBreakKind, ChainQuick, ChainReport,
    GENESIS, chain_hash,
};
use crate::pg::PgDb;

/// Appends one chained audit row in the caller's transaction (or as its own statement on a bare connection).
///
/// # Errors
/// Database errors (including the `actor_kind`/`actor_role` CHECKs).
pub(crate) async fn append(
    conn: &mut PgConnection,
    c: &AuditContent<'_>,
) -> Result<(), StoreError> {
    let _: i64 = sqlx::query_scalar("SELECT nzbd.audit_append($1, $2, $3, $4, $5, $6, $7, $8, $9)")
        .bind(c.ts)
        .bind(c.actor)
        .bind(c.event)
        .bind(c.detail)
        .bind(c.ip)
        .bind(c.actor_id)
        .bind(c.actor_kind)
        .bind(c.actor_role)
        .bind(c.target_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(())
}

const PAGE: i64 = 2000;

fn arr(v: Vec<u8>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

fn flag(report: &mut ChainReport, id: i64, kind: ChainBreakKind) {
    report.breaks = report.breaks.saturating_add(1);
    if report.first_break.is_none() {
        report.first_break = Some(ChainBreak { id, kind });
    }
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn row_of(r: &sqlx::postgres::PgRow) -> Result<AuditExportRow, StoreError> {
    Ok(AuditExportRow {
        id: r.try_get("id")?,
        ts: r.try_get("ts")?,
        actor: r.try_get("actor")?,
        event: r.try_get("event")?,
        detail: r.try_get("detail")?,
        ip: r.try_get("ip")?,
        actor_id: r.try_get("actor_id")?,
        actor_kind: r.try_get("actor_kind")?,
        actor_role: r.try_get("actor_role")?,
        target_id: r.try_get("target_id")?,
        chain_class: r.try_get::<Option<i16>, _>("chain_class")?.map(i64::from),
        chain_hash: r.try_get::<Option<Vec<u8>>, _>("chain_hash")?.and_then(arr),
    })
}

/// Per-class walk state.
struct Lane {
    prev: [u8; 32],
    last_id: i64,
    rows: u64,
}

impl PgDb {
    /// The recorded head hash of each chain class and the stored row count (the off-host anchor, SEC-080).
    ///
    /// # Errors
    /// Database errors.
    pub async fn audit_anchor(&self) -> Result<AuditAnchor, StoreError> {
        let rows =
            sqlx::query("SELECT class, head_hash, rows FROM audit_chain_state ORDER BY class")
                .fetch_all(self.background())
                .await?;
        let mut a = AuditAnchor {
            head_log: GENESIS,
            head_account: GENESIS,
            rows: 0,
        };
        for r in &rows {
            let class: i16 = r.try_get("class")?;
            let head =
                arr(r.try_get("head_hash")?).ok_or(StoreError::AuditChain("head hash length"))?;
            let n: i64 = r.try_get("rows")?;
            a.rows = a.rows.saturating_add(to_u64(n));
            if class == 1 {
                a.head_account = head;
            } else {
                a.head_log = head;
            }
        }
        Ok(a)
    }

    /// Row counts and head hashes against the stored state, without walking the chain (one snapshot).
    ///
    /// # Errors
    /// Database errors.
    pub async fn audit_chain_quick(&self) -> Result<ChainQuick, StoreError> {
        let mut tx = self.background().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let mut rows = 0_u64;
        let mut consistent = true;
        for class in [0_i16, 1] {
            let st = sqlx::query("SELECT head_hash, rows FROM audit_chain_state WHERE class = $1")
                .bind(class)
                .fetch_one(&mut *tx)
                .await?;
            let stored: i64 = st.try_get("rows")?;
            let head: Vec<u8> = st.try_get("head_hash")?;
            let n: i64 =
                sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE chain_class = $1")
                    .bind(class)
                    .fetch_one(&mut *tx)
                    .await?;
            let last: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT chain_hash FROM audit_log WHERE chain_class = $1 ORDER BY id DESC LIMIT 1",
            )
            .bind(class)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            let head_ok = match last {
                Some(h) => h == head,
                None => true,
            };
            consistent &= n == stored && head_ok;
            rows = rows.saturating_add(to_u64(n));
        }
        let unchained: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE chain_class IS NULL")
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(ChainQuick {
            rows,
            unchained: to_u64(unchained),
            consistent,
            // v3 has no bootstrap: every row arrives chained (audit_append, or a verified migration).
            bootstrapped: true,
        })
    }

    /// Walks every audit row in id order inside one `REPEATABLE READ READ ONLY` snapshot, verifies the chain with the
    /// Rust definition of the hash and calls `on_row` for rows with `ts >= since`.
    ///
    /// # Errors
    /// Database errors.
    #[allow(clippy::too_many_lines)] // one linear walk; splitting it would hide the per-class state
    pub async fn audit_walk(
        &self,
        since: Option<i64>,
        on_row: &mut (dyn FnMut(&AuditExportRow) + Send),
    ) -> Result<ChainReport, StoreError> {
        let mut tx = self.background().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let mut lanes: [Lane; 2] = [
            Lane {
                prev: GENESIS,
                last_id: 0,
                rows: 0,
            },
            Lane {
                prev: GENESIS,
                last_id: 0,
                rows: 0,
            },
        ];
        let mut floors = [GENESIS, GENESIS];
        let mut state_head = [GENESIS, GENESIS];
        let mut state_rows = [0_i64, 0_i64];
        for (i, class) in [0_i16, 1].into_iter().enumerate() {
            let st = sqlx::query(
                "SELECT floor_hash, head_hash, rows FROM audit_chain_state WHERE class = $1",
            )
            .bind(class)
            .fetch_one(&mut *tx)
            .await?;
            let f = arr(st.try_get("floor_hash")?)
                .ok_or(StoreError::AuditChain("floor hash length"))?;
            let h =
                arr(st.try_get("head_hash")?).ok_or(StoreError::AuditChain("head hash length"))?;
            if let Some(l) = lanes.get_mut(i) {
                l.prev = f;
            }
            if let Some(x) = floors.get_mut(i) {
                *x = f;
            }
            if let Some(x) = state_head.get_mut(i) {
                *x = h;
            }
            if let Some(x) = state_rows.get_mut(i) {
                *x = st.try_get("rows")?;
            }
        }
        let mut report = ChainReport {
            rows: 0,
            heads: floors,
            breaks: 0,
            first_break: None,
        };
        let mut after = 0_i64;
        loop {
            let page = sqlx::query(
                "SELECT id, ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id, \
                 chain_class, chain_prev, chain_hash FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2",
            )
            .bind(after)
            .bind(PAGE)
            .fetch_all(&mut *tx)
            .await?;
            if page.is_empty() {
                break;
            }
            for r in &page {
                let row = row_of(r)?;
                after = row.id;
                report.rows = report.rows.saturating_add(1);
                if since.is_none_or(|s| row.ts >= s) {
                    on_row(&row);
                }
                let prev_col: Option<Vec<u8>> = r.try_get("chain_prev")?;
                let (Some(class), Some(stored), Some(prev_col)) =
                    (row.chain_class, row.chain_hash, prev_col.and_then(arr))
                else {
                    flag(&mut report, row.id, ChainBreakKind::Unchained);
                    continue;
                };
                let idx = usize::from(class == 1);
                let Some(lane) = lanes.get_mut(idx) else {
                    flag(&mut report, row.id, ChainBreakKind::Unchained);
                    continue;
                };
                let content = AuditContent {
                    ts: row.ts,
                    actor: row.actor.as_deref(),
                    event: &row.event,
                    detail: row.detail.as_deref(),
                    ip: row.ip.as_deref(),
                    actor_id: row.actor_id,
                    actor_kind: row.actor_kind.as_deref(),
                    actor_role: row.actor_role.as_deref(),
                    target_id: row.target_id,
                };
                if chain_hash(class, &prev_col, &content) != stored {
                    flag(&mut report, row.id, ChainBreakKind::Edited);
                } else if prev_col != lane.prev {
                    flag(&mut report, row.id, ChainBreakKind::Gap);
                }
                lane.prev = stored;
                lane.last_id = row.id;
                lane.rows = lane.rows.saturating_add(1);
                if let Some(h) = report.heads.get_mut(idx) {
                    *h = stored;
                }
            }
        }
        for (i, lane) in lanes.iter().enumerate() {
            let head_ok = state_head.get(i) == Some(&lane.prev);
            let rows_ok = i64::try_from(lane.rows).ok() == state_rows.get(i).copied();
            if !(head_ok && rows_ok) {
                flag(&mut report, lane.last_id, ChainBreakKind::TailRemoved);
            }
        }
        tx.commit().await?;
        Ok(report)
    }
}
