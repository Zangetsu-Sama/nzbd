//! Tamper-evident audit log (T105; migration 0013, `DATA_MODEL` "Audit hash chain", SEC-071..073).
//!
//! Every `audit_log` row carries `chain_hash = SHA-256(domain || class || chain_prev || canonical content)` where
//! `chain_prev` is the hash of the previous row **of the same class**. Two classes exist because the retention of
//! account-lifecycle rows (365 days) differs from the rest (90 days): a purge removes only a *prefix by id* of one class
//! and records the hash of the last removed row as that class's `floor_hash`, so the surviving rows stay linked to a
//! known anchor and the chain stays verifiable after retention.
//!
//! What it detects: an edited row (content no longer matches its hash), a deleted or inserted row in the middle (the
//! next row no longer links to its surviving predecessor), removal of the newest rows (row count and head hash are kept
//! in `audit_chain_state`) and rows that bypassed the application (no chain columns). What it cannot detect: an
//! attacker with write access to the database who recomputes the whole chain and the state row. The hash is unkeyed on
//! purpose (a key would tie the chain to the TOTP key rotation and put a secret into every verification); the
//! mitigation is an external anchor: `nzbd audit export` prints the head hash, which an operator can store off-host, and
//! off-host backups hold earlier heads.
//!
//! Writes happen inside the transaction of the change they describe, under the single writer connection; when the
//! caller is not in a transaction the append opens one whose first statement takes the write lock, so two
//! processes (the server and the CLI) can never both extend the same head.

use sha2::{Digest, Sha256};
use sqlx::{Connection, Row, SqliteConnection};

use crate::{SqliteDb, StoreError};

/// Chain hash of "no previous row".
pub const GENESIS: [u8; 32] = [0; 32];
/// Domain separation of the canonical encoding (bump on any change of the encoding).
const DOMAIN: &[u8] = b"nzbd-audit-chain-v1";
/// Rows fetched per page while walking the chain.
const PAGE: i64 = 2000;

/// Chain class of an event: 1 for account-lifecycle rows (long retention), 0 for everything else. Decided by the event
/// NAME at write time and stored, so later changes to the event list cannot reshuffle history.
#[must_use]
pub fn class_of(event: &str) -> i64 {
    i64::from(crate::ACCOUNT_AUDIT_EVENTS.contains(&event))
}

/// The content of an audit row as hashed (everything but `id` and the chain columns).
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuditContent<'a> {
    pub(crate) ts: i64,
    pub(crate) actor: Option<&'a str>,
    pub(crate) event: &'a str,
    pub(crate) detail: Option<&'a str>,
    pub(crate) ip: Option<&'a str>,
    pub(crate) actor_id: Option<i64>,
    pub(crate) actor_kind: Option<&'a str>,
    pub(crate) actor_role: Option<&'a str>,
    pub(crate) target_id: Option<i64>,
}

fn put_text(h: &mut Sha256, v: Option<&str>) {
    match v {
        None => h.update([0_u8]),
        Some(s) => {
            h.update([1_u8]);
            // usize -> u64 is lossless on every supported target; the fallback keeps the function total.
            h.update(u64::try_from(s.len()).unwrap_or(u64::MAX).to_be_bytes());
            h.update(s.as_bytes());
        }
    }
}

fn put_int(h: &mut Sha256, v: Option<i64>) {
    match v {
        None => h.update([0_u8]),
        Some(n) => {
            h.update([2_u8]);
            h.update(n.to_be_bytes());
        }
    }
}

/// Canonical, length-prefixed, type-tagged hash input: no field boundary can be shifted by hostile content.
#[must_use]
pub(crate) fn chain_hash(class: i64, prev: &[u8; 32], c: &AuditContent<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(class.to_be_bytes());
    h.update(prev);
    put_int(&mut h, Some(c.ts));
    put_text(&mut h, c.actor);
    put_text(&mut h, Some(c.event));
    put_text(&mut h, c.detail);
    put_text(&mut h, c.ip);
    put_int(&mut h, c.actor_id);
    put_text(&mut h, c.actor_kind);
    put_text(&mut h, c.actor_role);
    put_int(&mut h, c.target_id);
    h.finalize().into()
}

fn arr(v: Vec<u8>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

/// Appends one chained audit row on `conn`. The row, the state update and the chain link are one unit: an error
/// or cancellation rolls the transaction back, so a half-written link never remains. Inside a caller's `SQLx`
/// transaction this creates a savepoint, preserving the caller's other writes if only this append is cancelled.
///
/// # Errors
/// Database errors; [`StoreError::AuditChain`] when the state row is missing or was changed concurrently.
pub(crate) async fn append(
    conn: &mut SqliteConnection,
    c: &AuditContent<'_>,
) -> Result<(), StoreError> {
    // SQLx must own the transaction depth and its rollback guard. Raw SAVEPOINT SQL leaves a pooled connection
    // in an open transaction when this future is dropped before the matching RELEASE/ROLLBACK is executed.
    let mut tx = conn.begin().await?;
    match append_inner(&mut tx, c).await {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(e) => {
            // Best effort: the original error is what the caller needs.
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

async fn append_inner(conn: &mut SqliteConnection, c: &AuditContent<'_>) -> Result<(), StoreError> {
    let class = class_of(c.event);
    // First statement is a write: it takes the database write lock before the head is read, so the head cannot
    // change between the read and the update (cross-process safety when the caller holds no transaction).
    let n = sqlx::query("UPDATE audit_chain_state SET rows = rows + 1 WHERE class = ?1")
        .bind(class)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if n != 1 {
        return Err(StoreError::AuditChain("state row missing"));
    }
    let head: Vec<u8> =
        sqlx::query_scalar("SELECT head_hash FROM audit_chain_state WHERE class = ?1")
            .bind(class)
            .fetch_one(&mut *conn)
            .await?;
    let prev = arr(head).ok_or(StoreError::AuditChain("head hash length"))?;
    let hash = chain_hash(class, &prev, c);
    sqlx::query(
        "INSERT INTO audit_log (ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id, \
         chain_class, chain_prev, chain_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .bind(c.ts)
    .bind(c.actor)
    .bind(c.event)
    .bind(c.detail)
    .bind(c.ip)
    .bind(c.actor_id)
    .bind(c.actor_kind)
    .bind(c.actor_role)
    .bind(c.target_id)
    .bind(class)
    .bind(prev.to_vec())
    .bind(hash.to_vec())
    .execute(&mut *conn)
    .await?;
    let moved = sqlx::query(
        "UPDATE audit_chain_state SET head_hash = ?2 WHERE class = ?1 AND head_hash = ?3",
    )
    .bind(class)
    .bind(hash.to_vec())
    .bind(prev.to_vec())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if moved != 1 {
        return Err(StoreError::AuditChain("head moved concurrently"));
    }
    Ok(())
}

/// One stored audit row as exported (raw database values; the exporter escapes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditExportRow {
    /// Row id.
    pub id: i64,
    /// Unix seconds.
    pub ts: i64,
    /// Actor snapshot text.
    pub actor: Option<String>,
    /// Event name.
    pub event: String,
    /// Event detail (no secrets by SEC-033).
    pub detail: Option<String>,
    /// Client address.
    pub ip: Option<String>,
    /// Acting account id.
    pub actor_id: Option<i64>,
    /// `user`, `cli`, `system`, `api_key`, `anonymous` or `None` for 1.x rows.
    pub actor_kind: Option<String>,
    /// Role snapshot.
    pub actor_role: Option<String>,
    /// Target account id.
    pub target_id: Option<i64>,
    /// 0 log, 1 account, `None` = unchained.
    pub chain_class: Option<i64>,
    /// This row's chain hash.
    pub chain_hash: Option<[u8; 32]>,
}

/// What is wrong with a row or with the end of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainBreakKind {
    /// The row has no (valid) chain columns: it bypassed the application or predates a failed bootstrap.
    Unchained,
    /// The row's content or hash was changed: its stored hash does not match its content and recorded predecessor.
    Edited,
    /// The row does not link to the surviving row before it: a row between them was deleted, or one was inserted.
    Gap,
    /// The newest rows of a class are missing (head hash or row count differ from the recorded state).
    TailRemoved,
}

impl ChainBreakKind {
    /// Stable identifier (CLI output, metrics documentation).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unchained => "unchained",
            Self::Edited => "edited",
            Self::Gap => "gap",
            Self::TailRemoved => "tail_removed",
        }
    }
}

/// The first problem found (lowest id; tail problems report the last surviving id of the class, 0 when none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainBreak {
    /// Row id the problem is reported at.
    pub id: i64,
    /// Kind of problem.
    pub kind: ChainBreakKind,
}

/// Result of walking the whole chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    /// Rows examined (all classes).
    pub rows: u64,
    /// Chain hash of the newest row per class (`[log, account]`; the genesis value when a class has no rows).
    pub heads: [[u8; 32]; 2],
    /// Number of rows or chain ends flagged.
    pub breaks: u64,
    /// The first flagged position, if any.
    pub first_break: Option<ChainBreak>,
}

impl ChainReport {
    /// No problem found.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.first_break.is_none()
    }
}

/// The recorded chain heads and row count (see [`SqliteDb::audit_anchor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditAnchor {
    /// Head hash of the log class.
    pub head_log: [u8; 32],
    /// Head hash of the account-lifecycle class.
    pub head_account: [u8; 32],
    /// Chained rows currently stored (both classes).
    pub rows: u64,
}

impl AuditAnchor {
    /// `head_log=<hex> head_account=<hex> rows=<n>`: the line logged at startup, after backups and after purges.
    #[must_use]
    pub fn line(&self) -> String {
        use std::fmt::Write as _;
        let hex = |h: &[u8; 32]| {
            h.iter().fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
        };
        format!(
            "head_log={} head_account={} rows={}",
            hex(&self.head_log),
            hex(&self.head_account),
            self.rows
        )
    }
}

/// Cheap consistency facts for the health page and metrics: counts and the head, no row walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainQuick {
    /// Chained rows stored.
    pub rows: u64,
    /// Rows without chain columns (0 on a healthy database).
    pub unchained: u64,
    /// The stored row counts and head hashes agree with the rows themselves.
    pub consistent: bool,
    /// The 2.x one-off bootstrap of pre-chain rows has completed; always true on v3 (no 2.x upgrade, D37), kept so
    /// the health and metrics code stays one shape.
    pub bootstrapped: bool,
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

fn row_of(r: &sqlx::sqlite::SqliteRow) -> Result<AuditExportRow, StoreError> {
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
        chain_class: r.try_get("chain_class")?,
        chain_hash: r.try_get::<Option<Vec<u8>>, _>("chain_hash")?.and_then(arr),
    })
}

const SELECT_ROWS: &str = "SELECT id, ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id, \
     chain_class, chain_prev, chain_hash FROM audit_log WHERE id > ?1 ORDER BY id LIMIT ?2";

/// Per-class walk state.
struct Lane {
    /// Expected `chain_prev` of the next row of the class.
    prev: [u8; 32],
    /// Last row id seen.
    last_id: i64,
    /// Rows seen.
    rows: u64,
}

impl SqliteDb {
    /// The recorded head hash of each chain class and the stored row count: the value an operator should keep
    /// off-host (T105 M1). Read from the state table only; use [`SqliteDb::audit_walk`] to check it against the rows.
    ///
    /// # Errors
    /// Database errors.
    pub async fn audit_anchor(&self) -> Result<AuditAnchor, StoreError> {
        let rows =
            sqlx::query("SELECT class, head_hash, rows FROM audit_chain_state ORDER BY class")
                .fetch_all(self.readers())
                .await?;
        let mut a = AuditAnchor {
            head_log: GENESIS,
            head_account: GENESIS,
            rows: 0,
        };
        for r in &rows {
            let class: i64 = r.try_get("class")?;
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

    /// Row counts and head hashes against the stored state, without walking the chain: one indexed count and one
    /// indexed head lookup per class.
    ///
    /// # Errors
    /// Database errors (including a database that has not been migrated to 0013).
    pub async fn audit_chain_quick(&self) -> Result<ChainQuick, StoreError> {
        let mut conn = self.readers().acquire().await?;
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let mut rows = 0_u64;
        let mut consistent = true;
        for class in [0_i64, 1] {
            let st = sqlx::query("SELECT head_hash, rows FROM audit_chain_state WHERE class = ?1")
                .bind(class)
                .fetch_one(&mut *tx)
                .await?;
            let stored: i64 = st.try_get("rows")?;
            let head: Vec<u8> = st.try_get("head_hash")?;
            let n: i64 =
                sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE chain_class = ?1")
                    .bind(class)
                    .fetch_one(&mut *tx)
                    .await?;
            let last: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT chain_hash FROM audit_log WHERE chain_class = ?1 ORDER BY id DESC LIMIT 1",
            )
            .bind(class)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            // A class whose rows were all purged keeps its head in the state (it is the new floor).
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
            // v3 has no 2.x bootstrap: every row is chained when it is written.
            bootstrapped: true,
        })
    }

    /// Walks every audit row in id order inside one read snapshot, verifies the chain and calls `on_row` for rows with
    /// `ts >= since` (all rows when `since` is `None`). Verification always covers the whole table: a chain cannot be
    /// checked from the middle.
    ///
    /// # Errors
    /// Database errors; [`StoreError::AuditChain`] when the database predates the bootstrap (nothing to verify yet).
    #[allow(clippy::too_many_lines)] // one linear walk; splitting it would hide the per-class state
    pub async fn audit_walk(
        &self,
        since: Option<i64>,
        on_row: &mut (dyn FnMut(&AuditExportRow) + Send),
    ) -> Result<ChainReport, StoreError> {
        let mut conn = self.readers().acquire().await?;
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
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
        for (i, class) in [0_i64, 1].into_iter().enumerate() {
            let st = sqlx::query(
                "SELECT floor_hash, head_hash, rows FROM audit_chain_state WHERE class = ?1",
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
            let page = sqlx::query(SELECT_ROWS)
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
                // Content first: an edited row is reported as such even when its link is also wrong.
                if chain_hash(class, &prev_col, &content) != stored {
                    flag(&mut report, row.id, ChainBreakKind::Edited);
                } else if prev_col != lane.prev {
                    flag(&mut report, row.id, ChainBreakKind::Gap);
                }
                // Resynchronise on what the row claims so later, independent problems are still counted once.
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

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn hash_input_is_unambiguous() {
        let base = AuditContent {
            ts: 1,
            actor: Some("ab"),
            event: "e",
            detail: Some("c"),
            ip: None,
            actor_id: None,
            actor_kind: None,
            actor_role: None,
            target_id: None,
        };
        // Moving a byte across a field boundary must change the hash (length prefixes).
        let shifted = AuditContent {
            actor: Some("a"),
            event: "be",
            ..base
        };
        assert_ne!(
            chain_hash(0, &GENESIS, &base),
            chain_hash(0, &GENESIS, &shifted)
        );
        // NULL and the empty string differ.
        let empty = AuditContent {
            detail: Some(""),
            ..base
        };
        let null = AuditContent {
            detail: None,
            ..base
        };
        assert_ne!(
            chain_hash(0, &GENESIS, &empty),
            chain_hash(0, &GENESIS, &null)
        );
        // The class and the previous hash are part of the input.
        assert_ne!(
            chain_hash(0, &GENESIS, &base),
            chain_hash(1, &GENESIS, &base)
        );
        assert_ne!(
            chain_hash(0, &GENESIS, &base),
            chain_hash(0, &[1; 32], &base)
        );
    }

    #[test]
    fn class_follows_the_account_event_list() {
        for e in crate::ACCOUNT_AUDIT_EVENTS {
            assert_eq!(class_of(e), 1, "{e}");
        }
        assert_eq!(class_of("login.fail"), 0);
        assert_eq!(class_of("authz_denied"), 0);
    }
}
