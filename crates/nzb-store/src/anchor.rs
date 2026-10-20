//! Detection of restores nzbd did not perform and of a switched library (review 30 M2 b, review 34 M2/M3;
//! ARCHITECTURE v3 10 and 13.5; SEC-094, SEC-101), shared by both backends.
//!
//! `serve` keeps `paths.state/db-anchor.json` (written tmp + fsync + rename, 0600) with the library identity (backend
//! and `db_state.instance_id`), on Postgres the cluster's `system_identifier`, the last values of the `audit_log`,
//! `release` and `search_outbox` id sequences, and both audit classes' head, floor and row count. A database with
//! another identity is refused (`LIBRARY_MISMATCH`); a database that is BEHIND the file (a sequence below its anchored
//! value, another cluster, an anchored audit head missing from its chain) is reported (`RESTORE_DETECTED`) until
//! `nzbd db restore-finish` writes a new anchor. Residuals (documented): a rollback of the database and `paths.state`
//! together, and changes of the last <= 10 s (the file is rewritten every 10 s while something changed).
//! The file holds no secret: identifiers, counters and hashes only.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use serde_json::{Value, json};
use sqlx::Row as _;

use crate::{SqliteDb, StoreError};

/// Largest anchor file accepted.
const MAX_ANCHOR_BYTES: u64 = 16 * 1024;

/// What the anchor remembers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbAnchor {
    /// The library's backend (`sqlite` or `postgres`, `db_state.backend`).
    pub backend: String,
    /// The library's random identity (`db_state.instance_id`, hex).
    pub instance_id: String,
    /// Postgres: `pg_control_system().system_identifier` (as text: an unsigned 64-bit value). SQLite: empty.
    pub system_identifier: String,
    /// Last value handed out by the `audit_log` identity (0 = none yet).
    pub seq_audit: i64,
    /// Last value handed out by the `release` identity.
    pub seq_release: i64,
    /// Last value handed out by the `search_outbox` identity.
    pub seq_outbox: i64,
    /// Per audit class: `(head hash hex, floor hash hex, rows)`.
    pub classes: [(String, String, i64); 2],
}

/// The verdict of [`PgDb::check_anchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// The database is the anchored one or newer.
    Consistent,
    /// The database is another cluster or behind the anchor (fixed reason, no data).
    RestoreDetected(&'static str),
    /// The database is another library than the anchored one (backend or instance id differ, SEC-101).
    LibraryMismatch,
}

impl AnchorVerdict {
    /// Stable code, `None` when consistent.
    #[must_use]
    pub const fn code(&self) -> Option<&'static str> {
        match self {
            Self::Consistent => None,
            Self::RestoreDetected(_) => Some("RESTORE_DETECTED"),
            Self::LibraryMismatch => Some("LIBRARY_MISMATCH"),
        }
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(64), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

impl SqliteDb {
    /// Reads the current anchor values (one read snapshot).
    ///
    /// # Errors
    /// Database errors.
    pub async fn capture_anchor(&self) -> Result<DbAnchor, StoreError> {
        let mut tx = self.readers().begin().await?;
        let r = sqlx::query(
            "SELECT backend, instance_id, \
             coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'), 0) AS a, \
             coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'release'), 0) AS r, \
             coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'search_outbox'), 0) AS o \
             FROM db_state WHERE id = 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        let rows = sqlx::query(
            "SELECT class, head_hash, floor_hash, rows FROM audit_chain_state ORDER BY class",
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DbAnchor {
            backend: r.try_get("backend")?,
            instance_id: hex(&r.try_get::<Vec<u8>, _>("instance_id")?),
            system_identifier: String::new(),
            seq_audit: r.try_get("a")?,
            seq_release: r.try_get("r")?,
            seq_outbox: r.try_get("o")?,
            classes: classes_of(&rows)?,
        })
    }

    /// Compares the database with an anchor taken earlier (see the module docs).
    ///
    /// # Errors
    /// Database errors.
    pub async fn check_anchor(&self, anchored: &DbAnchor) -> Result<AnchorVerdict, StoreError> {
        let now = self.capture_anchor().await?;
        if let Some(v) = compare(anchored, &now) {
            return Ok(v);
        }
        for (class, (head, _, _)) in heads_to_probe(anchored, &now) {
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM audit_log WHERE chain_class = ?1 AND hex(chain_hash) = upper(?2))",
            )
            .bind(class)
            .bind(head)
            .fetch_one(self.readers())
            .await?;
            if !present {
                return Ok(AnchorVerdict::RestoreDetected("audit head missing"));
            }
        }
        Ok(AnchorVerdict::Consistent)
    }

    /// True when the library holds no account and no release (a new, never used database).
    ///
    /// # Errors
    /// Database errors.
    pub async fn library_is_empty(&self) -> Result<bool, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM account) + (SELECT count(*) FROM release) \
             + (SELECT count(*) FROM release_trash)",
        )
        .fetch_one(self.readers())
        .await?;
        Ok(n == 0)
    }
}

/// `(head hex, floor hex, rows)` per class, class 0 first.
pub(crate) fn classes_of<R: sqlx::Row>(rows: &[R]) -> Result<[(String, String, i64); 2], StoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Vec<u8>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let mut classes: [(String, String, i64); 2] = Default::default();
    for row in rows {
        let class: i64 = row.try_get("class")?;
        let slot = classes
            .get_mut(usize::from(class == 1))
            .ok_or(StoreError::OutOfRange("audit class"))?;
        *slot = (
            hex(&row.try_get::<Vec<u8>, _>("head_hash")?),
            hex(&row.try_get::<Vec<u8>, _>("floor_hash")?),
            row.try_get("rows")?,
        );
    }
    Ok(classes)
}

/// The identity and sequence rules of the comparison; `None` = go on with the audit head probes.
pub(crate) fn compare(anchored: &DbAnchor, now: &DbAnchor) -> Option<AnchorVerdict> {
    if now.backend != anchored.backend || now.instance_id != anchored.instance_id {
        return Some(AnchorVerdict::LibraryMismatch);
    }
    if now.system_identifier != anchored.system_identifier {
        return Some(AnchorVerdict::RestoreDetected("another cluster"));
    }
    if now.seq_audit < anchored.seq_audit
        || now.seq_release < anchored.seq_release
        || now.seq_outbox < anchored.seq_outbox
    {
        return Some(AnchorVerdict::RestoreDetected("sequence behind the anchor"));
    }
    None
}

/// Anchored audit heads that must still be in their chain: a purge since the anchor moves the floor and the anchored
/// head may then be gone legitimately (the sequence checks still catch a rollback); an all-zero head is a class
/// without rows.
pub(crate) fn heads_to_probe<'a>(
    anchored: &'a DbAnchor,
    now: &DbAnchor,
) -> Vec<(i64, &'a (String, String, i64))> {
    anchored
        .classes
        .iter()
        .zip(&now.classes)
        .zip([0_i64, 1])
        .filter(|((a, n), _)| a.1 == n.1 && !a.0.chars().all(|c| c == '0'))
        .map(|((a, _), class)| (class, a))
        .collect()
}

/// Writes the anchor file: 0600, tmp + fsync + rename + directory fsync.
///
/// # Errors
/// Filesystem errors.
pub fn write_anchor(path: &Path, a: &DbAnchor) -> Result<(), StoreError> {
    let text = json!({
        "v": 2,
        "backend": a.backend,
        "instance_id": a.instance_id,
        "system_identifier": a.system_identifier,
        "seq_audit": a.seq_audit,
        "seq_release": a.seq_release,
        "seq_outbox": a.seq_outbox,
        "classes": a.classes.iter().map(|(h, f, r)| json!({"head": h, "floor": f, "rows": r})).collect::<Vec<_>>(),
    })
    .to_string();
    let dir = path.parent().ok_or(StoreError::OutOfRange("anchor path"))?;
    let tmp = path.with_extension("json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Reads the anchor file; `None` when it does not exist (first start).
///
/// # Errors
/// Filesystem errors; [`StoreError::Integrity`] for a malformed file.
pub fn read_anchor(path: &Path) -> Result<Option<DbAnchor>, StoreError> {
    let not_small_file = || StoreError::Integrity("anchor file is not a small regular file".into());
    // Opened `O_NOFOLLOW|O_NONBLOCK` and checked through the descriptor: a swap of the path between
    // a check and the read cannot substitute another file, and a FIFO cannot block.
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(not_small_file()),
        Err(e) => return Err(e.into()),
    };
    let meta = f.metadata()?;
    if !meta.is_file() || meta.len() > MAX_ANCHOR_BYTES {
        return Err(not_small_file());
    }
    let mut bytes = Vec::new();
    f.take(MAX_ANCHOR_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ANCHOR_BYTES {
        return Err(not_small_file());
    }
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|_| StoreError::Integrity("anchor file is not valid".into()))?;
    let bad = || StoreError::Integrity("anchor file is not valid".into());
    let int = |k: &str| v.get(k).and_then(Value::as_i64).ok_or_else(bad);
    let classes = v.get("classes").and_then(Value::as_array).ok_or_else(bad)?;
    let class = |i: usize| -> Result<(String, String, i64), StoreError> {
        let c = classes.get(i).ok_or_else(bad)?;
        Ok((
            c.get("head")
                .and_then(Value::as_str)
                .ok_or_else(bad)?
                .to_owned(),
            c.get("floor")
                .and_then(Value::as_str)
                .ok_or_else(bad)?
                .to_owned(),
            c.get("rows").and_then(Value::as_i64).ok_or_else(bad)?,
        ))
    };
    let text = |k: &str| -> Result<String, StoreError> {
        Ok(v.get(k).and_then(Value::as_str).ok_or_else(bad)?.to_owned())
    };
    Ok(Some(DbAnchor {
        backend: text("backend")?,
        instance_id: text("instance_id")?,
        system_identifier: v
            .get("system_identifier")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_owned(),
        seq_audit: int("seq_audit")?,
        seq_release: int("seq_release")?,
        seq_outbox: int("seq_outbox")?,
        classes: [class(0)?, class(1)?],
    }))
}
