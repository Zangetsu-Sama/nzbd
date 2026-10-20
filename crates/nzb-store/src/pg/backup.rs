//! Snapshot backup and restore on Postgres (T112; ARCHITECTURE v3 section 10, `SECURITY_DELTA` 2.6, SEC-044,
//! SEC-052, SEC-094, review L7).
//!
//! This nzbd-native export is the default backup (D35 d, owner answer Q8; physical backups stay an expert option).
//!
//! **Backup** (`nzbd backup`, app role): one `REPEATABLE READ READ ONLY` transaction; every exported table is streamed
//! with `COPY (SELECT ...) TO STDOUT (FORMAT binary)` in dependency order into a framed file, its row count taken in
//! the same snapshot and its bytes hashed; a trailing manifest (format, schema version, index epoch, per-table rows and
//! SHA-256, audit anchors) closes the file. Written to a 0600 hidden temp file, fsynced, renamed (or sealed with the
//! T104 container first when a backup key is configured), then rotated. No `pg_dump` binary is needed.
//!
//! **Not exported:** sessions, staged credentials, open invitations and recovery codes, MFA recovery codes, the
//! throttle tables (credential-derived; `restore-finish` deletes them anyway), the search tables (the index is
//! rebuilt), `category_stats` (recomputed exactly on restore), migration bookkeeping and `db_state`. Database role
//! passwords and key files are never in the database, so never in a backup.
//!
//! **Restore** (`nzbd db restore`, the `setup` service, OWNER role): the whole file is verified against its manifest
//! first (table set, byte counts, digests); then `db_state.restore_pending` is set in its own FIRST transaction (an
//! interrupted restore is never servable), the data is loaded in one transaction into an EMPTY schema at the SAME
//! migration version, the per-category totals and identity sequences are rebuilt, and the audit chain is verified.
//! `serve` refuses until `nzbd db restore-finish` (SEC-068 effects, epoch rotation).
//!
//! File layout (plaintext, before the optional T104 sealing): `NZBDPGX1`, then per table `0x01, u16 name length,
//! name, chunks (u32 length > 0, bytes)..., u32 0`, then `0x02, u32 manifest length, manifest JSON, NZBDEND1`. Binary
//! `COPY` data is produced and consumed by Postgres itself (no text escaping anywhere, SEC-088).

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use futures_util::StreamExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection as _, PgConnection, Row as _};

use crate::StoreError;
use crate::backup_crypto::{self, BackupKey};
use crate::pg::{MIGRATOR, PgDb};

const MAGIC: &[u8; 8] = b"NZBDPGX1";
const END: &[u8; 8] = b"NZBDEND1";
const TAG_TABLE: u8 = 1;
const TAG_MANIFEST: u8 = 2;
/// Manifest format version.
const FORMAT: i64 = 1;
/// Largest manifest accepted on restore (it lists a dozen tables).
const MAX_MANIFEST: u32 = 1 << 20;
/// Largest single chunk accepted on restore (the writer emits at most `COPY` message sizes, well below this).
const MAX_CHUNK: u32 = 64 << 20;
/// File name parts: `nzbd-YYYYMMDDTHHMMSSZ.nzbdpg` (+ `.enc` when sealed).
const PREFIX: &str = "nzbd-";
const SUFFIX: &str = "Z.nzbdpg";
const TMP_SUFFIX: &str = ".tmp";

/// One exported table: name, `COPY ... TO STDOUT`, `COPY ... FROM STDIN`, row count in the snapshot. All four are
/// compile-time literals with explicit column lists, identical on both sides.
struct Table {
    name: &'static str,
    export: &'static str,
    import: &'static str,
    count: &'static str,
}

macro_rules! table {
    ($name:literal, $cols:literal, $from:literal, $order:literal) => {
        Table {
            name: $name,
            export: concat!(
                "COPY (SELECT ",
                $cols,
                " FROM ",
                $from,
                " ORDER BY ",
                $order,
                ") TO STDOUT (FORMAT binary)"
            ),
            import: concat!("COPY ", $name, " (", $cols, ") FROM STDIN (FORMAT binary)"),
            count: concat!("SELECT count(*) FROM ", $from),
        }
    };
}

/// Dependency order (referenced tables first).
const TABLES: [Table; 13] = [
    table!(
        "account",
        "id, username, password_hash, role, totp_secret_enc, totp_enabled, totp_last_step, failed_logins, \
         locked_until, last_failed_at, enroll_token_hash, enroll_token_expires, created_at, password_changed_at, \
         disabled_at, deleted_at, created_by, last_login_at, display_name, credentials_replaced_at, \
         credentials_replaced_by, email",
        "account",
        "id"
    ),
    table!(
        "user_pref",
        "account_id, hide_xxx, theme, page_size_releases, page_size_files, updated_at",
        "user_pref",
        "account_id"
    ),
    // Private per account (T127), restored like `user_pref`.
    table!(
        "saved_search",
        "id, account_id, name, filters, created_at, last_seen_at",
        "saved_search",
        "id"
    ),
    table!(
        "api_key",
        "id, name, prefix, key_hash, scope, created_at, last_used_at, revoked_at, owner_id, rate_per_min, revoked_by",
        "api_key",
        "id"
    ),
    // Closed codes only: open invitations and recovery codes are never exported (review L7).
    table!(
        "invite",
        "id, purpose, token_hash, username, role, account_id, created_by, created_via, created_at, expires_at, \
         used_at, used_by, revoked_at, name_refusals",
        "invite WHERE used_at IS NOT NULL OR revoked_at IS NOT NULL",
        "id"
    ),
    table!(
        "release",
        "id, sha256, title, category_id, category_source, category_overridden, posted_at, ingested_at, total_bytes, \
         poster, file_count, segment_count, missing_segment_count, par2_blocks, flags, nzb_size_bytes, source_name, \
         source_label, origin, meta_json, scene_family, scene_year, scene_season, scene_episode, scene_resolution, \
         scene_source, scene_codec, scene_group, scene_title, scene_languages, scene_json, added_by, index_version",
        "release",
        "id"
    ),
    table!(
        "nzb_file",
        "release_id, idx, subject, filename, kind, poster, posted_at, bytes, segment_count, declared_segments, \
         missing_ranges, groups",
        "nzb_file",
        "release_id, idx"
    ),
    table!(
        "release_trash",
        "id, original_id, sha256, title, category_id, total_bytes, nzb_size_bytes, file_count, source_name, \
         ingested_at, deleted_at, added_by, deleted_by",
        "release_trash",
        "id"
    ),
    // Keyed by digest, no foreign key (T140): restored after both release tables.
    table!(
        "release_nfo",
        "sha256, bytes, added_at, added_by, trashed_at, restored_at",
        "release_nfo",
        "sha256"
    ),
    table!(
        "ingest_log",
        "id, ts, source, api_key_id, account_id, source_name, sha256, outcome, error_code, detail, release_id",
        "ingest_log",
        "ts, id"
    ),
    table!(
        "audit_log",
        "id, ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id, chain_class, chain_prev, \
         chain_hash",
        "audit_log",
        "id"
    ),
    table!(
        "audit_chain_state",
        "class, floor_hash, head_hash, rows",
        "audit_chain_state",
        "class"
    ),
    table!(
        "retention_policy",
        "id, log_days, account_days, ingest_days, keep_all, account_keep_all",
        "retention_policy",
        "id"
    ),
];

/// Result of a backup run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReport {
    /// The file written.
    pub path: PathBuf,
    /// Older backups removed by rotation.
    pub rotated: usize,
    /// Rows exported per table, in file order.
    pub tables: Vec<(String, u64)>,
}

/// Result of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Rows loaded per table, in file order.
    pub tables: Vec<(String, u64)>,
    /// The restored audit chain verified (always true on success; a broken chain is an error).
    pub audit_chain_ok: bool,
}

fn bad(what: &'static str) -> StoreError {
    StoreError::Integrity(format!("backup file: {what}"))
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

/// Generated backup file name for a Unix timestamp (UTC).
#[must_use]
pub fn snapshot_name(now: i64) -> String {
    let legacy = crate::backup::backup_name(now);
    // `nzbd-YYYYMMDDTHHMMSSZ.sqlite` -> same stamp, v3 suffix.
    let stamp = legacy
        .strip_prefix(PREFIX)
        .and_then(|s| s.split('Z').next())
        .unwrap_or_default();
    format!("{PREFIX}{stamp}{SUFFIX}")
}

/// Exactly `nzbd-` + 8 digits + `T` + 6 digits + `Z.nzbdpg` (+ `.enc`).
fn is_snapshot_name(name: &str) -> bool {
    let name = name.strip_suffix(crate::ENC_SUFFIX).unwrap_or(name);
    let Some(mid) = name
        .strip_prefix(PREFIX)
        .and_then(|s| s.strip_suffix(SUFFIX))
    else {
        return false;
    };
    let b = mid.as_bytes();
    b.len() == 15
        && b.iter().enumerate().all(|(i, c)| {
            if i == 8 {
                *c == b'T'
            } else {
                c.is_ascii_digit()
            }
        })
}

fn open_new_0600(p: &Path) -> Result<File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?)
}

fn rotate(dir: &Path, keep: usize, published: &str) -> Result<usize, StoreError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name != published && is_snapshot_name(&name) && entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    // Keep the just-published snapshot even if its timestamp precedes earlier runs after a clock
    // rollback. The remaining slots retain the existing newest-name-first ordering.
    names.sort_unstable_by(|a, b| b.cmp(a));
    let mut removed = 0;
    for name in names.iter().skip(keep.saturating_sub(1)) {
        fs::remove_file(dir.join(name))?;
        removed += 1;
    }
    Ok(removed)
}

fn clean_stale_tmp(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(n) = entry.file_name().to_str()
            && n.strip_prefix('.')
                .and_then(|s| s.strip_suffix(TMP_SUFFIX))
                .is_some_and(is_snapshot_name)
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn crypto_err(e: backup_crypto::BackupCryptoError) -> StoreError {
    match e {
        backup_crypto::BackupCryptoError::Io(io) => StoreError::Io(io),
        other => StoreError::Integrity(format!("backup encryption: {other}")),
    }
}

fn len_u32(n: usize) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| bad("section too large"))
}

impl PgDb {
    /// Writes a consistent snapshot of the database into `dir` (0600, tmp + fsync + rename, sealed with `key` when
    /// given) and keeps the newest `keep` snapshots.
    ///
    /// # Errors
    /// Database, filesystem or encryption errors; an existing file of the same second is never overwritten.
    #[allow(clippy::too_many_lines)] // one snapshot transaction, one file
    pub async fn snapshot_backup(
        &self,
        dir: &Path,
        now: i64,
        keep: usize,
        key: Option<&BackupKey>,
    ) -> Result<SnapshotReport, StoreError> {
        // Same directory lock as the SQLite backup: a CLI backup must not remove the in-flight
        // temporary snapshot of the server's maintenance task (or vice versa), and two exports of
        // the same second cannot race past the `dest.exists()` check below.
        let _lock = crate::backup::lock_backup_dir(dir)?;
        clean_stale_tmp(dir)?;
        let name = snapshot_name(now);
        let final_name = if key.is_some() {
            format!("{name}{}", crate::ENC_SUFFIX)
        } else {
            name.clone()
        };
        let dest = dir.join(&final_name);
        if dest.exists() {
            return Err(StoreError::Io(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists,
            )));
        }
        let tmp = dir.join(format!(".{name}{TMP_SUFFIX}"));
        let enc_tmp = dir.join(format!(".{final_name}{TMP_SUFFIX}"));
        // `create_new`: a temp file this call did not create is never removed below.
        let file = open_new_0600(&tmp)?;
        let res = self.write_snapshot(file, now).await;
        let tables = match res {
            Ok(t) => t,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        let publish = || -> Result<(), StoreError> {
            if let Some(key) = key {
                backup_crypto::encrypt_file(key, &tmp, &enc_tmp).map_err(crypto_err)?;
                fs::remove_file(&tmp)?;
                fs::rename(&enc_tmp, &dest)?;
            } else {
                File::open(&tmp)?.sync_all()?;
                fs::rename(&tmp, &dest)?;
            }
            File::open(dir)?.sync_all()?;
            Ok(())
        };
        if let Err(e) = publish() {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&enc_tmp);
            return Err(e);
        }
        let rotated = rotate(dir, keep, &final_name)?;
        Ok(SnapshotReport {
            path: dest,
            rotated,
            tables,
        })
    }

    async fn write_snapshot(&self, file: File, now: i64) -> Result<Vec<(String, u64)>, StoreError> {
        let mut out = BufWriter::new(file);
        out.write_all(MAGIC)?;
        let mut tx = self.background().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        // No statement timeout for the export (the background pool's default would cut a large one).
        sqlx::query("SET LOCAL statement_timeout = 0")
            .execute(&mut *tx)
            .await?;
        let mut manifest_tables = Vec::new();
        let mut report = Vec::new();
        for t in &TABLES {
            let rows: i64 = sqlx::query_scalar(t.count).fetch_one(&mut *tx).await?;
            out.write_all(&[TAG_TABLE])?;
            let name = t.name.as_bytes();
            out.write_all(
                &u16::try_from(name.len())
                    .map_err(|_| bad("name"))?
                    .to_be_bytes(),
            )?;
            out.write_all(name)?;
            let mut h = Sha256::new();
            let mut bytes = 0_u64;
            {
                let mut stream = tx.copy_out_raw(t.export).await?;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    if chunk.is_empty() {
                        continue;
                    }
                    out.write_all(&len_u32(chunk.len())?.to_be_bytes())?;
                    out.write_all(&chunk)?;
                    h.update(&chunk);
                    bytes = bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                }
            }
            out.write_all(&0_u32.to_be_bytes())?;
            manifest_tables.push(json!({
                "name": t.name,
                "rows": rows,
                "bytes": bytes,
                "sha256": hex(&h.finalize()),
            }));
            report.push((t.name.to_owned(), u64::try_from(rows).unwrap_or(0)));
        }
        let schema: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(version), 0) FROM nzbd._sqlx_migrations WHERE success",
        )
        .fetch_one(&mut *tx)
        .await?;
        let epoch: Vec<u8> = sqlx::query_scalar("SELECT epoch FROM search_state WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;
        // The library identity travels with the snapshot (SEC-101): a restore is the same library, not another one.
        let instance: Vec<u8> = sqlx::query_scalar("SELECT instance_id FROM db_state WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;
        let heads =
            sqlx::query("SELECT class, head_hash, rows FROM audit_chain_state ORDER BY class")
                .fetch_all(&mut *tx)
                .await?;
        let mut anchors = serde_json::Map::new();
        for r in &heads {
            let class: i16 = r.try_get("class")?;
            let head: Vec<u8> = r.try_get("head_hash")?;
            let rows: i64 = r.try_get("rows")?;
            anchors.insert(
                format!("class{class}"),
                json!({"head": hex(&head), "rows": rows}),
            );
        }
        tx.commit().await?;
        let manifest = json!({
            "format": FORMAT,
            "schema_version": schema,
            "epoch": hex(&epoch),
            "instance_id": hex(&instance),
            "created_at": now,
            "tables": manifest_tables,
            "anchors": Value::Object(anchors),
        })
        .to_string();
        out.write_all(&[TAG_MANIFEST])?;
        out.write_all(&len_u32(manifest.len())?.to_be_bytes())?;
        out.write_all(manifest.as_bytes())?;
        out.write_all(END)?;
        let f = out
            .into_inner()
            .map_err(|e| StoreError::Io(e.into_error()))?;
        f.sync_all()?;
        Ok(report)
    }
}

/// One verified table section of a snapshot file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    name: String,
    rows: u64,
    bytes: u64,
    sha256: String,
}

fn read_exact_or(r: &mut impl Read, buf: &mut [u8], what: &'static str) -> Result<(), StoreError> {
    r.read_exact(buf).map_err(|_| bad(what))
}

/// Sequential reader of a plaintext snapshot (blocking reads of bounded chunks; `nzbd db restore` is a one-shot
/// command). Used twice: the verify pass, then the load pass that streams each chunk into `COPY FROM`.
struct SectionReader {
    r: BufReader<File>,
    buf: Vec<u8>,
}

/// What comes next in the file.
enum Next {
    /// A table section (index into [`TABLES`]).
    Table(usize),
    /// The manifest (the file ended correctly after it).
    Manifest(Value),
}

impl SectionReader {
    fn open(path: &Path) -> Result<Self, StoreError> {
        let mut r = BufReader::new(File::open(path)?);
        let mut magic = [0_u8; 8];
        read_exact_or(&mut r, &mut magic, "not a v3 snapshot")?;
        if &magic != MAGIC {
            return Err(bad("not a v3 snapshot"));
        }
        Ok(Self { r, buf: Vec::new() })
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let mut b = [0_u8; 4];
        read_exact_or(&mut self.r, &mut b, "truncated")?;
        Ok(u32::from_be_bytes(b))
    }

    /// The next section header; `expected` is the index the table must have (files list every table once, in order).
    fn next(&mut self, expected: usize) -> Result<Next, StoreError> {
        let mut tag = [0_u8; 1];
        read_exact_or(&mut self.r, &mut tag, "truncated")?;
        match tag {
            [TAG_TABLE] => {
                let mut l = [0_u8; 2];
                read_exact_or(&mut self.r, &mut l, "truncated")?;
                let mut name = vec![0_u8; usize::from(u16::from_be_bytes(l))];
                read_exact_or(&mut self.r, &mut name, "truncated")?;
                let name = String::from_utf8(name).map_err(|_| bad("table name"))?;
                TABLES
                    .iter()
                    .position(|t| t.name == name)
                    .filter(|i| *i == expected)
                    .map(Next::Table)
                    .ok_or_else(|| bad("unexpected table or order"))
            }
            [TAG_MANIFEST] => {
                let n = self.u32()?;
                if n > MAX_MANIFEST {
                    return Err(bad("manifest too large"));
                }
                let mut m = vec![0_u8; usize::try_from(n).map_err(|_| bad("manifest"))?];
                read_exact_or(&mut self.r, &mut m, "truncated")?;
                let mut end = [0_u8; 8];
                read_exact_or(&mut self.r, &mut end, "truncated")?;
                if &end != END {
                    return Err(bad("trailer"));
                }
                let mut extra = [0_u8; 1];
                if self.r.read(&mut extra)? != 0 {
                    return Err(bad("data after the trailer"));
                }
                Ok(Next::Manifest(
                    serde_json::from_slice(&m).map_err(|_| bad("manifest"))?,
                ))
            }
            _ => Err(bad("unknown section")),
        }
    }

    /// The next chunk of the current table, `None` at its end.
    fn chunk(&mut self) -> Result<Option<&[u8]>, StoreError> {
        let n = self.u32()?;
        if n == 0 {
            return Ok(None);
        }
        if n > MAX_CHUNK {
            return Err(bad("chunk too large"));
        }
        self.buf
            .resize(usize::try_from(n).map_err(|_| bad("chunk"))?, 0);
        read_exact_or(&mut self.r, &mut self.buf, "truncated")?;
        Ok(Some(&self.buf))
    }
}

/// Verify pass: every table's byte count and digest, and the manifest.
/// `(table name, bytes, sha256 hex)` per section, as computed from the file.
type Seen = Vec<(String, u64, String)>;

fn walk_file(path: &Path) -> Result<(Seen, Value), StoreError> {
    let mut rd = SectionReader::open(path)?;
    let mut seen = Vec::new();
    loop {
        match rd.next(seen.len())? {
            Next::Table(i) => {
                let mut h = Sha256::new();
                let mut bytes = 0_u64;
                while let Some(c) = rd.chunk()? {
                    h.update(c);
                    bytes = bytes.saturating_add(u64::try_from(c.len()).unwrap_or(u64::MAX));
                }
                let name = TABLES.get(i).map_or("", |t| t.name).to_owned();
                seen.push((name, bytes, hex(&h.finalize())));
            }
            Next::Manifest(m) => return Ok((seen, m)),
        }
    }
}

/// Checks the computed sections against the manifest; returns the verified sections and the schema version.
fn verify_manifest(
    seen: &[(String, u64, String)],
    manifest: &Value,
) -> Result<(Vec<Section>, i64), StoreError> {
    if manifest.get("format").and_then(Value::as_i64) != Some(FORMAT) {
        return Err(bad("unknown format"));
    }
    let schema = manifest
        .get("schema_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| bad("schema version"))?;
    let tables = manifest
        .get("tables")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("manifest tables"))?;
    if tables.len() != TABLES.len() || seen.len() != TABLES.len() {
        return Err(bad("table set"));
    }
    let mut out = Vec::new();
    for ((m, s), t) in tables.iter().zip(seen).zip(&TABLES) {
        let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
        let rows = m
            .get("rows")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("rows"))?;
        let bytes = m
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("bytes"))?;
        let sha = m.get("sha256").and_then(Value::as_str).unwrap_or_default();
        if name != t.name || s.0 != t.name || bytes != s.1 || sha != s.2 {
            return Err(bad("manifest does not match the data"));
        }
        out.push(Section {
            name: name.to_owned(),
            rows,
            bytes,
            sha256: sha.to_owned(),
        });
    }
    Ok((out, schema))
}

/// Restore options.
#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreOptions<'a> {
    /// The configured backup key (`maintenance.backup_encryption_key_file`).
    pub key: Option<&'a BackupKey>,
    /// Accept a plaintext file although a key is configured (`--allow-unencrypted`, SEC-094).
    pub allow_unencrypted: bool,
}

/// Restores a v3 snapshot into an EMPTY database at the same migration version, connected as the OWNER role (the
/// `setup` service). See the module docs for the order of the steps.
///
/// # Errors
/// [`StoreError::Integrity`] for a refused file (format, manifest, digests, plaintext without the flag, wrong key),
/// a non-empty database or another schema version, or an audit chain that does not verify after the load; database
/// and filesystem errors.
pub async fn restore_snapshot(
    owner: PgConnectOptions,
    file: &Path,
    scratch: &Path,
    opts: RestoreOptions<'_>,
    now: i64,
) -> Result<RestoreReport, StoreError> {
    restore_inner(owner, file, scratch, opts, now, None).await
}

#[allow(clippy::too_many_lines)] // one linear restore: verify, mark, load, rebuild, verify
pub(crate) async fn restore_inner(
    owner: PgConnectOptions,
    file: &Path,
    scratch: &Path,
    opts: RestoreOptions<'_>,
    now: i64,
    fail_after_tables: Option<usize>,
) -> Result<RestoreReport, StoreError> {
    // 1. Plaintext in hand (decrypt into a 0600 scratch file when sealed).
    let encrypted = backup_crypto::looks_encrypted(file);
    let mut plain_tmp: Option<PathBuf> = None;
    let plain: PathBuf = if encrypted {
        let key = opts
            .key
            .ok_or_else(|| bad("encrypted, but no backup key is configured"))?;
        let p = scratch.join(".nzbd-restore.plain.tmp");
        // Leftovers of a crashed restore (authenticated plaintext; `SECURITY_REVIEW` 31 I4) are removed first.
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(scratch.join("..nzbd-restore.plain.tmp.decrypt.tmp"));
        if let Err(e) = backup_crypto::decrypt_file(key, file, &p) {
            // A publish whose link succeeded but whose unlink failed leaves the plaintext at `p`
            // (review 55): the scratch name is ours, so it goes on every error.
            let _ = fs::remove_file(&p);
            return Err(crypto_err(e));
        }
        plain_tmp = Some(p.clone());
        p
    } else {
        if opts.key.is_some() && !opts.allow_unencrypted {
            return Err(bad(
                "plaintext, but a backup key is configured (use --allow-unencrypted)",
            ));
        }
        file.to_path_buf()
    };
    let res = restore_plain(owner, &plain, now, fail_after_tables).await;
    if let Some(p) = plain_tmp {
        let _ = fs::remove_file(p);
    }
    res
}

#[allow(clippy::too_many_lines)]
async fn restore_plain(
    owner: PgConnectOptions,
    plain: &Path,
    now: i64,
    fail_after_tables: Option<usize>,
) -> Result<RestoreReport, StoreError> {
    // 2. Verify the whole file before anything is written.
    let (seen, manifest) = walk_file(plain)?;
    let (sections, schema) = verify_manifest(&seen, &manifest)?;
    let ours = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
    let mut conn = PgConnection::connect_with(&owner).await?;
    let applied: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(version), 0) FROM nzbd._sqlx_migrations WHERE success",
    )
    .fetch_one(&mut conn)
    .await?;
    if schema != ours || applied != ours {
        return Err(StoreError::Integrity(format!(
            "restore needs the same schema version: backup {schema}, database {applied}, binary {ours}"
        )));
    }
    let used: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM account) + (SELECT count(*) FROM release) + (SELECT count(*) FROM api_key) \
         + (SELECT count(*) FROM audit_log) + (SELECT count(*) FROM release_trash)",
    )
    .fetch_one(&mut conn)
    .await?;
    if used != 0 {
        return Err(StoreError::Integrity(
            "restore needs an empty database".into(),
        ));
    }
    // 3. FIRST transaction: the database is marked as a pending restore before any data exists (review L7).
    // The snapshot's library identity (SEC-101; snapshots written before it existed keep the new database's own).
    let instance = manifest
        .get("instance_id")
        .and_then(Value::as_str)
        .map(unhex)
        .transpose()?;
    sqlx::query(
        "UPDATE db_state SET restore_pending = true, restored_at = $1, \
         instance_id = coalesce($2, instance_id) WHERE id = 1",
    )
    .bind(now)
    .bind(instance)
    .execute(&mut conn)
    .await?;
    // 4. One transaction for the data.
    let mut tx = conn.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = 0")
        .execute(&mut *tx)
        .await?;
    // Legacy rows may carry reserved login names (flagged, never renamed, N5): the insert triggers are for new
    // accounts, not for a verified copy.
    sqlx::query("ALTER TABLE account DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM audit_chain_state")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM retention_policy")
        .execute(&mut *tx)
        .await?;
    let mut loaded = Vec::new();
    // Second pass over the verified file, each chunk streamed into `COPY FROM`; the digest is checked again on the
    // bytes actually sent, and the row count Postgres reports must equal the manifest's.
    let mut rd = SectionReader::open(plain)?;
    for (i, t) in TABLES.iter().enumerate() {
        if fail_after_tables.is_some_and(|n| i >= n) {
            return Err(StoreError::Integrity("injected restore failure".into()));
        }
        if t.name == "nzb_file" {
            // The partition function clamps to the release sequence (`SECURITY_REVIEW` 31 L1): move it past the
            // restored ids first (the full setval of every identity follows below).
            let max: Option<i64> = sqlx::query_scalar(
                "SELECT setval(pg_get_serial_sequence('nzbd.release', 'id'), max(id)) FROM release HAVING count(*) > 0",
            )
            .fetch_optional(&mut *tx)
            .await?;
            let _: i32 = sqlx::query_scalar("SELECT nzbd.ensure_file_partitions($1)")
                .bind(max.unwrap_or(0))
                .fetch_one(&mut *tx)
                .await?;
        }
        match rd.next(i)? {
            Next::Table(k) if k == i => {}
            _ => return Err(bad("table set")),
        }
        let mut h = Sha256::new();
        let mut copy = tx.copy_in_raw(t.import).await?;
        while let Some(c) = rd.chunk()? {
            h.update(c);
            copy.send(c).await?;
        }
        let rows = copy.finish().await?;
        let section = sections.get(i).ok_or_else(|| bad("section"))?;
        if rows != section.rows || hex(&h.finalize()) != section.sha256 {
            return Err(bad("loaded data does not match the manifest"));
        }
        loaded.push((t.name.to_owned(), rows));
    }
    sqlx::query("ALTER TABLE account ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await?;
    // Exact per-category totals, rebuilt from the rows.
    sqlx::query(
        "UPDATE category_stats c SET releases = coalesce(r.n, 0), files = coalesce(r.f, 0), \
         segments = coalesce(r.s, 0), bytes = coalesce(r.b, 0) \
         FROM (SELECT id FROM category) k LEFT JOIN (SELECT category_id, count(*) AS n, sum(file_count) AS f, \
         sum(segment_count) AS s, sum(total_bytes) AS b FROM release GROUP BY category_id) r \
         ON r.category_id = k.id WHERE c.category_id = k.id",
    )
    .execute(&mut *tx)
    .await?;
    // Identity sequences continue above the restored ids.
    sqlx::query(
        "SELECT setval(pg_get_serial_sequence('nzbd.account', 'id'), coalesce((SELECT max(id) FROM account), 1), \
                (SELECT count(*) > 0 FROM account)), \
                setval(pg_get_serial_sequence('nzbd.api_key', 'id'), coalesce((SELECT max(id) FROM api_key), 1), \
                (SELECT count(*) > 0 FROM api_key)), \
                setval(pg_get_serial_sequence('nzbd.invite', 'id'), coalesce((SELECT max(id) FROM invite), 1), \
                (SELECT count(*) > 0 FROM invite)), \
                setval(pg_get_serial_sequence('nzbd.release', 'id'), coalesce((SELECT max(id) FROM release), 1), \
                (SELECT count(*) > 0 FROM release)), \
                setval(pg_get_serial_sequence('nzbd.release_trash', 'id'), \
                coalesce((SELECT max(id) FROM release_trash), 1), (SELECT count(*) > 0 FROM release_trash)), \
                setval(pg_get_serial_sequence('nzbd.ingest_log', 'id'), coalesce((SELECT max(id) FROM ingest_log), 1), \
                (SELECT count(*) > 0 FROM ingest_log)), \
                setval(pg_get_serial_sequence('nzbd.audit_log', 'id'), coalesce((SELECT max(id) FROM audit_log), 1), \
                (SELECT count(*) > 0 FROM audit_log)), \
                setval(pg_get_serial_sequence('nzbd.saved_search', 'id'), \
                coalesce((SELECT max(id) FROM saved_search), 1), (SELECT count(*) > 0 FROM saved_search))",
    )
    .execute(&mut *tx)
    .await?;
    // A new index epoch: no index built before the restore is ever served (SEC-091).
    sqlx::query("UPDATE search_state SET epoch = uuid_send(gen_random_uuid()) WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    conn.close().await?;
    // 5. The restored chain must verify (restore_pending stays set either way: restore-finish is the operator's).
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(owner)
        .await?;
    let db = PgDb::from_pools(pool.clone(), pool.clone(), pool.clone());
    let report = db.audit_walk(None, &mut |_| {}).await?;
    pool.close().await;
    if !report.is_ok() {
        return Err(StoreError::AuditChain(
            "the restored audit chain does not verify",
        ));
    }
    Ok(RestoreReport {
        tables: loaded,
        audit_chain_ok: true,
    })
}

/// A 16-byte identity from its lower-case hex form.
fn unhex(s: &str) -> Result<Vec<u8>, StoreError> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("manifest instance_id"));
    }
    (0..16)
        .map(|i| {
            s.get(i * 2..i * 2 + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| bad("manifest instance_id"))
        })
        .collect()
}
