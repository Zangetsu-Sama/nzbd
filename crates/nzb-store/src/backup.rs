//! Backups and maintenance purges (SEC-044).
//!
//! A backup is a consistent snapshot made with `VACUUM INTO`, written to a 0600 temp file in the
//! backups directory, integrity-checked, fsynced and renamed into place. File names are generated
//! from the clock only (`nzbd-YYYYMMDDTHHMMSSZ.sqlite`), never from external input, and rotation
//! deletes only files matching that exact pattern. NZB blobs are never touched, and the TOTP
//! encryption key is a file outside the database, so it is deliberately *not* part of any backup.
//!
//! With a [`BackupKey`] (T104) the verified snapshot is additionally sealed into
//! `nzbd-...Z.sqlite.enc` (authenticated chunked AEAD, see `backup_crypto`) and the plaintext
//! snapshot, which only ever exists as a 0600 hidden temp file in the backups directory, is
//! removed before the encrypted file is published.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use sqlx::Row as _;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::backup_crypto::{self, BackupKey};
use crate::db::SqliteDb;
use crate::error::StoreError;
use crate::retention::RetentionPolicy;

macro_rules! account_audit_events_sql_sql {
    () => {
        "'invite_create','invite_revoke','invite_redeem','user_create',\
'role_change','user_disable','user_enable','user_delete','user_unlock','user_display_name',\
'recover_issue','recover_redeem','recover_apply','recover_cancel','sessions_revoke',\
'user.create','user.reset_password','user.reset_mfa','user.enroll_token_issued','db.restore_finish'"
    };
}

/// Default number of backups kept by rotation.
pub const DEFAULT_KEEP: usize = 14;
const PREFIX: &str = "nzbd-";
const SUFFIX: &str = "Z.sqlite";
const TMP_SUFFIX: &str = ".tmp";
/// Extra suffix of encrypted backups (`nzbd-...Z.sqlite.enc`).
pub const ENC_SUFFIX: &str = ".enc";
/// Rows per purge transaction on SQLite (review 35 L8; the Postgres functions use the same 10,000).
pub(crate) const PURGE_BATCH: i64 = 10_000;
/// Upper bound of batches per purge step, so one run always ends (100M rows at the default batch).
const PURGE_MAX_ROUNDS: u32 = 10_000;
const SECS_PER_DAY: i64 = 86_400;
/// Default `maintenance.account_audit_retention_days`.
pub const DEFAULT_ACCOUNT_AUDIT_DAYS: u32 = 365;
/// Account-lifecycle audit events kept for the account retention instead of the 90-day log retention
/// (`AUTH_SPEC` "Retention"; the 1.x CLI `user.*` events included). High-volume and attacker-driven events
/// (`authz_denied`, `invite_redeem_failure`, `account_throttled`, `session_pending_killed`, `login.fail`,
/// `mfa.fail`) are deliberately not here.
pub const ACCOUNT_AUDIT_EVENTS: [&str; 20] = [
    "invite_create",
    "invite_revoke",
    "invite_redeem",
    "user_create",
    "role_change",
    "user_disable",
    "user_enable",
    "user_delete",
    "user_unlock",
    "user_display_name",
    "recover_issue",
    "recover_redeem",
    "recover_apply",
    "recover_cancel",
    "sessions_revoke",
    "user.create",
    "user.reset_password",
    "user.reset_mfa",
    "user.enroll_token_issued",
    "db.restore_finish",
];

/// Result of a backup run.
#[derive(Debug, Clone)]
pub struct BackupReport {
    /// The backup file created.
    pub path: PathBuf,
    /// Older backups removed by rotation.
    pub rotated: usize,
}

/// Rows removed by [`SqliteDb::purge_old_logs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// `audit_log` rows deleted.
    pub audit: u64,
    /// `ingest_log` rows deleted.
    pub ingest: u64,
    /// Audit rows whose timestamp is more than a day in the future (clock step or wrong RTC). They count as
    /// aged for the purge boundary, so one of them cannot pin the whole log; the caller logs a warning.
    pub future_rows: u64,
}

/// Slack before a row timestamp counts as "in the future" for the purge boundary.
const FUTURE_SLACK_SECS: i64 = SECS_PER_DAY;

/// Generated backup file name for a unix timestamp (UTC, seconds).
#[must_use]
pub fn backup_name(now: i64) -> String {
    let days = now.div_euclid(SECS_PER_DAY);
    let rem = now.rem_euclid(SECS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{PREFIX}{y:04}{m:02}{d:02}T{:02}{:02}{:02}{SUFFIX}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days` (inputs are clock values, far from overflow).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(m <= 2));
    (y, m, d)
}

/// True only for exactly `nzbd-` + 8 digits + `T` + 6 digits + `Z.sqlite` (+ optional `.enc`).
pub(crate) fn is_backup_name(name: &str) -> bool {
    let name = name.strip_suffix(ENC_SUFFIX).unwrap_or(name);
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

/// The worker owns every resource until the snapshot and cleanup finish. Dropping the caller's
/// future only detaches its join handle: `SQLx` may continue `VACUUM INTO` after an awaiting future
/// is cancelled, so the directory lock must not belong to that future. Filesystem work and
/// encryption also stay off the async runtime threads. Every owned key copy zeroizes on drop.
async fn run_backup(
    pool: SqlitePool,
    dir: PathBuf,
    now: i64,
    keep: usize,
    key: Option<BackupKey>,
    close_pool: bool,
) -> Result<BackupReport, StoreError> {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        runtime.block_on(async move {
            let result = backup_pool(&pool, &dir, now, keep, key.as_ref()).await;
            if close_pool {
                pool.close().await;
            }
            result
        })
    })
    .await
    .map_err(|_| StoreError::Io(std::io::Error::other("backup worker failed")))?
}

/// Exercise the real worker with a deliberately occupied private pool, independently of the
/// request reader pool. This keeps cancellation/locking tests deterministic without a large file.
#[cfg(test)]
pub(crate) async fn backup_with_pool_for_test(
    pool: SqlitePool,
    dir: PathBuf,
    now: i64,
    keep: usize,
) -> Result<BackupReport, StoreError> {
    run_backup(pool, dir, now, keep, None, true).await
}

/// Snapshot `pool`'s database into `dir`, then rotate to `keep` files (min 1).
async fn backup_pool(
    pool: &SqlitePool,
    dir: &Path,
    now: i64,
    keep: usize,
    key: Option<&BackupKey>,
) -> Result<BackupReport, StoreError> {
    // The directory inode is shared by every handle/process using this destination. Hold its
    // advisory lock through cleanup, snapshot publication and rotation: a CLI backup must not
    // remove the in-flight temporary snapshot of the server's maintenance task (or vice versa).
    // No lock file is created or unlinked, so there is no stale-file or lock-inode replacement race.
    let _lock = lock_backup_dir(dir)?;
    clean_stale_tmp(dir)?;
    let name = backup_name(now);
    let final_name = if key.is_some() {
        format!("{name}{ENC_SUFFIX}")
    } else {
        name.clone()
    };
    let dest = dir.join(&final_name);
    // The plaintext snapshot always uses the plain generated name as its temp file.
    let tmp = dir.join(format!(".{name}{TMP_SUFFIX}"));
    let enc_tmp = dir.join(format!(".{final_name}{TMP_SUFFIX}"));
    if dest.exists() {
        return Err(StoreError::Io(std::io::Error::from(
            std::io::ErrorKind::AlreadyExists,
        )));
    }
    // Pre-create the empty 0600 target: VACUUM INTO accepts an existing empty file, and this way
    // the snapshot is never visible with default (umask) permissions. `create_new` also refuses
    // to follow or reuse anything already at that path (stale ones are cleaned by the callers).
    open_new_0600(&tmp)?;
    let res = snapshot_and_publish(pool, &tmp, &enc_tmp, &dest, dir, key).await;
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
        if key.is_some() {
            let _ = fs::remove_file(&enc_tmp);
        }
    }
    res?;
    let rotated = rotate(dir, keep, &final_name)?;
    Ok(BackupReport {
        path: dest,
        rotated,
    })
}

pub(crate) fn lock_backup_dir(dir: &Path) -> Result<File, StoreError> {
    let file = File::open(dir)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "another backup is using this directory",
        )
        .into()),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

async fn snapshot_and_publish(
    pool: &SqlitePool,
    tmp: &Path,
    enc_tmp: &Path,
    dest: &Path,
    dir: &Path,
    key: Option<&BackupKey>,
) -> Result<(), StoreError> {
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| StoreError::Integrity("backup path is not UTF-8".into()))?;
    sqlx::query("VACUUM INTO ?1")
        .bind(tmp_str)
        .execute(pool)
        .await?;
    // Review 34 M3: every backup copy is a pending restore. Whatever puts it back in place (`nzbd db restore`, a
    // manual copy, a volume tool), `serve` refuses it until `nzbd db restore-finish` applies the SEC-068 effects.
    // Rollback journal on the copy (it is a single file) so the mark is inside the file when it is closed.
    let mark = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(tmp)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
                .pragma("secure_delete", "ON"),
        )
        .await?;
    let marked = strip_copy(&mark).await;
    mark.close().await;
    marked?;
    // Verify the copy before it can ever be mistaken for a good backup.
    let check = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(tmp).read_only(true))
        .await?;
    let rows: Result<Vec<String>, _> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&check)
        .await;
    check.close().await;
    let rows = rows?;
    if rows.len() != 1 || rows.first().map(String::as_str) != Some("ok") {
        return Err(StoreError::Integrity(
            "backup failed integrity_check".into(),
        ));
    }
    if let Some(key) = key {
        // Seal, fsync, drop the plaintext, then publish: a crash at any point leaves only hidden
        // temp files (cleaned by the next run) and never a half-written backup under its final name.
        backup_crypto::encrypt_file(key, tmp, enc_tmp).map_err(crypto_err)?;
        fs::remove_file(tmp)?;
        fs::rename(enc_tmp, dest)?;
    } else {
        File::open(tmp)?.sync_all()?;
        fs::rename(tmp, dest)?;
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Review 34 L2 (parity with the Postgres export, review 30 L7): the copy keeps no credential-derived or short-lived
/// state. Sessions (with their CSRF tokens), staged credentials, open invitations and admin recovery codes, MFA
/// recovery codes and the throttle tables are deleted with `secure_delete` on, the copy is marked restore-pending,
/// then `VACUUM`ed so no freed page keeps the old bytes. `restore-finish` would delete them anyway; this keeps them
/// out of the backup at rest. One transaction for the deletes and the mark; `VACUUM` cannot run inside one.
async fn strip_copy(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;
    // Staging first (it references the invitation and the session), then its owners. Static statements only.
    sqlx::query("DELETE FROM credential_staging")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM session").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM invite WHERE used_at IS NULL AND revoked_at IS NULL")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM recovery_code")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM login_lock")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM account_throttle")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_known_ip")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE db_state SET restore_pending = 1 WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    sqlx::query("VACUUM").execute(pool).await?;
    Ok(())
}

fn crypto_err(e: backup_crypto::BackupCryptoError) -> StoreError {
    match e {
        backup_crypto::BackupCryptoError::Io(io) => StoreError::Io(io),
        other => StoreError::Integrity(format!("backup encryption: {other}")),
    }
}

fn open_new_0600(p: &Path) -> Result<File, StoreError> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(p)?)
}

/// Keep the published backup and the newest `keep - 1` other generated-name backups (min 1 total).
fn rotate(dir: &Path, keep: usize, published: &str) -> Result<usize, StoreError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // Regular files only (file_type does not follow symlinks).
        if name != published && is_backup_name(&name) && entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    // A clock rollback must not delete the snapshot we just published. The remaining fixed-width
    // UTC timestamps sort chronologically as strings, preserving the existing retention order.
    names.sort_unstable_by(|a, b| b.cmp(a));
    let mut removed = 0;
    for name in names.iter().skip(keep.saturating_sub(1)) {
        fs::remove_file(dir.join(name))?;
        removed += 1;
    }
    Ok(removed)
}

/// Exact temporary names created by backup, including the plaintext copy's rollback journal.
fn is_backup_tmp_name(name: &str) -> bool {
    let (name, journal) = name
        .strip_suffix("-journal")
        .map_or((name, false), |base| (base, true));
    name.strip_prefix('.')
        .and_then(|s| s.strip_suffix(TMP_SUFFIX))
        .is_some_and(|base| is_backup_name(base) && (!journal || !base.ends_with(ENC_SUFFIX)))
}

/// Remove stale temp files of crashed runs (exact generated pattern only). A crash during
/// `strip_copy` can leave old credential pages in the plaintext SQLite rollback journal, even
/// when the intended backup was encrypted. Encrypted files themselves never have a journal.
fn clean_stale_tmp(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(n) = entry.file_name().to_str()
            && is_backup_tmp_name(n)
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Back up the database at `db_path` without opening it for writes or running migrations
/// (so `nzbd backup` before an upgrade snapshots the *old* schema, even while the server runs).
///
/// # Errors
/// Database or filesystem errors.
pub async fn backup_file(
    db_path: &Path,
    dir: &Path,
    now: i64,
    keep: usize,
) -> Result<BackupReport, StoreError> {
    backup_file_with(db_path, dir, now, keep, None).await
}

/// [`backup_file`] with optional at-rest encryption (`Some(key)` writes `...sqlite.enc`).
///
/// # Errors
/// Database, filesystem or encryption errors.
pub async fn backup_file_with(
    db_path: &Path,
    dir: &Path,
    now: i64,
    keep: usize,
    key: Option<&BackupKey>,
) -> Result<BackupReport, StoreError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(db_path)
                .read_only(true)
                .busy_timeout(std::time::Duration::from_secs(5)),
        )
        .await?;
    run_backup(pool, dir.to_path_buf(), now, keep, key.cloned(), true).await
}

impl SqliteDb {
    /// Consistent `VACUUM INTO` backup into `dir` (0600, tmp+fsync+rename), then keep-`keep` rotation.
    ///
    /// # Errors
    /// Database or filesystem errors; an existing file of the same second is never overwritten.
    pub async fn backup(
        &self,
        dir: &Path,
        now: i64,
        keep: usize,
    ) -> Result<BackupReport, StoreError> {
        self.backup_with(dir, now, keep, None).await
    }

    /// [`SqliteDb::backup`] with optional at-rest encryption (`Some(key)` writes `...sqlite.enc`).
    /// Each admitted snapshot owns a separate connection until its worker finishes. Await this
    /// operation when its completion is required: [`SqliteDb::close`] closes the ordinary pools,
    /// but does not join a snapshot already in progress. An already-closed handle is refused.
    ///
    /// # Errors
    /// Database, filesystem or encryption errors.
    pub async fn backup_with(
        &self,
        dir: &Path,
        now: i64,
        keep: usize,
        key: Option<&BackupKey>,
    ) -> Result<BackupReport, StoreError> {
        // Preserve the closed-handle contract instead of reopening a database after shutdown.
        if self.readers().is_closed() {
            return Err(sqlx::Error::PoolClosed.into());
        }
        // Keep the exact filename and connection pragmas, but not the request pool's progress
        // handler: a maintenance snapshot must not inherit a request's statement deadline.
        // Lazy opening transfers ownership to the worker before any connection attempt awaits.
        let options = self
            .readers()
            .connect_options()
            .as_ref()
            .clone()
            .read_only(true)
            .create_if_missing(false);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        run_backup(pool, dir.to_path_buf(), now, keep, key.cloned(), true).await
    }

    /// Delete sessions whose `expires_at` is at or before `now`. Returns rows removed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM session WHERE expires_at <= ?1")
            .bind(now)
            .execute(self.writer())
            .await?;
        Ok(r.rows_affected())
    }

    /// Delete `audit_log` and `ingest_log` rows older than `days` days (one transaction); account
    /// lifecycle audit rows follow [`DEFAULT_ACCOUNT_AUDIT_DAYS`] ([`SqliteDb::purge_logs`]).
    /// `days == 0` keeps everything.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_old_logs(&self, now: i64, days: u32) -> Result<PurgeReport, StoreError> {
        self.purge_logs_at(now, days, DEFAULT_ACCOUNT_AUDIT_DAYS)
            .await
    }

    /// The retention policy in force (`retention_policy`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn retention_policy(&self) -> Result<RetentionPolicy, StoreError> {
        let r = sqlx::query(
            "SELECT log_days, account_days, ingest_days, keep_all, account_keep_all FROM retention_policy \
             WHERE id = 1",
        )
        .fetch_one(self.readers())
        .await?;
        let days = |name: &'static str| -> Result<u32, StoreError> {
            u32::try_from(r.try_get::<i64, _>(name)?).map_err(|_| StoreError::OutOfRange(name))
        };
        Ok(RetentionPolicy {
            log_days: days("log_days")?,
            account_days: days("account_days")?,
            ingest_days: days("ingest_days")?,
            keep_all: r.try_get::<i64, _>("keep_all")? != 0,
            account_keep_all: r.try_get::<i64, _>("account_keep_all")? != 0,
        })
    }

    /// Writes the retention policy (`nzbd db set-retention` on SQLite). Values below the floors are refused first
    /// (and by the table's CHECKs).
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] below a floor; database errors.
    pub async fn set_retention_policy(&self, p: RetentionPolicy) -> Result<(), StoreError> {
        p.validate()?;
        sqlx::query(
            "UPDATE retention_policy SET log_days = ?1, account_days = ?2, ingest_days = ?3, keep_all = ?4, \
             account_keep_all = ?5 WHERE id = 1",
        )
        .bind(i64::from(p.log_days))
        .bind(i64::from(p.account_days))
        .bind(i64::from(p.ingest_days))
        .bind(i64::from(p.keep_all))
        .bind(i64::from(p.account_keep_all))
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// Applies the retention policy in force (the daily maintenance job): cutoffs from the policy row and the
    /// database clock (`unixepoch()`, the clock of the `audit_log_floor` trigger). Same contract as the Postgres
    /// backend's `purge_logs`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_logs(&self) -> Result<PurgeReport, StoreError> {
        let p = self.retention_policy().await?;
        if p.keep_all {
            return Ok(PurgeReport {
                audit: 0,
                ingest: 0,
                future_rows: 0,
            });
        }
        let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
            .fetch_one(self.readers())
            .await?;
        let account_days = if p.account_keep_all {
            0
        } else {
            p.account_days
        };
        self.purge_logs_with(now, p.log_days, account_days, p.ingest_days)
            .await
    }

    /// Like [`SqliteDb::purge_old_logs`] with an explicit clock and retention (tests and 2.x callers; production
    /// uses [`SqliteDb::purge_logs`] and the policy row) for the account-lifecycle audit rows
    /// ([`ACCOUNT_AUDIT_EVENTS`], decided by event NAME, never by `target_id`, I-6):
    /// `account_audit_days == 0` keeps them forever, otherwise they are removed only when older than
    /// `max(days, account_audit_days)`. `days == 0` keeps everything.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_logs_at(
        &self,
        now: i64,
        days: u32,
        account_audit_days: u32,
    ) -> Result<PurgeReport, StoreError> {
        self.purge_logs_with(now, days, account_audit_days, days)
            .await
    }

    async fn purge_logs_with(
        &self,
        now: i64,
        days: u32,
        account_audit_days: u32,
        ingest_days: u32,
    ) -> Result<PurgeReport, StoreError> {
        self.purge_logs_batched(now, days, account_audit_days, ingest_days, PURGE_BATCH)
            .await
    }

    /// One audit class's prefix purge in batches (see [`SqliteDb::purge_logs_batched`]); returns the rows removed.
    async fn purge_audit_class(
        &self,
        class: i64,
        cut: i64,
        latest_sane: i64,
        batch: i64,
    ) -> Result<u64, StoreError> {
        let mut total = 0_u64;
        for _ in 0..PURGE_MAX_ROUNDS {
            // BEGIN IMMEDIATE: the chain boundary is read and acted on under the write lock, per batch.
            let mut tx = self.begin_immediate().await?;
            let boundary: Option<i64> = sqlx::query_scalar(
                "SELECT MIN(id) FROM audit_log WHERE chain_class = ?1 AND ts >= ?2 AND ts <= ?3",
            )
            .bind(class)
            .bind(cut)
            .bind(latest_sane)
            .fetch_one(&mut *tx)
            .await?;
            let below = boundary.unwrap_or(i64::MAX);
            // The batch ends after the `batch`-th row of the prefix (or at the boundary).
            let last: Option<(i64, Vec<u8>)> = sqlx::query_as(
                "SELECT id, chain_hash FROM (SELECT id, chain_hash FROM audit_log WHERE chain_class = ?1 AND id < ?2 ORDER BY id LIMIT ?3) ORDER BY id DESC LIMIT 1",
            )
            .bind(class)
            .bind(below)
            .bind(batch)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((last_id, floor)) = last else {
                break;
            };
            let n = sqlx::query("DELETE FROM audit_log WHERE chain_class = ?1 AND id <= ?2")
                .bind(class)
                .bind(last_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let n_i = i64::try_from(n).map_err(|_| StoreError::OutOfRange("purged rows"))?;
            sqlx::query(
                "UPDATE audit_chain_state SET floor_hash = ?2, rows = rows - ?3 WHERE class = ?1",
            )
            .bind(class)
            .bind(floor)
            .bind(n_i)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            total = total.saturating_add(n);
        }
        Ok(total)
    }

    /// The purge in write transactions of at most `batch` rows each (review 35 L8): the single SQLite writer is held
    /// for one bounded batch at a time, so logins, session touches and revocations interleave with a large purge
    /// instead of waiting for all of it (the Postgres purge is batched the same way). Every audit batch removes a
    /// prefix of its class and moves the floor to the last removed row, so the chain stays verifiable after any
    /// batch; a crash between batches leaves a smaller, still consistent purge.
    pub(crate) async fn purge_logs_batched(
        &self,
        now: i64,
        days: u32,
        account_audit_days: u32,
        ingest_days: u32,
        batch: i64,
    ) -> Result<PurgeReport, StoreError> {
        if days == 0 {
            return Ok(PurgeReport {
                audit: 0,
                ingest: 0,
                future_rows: 0,
            });
        }
        let batch = batch.max(1);
        let cutoff = now.saturating_sub(i64::from(days).saturating_mul(SECS_PER_DAY));
        let account_cutoff = if account_audit_days == 0 {
            i64::MIN
        } else {
            now.saturating_sub(i64::from(days.max(account_audit_days)).saturating_mul(SECS_PER_DAY))
        };
        // Chained rows (T105): a purge removes only a PREFIX by id of each chain class, so the survivors stay linked
        // to a known anchor. The boundary is the first row of the class that is still young enough; a young row that
        // sits before older ones (clock steps back) therefore delays their removal until it has aged too.
        // A row stamped more than a day ahead is treated as aged (it must not pin everything after it, L2) and is
        // counted so the caller can warn about the clock.
        let latest_sane = now.saturating_add(FUTURE_SLACK_SECS);
        let future_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE chain_class IS NOT NULL AND ts > ?1",
        )
        .bind(latest_sane)
        .fetch_one(self.readers())
        .await?;
        let mut audit = 0_u64;
        for (class, cut) in [(0_i64, cutoff), (1_i64, account_cutoff)] {
            if class == 1 && account_audit_days == 0 {
                continue; // keep every account-lifecycle row
            }
            audit = audit.saturating_add(
                self.purge_audit_class(class, cut, latest_sane, batch)
                    .await?,
            );
        }
        // Rows without chain columns (written by a bypass, or by tests) keep the plain age rule, by event NAME.
        for _ in 0..PURGE_MAX_ROUNDS {
            let n = sqlx::query(concat!(
                "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log WHERE chain_class IS NULL AND \
                 ((ts < ?1 AND event NOT IN (",
                account_audit_events_sql_sql!(),
                ")) \
                 OR (ts < ?2 AND event IN (",
                account_audit_events_sql_sql!(),
                "))) LIMIT ?3)"
            ))
            .bind(cutoff)
            .bind(account_cutoff)
            .bind(batch)
            .execute(self.writer())
            .await?
            .rows_affected();
            audit = audit.saturating_add(n);
            if n == 0 {
                break;
            }
        }
        let ingest_cutoff = now.saturating_sub(i64::from(ingest_days).saturating_mul(SECS_PER_DAY));
        let mut ingest = 0_u64;
        for _ in 0..PURGE_MAX_ROUNDS {
            let n = sqlx::query(
                "DELETE FROM ingest_log WHERE id IN (SELECT id FROM ingest_log WHERE ts < ?1 LIMIT ?2)",
            )
            .bind(ingest_cutoff)
            .bind(batch)
            .execute(self.writer())
            .await?
            .rows_affected();
            ingest = ingest.saturating_add(n);
            if n == 0 {
                break;
            }
        }
        Ok(PurgeReport {
            audit,
            ingest,
            future_rows: u64::try_from(future_rows).unwrap_or(0),
        })
    }
}
