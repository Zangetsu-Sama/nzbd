//! Database bootstrap: pools, pragmas, startup checks, migrations, category seed.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

use crate::error::StoreError;
use crate::taxonomy::seed_rows;

/// Number of connections in the reader pool.
pub const READER_CONNECTIONS: u32 = 4;
const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);
/// Longest a reader statement may run (review 34 L5, the SQLite counterpart of the Postgres `statement_timeout`):
/// the progress handler interrupts it (`SQLITE_INTERRUPT`, a busy error: the uniform `503 BUSY`).
const READER_STATEMENT_DEADLINE: Duration = Duration::from_secs(30);
/// VM instructions between progress-handler calls (a call costs one clock read).
const READER_PROGRESS_OPS: i32 = 10_000;
/// A pause this long between handler calls starts a new deadline window: SQLite has no statement hook, so a window
/// is a burst of execution with no idle gap; statements of one request that run back to back share it (conservative).
const READER_BURST_GAP: Duration = Duration::from_millis(50);

/// Interval of [`OpenEvent::MigrationRunning`] heartbeats.
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);

/// Database settings (subset of the `[db]` config section).
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Path of the SQLite file (created if missing).
    pub path: PathBuf,
}

/// How much of the database file [`SqliteDb::open_with`] reads before it serves (T088).
///
/// `PRAGMA integrity_check` + `foreign_key_check` read the whole file and cost 107 s cold at
/// 1,000,000 releases (docs/BENCHMARK.md), on every start. Whatever the mode, a database with
/// **pending migrations** always gets [`StartupCheck::Full`] first: a migration rewrites pages and
/// builds indexes, so a damaged file must fail fast *before* anything touches it (restore from a
/// backup instead). The full check stays available on demand (`nzbd db check --full`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartupCheck {
    /// Bounded, independent of the library size: the header and schema must parse
    /// (`sqlite_master`), the migration ledger must be readable, and `PRAGMA quick_check` runs over
    /// the small tables that carry authentication state and configuration ([`CRITICAL_TABLES`]).
    /// Bulk tables (releases, files, blobs, FTS) are not read; damage there surfaces as
    /// `SQLITE_CORRUPT` on the page that reads it, or in the on-demand checks.
    #[default]
    Fast,
    /// `PRAGMA quick_check` over the whole file: reads every page and validates the b-tree
    /// structure, but not index-vs-table agreement or foreign keys.
    Quick,
    /// `PRAGMA integrity_check` + `PRAGMA foreign_key_check` (the pre-T088 behaviour).
    Full,
}

impl StartupCheck {
    /// Stable lowercase name (config value, log field).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Quick => "quick",
            Self::Full => "full",
        }
    }
}

/// Small tables the [`StartupCheck::Fast`] mode runs `quick_check` over: users, sessions, API
/// keys, the taxonomy and the sqlx ledger. Fixed identifiers (never input), present after every
/// migration; none grows with the library.
pub const CRITICAL_TABLES: [&str; 12] = [
    "account",
    "recovery_code",
    "session",
    "invite",
    "credential_staging",
    "account_throttle",
    "login_lock",
    "user_known_ip",
    "api_key",
    "audit_chain_state",
    "category",
    "_sqlx_migrations",
];

/// Progress notifications of [`SqliteDb::open_with`]. They carry nothing from the database beyond
/// migration numbers and their compiled-in descriptions.
#[derive(Debug, Clone)]
pub enum OpenEvent {
    /// A startup check is starting.
    CheckStarted {
        /// The mode actually run.
        mode: StartupCheck,
        /// True when pending migrations forced a stronger mode than the one requested.
        escalated: bool,
    },
    /// The startup check passed.
    CheckFinished {
        /// The mode that ran.
        mode: StartupCheck,
        /// Wall-clock seconds it took.
        secs: f64,
    },
    /// About to apply `total` migrations (versions `first..=last`).
    MigrationsPending {
        /// Number of pending migrations.
        total: usize,
        /// Lowest pending version.
        first: i64,
        /// Highest pending version.
        last: i64,
    },
    /// One migration starts.
    MigrationStarted {
        /// Version number.
        version: i64,
        /// Compiled-in description (the file name part after the number).
        description: String,
        /// 1-based position among the pending ones.
        index: usize,
        /// Number of pending migrations.
        total: usize,
    },
    /// A long migration is still running (emitted every [`PROGRESS_EVERY`]).
    MigrationRunning {
        /// Version number.
        version: i64,
        /// Seconds since this migration started.
        elapsed_secs: u64,
    },
    /// One migration committed.
    MigrationFinished {
        /// Version number.
        version: i64,
        /// Seconds it took.
        secs: f64,
    },
    /// SEC-102: a database file of the service uid was readable or writable by group/other (an operator copy
    /// without `chmod`) and has been set to 0600. Worth a warning: the data was exposed until now.
    FileModeFixed {
        /// Which file: `""` (the database), `"-wal"` or `"-shm"`.
        suffix: &'static str,
        /// The permission bits it had.
        mode: u32,
    },
}

/// Open database: one writer connection and a small reader pool.
#[derive(Debug, Clone)]
pub struct SqliteDb {
    writer: SqlitePool,
    readers: SqlitePool,
    /// Bumped after every committed change to the `release` table (T102); see [`SqliteDb::release_epoch`].
    epoch: Arc<AtomicU64>,
}

impl SqliteDb {
    /// Open (creating if needed), verify ([`StartupCheck::Fast`]), migrate and seed the database.
    ///
    /// # Errors
    /// See [`SqliteDb::open_with`].
    pub async fn open(cfg: &DbConfig) -> Result<Self, StoreError> {
        Self::open_with(cfg, StartupCheck::Fast, &|_| {}).await
    }

    /// Open (creating if needed), check, migrate and seed the database.
    ///
    /// Order matters: the check runs on the existing file *before* any migration touches it, so
    /// a corrupt database fails fast without being modified. When migrations are pending the
    /// check is always [`StartupCheck::Full`] (see its docs). `progress` receives [`OpenEvent`]s
    /// as the open advances; it must be cheap and non-blocking.
    ///
    /// # Errors
    /// [`StoreError::Integrity`] when the file is corrupt, not a database, or violates foreign keys.
    pub async fn open_with(
        cfg: &DbConfig,
        check: StartupCheck,
        progress: &(dyn Fn(OpenEvent) + Send + Sync),
    ) -> Result<Self, StoreError> {
        let migrator = sqlx::migrate!("../../migrations/v3-sqlite");
        Self::open_migrating(cfg, check, progress, &migrator).await
    }

    /// Test-only: [`SqliteDb::open`] as an older release ran it, with only the compiled-in migrations up to and
    /// including `last` (the 3.1 -> 3.2 upgrade-path test builds a 3.1-shaped library this way; the migration files
    /// of a released version are never edited, which `upgrade_tests` pins by checksum).
    #[cfg(test)]
    pub(crate) async fn open_at_version(cfg: &DbConfig, last: i64) -> Result<Self, StoreError> {
        let all = sqlx::migrate!("../../migrations/v3-sqlite");
        let migrator = Migrator {
            migrations: Cow::Owned(
                all.migrations
                    .iter()
                    .filter(|m| m.version <= last)
                    .cloned()
                    .collect(),
            ),
            ..Migrator::DEFAULT
        };
        Self::open_migrating(cfg, StartupCheck::Fast, &|_| {}, &migrator).await
    }

    /// [`SqliteDb::open_with`] with an explicit migration set.
    async fn open_migrating(
        cfg: &DbConfig,
        check: StartupCheck,
        progress: &(dyn Fn(OpenEvent) + Send + Sync),
        migrator: &Migrator,
    ) -> Result<Self, StoreError> {
        // SEC-102 refusals first: nothing reads a file that is a symbolic link or belongs to someone else.
        check_db_files(&cfg.path, Some(process_uid()), None)?;
        // Fresh start (D37): a database written by 2.x (or anything else that is not a 3.x SQLite library) is refused
        // before anything is created, migrated or written, and before the 0600 fix-up below: it is never modified,
        // not even its mode (review 35 L3).
        refuse_legacy(&cfg.path).await?;
        // SEC-102 fix-up of a 3.x library copied without `chmod`.
        check_db_files(&cfg.path, Some(process_uid()), Some(progress))?;
        // Create the file 0600 *before* SQLite does: SQLite gives `-wal` and `-shm` the mode of the
        // main file, so they never exist world-readable (T061 L-2).
        precreate_private(&cfg.path)?;
        let writer = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options(&cfg.path, false))
            .await
            .map_err(open_err)?;

        // Cheap and read-only; also rejects a file that is not a database before anything else.
        let pending = pending_migrations(&writer, migrator).await?;
        let mode = if pending.is_empty() {
            check
        } else {
            StartupCheck::Full
        };
        progress(OpenEvent::CheckStarted {
            mode,
            escalated: mode != check,
        });
        let started = Instant::now();
        run_check(&writer, mode).await?;
        progress(OpenEvent::CheckFinished {
            mode,
            secs: started.elapsed().as_secs_f64(),
        });
        apply_migrations(&writer, migrator, &pending, progress).await?;
        seed_categories(&writer).await?;
        restrict_permissions(&cfg.path)?;

        // Readers open only after the writer created the file and enabled WAL.
        let readers = reader_pool(options(&cfg.path, true), READER_STATEMENT_DEADLINE).await?;
        // Databases created by an older release may have world-readable sidecars; fix them too.
        restrict_permissions(&cfg.path)?;
        let db = Self {
            writer,
            readers,
            epoch: Arc::new(AtomicU64::new(0)),
        };
        Ok(db)
    }

    /// Opens an existing database strictly read-only: no creation, no integrity pass, no
    /// migration, no seeding, no permission change. Both pools use read-only file handles, so
    /// any write attempt fails with `SQLITE_READONLY`. For diagnostics (`nzbd health`) that must
    /// not alter the data they inspect.
    ///
    /// # Errors
    /// The file is missing or cannot be opened; [`StoreError::Integrity`] when SQLite reports it
    /// is not a database or is malformed (so `nzbd db check` can say "damaged");
    /// [`StoreError::Refused`] (`LEGACY_DATABASE`) for a 2.x or foreign database.
    pub async fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        // SEC-102 without the mode fix (a read-only open changes nothing).
        check_db_files(path, Some(process_uid()), None)?;
        // A 2.x (or foreign) database gets the same `LEGACY_DATABASE` answer as a read-write open, not a missing-table
        // error from whatever the caller reads first, and through the same probe that leaves no sidecar behind.
        if path.is_file() {
            refuse_legacy(path).await?;
        }
        let writer = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options_read_only(path))
            .await
            .map_err(open_err)?;
        let readers = reader_pool(options_read_only(path), READER_STATEMENT_DEADLINE)
            .await
            .map_err(open_err)?;
        Ok(Self {
            writer,
            readers,
            epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The single-connection writer pool. All writes go through it (each multi-row write in one tx).
    #[must_use]
    pub fn writer(&self) -> &SqlitePool {
        &self.writer
    }

    /// Change counter of the `release` table, for caches of derived numbers (library totals).
    ///
    /// It is bumped (after the commit) by every release insert, delete, trash and category
    /// change made through this process's [`SqliteDb`] handles. A cache stores the value it read
    /// *before* computing and is valid only while the counter is unchanged; a change that lands
    /// during the computation therefore invalidates the entry. Writes by another process (CLI
    /// restore) are not seen, so callers keep a time bound as well.
    #[must_use]
    pub fn release_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Marks the `release` table as changed (call after the commit).
    pub(crate) fn bump_release_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Starts a `BEGIN IMMEDIATE` transaction on the writer: the write lock is taken up front, so a
    /// read-check-write sequence (last-admin rule, single-use codes, throttle counters) can never be
    /// interleaved by another process (the `nzbd` CLI) and never fails late with `SQLITE_BUSY` on
    /// the lock upgrade. Within this process the single writer connection already serialises.
    ///
    /// # Errors
    /// Database failure (busy timeout, I/O).
    pub(crate) async fn begin_immediate(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, StoreError> {
        Ok(self.writer.begin_with("BEGIN IMMEDIATE").await?)
    }

    /// The read-only pool.
    #[must_use]
    pub fn readers(&self) -> &SqlitePool {
        &self.readers
    }

    /// Run `PRAGMA integrity_check` and `PRAGMA foreign_key_check` on the writer.
    ///
    /// # Errors
    /// [`StoreError::Integrity`] on any reported problem.
    pub async fn integrity_check(&self) -> Result<(), StoreError> {
        run_check(&self.writer, StartupCheck::Full).await
    }

    /// Run the check of `mode` on the writer connection (read-only work). Backs
    /// `nzbd db check [--full]`.
    ///
    /// # Errors
    /// [`StoreError::Integrity`] on any reported problem.
    pub async fn check(&self, mode: StartupCheck) -> Result<(), StoreError> {
        run_check(&self.writer, mode).await
    }

    /// Close both pools (checkpoints the WAL when the last connection closes).
    pub async fn close(&self) {
        self.readers.close().await;
        self.writer.close().await;
    }
}

/// The reader pool: every connection gets the statement deadline through sqlx's safe progress-handler API.
pub(crate) async fn reader_pool(
    options: SqliteConnectOptions,
    deadline: Duration,
) -> Result<SqlitePool, sqlx::Error> {
    SqlitePoolOptions::new()
        .max_connections(READER_CONNECTIONS)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                let mut h = conn.lock_handle().await?;
                let mut start = Instant::now();
                let mut last = start;
                h.set_progress_handler(READER_PROGRESS_OPS, move || {
                    let now = Instant::now();
                    if now.saturating_duration_since(last) > READER_BURST_GAP {
                        start = now;
                    }
                    last = now;
                    // false interrupts the running statement.
                    now.saturating_duration_since(start) < deadline
                });
                Ok(())
            })
        })
        .connect_with(options)
        .await
}

/// Read-only options that never try to change the journal mode of an existing file: a freshly
/// copied backup is in rollback-journal mode, and the `journal_mode=WAL` pragma that every normal
/// connection sets would need a write (`attempt to write a readonly database`). The mode is read
/// from the SQLite header (bytes 18 and 19 are 2 for WAL); anything else, or a missing file, gets
/// the default behaviour.
fn options_read_only(path: &Path) -> SqliteConnectOptions {
    use std::io::Read as _;
    let mut head = [0_u8; 20];
    let is_wal = std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| head.get(18..20) == Some(&[2, 2][..]));
    let o = options(path, true);
    if is_wal || !path.is_file() {
        o
    } else {
        o.journal_mode(SqliteJournalMode::Delete)
    }
}

fn options(path: &Path, read_only: bool) -> SqliteConnectOptions {
    // Built from a path (not a URL string) so unusual characters in the path cannot alter options.
    SqliteConnectOptions::new()
        .filename(path)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        // D36 (c): always FULL, no knob. In WAL mode `NORMAL` can lose the last commits on power loss, which would
        // silently undo revocations an admin saw succeed; the ingest ordering needs a durable commit before a source
        // file is removed (review 34 I4, O3).
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(BUSY_TIMEOUT)
        // Sorter and temp b-tree spill stay in memory instead of files in /tmp. The production container's
        // /tmp is a 16 MiB tmpfs; building the migration 0010 indexes needs ~62 MiB of sorter space at 1 M
        // releases and failed with SQLITE_FULL there (T087-H1). Applied to every connection: a reader's
        // seek+sort of a rare term's matches (bounded by the planner's cost model) would otherwise be the
        // next thing to hit the same 16 MiB wall, and memory is bounded by the 512 MiB container limit.
        .pragma("temp_store", "MEMORY")
        // 0011 (SEC-062, L3a): `user_no_row_delete` must also fire when a conflict resolution (INSERT OR REPLACE)
        // would delete a row; without this pragma SQLite skips delete triggers for REPLACE.
        .pragma("recursive_triggers", "ON")
        .create_if_missing(!read_only)
        .read_only(read_only)
}

fn integrity_err(e: &sqlx::Error) -> StoreError {
    StoreError::Integrity(e.to_string())
}

/// `SQLITE_CORRUPT` (11) and `SQLITE_NOTADB` (26), primary codes, become [`StoreError::Integrity`];
/// everything else (`BUSY`, `IOERR`, `FULL`, pool/IO errors) stays a plain database error, so a
/// transient failure is "could not run" (exit 1 in `nzbd db check`), never "damaged" (T090-L4).
pub(crate) fn open_err(e: sqlx::Error) -> StoreError {
    let damaged = match &e {
        sqlx::Error::Database(d) => d
            .code()
            .and_then(|c| c.parse::<i64>().ok())
            .is_some_and(|c| matches!(c & 0xFF, 11 | 26)),
        _ => false,
    };
    if damaged {
        integrity_err(&e)
    } else {
        StoreError::Db(e)
    }
}

async fn run_check(pool: &SqlitePool, mode: StartupCheck) -> Result<(), StoreError> {
    match mode {
        StartupCheck::Fast => fast_check(pool).await,
        StartupCheck::Quick => quick_check(pool).await,
        StartupCheck::Full => full_check(pool).await,
    }
}

/// Refuses (`LEGACY_DATABASE`) an existing, non-empty database file that is not a 3.x SQLite library: it has tables
/// but no `db_state` row naming the `sqlite` backend (a 2.x `nzbd.sqlite`, another program's file). Probed on a
/// read-only connection that never changes the journal mode, so the file is not modified. A missing or empty file
/// (no tables yet) is a new library.
async fn refuse_legacy(path: &Path) -> Result<(), StoreError> {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 => {}
        _ => return Ok(()),
    }
    // Without a `-wal` file the main file is complete and an `immutable` open reads it without creating `-wal`/`-shm`
    // next to it (review 35 L3: a plain read-only open of a WAL-mode file leaves both behind). With a `-wal` (an
    // unclean stop, or a running 3.x server) the WAL must be read, so the normal read-only open is used; the sidecars
    // exist already then.
    let wal = db_files(path).get(1).is_some_and(|w| w.exists());
    let options = if wal {
        options_read_only(path)
    } else {
        options_read_only(path).immutable(true)
    };
    let probe = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(open_err)?;
    let verdict = legacy_verdict(&probe).await;
    probe.close().await;
    verdict
}

async fn legacy_verdict(pool: &SqlitePool) -> Result<(), StoreError> {
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table'")
        .fetch_one(pool)
        .await
        .map_err(open_err)?;
    if tables == 0 {
        return Ok(());
    }
    let has_state: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'db_state'",
    )
    .fetch_one(pool)
    .await
    .map_err(open_err)?;
    let backend: Option<String> = if has_state == 0 {
        None
    } else {
        sqlx::query_scalar("SELECT backend FROM db_state WHERE id = 1")
            .fetch_optional(pool)
            .await
            .map_err(open_err)?
    };
    if backend.as_deref() == Some("sqlite") {
        Ok(())
    } else {
        Err(StoreError::Refused("LEGACY_DATABASE"))
    }
}

/// Versions and descriptions of the compiled-in migrations the database has not applied yet.
/// Reads `sqlite_master` first, so a file that is not a database fails here.
async fn pending_migrations(
    pool: &SqlitePool,
    migrator: &Migrator,
) -> Result<Vec<(i64, String)>, StoreError> {
    let has_ledger: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await
    .map_err(open_err)?;
    let applied: Vec<i64> = if has_ledger > 0 {
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
            .fetch_all(pool)
            .await
            .map_err(open_err)?
    } else {
        Vec::new()
    };
    // A ledger entry this binary does not know = a database written by a newer release.
    if let Some(v) = applied
        .iter()
        .find(|v| !migrator.iter().any(|m| m.version == **v))
    {
        return Err(StoreError::Migrate(
            sqlx::migrate::MigrateError::VersionMissing(*v),
        ));
    }
    Ok(migrator
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !applied.contains(&m.version))
        .map(|m| (m.version, m.description.to_string()))
        .collect())
}

/// Applies `pending` one migration at a time, reporting progress. Running the migrator over the
/// migrations up to version `v` applies exactly the pending ones among them and re-validates the
/// checksums of the applied ones, so the semantics equal one `Migrator::run` over everything.
async fn apply_migrations(
    pool: &SqlitePool,
    migrator: &Migrator,
    pending: &[(i64, String)],
    progress: &(dyn Fn(OpenEvent) + Send + Sync),
) -> Result<(), StoreError> {
    let (Some((first, _)), Some((last, _))) = (pending.first(), pending.last()) else {
        // Nothing to apply; the run still validates checksums / dirty state of the ledger.
        migrator.run(pool).await?;
        return Ok(());
    };
    progress(OpenEvent::MigrationsPending {
        total: pending.len(),
        first: *first,
        last: *last,
    });
    for (n, (version, description)) in pending.iter().enumerate() {
        progress(OpenEvent::MigrationStarted {
            version: *version,
            description: description.clone(),
            index: n.saturating_add(1),
            total: pending.len(),
        });
        let upto = Migrator {
            migrations: Cow::Owned(
                migrator
                    .migrations
                    .iter()
                    .filter(|m| m.version <= *version)
                    .cloned()
                    .collect(),
            ),
            // Entries above `version` are applied-or-pending later; unknown ones were rejected
            // in `pending_migrations`. Without this a ledger with a hole (a lower version still
            // pending under a higher applied one) would report the higher one as missing.
            ignore_missing: true,
            ..Migrator::DEFAULT
        };
        let started = Instant::now();
        let mut run = Box::pin(upto.run(pool));
        loop {
            match tokio::time::timeout(PROGRESS_EVERY, run.as_mut()).await {
                Ok(r) => break r?,
                Err(_) => progress(OpenEvent::MigrationRunning {
                    version: *version,
                    elapsed_secs: started.elapsed().as_secs(),
                }),
            }
        }
        progress(OpenEvent::MigrationFinished {
            version: *version,
            secs: started.elapsed().as_secs_f64(),
        });
    }
    // Everything is applied now: one validation of the whole ledger (checksums, dirty flags)
    // exactly as a plain `Migrator::run` would have done. A no-op otherwise.
    migrator.run(pool).await?;
    Ok(())
}

/// Bounded check (see [`StartupCheck::Fast`]).
async fn fast_check(pool: &SqlitePool) -> Result<(), StoreError> {
    // Parses the schema (page 1 and the schema b-tree only; other roots are not touched). The
    // coverage that matters is the per-table `quick_check` below: an unknown (renamed) table
    // errors with "no such table", so the check fails closed.
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master")
        .fetch_one(pool)
        .await
        .map_err(open_err)?;
    for table in CRITICAL_TABLES {
        // The table-valued form takes the table name as a bound argument (the names are the constants above).
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT quick_check FROM pragma_quick_check(?1)")
                .bind(table)
                .fetch_all(pool)
                .await
                .map_err(open_err)?;
        expect_ok(rows)?;
    }
    Ok(())
}

async fn quick_check(pool: &SqlitePool) -> Result<(), StoreError> {
    let rows: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_all(pool)
        .await
        .map_err(open_err)?;
    expect_ok(rows)
}

fn expect_ok(rows: Vec<String>) -> Result<(), StoreError> {
    if rows.len() != 1 || rows.first().map(String::as_str) != Some("ok") {
        let first = rows.into_iter().take(5).collect::<Vec<_>>().join("; ");
        return Err(StoreError::Integrity(first));
    }
    Ok(())
}

async fn full_check(pool: &SqlitePool) -> Result<(), StoreError> {
    let rows: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(pool)
        .await
        .map_err(open_err)?;
    expect_ok(rows)?;
    // One row per violation; the first column is the child table name.
    let violations: Vec<String> =
        sqlx::query_scalar("SELECT \"table\" FROM pragma_foreign_key_check")
            .fetch_all(pool)
            .await
            .map_err(open_err)?;
    if !violations.is_empty() {
        return Err(StoreError::Integrity(format!(
            "{} foreign key violation(s), first in table {}",
            violations.len(),
            violations.first().map_or("?", String::as_str)
        )));
    }
    Ok(())
}

/// Upsert the taxonomy in one transaction (idempotent; keeps ids stable across restarts).
async fn seed_categories(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;
    for (id, parent, name) in &seed_rows()? {
        sqlx::query(
            "INSERT INTO category (id, parent_id, name) VALUES (?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET parent_id = excluded.parent_id, name = excluded.name",
        )
        .bind(id)
        .bind(parent)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    }
    // A totals row for every category (`category_stats`, maintained by the release triggers).
    sqlx::query(
        "INSERT INTO category_stats (category_id) SELECT id FROM category WHERE true \
         ON CONFLICT(category_id) DO NOTHING",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The database file and its WAL/shared-memory sidecars (same rows, same secrets as the main file).
fn db_files(path: &Path) -> [PathBuf; 3] {
    let with = |suffix: &str| {
        let mut o = path.as_os_str().to_owned();
        o.push(suffix);
        PathBuf::from(o)
    };
    [path.to_path_buf(), with("-wal"), with("-shm")]
}

/// The effective uid of this process. Not the owner of `/proc/self`: nzbd makes itself non-dumpable
/// (review 44 M1), and `/proc/self` of a non-dumpable process belongs to root.
fn process_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// SEC-102 (review 34 I3): the checks on `paths.db` and its sidecars before SQLite opens them. Refused with
/// `DB_FILE_MODE`: a database directory writable by group/other (anyone could swap the file), a symbolic link or a
/// non-regular file, a file owned by another uid than `uid` (skipped when `uid` is root or unknown). A file of the
/// service uid with group/other bits is set to 0600 and reported through `progress` (the read-only open passes
/// `None`: it changes nothing and only refuses what it must). A missing file is fine (created 0600 by the open).
pub(crate) fn check_db_files(
    path: &Path,
    uid: Option<u32>,
    progress: Option<&(dyn Fn(OpenEvent) + Send + Sync)>,
) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if let Ok(d) = std::fs::metadata(dir)
            && d.permissions().mode() & 0o022 != 0
        {
            return Err(StoreError::Refused(
                "DB_FILE_MODE: the database directory is writable by group or other",
            ));
        }
        let owner_checked = uid.filter(|u| *u != 0);
        for (f, suffix) in db_files(path).iter().zip(["", "-wal", "-shm"]) {
            let m = match std::fs::symlink_metadata(f) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            if m.file_type().is_symlink() {
                return Err(StoreError::Refused(
                    "DB_FILE_MODE: the database file (or its -wal/-shm) is a symbolic link",
                ));
            }
            if !m.is_file() {
                return Err(StoreError::Refused(
                    "DB_FILE_MODE: the database file (or its -wal/-shm) is not a regular file",
                ));
            }
            // A second name (hard link) of the database outside its directory would keep a readable copy of every
            // change wherever it lives (review 35 I2; SEC-051 refuses the same for purges).
            if m.nlink() > 1 {
                return Err(StoreError::Refused(
                    "DB_FILE_MODE: the database file (or its -wal/-shm) has more than one name (hard link)",
                ));
            }
            if owner_checked.is_some_and(|u| u != m.uid()) {
                return Err(StoreError::Refused(
                    "DB_FILE_MODE: the database file (or its -wal/-shm) is not owned by the service uid",
                ));
            }
            let mode = m.permissions().mode() & 0o777;
            if mode & 0o077 != 0
                && let Some(report) = progress
            {
                std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600))?;
                report(OpenEvent::FileModeFixed { suffix, mode });
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, uid, progress);
    Ok(())
}

#[cfg(unix)]
fn precreate_private(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        // Already there (the normal case after the first start): permissions are fixed after open.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(unix))]
fn precreate_private(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    for (i, f) in db_files(path).iter().enumerate() {
        match std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            // The sidecars only exist while a connection is open in WAL mode.
            Err(e) if i > 0 && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod backup_deadline_regressions {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // Exercise the real progress handler with a zero budget. This is not a timing claim about
    // the production 30-second value; every query/backup below uses real SQLite statements.
    async fn deadline_db(rollback_read_only: bool) -> (tempfile::TempDir, SqliteDb) {
        let dir = tempfile::tempdir().unwrap();
        // A filename, not a URL: cloning options must preserve spaces and the literal '#'.
        let path = dir.path().join("library #1.sqlite");
        let mut db = SqliteDb::open(&DbConfig { path: path.clone() })
            .await
            .unwrap();
        sqlx::query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 20000) \
             INSERT INTO ingest_log (ts, source, outcome) SELECT 1700000000+x, 'watch', 'ok' FROM n",
        )
        .execute(db.writer())
        .await
        .unwrap();
        if rollback_read_only {
            db.readers().close().await;
            let mode: String = sqlx::query_scalar("PRAGMA journal_mode = DELETE")
                .fetch_one(db.writer())
                .await
                .unwrap();
            assert_eq!(mode, "delete");
            db.close().await;
            db = SqliteDb::open_read_only(&path).await.unwrap();
        }
        let bounded = reader_pool(
            db.readers().connect_options().as_ref().clone(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let previous = std::mem::replace(&mut db.readers, bounded);
        previous.close().await;
        (dir, db)
    }

    async fn assert_request_deadline(db: &SqliteDb) {
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            sqlx::query_scalar::<_, i64>("SELECT sum(ts) FROM ingest_log").fetch_one(db.readers()),
        )
        .await
        .expect("ordinary reader query remains bounded")
        .unwrap_err();
        assert!(
            matches!(&error, sqlx::Error::Database(e) if e.code().as_deref() == Some("9")),
            "ordinary reads must still receive SQLITE_INTERRUPT: {error:?}"
        );
    }

    async fn assert_backup(key: Option<&crate::BackupKey>, rollback_read_only: bool) {
        let (dir, db) = deadline_db(rollback_read_only).await;
        assert_request_deadline(&db).await;
        let backups = dir.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            db.backup_with(&backups, 1_700_000_000, 2, key),
        )
        .await
        .expect("diagnostic snapshot finishes");
        assert!(
            result.is_ok(),
            "online backup must not inherit the request reader deadline: {result:?}"
        );
        let snapshot = result.unwrap();
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), 1);
        assert_request_deadline(&db).await;
        assert!(
            !db.readers().is_closed(),
            "backup must not close request readers"
        );

        let restored = if let Some(key) = key {
            assert!(crate::looks_encrypted(&snapshot.path));
            let path = dir.path().join("decrypted.sqlite");
            crate::decrypt_file(key, &snapshot.path, &path).unwrap();
            path
        } else {
            assert!(!crate::looks_encrypted(&snapshot.path));
            snapshot.path
        };
        let control = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(restored)
                    .read_only(true),
            )
            .await
            .unwrap();
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&control)
            .await
            .unwrap();
        assert_eq!(integrity, "ok");
        let copied: (i64, i64, i64) =
            sqlx::query_as("SELECT count(*), min(ts), max(ts) FROM ingest_log")
                .fetch_one(&control)
                .await
                .unwrap();
        assert_eq!(copied, (20_000, 1_700_000_001, 1_700_020_000));
        let pending: i64 = sqlx::query_scalar("SELECT restore_pending FROM db_state WHERE id = 1")
            .fetch_one(&control)
            .await
            .unwrap();
        assert_eq!(pending, 1);
        let original: (i64, i64, i64) =
            sqlx::query_as("SELECT count(*), min(ts), max(ts) FROM ingest_log")
                .fetch_one(db.writer())
                .await
                .unwrap();
        assert_eq!(original, copied, "backup leaves source data intact");
        control.close().await;
        db.close().await;
        let closed = db
            .backup_with(&backups, 1_700_000_001, 2, key)
            .await
            .unwrap_err();
        assert!(matches!(closed, StoreError::Db(sqlx::Error::PoolClosed)));
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn plain_backup_does_not_inherit_request_reader_deadline() {
        assert_backup(None, false).await;
    }

    #[tokio::test]
    async fn encrypted_backup_does_not_inherit_request_reader_deadline() {
        let key = crate::BackupKey::from_slice(&[11; 32]).unwrap();
        assert_backup(Some(&key), true).await;
    }
}
