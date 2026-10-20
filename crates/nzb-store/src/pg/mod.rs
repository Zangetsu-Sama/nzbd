//! v3 store on PostgreSQL (T112, D33; `docs/v3/ARCHITECTURE.md`, `DATA_MODEL.md`, `SECURITY_DELTA.md`).
//!
//! While the port is in progress the 2.x SQLite store (`crate::SqliteDb`) stays compiled and keeps serving the 2.x binary;
//! everything in this module is the v3 implementation and is exercised by tests against a real Postgres
//! (`scripts/dev` starts an ephemeral, digest-pinned server with no network). Repositories keep the 2.x names and
//! semantics on [`PgDb`]; differences are listed in `DATA_MODEL` v3 section 7.
//!
//! Rules that hold for every statement here (SEC-088): static SQL text with `$n` placeholders only, multi-row data bound
//! as arrays, every multi-row write in one transaction, the global lock order of ARCHITECTURE v3 section 6 (account
//! domain advisory lock, then release rows in ascending id order, then `category_stats` rows, then the audit chain
//! state as the last lock before `COMMIT`).

mod account;
mod anchor;
mod apikey;
mod audit;
mod auth;
mod backup;
mod bulk;
pub mod config;
mod health;
mod ingest_log;
mod invite;
mod maintenance;
mod mfa;
mod nfo;
mod pref;
mod release;
mod restore_finish;
mod saved_search;
mod schema;
mod search_source;
#[cfg(any(test, feature = "pg-test-support"))]
pub mod testing;
mod throttle;
mod totp_rotate;
mod user;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// Connection options (opaque to `nzbd`: built by [`connect_options`] for the owner role, passed back to the store).
pub use sqlx::postgres::PgConnectOptions;
use sqlx::postgres::{PgPool, PgPoolOptions, PgSslMode};

pub use crate::anchor::{AnchorVerdict, DbAnchor, read_anchor, write_anchor};
pub use backup::{RestoreOptions, RestoreReport, SnapshotReport, restore_snapshot, snapshot_name};
pub use config::{PgConfigError, PgHost, PgSettings, RawPgSettings};
pub use maintenance::{RETENTION_FLOORS, RetentionPolicy, set_retention_policy};
pub use release::{DEGRADED_SCAN_BUDGET, DegradedPage};
pub use schema::{
    MIGRATOR, MIN_SERVER_VERSION_NUM, Readiness, app_sessions_as_owner, migrate_as_owner,
    pending_as_owner, pending_migrations,
};

use crate::StoreError;

/// Advisory lock namespace (`'nzbd'` as a 32-bit integer), first half of every two-integer advisory key. Pinned to
/// `nzbd.lock_namespace()` in the schema by a test.
pub const LOCK_NAMESPACE: i32 = 0x6E7A_6264;
/// Advisory key: account-domain mutations (ARCHITECTURE v3 section 6, lock 1). Pinned to `nzbd.account_domain_key()`.
pub const LOCK_ACCOUNT_DOMAIN: i32 = 1;
/// Advisory key: the single search indexer (session lock on an unpooled connection, T113).
pub const LOCK_INDEXER: i32 = 2;
/// Advisory key: `nzbd migrate --from-sqlite` (T115).
pub const LOCK_MIGRATE: i32 = 3;
/// Advisory key: partition upkeep (taken inside the definer functions).
pub const LOCK_PARTITIONS: i32 = 4;

/// Width of one `nzb_file` partition in release ids (`DATA_MODEL` v3 section 2).
pub const FILE_PARTITION_SPAN: i64 = 10_000_000;

/// `statement_timeout` of the `ingest` pool.
const INGEST_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// `statement_timeout` of the `background` pool (backup, rebuild and long purges set their own per transaction).
const BACKGROUND_STATEMENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Which pool a connection belongs to (fixed `application_name`, fixed metric label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKind {
    /// HTTP handlers.
    Web,
    /// Commit-group writers and ingest bookkeeping.
    Ingest,
    /// Indexer reads, maintenance, health, backup.
    Background,
}

impl PoolKind {
    /// `application_name` of the pool's connections (a constant, never input, review L1).
    #[must_use]
    pub const fn application_name(self) -> &'static str {
        match self {
            Self::Web => "nzbd-web",
            Self::Ingest => "nzbd-ingest",
            Self::Background => "nzbd-background",
        }
    }
}

/// Connection options built field by field (never a URL; `SECURITY_DELTA` 2.1): `new_without_pgpass`, every field set
/// explicitly, TLS disabled (no TLS stack is linked in 3.0), per-connection session settings of ARCHITECTURE v3
/// section 4. The password is copied into the options (sqlx keeps it as a plain `String`; nzbd never formats or logs
/// the options: [`PgDb`] has a redacting `Debug`).
#[must_use]
pub fn connect_options(
    s: &PgSettings,
    user: &str,
    password: &str,
    pool: PoolKind,
    statement_timeout: Duration,
) -> PgConnectOptions {
    let o = PgConnectOptions::new_without_pgpass();
    let o = match &s.host {
        PgHost::Socket(dir) => o.socket(dir),
        PgHost::Ip(ip) => o.host(&ip.to_string()),
    };
    // No TLS mode in 3.0 (D35 d, owner answer Q10; review M5). Changing it needs an owner decision extending D33 (d), a `tls-*` sqlx feature and a verifier that trusts only the
    // configured CA (`sec_086_tls_trusts_only_the_configured_ca`).
    o.port(s.port)
        .username(user)
        .password(password)
        .database(&s.name)
        .ssl_mode(PgSslMode::Disable)
        .application_name(pool.application_name())
        .statement_cache_capacity(256)
        .options(session_settings(statement_timeout))
}

/// Startup parameters sent with every connection (`-c name=value`): timeouts, search path, UTC, no JIT.
fn session_settings(statement_timeout: Duration) -> [(&'static str, String); 7] {
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX).to_string();
    [
        ("statement_timeout", ms(statement_timeout)),
        ("lock_timeout", "5000".to_owned()),
        ("idle_in_transaction_session_timeout", "60000".to_owned()),
        ("search_path", "nzbd,pg_temp".to_owned()),
        ("timezone", "UTC".to_owned()),
        ("jit", "off".to_owned()),
        ("client_encoding", "UTF8".to_owned()),
    ]
}

/// The v3 database handle: three pools (ARCHITECTURE v3 section 4). Cheap to clone.
#[derive(Clone)]
pub struct PgDb {
    web: PgPool,
    ingest: PgPool,
    background: PgPool,
    /// Exclusive upper bound of the release ids covered by `nzb_file` partitions (cached; 0 = unknown).
    file_partition_upper: Arc<AtomicI64>,
    /// Highest release id this process inserted (decides when partitions are made ahead).
    last_release_id: Arc<AtomicI64>,
}

impl fmt::Debug for PgDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the connect options (they hold the password).
        f.debug_struct("PgDb")
            .field("web", &self.web.size())
            .field("ingest", &self.ingest.size())
            .field("background", &self.background.size())
            .finish_non_exhaustive()
    }
}

impl PgDb {
    /// Connects the three pools with the app role. Does NOT migrate (review M4: `serve` never migrates); call
    /// [`PgDb::readiness`] before serving.
    ///
    /// # Errors
    /// Connection failure (the first connection of each pool is opened eagerly so a bad password or socket fails here).
    pub async fn connect(s: &PgSettings, password: &str) -> Result<Self, StoreError> {
        let pool = |kind: PoolKind, size: u32, timeout: Duration| {
            PgPoolOptions::new()
                .max_connections(size)
                .min_connections(0)
                .acquire_timeout(s.acquire_timeout)
                .test_before_acquire(true)
                .connect_with(connect_options(s, &s.user, password, kind, timeout))
        };
        let web = pool(PoolKind::Web, s.pool_web, s.statement_timeout).await?;
        let ingest = pool(PoolKind::Ingest, s.pool_ingest, INGEST_STATEMENT_TIMEOUT).await?;
        let background = pool(
            PoolKind::Background,
            s.pool_background,
            BACKGROUND_STATEMENT_TIMEOUT,
        )
        .await?;
        Ok(Self::from_pools(web, ingest, background))
    }

    /// Wraps existing pools (tests, CLI tools that need a single small pool for everything).
    #[must_use]
    pub fn from_pools(web: PgPool, ingest: PgPool, background: PgPool) -> Self {
        Self {
            web,
            ingest,
            background,
            file_partition_upper: Arc::new(AtomicI64::new(0)),
            last_release_id: Arc::new(AtomicI64::new(0)),
        }
    }

    /// The `web` pool (HTTP handlers).
    #[must_use]
    pub fn web(&self) -> &PgPool {
        &self.web
    }

    /// The `ingest` pool (commit groups).
    #[must_use]
    pub fn ingest(&self) -> &PgPool {
        &self.ingest
    }

    /// The `background` pool (maintenance, health, backup, indexer reads).
    #[must_use]
    pub fn background(&self) -> &PgPool {
        &self.background
    }

    /// Closes every pool.
    pub async fn close(&self) {
        self.web.close().await;
        self.ingest.close().await;
        self.background.close().await;
    }

    /// Begins a transaction on the `web` pool holding the account-domain advisory lock (lock 1 of the global order):
    /// the Postgres equivalent of the 2.x `BEGIN IMMEDIATE` single writer for every account-domain rule (last admin,
    /// caps, single use, name uniqueness, session cap, throttle verdicts).
    ///
    /// # Errors
    /// Database errors (pool timeout, lock timeout).
    pub(crate) async fn begin_account(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, StoreError> {
        let mut tx = self.web.begin().await?;
        lock_account_domain(&mut tx).await?;
        Ok(tx)
    }

    /// Exclusive upper bound of the release ids known to be covered by `nzb_file` partitions (0 = not checked yet in
    /// this process).
    pub(crate) fn partition_upper(&self) -> i64 {
        self.file_partition_upper.load(Ordering::Acquire)
    }

    /// Highest release id this process inserted.
    pub(crate) fn last_release_id(&self) -> i64 {
        self.last_release_id.load(Ordering::Acquire)
    }

    /// Records an inserted release id.
    pub(crate) fn note_release_id(&self, id: i64) {
        self.last_release_id.fetch_max(id, Ordering::AcqRel);
    }

    /// Records that partitions cover ids below `upper` (after the creating transaction committed).
    pub(crate) fn note_partitions_upto(&self, upper: i64) {
        self.file_partition_upper.fetch_max(upper, Ordering::AcqRel);
    }
}

/// Test access to the restore with fault injection.
#[cfg(test)]
pub(crate) use backup::restore_inner as restore_inner_for_tests;

/// Test access to the private audit append (one row on `conn`, in its transaction).
#[cfg(test)]
pub(crate) use audit::append as audit_append_for_tests;

/// Takes the account-domain advisory lock for the rest of the transaction (lock 1 of the global order).
///
/// # Errors
/// Database errors (lock timeout).
pub(crate) async fn lock_account_domain(conn: &mut sqlx::PgConnection) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(LOCK_NAMESPACE)
        .bind(LOCK_ACCOUNT_DOMAIN)
        .execute(conn)
        .await?;
    Ok(())
}
