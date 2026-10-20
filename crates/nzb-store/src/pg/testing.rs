//! Test harness: one private database per test, copied from a migrated template (ARCHITECTURE v3 section 11).
//!
//! The server is the ephemeral Postgres that `scripts/dev` starts next to the dev container (service `pg` of
//! `compose.dev.yaml`): no network at all, reached through its Unix socket only, data on a tmpfs, removed after the
//! run. Connection details come from `NZBD_TEST_PG_*` variables set by `compose.dev.yaml` (never `PG*`, which nzbd
//! refuses, SEC-086).
//!
//! The template `nzbd_tpl_<hash>` is built once per migration set (the hash covers every migration checksum, the
//! superuser bootstrap and the taxonomy), under a cluster-wide advisory lock so parallel test binaries never race. Each
//! test then gets `CREATE DATABASE ... TEMPLATE` (milliseconds), the database-level part of the superuser bootstrap
//! ([`DB_PRIVILEGES_SQL`]: privileges on the database object are not copied from a template), and a [`PgDb`] connected as `nzbd_app` with small pools. The database
//! is dropped when the [`TestDb`] is dropped.
//! `AssertSqlSafe` is limited to harness DDL containing generated checksum/PID/counter identifiers or numeric clocks.
#![allow(clippy::missing_panics_doc, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{ConnectOptions as _, Connection as _, PgConnection};

use super::{MIGRATOR, PgDb, PgHost, PgSettings, PoolKind, connect_options, migrate_as_owner};

/// Superuser bootstrap (roles, database and schema privileges).
pub const ROLES_SQL: &str = include_str!("../../../../migrations/v3/superuser/0001_roles.sql");
/// The database-level part of [`ROLES_SQL`] (privileges on the database object are not copied by
/// `CREATE DATABASE ... TEMPLATE`). Run on every per-test database; the cluster-level role statements are not re-run
/// there, because parallel `ALTER ROLE` on the same role fails with "tuple concurrently updated".
pub const DB_PRIVILEGES_SQL: &str = "DO $db$ BEGIN \
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()); \
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO nzbd_owner, nzbd_app', current_database()); \
    END $db$;";
/// Password of `nzbd_app` in the test cluster (throwaway; the server lives for one run).
pub const TEST_APP_PASSWORD: &str = "nzbd-test-app";
/// Password of `nzbd_owner` in the test cluster.
pub const TEST_OWNER_PASSWORD: &str = "nzbd-test-owner";

static COUNTER: AtomicU64 = AtomicU64::new(0);
static TEMPLATE: OnceLock<String> = OnceLock::new();

/// Where the test server is (from `NZBD_TEST_PG_*`).
#[derive(Clone, Debug)]
pub struct Server {
    socket: PathBuf,
    port: u16,
    superuser: String,
    password: String,
}

impl Server {
    /// Reads `NZBD_TEST_PG_SOCKET`, `NZBD_TEST_PG_PORT`, `NZBD_TEST_PG_SUPERUSER`, `NZBD_TEST_PG_PASSWORD`.
    ///
    /// # Panics
    /// When the variables are missing: the tests must run through `scripts/dev` (which starts the server).
    #[must_use]
    pub fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| {
                panic!("{k} is not set: run the tests through scripts/dev, which starts the test Postgres")
            })
        };
        Self {
            socket: PathBuf::from(var("NZBD_TEST_PG_SOCKET")),
            port: var("NZBD_TEST_PG_PORT").parse().expect("NZBD_TEST_PG_PORT"),
            superuser: var("NZBD_TEST_PG_SUPERUSER"),
            password: var("NZBD_TEST_PG_PASSWORD"),
        }
    }

    fn base(&self, db: &str) -> PgConnectOptions {
        PgConnectOptions::new_without_pgpass()
            .socket(&self.socket)
            .port(self.port)
            .database(db)
            .ssl_mode(PgSslMode::Disable)
            .application_name("nzbd-test")
            .disable_statement_logging()
    }

    /// Superuser connection options for database `db`.
    #[must_use]
    pub fn superuser_options(&self, db: &str) -> PgConnectOptions {
        self.base(db)
            .username(&self.superuser)
            .password(&self.password)
    }

    /// Settings of database `db` as the production code sees them (socket mode).
    #[must_use]
    pub fn settings(&self, db: &str) -> PgSettings {
        PgSettings {
            host: PgHost::Socket(self.socket.clone()),
            port: self.port,
            name: db.to_owned(),
            user: "nzbd_app".to_owned(),
            password_file: PathBuf::from("/nonexistent/test-password"),
            pool_web: 4,
            pool_ingest: 2,
            pool_background: 2,
            acquire_timeout: Duration::from_secs(20),
            statement_timeout: Duration::from_secs(60),
        }
    }
}

/// Template name for the compiled-in migration set.
fn template_name() -> String {
    let mut h = Sha256::new();
    for m in MIGRATOR.iter() {
        h.update(m.version.to_be_bytes());
        h.update(&*m.checksum);
    }
    h.update(ROLES_SQL.as_bytes());
    for (id, parent, name) in crate::taxonomy::seed_rows().expect("taxonomy") {
        h.update(id.to_be_bytes());
        h.update(parent.unwrap_or(-1).to_be_bytes());
        h.update(name.as_bytes());
    }
    let d = h.finalize();
    let mut name = String::from("nzbd_tpl_");
    for b in d.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(name, "{b:02x}");
    }
    name
}

/// Runs `f` on a fresh current-thread runtime in its own OS thread (used where no async context may be borrowed:
/// the one-time template build and `Drop`).
fn on_own_runtime<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(f).join().expect("harness thread")
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

async fn build_template(server: Server, tpl: String) {
    let mut admin = server
        .superuser_options("postgres")
        .connect()
        .await
        .expect("connect to the test Postgres as superuser (is scripts/dev running it?)");
    // Cluster-wide: parallel test binaries build the template once.
    sqlx::query("SELECT pg_advisory_lock(1853514340, 99)")
        .execute(&mut admin)
        .await
        .expect("lock");
    let ready: Option<bool> =
        sqlx::query_scalar("SELECT datistemplate FROM pg_database WHERE datname = $1")
            .bind(&tpl)
            .fetch_optional(&mut admin)
            .await
            .expect("lookup");
    if ready != Some(true) {
        if ready.is_some() {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE \"{tpl}\" WITH (FORCE)"
            )))
            .execute(&mut admin)
            .await
            .expect("drop half-built template");
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{tpl}\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'")))
            .execute(&mut admin)
            .await
            .expect("create template");
        {
            let mut su = server
                .superuser_options(&tpl)
                .connect()
                .await
                .expect("connect template");
            sqlx::raw_sql(ROLES_SQL)
                .execute(&mut su)
                .await
                .expect("roles bootstrap");
            sqlx::raw_sql(
                "ALTER ROLE nzbd_app PASSWORD 'nzbd-test-app'; ALTER ROLE nzbd_owner PASSWORD 'nzbd-test-owner';",
            )
            .execute(&mut su)
            .await
            .expect("role passwords");
            su.close().await.expect("close");
        }
        let settings = server.settings(&tpl);
        let owner = connect_options(
            &settings,
            "nzbd_owner",
            TEST_OWNER_PASSWORD,
            PoolKind::Background,
            Duration::from_secs(120),
        );
        migrate_as_owner(owner).await.expect("migrate template");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER DATABASE \"{tpl}\" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false"
        )))
        .execute(&mut admin)
        .await
        .expect("mark template");
    }
    sqlx::query("SELECT pg_advisory_unlock(1853514340, 99)")
        .execute(&mut admin)
        .await
        .expect("unlock");
    admin.close().await.expect("close");
}

fn template(server: &Server) -> String {
    TEMPLATE
        .get_or_init(|| {
            let tpl = template_name();
            let (s, t) = (server.clone(), tpl.clone());
            on_own_runtime(move || block_on(build_template(s, t)));
            tpl
        })
        .clone()
}

/// A private, migrated database for one test, dropped on `Drop`.
pub struct TestDb {
    /// The app-role handle (what production code uses).
    pub db: PgDb,
    /// Database name.
    pub name: String,
    server: Server,
}

impl std::fmt::Debug for TestDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDb")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl TestDb {
    /// Creates the database (from the template) and connects the app-role pools.
    pub async fn new() -> Self {
        let server = Server::from_env();
        let tpl = template(&server);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("nzbd_t_{}_{n}", std::process::id());
        let mut admin = server
            .superuser_options("postgres")
            .connect()
            .await
            .expect("connect superuser");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{name}\" TEMPLATE \"{tpl}\" STRATEGY FILE_COPY"
        )))
        .execute(&mut admin)
        .await
        .expect("create test database");
        admin.close().await.expect("close");
        let mut su = server
            .superuser_options(&name)
            .connect()
            .await
            .expect("connect test db");
        sqlx::raw_sql(DB_PRIVILEGES_SQL)
            .execute(&mut su)
            .await
            .expect("database privileges");
        su.close().await.expect("close");
        let settings = server.settings(&name);
        let db = PgDb::connect(&settings, TEST_APP_PASSWORD)
            .await
            .expect("connect app role");
        Self { db, name, server }
    }

    /// A private database migrated only up to and including version `last`, as an older release left it (the
    /// 3.1 -> 3.2 upgrade-path test). Built from `template0` like the template itself (superuser bootstrap, then the
    /// owner-only migration and taxonomy seed), not from the template, which carries every migration of this binary.
    #[cfg(test)]
    pub(crate) async fn new_upto(last: i64) -> Self {
        let server = Server::from_env();
        // Building the template (once per process) creates the roles and sets their test passwords.
        let _ = template(&server);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("nzbd_u_{}_{n}", std::process::id());
        let mut admin = server
            .superuser_options("postgres")
            .connect()
            .await
            .expect("connect superuser");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
        )))
        .execute(&mut admin)
        .await
        .expect("create test database");
        // The bootstrap re-asserts the cluster-wide role attributes (`ALTER ROLE`): under the template lock, so it never
        // runs concurrently with another binary's template build ("tuple concurrently updated").
        sqlx::query("SELECT pg_advisory_lock(1853514340, 99)")
            .execute(&mut admin)
            .await
            .expect("lock");
        let mut su = server
            .superuser_options(&name)
            .connect()
            .await
            .expect("connect test db");
        sqlx::raw_sql(ROLES_SQL)
            .execute(&mut su)
            .await
            .expect("roles bootstrap");
        su.close().await.expect("close");
        sqlx::query("SELECT pg_advisory_unlock(1853514340, 99)")
            .execute(&mut admin)
            .await
            .expect("unlock");
        admin.close().await.expect("close");
        let settings = server.settings(&name);
        let owner = connect_options(
            &settings,
            "nzbd_owner",
            TEST_OWNER_PASSWORD,
            PoolKind::Background,
            Duration::from_secs(120),
        );
        super::schema::migrate_as_owner_upto(owner, last)
            .await
            .expect("migrate to the older schema");
        let db = PgDb::connect(&settings, TEST_APP_PASSWORD)
            .await
            .expect("connect app role");
        Self { db, name, server }
    }

    /// Settings of this database (socket mode, app role).
    #[must_use]
    pub fn settings(&self) -> PgSettings {
        self.server.settings(&self.name)
    }

    /// App-role options for a separate connection (concurrency tests).
    #[must_use]
    pub fn app_options(&self) -> PgConnectOptions {
        connect_options(
            &self.settings(),
            "nzbd_app",
            TEST_APP_PASSWORD,
            PoolKind::Web,
            Duration::from_secs(60),
        )
    }

    /// Owner-role options (setup-service operations).
    #[must_use]
    pub fn owner_options(&self) -> PgConnectOptions {
        connect_options(
            &self.settings(),
            "nzbd_owner",
            TEST_OWNER_PASSWORD,
            PoolKind::Background,
            Duration::from_secs(60),
        )
    }

    /// Superuser options for this database.
    #[must_use]
    pub fn superuser_options(&self) -> PgConnectOptions {
        self.server.superuser_options(&self.name)
    }

    /// A one-off app-role connection.
    pub async fn app_conn(&self) -> PgConnection {
        self.app_options().connect().await.expect("app connection")
    }

    /// A one-off owner-role connection.
    pub async fn owner_conn(&self) -> PgConnection {
        self.owner_options()
            .connect()
            .await
            .expect("owner connection")
    }

    /// A one-off superuser connection to this database.
    pub async fn superuser_conn(&self) -> PgConnection {
        self.superuser_options()
            .connect()
            .await
            .expect("superuser connection")
    }

    /// A pool with the app role (for code that wants its own pool).
    pub async fn app_pool(&self, size: u32) -> sqlx::PgPool {
        PgPoolOptions::new()
            .max_connections(size)
            .connect_with(self.app_options())
            .await
            .expect("app pool")
    }

    /// Freezes the DATABASE clock (`nzbd.db_clock()`, used by retention and partition upkeep) at `secs`. Test-only:
    /// replaces the function body as the owner of this private database.
    pub async fn set_db_clock(&self, secs: i64) {
        let mut c = self.owner_conn().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE OR REPLACE FUNCTION nzbd.db_clock() RETURNS bigint LANGUAGE sql STABLE \
             SET search_path = nzbd, pg_temp AS $$ SELECT {secs}::bigint $$"
        )))
        .execute(&mut c)
        .await
        .expect("set db clock");
        c.close().await.expect("close");
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let server = self.server.clone();
        let name = self.name.clone();
        // FORCE terminates the pools' connections; the pools themselves drop with `self` afterwards.
        on_own_runtime(move || {
            block_on(async move {
                if let Ok(mut admin) = server.superuser_options("postgres").connect().await {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
                    )))
                    .execute(&mut admin)
                    .await;
                    let _ = admin.close().await;
                }
            });
        });
    }
}
