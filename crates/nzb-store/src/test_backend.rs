//! The backend matrix of the web, ingest and nzbd test suites (ARCHITECTURE v3 13.7, review 34 M4, SEC-104): the
//! harnesses build their [`Store`] from `NZBD_TEST_BACKEND` (`sqlite` or `postgres`). There is **no default**: an
//! unset or unknown value fails the harness, so a CI leg can never silently test the other backend. Each test binary
//! prints `NZBD_TEST_BACKEND opened <backend> by <binary>` once on stderr, which `scripts/ci.sh` checks per leg and per
//! harness binary (`scripts/sec_104_markers.py`).
//!
//! Raw SQL of the tests goes through [`TestStore`] (full privileges: the SQLite writer, the Postgres superuser on the
//! private test database) and is written in the dialect both accept (`true`/`false`, `count(*)`, [`TestStore::blob`]
//! for byte literals, no parameters: test values are formatted in by the test, never input). Test-only.
//! `AssertSqlSafe` below marks only this fixture-authored SQL; bound values in `sql_with` remain parameters.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Once;

use sqlx::{Connection as _, Row as _};

use crate::pg::testing::TestDb;
use crate::{DbBackend, DbConfig, Store};

/// The backend named by `NZBD_TEST_BACKEND`.
///
/// # Panics
/// When the variable is unset, empty or not exactly `sqlite` / `postgres` (no default, review 34 M4).
#[must_use]
pub fn test_backend() -> DbBackend {
    let v = std::env::var("NZBD_TEST_BACKEND").unwrap_or_default();
    v.parse().unwrap_or_else(|_| {
        panic!(
            "NZBD_TEST_BACKEND must be \"sqlite\" or \"postgres\" (got {v:?}); there is no default \
             (scripts/ci.sh runs both legs)"
        )
    })
}

static MARK: Once = Once::new();

/// A connection that asks whether the account-domain lock is free (see [`TestStore::account_lock_probe`]).
pub enum LockProbe {
    /// SQLite: a connection with no busy wait.
    Sqlite(sqlx::SqliteConnection),
    /// Postgres: a superuser connection.
    Postgres(sqlx::PgConnection),
}

impl std::fmt::Debug for LockProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockProbe")
    }
}

impl LockProbe {
    /// Whether the lock is free right now, without waiting (SQLite: the single writer, `BEGIN IMMEDIATE`; Postgres:
    /// `pg_try_advisory_lock` on the account-domain key). Whatever it takes is released at once.
    pub async fn is_free(&mut self) -> bool {
        match self {
            Self::Sqlite(c) => {
                let free = sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut *c)
                    .await
                    .is_ok();
                if free {
                    sqlx::query("ROLLBACK").execute(&mut *c).await.unwrap();
                }
                free
            }
            Self::Postgres(c) => {
                let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
                    .bind(crate::pg::LOCK_NAMESPACE)
                    .bind(crate::pg::LOCK_ACCOUNT_DOMAIN)
                    .fetch_one(&mut *c)
                    .await
                    .unwrap();
                if free {
                    sqlx::query("SELECT pg_advisory_unlock($1, $2)")
                        .bind(crate::pg::LOCK_NAMESPACE)
                        .bind(crate::pg::LOCK_ACCOUNT_DOMAIN)
                        .execute(&mut *c)
                        .await
                        .unwrap();
                }
                free
            }
        }
    }
}

/// A write lock held by [`TestStore::hold_write_lock`].
pub enum HeldLock {
    /// The SQLite connection inside `BEGIN IMMEDIATE`.
    Sqlite(sqlx::SqliteConnection),
    /// The Postgres superuser connection inside the locking transaction.
    Postgres(sqlx::PgConnection),
}

impl std::fmt::Debug for HeldLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldLock")
    }
}

impl HeldLock {
    /// Rolls back and closes the connection.
    pub async fn release(self) {
        match self {
            Self::Sqlite(mut c) => {
                sqlx::query("ROLLBACK").execute(&mut c).await.unwrap();
                c.close().await.unwrap();
            }
            Self::Postgres(mut c) => {
                sqlx::query("ROLLBACK").execute(&mut c).await.unwrap();
                c.close().await.unwrap();
            }
        }
    }
}

/// Variables a test removes from the environment of an `nzbd` child process: `cargo` exports `SSL_CERT_FILE`/
/// `SSL_CERT_DIR` to everything it starts, and the Postgres backend refuses them (SEC-086).
pub const CHILD_ENV_REMOVALS: [&str; 2] = ["SSL_CERT_FILE", "SSL_CERT_DIR"];

fn mark(backend: DbBackend) {
    // Written to the process's stderr directly (not `eprintln!`, which the test harness captures), so every test
    // binary of a CI leg shows the backend it really opened (SEC-104, checked by scripts/ci.sh).
    MARK.call_once(|| {
        use std::io::Write as _;
        // The test binary's name without cargo's hash suffix (`download-1a2b..` -> `download`), so CI can require one
        // marker per harness binary (review 35 M1 b).
        let exe = std::env::current_exe().ok();
        let stem = exe
            .as_deref()
            .and_then(Path::file_stem)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = stem.rsplit_once('-').map_or(stem.as_str(), |(n, _)| n);
        // One `write` of the whole line (unbuffered stderr would otherwise write the pieces separately and libtest's
        // concurrent output could land in between); the leading newline puts it on its own line after a partial
        // `test x ... ` line.
        let line = format!("\nNZBD_TEST_BACKEND opened {backend} by {name}\n");
        let _ = std::io::stderr().write_all(line.as_bytes());
    });
}

/// A test library of the selected backend, with raw-SQL helpers.
pub struct TestStore {
    /// The library.
    pub store: Store,
    pg: Option<TestDb>,
    sqlite_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for TestStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestStore")
            .field("backend", &self.store.backend())
            .finish_non_exhaustive()
    }
}

impl TestStore {
    /// Opens a fresh library of the selected backend (SQLite: `dir/t.sqlite`; Postgres: a private database cloned
    /// from the migrated template).
    pub async fn open(dir: &Path) -> Self {
        Self::open_backend(test_backend(), dir).await
    }

    /// Like [`TestStore::open`], with the SQLite file at `sqlite_path` (tests whose config names the file; the
    /// Postgres leg ignores the path).
    pub async fn open_file(sqlite_path: &Path) -> Self {
        let backend = test_backend();
        mark(backend);
        match backend {
            DbBackend::Sqlite => Self {
                store: Store::open_sqlite(&DbConfig {
                    path: sqlite_path.to_path_buf(),
                })
                .await
                .expect("open sqlite"),
                pg: None,
                sqlite_path: Some(sqlite_path.to_path_buf()),
            },
            DbBackend::Postgres => Self::open_backend(backend, Path::new("/nonexistent")).await,
        }
    }

    /// The `[db]` section of an nzbd config file that opens this library as the binary does (the SQLite leg: just
    /// the backend, the file is `paths.db`; the Postgres leg: the app role over the test server's socket with a
    /// 0600 password file written into `dir`). Child processes must also drop the `SSL_CERT_*` variables `cargo`
    /// exports (SEC-086 refuses them with the Postgres backend): see [`CHILD_ENV_REMOVALS`].
    #[must_use]
    pub fn config_db_section(&self, dir: &Path) -> String {
        match &self.pg {
            None => "[db]\nbackend = \"sqlite\"\n".to_owned(),
            Some(t) => {
                use std::os::unix::fs::PermissionsExt as _;
                let s = t.settings();
                let socket = match &s.host {
                    crate::pg::PgHost::Socket(p) => p.display().to_string(),
                    crate::pg::PgHost::Ip(ip) => ip.to_string(),
                };
                let pw = dir.join("db-app.password");
                std::fs::write(&pw, crate::pg::testing::TEST_APP_PASSWORD).unwrap();
                std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
                format!(
                    "[db]\nbackend = \"postgres\"\nhost = {socket:?}\nport = {port}\nname = {name:?}\n\
                     user = \"nzbd_app\"\npassword_file = {pw:?}\n",
                    port = s.port,
                    name = s.name,
                    pw = pw.display().to_string(),
                )
            }
        }
    }

    /// A new handle on the same library, as a restarted process opens it (SQLite: the file again; Postgres: a new
    /// app-role connection). The caller closes the old [`TestStore::store`] handle first if it wants a clean restart.
    pub async fn reopen(&self) -> Store {
        match (&self.sqlite_path, &self.pg) {
            (Some(p), _) => Store::open_sqlite(&DbConfig { path: p.clone() })
                .await
                .expect("reopen sqlite"),
            (None, Some(t)) => Store::Postgres(
                crate::pg::PgDb::connect(&t.settings(), crate::pg::testing::TEST_APP_PASSWORD)
                    .await
                    .expect("reconnect postgres"),
            ),
            (None, None) => panic!("test store without a library"),
        }
    }

    /// Holds the database's write lock from a separate connection until [`HeldLock::release`] (SEC-095 busy tests):
    /// SQLite `BEGIN IMMEDIATE` on its own connection to the file (other writers wait `busy_timeout`, then fail
    /// busy); Postgres an open superuser transaction holding `ACCESS EXCLUSIVE` on `table` (the app's statements on
    /// it wait `lock_timeout`, then fail busy).
    pub async fn hold_write_lock(&self, table: &str) -> HeldLock {
        match (&self.sqlite_path, &self.pg) {
            (Some(p), _) => {
                use sqlx::ConnectOptions as _;
                let mut c = sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(p)
                    .connect()
                    .await
                    .unwrap();
                sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut c)
                    .await
                    .unwrap();
                HeldLock::Sqlite(c)
            }
            (None, Some(t)) => {
                let mut c = t.superuser_conn().await;
                sqlx::query("SET search_path = nzbd, pg_temp")
                    .execute(&mut c)
                    .await
                    .unwrap();
                sqlx::query("BEGIN").execute(&mut c).await.unwrap();
                let lock = match table {
                    "session" => "LOCK TABLE session IN ACCESS EXCLUSIVE MODE",
                    "account" => "LOCK TABLE account IN ACCESS EXCLUSIVE MODE",
                    other => panic!("hold_write_lock: no lock statement for {other}"),
                };
                sqlx::query(lock).execute(&mut c).await.unwrap();
                HeldLock::Postgres(c)
            }
            (None, None) => panic!("test store without a library"),
        }
    }

    /// A probe of the account-domain lock on its own connection (SEC-026/095 lock tests); see [`LockProbe::is_free`].
    pub async fn account_lock_probe(&self) -> LockProbe {
        match (&self.sqlite_path, &self.pg) {
            (Some(p), _) => {
                use sqlx::ConnectOptions as _;
                LockProbe::Sqlite(
                    sqlx::sqlite::SqliteConnectOptions::new()
                        .filename(p)
                        .busy_timeout(std::time::Duration::ZERO)
                        .connect()
                        .await
                        .unwrap(),
                )
            }
            (None, Some(t)) => LockProbe::Postgres(t.superuser_conn().await),
            (None, None) => panic!("test store without a library"),
        }
    }

    /// Writes the owner-role password of the Postgres test server into `dir` (0600, SEC-042 rules) for the
    /// `setup`-service commands (`nzbd db migrate | set-retention | restore --owner-password-file`); `None` on SQLite.
    #[must_use]
    pub fn owner_password_file(&self, dir: &Path) -> Option<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;
        self.pg.as_ref()?;
        let p = dir.join("db-owner.password");
        std::fs::write(&p, crate::pg::testing::TEST_OWNER_PASSWORD).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        Some(p)
    }

    /// The Postgres leg's connection settings for an in-process `nzbd` config, with a 0600 app-role password file
    /// written into `dir`; `None` on the SQLite leg.
    #[must_use]
    pub fn pg_settings_with_password_file(&self, dir: &Path) -> Option<crate::pg::PgSettings> {
        use std::os::unix::fs::PermissionsExt as _;
        let t = self.pg.as_ref()?;
        let mut s = t.settings();
        let pw = dir.join("db-app.password");
        std::fs::write(&pw, crate::pg::testing::TEST_APP_PASSWORD).unwrap();
        std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
        s.password_file = pw;
        Some(s)
    }

    /// Opens a fresh library of `backend` (tests that must run one backend explicitly).
    pub async fn open_backend(backend: DbBackend, dir: &Path) -> Self {
        mark(backend);
        match backend {
            DbBackend::Sqlite => Self {
                store: Store::open_sqlite(&DbConfig {
                    path: dir.join("t.sqlite"),
                })
                .await
                .expect("open sqlite"),
                pg: None,
                sqlite_path: Some(dir.join("t.sqlite")),
            },
            DbBackend::Postgres => {
                let t = TestDb::new().await;
                Self {
                    store: Store::Postgres(t.db.clone()),
                    pg: Some(t),
                    sqlite_path: None,
                }
            }
        }
    }

    /// The backend under test.
    #[must_use]
    pub fn backend(&self) -> DbBackend {
        self.store.backend()
    }

    /// The Postgres test database (Postgres leg only).
    #[must_use]
    pub fn pg(&self) -> Option<&TestDb> {
        self.pg.as_ref()
    }

    /// A byte-string literal in the backend's dialect.
    #[must_use]
    pub fn blob(&self, b: &[u8]) -> String {
        let mut hex = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(hex, "{x:02x}");
        }
        match self.backend() {
            DbBackend::Sqlite => format!("x'{hex}'"),
            DbBackend::Postgres => format!("'\\x{hex}'::bytea"),
        }
    }

    /// Runs statements (no parameters, no result) with full privileges. A boxed `Send` future (usable inside
    /// `async_trait` methods).
    pub fn exec<'a>(
        &'a self,
        sql: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let sql = sql.to_owned();
        let target = match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => Ok(db.writer().clone()),
            (Store::Postgres(_), Some(t)) => Err(t.superuser_options()),
            (Store::Postgres(_), None) => panic!("postgres store without its test database"),
        };
        // One statement at a time on one connection (`raw_sql` futures are not `Send` for every lifetime). Test SQL
        // never has a `;` inside a literal.
        let stmts: Vec<String> = sql
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        Box::pin(async move {
            match target {
                Ok(pool) => {
                    let mut c = pool.acquire().await.unwrap();
                    for st in stmts {
                        sqlx::query(sqlx::AssertSqlSafe(st))
                            .execute(&mut *c)
                            .await
                            .unwrap();
                    }
                }
                Err(opts) => {
                    use sqlx::ConnectOptions as _;
                    let mut c = opts.connect().await.unwrap();
                    sqlx::query("SET search_path = nzbd, pg_temp")
                        .execute(&mut c)
                        .await
                        .unwrap();
                    for st in stmts {
                        sqlx::query(sqlx::AssertSqlSafe(st))
                            .execute(&mut c)
                            .await
                            .unwrap();
                    }
                    c.close().await.unwrap();
                }
            }
        })
    }

    /// Renumbers release `from` to `to` (its files follow), bypassing the foreign keys for the one transaction: the
    /// stand-in for a restored older backup that brings another release back under a known id (the T119 digest
    /// binding tests, review 34 L1).
    pub fn renumber_release(
        &self,
        from: i64,
        to: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match self.backend() {
                DbBackend::Sqlite => {
                    self.exec(&format!(
                    "BEGIN; PRAGMA defer_foreign_keys = ON; UPDATE release SET id = {to} WHERE id = {from}; \
                     UPDATE nzb_file SET release_id = {to} WHERE release_id = {from}; COMMIT;"
                ))
                .await;
                }
                DbBackend::Postgres => {
                    self.exec(&format!(
                        "BEGIN; SET LOCAL session_replication_role = replica; \
                     UPDATE release SET id = {to} WHERE id = {from}; \
                     UPDATE nzb_file SET release_id = {to} WHERE release_id = {from}; COMMIT;"
                    ))
                    .await;
                }
            }
        })
    }

    /// Like [`TestStore::exec`], but returns whether it succeeded (statements a trigger or CHECK must refuse).
    pub async fn try_exec(&self, sql: &str) -> Result<(), String> {
        match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
                .execute(db.writer())
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            (Store::Postgres(_), Some(t)) => {
                let mut c = t.superuser_conn().await;
                let r = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "SET search_path = nzbd, pg_temp; {sql}"
                )))
                .execute(&mut c)
                .await
                .map(|_| ())
                .map_err(|e| {
                    e.as_database_error()
                        .map_or_else(|| e.to_string(), |d| d.message().to_owned())
                });
                let _ = c.close().await;
                r
            }
            (Store::Postgres(_), None) => Err("postgres store without its test database".into()),
        }
    }

    /// One `bigint`/`INTEGER` value (write the query so the column is an integer on both: `count(*)`,
    /// `CAST(x AS INTEGER)`; `NULL` is 0).
    pub async fn i64(&self, sql: &str) -> i64 {
        self.opt_i64(sql).await.unwrap_or(0)
    }

    /// One nullable integer value.
    pub async fn opt_i64(&self, sql: &str) -> Option<i64> {
        match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            (Store::Postgres(_), Some(t)) => {
                let mut c = t.superuser_conn().await;
                let mut tx = c.begin().await.unwrap();
                sqlx::query("SET LOCAL search_path = nzbd, pg_temp")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let row = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT ({sql})::bigint AS v")))
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                row.get("v")
            }
            (Store::Postgres(_), None) => panic!("postgres store without its test database"),
        }
    }

    /// One nullable byte-string value.
    pub async fn opt_bytes(&self, sql: &str) -> Option<Vec<u8>> {
        match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            (Store::Postgres(_), Some(t)) => {
                let mut c = t.superuser_conn().await;
                let mut tx = c.begin().await.unwrap();
                sqlx::query("SET LOCAL search_path = nzbd, pg_temp")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let v: Option<Vec<u8>> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                v
            }
            (Store::Postgres(_), None) => panic!("postgres store without its test database"),
        }
    }

    /// Every value of a byte-string column.
    pub async fn bytes_list(&self, sql: &str) -> Vec<Vec<u8>> {
        match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_all(db.writer())
                .await
                .unwrap(),
            (Store::Postgres(_), Some(t)) => {
                let mut c = t.superuser_conn().await;
                let mut tx = c.begin().await.unwrap();
                sqlx::query("SET LOCAL search_path = nzbd, pg_temp")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let v: Vec<Vec<u8>> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                v
            }
            (Store::Postgres(_), None) => panic!("postgres store without its test database"),
        }
    }

    /// One nullable text value.
    pub async fn opt_text(&self, sql: &str) -> Option<String> {
        match (&self.store, &self.pg) {
            (Store::Sqlite(db), _) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            (Store::Postgres(_), Some(t)) => {
                let mut c = t.superuser_conn().await;
                let mut tx = c.begin().await.unwrap();
                sqlx::query("SET LOCAL search_path = nzbd, pg_temp")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let v: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                v
            }
            (Store::Postgres(_), None) => panic!("postgres store without its test database"),
        }
    }
}

/// Raw test SQL with the application's own privileges (the SQLite writer, the Postgres app role, which may
/// `SELECT`/`UPDATE` what the app may). Statements without parameters, written in the dialect both accept
/// (`true`/`false`, [`blob`] literals); test values are formatted in by the test. For DDL or privileged writes use
/// [`TestStore::exec`].
pub mod sql {
    use crate::{DbBackend, Store};

    /// A byte-string literal in the dialect of `store`.
    #[must_use]
    pub fn blob(store: &Store, b: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(hex, "{x:02x}");
        }
        match store.backend() {
            DbBackend::Sqlite => format!("x'{hex}'"),
            DbBackend::Postgres => format!("'\\x{hex}'::bytea"),
        }
    }

    /// Runs one statement.
    pub async fn exec(store: &Store, sql: &str) {
        match store {
            Store::Sqlite(db) => {
                sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
                    .execute(db.writer())
                    .await
                    .unwrap();
            }
            Store::Postgres(db) => {
                sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
                    .execute(db.web())
                    .await
                    .unwrap();
            }
        }
    }

    /// One integer (`NULL` = 0). Postgres: the value is cast to `bigint`.
    pub async fn i64(store: &Store, sql: &str) -> i64 {
        match store {
            Store::Sqlite(db) => {
                sqlx::query_scalar::<_, Option<i64>>(sqlx::AssertSqlSafe(sql.to_owned()))
                    .fetch_one(db.writer())
                    .await
                    .unwrap()
                    .unwrap_or(0)
            }
            Store::Postgres(db) => sqlx::query_scalar::<_, Option<i64>>(sqlx::AssertSqlSafe(
                format!("SELECT ({sql})::bigint"),
            ))
            .fetch_one(db.web())
            .await
            .unwrap()
            .unwrap_or(0),
        }
    }

    /// One nullable integer. Postgres: the value is cast to `bigint`.
    pub async fn opt_i64(store: &Store, sql: &str) -> Option<i64> {
        match store {
            Store::Sqlite(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            Store::Postgres(db) => {
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT ({sql})::bigint")))
                    .fetch_one(db.web())
                    .await
                    .unwrap()
            }
        }
    }

    /// One nullable byte string.
    pub async fn opt_bytes(store: &Store, sql: &str) -> Option<Vec<u8>> {
        match store {
            Store::Sqlite(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            Store::Postgres(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.web())
                .await
                .unwrap(),
        }
    }

    /// Every value of a byte-string column.
    pub async fn bytes_list(store: &Store, sql: &str) -> Vec<Vec<u8>> {
        match store {
            Store::Sqlite(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_all(db.writer())
                .await
                .unwrap(),
            Store::Postgres(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_all(db.web())
                .await
                .unwrap(),
        }
    }

    /// One nullable text value.
    pub async fn opt_text(store: &Store, sql: &str) -> Option<String> {
        match store {
            Store::Sqlite(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.writer())
                .await
                .unwrap(),
            Store::Postgres(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
                .fetch_one(db.web())
                .await
                .unwrap(),
        }
    }
}

/// A bound value of [`sql_with`] helpers.
#[derive(Debug, Clone)]
pub enum V {
    /// An integer.
    I(i64),
    /// A byte string.
    B(Vec<u8>),
    /// A text value.
    S(String),
    /// `NULL` text.
    Null,
    /// `NULL` integer.
    NullInt,
}

impl From<i64> for V {
    fn from(v: i64) -> Self {
        Self::I(v)
    }
}
impl From<Option<i64>> for V {
    fn from(v: Option<i64>) -> Self {
        v.map_or(Self::NullInt, Self::I)
    }
}
impl From<&[u8]> for V {
    fn from(v: &[u8]) -> Self {
        Self::B(v.to_vec())
    }
}
impl From<Vec<u8>> for V {
    fn from(v: Vec<u8>) -> Self {
        Self::B(v)
    }
}
impl From<&Vec<u8>> for V {
    fn from(v: &Vec<u8>) -> Self {
        Self::B(v.clone())
    }
}
impl From<&str> for V {
    fn from(v: &str) -> Self {
        Self::S(v.to_owned())
    }
}
impl From<Option<&str>> for V {
    fn from(v: Option<&str>) -> Self {
        v.map_or(Self::Null, |s| Self::S(s.to_owned()))
    }
}

/// Raw test SQL with bound values ([`V`]), `?N` placeholders (rewritten to `$N` for Postgres; a bare `?` is
/// numbered in order). Same privileges as [`sql`].
pub mod sql_with {
    use super::V;
    use crate::{DbBackend, Store};

    fn pg_text(sql: &str) -> String {
        let mut out = String::with_capacity(sql.len());
        let mut n = 0_u32;
        let mut it = sql.chars().peekable();
        while let Some(c) = it.next() {
            if c == '?' {
                if it.peek().is_some_and(char::is_ascii_digit) {
                    out.push('$');
                } else {
                    n += 1;
                    out.push('$');
                    out.push_str(&n.to_string());
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    macro_rules! bound {
        ($q:expr, $vals:expr) => {{
            let mut q = $q;
            for v in $vals {
                q = match v {
                    V::I(i) => q.bind(*i),
                    V::B(b) => q.bind(b.clone()),
                    V::S(s) => q.bind(s.clone()),
                    V::Null => q.bind(None::<String>),
                    V::NullInt => q.bind(None::<i64>),
                };
            }
            q
        }};
    }

    /// Runs one statement. Returns a boxed `Send` future (usable inside `async_trait` methods, where sqlx's
    /// executor bounds are otherwise not general enough).
    pub fn exec<'a>(
        store: &'a Store,
        sql: &'a str,
        vals: &'a [V],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let store = store.clone();
        let sql = sql.to_owned();
        let vals = vals.to_vec();
        Box::pin(async move {
            match store {
                Store::Sqlite(db) => {
                    let pool = db.writer().clone();
                    bound!(sqlx::query(sqlx::AssertSqlSafe(sql)), &vals)
                        .execute(&pool)
                        .await
                        .unwrap();
                }
                Store::Postgres(db) => {
                    let t = pg_text(&sql);
                    let pool = db.web().clone();
                    bound!(sqlx::query(sqlx::AssertSqlSafe(t)), &vals)
                        .execute(&pool)
                        .await
                        .unwrap();
                }
            }
        })
    }

    /// One nullable integer (Postgres: cast to `bigint`).
    pub async fn opt_i64(store: &Store, sql: &str, vals: &[V]) -> Option<i64> {
        match store {
            Store::Sqlite(db) => bound!(
                sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned())),
                vals
            )
            .fetch_one(db.writer())
            .await
            .unwrap(),
            Store::Postgres(db) => {
                let t = format!("SELECT ({})::bigint", pg_text(sql));
                bound!(sqlx::query_scalar(sqlx::AssertSqlSafe(t)), vals)
                    .fetch_one(db.web())
                    .await
                    .unwrap()
            }
        }
    }

    /// One integer (`NULL` = 0).
    pub async fn i64(store: &Store, sql: &str, vals: &[V]) -> i64 {
        opt_i64(store, sql, vals).await.unwrap_or(0)
    }

    /// One nullable byte string.
    pub async fn opt_bytes(store: &Store, sql: &str, vals: &[V]) -> Option<Vec<u8>> {
        match store {
            Store::Sqlite(db) => bound!(
                sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned())),
                vals
            )
            .fetch_one(db.writer())
            .await
            .unwrap(),
            Store::Postgres(db) => {
                let t = pg_text(sql);
                bound!(sqlx::query_scalar(sqlx::AssertSqlSafe(t)), vals)
                    .fetch_one(db.web())
                    .await
                    .unwrap()
            }
        }
    }

    /// One nullable text value.
    pub async fn opt_text(store: &Store, sql: &str, vals: &[V]) -> Option<String> {
        match store {
            Store::Sqlite(db) => bound!(
                sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned())),
                vals
            )
            .fetch_one(db.writer())
            .await
            .unwrap(),
            Store::Postgres(db) => {
                let t = pg_text(sql);
                bound!(sqlx::query_scalar(sqlx::AssertSqlSafe(t)), vals)
                    .fetch_one(db.web())
                    .await
                    .unwrap()
            }
        }
    }

    /// Whether `store` is Postgres (for the few statements whose text must differ).
    #[must_use]
    pub fn is_pg(store: &Store) -> bool {
        store.backend() == DbBackend::Postgres
    }
}
