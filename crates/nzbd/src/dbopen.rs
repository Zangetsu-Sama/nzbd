//! Opening the configured backend (`db.backend`, ARCHITECTURE v3 13.1/13.5). The only place in `nzbd` that names
//! both backends' constructors; everything else holds a [`Store`].
//!
//! * SQLite: `paths.db`, created and migrated on open (fresh 3.x library) or refused (`LEGACY_DATABASE` for a 2.x
//!   file, never modified).
//! * Postgres: the app role over the configured socket or internal address, password from `db.password_file`
//!   (SEC-042 rules); never migrates (`serve` refuses `MIGRATIONS_PENDING` and every other readiness code: migrations
//!   are applied with the owner role by `nzbd db migrate` in the one-shot `setup` service, review 30 M4).

use nzb_store::pg::PgDb;
use nzb_store::pg::config::read_password_file;
use nzb_store::{DbBackend, DbConfig, OpenEvent, SqliteDb, StartupCheck, Store, StoreError};

use crate::config::Config;

/// Why an open failed: a stable code for the operator plus the store error when there is one.
#[derive(Debug)]
pub enum OpenError {
    /// A store error (SQLite open/migration, Postgres connection).
    Store(StoreError),
    /// A refusal with a stable code (`MIGRATIONS_PENDING`, `DB_PASSWORD_FILE`, ...).
    Refused(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Refused(s) => f.write_str(s),
        }
    }
}

impl From<StoreError> for OpenError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

async fn connect_pg(cfg: &Config) -> Result<PgDb, OpenError> {
    crate::config::check_process_environment().map_err(|e| OpenError::Refused(e.to_string()))?;
    let s = cfg
        .db
        .pg_settings()
        .map_err(|e| OpenError::Refused(e.to_string()))?;
    let password = read_password_file(&s.password_file)
        .map_err(|e| OpenError::Refused(format!("{}: {e}", e.code())))?;
    Ok(PgDb::connect(&s, &password).await?)
}

async fn ready(db: PgDb) -> Result<Store, OpenError> {
    let r = db.readiness().await?;
    match r.code() {
        None => {
            // This is a Ready read-write open, before the caller's library-anchor admission.
            // Prepare the current/next ingest-log months before the first ingest can populate
            // DEFAULT. Read-only and restore-pending opens deliberately bypass this write step.
            // Upkeep is best effort: existing DEFAULT/file insertion fallbacks remain usable.
            if let Err(e) = db.partition_upkeep().await {
                tracing::warn!(error = %e, "PostgreSQL partition upkeep failed at startup");
            }
            Ok(Store::Postgres(db))
        }
        Some(code) => {
            db.close().await;
            Err(OpenError::Refused(format!(
                "{code}: the PostgreSQL database is not ready for this release"
            )))
        }
    }
}

/// Opens the library read-write (operator commands): SQLite creates and migrates a new file; Postgres must be ready.
/// A library marked `restore_pending` is refused with `RESTORE_PENDING` on both backends (review 35 L6): only the
/// commands of the gate list (`db restore-finish`, `db check`, `audit verify`, `backup`, `search status`) run then,
/// through [`open_allow_restore_pending`] or [`open_read_only`].
///
/// # Errors
/// See [`OpenError`].
pub async fn open(cfg: &Config) -> Result<Store, OpenError> {
    open_with(cfg, cfg.db.startup_check.into(), &operator_progress).await
}

/// Operator commands stay quiet about the routine open steps; a fixed file mode (SEC-102) is always a warning.
#[allow(clippy::needless_pass_by_value)] // the progress callback type (`dyn Fn(OpenEvent)`) passes it by value
fn operator_progress(ev: OpenEvent) {
    if matches!(ev, OpenEvent::FileModeFixed { .. }) {
        crate::dbcheck::log_open_event(&ev);
    }
}

/// [`open`] with the SQLite startup check mode and progress events (`serve`).
///
/// # Errors
/// See [`OpenError`].
pub async fn open_with(
    cfg: &Config,
    check: StartupCheck,
    progress: &(dyn Fn(OpenEvent) + Send + Sync),
) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => {
            let db = open_sqlite(cfg, check, progress).await?;
            if db.restore_pending().await? {
                db.close().await;
                return Err(OpenError::Refused(
                    "RESTORE_PENDING: this database was restored; run `nzbd db restore-finish` first".to_owned(),
                ));
            }
            Ok(Store::Sqlite(db))
        }
        DbBackend::Postgres => ready(connect_pg(cfg).await?).await,
    }
}

async fn open_sqlite(
    cfg: &Config,
    check: StartupCheck,
    progress: &(dyn Fn(OpenEvent) + Send + Sync),
) -> Result<SqliteDb, OpenError> {
    Ok(SqliteDb::open_with(
        &DbConfig {
            path: cfg.paths.db.clone(),
        },
        check,
        progress,
    )
    .await?)
}

/// Opens the library for `nzbd db restore-finish` and `nzbd backup`: like [`open`], but a database that is only
/// pending a restore (the state restore-finish ends) is accepted on both backends.
///
/// # Errors
/// See [`OpenError`].
pub async fn open_allow_restore_pending(cfg: &Config) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => Ok(Store::Sqlite(
            open_sqlite(cfg, cfg.db.startup_check.into(), &operator_progress).await?,
        )),
        DbBackend::Postgres => {
            let db = connect_pg(cfg).await?;
            match db.readiness().await? {
                nzb_store::pg::Readiness::Ready | nzb_store::pg::Readiness::RestorePending => {
                    Ok(Store::Postgres(db))
                }
                other => {
                    db.close().await;
                    Err(OpenError::Refused(format!(
                        "{}: the PostgreSQL database is not ready for this release",
                        other.code().unwrap_or("NOT_READY")
                    )))
                }
            }
        }
    }
}

/// Opens the library without creating, migrating or writing anything (diagnostics, dry runs).
///
/// # Errors
/// See [`OpenError`].
pub async fn open_read_only(cfg: &Config) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => Ok(SqliteDb::open_read_only(&cfg.paths.db)
            .await
            .map(Store::Sqlite)?),
        DbBackend::Postgres => Ok(Store::Postgres(connect_pg(cfg).await?)),
    }
}

/// Whether the configured library exists at all (SQLite: the file; Postgres: always, the server holds it).
#[must_use]
pub fn exists(cfg: &Config) -> bool {
    match cfg.db.backend {
        DbBackend::Sqlite => cfg.paths.db.is_file(),
        DbBackend::Postgres => true,
    }
}

#[cfg(test)]
mod upkeep_regressions {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use nzb_store::pg::testing::{TEST_APP_PASSWORD, TestDb};
    use nzb_store::prelude::*;

    // 2027-03-15 12:00:00 UTC, independent of the host clock.
    const NOW: i64 = 1_805_112_000;

    async fn partitions(t: &TestDb) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
             WHERE i.inhparent = 'nzbd.ingest_log'::regclass ORDER BY 1",
        )
        .fetch_all(&mut t.app_conn().await)
        .await
        .unwrap()
    }

    async fn insert_target(t: &TestDb, ts: i64) -> String {
        sqlx::query_scalar(
            "INSERT INTO ingest_log (ts, source, outcome) VALUES ($1, 'watch', 'ok') \
             RETURNING tableoid::regclass::text",
        )
        .bind(ts)
        .fetch_one(&mut t.app_conn().await)
        .await
        .unwrap()
    }

    fn config(t: &TestDb, dir: &std::path::Path) -> Config {
        let settings = t.settings();
        let password = dir.join("test-app-password");
        std::fs::write(&password, TEST_APP_PASSWORD).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        Config {
            db: crate::config::Db {
                backend: DbBackend::Postgres,
                host: Some(match settings.host {
                    nzb_store::pg::PgHost::Socket(path) => path.to_str().unwrap().to_owned(),
                    nzb_store::pg::PgHost::Ip(ip) => ip.to_string(),
                }),
                port: settings.port,
                name: settings.name,
                user: settings.user,
                password_file: Some(password),
                pool_web: settings.pool_web,
                pool_ingest: settings.pool_ingest,
                pool_background: settings.pool_background,
                ..crate::config::Db::default()
            },
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn ready_prepares_log_partitions_before_the_first_ingest() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);

        let db = ready(t.db.clone()).await.unwrap();
        assert_eq!(
            partitions(&t).await,
            [
                "ingest_log_default",
                "ingest_log_y2027m03",
                "ingest_log_y2027m04",
                "ingest_log_y2027m05"
            ],
            "ready must prepare the current and next two log months before ingestion"
        );
        assert_eq!(insert_target(&t, NOW).await, "ingest_log_y2027m03");
        // Opening another writer is idempotent and does not relocate existing rows.
        let again = ready(t.db.clone()).await.unwrap();
        assert_eq!(partitions(&t).await.len(), 4);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ingest_log")
            .fetch_one(&mut t.app_conn().await)
            .await
            .unwrap();
        assert_eq!(count, 1);
        drop(again);
        drop(db);
    }

    #[tokio::test]
    async fn ready_keeps_populated_default_month_and_prepares_future_months() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        assert_eq!(insert_target(&t, NOW).await, "ingest_log_default");

        let db = ready(t.db.clone()).await.unwrap();
        assert_eq!(
            partitions(&t).await,
            [
                "ingest_log_default",
                "ingest_log_y2027m04",
                "ingest_log_y2027m05"
            ],
            "ready must prepare empty future months without moving populated DEFAULT rows"
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ingest_log WHERE ts = $1 \
             AND tableoid = 'nzbd.ingest_log_default'::regclass",
        )
        .bind(NOW)
        .fetch_one(&mut t.app_conn().await)
        .await
        .unwrap();
        assert_eq!(count, 1, "upkeep must preserve the existing row");
        assert_eq!(insert_target(&t, NOW + 1).await, "ingest_log_default");
        assert_eq!(
            insert_target(&t, NOW + 31 * 86_400).await,
            "ingest_log_y2027m04"
        );
        drop(db);
    }

    #[tokio::test]
    async fn ready_keeps_default_routing_when_upkeep_fails() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        sqlx::query("REVOKE EXECUTE ON FUNCTION nzbd.ensure_log_partitions() FROM nzbd_app")
            .execute(&mut t.owner_conn().await)
            .await
            .unwrap();
        let db = ready(t.db.clone()).await.unwrap();
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
        assert_eq!(insert_target(&t, NOW).await, "ingest_log_default");
        drop(db);
    }

    #[tokio::test]
    async fn diagnostic_and_restore_pending_opens_do_not_run_upkeep() {
        let t = TestDb::new().await;
        t.set_db_clock(NOW).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&t, dir.path());

        let readonly = open_read_only(&cfg).await.unwrap();
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
        readonly.close().await;
        sqlx::query("UPDATE db_state SET restore_pending = true WHERE id = 1")
            .execute(&mut t.owner_conn().await)
            .await
            .unwrap();
        let pending = open_allow_restore_pending(&cfg).await.unwrap();
        assert!(pending.restore_pending().await.unwrap());
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
        pending.close().await;
        let readonly = open_read_only(&cfg).await.unwrap();
        assert!(readonly.restore_pending().await.unwrap());
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
        readonly.close().await;

        let refusal = ready(t.db.clone()).await;
        assert!(
            matches!(refusal, Err(OpenError::Refused(code)) if code.starts_with("RESTORE_PENDING:"))
        );
        // ready closes its pooled handle on refusal; this standalone app connection is independent.
        assert_eq!(partitions(&t).await, ["ingest_log_default"]);
    }
}
