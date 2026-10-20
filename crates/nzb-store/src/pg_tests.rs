//! v3 schema, roles and connection-layer tests against the ephemeral test Postgres (T112).
//! Dynamic SQL marked `AssertSqlSafe` uses fixture-generated names, numeric ids and literal test statements only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::Path;

use sqlx::{Connection as _, Row as _};

use crate::audit_chain::{AuditContent, GENESIS, chain_hash, class_of};
use crate::pg::config::{
    REFUSED_ENV_VARS, check_environment, check_identifier, ip_is_internal, parse_host,
    read_password_file,
};
use crate::pg::testing::TestDb;
use crate::pg::{
    LOCK_ACCOUNT_DOMAIN, LOCK_NAMESPACE, PgConfigError, PgDb, PgHost, PoolKind, RawPgSettings,
    Readiness, connect_options,
};

/// Postgres error code of a failed statement (`42501` insufficient privilege, `23514` check violation, `P0001` raise).
fn sqlstate(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code().map(std::borrow::Cow::into_owned))
        .unwrap_or_default()
}

fn raw<'a>(host: &'a str, name: &'a str, user: &'a str) -> RawPgSettings<'a> {
    RawPgSettings {
        host,
        port: 5432,
        name,
        user,
        password_file: Path::new("/run/secrets/nzbd_db_password"),
        pool_web: 16,
        pool_ingest: 4,
        pool_background: 4,
        acquire_timeout_ms: 3000,
        statement_timeout_ms: 5000,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SEC-086: endpoint and identifiers (pure validation, no server needed).

#[test]
fn sec_086_db_host_must_be_a_socket_path_or_ip_literal() {
    assert!(matches!(
        parse_host("/run/postgresql"),
        Ok(PgHost::Socket(_))
    ));
    assert!(matches!(parse_host("172.30.1.3"), Ok(PgHost::Ip(_))));
    assert!(matches!(parse_host("fd00::3"), Ok(PgHost::Ip(_))));
    for bad in [
        "postgres",
        "db.internal",
        "localhost",
        "",
        "run/postgresql",
        "[fd00::3]",
        "fe80::1%eth0",
    ] {
        assert_eq!(parse_host(bad), Err(PgConfigError::HostNotLiteral), "{bad}");
    }
    for bad in ["/run/../etc", "/run/pg/..", "/run/p\0g"] {
        assert_eq!(
            parse_host(bad),
            Err(PgConfigError::SocketPathInvalid),
            "{bad:?}"
        );
    }
    assert_eq!(
        raw("postgres", "nzbd", "nzbd_app")
            .validate()
            .unwrap_err()
            .code(),
        "DB_HOST_NOT_LITERAL"
    );
}

#[test]
fn sec_086_db_ip_literal_must_be_internal() {
    for ok in [
        "127.0.0.1",
        "127.8.9.10",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "::1",
        "fd00::3",
        "fc00::1",
    ] {
        assert!(ip_is_internal(ok.parse::<IpAddr>().unwrap()), "{ok}");
    }
    for bad in [
        "8.8.8.8",
        "1.1.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "169.254.1.1",
        "172.32.0.1",
        "100.128.0.1",
        "::",
        "2001:db8::1",
        "fe80::1",
        "ff02::1",
        "::ffff:10.0.0.1",
    ] {
        assert!(!ip_is_internal(bad.parse::<IpAddr>().unwrap()), "{bad}");
        assert_eq!(
            parse_host(bad),
            Err(PgConfigError::HostNotInternal),
            "{bad}"
        );
    }
}

#[test]
fn sec_086_db_identifiers_are_validated() {
    for ok in ["nzbd", "nzbd_app", "_x", "a1", &"a".repeat(63)] {
        assert!(check_identifier(ok, "db.name").is_ok(), "{ok}");
    }
    for bad in [
        "",
        "Nzbd",
        "1nzbd",
        "nzbd-app",
        "nzbd app",
        "nzbd\0options=-c",
        "nzbd;",
        &"a".repeat(64),
        "é",
    ] {
        assert_eq!(
            check_identifier(bad, "db.user"),
            Err(PgConfigError::IdentifierInvalid("db.user")),
            "{bad:?}"
        );
    }
    let e = raw("/run/postgresql", "nzbd\0x", "nzbd_app")
        .validate()
        .unwrap_err();
    assert_eq!(e.code(), "DB_IDENTIFIER_INVALID");
    let e = raw("/run/postgresql", "nzbd", "NZBD")
        .validate()
        .unwrap_err();
    assert_eq!(e, PgConfigError::IdentifierInvalid("db.user"));
    let ok = raw("/run/postgresql", "nzbd", "nzbd_app")
        .validate()
        .unwrap();
    assert_eq!(ok.pool_web, 16);
    let mut big = raw("/run/postgresql", "nzbd", "nzbd_app");
    big.pool_web = 65;
    assert_eq!(
        big.validate().unwrap_err().code(),
        "DB_SETTING_OUT_OF_RANGE"
    );
}

#[test]
fn sec_086_pg_and_ssl_cert_environment_variables_are_refused() {
    let env = |pairs: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    };
    assert!(check_environment(env(&[("HOME", "/home/x"), ("PATH", "/bin"), ("PGX", "1")])).is_ok());
    for var in REFUSED_ENV_VARS {
        let e = check_environment(env(&[("HOME", "/h"), (var, "")])).unwrap_err();
        assert_eq!(e.code(), "DB_ENV_AMBIGUOUS");
        assert_eq!(e, PgConfigError::EnvAmbiguous(var.to_owned()));
    }
    // Names only, sorted, never the value.
    let e = check_environment(env(&[
        ("PGPASSWORD", "hunter2-secret"),
        ("PGHOST", "evil.example"),
    ]))
    .unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("PGHOST,PGPASSWORD"), "{msg}");
    assert!(
        !msg.contains("hunter2") && !msg.contains("evil.example"),
        "{msg}"
    );
}

#[test]
fn sec_086_connect_options_ignore_pgpass_and_service_files() {
    let s = raw("/run/postgresql", "nzbd", "nzbd_app")
        .validate()
        .unwrap();
    let o = connect_options(
        &s,
        "nzbd_app",
        "pw",
        PoolKind::Web,
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        o.get_socket().map(std::path::PathBuf::as_path),
        Some(Path::new("/run/postgresql"))
    );
    assert_eq!(o.get_port(), 5432);
    assert_eq!(o.get_username(), "nzbd_app");
    assert_eq!(o.get_database(), Some("nzbd"));
    assert!(matches!(
        o.get_ssl_mode(),
        sqlx::postgres::PgSslMode::Disable
    ));
    assert_eq!(o.get_application_name(), Some("nzbd-web"));
    let opts = o.get_options().unwrap_or_default().to_owned();
    for want in [
        "statement_timeout=5000",
        "lock_timeout=5000",
        "idle_in_transaction_session_timeout=60000",
        "search_path=nzbd,pg_temp",
        "timezone=UTC",
        "jit=off",
    ] {
        assert!(opts.contains(want), "{want} missing in {opts}");
    }
    // The options are never printed with the password through our handle types.
    let ip = raw("10.1.2.3", "nzbd", "nzbd_app").validate().unwrap();
    let o = connect_options(
        &ip,
        "nzbd_app",
        "pw",
        PoolKind::Ingest,
        std::time::Duration::from_secs(30),
    );
    assert_eq!(o.get_host(), "10.1.2.3");
    assert_eq!(o.get_application_name(), Some("nzbd-ingest"));
}

// ---------------------------------------------------------------------------------------------------------------
// SEC-042 rules for the database password file.

#[test]
fn sec_042_db_secret_files_follow_the_key_file_rules() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pw");
    std::fs::write(&p, "s3cret-Value\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(read_password_file(&p).unwrap().as_str(), "s3cret-Value");

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let e = read_password_file(&p).unwrap_err();
    assert_eq!(e.code(), "DB_PASSWORD_FILE");
    assert!(!e.to_string().contains("s3cret"), "{e}");

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(
        read_password_file(&link)
            .unwrap_err()
            .to_string()
            .contains("symbolic link")
    );

    let empty = dir.path().join("empty");
    std::fs::write(&empty, "\n").unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(
        read_password_file(&empty)
            .unwrap_err()
            .to_string()
            .contains("empty")
    );

    let two = dir.path().join("two");
    std::fs::write(&two, "a\nb\n").unwrap();
    std::fs::set_permissions(&two, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(read_password_file(&two).is_err());

    assert!(
        read_password_file(dir.path()).is_err(),
        "a directory is not a password file"
    );
    assert!(read_password_file(&dir.path().join("missing")).is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// Harness, readiness gate, migrations never run by serve (M4).

#[tokio::test]
async fn harness_database_is_ready_and_seeded() {
    let t = TestDb::new().await;
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::Ready);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM category")
        .fetch_one(t.db.web())
        .await
        .unwrap();
    let seed = crate::taxonomy::seed_rows().unwrap();
    assert_eq!(usize::try_from(n).unwrap(), seed.len());
    let stats: i64 = sqlx::query_scalar("SELECT count(*) FROM category_stats")
        .fetch_one(t.db.web())
        .await
        .unwrap();
    assert_eq!(stats, n);
    let who: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(t.db.web())
        .await
        .unwrap();
    assert_eq!(who, "nzbd_app");
    let app: String = sqlx::query_scalar("SELECT current_setting('application_name')")
        .fetch_one(t.db.ingest())
        .await
        .unwrap();
    assert_eq!(app, "nzbd-ingest");
}

/// T146: a library seeded with the older taxonomy gets the new categories when the owner migrates again.
#[tokio::test]
async fn t146_old_library_gets_new_categories_on_migrate() {
    let t = TestDb::new().await;
    let mut o = t.owner_conn().await;
    for q in [
        "DELETE FROM category_stats WHERE category_id IN (1010, 1020, 1030, 4010, 4020, 4500, 4510, 4520, 7040)",
        "DELETE FROM category WHERE id IN (1010, 1020, 1030, 4010, 4020, 4500, 4510, 4520, 7040)",
    ] {
        sqlx::query(q).execute(&mut o).await.unwrap();
    }
    sqlx::Connection::close(o).await.unwrap();
    crate::pg::migrate_as_owner(t.owner_options())
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM category")
        .fetch_one(t.db.web())
        .await
        .unwrap();
    assert_eq!(
        usize::try_from(n).unwrap(),
        crate::taxonomy::seed_rows().unwrap().len()
    );
    let stats: i64 = sqlx::query_scalar("SELECT count(*) FROM category_stats")
        .fetch_one(t.db.web())
        .await
        .unwrap();
    assert_eq!(stats, n);
}

#[tokio::test]
async fn advisory_lock_constants_match_the_schema() {
    let t = TestDb::new().await;
    let (ns, acct): (i32, i32) =
        sqlx::query_as("SELECT nzbd.lock_namespace(), nzbd.account_domain_key()")
            .fetch_one(t.db.web())
            .await
            .unwrap();
    assert_eq!((ns, acct), (LOCK_NAMESPACE, LOCK_ACCOUNT_DOMAIN));
}

#[tokio::test]
async fn sec_087_serve_never_runs_migrations() {
    let t = TestDb::new().await;
    // A second, empty database: bootstrap only, no migration. Connecting the app role must not create anything.
    let name = format!("{}_empty", t.name);
    let mut su = t.superuser_conn().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{name}\" TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"
    )))
    .execute(&mut su)
    .await
    .unwrap();
    let server = crate::pg::testing::Server::from_env();
    {
        use sqlx::ConnectOptions as _;
        let mut c = server.superuser_options(&name).connect().await.unwrap();
        sqlx::raw_sql(crate::pg::testing::ROLES_SQL)
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
    }
    let db = PgDb::connect(
        &server.settings(&name),
        crate::pg::testing::TEST_APP_PASSWORD,
    )
    .await
    .unwrap();
    match db.readiness().await.unwrap() {
        Readiness::MigrationsPending(v) => assert_eq!(v.len(), crate::pg::MIGRATOR.iter().count()),
        other => panic!("expected pending migrations, got {other:?}"),
    }
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'nzbd'",
    )
    .fetch_one(db.web())
    .await
    .unwrap();
    assert_eq!(tables, 0, "connecting must never migrate");
    db.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE \"{name}\" WITH (FORCE)"
    )))
    .execute(&mut su)
    .await
    .unwrap();
}

#[tokio::test]
async fn readiness_refuses_pending_migrations_newer_schema_and_pending_restore() {
    let t = TestDb::new().await;
    let mut su = t.superuser_conn().await;
    let last: i64 = sqlx::query_scalar("SELECT max(version) FROM nzbd._sqlx_migrations")
        .fetch_one(&mut su)
        .await
        .unwrap();
    // A ledger row this binary does not know: a newer release wrote the database.
    sqlx::query(
        "INSERT INTO nzbd._sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (99999, 'future', true, '\\x00', 0)",
    )
    .execute(&mut su)
    .await
    .unwrap();
    assert_eq!(
        t.db.readiness().await.unwrap(),
        Readiness::SchemaNewer(99999)
    );
    sqlx::query("DELETE FROM nzbd._sqlx_migrations WHERE version IN (99999, $1)")
        .bind(last)
        .execute(&mut su)
        .await
        .unwrap();
    let r = t.db.readiness().await.unwrap();
    assert_eq!(r, Readiness::MigrationsPending(vec![last]));
    assert_eq!(r.code(), Some("MIGRATIONS_PENDING"));
    su.close().await.unwrap();

    // Restore pending (SEC-094, review L7): only the owner can set it; only restore_finish (cleanup + mark) clears it.
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    let e = sqlx::query("UPDATE db_state SET restore_pending = true")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42501");
    let mut owner = t.owner_conn().await;
    sqlx::query("UPDATE db_state SET restore_pending = true, restored_at = 1")
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::RestorePending);
    sqlx::query("SELECT * FROM nzbd.restore_finish()")
        .execute(&mut app)
        .await
        .unwrap();
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::Ready);
}

// ---------------------------------------------------------------------------------------------------------------
// SEC-087 / SEC-088: least privilege and definer-function hygiene (review L4).

#[tokio::test]
async fn sec_087_app_role_cannot_run_ddl() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    for stmt in [
        "CREATE TABLE nzbd.x (a int)",
        "CREATE TABLE public.x (a int)",
        "CREATE TEMP TABLE x (a int)",
        "CREATE SCHEMA evil",
        "ALTER TABLE release ADD COLUMN x int",
        "DROP TABLE release_trash",
        "TRUNCATE release",
        "TRUNCATE search_outbox",
        "CREATE FUNCTION nzbd.f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "CREATE OR REPLACE FUNCTION nzbd.db_clock() RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint'",
        "INSERT INTO category (id, name) VALUES (99998, 'x')",
        "UPDATE category SET name = 'x' WHERE id = 5040",
        "CREATE INDEX ON release (title)",
    ] {
        let e = sqlx::raw_sql(stmt).execute(&mut app).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{stmt}: {e}");
    }
    let attrs: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles \
         WHERE rolname = 'nzbd_app'",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    assert_eq!(attrs, (false, false, false, false, false));
}

#[tokio::test]
async fn sec_087_app_role_cannot_delete_accounts_or_touch_audit_rows() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    sqlx::query(
        "SELECT nzbd.audit_append(1, 'a', 'login.ok', NULL, NULL, NULL, 'user', NULL, NULL)",
    )
    .execute(&mut app)
    .await
    .unwrap();
    for stmt in [
        "DELETE FROM account",
        "INSERT INTO audit_log (ts, event) VALUES (1, 'forged')",
        "UPDATE audit_log SET detail = 'x'",
        "DELETE FROM audit_log",
        "UPDATE audit_chain_state SET rows = 0",
        "DELETE FROM audit_chain_state",
        "UPDATE retention_policy SET log_days = 9999",
        "UPDATE db_state SET restore_pending = false",
        "DELETE FROM ingest_log",
        "UPDATE nzbd._sqlx_migrations SET success = false",
        "UPDATE ingest_log SET ts = 0",
    ] {
        let e = sqlx::query(stmt).execute(&mut app).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{stmt}: {e}");
    }
    // Even the owner cannot rewrite audit content (trigger).
    let mut owner = t.owner_conn().await;
    let e = sqlx::query("UPDATE audit_log SET detail = 'x'")
        .execute(&mut owner)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("immutable"), "{e}");
}

#[tokio::test]
async fn sec_088_definer_functions_are_not_executable_by_public() {
    let t = TestDb::new().await;
    let mut su = t.superuser_conn().await;
    // proacl NULL means the default ACL, which includes EXECUTE for PUBLIC.
    let public_exec: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'nzbd' AND (p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a \
         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')) ORDER BY 1",
    )
    .fetch_all(&mut su)
    .await
    .unwrap();
    assert!(
        public_exec.is_empty(),
        "PUBLIC can execute: {public_exec:?}"
    );
    // Every SECURITY DEFINER function is owned by nzbd_owner, executable by nzbd_app, and only by it.
    let definers: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT p.proname::text, pg_get_userbyid(p.proowner)::text, \
                has_function_privilege('nzbd_app', p.oid, 'EXECUTE') \
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'nzbd' AND p.prosecdef ORDER BY 1",
    )
    .fetch_all(&mut su)
    .await
    .unwrap();
    let names: Vec<&str> = definers.iter().map(|d| d.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "audit_append",
            "audit_purge",
            "ensure_file_partitions",
            "ensure_log_partitions",
            "log_retention_apply",
            "restore_finish"
        ]
    );
    for (name, owner, app) in &definers {
        assert_eq!(owner, "nzbd_owner", "{name}");
        assert!(app, "{name}");
    }
    // PUBLIC has no CREATE/USAGE on schema public, no CONNECT/TEMP on the database.
    let (pub_create, pub_usage): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public' \
                        AND a.grantee = 0 AND a.privilege_type = 'CREATE'), \
                EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public' \
                        AND a.grantee = 0 AND a.privilege_type = 'USAGE')",
    )
    .fetch_one(&mut su)
    .await
    .unwrap();
    assert!(!pub_create && !pub_usage);
    let db_public: Vec<String> = sqlx::query_scalar(
        "SELECT a.privilege_type::text FROM pg_database d, aclexplode(d.datacl) a \
         WHERE d.datname = current_database() AND a.grantee = 0",
    )
    .fetch_all(&mut su)
    .await
    .unwrap();
    assert!(
        db_public.is_empty(),
        "PUBLIC database privileges: {db_public:?}"
    );
}

#[tokio::test]
async fn sec_088_definer_functions_pin_search_path() {
    let t = TestDb::new().await;
    let mut su = t.superuser_conn().await;
    let rows: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
        "SELECT p.proname::text, p.proconfig::text[] FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'nzbd' ORDER BY 1",
    )
    .fetch_all(&mut su)
    .await
    .unwrap();
    assert!(rows.len() > 10);
    for (name, cfg) in rows {
        let cfg = cfg.unwrap_or_default();
        assert!(
            cfg.iter().any(|c| c == "search_path=nzbd, pg_temp"),
            "{name}: {cfg:?}"
        );
    }
}

async fn parts(c: &mut sqlx::PgConnection) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
         WHERE i.inhparent = 'nzbd.nzb_file'::regclass ORDER BY 1",
    )
    .fetch_all(c)
    .await
    .unwrap()
}

#[tokio::test]
async fn sec_088_partition_function_clamps_its_argument() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    assert_eq!(parts(&mut app).await, ["nzb_file_p000000"]);
    // A huge request is clamped to the release sequence + 20M: partitions 0..=2 only, never millions.
    let created: i32 =
        sqlx::query_scalar("SELECT nzbd.ensure_file_partitions(9000000000000000000)")
            .fetch_one(&mut app)
            .await
            .unwrap();
    assert_eq!(created, 2);
    assert_eq!(
        parts(&mut app).await,
        ["nzb_file_p000000", "nzb_file_p000001", "nzb_file_p000002"]
    );
    let neg: i32 = sqlx::query_scalar("SELECT nzbd.ensure_file_partitions(-5)")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(neg, 0);
    // `SECURITY_REVIEW` 31 L1: an explicit id written by the app role does not move the clamp (it follows the
    // sequence, which the app can only advance by inserting rows). Before the fix this created 50 partitions.
    sqlx::query(
        "INSERT INTO release (id, sha256, title, category_id, ingested_at, total_bytes, file_count, \
         segment_count, nzb_size_bytes) VALUES (500000000, sha256('big'::bytea), 't', 5040, 1, 0, 0, 0, 0)",
    )
    .execute(&mut app)
    .await
    .unwrap();
    let created: i32 = sqlx::query_scalar("SELECT nzbd.ensure_file_partitions(500000000)")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(created, 0);
    assert_eq!(parts(&mut app).await.len(), 3);
    // Six-digit names: an index beyond 999999 is refused instead of colliding (the sequence itself can only be moved
    // that far by the owner or the superuser, e.g. a restore of such ids).
    let mut su = t.superuser_conn().await;
    sqlx::query("SELECT setval('nzbd.release_id_seq', 10000000000000)")
        .execute(&mut su)
        .await
        .unwrap();
    let e = sqlx::query("SELECT nzbd.ensure_file_partitions(10000000000000)")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("PARTITION_INDEX_OUT_OF_RANGE"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// SEC-080 / SEC-093: audit chain in SQL.

async fn sql_hash(
    c: &mut sqlx::PgConnection,
    class: i64,
    prev: &[u8; 32],
    a: &AuditContent<'_>,
) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT nzbd.audit_chain_hash($1::smallint, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(i16::try_from(class).unwrap())
    .bind(prev.as_slice())
    .bind(a.ts)
    .bind(a.actor)
    .bind(a.event)
    .bind(a.detail)
    .bind(a.ip)
    .bind(a.actor_id)
    .bind(a.actor_kind)
    .bind(a.actor_role)
    .bind(a.target_id)
    .fetch_one(c)
    .await
    .unwrap()
}

#[test]
fn sec_080_sql_hash_equals_rust_hash() {
    use proptest::prelude::*;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (t, conn) = rt.block_on(async {
        let t = TestDb::new().await;
        let c = t.app_conn().await;
        (t, c)
    });
    let conn = std::cell::RefCell::new(conn);
    // NUL-free text (Postgres text cannot hold NUL; sanitize_text removes it upstream), hostile content otherwise:
    // separators, tags, multi-byte characters, max-length fields, and NULL in every optional position.
    let text = || proptest::option::of("[^\u{0}]{0,64}|\\x01\\x02|[^\u{0}]{200,400}");
    let kind = proptest::option::of(proptest::sample::select(vec![
        "user",
        "cli",
        "system",
        "api_key",
        "anonymous",
    ]));
    let role = proptest::option::of(proptest::sample::select(vec![
        "admin", "uploader", "viewer",
    ]));
    let event = proptest::sample::select(vec![
        "login.ok",
        "user_create",
        "download",
        "role_change",
        "x",
    ]);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    });
    runner
        .run(
            &(
                any::<i64>(),
                text(),
                event,
                text(),
                text(),
                any::<Option<i64>>(),
                kind,
                role,
                any::<Option<i64>>(),
                any::<[u8; 32]>(),
            ),
            |(ts, actor, event, detail, ip, actor_id, kind, role, target, prev)| {
                let a = AuditContent {
                    ts,
                    actor: actor.as_deref(),
                    event,
                    detail: detail.as_deref(),
                    ip: ip.as_deref(),
                    actor_id,
                    actor_kind: kind,
                    actor_role: role,
                    target_id: target,
                };
                let class = class_of(event);
                let want = chain_hash(class, &prev, &a).to_vec();
                let got = rt.block_on(sql_hash(&mut conn.borrow_mut(), class, &prev, &a));
                prop_assert_eq!(got, want);
                Ok(())
            },
        )
        .unwrap();
    // The event list deciding the class is the Rust constant.
    for e in crate::ACCOUNT_AUDIT_EVENTS {
        let c: i16 = rt
            .block_on(
                sqlx::query_scalar("SELECT nzbd.audit_class_of($1)")
                    .bind(e)
                    .fetch_one(&mut *conn.borrow_mut()),
            )
            .unwrap();
        assert_eq!(i64::from(c), class_of(e), "{e}");
        assert_eq!(c, 1, "{e}");
    }
    let c: i16 = rt
        .block_on(
            sqlx::query_scalar("SELECT nzbd.audit_class_of('download')")
                .fetch_one(&mut *conn.borrow_mut()),
        )
        .unwrap();
    assert_eq!(c, 0);
    drop(conn);
    drop(t);
}

/// Walks every chained row of `class` and checks links and hashes with the Rust definition.
async fn verify_class(c: &mut sqlx::PgConnection, class: i16) -> usize {
    let (floor, head, rows): (Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
        "SELECT floor_hash, head_hash, rows FROM audit_chain_state WHERE class = $1",
    )
    .bind(class)
    .fetch_one(&mut *c)
    .await
    .unwrap();
    let all = sqlx::query(
        "SELECT ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id, chain_prev, chain_hash \
         FROM audit_log WHERE chain_class = $1 ORDER BY id",
    )
    .bind(class)
    .fetch_all(&mut *c)
    .await
    .unwrap();
    let mut prev: [u8; 32] = floor.try_into().unwrap();
    for r in &all {
        let stored_prev: Vec<u8> = r.get("chain_prev");
        assert_eq!(stored_prev, prev.to_vec(), "gap");
        let actor: Option<String> = r.get("actor");
        let event: String = r.get("event");
        let detail: Option<String> = r.get("detail");
        let ip: Option<String> = r.get("ip");
        let kind: Option<String> = r.get("actor_kind");
        let role: Option<String> = r.get("actor_role");
        let a = AuditContent {
            ts: r.get("ts"),
            actor: actor.as_deref(),
            event: &event,
            detail: detail.as_deref(),
            ip: ip.as_deref(),
            actor_id: r.get("actor_id"),
            actor_kind: kind.as_deref(),
            actor_role: role.as_deref(),
            target_id: r.get("target_id"),
        };
        let h = chain_hash(i64::from(class), &prev, &a);
        let stored: Vec<u8> = r.get("chain_hash");
        assert_eq!(stored, h.to_vec(), "edited");
        prev = h;
    }
    assert_eq!(head, prev.to_vec(), "head");
    assert_eq!(usize::try_from(rows).unwrap(), all.len(), "rows");
    all.len()
}

#[tokio::test]
async fn sec_093_appends_serialize_across_connections() {
    let t = TestDb::new().await;
    let pool = t.app_pool(8).await;
    let mut tasks = Vec::new();
    for w in 0..8_i64 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..25_i64 {
                let mut tx = pool.begin().await.unwrap();
                let ev = if i % 5 == 0 {
                    "user_create"
                } else {
                    "download"
                };
                sqlx::query(
                    "SELECT nzbd.audit_append($1, $2, $3, NULL, NULL, $4, 'user', 'admin', NULL)",
                )
                .bind(w * 1000 + i)
                .bind(format!("w{w}"))
                .bind(ev)
                .bind(w)
                .execute(&mut *tx)
                .await
                .unwrap();
                if i % 7 == 3 {
                    tx.rollback().await.unwrap(); // a rolled-back caller leaves no trace in the chain
                } else {
                    tx.commit().await.unwrap();
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut c = t.app_conn().await;
    let n0 = verify_class(&mut c, 0).await;
    let n1 = verify_class(&mut c, 1).await;
    // Per worker: 25 appends, i in {3, 10, 17, 24} rolled back; 5 of 25 are class 1 (i = 0, 5, 10, 15, 20), i=10
    // rolled back.
    assert_eq!(n1, 8 * 4);
    assert_eq!(n0 + n1, 8 * 21);
}

#[tokio::test]
async fn sec_093_app_role_cannot_purge_inside_the_retention_window() {
    let t = TestDb::new().await;
    let now = 1_800_000_000_i64;
    t.set_db_clock(now).await;
    let mut app = t.app_conn().await;
    for (age_days, ev) in [
        (400, "download"),
        (200, "download"),
        (100, "user_create"),
        (10, "download"),
        (1, "user_create"),
    ] {
        sqlx::query("SELECT nzbd.audit_append($1, 'a', $2, NULL, NULL, NULL, 'user', NULL, NULL)")
            .bind(now - age_days * 86_400)
            .bind(ev)
            .execute(&mut app)
            .await
            .unwrap();
    }
    // The purge takes no cutoff: default policy 90 / 365 days from the DATABASE clock.
    let n0: i64 = sqlx::query_scalar("SELECT nzbd.audit_purge(0::smallint)")
        .fetch_one(&mut app)
        .await
        .unwrap();
    let n1: i64 = sqlx::query_scalar("SELECT nzbd.audit_purge(1::smallint)")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(
        (n0, n1),
        (2, 0),
        "the 400- and 200-day log rows go; account rows are inside 365 days"
    );
    let left: Vec<i64> = sqlx::query_scalar("SELECT ts FROM audit_log ORDER BY id")
        .fetch_all(&mut app)
        .await
        .unwrap();
    assert_eq!(left, [now - 100 * 86_400, now - 10 * 86_400, now - 86_400]);
    assert_eq!(verify_class(&mut app, 0).await, 1);
    assert_eq!(verify_class(&mut app, 1).await, 2);
    // Moving the app's own notion of time changes nothing: there is no argument to pass.
    let e = sqlx::query("SELECT nzbd.audit_purge(0::smallint, 0)")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42883");
    let e = sqlx::query("SELECT nzbd.audit_purge(7::smallint)")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("AUDIT_CLASS_INVALID"));
}

#[tokio::test]
async fn sec_093_retention_policy_is_owner_only_with_floors() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    let e = sqlx::query("UPDATE retention_policy SET log_days = 1")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42501");
    let mut owner = t.owner_conn().await;
    for stmt in [
        "UPDATE retention_policy SET log_days = 89",
        "UPDATE retention_policy SET account_days = 364",
        "UPDATE retention_policy SET ingest_days = 0",
        "INSERT INTO retention_policy (id) VALUES (2)",
    ] {
        let e = sqlx::query(stmt).execute(&mut owner).await.unwrap_err();
        assert_eq!(sqlstate(&e), "23514", "{stmt}");
    }
    sqlx::query("UPDATE retention_policy SET log_days = 90, account_days = 400, ingest_days = 1")
        .execute(&mut owner)
        .await
        .unwrap();
}

#[tokio::test]
async fn sec_093_purge_is_prefix_only() {
    let t = TestDb::new().await;
    let now = 1_800_000_000_i64;
    t.set_db_clock(now).await;
    let mut app = t.app_conn().await;
    // old, young, old: the old row AFTER a young one is not removed (prefix rule), and a far-future row never pins.
    for age in [300_i64, 5, 300, -10] {
        sqlx::query("SELECT nzbd.audit_append($1, NULL, 'download', NULL, NULL, NULL, 'system', NULL, NULL)")
            .bind(now - age * 86_400)
            .execute(&mut app)
            .await
            .unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT nzbd.audit_purge(0::smallint)")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(verify_class(&mut app, 0).await, 3);
    let (floor, first_prev): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT s.floor_hash, (SELECT chain_prev FROM audit_log WHERE chain_class = 0 ORDER BY id LIMIT 1) \
         FROM audit_chain_state s WHERE class = 0",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    assert_eq!(floor, first_prev);
    assert_ne!(floor, GENESIS.to_vec());
}

#[tokio::test]
async fn sec_081_purge_runs_in_bounded_batches() {
    let t = TestDb::new().await;
    let now = 1_800_000_000_i64;
    t.set_db_clock(now).await;
    let mut app = t.app_conn().await;
    sqlx::query(
        "SELECT nzbd.audit_append($1 + g, NULL, 'download', NULL, NULL, NULL, 'system', NULL, NULL) \
         FROM generate_series(1, 10050) g",
    )
    .bind(now - 200 * 86_400)
    .execute(&mut app)
    .await
    .unwrap();
    let mut got = Vec::new();
    loop {
        let n: i64 = sqlx::query_scalar("SELECT nzbd.audit_purge(0::smallint)")
            .fetch_one(&mut app)
            .await
            .unwrap();
        got.push(n);
        assert_eq!(
            verify_class(&mut app, 0).await,
            usize::try_from(10050 - got.iter().sum::<i64>()).unwrap()
        );
        if n == 0 {
            break;
        }
    }
    assert_eq!(got, [10_000, 50, 0]);
}

#[tokio::test]
async fn ingest_log_partitions_follow_the_database_clock_and_retention_drops_months() {
    let t = TestDb::new().await;
    // 2027-03-15 12:00 UTC.
    let now = 1_805_112_000_i64;
    t.set_db_clock(now).await;
    let mut app = t.app_conn().await;
    let created: i32 = sqlx::query_scalar("SELECT nzbd.ensure_log_partitions()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(created, 3);
    let again: i32 = sqlx::query_scalar("SELECT nzbd.ensure_log_partitions()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(again, 0);
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
         WHERE i.inhparent = 'nzbd.ingest_log'::regclass ORDER BY 1",
    )
    .fetch_all(&mut app)
    .await
    .unwrap();
    assert_eq!(
        names,
        [
            "ingest_log_default",
            "ingest_log_y2027m03",
            "ingest_log_y2027m04",
            "ingest_log_y2027m05"
        ]
    );
    // Rows: one in March 2027 (partition), two far in the past (DEFAULT partition).
    for ts in [now - 3600, now - 200 * 86_400, now - 100 * 86_400] {
        sqlx::query("INSERT INTO ingest_log (ts, source, outcome) VALUES ($1, 'watch', 'ok')")
            .bind(ts)
            .execute(&mut app)
            .await
            .unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT nzbd.log_retention_apply()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(n, 2, "both rows older than 90 days go");
    // Move the clock 5 months ahead: the March..May partitions are older than 90 days and are dropped whole.
    t.set_db_clock(now + 200 * 86_400).await;
    let n: i64 = sqlx::query_scalar("SELECT nzbd.log_retention_apply()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
         WHERE i.inhparent = 'nzbd.ingest_log'::regclass ORDER BY 1",
    )
    .fetch_all(&mut app)
    .await
    .unwrap();
    assert_eq!(names, ["ingest_log_default"]);
    // keep_all disables it entirely.
    let mut owner = t.owner_conn().await;
    sqlx::query("UPDATE retention_policy SET keep_all = true")
        .execute(&mut owner)
        .await
        .unwrap();
    sqlx::query("INSERT INTO ingest_log (ts, source, outcome) VALUES (1, 'watch', 'ok')")
        .execute(&mut app)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT nzbd.log_retention_apply()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(n, 0);
    owner.close().await.unwrap();
}

#[tokio::test]
async fn account_triggers_keep_the_2x_rules() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    let ins = "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
               VALUES ($1, 'x', $2, 1, 1) RETURNING id";
    let a: i64 = sqlx::query_scalar(ins)
        .bind("alice")
        .bind("admin")
        .fetch_one(&mut app)
        .await
        .unwrap();
    // Reserved handle form, collisions (NOCASE), ON CONFLICT cannot replace.
    let e = sqlx::query(ins)
        .bind("User-12")
        .bind("viewer")
        .fetch_one(&mut app)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("RESERVED_LOGIN_NAME"), "{e}");
    let e = sqlx::query(ins)
        .bind("ALICE")
        .bind("viewer")
        .fetch_one(&mut app)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("ACCOUNT_ROWS_ARE_NEVER_REPLACED"),
        "{e}"
    );
    let e = sqlx::query(
        "INSERT INTO account (id, username, password_hash, created_at, password_changed_at) \
         VALUES ($1, 'bob', 'x', 1, 1) ON CONFLICT DO NOTHING",
    )
    .bind(a)
    .execute(&mut app)
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("ACCOUNT_ROWS_ARE_NEVER_REPLACED"),
        "{e}"
    );
    // Last admin.
    let e = sqlx::query("UPDATE account SET role = 'viewer' WHERE id = $1")
        .bind(a)
        .execute(&mut app)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("LAST_ADMIN"), "{e}");
    // Shape CHECKs (2.x 0011/0014 + display-name rule).
    for (col, val) in [
        ("username", "a b"),
        ("display_name", " lead"),
        ("email", "UP@x.io"),
        ("email", "a@b"),
        ("display_name", "x\u{7}y"),
    ] {
        let sql = match col {
            "username" => "UPDATE account SET username = $1 WHERE id = $2",
            "display_name" => "UPDATE account SET display_name = $1 WHERE id = $2",
            _ => "UPDATE account SET email = $1 WHERE id = $2",
        };
        let e = sqlx::query(sql)
            .bind(val)
            .bind(a)
            .execute(&mut app)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&e), "23514", "{col}={val:?}");
    }
    sqlx::query("UPDATE account SET email = 'a.b+c@x.io', display_name = 'Al ice' WHERE id = $1")
        .bind(a)
        .execute(&mut app)
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::many_single_char_names)]
async fn sec_062_raw_sql_demotions_in_two_sessions_cannot_both_commit() {
    let t = TestDb::new().await;
    let mut c1 = t.app_conn().await;
    let mut c2 = t.app_conn().await;
    let ins = "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
               VALUES ($1, 'x', 'admin', 1, 1) RETURNING id";
    let a: i64 = sqlx::query_scalar(ins)
        .bind("a1")
        .fetch_one(&mut c1)
        .await
        .unwrap();
    let b: i64 = sqlx::query_scalar(ins)
        .bind("b1")
        .fetch_one(&mut c1)
        .await
        .unwrap();
    // Session 1 demotes A and keeps its transaction open; session 2 demotes B and must wait for the trigger's lock,
    // then see A demoted and refuse.
    let mut tx1 = c1.begin().await.unwrap();
    sqlx::query("UPDATE account SET role = 'uploader' WHERE id = $1")
        .bind(a)
        .execute(&mut *tx1)
        .await
        .unwrap();
    let second = tokio::spawn(async move {
        let r = sqlx::query("UPDATE account SET role = 'uploader' WHERE id = $1")
            .bind(b)
            .execute(&mut c2)
            .await;
        (r.map(|_| ()).map_err(|e| e.to_string()), c2)
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !second.is_finished(),
        "the second demotion must wait for the first transaction"
    );
    tx1.commit().await.unwrap();
    let (r, _c2) = second.await.unwrap();
    let e = r.unwrap_err();
    assert!(e.contains("LAST_ADMIN"), "{e}");
    let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE role = 'admin'")
        .fetch_one(&mut c1)
        .await
        .unwrap();
    assert_eq!(admins, 1);
}

#[tokio::test]
async fn staging_triggers_delete_the_staged_credentials() {
    let t = TestDb::new().await;
    let mut c = t.app_conn().await;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
         VALUES ('m', 'x', 'uploader', 1, 1) RETURNING id",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    let inv: i64 = sqlx::query_scalar(
        "INSERT INTO invite (purpose, token_hash, account_id, created_via, created_at, expires_at) \
         VALUES ('recover', sha256('t'::bytea), $1, 'cli', 1, 100) RETURNING id",
    )
    .bind(id)
    .fetch_one(&mut c)
    .await
    .unwrap();
    let stage = |sess: &'static str| {
        format!(
            "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, expires_at) \
             VALUES (sha256('{sess}'::bytea), {id}, 'pending_mfa', sha256('c'::bytea), 1, 1, 100); \
             INSERT INTO credential_staging (account_id, session_hash, invite_id, password_hash, created_at, expires_at) \
             VALUES ({id}, sha256('{sess}'::bytea), {inv}, 'h', 1, 100);"
        )
    };
    sqlx::raw_sql(sqlx::AssertSqlSafe(stage("s1")))
        .execute(&mut c)
        .await
        .unwrap();
    sqlx::query("DELETE FROM session WHERE id_hash = sha256('s1'::bytea)")
        .execute(&mut c)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_staging")
        .fetch_one(&mut c)
        .await
        .unwrap();
    assert_eq!(n, 0, "staging dies with its session");
    sqlx::raw_sql(sqlx::AssertSqlSafe(stage("s2")))
        .execute(&mut c)
        .await
        .unwrap();
    sqlx::query("UPDATE account SET disabled_at = 5 WHERE id = $1")
        .bind(id)
        .execute(&mut c)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_staging")
        .fetch_one(&mut c)
        .await
        .unwrap();
    assert_eq!(n, 0, "staging dies with a credential/role/disabled change");
}

#[tokio::test]
async fn sec_093_app_role_cannot_bypass_audit_append() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    // No direct insert (no grant), no way to forge the chain columns, no way to move the head.
    for stmt in [
        "INSERT INTO audit_log (ts, event, chain_class, chain_prev, chain_hash) \
         VALUES (1, 'x', 0, sha256(''::bytea), sha256(''::bytea))",
        "UPDATE audit_chain_state SET head_hash = sha256('x'::bytea)",
        "SELECT nzbd.audit_enc_text('x'); DELETE FROM audit_log",
    ] {
        let e = sqlx::raw_sql(stmt).execute(&mut app).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{stmt}: {e}");
    }
    // The definer function computes class, link and hash itself: arguments cannot choose them.
    let id: i64 = sqlx::query_scalar(
        "SELECT nzbd.audit_append(5, 'cli', 'user_create', 'd', NULL, NULL, 'cli', NULL, 9)",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    let class: i16 = sqlx::query_scalar("SELECT chain_class FROM audit_log WHERE id = $1")
        .bind(id)
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(class, 1);
    assert_eq!(verify_class(&mut app, 1).await, 1);
    // Unknown actor kinds and roles are refused by the CHECKs inside the append.
    let e =
        sqlx::query("SELECT nzbd.audit_append(5, NULL, 'x', NULL, NULL, NULL, 'root', NULL, NULL)")
            .execute(&mut app)
            .await
            .unwrap_err();
    assert_eq!(sqlstate(&e), "23514");
}

#[tokio::test]
async fn sec_095_statement_timeout_is_set_on_every_pool() {
    let t = TestDb::new().await;
    let want_web = format!("{}ms", t.settings().statement_timeout.as_millis());
    for (pool, want, app) in [
        (t.db.web(), want_web.as_str(), "nzbd-web"),
        (t.db.ingest(), "30s", "nzbd-ingest"),
        (t.db.background(), "5min", "nzbd-background"),
    ] {
        let mut c = pool.acquire().await.unwrap();
        let st: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(&mut *c)
            .await
            .unwrap();
        let normalize = |v: &str| v.replace("60000ms", "1min");
        assert_eq!(normalize(&st), normalize(want), "{app}");
        for (setting, value) in [
            ("lock_timeout", "5s"),
            ("idle_in_transaction_session_timeout", "1min"),
            ("TimeZone", "UTC"),
            ("jit", "off"),
            ("application_name", app),
        ] {
            let v: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SHOW {setting}")))
                .fetch_one(&mut *c)
                .await
                .unwrap();
            assert_eq!(v, value, "{app} {setting}");
        }
        let sp: String = sqlx::query_scalar("SHOW search_path")
            .fetch_one(&mut *c)
            .await
            .unwrap();
        assert!(sp.starts_with("nzbd"), "{sp}");
    }
}

/// SEC-088 lint (`SECURITY_DELTA` 2.2, review 34 L3): in the store of BOTH backends, every statement handed to sqlx is
/// a string literal or a constant; `raw_sql` and `QueryBuilder` do not appear outside tests. sqlx-sqlite runs every
/// `;`-separated part of a statement and Postgres' simple protocol accepts several, so "no statement text is ever
/// built from input" is the only control. Scans the whole source tree, so a new file is covered without registration.
#[test]
#[allow(clippy::too_many_lines)] // one scan, one list of rules
fn sec_088_no_string_built_sql() {
    fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(files.len() >= 3, "scan found {files:?}");
    let mut bad = Vec::new();
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with("_tests.rs")
            || name == "testing.rs"
            || name == "tests.rs"
            || name.ends_with("testkit.rs")
            // Test-only (`cfg(any(test, feature = "pg-test-support"))`): the matrix legs' raw SQL helpers.
            || name == "test_backend.rs"
        {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap();
        // Skip an inline `#[cfg(test)] mod tests` block at the end of a file.
        let src = src
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default();
        for banned in ["raw_sql(", "QueryBuilder"] {
            if src.contains(banned) {
                bad.push(format!("{name}: {banned}"));
            }
        }
        for call in [
            "query(",
            "query_scalar(",
            "query_as(",
            "query_with(",
            "query_scalar_with(",
            "query_as_with(",
        ] {
            for (i, _) in src.match_indices(call) {
                // Only sqlx calls: `sqlx::query(` or a `query_as::<..>(` turbofish is matched by the generic form below.
                let before = &src[..i];
                if !before.ends_with("sqlx::") {
                    continue;
                }
                let rest = src[i + call.len()..].trim_start();
                let first = rest.chars().next().unwrap_or(' ');
                let literal =
                    rest.starts_with('"') || rest.starts_with("r\"") || rest.starts_with("r#\"");
                // A constant, `concat!` of literals and literal-producing macros (compile time only), or a field of
                // the `TABLES` constant of the snapshot backup (each field is such a `concat!`).
                let table_field = src.contains("const TABLES:")
                    && ["t.export", "t.import", "t.count"]
                        .iter()
                        .any(|f| rest.starts_with(f));
                let constant =
                    first.is_ascii_uppercase() || rest.starts_with("concat!(") || table_field;
                if !(literal || constant) {
                    let line = before.lines().count() + 1;
                    bad.push(format!(
                        "{name}:{line}: {call} with a non-literal statement"
                    ));
                }
            }
        }
        // Turbofish forms of every sqlx statement constructor (`query_scalar::<_, i64>(`, ...).
        for call in [
            "query",
            "query_scalar",
            "query_as",
            "query_with",
            "query_scalar_with",
            "query_as_with",
        ] {
            let pat = format!("sqlx::{call}::<");
            for (i, _) in src.match_indices(&pat) {
                let rest = &src[i..];
                let open = rest.find(">(").map_or("", |k| rest[k + 2..].trim_start());
                if !(open.starts_with('"')
                    || open.starts_with("concat!(")
                    || open.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                {
                    bad.push(format!("{name}: {call}::<..> with a non-literal statement"));
                }
            }
        }
        // COPY statements: literals, constants or the `TABLES` fields only.
        for call in ["copy_in_raw(", "copy_out_raw("] {
            for (i, _) in src.match_indices(call) {
                let rest = src[i + call.len()..].trim_start();
                let ok = rest.starts_with('"')
                    || rest.starts_with("concat!(")
                    || rest.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    || (src.contains("const TABLES:")
                        && ["t.export", "t.import"].iter().any(|f| rest.starts_with(f)));
                if !ok {
                    bad.push(format!("{name}: {call} with a non-literal statement"));
                }
            }
        }
        // `Executor::execute(&str)` / `fetch_*(&str)`: a statement handed straight to an executor must not be built
        // at run time either.
        for call in [
            ".execute(",
            ".fetch_one(",
            ".fetch_all(",
            ".fetch_optional(",
            ".fetch(",
        ] {
            for (i, _) in src.match_indices(call) {
                let rest = &src[i + call.len()..];
                let arg: String = rest.chars().take_while(|c| *c != ')').collect();
                if ["format!", "String::", "to_string()", "push_str", ".concat("]
                    .iter()
                    .any(|b| arg.contains(b))
                {
                    bad.push(format!("{name}: {call} with a run-time built argument"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "string-built SQL in the v3 store: {bad:#?}");
}

/// SEC-087 (review M4): `serve` refuses to run while an owner secret is readable by its uid.
#[test]
fn sec_087_serve_refuses_a_readable_owner_secret() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let readable = dir.path().join("owner");
    std::fs::write(&readable, "owner-pw").unwrap();
    std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o400)).unwrap();
    let e = crate::pg::config::refuse_readable_owner_secret(&[readable.as_path()]).unwrap_err();
    assert_eq!(e.code(), "OWNER_SECRET_VISIBLE");
    assert!(!e.to_string().contains("owner-pw"), "{e}");
    // Not mounted (the documented path does not exist here) or not readable by this uid: fine.
    let missing = dir.path().join("missing");
    assert!(crate::pg::config::refuse_readable_owner_secret(&[missing.as_path()]).is_ok());
    std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&readable).is_err() {
        assert!(crate::pg::config::refuse_readable_owner_secret(&[readable.as_path()]).is_ok());
    }
}

/// SEC-087: a wrong or right database password never appears in an error or in `Debug` of the handles.
#[tokio::test]
async fn sec_087_db_password_never_in_logs_or_errors() {
    let t = TestDb::new().await;
    let secret = "hunter2-Wrong-db-password";
    let err = PgDb::connect(&t.settings(), secret).await.unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(!shown.contains(secret), "{shown}");
    assert!(
        shown.contains("28P01"),
        "authentication failure is reported by SQLSTATE: {shown}"
    );
    let shown = format!("{:?} {:?}", t.db, t.settings());
    assert!(
        !shown.contains(crate::pg::testing::TEST_APP_PASSWORD),
        "{shown}"
    );
    // The password file reader's errors name the file and a fixed reason only.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pw");
    std::fs::write(&p, secret).unwrap();
    let e = read_password_file(&p).unwrap_err();
    assert!(!e.to_string().contains(secret));
}

/// ARCHITECTURE v3 section 6 (lock order lint): in the v3 store, no function both takes the account-domain lock and
/// locks release rows, and no function locks release rows or `category_stats` after it appended an audit row (the
/// audit class lock must be the last lock before `COMMIT`).
#[test]
fn lock_order_lint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.extension().is_none_or(|x| x != "rs") || name == "testing.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&p).unwrap();
        for (i, body) in src.split("async fn ").enumerate().skip(1) {
            let fn_name: String = body
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let account = body
                .find("begin_account()")
                .or_else(|| body.find("lock_account_domain("));
            let release_lock = body
                .find("FOR UPDATE\"")
                .or_else(|| body.find("lock_release("))
                .filter(|_| {
                    body.contains("FROM release")
                        || body.contains("lock_release(")
                        || body.contains("load_visible(")
                });
            if account.is_some() && release_lock.is_some() {
                bad.push(format!(
                    "{name}#{i} {fn_name}: account lock and release row locks"
                ));
            }
            if let Some(audit) = body
                .find("write_audit(")
                .or_else(|| body.find("write_audit_legacy("))
            {
                for later in [
                    "FOR UPDATE",
                    "apply_stats(",
                    "lock_release(",
                    "begin_account()",
                ] {
                    if body[audit..].contains(later) {
                        bad.push(format!(
                            "{name}#{i} {fn_name}: {later} after an audit append"
                        ));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "lock order violations: {bad:#?}");
}

/// SEC-095: no expensive work under the account-domain lock. The store never hashes passwords (no Argon2 in this
/// crate: callers verify before they call the verdict), and no function that takes the lock touches the filesystem,
/// spawns blocking work or sleeps; a transaction holding it only runs SQL.
#[test]
fn sec_095_no_long_work_under_account_lock() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for dep in ["argon2", "password-hash", "scrypt", "bcrypt"] {
        assert!(!manifest.contains(dep), "{dep} in nzb-store");
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg");
    let mut checked = 0;
    for entry in std::fs::read_dir(&root).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).unwrap();
        for body in src.split("async fn ").skip(1) {
            if !(body.contains("begin_account()") || body.contains("lock_account_domain(")) {
                continue;
            }
            checked += 1;
            for slow in [
                "std::fs",
                "File::",
                "spawn_blocking",
                "sleep(",
                "argon2",
                "read_password_file",
            ] {
                assert!(
                    !body.contains(slow),
                    "{slow} under the account lock in {}",
                    p.display()
                );
            }
        }
    }
    assert!(checked > 30, "only {checked} locked functions found");
}

/// `SECURITY_REVIEW` 31 L2: the app role cannot make a restored database servable without the SEC-068 effects: the mark
/// alone does not exist any more, and the one function that clears it performs the whole cleanup atomically.
#[tokio::test]
async fn sec_068_restore_mark_cannot_be_cleared_without_its_effects() {
    let t = TestDb::new().await;
    let mut app = t.app_conn().await;
    let a: i64 = sqlx::query_scalar(
        "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
         VALUES ('root', 'x', 'admin', 1, 1) RETURNING id",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, expires_at) \
         VALUES (sha256('s'::bytea), {a}, 'active', sha256('c'::bytea), 1, 1, 9999999999); \
         INSERT INTO api_key (name, prefix, key_hash, created_at, owner_id) VALUES ('k', 'p', sha256('k'::bytea), 1, {a});"
    )))
    .execute(&mut app)
    .await
    .unwrap();
    let mut owner = t.owner_conn().await;
    sqlx::query("UPDATE db_state SET restore_pending = true WHERE id = 1")
        .execute(&mut owner)
        .await
        .unwrap();
    // The old mark-only function is gone; the state row stays owner-only.
    let e = sqlx::query("SELECT nzbd.restore_finish_mark()")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42883", "{e}");
    let e = sqlx::query("UPDATE db_state SET restore_pending = false")
        .execute(&mut app)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42501");
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::RestorePending);
    // The app role may call the combined function, but then the effects come with the mark, in one step.
    sqlx::query("SELECT * FROM nzbd.restore_finish()")
        .execute(&mut app)
        .await
        .unwrap();
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::Ready);
    let (sessions, active_keys): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM session), (SELECT count(*) FROM api_key WHERE revoked_at IS NULL)",
    )
    .fetch_one(&mut app)
    .await
    .unwrap();
    assert_eq!((sessions, active_keys), (0, 0));
}

/// `SECURITY_REVIEW` 31 L3: the ingest log is append-only for the app role; moving a recent row's `ts` out of the
/// retention window (the reviewer's `ts = 0` repro) is refused.
#[tokio::test]
async fn sec_093_app_role_cannot_rewrite_the_ingest_log() {
    let t = TestDb::new().await;
    let now = 1_800_000_000_i64;
    t.set_db_clock(now).await;
    let mut app = t.app_conn().await;
    sqlx::query("INSERT INTO ingest_log (ts, source, outcome) VALUES ($1, 'watch', 'ok')")
        .bind(now)
        .execute(&mut app)
        .await
        .unwrap();
    for stmt in [
        "UPDATE ingest_log SET ts = 0",
        "DELETE FROM ingest_log",
        "UPDATE nzb_file SET bytes = 0",
        "DELETE FROM nzb_file",
    ] {
        let e = sqlx::query(stmt).execute(&mut app).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{stmt}");
    }
    let n: i64 = sqlx::query_scalar("SELECT nzbd.log_retention_apply()")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(n, 0, "the recent row stays");
    assert_eq!(
        t.db.privilege_self_test().await.unwrap(),
        Vec::<String>::new()
    );
}

/// `SECURITY_REVIEW` 31 L5: membership in another role (for `nzbd_app` in `nzbd_owner`, `SET ROLE` would follow) and
/// ownership of any object fail the privilege self-test of `nzbd db check`; the bootstrap removes memberships of the app
/// role. Memberships are cluster-wide, so the test uses its own login role (a member of `nzbd_app`) instead of
/// changing `nzbd_app` under the other tests.
#[tokio::test]
async fn sec_087_db_check_fails_on_role_membership_or_ownership() {
    assert!(crate::pg::testing::ROLES_SQL.contains("REVOKE %I FROM nzbd_app"));
    let t = TestDb::new().await;
    let probe = format!("nzbd_probe_{}", t.name.trim_start_matches("nzbd_t_"));
    let mut su = t.superuser_conn().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {probe} LOGIN PASSWORD 'probe-pass'; GRANT nzbd_app TO {probe}; \
         GRANT CONNECT ON DATABASE \"{}\" TO {probe}; ALTER ROLE {probe} SET search_path = nzbd, pg_temp;",
        t.name
    )))
    .execute(&mut su)
    .await
    .unwrap();
    let mut settings = t.settings();
    settings.user = probe.clone();
    let db = PgDb::connect(&settings, "probe-pass").await.unwrap();
    let excess = db.privilege_self_test().await.unwrap();
    assert!(
        excess.contains(&"member of a role".to_owned()),
        "{excess:?}"
    );
    assert!(
        !excess.contains(&"owns objects in schema nzbd".to_owned()),
        "{excess:?}"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE nzbd.search_replay OWNER TO {probe}"
    )))
    .execute(&mut su)
    .await
    .unwrap();
    let excess = db.privilege_self_test().await.unwrap();
    assert!(
        excess.contains(&"owns objects in schema nzbd".to_owned()),
        "{excess:?}"
    );
    assert!(!db.deep_db_check().await.unwrap().quick_check_ok);
    db.close().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE nzbd.search_replay OWNER TO nzbd_owner; REVOKE CONNECT ON DATABASE \"{}\" FROM {probe}; \
         DROP ROLE {probe};",
        t.name
    )))
    .execute(&mut su)
    .await
    .unwrap();
}

/// `SECURITY_REVIEW` 31 L6: a database that is not UTF-8 is refused before anything else is read.
#[tokio::test]
async fn readiness_refuses_a_database_that_is_not_utf8() {
    let t = TestDb::new().await;
    let name = format!("{}_ascii", t.name);
    let mut su = t.superuser_conn().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'SQL_ASCII' LC_COLLATE 'C' LC_CTYPE 'C'"
    )))
    .execute(&mut su)
    .await
    .unwrap();
    let server = crate::pg::testing::Server::from_env();
    {
        use sqlx::ConnectOptions as _;
        let mut c = server.superuser_options(&name).connect().await.unwrap();
        sqlx::raw_sql(crate::pg::testing::DB_PRIVILEGES_SQL)
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
    }
    let db = PgDb::connect(
        &server.settings(&name),
        crate::pg::testing::TEST_APP_PASSWORD,
    )
    .await
    .unwrap();
    let r = db.readiness().await.unwrap();
    assert_eq!(r, Readiness::EncodingNotUtf8);
    assert_eq!(r.code(), Some("DB_ENCODING_NOT_UTF8"));
    db.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE \"{name}\" WITH (FORCE)"
    )))
    .execute(&mut su)
    .await
    .unwrap();
}

/// T134 review I4: the roles migration (`v3/0010_roles`) refuses a library that already holds an account, or only an
/// audit chain head, with `FRESH_DATA_REQUIRED` (the same libraries as the SQLite twin
/// `sqlite_v3_tests::t134_roles_migration_refuses_a_filled_library`); an empty 3.4 database migrates.
#[tokio::test]
async fn t134_roles_migration_refuses_a_filled_library() {
    for case in ["account", "chain_head", "empty"] {
        let t = TestDb::new_upto(9).await;
        let mut su = t.superuser_conn().await;
        match case {
            "account" => {
                sqlx::query(
                    "INSERT INTO nzbd.account (username, password_hash, role, created_at, password_changed_at) \
                     VALUES ('alice', 'x', 'admin', 1, 1)",
                )
                .execute(&mut su)
                .await
                .unwrap();
            }
            "chain_head" => {
                sqlx::query(
                    "UPDATE nzbd.audit_chain_state SET head_hash = sha256('x'::bytea), rows = 0",
                )
                .execute(&mut su)
                .await
                .unwrap();
            }
            _ => {}
        }
        sqlx::Connection::close(su).await.unwrap();
        let r = crate::pg::migrate_as_owner(t.owner_options()).await;
        if case == "empty" {
            assert_eq!(r.unwrap(), [10, 11], "{case}");
        } else {
            let e = r.expect_err("a filled library must be refused");
            assert!(e.to_string().contains("FRESH_DATA_REQUIRED"), "{case}: {e}");
        }
    }
}
