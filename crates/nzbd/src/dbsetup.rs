//! `nzbd db migrate` and `nzbd db restore <file>` (ARCHITECTURE v3 section 9, T116).
//!
//! On PostgreSQL both run with the OWNER role and exist for the one-shot `setup` compose service only: that service is
//! the only container that mounts the owner secret (`/run/setup-secrets/nzbd_db_owner_password`, review 30 M4,
//! `sec_087_owner_secret_not_mounted_in_serve`); `serve` never migrates and refuses `MIGRATIONS_PENDING`. On SQLite the
//! library migrates itself on open, so `db migrate` only opens (creates) it, and a restore is a file copy
//! (`docs/RUNBOOK.md`): every nzbd backup copy carries `restore_pending`, so `serve` refuses it until
//! `nzbd db restore-finish`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use nzb_store::DbBackend;
use nzb_store::pg::PoolKind;
use nzb_store::pg::config::{check_identifier, read_password_file};

use crate::config::Config;

/// Default owner role name (`migrations/v3/superuser/0001_roles.sql`).
pub const OWNER_USER: &str = "nzbd_owner";

/// Review 36 M1: a schema change or a restore never runs under a live `serve`. Refused (`APP_SESSIONS_ACTIVE`) while
/// the app role holds a session on the database, unless the operator passes `--force`.
fn live_serve_refusal(sessions: i64, force: bool) -> Result<(), String> {
    if sessions > 0 && !force {
        return Err(format!(
            "APP_SESSIONS_ACTIVE: {sessions} session(s) of the app role are connected (is `nzbd serve` running?); \
             stop nzbd first (`docker compose stop nzbd`), or pass --force if you know they are not a server"
        ));
    }
    if sessions > 0 {
        eprintln!("warning: --force: {sessions} app-role session(s) are connected; continuing");
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

fn now() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before 1970".to_owned())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_owned()))
}

/// The validated settings and the OWNER password for [`nzb_store::pg::connect_options`] (built field by field, never a
/// URL). The password stays in a zeroizing buffer; it never appears in an error or a log line. Callers pass no
/// statement timeout: migrations and restores are long-running by nature.
fn owner_secret(
    cfg: &Config,
    owner_user: &str,
    owner_password_file: &Path,
) -> Result<(nzb_store::pg::PgSettings, zeroize::Zeroizing<String>), String> {
    crate::config::check_process_environment().map_err(|e| e.to_string())?;
    let s = cfg.db.pg_settings().map_err(|e| e.to_string())?;
    check_identifier(owner_user, "--owner-user").map_err(|e| format!("{}: {e}", e.code()))?;
    let pw = read_password_file(owner_password_file).map_err(|e| format!("{}: {e}", e.code()))?;
    Ok((s, pw))
}

/// `nzbd db migrate [--yes]`: prints the plan; with `--yes` applies it (Postgres: OWNER role).
///
/// # Errors
/// Configuration, secret file, connection or migration errors (stable codes, never the password).
pub fn run_migrate(
    cfg: &Config,
    yes: bool,
    force: bool,
    owner_user: &str,
    owner_password_file: &Path,
) -> Result<ExitCode, String> {
    let rt = runtime()?;
    match cfg.db.backend {
        DbBackend::Sqlite => rt.block_on(async {
            // A SQLite library is created and migrated by every read-write open; a 2.x file is refused with
            // LEGACY_DATABASE and left untouched.
            let db = crate::dbopen::open(cfg)
                .await
                .map_err(|e| format!("database: {e}"))?;
            db.close().await;
            println!(
                "SQLite library {} is at the current schema (SQLite migrates on open; nothing else to do)",
                cfg.paths.db.display()
            );
            Ok(ExitCode::SUCCESS)
        }),
        DbBackend::Postgres => {
            let (s, pw) = owner_secret(cfg, owner_user, owner_password_file)?;
            let opts = nzb_store::pg::connect_options(&s, owner_user, &pw, PoolKind::Background, Duration::ZERO);
            rt.block_on(async {
                let (pending, unknown) = nzb_store::pg::pending_as_owner(opts.clone())
                    .await
                    .map_err(|e| format!("database: {e}"))?;
                if let Some(v) = unknown {
                    return Err(format!(
                        "SCHEMA_NEWER: the database has migration {v}, which this nzbd does not know; \
                         run the matching or a newer release"
                    ));
                }
                if pending.is_empty() {
                    println!("PostgreSQL schema is current: nothing to migrate");
                    return Ok(ExitCode::SUCCESS);
                }
                let list = pending
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("pending migrations: {list}");
                if !yes {
                    println!("dry run: nothing was changed; pass --yes to apply");
                    return Ok(ExitCode::SUCCESS);
                }
                let sessions = nzb_store::pg::app_sessions_as_owner(opts.clone())
                    .await
                    .map_err(|e| format!("database: {e}"))?;
                live_serve_refusal(sessions, force)?;
                let applied = nzb_store::pg::migrate_as_owner(opts)
                    .await
                    .map_err(|e| format!("migration: {e}"))?;
                println!(
                    "applied {} migration(s); taxonomy synchronized. `nzbd serve` may start now",
                    applied.len()
                );
                Ok(ExitCode::SUCCESS)
            })
        }
    }
}

/// `nzbd db restore <file> [--allow-unencrypted]`: loads a snapshot export into an EMPTY, migrated Postgres database
/// (OWNER role). The database stays `restore_pending` until `nzbd db restore-finish`.
///
/// # Errors
/// SQLite (restored by file copy), configuration, secret, key or restore errors.
pub fn run_restore(
    cfg: &Config,
    file: &Path,
    allow_unencrypted: bool,
    force: bool,
    owner_user: &str,
    owner_password_file: &Path,
) -> Result<ExitCode, String> {
    if cfg.db.backend == DbBackend::Sqlite {
        return Err(
            "a SQLite library is restored by copying the backup file into place (decrypt it first with \
             `nzbd backup decrypt`), then `nzbd db restore-finish`: docs/RUNBOOK.md, section \"Restore (SQLite)\""
                .to_owned(),
        );
    }
    let key = crate::keys::load_backup_key(cfg)?;
    let (s, pw) = owner_secret(cfg, owner_user, owner_password_file)?;
    let opts =
        nzb_store::pg::connect_options(&s, owner_user, &pw, PoolKind::Background, Duration::ZERO);
    let now = now()?;
    let rt = runtime()?;
    rt.block_on(async {
        let sessions = nzb_store::pg::app_sessions_as_owner(opts.clone())
            .await
            .map_err(|e| format!("database: {e}"))?;
        live_serve_refusal(sessions, force)?;
        let rep = nzb_store::pg::restore_snapshot(
            opts,
            file,
            &cfg.paths.tmp,
            nzb_store::pg::RestoreOptions {
                key: key.as_ref(),
                allow_unencrypted,
            },
            now,
        )
        .await
        .map_err(|e| format!("restore: {e}"))?;
        for (table, rows) in &rep.tables {
            println!("  {table}: {rows} row(s)");
        }
        println!(
            "restore loaded and verified (audit chain ok: {}). The database is restore-pending: `serve` refuses it \
             until `nzbd db restore-finish --yes` (run it as the service, e.g. `docker compose run --rm --no-deps \
             nzbd /nzbd db restore-finish --yes`)",
            rep.audit_chain_ok
        );
        Ok(ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod tests {
    use super::live_serve_refusal;

    #[test]
    fn migrate_and_restore_refuse_under_a_live_serve_unless_forced() {
        assert!(live_serve_refusal(0, false).is_ok());
        let e = live_serve_refusal(3, false).unwrap_err();
        assert!(e.starts_with("APP_SESSIONS_ACTIVE"), "{e}");
        assert!(live_serve_refusal(3, true).is_ok());
    }
}
