//! `nzbd db set-retention` (ARCHITECTURE v3 section 9, T122). On Postgres it uses the OWNER role and runs only in the
//! one-shot `setup` service (review 30 M4: `serve` never holds the owner credential); on SQLite the policy is written
//! with the file's own connection. (`db migrate` and `db restore` live in `dbsetup.rs`, T116.)

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use nzb_store::DbBackend;
use nzb_store::pg::config::{OWNER_SECRET_PATH, read_password_file};
use nzb_store::pg::{PoolKind, RetentionPolicy, connect_options};
use nzb_store::prelude::*;

use crate::config::Config;

/// Default login role of the `setup` service.
pub const OWNER_USER: &str = "nzbd_owner";

/// Statement timeout of the owner connection (one small `UPDATE`).
const OWNER_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Where the owner credential comes from (`--owner-user`, `--owner-password-file`).
#[derive(Debug, Clone)]
pub struct Owner {
    /// Role name.
    pub user: String,
    /// Secret file (SEC-042 rules).
    pub password_file: PathBuf,
}

impl Owner {
    /// The documented defaults of the `setup` service.
    #[must_use]
    pub fn from_args(user: Option<String>, password_file: Option<PathBuf>) -> Self {
        Self {
            user: user.unwrap_or_else(|| OWNER_USER.to_owned()),
            password_file: password_file.unwrap_or_else(|| PathBuf::from(OWNER_SECRET_PATH)),
        }
    }

    fn options(&self, cfg: &Config) -> Result<nzb_store::pg::PgConnectOptions, String> {
        crate::config::check_process_environment().map_err(|e| e.to_string())?;
        let s = cfg.db.pg_settings().map_err(|e| e.to_string())?;
        let pw =
            read_password_file(&self.password_file).map_err(|e| format!("{}: {e}", e.code()))?;
        Ok(connect_options(
            &s,
            &self.user,
            &pw,
            PoolKind::Background,
            OWNER_STATEMENT_TIMEOUT,
        ))
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

fn now_secs() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before 1970".to_owned())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_owned()))
}

/// `nzbd db set-retention`: writes the retention policy (floors 90 / 365 / 1 days, SEC-103 / review 30 M3).
///
/// # Errors
/// A value below a floor, credential, connection or database errors.
pub fn run_set_retention(
    cfg: &Config,
    owner: &Owner,
    p: RetentionPolicy,
) -> Result<ExitCode, String> {
    p.validate().map_err(|e| format!("retention: {e}"))?;
    let now = now_secs()?;
    let detail = format!(
        "log_days={} account_days={} ingest_days={} keep_all={} account_keep_all={}",
        p.log_days,
        p.account_days,
        p.ingest_days,
        u8::from(p.keep_all),
        u8::from(p.account_keep_all)
    );
    runtime()?.block_on(async {
        match cfg.db.backend {
            DbBackend::Sqlite => {
                let db = crate::dbopen::open(cfg)
                    .await
                    .map_err(|e| format!("database: {e}"))?;
                let r = match db.as_sqlite() {
                    Some(s) => s.set_retention_policy(p).await.map_err(|e| e.to_string()),
                    None => Err("internal: not a SQLite store".to_owned()),
                };
                if r.is_ok() {
                    db.audit_event(now, Some("cli"), "retention.set", Some(&detail), None)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                db.close().await;
                r?;
            }
            DbBackend::Postgres => {
                nzb_store::pg::set_retention_policy(owner.options(cfg)?, p)
                    .await
                    .map_err(|e| e.to_string())?;
                let db = crate::dbopen::open(cfg)
                    .await
                    .map_err(|e| format!("database: {e}"))?;
                db.audit_event(now, Some("cli"), "retention.set", Some(&detail), None)
                    .await
                    .map_err(|e| e.to_string())?;
                db.close().await;
            }
        }
        println!("retention policy written: {detail}");
        Ok(ExitCode::SUCCESS)
    })
}

/// [`run_set_retention`] for the parsed `nzbd db set-retention` arguments.
///
/// # Errors
/// See [`run_set_retention`].
pub fn run_set_retention_action(
    cfg: &Config,
    action: &crate::dbcheck::DbAction,
) -> Result<ExitCode, String> {
    let crate::dbcheck::DbAction::SetRetention {
        log_days,
        account_days,
        ingest_days,
        keep_all,
        account_keep_all,
        owner_user,
        owner_password_file,
    } = action
    else {
        return Err("internal: not a set-retention action".to_owned());
    };
    let o = Owner::from_args(owner_user.clone(), owner_password_file.clone());
    let p = RetentionPolicy {
        log_days: *log_days,
        account_days: *account_days,
        ingest_days: *ingest_days,
        keep_all: *keep_all,
        account_keep_all: *account_keep_all,
    };
    run_set_retention(cfg, &o, p)
}
