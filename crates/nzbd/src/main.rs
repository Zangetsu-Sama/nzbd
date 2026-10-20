//! `nzbd` binary: CLI, config loading, app wiring, graceful shutdown.
#![forbid(unsafe_code)]

mod admin;
mod apikeys;
mod audit;
mod cleanup;
mod config;
mod dbadmin;
mod dbcheck;
mod dbopen;
mod dbsetup;
#[cfg(feature = "dev-tools")]
mod devtools;
mod health;
mod import;
mod keys;
mod library;
mod logging;
mod maintenance;
mod metrics;
mod ops;
mod search;
mod users;
mod watch;

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use config::Config;

#[derive(Parser)]
#[command(name = "nzbd", version, about = "Single-user NZB indexer")]
struct Cli {
    /// Path to the TOML config file (env `NZBD__section__key` overrides apply on top). Without the
    /// flag, the path in the environment variable `NZBD_CONFIG_FILE` is used, if set.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run a command that writes to the library, the store, the index or the state although the process is root
    /// (files it creates would be root-owned and refused or unusable for `serve`). Goes before the subcommand:
    /// `nzbd --allow-root user list`. `db check|migrate|restore|restore-finish`, `audit` and `import` keep their own
    /// `--allow-root` after the subcommand.
    #[arg(long = "allow-root")]
    allow_root: bool,
    #[command(subcommand)]
    command: Command,
}

/// Review 39 L2: whether the dispatcher refuses this command for a root process. Exempt: commands that touch no
/// library, store, index or state file (`healthcheck`, `categories`, `security-headers`, `keygen`), and the ones that
/// carry their own `--allow-root` and check it themselves (`db check|migrate|restore|restore-finish`, `audit`,
/// `import`). Everything else, `serve` included, is refused as root unless `--allow-root`; that includes the read-only
/// `watch rules` (review 41 L1: its walk is path-based, so as root a racing writer could steer it into directories the
/// service user cannot read).
fn dispatcher_checks_root(cmd: &Command) -> bool {
    match cmd {
        Command::Healthcheck
        | Command::Categories
        | Command::SecurityHeaders
        | Command::Keygen { .. }
        | Command::Audit { .. }
        | Command::Import(_) => false,
        Command::Db { action } => matches!(action, dbcheck::DbAction::SetRetention { .. }),
        _ => true,
    }
}

/// The refusal for a root process (`as_root`), `None` when the command may run.
fn root_refusal(cmd: &Command, as_root: bool, allow_root: bool) -> Option<&'static str> {
    (as_root && !allow_root && dispatcher_checks_root(cmd)).then_some(
        "refusing to run as root (uid 0 or group 0): files created now (database, -wal/-shm, NZB store, backups, \
         search index, state) would be root-owned and refused or unusable for `serve`. Run it as the service user (`docker compose exec \
         nzbd /nzbd ...` does), or pass --allow-root before the subcommand",
    )
}

#[derive(Subcommand)]
enum Command {
    /// Run the web server.
    Serve,
    /// Configuration utilities.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Probe `GET /healthz` on the configured listener (for container HEALTHCHECK).
    Healthcheck,
    /// Check the whole installation (files, database, ingest, security) and print a table.
    /// Read-only. Exit code 0 = all OK, 1 = warnings, 2 = failures. Operator tool; the
    /// container HEALTHCHECK stays `healthcheck`.
    Health,
    /// The search index (Tantivy, both backends): status, verify, rebuild.
    Search {
        #[command(subcommand)]
        action: search::SearchAction,
    },
    /// Database utilities (on-demand integrity checks).
    Db {
        #[command(subcommand)]
        action: dbcheck::DbAction,
    },
    /// Manage accounts (passwords are read from a no-echo prompt or stdin, never from argv).
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Manage upload-only API keys for `POST /api/v1/nzb`.
    Apikey {
        #[command(subcommand)]
        action: ApikeyAction,
    },
    /// Back up the database (`VACUUM INTO`, 0600, rotated), then purge expired sessions and old logs.
    ///
    /// The TOTP key file is not part of the backup; store it separately. With
    /// `maintenance.backup_encryption_key_file` set the snapshot is encrypted (`.sqlite.enc`);
    /// `nzbd backup decrypt` turns it back into a plain database for a restore.
    Backup {
        #[command(subcommand)]
        action: Option<keys::BackupAction>,
        /// Number of backups to keep.
        #[arg(long, default_value_t = nzb_store::DEFAULT_KEEP)]
        keep: usize,
    },
    /// Print the metrics of the running server (a GET of `/metrics` on `metrics.listen`, local only).
    Metrics,
    /// Export the audit log (JSON Lines, ASCII only) and verify its hash chain (T105).
    Audit {
        #[command(subcommand)]
        action: audit::AuditAction,
    },
    /// Import a directory of NZB files (a 2.x `data/store/`, an `.nzb` collection) into this library through the
    /// ingest pipeline. Read only: files are copied, never moved or deleted; symbolic links and special files are
    /// skipped. Re-running it imports nothing twice. SQLite: stop `serve` first.
    Import(import::ImportArgs),
    /// Inspect and retry files quarantined in `failed/`.
    Failed {
        #[command(subcommand)]
        action: ops::FailedAction,
    },
    /// Show or purge the Trash / Blocked / Failed cleanup buckets (twin of the admin Cleanup panel).
    Cleanup {
        #[command(subcommand)]
        action: cleanup::CleanupAction,
    },
    /// List or restore releases deleted from the web UI, or purge the trash.
    Trash {
        #[command(subcommand)]
        action: cleanup::TrashAction,
    },
    /// Verify or garbage-collect the NZB blob store.
    Store {
        #[command(subcommand)]
        action: ops::StoreAction,
    },
    /// List the category taxonomy (id, slug, name): the values accepted by `X-Category`.
    Categories,
    /// Watch-folder tools (read-only).
    Watch {
        #[command(subcommand)]
        action: watch::WatchAction,
    },
    /// Print the security response headers nzbd sets on its HTML pages, one `Name: value` per
    /// line (the reference for `deploy/audit-headers.sh`). Needs no config, database or network.
    SecurityHeaders,
    /// DEV ONLY: print a valid TOTP code for the user (feature `dev-tools`, not in release builds).
    #[cfg(feature = "dev-tools")]
    DevTotp,
    /// Secret-key maintenance (offline): re-seal TOTP secrets under a new key.
    Keys {
        #[command(subcommand)]
        action: keys::KeysAction,
    },
    /// Generate a random 32-byte key (base64): TOTP encryption key or backup encryption key.
    Keygen {
        /// Write the key to this new file with mode 0400 instead of printing it.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Create an account. Prompts for the password twice and prints a one-time enrollment token.
    /// The first account becomes the administrator; further accounts need `--role` and
    /// `security.multi_user = true`. This (with `set-role`) is the only way to make an administrator.
    Create {
        /// Login name: 1-64 characters from A-Z a-z 0-9 . _ -
        username: String,
        /// `admin`, `uploader` or `viewer` (mandatory unless this is the first account).
        #[arg(long)]
        role: Option<String>,
    },
    /// List accounts (username, display name, role, status, MFA, last login; no secrets).
    List,
    /// Change an account's role (the only way to grant or take away `admin`).
    SetRole {
        /// Login name.
        username: String,
        /// `admin`, `uploader` or `viewer`.
        role: String,
    },
    /// Disable an account: sessions revoked, API keys suspended, codes it issued revoked.
    Disable {
        /// Login name.
        username: String,
    },
    /// Enable a disabled account.
    Enable {
        /// Login name.
        username: String,
    },
    /// Delete a disabled account (tombstone: releases and audit rows keep their attribution).
    Delete {
        /// Login name.
        username: String,
    },
    /// Clear every lock and the persisted throttle state of an account.
    Unlock {
        /// Login name.
        username: String,
    },
    /// End every session of an account.
    RevokeSessions {
        /// Login name.
        username: String,
    },
    /// Set the non-login display name used for attribution (empty text restores the default).
    SetDisplayName {
        /// Login name.
        username: String,
        /// Display name: 1-32 characters from A-Z a-z 0-9 space . _ -
        text: String,
    },
    /// Issue an invitation code for a new uploader or viewer (needs `security.multi_user`).
    /// The code is printed once. There is no administrator invitation.
    Invite {
        /// Login name the invitation reserves.
        username: String,
        /// `uploader` or `viewer`.
        #[arg(long)]
        role: String,
    },
    /// Set a new password for an account and revoke its sessions and keys.
    ResetPassword {
        /// Login name (optional while exactly one account exists).
        username: Option<String>,
    },
    /// Clear TOTP, recovery codes and all sessions; MFA must be re-enrolled at next login.
    /// Prints a one-time enrollment token (valid 24 h) that the web enrollment page requires.
    ResetMfa {
        /// Login name (optional while exactly one account exists).
        username: Option<String>,
    },
    /// Print a new one-time MFA enrollment token (while MFA is not enabled), e.g. after expiry.
    EnrollToken {
        /// Login name (optional while exactly one account exists).
        username: Option<String>,
    },
}

#[derive(Subcommand)]
enum ApikeyAction {
    /// Create a key; it is printed once and cannot be shown again.
    Create {
        /// Label, 1-64 letters, digits, spaces or . _ - : @ ( ) + # /
        label: String,
        /// Owning account (an uploader or administrator); default: the oldest enabled administrator.
        #[arg(long)]
        user: Option<String>,
        /// Per-key budget in uploads per minute (1-30); it can only lower `limits.upload_per_key_per_min`.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=30))]
        rate: Option<u32>,
    },
    /// List keys (id, prefix, label, owner, scope, rate, dates, status; never the secret).
    List,
    /// Revoke the key with this id (see `apikey list`).
    Revoke {
        /// Key id.
        id: i64,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate the configuration and exit non-zero on problems.
    Check,
}

/// `nzbd config check`: validation (warnings on stderr), then the facts an operator needs.
fn config_check(cfg: &Config) -> Result<(), String> {
    for w in cfg.validate().map_err(|e| e.to_string())? {
        eprintln!("warning: {w}");
    }
    println!("config ok");
    // T135: where invitees go (not a secret; only the operator runs this).
    let url = cfg.invite_url().map_err(|e| e.to_string())?;
    if cfg.security.multi_user {
        println!("invitation page: {url}");
    } else {
        println!("invitation page: {url} (not served: security.multi_user = false)");
    }
    Ok(())
}

/// Address a local probe should connect to for a given listen address.
fn probe_addr(listen: SocketAddr) -> SocketAddr {
    let ip = if listen.ip().is_unspecified() {
        match listen.ip() {
            IpAddr::V4(_) => IpAddr::from([127, 0, 0, 1]),
            IpAddr::V6(_) => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
        }
    } else {
        listen.ip()
    };
    SocketAddr::new(ip, listen.port())
}

/// Outcome of the local `/healthz` probe.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// `200`: serving and the ingest heartbeat is fresh.
    Healthy,
    /// The listener answers its `STARTING` page: the database is still being checked or
    /// migrated (T088). Not a failure of a running service.
    Starting,
    /// Anything else (no listener, `503 BUSY`/unhealthy heartbeat, ...), with a short reason.
    Unhealthy(String),
}

/// Minimal raw-TCP `GET /healthz` (std only: no HTTP client crate, no outbound traffic).
fn healthcheck(addr: SocketAddr) -> Probe {
    let timeout = Duration::from_secs(3);
    let mut s = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => return Probe::Unhealthy(format!("connect: {}", e.kind())),
    };
    if let Err(e) = s.set_read_timeout(Some(timeout)) {
        return Probe::Unhealthy(e.to_string());
    }
    if let Err(e) =
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    {
        return Probe::Unhealthy(format!("write: {}", e.kind()));
    }
    // Head plus the small uniform error body (no Accept header: JSON); `Connection: close` ends it.
    let mut buf = [0_u8; 2048];
    let mut len = 0_usize;
    while let Some(rest) = buf.get_mut(len..).filter(|r| !r.is_empty()) {
        match s.read(rest) {
            Ok(0) => break,
            Ok(n) => len = len.saturating_add(n),
            // A timeout after some bytes still leaves a usable response.
            Err(_) if len > 0 => break,
            Err(e) => return Probe::Unhealthy(format!("read: {}", e.kind())),
        }
    }
    let resp = buf.get(..len).unwrap_or_default();
    if resp.starts_with(b"HTTP/1.1 200") {
        return Probe::Healthy;
    }
    let marker = format!("\"code\":\"{}\"", nzb_web::starting::STARTING_CODE);
    if resp.starts_with(b"HTTP/1.1 503") && String::from_utf8_lossy(resp).contains(marker.as_str())
    {
        return Probe::Starting;
    }
    Probe::Unhealthy("unexpected response".into())
}

/// Raw-TCP `GET /metrics` of the local listener; returns the body of a `200` (std only, loopback or the container's
/// own address; no outbound traffic).
fn fetch_metrics(addr: SocketAddr) -> Result<String, String> {
    let timeout = Duration::from_secs(5);
    let mut s =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect: {}", e.kind()))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| format!("socket: {}", e.kind()))?;
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("write: {}", e.kind()))?;
    let mut raw = Vec::new();
    s.take(1 << 20)
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {}", e.kind()))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "unexpected response".to_owned())?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err("metrics endpoint refused the request".to_owned());
    }
    // Whatever answered on that port is printed to a terminal: keep printable ASCII and newlines only (SEC-083).
    Ok(body
        .chars()
        .filter(|c| *c == '\n' || (' '..='~').contains(c))
        .collect())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut t), Ok(mut i)) => {
            tokio::select! { _ = t.recv() => {}, _ = i.recv() => {} }
        }
        // Cannot install handlers: fall back to Ctrl-C only.
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    tracing::info!("shutdown signal received, draining connections");
}

/// Reads `security.totp_key_file` into the zeroize-on-drop TOTP key.
fn load_totp_key(cfg: &Config) -> Result<nzb_web::totp::TotpKey, String> {
    let key = config::load_key_file(&cfg.security.totp_key_file).map_err(|e| e.to_string())?;
    nzb_web::totp::TotpKey::from_slice(&key.0)
        .ok_or_else(|| "security.totp_key_file must hold exactly 32 bytes".to_string())
}

// Linear startup sequence (bind, db, auth, ingest, serve); splitting it would only hide the order.
#[allow(clippy::too_many_lines)]
fn serve(cfg: &Config) -> Result<(), String> {
    use nzb_ingest as ing;
    use std::sync::Arc;

    for w in cfg.validate().map_err(|e| e.to_string())? {
        tracing::warn!("{w}");
    }
    // Review 30 M4: `serve` never holds the Postgres owner role; a readable owner secret is a deployment error.
    // SEC-086: the libpq/`SSL_CERT_*` refusal is about the database connection, so it applies to the Postgres backend
    // only (a SQLite library opens no connection; `cargo` itself exports `SSL_CERT_*` to the processes it starts).
    if cfg.db.backend == nzb_store::DbBackend::Postgres {
        crate::config::check_process_environment().map_err(|e| e.to_string())?;
        nzb_store::pg::config::refuse_readable_owner_secret(&[])
            .map_err(|e| format!("{}: {e}", e.code()))?;
    }
    // One `serve` per library (SEC-102), held until this function returns.
    let _serve_lock = library::lock_serve(cfg)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(cfg.server.listen)
            .await
            .map_err(|e| format!("cannot bind {}: {}", cfg.server.listen, e.kind()))?;
        tracing::info!(listen = %cfg.server.listen, "listening (starting: database not ready yet)");
        // Serve a static 503 "starting" page from now on, while the database is checked and
        // migrated (minutes on a large library, T088). Only the web layer's own hardening runs
        // until `gate.open`; no handler or DB access exists behind it. The limits equal the
        // real app's: one `WebConfig` is built here and the real app's config is derived from
        // it below (`..web.clone()`), so a listener limit can never apply to only one of them.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let stop_tx = Arc::new(stop_tx);
        let early = nzb_web::WebConfig {
            trusted_proxies: cfg.server.trusted_proxies.clone(),
            insecure_cookies: cfg.server.insecure_cookies,
            max_file_bytes: cfg.limits.max_file_bytes,
            ..nzb_web::WebConfig::default()
        };
        let gate = nzb_web::starting::StartGate::new(&early);
        let mut http_task = tokio::spawn(nzb_web::listener::serve(
            early.limit_listener(listener),
            gate.router(),
            {
                let (tx, mut rx) = (Arc::clone(&stop_tx), stop_rx.clone());
                async move {
                    tokio::select! {
                        () = shutdown_signal() => {}
                        _ = rx.wait_for(|stop| *stop) => {}
                    }
                    let _ = tx.send(true);
                }
            },
        ));
        // SIGTERM/SIGINT while checking or migrating stops now (a migration is one transaction,
        // so an interrupted one is rolled back and re-run on the next start); a server that dies
        // here is an error, not a shutdown (T088 L2).
        let opened = wait_for_db(
            async {
                dbopen::open_with(cfg, cfg.db.startup_check.into(), &|ev| {
                    dbcheck::log_open_event(&ev);
                })
                .await
                .map_err(|e| format!("database: {e}"))
            },
            &mut http_task,
        )
        .await?;
        let Some(db) = opened else {
            return Ok(());
        };
        // Library identity and restore detection (SEC-094, SEC-101) before anything is served.
        if let Err(e) = library::admit(cfg, &db).await {
            db.close().await;
            return Err(e);
        }
        let anchor_task = library::spawn_anchor_writer(cfg, db.clone(), stop_rx.clone());
        tracing::info!(backend = %db.backend(), "database ready");
        audit::log_anchor(&db, "startup").await;
        if let Some(r) = stop_if_requested(&stop_rx, &mut http_task, &db, "before auth").await {
            return r;
        }
        // The key file was validated by `cfg.validate()`; it is read again here (not cached in the
        // config) and copied into a zeroize-on-drop key. A bad file aborts startup.
        let totp_key = load_totp_key(cfg)?;
        startup_accounts(cfg, &db).await?;
        let auth_cfg = nzb_web::AuthConfig {
            multi_user: cfg.security.multi_user,
            registration_enabled: cfg.security.registration_enabled,
            invite_ttl_secs: i64::from(cfg.security.invite_ttl_hours).saturating_mul(3600),
            recover_ttl_secs: i64::from(cfg.security.recover_ttl_hours).saturating_mul(3600),
            max_accounts: cfg.security.max_accounts,
            public_url: cfg.public_url(),
            invite_path: cfg.invite_path().map_err(|e| e.to_string())?,
            idle_secs: i64::from(cfg.security.session_idle_mins) * 60,
            max_secs: i64::from(cfg.security.session_max_hours) * 3600,
            insecure_cookies: cfg.server.insecure_cookies,
            allowed_hosts: cfg.server.allowed_hosts.clone(),
            totp_key: Some(std::sync::Arc::new(totp_key)),
            ..nzb_web::AuthConfig::default()
        };
        // Computes the dummy password hash once; any failure aborts startup (fail closed).
        let taxonomy = std::sync::Arc::new(
            nzb_core::Taxonomy::builtin().map_err(|e| format!("taxonomy: {e}"))?,
        );
        let auth_cfg = nzb_web::AuthConfig {
            hidden_categories: hidden_categories(cfg, &taxonomy),
            // "Hide XXX for me" (T120): the same subtree the instance switch hides.
            xxx_categories: std::sync::Arc::from(taxonomy.subtree_ids(nzb_core::XXX_CATEGORY)),
            ..auth_cfg
        };
        let store = open_store(cfg)?;
        // The search index of both backends (T122): the indexer task starts now (a missing or stale index is
        // rebuilt in the background while the UI serves the bounded degraded browse).
        let search = search::start(cfg, &db, stop_rx.clone()).await?;
        let ui_routes = ui_routes(
            cfg,
            &db,
            Arc::clone(&taxonomy),
            store.clone(),
            search.index.clone(),
        );
        // Delete release + admin Cleanup panel (T081); the fs store doubles as trash store.
        let cleanup_deps = nzb_web::cleanup::CleanupDeps::new(
            nzb_ingest::cleanup::CleanupEnv {
                db: db.clone(),
                store: store.clone(),
                failed_dir: cfg.paths.failed.clone(),
            },
            Arc::new(nzb_web::auth::SystemWallClock),
            Arc::clone(&taxonomy),
        );
        let auth = nzb_web::AuthState::new(
            db.clone(),
            auth_cfg,
            Arc::new(nzb_web::auth::SystemWallClock),
        )
        .await
        .map_err(|e| format!("auth: {e}"))?;
        auth.purge_expired()
            .await
            .map_err(|e| format!("auth: {e}"))?;
        auth.spawn_purger();
        db.purge_revoked_api_keys(now_unix(), REVOKED_KEY_RETENTION_DAYS)
            .await
            .map_err(|e| format!("auth: {e}"))?;

        // /healthz is unhealthy while the scan loop's heartbeat is older than 3 scan intervals.
        // The first beat is recorded now so a freshly started container is not reported dead.
        let heartbeat = ing::Heartbeat::new();
        let wall = ing::SystemWallClock;
        heartbeat.beat(ing::WallClock::now_unix(&wall));
        let interval = Duration::from_secs(cfg.ingest.scan_interval_secs);
        let probe = heartbeat.clone();
        let web = nzb_web::WebConfig {
            health_check: Some(Arc::new(move || {
                probe.is_fresh(ing::WallClock::now_unix(&ing::SystemWallClock), interval)
            })),
            ..early.clone()
        };
        let pipeline_slot = Arc::new(std::sync::OnceLock::new());
        let admin_routes = nzb_web::admin::routes(admin::deps(
            cfg,
            &db,
            heartbeat.clone(),
            Arc::clone(&pipeline_slot),
        ));
        // Recovery runs before anything is accepted; ingest (and its queue handle, needed by the
        // upload routes) starts before the router is built; the starting page covers the wait.
        let recovery_slot = Arc::new(std::sync::OnceLock::new());
        // A SIGTERM during start-up must not run recovery or start the scan loop (T088 L3):
        // otherwise the work can outlast `stop_grace_period` and be SIGKILLed.
        if let Some(r) = stop_if_requested(&stop_rx, &mut http_task, &db, "before recovery").await {
            return r;
        }
        startup_recovery(cfg, &db, &store, &recovery_slot).await;
        if let Some(r) = stop_if_requested(&stop_rx, &mut http_task, &db, "before ingest").await {
            return r;
        }
        // SEC-092: the scanner pauses while the search index lags too far behind (shared with health/metrics).
        let lag_gate = ing::LagGate::for_store(db.clone(), cfg.search.lag_pause_rows);
        let health_engine = health::Engine::server(
            cfg,
            db.clone(),
            health::LiveHandles {
                heartbeat: heartbeat.clone(),
                pipeline: Arc::clone(&pipeline_slot),
                lag_gate: Some(lag_gate.clone()),
            },
            recovery_slot,
            cfg!(feature = "dev-tools"),
        );
        let health_routes = nzb_web::health::routes(health::web_deps(&health_engine));
        if let Some(addr) = cfg.metrics.listen {
            spawn_metrics(cfg, addr, health_engine.clone(), stop_rx.clone()).await?;
        }
        spawn_retention(cfg, stop_rx.clone());
        spawn_maintenance(cfg, &db, stop_rx.clone());
        let (mut ingest, handle) = start_ingest(
            cfg,
            db.clone(),
            store,
            heartbeat,
            &pipeline_slot,
            lag_gate,
            stop_rx.clone(),
        )?;
        let upload_deps = upload_deps(cfg, handle, taxonomy, web.upload_timeout)
            .with_audit(db.clone(), Arc::new(nzb_web::auth::SystemWallClock));
        let session_routes = ui_routes
            .merge(admin_routes)
            .merge(health_routes)
            // Bulk actions on the result list (T119) share the delete flow's deps.
            .merge(nzb_web::bulk::routes(&auth, cleanup_deps.clone()))
            .merge(nzb_web::cleanup::routes(&auth, cleanup_deps))
            .merge(nzb_web::account_routes(&auth))
            .merge(account_admin_routes(cfg, &auth))
            .merge(nzb_web::upload::ui_routes(upload_deps.clone()));
        let app = nzb_web::router_with_upload(
            &web,
            &auth,
            session_routes,
            Some(nzb_web::upload::api_route(upload_deps)),
        );

        // From here on the already-listening server dispatches to the real router. The router
        // holds a clone of the ingest queue handle: the server task must have ended (it drops
        // the gate with it) before `drain`, or the workers would never see the queue close, so
        // this function keeps no gate clone of its own.
        if !gate.open(app) {
            return Err("startup gate was already open".to_owned());
        }
        drop(gate);
        tracing::info!(listen = %cfg.server.listen, "ready");
        let (served, fatal) = {
            let server_err = server_result;
            let mut fatal: Option<&'static str> = None;
            let served = tokio::select! {
                r = &mut http_task => server_err(r),
                why = ingest.first_exit() => {
                    // The scan loop or a worker ended while the process was not shutting down:
                    // ingestion is dead, so the process must not keep reporting healthy.
                    if !*stop_tx.borrow() {
                        tracing::error!(reason = why, "ingest stopped unexpectedly; shutting down");
                        fatal = Some(why);
                    }
                    let _ = stop_tx.send(true);
                    server_err((&mut http_task).await)
                }
            };
            (served, fatal)
        };
        ingest.drain().await;
        let _ = stop_tx.send(true);
        let _ = search.task.await;
        let _ = anchor_task.await;
        // The final anchor write closes the documented "last <= 10 s" restore-detection window on an orderly stop.
        match library::write_now(cfg, &db).await {
            Ok(()) => tracing::info!("shutdown anchor written"),
            Err(e) => tracing::warn!(error = %e, "shutdown anchor not written"),
        }
        db.close().await;
        served?;
        if let Some(why) = fatal {
            return Err(format!("ingest stopped unexpectedly: {why}"));
        }
        tracing::info!("stopped");
        Ok(())
    })
}

/// Starts the internal-only metrics listener (T105): its own socket and router, never part of the application
/// router. It stops with the server (`stop`). A bind failure aborts startup rather than silently running without it.
async fn spawn_metrics(
    cfg: &Config,
    addr: SocketAddr,
    engine: health::Engine,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind metrics.listen {addr}: {}", e.kind()))?;
    let render: nzb_web::metrics::RenderFn = Arc::new(move || {
        let engine = engine.clone();
        Box::pin(async move { metrics::render(&engine.metrics_facts(now_unix()).await) })
    });
    let app = nzb_web::metrics::router(nzb_web::metrics::MetricsDeps {
        render,
        trusted_proxies: cfg.server.trusted_proxies.clone().into(),
    });
    let limited = nzb_web::WebConfig::default().limit_listener(listener);
    tracing::info!(listen = %addr, "metrics listener (internal only)");
    tokio::spawn(async move {
        let served = nzb_web::listener::serve(limited, app, async move {
            let _ = stop.wait_for(|s| *s).await;
        })
        .await;
        if let Err(e) = served {
            tracing::error!(error = %e.kind(), "metrics listener ended");
        }
    });
    Ok(())
}

/// The Users page routes: mounted only while `security.multi_user = true` (the access gate also
/// answers the uniform 404 for them otherwise, belt and braces).
fn account_admin_routes(cfg: &Config, auth: &nzb_web::AuthState) -> axum::Router {
    if cfg.security.multi_user {
        nzb_web::users::routes(auth)
    } else {
        axum::Router::new()
    }
}

/// Account-related start-up work (`AUTH_SPEC` `security.multi_user`, D28): logs the mode, revokes
/// open invitations while they cannot be redeemed (`multi_user` off or registration disabled, so a
/// flag flip cannot revive an old code), and warns about states the operator should look at.
async fn startup_accounts(cfg: &Config, db: &nzb_store::Store) -> Result<(), String> {
    let e = |e: nzb_store::StoreError| format!("accounts: {e}");
    let now = now_unix();
    tracing::info!(
        multi_user = cfg.security.multi_user,
        registration_enabled = cfg.security.registration_enabled,
        "account mode"
    );
    let reason = if !cfg.security.multi_user {
        Some("multi_user_off")
    } else if !cfg.security.registration_enabled {
        Some("registration_disabled")
    } else {
        None
    };
    if let Some(reason) = reason {
        let n = db
            .revoke_open_invites_system_for(now, reason)
            .await
            .map_err(e)?;
        if n > 0 {
            tracing::warn!(revoked = n, reason, "open invitations revoked at startup");
        }
    }
    let live = db.count_live_accounts().await.map_err(e)?;
    if live > 1 && !cfg.security.multi_user {
        tracing::warn!(
            accounts = live,
            "several accounts exist but security.multi_user is off"
        );
    }
    for r in db.reserved_login_accounts().await.map_err(e)? {
        // The id only: the login name is not logged.
        tracing::warn!(account = r.id, kind = ?r.kind, "login name uses a reserved form");
    }
    let throttled = db.count_throttled_accounts(now).await.map_err(e)?;
    if throttled > 0 {
        tracing::warn!(
            accounts = throttled,
            "accounts are under unknown-address throttling"
        );
    }
    Ok(())
}

/// Outcome of the HTTP server task as a `serve` result: its I/O error kind (never the message),
/// or "task failed" for a panic/cancellation.
fn server_result(r: Result<std::io::Result<()>, tokio::task::JoinError>) -> Result<(), String> {
    match r {
        Ok(r) => r.map_err(|e| format!("server: {}", e.kind())),
        Err(_) => Err("server: task failed".to_owned()),
    }
}

/// Waits for the database open to finish while watching the already-listening server task.
/// `Ok(Some(v))` = opened; `Ok(None)` = the server ended cleanly, i.e. a graceful shutdown was
/// requested (SIGTERM/SIGINT: the task only ends `Ok` after the stop signal), so the caller
/// returns without opening anything; `Err` = the open failed or the server died (error or
/// panic), which is a failure and must not look like a shutdown (T088 L2).
async fn wait_for_db<T>(
    open: impl std::future::Future<Output = Result<T, String>>,
    http_task: &mut tokio::task::JoinHandle<std::io::Result<()>>,
) -> Result<Option<T>, String> {
    tokio::select! {
        r = open => r.map(Some),
        r = &mut *http_task => match server_result(r) {
            Ok(()) => {
                tracing::info!("shutdown requested while the database was starting");
                Ok(None)
            }
            Err(e) => {
                tracing::error!(error = %e, "http server stopped while the database was starting");
                Err(e)
            }
        },
    }
}

/// When a stop was requested during start-up: closes the database, waits for the server task
/// (its graceful shutdown) and returns the `serve` result; `None` = carry on (T088 L3).
async fn stop_if_requested(
    stop_rx: &tokio::sync::watch::Receiver<bool>,
    http_task: &mut tokio::task::JoinHandle<std::io::Result<()>>,
    db: &nzb_store::Store,
    stage: &str,
) -> Option<Result<(), String>> {
    if !*stop_rx.borrow() {
        return None;
    }
    tracing::info!(
        stage,
        "shutdown requested during start-up; not starting ingest"
    );
    db.close().await;
    Some(server_result(http_task.await))
}

/// Running ingest side of `serve`: the scan loop and the worker tasks.
struct Ingest {
    /// `None` once the scan loop has finished: `first_exit` may already have polled its handle to completion, and a
    /// `JoinHandle` polled again after that panics ("polled after completion"), which turned every SIGTERM into an
    /// exit 101 that skipped the drain, the indexer stop, the shutdown anchor write and `db.close()` (review 39 M1).
    scan: Option<tokio::task::JoinHandle<nzb_ingest::ScanExit>>,
    workers: tokio::task::JoinSet<()>,
}

/// Resolves, with a reason, as soon as the scan loop or any worker task has ended.
async fn first_exit(
    scan: &mut tokio::task::JoinHandle<nzb_ingest::ScanExit>,
    workers: &mut tokio::task::JoinSet<()>,
) -> &'static str {
    tokio::select! {
        r = scan => match r {
            Ok(nzb_ingest::ScanExit::Shutdown) => "scan loop ended",
            Ok(nzb_ingest::ScanExit::WorkersGone) => "ingest workers are gone",
            Err(_) => "scan loop panicked",
        },
        Some(r) = workers.join_next() => {
            if r.is_err() { "ingest worker panicked" } else { "ingest worker ended" }
        }
    }
}

impl Ingest {
    async fn first_exit(&mut self) -> &'static str {
        let Some(scan) = self.scan.as_mut() else {
            // Only reachable if called twice; the scan loop already ended, so only the workers can still end.
            return match self.workers.join_next().await {
                Some(Err(_)) => "ingest worker panicked",
                Some(Ok(())) => "ingest worker ended",
                None => "ingest workers are gone",
            };
        };
        let why = first_exit(scan, &mut self.workers).await;
        // A finished handle is never awaited again (polled or not, its result is no longer needed).
        if scan.is_finished() {
            self.scan = None;
        }
        why
    }

    /// Waits for the scan loop (already told to stop) and the in-flight jobs.
    async fn drain(mut self) {
        if let Some(scan) = self.scan.take() {
            let _ = scan.await;
        }
        while self.workers.join_next().await.is_some() {}
    }
}

/// One store handle shared by ingest (writes) and the explorer (reads): `FsStore::open` cleans
/// `.tmp/`, so a second handle opened later could delete in-flight ingest temp files. v3 keeps NZB
/// files on the filesystem only (D36 a).
fn open_store(cfg: &Config) -> Result<std::sync::Arc<nzb_store::FsStore>, String> {
    let fs = nzb_store::FsStore::open(&cfg.paths.store).map_err(|e| format!("store: {e}"))?;
    Ok(std::sync::Arc::new(ops::fs_store(cfg, fs)))
}

/// Category ids hidden from every UI view: XXX and its children when `ui.show_xxx = false`,
/// derived once from the taxonomy (empty when shown).
fn hidden_categories(cfg: &Config, tax: &nzb_core::Taxonomy) -> std::sync::Arc<[u16]> {
    if cfg.ui.show_xxx {
        std::sync::Arc::from(Vec::new())
    } else {
        std::sync::Arc::from(tax.subtree_ids(nzb_core::XXX_CATEGORY))
    }
}

/// Session-gated UI routes: index plus the release detail/explorer.
fn ui_routes(
    cfg: &Config,
    db: &nzb_store::Store,
    taxonomy: std::sync::Arc<nzb_core::Taxonomy>,
    blobs: std::sync::Arc<nzb_store::FsStore>,
    index: nzb_search::TantivyIndex<nzb_store::Store>,
) -> axum::Router {
    use std::sync::Arc;
    let release_routes = nzb_web::release::routes(nzb_web::release::ReleaseDeps {
        db: db.clone(),
        taxonomy: Arc::clone(&taxonomy),
        store: blobs,
        limits: parser_limits(cfg),
        clock: Arc::new(nzb_web::auth::SystemWallClock),
        // `serve` keeps the default request timeout (15 s); stay one second below it.
        max_parse: nzb_web::WebConfig::default()
            .request_timeout
            .saturating_sub(Duration::from_secs(1)),
    });
    nzb_web::index::routes_with(db.clone(), index, taxonomy).merge(release_routes)
}

/// Parser limits shared by ingest and the on-demand explorer (same limits, same deadline).
/// Upload route dependencies with the production limits applied. Without the limiter and the
/// storage guard installed here the routes would run unlimited (the `UploadDeps::new` defaults
/// are only a safety net for tests).
fn upload_deps(
    cfg: &Config,
    handle: nzb_ingest::IngestHandle,
    taxonomy: Arc<nzb_core::Taxonomy>,
    upload_timeout: Duration,
) -> nzb_web::upload::UploadDeps {
    let mut deps = nzb_web::upload::UploadDeps::new(
        handle,
        taxonomy,
        cfg.paths.tmp.clone(),
        cfg.limits.max_file_bytes,
    );
    // The reply wait is bounded by what is left of the request budget (`upload_timeout`, minus a
    // margin to answer 504), per request and not per file (T051 L2).
    deps.request_budget = upload_timeout;
    deps.reply_timeout = upload_timeout.saturating_sub(deps.deadline_margin);
    // SEC-029 per-key / per-session buckets and the T051 M2 storage guard.
    let clock: Arc<dyn nzb_web::ratelimit::Clock> =
        Arc::new(nzb_web::ratelimit::SystemClock::new());
    deps.limiter = Arc::new(nzb_web::upload_guard::UploadLimiter::new(
        cfg.limits.upload_per_key_per_min,
        cfg.limits.upload_per_session_per_min,
        &clock,
    ));
    deps.storage = Some(Arc::new(storage_guard(cfg, clock)));
    deps
}

/// Free-space guard over the volumes uploads write to (`paths.tmp`, `paths.store`).
fn storage_guard(
    cfg: &Config,
    clock: Arc<dyn nzb_web::ratelimit::Clock>,
) -> nzb_web::upload_guard::StorageGuard {
    let dirs = [cfg.paths.tmp.clone(), cfg.paths.store.clone()];
    nzb_web::upload_guard::StorageGuard::new(
        Arc::new(move || {
            dirs.iter()
                .filter_map(|d| health::free_space(d))
                .map(|(free, total)| nzb_web::upload_guard::Space { free, total })
                .collect()
        }),
        cfg.limits.upload_min_free_bytes,
        cfg.limits.upload_min_free_percent,
        clock,
    )
}

fn parser_limits(cfg: &Config) -> nzb_core::Limits {
    nzb_core::Limits {
        max_file_bytes: cfg.limits.max_file_bytes,
        parse_deadline: Duration::from_secs(cfg.limits.parse_deadline_secs),
        ..nzb_core::Limits::default()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Reconciles whatever a crash left behind before anything new is accepted (SEC-008).
async fn startup_recovery(
    cfg: &Config,
    db: &nzb_store::Store,
    store: &nzb_store::FsStore,
    summary: &std::sync::OnceLock<health::RecoverySummary>,
) {
    let rep = nzb_ingest::recover(&recovery_config(cfg), db, store, now_unix()).await;
    // Shown on the health page; counts only.
    let _ = summary.set(health::RecoverySummary::from(&rep));
    if rep.missing_total > 0 {
        tracing::warn!(
            missing = rep.missing_total,
            "releases without a blob in the store; run `nzbd store verify`"
        );
    }
}

fn recovery_config(cfg: &Config) -> nzb_ingest::RecoveryConfig {
    nzb_ingest::RecoveryConfig {
        watch_dir: cfg.paths.watch.clone(),
        failed_dir: cfg.paths.failed.clone(),
        duplicates_dir: cfg.paths.duplicates.clone(),
        tmp_dir: Some(cfg.paths.tmp.clone()),
        recursive: cfg.ingest.recursive,
        max_file_bytes: cfg.limits.max_file_bytes,
    }
}

/// D12: applies `failed_retention_days` now and every 6 hours, in the background (it hashes
/// files, so it must not delay the listener). Expired files are moved to `failed/expired/`,
/// never deleted; only files nzbd wrote a `reason.json` for qualify.
fn spawn_retention(cfg: &Config, mut stop: tokio::sync::watch::Receiver<bool>) {
    let days = cfg.ingest.failed_retention_days;
    if days == 0 {
        return;
    }
    let dir = cfg.paths.failed.clone();
    tokio::spawn(async move {
        // First run shortly after the listener is up, then every 6 hours.
        let first = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut tick = tokio::time::interval_at(first, Duration::from_hours(6));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let d = dir.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        nzb_ingest::apply_retention(&d, days, now_unix())
                    })
                    .await;
                }
                () = async { let _ = stop.wait_for(|v| *v).await; } => break,
            }
        }
    });
}

/// L-3: daily backup + log/key purges inside `serve` (first run 60 s after start). Disabled with
/// `maintenance.backup_interval_hours = 0`.
fn spawn_maintenance(
    cfg: &Config,
    db: &nzb_store::Store,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let m = &cfg.maintenance;
    if m.backup_interval_hours == 0 {
        tracing::info!("scheduled maintenance disabled (maintenance.backup_interval_hours = 0)");
        return;
    }
    let params = maintenance::Params {
        first_delay: maintenance::FIRST_RUN_DELAY,
        interval: Duration::from_secs(u64::from(m.backup_interval_hours).saturating_mul(3600)),
        backups_dir: cfg.paths.backups.clone(),
        keep: usize::try_from(m.keep_backups).unwrap_or(usize::MAX),
        // Fail closed: a configured but unusable key disables backups with an error, it never
        // downgrades to plaintext snapshots.
        backup_key: match keys::load_backup_key(cfg) {
            Ok(k) => k.map(Arc::new),
            Err(e) => {
                tracing::error!(error = %e, "backup encryption key unusable; scheduled backups disabled");
                return;
            }
        },
    };
    tracing::info!(
        encrypted = params.backup_key.is_some(),
        every_hours = m.backup_interval_hours,
        keep = m.keep_backups,
        "scheduled maintenance enabled"
    );
    // Detached on purpose: it ends with the stop signal (or the runtime).
    drop(maintenance::spawn(
        db.clone(),
        params,
        Arc::new(now_unix),
        stop,
    ));
}

/// Starts the workers plus the scan loop (`INGEST_SPEC`) on the already opened database.
fn start_ingest(
    cfg: &Config,
    db: nzb_store::Store,
    store: std::sync::Arc<nzb_store::FsStore>,
    heartbeat: nzb_ingest::Heartbeat,
    pipeline_slot: &std::sync::OnceLock<nzb_ingest::Pipeline>,
    lag_gate: nzb_ingest::LagGate,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(Ingest, nzb_ingest::IngestHandle), String> {
    use nzb_ingest as ing;
    let limits = parser_limits(cfg);
    let action = match cfg.ingest.duplicates_action {
        config::DuplicatesAction::Move => ing::DuplicatesAction::Move,
        config::DuplicatesAction::Delete => ing::DuplicatesAction::Delete,
    };
    let watch_rules = cfg.watch_rules().map_err(|e| e.to_string())?;
    if !watch_rules.is_empty() {
        tracing::info!(
            rules = watch_rules.rules().len(),
            "watch-folder rules loaded"
        );
    }
    let pipeline = ing::Pipeline::new_with_rules(
        ing::PipelineConfig {
            limits,
            watch_dir: cfg.paths.watch.clone(),
            failed_dir: cfg.paths.failed.clone(),
            duplicates_dir: cfg.paths.duplicates.clone(),
            duplicates_action: action,
            category_from_subfolder: cfg.ingest.category_from_subfolder,
            failed_uploads_max_files: cfg.ingest.failed_uploads_max_files,
            failed_uploads_max_bytes: cfg.ingest.failed_uploads_max_bytes,
        },
        watch_rules,
        db,
        store,
        std::sync::Arc::new(ing::SystemWallClock),
    )
    .map_err(|e| format!("ingest: {e}"))?;
    // Shares the live counters with the admin page.
    let _ = pipeline_slot.set(pipeline.clone());
    let settings = cfg.ingest.settings();
    let (handle, worker_tasks) = pipeline.spawn(settings);
    let mut worker_set = tokio::task::JoinSet::new();
    for w in worker_tasks {
        worker_set.spawn(async move {
            let _ = w.await;
        });
    }
    let scanner = ing::Scanner::new(
        ing::ScannerConfig {
            watch_dir: cfg.paths.watch.clone(),
            recursive: cfg.ingest.recursive,
            max_file_bytes: cfg.limits.max_file_bytes,
            stable_secs: cfg.ingest.stable_secs,
            backoff_secs: 600,
            max_entries_per_scan: ing::scanner::DEFAULT_MAX_ENTRIES,
        },
        ing::SystemClock::new(),
    );
    let wake = std::sync::Arc::new(ing::spawn_watcher(&cfg.paths.watch, cfg.ingest.recursive));
    let scan = tokio::spawn(ing::run_scan_loop_gated(
        std::sync::Arc::new(std::sync::Mutex::new(scanner)),
        handle.clone(),
        wake,
        ing::RunnerConfig {
            scan_interval: Duration::from_secs(cfg.ingest.scan_interval_secs),
            max_batch: settings.queue_cap,
        },
        heartbeat,
        std::sync::Arc::new(ing::SystemWallClock),
        Some(lag_gate),
        async move {
            let _ = stop.wait_for(|v| *v).await;
        },
    ));
    let workers = settings.workers;
    tracing::info!(workers, "ingest started");
    Ok((
        Ingest {
            scan: Some(scan),
            workers: worker_set,
        },
        handle,
    ))
}

use maintenance::REVOKED_KEY_RETENTION_DAYS;

/// `nzbd backup`: snapshot first (before anything can migrate), then maintenance purges.
fn backup(cfg: &Config, keep: usize) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before 1970".to_string())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_string()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    // Fail before touching anything when a configured key cannot be used: never fall back to a
    // plaintext backup for a user who asked for encryption.
    let key = keys::load_backup_key(cfg)?;
    rt.block_on(async {
        // Allowed on a restore-pending library (the gate list, review 35 L6); the purges below are not, they would
        // write to it.
        // SQLite: the `VACUUM INTO` copy of the file (works next to a running server). PostgreSQL: the snapshot
        // export through the app role (T116: `nzbd backup` used to copy `paths.db` whatever the backend).
        let (rep, db) = if cfg.db.backend == nzb_store::DbBackend::Postgres {
            let db = crate::dbopen::open_allow_restore_pending(cfg)
                .await
                .map_err(|e| format!("open: {e}"))?;
            let rep = db
                .backup(&cfg.paths.backups, now, keep, key.as_ref())
                .await
                .map_err(|e| format!("backup: {e}"))?;
            (rep, db)
        } else {
            let rep = nzb_store::backup_file_with(
                &cfg.paths.db,
                &cfg.paths.backups,
                now,
                keep,
                key.as_ref(),
            )
            .await
            .map_err(|e| format!("backup: {e}"))?;
            let db = crate::dbopen::open_allow_restore_pending(cfg)
                .await
                .map_err(|e| format!("open: {e}"))?;
            (rep, db)
        };
        println!(
            "backup written: {}{}",
            rep.path.display(),
            if key.is_some() { " (encrypted)" } else { "" }
        );
        if db.restore_pending().await.map_err(|e| e.to_string())? {
            db.close().await;
            println!("the database is restore-pending: purges skipped (run `nzbd db restore-finish`)");
            return Ok(());
        }
        let sessions = db.purge_expired_sessions(now).await.map_err(|e| e.to_string())?;
        let logs = db.purge_logs().await.map_err(|e| e.to_string())?;
        let accounts = db.purge_account_state(now).await.map_err(|e| e.to_string())?;
        let keys = db
            .purge_revoked_api_keys(now, REVOKED_KEY_RETENTION_DAYS)
            .await
            .map_err(|e| e.to_string())?;
        if logs.future_rows > 0 {
            eprintln!(
                "warning: {} audit row(s) are stamped more than a day in the future; check the system clock",
                logs.future_rows
            );
        }
        match db.audit_anchor().await {
            Ok(a) => println!("audit chain anchor (keep off-host): {}", a.line()),
            Err(e) => eprintln!("warning: audit chain anchor unavailable: {e}"),
        }
        db.close().await;
        println!(
            "rotated {} old backup(s); purged {sessions} session(s), {} audit and {} ingest log row(s), {keys} revoked API key(s), {} spent account row(s)",
            rep.rotated,
            logs.audit,
            logs.ingest,
            accounts
                .invites
                .saturating_add(accounts.staging)
                .saturating_add(accounts.throttle)
                .saturating_add(accounts.locks)
                .saturating_add(accounts.known_ips)
        );
        Ok(())
    })
}

fn run_user(cfg: &Config, action: UserAction) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    // Only `create` may create/migrate a database; everything else must not conjure a new empty
    // one when the configured path is wrong.
    if !matches!(action, UserAction::Create { .. }) && !dbopen::exists(cfg) {
        return Err(format!(
            "database {} does not exist; check paths.db and run `nzbd user create` first",
            cfg.paths.db.display()
        ));
    }
    let policy = account_policy(cfg);
    rt.block_on(async {
        let db = crate::dbopen::open(cfg)
            .await
            .map_err(|e| format!("database: {e}"))?;
        let now = users::now_secs();
        let res = run_user_action(cfg, &db, action, policy, now).await;
        db.close().await;
        let out = res.map_err(|e| e.to_string())?;
        eprintln!("ok");
        // Stdout only, shown once, never logged: hand it to the person out of band.
        if let Some(text) = out {
            let mut o = std::io::stdout().lock();
            writeln!(o, "{text}").map_err(|e| format!("could not write output: {}", e.kind()))?;
        }
        Ok(())
    })
}

/// The account policy of the configuration (instance flags the store enforces).
fn account_policy(cfg: &Config) -> nzb_store::AccountPolicy {
    nzb_store::AccountPolicy {
        multi_user: cfg.security.multi_user,
        max_accounts: cfg.security.max_accounts,
        registration_enabled: cfg.security.registration_enabled,
    }
}

/// Runs one `user` subcommand; the returned text (a token, a code, a table) goes to stdout.
async fn run_user_action(
    cfg: &Config,
    db: &nzb_store::Store,
    action: UserAction,
    policy: nzb_store::AccountPolicy,
    now: i64,
) -> Result<Option<String>, users::UserCmdError> {
    use users::Lifecycle;
    let enroll = |t: String| {
        Some(format!(
            "Enrollment token (single use, valid 24 hours): {t}"
        ))
    };
    Ok(match action {
        UserAction::Create { username, role } => {
            let role = role.as_deref().map(users::parse_role).transpose()?;
            let t =
                users::create(db, &username, role, policy, &mut users::StdinSource, now).await?;
            enroll(t)
        }
        UserAction::List => Some(users::list(db, now).await?),
        UserAction::SetRole { username, role } => {
            users::set_role(db, &username, users::parse_role(&role)?, now).await?;
            None
        }
        UserAction::Disable { username } => {
            users::lifecycle(db, &username, Lifecycle::Disable, now).await?;
            None
        }
        UserAction::Enable { username } => {
            users::lifecycle(db, &username, Lifecycle::Enable, now).await?;
            None
        }
        UserAction::Delete { username } => {
            users::lifecycle(db, &username, Lifecycle::Delete, now).await?;
            None
        }
        UserAction::Unlock { username } => {
            users::lifecycle(db, &username, Lifecycle::Unlock, now).await?;
            None
        }
        UserAction::RevokeSessions { username } => {
            let n = users::lifecycle(db, &username, Lifecycle::RevokeSessions, now).await?;
            Some(format!("{n} session(s) revoked"))
        }
        UserAction::SetDisplayName { username, text } => {
            users::set_display_name(db, &username, &text, now).await?;
            None
        }
        UserAction::Invite { username, role } => {
            let ttl = i64::from(cfg.security.invite_ttl_hours).saturating_mul(3600);
            // Before the code exists: a bad `security.invite_path` must not burn an invitation.
            let url = cfg
                .invite_url()
                .map_err(|e| users::UserCmdError::Config(e.to_string()))?;
            let inv =
                users::invite(db, &username, users::parse_role(&role)?, policy, ttl, now).await?;
            // T135: the invitation page as the full URL to hand out (path alone without
            // `server.public_url` / `server.allowed_hosts`).
            let hint = if cfg.public_address().is_some() {
                format!("\nGive it to the person with {url}")
            } else {
                format!(
                    "\nGive it to the person with the invitation page {url} on this nzbd's address \
                     (set server.public_url to print the full address)"
                )
            };
            Some(format!(
                "Invitation code (single use, valid until {}): {}{hint}",
                nzb_web::fmt_utc(inv.expires_at),
                inv.code
            ))
        }
        UserAction::ResetPassword { username } => {
            users::reset_password(db, username.as_deref(), &mut users::StdinSource, now).await?;
            None
        }
        UserAction::ResetMfa { username } => {
            enroll(users::reset_mfa(db, username.as_deref(), now).await?)
        }
        UserAction::EnrollToken { username } => {
            enroll(users::enroll_token(db, username.as_deref(), now).await?)
        }
    })
}

fn run_apikey(cfg: &Config, action: ApikeyAction) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    if !dbopen::exists(cfg) {
        return Err(format!(
            "database {} does not exist; check paths.db and run `nzbd user create` first",
            cfg.paths.db.display()
        ));
    }
    rt.block_on(async {
        let db = crate::dbopen::open(cfg)
            .await
            .map_err(|e| format!("database: {e}"))?;
        // Stdout only: the secret (create) is shown once and never logged. Never `println!`:
        // it panics on a closed pipe, and a created key must not outlive a failed print.
        let mut out = std::io::stdout().lock();
        let res = match action {
            ApikeyAction::Create { label, user, rate } => {
                apikeys::create(&db, &label, user.as_deref(), rate, &mut out).await
            }
            ApikeyAction::List => match apikeys::list(&db).await {
                Ok(text) => {
                    use std::io::Write as _;
                    writeln!(out, "{text}").map_err(|e| apikeys::KeyCmdError::Print(e.kind()))
                }
                Err(e) => Err(e),
            },
            ApikeyAction::Revoke { id } => {
                let r = apikeys::revoke(&db, id).await;
                if r.is_ok() {
                    eprintln!("ok");
                }
                r
            }
        };
        db.close().await;
        res.map_err(|e| e.to_string())
    })
}

/// Table of the taxonomy for `nzbd categories`: `ID  SLUG  NAME`, children indented.
fn render_categories(tax: &nzb_core::Taxonomy) -> String {
    let mut out = format!("{:<6}{:<18}NAME\n", "ID", "SLUG");
    for c in tax.entries() {
        let _ = writeln!(out, "{:<6}{:<18}{}", c.id, c.slug, c.name);
    }
    out
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Keygen { out } => {
            let key = config::generate_key_b64().map_err(|e| format!("keygen: {}", e.kind()))?;
            if let Some(p) = out {
                config::write_secret_file(&p, &key).map_err(|e| format!("keygen: {}", e.kind()))
            } else {
                println!("{key}");
                Ok(())
            }
        }
        #[cfg(feature = "dev-tools")]
        Command::DevTotp => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            devtools::run(&cfg)
        }
        Command::Failed { .. }
        | Command::Audit { .. }
        | Command::Store { .. }
        | Command::Search { .. }
        | Command::Cleanup { .. }
        | Command::Trash { .. }
        | Command::Db { .. }
        | Command::Import(_)
        | Command::Health => Err("operator command dispatched in main".to_owned()),
        Command::SecurityHeaders => {
            print!("{}", nzb_web::security_headers_report());
            Ok(())
        }
        Command::Categories => {
            let tax = nzb_core::Taxonomy::builtin().map_err(|e| e.to_string())?;
            print!("{}", render_categories(&tax));
            Ok(())
        }
        Command::Watch { action } => watch::run(cli.config.as_deref(), &action),
        Command::User { action } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            run_user(&cfg, action)
        }
        Command::Apikey { action } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            run_apikey(&cfg, action)
        }
        Command::Config {
            action: ConfigAction::Check,
        } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            config_check(&cfg)
        }
        Command::Keys { action } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            keys::run_keys(&cfg, action)
        }
        Command::Backup {
            action:
                Some(keys::BackupAction::Decrypt {
                    file,
                    out,
                    key_file,
                }),
            ..
        } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            keys::run_decrypt(&cfg, &file, &out, key_file.as_deref())
        }
        Command::Backup { keep, action: None } => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            backup(&cfg, keep)
        }
        Command::Metrics => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            let addr = cfg
                .metrics
                .listen
                .ok_or_else(|| "metrics.listen is not configured".to_owned())?;
            print!("{}", fetch_metrics(probe_addr(addr))?);
            Ok(())
        }
        Command::Healthcheck => {
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            // Both non-healthy outcomes exit 1 (all a container runtime distinguishes; the
            // image's `--start-period` keeps `starting` from counting as a failure). The message
            // tells them apart in `docker inspect` health logs.
            match healthcheck(probe_addr(cfg.server.listen)) {
                Probe::Healthy => Ok(()),
                Probe::Starting => Err(
                    "starting: the database is being checked or migrated; not unhealthy, retry later"
                        .to_owned(),
                ),
                Probe::Unhealthy(why) => Err(format!("unhealthy: {why}")),
            }
        }
        Command::Serve => {
            logging::init();
            let cfg = Config::load(cli.config.as_deref()).map_err(|e| e.to_string())?;
            logging::print_banner(env!("CARGO_PKG_VERSION"), &cfg.server.listen.to_string());
            serve(&cfg)
        }
    }
}

/// Environment variable naming the config file when `--config` is absent. The container sets it, so
/// `serve` and every `docker compose exec nzbd /nzbd ...` command read the same mounted file. Single
/// underscore: it is not a `NZBD__section__key` override.
const CONFIG_FILE_ENV: &str = "NZBD_CONFIG_FILE";

/// `--config` wins; else a non-empty `NZBD_CONFIG_FILE`; else no file (built-in defaults + env).
fn config_path(flag: Option<PathBuf>, env: Option<std::ffi::OsString>) -> Option<PathBuf> {
    flag.or_else(|| env.filter(|v| !v.is_empty()).map(PathBuf::from))
}

/// Review 44 M1: makes this process non-dumpable before anything reads a secret. A dumpable process
/// lets every process of the same uid on the host open `/proc/<pid>/root` (the key volume, the
/// database socket), `/proc/<pid>/environ` and, without Yama, `/proc/<pid>/mem`; with T128 that uid
/// can be an ordinary host account. Non-dumpable, those entries belong to root. Also disables core
/// dumps (already off in compose). Linux only; elsewhere (no such `/proc`) a no-op.
fn make_not_dumpable() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(std::io::Error::from)?;
    Ok(())
}

fn main() -> ExitCode {
    // First, for every subcommand (serve, keygen, setup's migrations, operator commands): nothing
    // has been read yet, so no secret was ever reachable through /proc.
    if let Err(e) = make_not_dumpable() {
        eprintln!(
            "error: cannot make the process non-dumpable ({}); refusing to run",
            e.kind()
        );
        return ExitCode::FAILURE;
    }
    let mut cli = Cli::parse();
    cli.config = config_path(cli.config.take(), std::env::var_os(CONFIG_FILE_ENV));
    if let Some(msg) = root_refusal(&cli.command, dbcheck::running_as_root(), cli.allow_root) {
        eprintln!("error: {msg}");
        return ExitCode::FAILURE;
    }
    // Operator commands with meaningful exit codes (0 ok, 1 error, 2 problems found).
    if matches!(
        cli.command,
        Command::Failed { .. }
            | Command::Audit { .. }
            | Command::Store { .. }
            | Command::Search { .. }
            | Command::Cleanup { .. }
            | Command::Trash { .. }
            | Command::Db { .. }
            | Command::Import(_)
            | Command::Health
    ) {
        let cfg = match Config::load(cli.config.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let res = match cli.command {
            Command::Failed { action } => ops::run_failed(&cfg, action),
            Command::Audit { action } => audit::run_audit(&cfg, &action),
            Command::Store { action } => ops::run_store(&cfg, action),
            Command::Search { action } => search::run(&cfg, &action),
            Command::Cleanup { action } => cleanup::run_cleanup(&cfg, action),
            Command::Trash { action } => cleanup::run_trash(&cfg, action),
            Command::Db { action } => dbcheck::run_db(&cfg, &action),
            Command::Import(args) => import::run(&cfg, &args),
            Command::Health => health::run_cli(&cfg),
            _ => Ok(ExitCode::FAILURE),
        };
        return res.unwrap_or_else(|e| {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        });
    }
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Http = tokio::task::JoinHandle<std::io::Result<()>>;

    #[tokio::test]
    async fn t090_l2_a_server_failure_during_db_open_is_an_error_not_a_shutdown() {
        let pending = || std::future::pending::<Result<u8, String>>();
        // An I/O error from the server task.
        let mut t: Http = tokio::spawn(async { Err(std::io::Error::other("boom")) });
        let r = wait_for_db(pending(), &mut t).await;
        assert!(r.unwrap_err().starts_with("server:"));
        // A panic of the server task.
        let mut t: Http = tokio::spawn(async { panic!("server task panic") });
        let r = wait_for_db(pending(), &mut t).await;
        assert_eq!(r.unwrap_err(), "server: task failed");
        // A graceful end (SIGTERM) is a clean stop without a database.
        let mut t: Http = tokio::spawn(async { Ok(()) });
        assert_eq!(wait_for_db(pending(), &mut t).await, Ok(None));
        // The open finishing first yields the value; its error is passed through.
        let mut t: Http = tokio::spawn(std::future::pending());
        assert_eq!(
            wait_for_db(async { Ok::<_, String>(7_u8) }, &mut t).await,
            Ok(Some(7))
        );
        let r = wait_for_db(async { Err::<u8, _>("database: x".to_owned()) }, &mut t).await;
        assert_eq!(r, Err("database: x".to_owned()));
        t.abort();
    }

    #[tokio::test]
    async fn t090_l3_a_stop_requested_during_startup_returns_before_recovery_and_ingest() {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = ts.store.clone();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut http: Http = tokio::spawn({
            let mut rx = rx.clone();
            async move {
                let _ = rx.wait_for(|s| *s).await;
                Ok(())
            }
        });
        // Not stopping: carry on, the server task keeps running.
        assert!(
            stop_if_requested(&rx, &mut http, &db, "test")
                .await
                .is_none()
        );
        assert!(!http.is_finished());
        // Stopping: prompt clean return, server task joined, database closed.
        tx.send(true).unwrap();
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            stop_if_requested(&rx, &mut http, &db, "test"),
        )
        .await
        .unwrap();
        assert_eq!(r, Some(Ok(())));
        let closed = match &db {
            nzb_store::Store::Sqlite(s) => s.writer().is_closed(),
            nzb_store::Store::Postgres(p) => p.web().is_closed(),
        };
        assert!(closed, "database closed");
    }

    #[tokio::test]
    async fn t031_m3_a_finished_scan_or_worker_task_is_reported() {
        let mut workers = tokio::task::JoinSet::new();
        let mut scan = tokio::spawn(async { nzb_ingest::ScanExit::WorkersGone });
        assert_eq!(
            first_exit(&mut scan, &mut workers).await,
            "ingest workers are gone"
        );
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {});
        let mut scan = tokio::spawn(std::future::pending::<nzb_ingest::ScanExit>());
        assert_eq!(
            first_exit(&mut scan, &mut workers).await,
            "ingest worker ended"
        );
        scan.abort();
        let mut workers = tokio::task::JoinSet::new();
        let mut scan = tokio::spawn(async {
            let _ = std::hint::black_box(1);
            nzb_ingest::ScanExit::Shutdown
        });
        assert_eq!(first_exit(&mut scan, &mut workers).await, "scan loop ended");
    }

    /// Review 39 L2: one root rule in the dispatcher for every state-touching command; the exempt ones and the
    /// commands with their own flag are not refused here; `--allow-root` lifts it; a non-root process is never refused.
    #[test]
    fn sec_070_root_is_refused_for_every_state_touching_command() {
        let parse = |args: &[&str]| {
            let mut v = vec!["nzbd"];
            v.extend_from_slice(args);
            Cli::try_parse_from(v).unwrap()
        };
        for args in [
            &["serve"][..],
            &["backup"],
            &["health"],
            &["config", "check"],
            &["search", "status"],
            &["search", "verify"],
            &["search", "rebuild"],
            &["failed", "list"],
            &["trash", "list"],
            &["cleanup", "status"],
            &["store", "verify"],
            &["store", "gc"],
            &["user", "list"],
            &["user", "create", "x"],
            &["apikey", "list"],
            &["metrics"],
            // Review 41 L1: read-only, but as root its path-based walk could be raced into directories the
            // service user cannot read; run it as the service user so the preview matches what `serve` sees.
            &["watch", "rules"],
            &["keys", "rotate-totp", "--new-key-file", "/k"],
            &[
                "db",
                "set-retention",
                "--log-days",
                "90",
                "--account-days",
                "365",
                "--ingest-days",
                "1",
            ],
        ] {
            let cli = parse(args);
            assert!(
                root_refusal(&cli.command, true, false).is_some_and(|m| m.contains("--allow-root")),
                "{args:?} must be refused as root"
            );
            assert!(
                root_refusal(&cli.command, true, true).is_none(),
                "{args:?} with --allow-root"
            );
            assert!(
                root_refusal(&cli.command, false, false).is_none(),
                "{args:?} not root"
            );
            let lifted = parse(&[&["--allow-root"][..], args].concat());
            assert!(
                lifted.allow_root,
                "{args:?}: the global flag parses before the subcommand"
            );
        }
        for args in [
            &["healthcheck"][..],
            &["categories"],
            &["security-headers"],
            &["keygen"],
            &["db", "check"],
            &["db", "restore-finish"],
            &["db", "migrate"],
            &["audit", "verify"],
            &["import", "/tmp"],
        ] {
            let cli = parse(args);
            assert!(
                root_refusal(&cli.command, true, false).is_none(),
                "{args:?} is exempt or checks itself"
            );
        }
    }

    /// Review 39 M1: the scan loop ending first (the SIGTERM path) must not leave a completed handle for `drain`
    /// to poll again (tokio panics "`JoinHandle` polled after completion").
    #[tokio::test]
    async fn sec_008_drain_after_the_scan_loop_ended_first_does_not_panic() {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let mut ingest = Ingest {
            scan: Some(tokio::spawn(async { nzb_ingest::ScanExit::Shutdown })),
            workers,
        };
        assert_eq!(ingest.first_exit().await, "scan loop ended");
        assert!(ingest.scan.is_none(), "a finished scan handle is dropped");
        let drained = tokio::spawn(ingest.drain()).await;
        assert!(drained.is_ok(), "drain must not panic");
    }

    #[test]
    fn categories_listing_has_every_slug_and_id() {
        let Ok(tax) = nzb_core::Taxonomy::builtin() else {
            panic!("embedded taxonomy must load");
        };
        let out = render_categories(&tax);
        assert_eq!(out.lines().count(), tax.len() + 1);
        for c in tax.entries() {
            assert!(out.contains(&c.slug) && out.contains(&c.id.to_string()));
        }
    }

    #[test]
    fn probe_addr_maps_unspecified_to_loopback() {
        let a = probe_addr(SocketAddr::from(([0, 0, 0, 0], 8080)));
        assert_eq!(a, SocketAddr::from(([127, 0, 0, 1], 8080)));
    }

    /// T088: `nzbd healthcheck` tells "starting" (503 STARTING page) from "unhealthy" (nothing
    /// listening, or an ordinary 503) and from healthy, against a real socket.
    #[tokio::test(flavor = "multi_thread")]
    async fn t088_healthcheck_reports_starting_until_the_gate_opens() {
        let Ok(l) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(addr) = l.local_addr() else { return };
        let gate = nzb_web::starting::StartGate::new(&nzb_web::WebConfig::default());
        let service = gate
            .router()
            .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(l, service).await;
        });
        let probe = move || tokio::task::spawn_blocking(move || healthcheck(addr));
        assert_eq!(probe().await.ok(), Some(Probe::Starting));
        // The same socket turns healthy the moment the real app is handed over.
        assert!(gate.open(nzb_web::router(&nzb_web::WebConfig::default())));
        assert_eq!(probe().await.ok(), Some(Probe::Healthy));
        // An ordinary unhealthy 503 (stale ingest heartbeat) is not "starting".
        let Ok(l2) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(addr2) = l2.local_addr() else { return };
        tokio::spawn(async move {
            let cfg = nzb_web::WebConfig {
                health_check: Some(Arc::new(|| false)),
                ..nzb_web::WebConfig::default()
            };
            let app = nzb_web::router(&cfg).into_make_service_with_connect_info::<SocketAddr>();
            let _ = axum::serve(l2, app).await;
        });
        let r = tokio::task::spawn_blocking(move || healthcheck(addr2)).await;
        assert!(matches!(r.ok(), Some(Probe::Unhealthy(_))));
        // Nothing listening.
        let Ok(l3) = std::net::TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(addr3) = l3.local_addr() else { return };
        drop(l3);
        assert!(matches!(healthcheck(addr3), Probe::Unhealthy(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn healthcheck_against_real_server() {
        let Ok(l) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(addr) = l.local_addr() else { return };
        tokio::spawn(async move {
            let app = nzb_web::router(&nzb_web::WebConfig::default())
                .into_make_service_with_connect_info::<SocketAddr>();
            let _ = axum::serve(l, app).await;
        });
        let r = tokio::task::spawn_blocking(move || healthcheck(addr)).await;
        assert_eq!(r.ok(), Some(Probe::Healthy));
    }
}

#[cfg(test)]
mod config_path_tests {
    use super::config_path;
    use std::path::PathBuf;

    #[test]
    fn flag_wins_over_env_and_empty_env_means_no_file() {
        let flag = Some(PathBuf::from("/a.toml"));
        assert_eq!(config_path(flag.clone(), Some("/b.toml".into())), flag);
        assert_eq!(
            config_path(None, Some("/b.toml".into())),
            Some(PathBuf::from("/b.toml"))
        );
        assert_eq!(config_path(None, Some("".into())), None);
        assert_eq!(config_path(None, None), None);
    }
}

#[cfg(test)]
mod security_headers_cli_tests {
    use super::{Cli, Command};
    use clap::Parser;

    /// The command exists under the documented name and needs no config (it is not one of the
    /// operator commands that load it). Its text is `nzb_web::security_headers_report`, which
    /// `nzb-web/tests/security_auth.rs` compares with a real `/login` response.
    #[test]
    fn security_headers_command_parses_and_prints_one_header_per_line() {
        let cli = Cli::try_parse_from(["nzbd", "security-headers"]).unwrap();
        assert!(matches!(cli.command, Command::SecurityHeaders));
        let text = nzb_web::security_headers_report();
        assert!(text.ends_with('\n'));
        for line in text.lines() {
            let (name, value) = line.split_once(": ").unwrap();
            assert!(
                name.split('-')
                    .all(|p| p.starts_with(|c: char| c.is_ascii_uppercase()))
            );
            assert!(!value.is_empty() && value.is_ascii());
        }
        assert!(text.starts_with(&format!("Content-Security-Policy: {}\n", nzb_web::CSP)));
        assert!(text.contains("X-Frame-Options: DENY\n"));
    }
}
