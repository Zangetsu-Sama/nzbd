//! Health check engine behind `GET /admin/health` and the `nzbd health` CLI.
//!
//! Structure (so every threshold is testable without a filesystem, a database or a clock):
//!
//! 1. *gather*: [`gather_fs`] (blocking, std + `rustix` for `statvfs`/`access`), [`gather_db`]
//!    (bounded read-only queries) and [`gather_proc`] (`/proc/self`) collect plain facts into
//!    [`Inputs`];
//! 2. *evaluate*: [`build`] turns the facts into `Vec<Check>` through small pure functions
//!    (`scan_check`, `dir_check`, `backup_check`, ...), each with its thresholds documented
//!    and unit-tested with injected values;
//! 3. *render*: `nzb-web` renders the checks as HTML, [`render_text`] as a CLI table.
//!
//! Rules every check follows (`SECURITY_REVIEW` T048 and the T032 store notes):
//!
//! * read-only: no check changes the database, the store or the watch folder. The only
//!   file written is the uniquely named `.nzbd-health-*` probe in directories where nothing
//!   scans or lists by that name (never in the watch folder, never the store root), removed
//!   right away;
//! * no secrets and no paths in any value or hint: only counts, sizes, ages and logical names
//!   such as "watch folder". The TOTP key is reported as OK/FAIL only;
//! * no subprocesses, no network (the CLI's loopback probe talks to the local listener only).

use nzb_store::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nzb_ingest as ing;
use nzb_store::{
    ChainQuick, FsStore, LogCounts, PoolInfo, ReleaseTotals, SchemaInfo, SecurityFacts,
};
use nzb_web::health::{Check, Group, Status};
use nzb_web::index::human_bytes;

use crate::config::Config;

/// Entries counted per directory before the count is reported as "N+".
pub const COUNT_CAP: usize = 10_000;
/// Releases looked up in the store by one deep check.
pub const DEEP_RELEASE_CAP: u32 = 50_000;
/// A WAL file larger than this means checkpoints are not keeping up.
pub const WAL_WARN_BYTES: u64 = 256 * 1024 * 1024;
/// Resident memory above which the process is flagged.
pub const RSS_WARN_KIB: u64 = 1024 * 1024;
/// Failed sign-ins in 24 h above which the dashboard warns.
pub const FAILED_LOGIN_WARN: u64 = 10;
/// A newest backup older than this is a warning (the backup job is daily).
pub const BACKUP_MAX_AGE_SECS: i64 = 3 * 86_400;
/// Log tables beyond this many rows suggest the retention purge is not running.
pub const LOG_ROWS_WARN: u64 = 500_000;
/// Wall-clock values before this (2024-01-01) mean the clock is not set.
const CLOCK_FLOOR: i64 = 1_704_067_200;
/// An ingest record this far in the future means the clock went backwards.
const CLOCK_SKEW_SECS: i64 = 300;
/// Per-query deadline of the deep database pass.
const DEEP_DB_DEADLINE: Duration = Duration::from_secs(30);
/// Deadline of the blocking store walks inside the deep check.
const DEEP_FS_DEADLINE: Duration = Duration::from_secs(40);

// ---------------------------------------------------------------------------------------------
// Facts

/// A bounded directory count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    /// Entries counted (at most [`COUNT_CAP`]).
    pub n: usize,
    /// More entries exist.
    pub capped: bool,
}

impl Count {
    fn show(self) -> String {
        if self.capped {
            format!("{}+", group_thousands(self.n))
        } else {
            group_thousands(self.n)
        }
    }
}

/// "512 KiB", "3 MiB" (whole units, rounded down).
fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 20 {
        format!("{} MiB", b >> 20)
    } else {
        format!("{} KiB", b >> 10)
    }
}

fn group_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len().saturating_add(s.len() / 3));
    for (i, c) in s.chars().enumerate() {
        if i > 0 && s.len().saturating_sub(i) % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Facts about one configured directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirFacts {
    /// Logical name ("watch folder"), never the path.
    pub name: &'static str,
    /// Path resolves.
    pub exists: bool,
    /// It is a directory.
    pub is_dir: bool,
    /// Writable by this process (`None` = not determinable).
    pub writable: Option<bool>,
    /// `(available to unprivileged users, total)` bytes of the filesystem.
    pub free: Option<(u64, u64)>,
}

/// Filesystem-derived facts.
#[derive(Debug, Clone)]
pub struct FsFacts {
    /// Every configured directory.
    pub dirs: Vec<DirFacts>,
    /// Database file size.
    pub db_bytes: Option<u64>,
    /// `-wal` file size (`Some(0)` when absent).
    pub wal_bytes: Option<u64>,
    /// `dev` ids of watch, store and failed are equal (`None` = unknown).
    pub same_fs: Option<bool>,
    /// No directory overlaps another (config validation helpers).
    pub layout_ok: bool,
    /// SQLite: `paths.state` and the database share a filesystem (review 34 M3).
    pub anchor_same_fs: bool,
    /// The TOTP key file passes the startup validation.
    pub key_ok: bool,
    /// Candidate `.nzb` files waiting in the watch folder (top level).
    pub waiting: Result<Count, ()>,
    /// Quarantined files in `failed/`.
    pub failed: Result<Count, ()>,
    /// Files in `duplicates/`.
    pub duplicates: Result<Count, ()>,
    /// `.nzbd-trash.*` and stale `.part` files in watch, failed and duplicates.
    pub leftovers: usize,
    /// Quarantined blobs in `store/.gc-trash`.
    pub gc_trash: Option<usize>,
    /// Newest generated backup (unix seconds) and how many backups exist.
    pub backups: Result<(Option<i64>, usize), ()>,
}

/// Database-derived facts; `None` fields failed to load.
#[derive(Debug, Clone)]
pub struct DbFacts {
    /// `SELECT 1` on the writer.
    pub writer_ok: bool,
    /// `SELECT 1` on a reader.
    pub reader_ok: bool,
    /// Migration state.
    pub schema: Option<SchemaInfo>,
    /// Release/file/byte totals.
    pub totals: Option<ReleaseTotals>,
    /// Log table sizes and time span.
    pub logs: Option<LogCounts>,
    /// Pool state.
    pub pools: PoolInfo,
    /// Account facts.
    pub security: Option<SecurityFacts>,
    /// Time of the newest successful ingest.
    pub last_ok_ingest: Option<i64>,
    /// Cheap audit-chain consistency (row counts and head hashes; T105).
    pub audit_chain: Option<ChainQuick>,
    /// Search outbox depth and index lag (T114).
    pub outbox: Option<nzb_store::OutboxLag>,
}

/// `/proc/self` facts (all `None` off Linux).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcFacts {
    /// Resident set size in KiB.
    pub rss_kib: Option<u64>,
    /// Open file descriptors.
    pub open_fds: Option<u64>,
    /// Soft limit of open files (`None` = unlimited or unknown).
    pub fd_limit: Option<u64>,
}

/// Live ingest state, known only inside the server process.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveFacts {
    /// Unix seconds of the last completed scan cycle.
    pub heartbeat: Option<i64>,
    /// Releases indexed since start.
    pub ok: u64,
    /// Duplicates since start.
    pub duplicates: u64,
    /// Failures since start.
    pub failed: u64,
    /// Last success or duplicate.
    pub last_success: Option<i64>,
    /// Commit-group transactions since start.
    pub commit_groups: u64,
    /// NZB bytes holding the in-flight budget now.
    pub inflight_bytes: u64,
    /// The scanner is paused because the search index lags (SEC-092).
    pub lag_paused: bool,
}

/// Condensed startup recovery report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    /// Repairs applied at startup (parts, trash, split links, staging files).
    pub repaired: usize,
    /// Releases whose blob is missing.
    pub missing_blobs: usize,
    /// Unreferenced blobs a `store gc` would reclaim.
    pub orphan_blobs: usize,
    /// Failed files without a reason sidecar.
    pub failed_without_reason: u32,
    /// Recoverable errors during recovery.
    pub errors: usize,
}

impl From<&ing::RecoveryReport> for RecoverySummary {
    fn from(r: &ing::RecoveryReport) -> Self {
        let repaired = [
            r.stale_parts_removed,
            r.tmp_removed,
            r.split_links_healed,
            r.trash_unlinked,
            r.trash_to_duplicates,
            r.trash_restored,
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add)
        .saturating_add(usize::try_from(r.orphan_sidecars_removed).unwrap_or(usize::MAX));
        Self {
            repaired,
            missing_blobs: r.missing_total,
            orphan_blobs: r.orphan_blobs,
            failed_without_reason: r.failed_without_reason,
            errors: r.errors,
        }
    }
}

/// Condensed result of the last deep check, shown by the cheap Storage rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeepSummary {
    /// Unix seconds the run finished.
    pub at: i64,
    /// Releases whose blob is missing.
    pub missing: usize,
    /// The release/store comparison was incomplete (cap, timeout, or read error).
    pub partial: bool,
    /// Database integrity checks passed.
    pub db_ok: bool,
}

/// Config-derived facts (no paths).
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // plain configuration flags
pub struct CfgFacts {
    /// `ingest.workers` in force (automatic resolved).
    pub workers: u32,
    /// `ingest.queue_cap`.
    pub queue_cap: usize,
    /// `search.lag_warn_secs`.
    pub lag_warn_secs: u64,
    /// `ingest.scan_interval_secs`.
    pub scan_interval: u64,
    /// `ingest.atomic_moves`.
    pub atomic_moves: bool,
    /// `ingest.recursive`.
    pub recursive: bool,
    /// `server.insecure_cookies`.
    pub insecure_cookies: bool,
    /// The listen address is loopback.
    pub loopback: bool,
    /// `server.trusted_proxies` is not empty.
    pub has_proxies: bool,
    /// Number of `server.allowed_hosts`.
    pub allowed_hosts: usize,
    /// `security.multi_user`.
    pub multi_user: bool,
}

impl CfgFacts {
    /// Extracts the facts from the typed configuration.
    #[must_use]
    pub fn of(cfg: &Config) -> Self {
        Self {
            workers: cfg.ingest.effective_workers(),
            queue_cap: cfg.ingest.queue_cap,
            lag_warn_secs: cfg.search.lag_warn_secs,
            scan_interval: cfg.ingest.scan_interval_secs,
            atomic_moves: cfg.ingest.atomic_moves,
            recursive: cfg.ingest.recursive,
            insecure_cookies: cfg.server.insecure_cookies,
            loopback: cfg.server.listen.ip().is_loopback(),
            has_proxies: !cfg.server.trusted_proxies.is_empty(),
            allowed_hosts: cfg.server.allowed_hosts.len(),
            multi_user: cfg.security.multi_user,
        }
    }
}

/// Everything [`build`] needs.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Evaluation time (unix seconds).
    pub now: i64,
    /// Seconds since process start (`None` in the CLI).
    pub uptime: Option<u64>,
    /// Live ingest state (`None` in the CLI).
    pub live: Option<LiveFacts>,
    /// Built with the `dev-tools` feature.
    pub dev_tools: bool,
    /// Built without optimizations.
    pub debug_build: bool,
    /// Configuration facts.
    pub cfg: CfgFacts,
    /// Process facts.
    pub proc: ProcFacts,
    /// Database facts (`None` = could not be opened).
    pub db: Option<DbFacts>,
    /// Filesystem facts.
    pub fs: FsFacts,
    /// Startup recovery summary.
    pub recovery: Option<RecoverySummary>,
    /// Last deep check.
    pub deep: Option<DeepSummary>,
    /// Result of the loopback `/healthz` probe (CLI only).
    pub http_probe: Option<bool>,
}

// ---------------------------------------------------------------------------------------------
// Formatting helpers

/// "12 s", "5 min", "3 h", "2 d".
#[must_use]
pub fn fmt_secs(secs: i64) -> String {
    let s = secs.max(0);
    if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} d", s / 86_400)
    }
}

fn fmt_age(now: i64, then: i64) -> String {
    format!("{} ago", fmt_secs(now.saturating_sub(then)))
}

fn mk(
    group: Group,
    name: &'static str,
    status: Status,
    value: impl Into<String>,
    hint: &str,
) -> Check {
    Check::new(group, name, status, value, hint)
}

// ---------------------------------------------------------------------------------------------
// Pure checks: application

/// Uptime of the server process.
#[must_use]
pub fn uptime_check(uptime: Option<u64>) -> Check {
    match uptime {
        Some(s) => mk(
            Group::App,
            "Uptime",
            Status::Ok,
            fmt_secs(i64::try_from(s).unwrap_or(i64::MAX)),
            "",
        ),
        None => mk(
            Group::App,
            "Uptime",
            Status::Info,
            "n/a (not the server process)",
            "",
        ),
    }
}

/// Resident memory: WARN above [`RSS_WARN_KIB`] (1 GiB).
#[must_use]
pub fn memory_check(rss_kib: Option<u64>) -> Check {
    match rss_kib {
        None => mk(Group::App, "Memory (RSS)", Status::Info, "n/a", ""),
        Some(k) if k > RSS_WARN_KIB => mk(
            Group::App,
            "Memory (RSS)",
            Status::Warn,
            human_bytes(k.saturating_mul(1024)),
            "Unusually high for this application. Restart it and watch whether it grows again.",
        ),
        Some(k) => mk(
            Group::App,
            "Memory (RSS)",
            Status::Ok,
            human_bytes(k.saturating_mul(1024)),
            "",
        ),
    }
}

/// Open file descriptors: WARN from 80 % of the soft limit, FAIL from 95 %.
#[must_use]
pub fn fd_check(open: Option<u64>, limit: Option<u64>) -> Check {
    let Some(open) = open else {
        return mk(Group::App, "Open file descriptors", Status::Info, "n/a", "");
    };
    let Some(limit) = limit.filter(|l| *l > 0) else {
        return mk(
            Group::App,
            "Open file descriptors",
            Status::Ok,
            format!("{open} (no limit)"),
            "",
        );
    };
    let value = format!("{open} of {limit}");
    let used = open.saturating_mul(100);
    if used >= limit.saturating_mul(95) {
        mk(
            Group::App,
            "Open file descriptors",
            Status::Fail,
            value,
            "Almost out of descriptors. Raise the container's nofile limit and restart.",
        )
    } else if used >= limit.saturating_mul(80) {
        mk(
            Group::App,
            "Open file descriptors",
            Status::Warn,
            value,
            "High descriptor use. Check for a connection flood or raise the nofile limit.",
        )
    } else {
        mk(Group::App, "Open file descriptors", Status::Ok, value, "")
    }
}

/// Clock sanity: FAIL before 2024 (clock not set), WARN when the newest ingest record lies
/// more than five minutes in the future (the clock went backwards).
#[must_use]
pub fn clock_check(now: i64, newest_ingest: Option<i64>) -> Check {
    let value = nzb_web::fmt_utc(now);
    if now < CLOCK_FLOOR {
        return mk(
            Group::App,
            "Server time",
            Status::Fail,
            value,
            "The clock is wrong. Sessions, backups and ingest times depend on it; fix the host clock.",
        );
    }
    if newest_ingest.is_some_and(|t| t > now.saturating_add(CLOCK_SKEW_SECS)) {
        return mk(
            Group::App,
            "Server time",
            Status::Warn,
            value,
            "An ingest record is dated in the future: the clock was set back. Check host time sync.",
        );
    }
    mk(Group::App, "Server time", Status::Ok, value, "")
}

/// Build profile: a debug build is slow and not meant for production.
#[must_use]
pub fn build_check(debug: bool) -> Check {
    if debug {
        mk(
            Group::App,
            "Build profile",
            Status::Warn,
            "debug",
            "Use the release image for real use; debug builds are slow.",
        )
    } else {
        mk(Group::App, "Build profile", Status::Ok, "release", "")
    }
}

// ---------------------------------------------------------------------------------------------
// Pure checks: database

fn ping_check(name: &'static str, ok: bool) -> Check {
    if ok {
        mk(Group::Database, name, Status::Ok, "answers", "")
    } else {
        mk(
            Group::Database,
            name,
            Status::Fail,
            "no answer",
            "The database is unreachable or locked. See the server log; restart if it persists.",
        )
    }
}

/// Migration state: FAIL unless every embedded migration is applied and nothing newer exists.
#[must_use]
pub fn schema_check(s: Option<SchemaInfo>) -> Check {
    let Some(s) = s else {
        return mk(
            Group::Database,
            "Schema version",
            Status::Fail,
            "unreadable",
            "The migration table could not be read. See the server log.",
        );
    };
    let value = format!(
        "v{} ({} of {} migrations applied)",
        s.latest_applied, s.applied, s.embedded
    );
    if s.latest_applied > s.embedded_latest {
        mk(
            Group::Database,
            "Schema version",
            Status::Fail,
            value,
            "The database is newer than this program. Do not downgrade; run the matching version.",
        )
    } else if s.applied < s.embedded || s.latest_applied < s.embedded_latest {
        mk(
            Group::Database,
            "Schema version",
            Status::Fail,
            value,
            "Migrations are pending. Restart the server so it can apply them.",
        )
    } else {
        mk(Group::Database, "Schema version", Status::Ok, value, "")
    }
}

/// Database and WAL file sizes: WARN when the WAL exceeds [`WAL_WARN_BYTES`].
#[must_use]
pub fn wal_checks(db: Option<u64>, wal: Option<u64>) -> Vec<Check> {
    let size = |b: Option<u64>| b.map_or_else(|| "n/a".to_owned(), human_bytes);
    let mut v = vec![mk(
        Group::Database,
        "Database file size",
        Status::Info,
        size(db),
        "",
    )];
    v.push(match wal {
        Some(w) if w > WAL_WARN_BYTES => mk(
            Group::Database,
            "WAL file size",
            Status::Warn,
            human_bytes(w),
            "Checkpoints are not completing, often a long reader. Restart the server to checkpoint.",
        ),
        Some(w) => mk(Group::Database, "WAL file size", Status::Ok, human_bytes(w), ""),
        None => mk(Group::Database, "WAL file size", Status::Info, "n/a", ""),
    });
    v
}

/// Pool sanity: FAIL if a pool is closed.
#[must_use]
pub fn pools_check(p: PoolInfo) -> Check {
    let value = format!(
        "writer {} open; readers {} of {} open ({} idle)",
        p.writer_open, p.readers_open, p.readers_max, p.readers_idle
    );
    if p.closed {
        mk(
            Group::Database,
            "Connection pools",
            Status::Fail,
            value,
            "A pool is closed; the server is shutting down or broken. Restart it.",
        )
    } else {
        mk(Group::Database, "Connection pools", Status::Ok, value, "")
    }
}

/// Row counts: INFO for releases; WARN when a log table exceeds [`LOG_ROWS_WARN`].
#[must_use]
pub fn count_checks(totals: Option<ReleaseTotals>, logs: Option<LogCounts>) -> Vec<Check> {
    let mut v = Vec::new();
    v.push(match totals {
        Some(t) => mk(
            Group::Database,
            "Releases and files",
            Status::Info,
            format!(
                "{} releases, {} files, {}",
                t.releases,
                t.files,
                human_bytes(t.bytes)
            ),
            "",
        ),
        None => mk(
            Group::Database,
            "Releases and files",
            Status::Info,
            "n/a",
            "",
        ),
    });
    v.push(match logs {
        Some(l) => {
            let span = match (l.ingest_oldest, l.ingest_newest) {
                (Some(lo), Some(hi)) => {
                    format!(
                        "; ingest log from {} to {}",
                        nzb_web::fmt_utc(lo),
                        nzb_web::fmt_utc(hi)
                    )
                }
                _ => "; ingest log empty".to_owned(),
            };
            let value = format!(
                "{} ingest rows, {} audit rows{span}",
                l.ingest_rows, l.audit_rows
            );
            if l.ingest_rows > LOG_ROWS_WARN || l.audit_rows > LOG_ROWS_WARN {
                mk(
                    Group::Database,
                    "Log tables",
                    Status::Warn,
                    value,
                    "Logs are growing. `nzbd serve` purges them daily by the database retention policy (`nzbd db set-retention`); otherwise run `nzbd backup`.",
                )
            } else {
                mk(Group::Database, "Log tables", Status::Ok, value, "")
            }
        }
        None => mk(Group::Database, "Log tables", Status::Info, "n/a", ""),
    });
    v
}

// ---------------------------------------------------------------------------------------------
// Pure checks: ingest

/// Scan loop heartbeat: FAIL when none or older than 3 x the scan interval (the same rule as
/// `/healthz`), WARN beyond 2 x.
#[must_use]
pub fn scan_check(last: Option<i64>, now: i64, interval: u64) -> Check {
    let name = "Watch-folder scan";
    let Some(t) = last else {
        return mk(
            Group::Ingest,
            name,
            Status::Fail,
            "no completed scan yet",
            "The scan loop has not run. Check the server log for ingest errors.",
        );
    };
    let age = now.saturating_sub(t).max(0);
    let iv = i64::try_from(interval).unwrap_or(i64::MAX);
    let value = format!("last cycle {} ago (interval {interval} s)", fmt_secs(age));
    if age > iv.saturating_mul(3) {
        mk(
            Group::Ingest,
            name,
            Status::Fail,
            value,
            "The scan loop is stuck or dead (/healthz reports unhealthy). Restart the server.",
        )
    } else if age > iv.saturating_mul(2) {
        mk(
            Group::Ingest,
            name,
            Status::Warn,
            value,
            "A scan cycle is late. Large watch folders or a slow disk can cause this.",
        )
    } else {
        mk(Group::Ingest, name, Status::Ok, value, "")
    }
}

/// Counters since start and queue capacity (the depth is not exposed by the pipeline).
#[must_use]
pub fn counter_checks(live: Option<LiveFacts>, cfg: CfgFacts, now: i64) -> Vec<Check> {
    let workers = cfg.workers;
    let mut v = vec![
        mk(
            Group::Ingest,
            "Ingest workers",
            Status::Ok,
            format!("{workers} in use"),
            "",
        ),
        mk(
            Group::Ingest,
            "Ingest queue",
            Status::Info,
            format!("capacity {}; depth n/a (not exposed)", cfg.queue_cap),
            "",
        ),
    ];
    match live {
        Some(l) => {
            v.push(mk(
                Group::Ingest,
                "Counters since start",
                Status::Info,
                format!(
                    "{} ingested, {} duplicates, {} failed; {} commit groups; {} in flight",
                    l.ok,
                    l.duplicates,
                    l.failed,
                    l.commit_groups,
                    fmt_bytes(l.inflight_bytes)
                ),
                "",
            ));
            v.push(mk(
                Group::Ingest,
                "Last success since start",
                Status::Info,
                l.last_success
                    .map_or_else(|| "none yet".to_owned(), |t| fmt_age(now, t)),
                "",
            ));
        }
        None => v.push(mk(
            Group::Ingest,
            "Counters since start",
            Status::Info,
            "n/a (not the server process)",
            "",
        )),
    }
    v
}

/// Index lag (T114, ARCHITECTURE v3 3.2): changes not yet in the search index and the age of the oldest. WARN beyond
/// `search.lag_warn_secs`, and while the watch-folder scanner is paused for it.
#[must_use]
pub fn index_lag_check(
    outbox: Option<nzb_store::OutboxLag>,
    warn_secs: u64,
    paused: bool,
) -> Check {
    let name = "Search index lag";
    let Some(o) = outbox else {
        return mk(
            Group::Ingest,
            name,
            Status::Warn,
            "unknown",
            "The search outbox cannot be read. See the server log.",
        );
    };
    let value = if o.depth == 0 {
        "up to date".to_owned()
    } else {
        format!(
            "{} change(s) pending, oldest {} old",
            group_thousands(usize::try_from(o.depth).unwrap_or(usize::MAX)),
            fmt_secs(i64::try_from(o.lag_secs).unwrap_or(i64::MAX))
        )
    };
    if paused {
        mk(
            Group::Ingest,
            name,
            Status::Warn,
            format!("{value}; watch-folder scanning paused"),
            "The index is far behind (search.lag_pause_rows); scanning resumes by itself once it has caught up.",
        )
    } else if o.lag_secs > warn_secs {
        mk(
            Group::Ingest,
            name,
            Status::Warn,
            value,
            "New releases appear in lists late. A bulk import or a rebuild can cause this; otherwise check the server log for indexer errors.",
        )
    } else {
        mk(Group::Ingest, name, Status::Ok, value, "")
    }
}

/// Newest successful ingest according to the database log.
#[must_use]
pub fn last_ingest_check(last_ok: Option<i64>, now: i64) -> Check {
    mk(
        Group::Ingest,
        "Last successful ingest",
        Status::Info,
        last_ok.map_or_else(|| "never".to_owned(), |t| fmt_age(now, t)),
        "",
    )
}

/// Files waiting in the watch folder: INFO up to 100, WARN beyond (a backlog) or when capped,
/// FAIL when unreadable.
#[must_use]
pub fn waiting_check(c: Result<Count, ()>, recursive: bool) -> Check {
    let name = "Files waiting in watch folder";
    match c {
        Err(()) => mk(
            Group::Ingest,
            name,
            Status::Fail,
            "unreadable",
            "The watch folder cannot be listed. Check its mount and permissions.",
        ),
        Ok(c) if c.capped || c.n > 100 => mk(
            Group::Ingest,
            name,
            Status::Warn,
            c.show(),
            "A backlog is waiting. If the scan is healthy it will drain; otherwise see the failed folder.",
        ),
        Ok(c) => mk(
            Group::Ingest,
            name,
            Status::Ok,
            if recursive {
                format!("{} (top level)", c.show())
            } else {
                c.show()
            },
            "",
        ),
    }
}

/// `failed/`: OK when empty, WARN when files wait there, FAIL when unreadable.
#[must_use]
pub fn failed_dir_check(c: Result<Count, ()>) -> Check {
    let name = "Failed folder";
    match c {
        Err(()) => mk(
            Group::Ingest,
            name,
            Status::Fail,
            "unreadable",
            "The failed folder cannot be listed. Check its mount and permissions.",
        ),
        Ok(c) if c.n == 0 => mk(Group::Ingest, name, Status::Ok, "empty", ""),
        Ok(c) => mk(
            Group::Ingest,
            name,
            Status::Warn,
            format!("{} file(s)", c.show()),
            "Review them under Admin, then fix and re-add or run `nzbd failed retry`.",
        ),
    }
}

/// `duplicates/`: informational.
#[must_use]
pub fn duplicates_dir_check(c: Result<Count, ()>) -> Check {
    let name = "Duplicates folder";
    match c {
        Err(()) => mk(
            Group::Ingest,
            name,
            Status::Warn,
            "unreadable",
            "The duplicates folder cannot be listed. Check its mount and permissions.",
        ),
        Ok(c) => mk(
            Group::Ingest,
            name,
            Status::Info,
            format!("{} file(s)", c.show()),
            "",
        ),
    }
}

/// Interrupted-move leftovers (`.nzbd-trash.*`, stale `.part`): WARN when present.
#[must_use]
pub fn leftovers_check(n: usize) -> Check {
    if n == 0 {
        mk(
            Group::Ingest,
            "Leftover temporary files",
            Status::Ok,
            "none",
            "",
        )
    } else {
        mk(
            Group::Ingest,
            "Leftover temporary files",
            Status::Warn,
            format!("{n} found"),
            "A crash left hidden files behind. Restarting the server runs recovery, which handles them safely.",
        )
    }
}

/// Startup recovery summary.
#[must_use]
pub fn recovery_check(r: Option<RecoverySummary>) -> Check {
    let name = "Startup recovery";
    let Some(r) = r else {
        return mk(
            Group::Ingest,
            name,
            Status::Info,
            "n/a (not the server process)",
            "",
        );
    };
    let value = format!(
        "{} repaired, {} missing blobs, {} orphan blobs, {} errors",
        r.repaired, r.missing_blobs, r.orphan_blobs, r.errors
    );
    if r.errors > 0 || r.missing_blobs > 0 {
        mk(
            Group::Ingest,
            name,
            Status::Warn,
            value,
            "Run `nzbd store verify` on the host; restore missing blobs from your NZB sources.",
        )
    } else {
        mk(Group::Ingest, name, Status::Ok, value, "")
    }
}

// ---------------------------------------------------------------------------------------------
// Pure checks: storage

/// Free-space verdict: FAIL below 2 % or 64 MiB, WARN below 10 % or 1 GiB.
#[must_use]
pub fn free_status(free: u64, total: u64) -> Status {
    const MIB: u64 = 1024 * 1024;
    let pct_x100 = free.saturating_mul(10_000).checked_div(total).unwrap_or(0);
    if free < 64 * MIB || pct_x100 < 200 {
        Status::Fail
    } else if free < 1024 * MIB || pct_x100 < 1000 {
        Status::Warn
    } else {
        Status::Ok
    }
}

/// One configured directory: exists, is a directory, writable, free space.
#[must_use]
pub fn dir_check(d: &DirFacts) -> Check {
    let name = d.name;
    if !d.exists || !d.is_dir {
        return mk(
            Group::Storage,
            name,
            Status::Fail,
            if d.exists {
                "not a directory"
            } else {
                "missing"
            },
            "Create or mount the directory as configured, then restart the server.",
        );
    }
    let mut parts = Vec::new();
    let mut status = Status::Ok;
    let mut hint = "";
    match d.writable {
        Some(true) => parts.push("writable".to_owned()),
        Some(false) => {
            parts.push("NOT writable".to_owned());
            status = Status::Fail;
            hint = "The process cannot write here. Fix ownership or permissions of the mount.";
        }
        None => parts.push("writability n/a".to_owned()),
    }
    match d.free {
        Some((free, total)) => {
            let pct = free.saturating_mul(100).checked_div(total).unwrap_or(0);
            parts.push(format!("{pct}% free ({})", human_bytes(free)));
            let fs = free_status(free, total);
            if fs == Status::Fail || (fs == Status::Warn && status == Status::Ok) {
                status = fs;
                hint = "Free up disk space or grow the volume before ingest starts failing.";
            }
        }
        None => parts.push("free space n/a".to_owned()),
    }
    mk(Group::Storage, name, status, parts.join(", "), hint)
}

/// Watch, store and failed on one filesystem (atomic renames): FAIL when
/// `ingest.atomic_moves` demands it, WARN otherwise.
#[must_use]
pub fn same_fs_check(same: Option<bool>, atomic_moves: bool) -> Check {
    let name = "Same filesystem (watch, store, failed)";
    match same {
        None => mk(Group::Storage, name, Status::Info, "n/a", ""),
        Some(true) => mk(
            Group::Storage,
            name,
            Status::Ok,
            "yes, moves are atomic",
            "",
        ),
        Some(false) => mk(
            Group::Storage,
            name,
            if atomic_moves {
                Status::Fail
            } else {
                Status::Warn
            },
            "no",
            "Mount watch, store and failed on one volume so files move atomically.",
        ),
    }
}

/// `ANCHOR_SAME_FILESYSTEM` (review 34 M3): with SQLite, a snapshot of one filesystem that rolls back both the database
/// and `paths.state` is not detected; `paths.state` belongs on its own volume.
#[must_use]
pub fn anchor_same_fs_check() -> Check {
    mk(
        Group::Storage,
        "Restore detection",
        Status::Warn,
        "ANCHOR_SAME_FILESYSTEM: paths.state is on the database's filesystem",
        "Put paths.state on its own volume; a snapshot that rolls back both is not detected. Keep the logged anchor lines.",
    )
}

/// No directory lies inside another (reuses the startup validation).
#[must_use]
pub fn layout_check(ok: bool) -> Check {
    if ok {
        mk(
            Group::Storage,
            "Directory layout",
            Status::Ok,
            "no overlap",
            "",
        )
    } else {
        mk(
            Group::Storage,
            "Directory layout",
            Status::Fail,
            "directories overlap or cannot be resolved",
            "Run `nzbd config check` on the host and fix paths.* so no directory contains another.",
        )
    }
}

/// Quarantined blobs from `store gc` (restorable, informational).
#[must_use]
pub fn gc_trash_check(n: Option<usize>) -> Check {
    mk(
        Group::Storage,
        "Store quarantine (gc)",
        Status::Info,
        n.map_or_else(|| "n/a".to_owned(), |n| format!("{n} blob(s) restorable")),
        "",
    )
}

/// The cheap audit-chain row (T105): the stored row counts and head hashes against the rows themselves, no walk.
/// `Fail` means the log changed outside the application (or a backup restore mixed states); the full walk is
/// `nzbd audit verify` and the deep check.
#[must_use]
pub fn audit_chain_check(q: Option<ChainQuick>) -> Check {
    let g = Group::Security;
    let name = "Audit log chain";
    match q {
        None => mk(
            g,
            name,
            Status::Warn,
            "could not be read",
            "The database may predate this version; start the server once, then run `nzbd audit verify`.",
        ),
        Some(q) if !q.bootstrapped => mk(
            g,
            name,
            Status::Warn,
            "pre-upgrade rows are not chained yet",
            "Start the server once; it chains them at startup.",
        ),
        Some(q) if !q.consistent || q.unchained > 0 => mk(
            g,
            name,
            Status::Fail,
            format!(
                "inconsistent ({} row(s) without a chain)",
                group_thousands(usize::try_from(q.unchained).unwrap_or(usize::MAX))
            ),
            "The audit log was changed outside the application. Run `nzbd audit verify` for the first broken id and restore from a backup if it was not you.",
        ),
        Some(q) => mk(
            g,
            name,
            Status::Ok,
            format!(
                "{} row(s), consistent",
                group_thousands(usize::try_from(q.rows).unwrap_or(usize::MAX))
            ),
            "",
        ),
    }
}

/// Result of the last deep check as seen by the cheap Storage rows.
#[must_use]
pub fn deep_summary_check(d: Option<DeepSummary>, now: i64) -> Check {
    let name = "Store vs database (last deep check)";
    match d {
        None => mk(
            Group::Storage,
            name,
            Status::Info,
            "not run since start",
            "Use Run deep check below to compare every release with its blob.",
        ),
        Some(d) if d.missing > 0 || !d.db_ok => mk(
            Group::Storage,
            name,
            Status::Fail,
            format!("{} missing blob(s); {}", d.missing, fmt_age(now, d.at)),
            "Run `nzbd store verify` on the host and restore the missing NZBs.",
        ),
        Some(d) if d.partial => mk(
            Group::Storage,
            name,
            Status::Warn,
            format!("incomplete check; {}", fmt_age(now, d.at)),
            "The last comparison could not cover every release. Run the deep check again or use `nzbd store verify` on the host.",
        ),
        Some(d) => mk(
            Group::Storage,
            name,
            Status::Ok,
            format!("consistent; {}", fmt_age(now, d.at)),
            "",
        ),
    }
}

/// Newest backup: WARN when none exists, the directory is unreadable, or the newest is older
/// than [`BACKUP_MAX_AGE_SECS`] (3 days; the policy keeps 14).
#[must_use]
pub fn backup_check(b: Result<(Option<i64>, usize), ()>, now: i64) -> Check {
    let name = "Database backups";
    let keep = nzb_store::DEFAULT_KEEP;
    match b {
        Err(()) => mk(
            Group::Storage,
            name,
            Status::Warn,
            "backup folder unreadable",
            "Check the backups mount, then run `nzbd backup`.",
        ),
        Ok((None, _)) => mk(
            Group::Storage,
            name,
            Status::Warn,
            "no backup found",
            "Backups are made daily by `nzbd serve` after the first 60 s; if maintenance.backup_interval_hours is 0, schedule `nzbd backup`.",
        ),
        Ok((Some(t), n)) if now.saturating_sub(t) > BACKUP_MAX_AGE_SECS => mk(
            Group::Storage,
            name,
            Status::Warn,
            format!("newest {}; {n} kept (policy: {keep})", fmt_age(now, t)),
            "The backup job seems to have stopped. Run `nzbd backup` and check the schedule.",
        ),
        Ok((Some(t), n)) => mk(
            Group::Storage,
            name,
            Status::Ok,
            format!("newest {}; {n} kept (policy: {keep})", fmt_age(now, t)),
            "",
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Pure checks: security and configuration

/// Security and configuration rows.
#[must_use]
#[allow(clippy::too_many_lines)] // a flat list of independent rows
pub fn security_checks(
    cfg: CfgFacts,
    key_ok: bool,
    sec: Option<SecurityFacts>,
    dev_tools: bool,
) -> Vec<Check> {
    let g = Group::Security;
    let mut v = Vec::new();
    v.push(if key_ok {
        mk(g, "TOTP encryption key", Status::Ok, "configured, permissions and owner OK", "")
    } else {
        mk(
            g,
            "TOTP encryption key",
            Status::Fail,
            "missing, unreadable or unsafe",
            "Run `nzbd config check` on the host; the key file must be 0400, owned by the service user.",
        )
    });
    v.push(if cfg.insecure_cookies {
        mk(
            g,
            "Cookies",
            Status::Warn,
            "plain-HTTP cookies allowed (insecure_cookies)",
            "Development only. Turn it off behind HTTPS.",
        )
    } else {
        mk(g, "Cookies", Status::Ok, "secure cookies only", "")
    });
    v.push(if !cfg.loopback && !cfg.has_proxies {
        mk(
            g,
            "Listen address",
            Status::Warn,
            "reachable beyond this host, no trusted proxy configured",
            "Put a TLS proxy in front and set server.trusted_proxies, or bind to loopback.",
        )
    } else if cfg.loopback {
        mk(g, "Listen address", Status::Ok, "loopback only", "")
    } else {
        mk(
            g,
            "Listen address",
            Status::Ok,
            "non-loopback with trusted proxy",
            "",
        )
    });
    v.push(mk(
        g,
        "Extra allowed hosts",
        Status::Info,
        if cfg.allowed_hosts == 0 {
            "none (localhost and IP literals only)".to_owned()
        } else {
            format!("{} configured", cfg.allowed_hosts)
        },
        "",
    ));
    v.push(if dev_tools {
        mk(
            g,
            "Build features",
            Status::Fail,
            "dev-tools compiled in",
            "This binary contains development helpers. Deploy the release image instead.",
        )
    } else {
        mk(g, "Build features", Status::Ok, "no development tools", "")
    });
    v.push(mk(
        g,
        "Segment health check",
        Status::Info,
        if nzb_web::SEGMENT_HEALTH_CHECK_AVAILABLE {
            "available"
        } else {
            "not available (segment counts shown as max/max)"
        },
        "",
    ));
    v.push(mk(
        g,
        "Outbound network",
        Status::Ok,
        "The application makes no outbound connections (by design)",
        "",
    ));
    match sec {
        None => v.push(mk(
            g,
            "Account",
            Status::Info,
            "n/a (database unavailable)",
            "",
        )),
        Some(s) => {
            v.push(if s.user_exists {
                mk(g, "User account", Status::Ok, "exists", "")
            } else {
                mk(
                    g,
                    "User account",
                    Status::Fail,
                    "no user",
                    "Create one with `nzbd user create <name>` on the host.",
                )
            });
            if s.live_accounts > 1 && !cfg.multi_user {
                v.push(mk(
                    g,
                    "Accounts",
                    Status::Warn,
                    format!("{} accounts exist but multi_user is off", s.live_accounts),
                    "Set security.multi_user = true to use them as intended, or remove the extra accounts with `nzbd user delete`.",
                ));
            } else if s.live_accounts > 1 {
                v.push(mk(
                    g,
                    "Accounts",
                    Status::Info,
                    s.live_accounts.to_string(),
                    "",
                ));
            }
            if s.reserved_names > 0 {
                v.push(mk(
                    g,
                    "Reserved login names",
                    Status::Warn,
                    format!(
                        "{} login name(s) use a reserved or display-handle form",
                        s.reserved_names
                    ),
                    "Such accounts keep working but cannot be told apart from system actors in logs; create a new account and delete this one.",
                ));
            }
            if s.throttled_accounts > 0 {
                v.push(mk(
                    g,
                    "Throttled accounts",
                    Status::Warn,
                    format!("{} account(s) under unknown-address throttling", s.throttled_accounts),
                    "Someone may be guessing a password. Review the audit log (`account_throttled`); `nzbd user unlock <name>` clears it.",
                ));
            }
            if s.user_exists {
                v.push(if s.totp_enabled {
                    mk(g, "Two-factor sign-in (TOTP)", Status::Ok, "enrolled", "")
                } else {
                    mk(
                        g,
                        "Two-factor sign-in (TOTP)",
                        Status::Warn,
                        "not enrolled",
                        "Finish enrolment at the next sign-in (`nzbd user enroll-token` prints a token).",
                    )
                });
            }
            v.push(mk(
                g,
                "Active sessions",
                Status::Info,
                s.active_sessions.to_string(),
                "",
            ));
            v.push(mk(
                g,
                "Active API keys",
                Status::Info,
                s.active_api_keys.to_string(),
                "",
            ));
            v.push(if s.failed_logins_recent > FAILED_LOGIN_WARN {
                mk(
                    g,
                    "Failed sign-ins (24 h)",
                    Status::Warn,
                    s.failed_logins_recent.to_string(),
                    "Someone may be guessing the password. Review the audit log; consider a proxy-level block.",
                )
            } else {
                mk(
                    g,
                    "Failed sign-ins (24 h)",
                    Status::Ok,
                    s.failed_logins_recent.to_string(),
                    "",
                )
            });
            v.push(if s.locked {
                mk(
                    g,
                    "Account lock",
                    Status::Warn,
                    "locked after repeated failures",
                    "It unlocks by itself; if it was not you, review the audit log.",
                )
            } else {
                mk(g, "Account lock", Status::Ok, "not locked", "")
            });
        }
    }
    v
}

/// Liveness probe row: in the server the in-process `/healthz` predicate, in the CLI a loopback
/// request to the listener.
#[must_use]
pub fn http_check(scan_fresh: Option<bool>, probe: Option<bool>) -> Check {
    let name = "Liveness probe (/healthz)";
    match (scan_fresh, probe) {
        (_, Some(true)) | (Some(true), None) => {
            mk(Group::Http, name, Status::Ok, "healthy (answers 200)", "")
        }
        (_, Some(false)) => mk(
            Group::Http,
            name,
            Status::Fail,
            "no 200 answer on the local listener",
            "Is `nzbd serve` running with this configuration?",
        ),
        (Some(false), None) => mk(
            Group::Http,
            name,
            Status::Fail,
            "unhealthy (would answer 503)",
            "The scan loop heartbeat is stale; restart the server.",
        ),
        (None, None) => mk(Group::Http, name, Status::Info, "n/a", ""),
    }
}

// ---------------------------------------------------------------------------------------------
// Assembly

/// Evaluates every cheap check. Pure: no I/O.
#[must_use]
pub fn build(i: &Inputs) -> Vec<Check> {
    let now = i.now;
    let newest_ingest =
        i.db.as_ref()
            .and_then(|d| d.logs.and_then(|l| l.ingest_newest));
    let mut v = vec![
        mk(
            Group::App,
            "Version",
            Status::Ok,
            env!("CARGO_PKG_VERSION"),
            "",
        ),
        uptime_check(i.uptime),
        memory_check(i.proc.rss_kib),
        fd_check(i.proc.open_fds, i.proc.fd_limit),
        clock_check(now, newest_ingest),
        build_check(i.debug_build),
    ];
    match &i.db {
        None => v.push(mk(
            Group::Database,
            "Database",
            Status::Fail,
            "cannot be opened",
            "Check paths.db and file permissions; see the server log.",
        )),
        Some(d) => {
            v.push(ping_check("Writer connection", d.writer_ok));
            v.push(ping_check("Reader connection", d.reader_ok));
            v.push(schema_check(d.schema));
            v.extend(wal_checks(i.fs.db_bytes, i.fs.wal_bytes));
            v.push(pools_check(d.pools));
            v.extend(count_checks(d.totals, d.logs));
        }
    }
    if let Some(l) = i.live {
        v.push(scan_check(l.heartbeat, now, i.cfg.scan_interval));
    } else {
        v.push(mk(
            Group::Ingest,
            "Watch-folder scan",
            Status::Info,
            "n/a (not the server process)",
            "",
        ));
    }
    v.extend(counter_checks(i.live, i.cfg, now));
    if let Some(d) = i.db.as_ref() {
        v.push(index_lag_check(
            d.outbox,
            i.cfg.lag_warn_secs,
            i.live.is_some_and(|l| l.lag_paused),
        ));
    }
    v.push(last_ingest_check(
        i.live
            .and_then(|l| l.last_success)
            .or_else(|| i.db.as_ref().and_then(|d| d.last_ok_ingest)),
        now,
    ));
    v.push(waiting_check(i.fs.waiting, i.cfg.recursive));
    v.push(failed_dir_check(i.fs.failed));
    v.push(duplicates_dir_check(i.fs.duplicates));
    v.push(leftovers_check(i.fs.leftovers));
    v.push(recovery_check(i.recovery));
    v.extend(i.fs.dirs.iter().map(dir_check));
    v.push(same_fs_check(i.fs.same_fs, i.cfg.atomic_moves));
    v.push(layout_check(i.fs.layout_ok));
    if i.fs.anchor_same_fs {
        v.push(anchor_same_fs_check());
    }
    v.push(gc_trash_check(i.fs.gc_trash));
    v.push(deep_summary_check(i.deep, now));
    v.push(backup_check(i.fs.backups, now));
    v.extend(security_checks(
        i.cfg,
        i.fs.key_ok,
        i.db.as_ref().and_then(|d| d.security),
        i.dev_tools,
    ));
    if let Some(d) = i.db.as_ref() {
        v.push(audit_chain_check(d.audit_chain));
    }
    v.push(http_check(
        i.live
            .map(|l| ing_fresh(l.heartbeat, now, i.cfg.scan_interval)),
        i.http_probe,
    ));
    v
}

fn ing_fresh(last: Option<i64>, now: i64, interval: u64) -> bool {
    let iv = i64::try_from(interval).unwrap_or(i64::MAX);
    last.is_some_and(|t| now.saturating_sub(t) <= iv.saturating_mul(3))
}

// ---------------------------------------------------------------------------------------------
// Gathering (I/O)

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates and removes a uniquely named file under a reserved name.
fn write_probe(dir: &Path) -> bool {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let name = format!(
        ".nzbd-health-{}-{nanos}-{}",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let path = dir.join(name);
    let created = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .is_ok();
    if created {
        let _ = fs::remove_file(&path);
    }
    created
}

/// `(free, total)` bytes of the volume holding `dir`; `None` when unknown (also used by the upload
/// storage guard, which must not refuse on a volume it cannot measure).
pub(crate) fn free_space(dir: &Path) -> Option<(u64, u64)> {
    let s = rustix::fs::statvfs(dir).ok()?;
    let total = s.f_blocks.saturating_mul(s.f_frsize);
    // Some virtual filesystems report zero blocks: that is "unknown", not "full".
    (total > 0).then(|| (s.f_bavail.saturating_mul(s.f_frsize), total))
}

/// How a directory is tested for writability.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Create and remove a probe file here.
    Write,
    /// Create and remove a probe file in this sub-directory (it must already exist).
    WriteIn(&'static str),
    /// `stat` and `access(2)` only (the watch folder: the scanner must never see a probe).
    Access,
}

fn dir_facts(name: &'static str, path: &Path, probe: Probe) -> DirFacts {
    let meta = fs::metadata(path);
    let exists = meta.is_ok();
    let is_dir = meta.as_ref().is_ok_and(fs::Metadata::is_dir);
    let writable = if is_dir {
        match probe {
            Probe::Write => Some(write_probe(path)),
            Probe::WriteIn(sub) => {
                let p = path.join(sub);
                if p.is_dir() {
                    Some(write_probe(&p))
                } else {
                    Some(rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok())
                }
            }
            Probe::Access => Some(rustix::fs::access(path, rustix::fs::Access::WRITE_OK).is_ok()),
        }
    } else {
        None
    };
    DirFacts {
        name,
        exists,
        is_dir,
        writable,
        free: if is_dir { free_space(path) } else { None },
    }
}

/// Counts entries of `dir` accepted by `keep` (given the entry name and whether it is a
/// regular file; symlinks are never followed), stopping at [`COUNT_CAP`].
fn count_dir(dir: &Path, keep: &dyn Fn(&str, bool) -> bool) -> Result<Count, ()> {
    let rd = fs::read_dir(dir).map_err(|_| ())?;
    let mut n = 0usize;
    for e in rd {
        let Ok(e) = e else { continue };
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let is_file = e.file_type().is_ok_and(|t| t.is_file());
        if keep(&name, is_file) {
            if n >= COUNT_CAP {
                return Ok(Count { n, capped: true });
            }
            n = n.saturating_add(1);
        }
    }
    Ok(Count { n, capped: false })
}

fn is_nzb_candidate(name: &str, is_file: bool) -> bool {
    is_file && !name.starts_with('.') && name.to_ascii_lowercase().ends_with(".nzb")
}

fn is_leftover(name: &str) -> bool {
    name.starts_with(".nzbd-trash.")
        || (name.starts_with('.')
            && Path::new(name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("part")))
}

/// Parses `nzbd-YYYYMMDDTHHMMSSZ.sqlite` (or the encrypted `....sqlite.enc`) into unix seconds (UTC).
#[must_use]
pub fn parse_backup_ts(name: &str) -> Option<i64> {
    let name = name.strip_suffix(".enc").unwrap_or(name);
    // Both backends' backup names: the SQLite file copy (`Z.sqlite`) and the Postgres snapshot (`Z.nzbdpg`).
    let base = name.strip_prefix("nzbd-")?;
    let stamp = base
        .strip_suffix("Z.sqlite")
        .or_else(|| base.strip_suffix("Z.nzbdpg"))?;
    let b = stamp.as_bytes();
    if b.len() != 15 || b.get(8) != Some(&b'T') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = stamp.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())
            .flatten()
    };
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days_from_civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

fn scan_backups(dir: &Path) -> Result<(Option<i64>, usize), ()> {
    let rd = fs::read_dir(dir).map_err(|_| ())?;
    let (mut newest, mut n) = (None::<i64>, 0usize);
    for e in rd.take(COUNT_CAP) {
        let Ok(e) = e else { continue };
        let Some(ts) = e.file_name().to_str().and_then(parse_backup_ts) else {
            continue;
        };
        if e.file_type().is_ok_and(|t| t.is_file()) {
            n = n.saturating_add(1);
            newest = Some(newest.map_or(ts, |c| c.max(ts)));
        }
    }
    Ok((newest, n))
}

fn path_with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut os = p.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Reads every filesystem fact. Blocking; run it on a blocking thread.
#[must_use]
pub fn gather_fs(cfg: &Config) -> FsFacts {
    let p = &cfg.paths;
    let mut dirs = vec![
        dir_facts("Watch folder", &p.watch, Probe::Access),
        dir_facts("Blob store", &p.store, Probe::WriteIn(".tmp")),
        dir_facts("Failed folder", &p.failed, Probe::Write),
        dir_facts("Duplicates folder", &p.duplicates, Probe::Write),
        dir_facts("Upload staging folder", &p.tmp, Probe::Write),
        dir_facts("Backups folder", &p.backups, Probe::Write),
    ];
    if cfg.db.backend == nzb_store::DbBackend::Sqlite {
        // The SQLite directory is probed unless it is the watch folder itself.
        let db_dir =
            p.db.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
        let same_dir = |a: &Path, b: &Path| matches!((fs::canonicalize(a), fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y);
        let db_probe = if same_dir(db_dir, &p.watch) {
            Probe::Access
        } else {
            Probe::Write
        };
        dirs.push(dir_facts("Database folder", db_dir, db_probe));
    }
    let dev = |d: &Path| fs::metadata(d).map(|m| m.dev()).ok();
    let same_fs = match (dev(&p.watch), dev(&p.store), dev(&p.failed)) {
        (Some(a), Some(b), Some(c)) => Some(a == b && b == c),
        _ => None,
    };
    let leftovers = [&p.watch, &p.failed, &p.duplicates]
        .into_iter()
        .filter_map(|d| count_dir(d, &|n, _| is_leftover(n)).ok())
        .fold(0usize, |a, c| a.saturating_add(c.n));
    let (db_bytes, wal_bytes) = match cfg.db.backend {
        nzb_store::DbBackend::Sqlite => (
            fs::metadata(&p.db).map(|m| m.len()).ok(),
            match fs::metadata(path_with_suffix(&p.db, "-wal")) {
                Ok(m) => Some(m.len()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Some(0),
                Err(_) => None,
            },
        ),
        nzb_store::DbBackend::Postgres => (None, None),
    };
    FsFacts {
        dirs,
        db_bytes,
        wal_bytes,
        same_fs,
        layout_ok: cfg.check_layout().is_ok(),
        anchor_same_fs: crate::library::anchor_shares_filesystem(cfg),
        key_ok: crate::config::load_key_file(&cfg.security.totp_key_file).is_ok(),
        waiting: count_dir(&p.watch, &is_nzb_candidate),
        failed: count_dir(&p.failed, &|n, f| f && ing::is_failed_name(n)),
        // A sidecar NFO moved next to its duplicate NZB (T141) is not a duplicate of its own.
        duplicates: count_dir(&p.duplicates, &|n, f| {
            f && !n.starts_with('.') && !n.to_ascii_lowercase().ends_with(".nfo")
        }),
        leftovers,
        gc_trash: count_dir(&p.store.join(".gc-trash"), &|_, f| f)
            .map(|c| c.n)
            .ok()
            .or_else(|| {
                // No quarantine directory yet is a normal "0".
                (!p.store.join(".gc-trash").exists()).then_some(0)
            }),
        backups: scan_backups(&p.backups),
    }
}

/// `/proc/self` facts; every field degrades to `None`.
#[must_use]
pub fn gather_proc() -> ProcFacts {
    ProcFacts {
        rss_kib: fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| parse_rss_kib(&s)),
        open_fds: fs::read_dir("/proc/self/fd")
            .ok()
            .map(|d| u64::try_from(d.count()).unwrap_or(u64::MAX)),
        fd_limit: fs::read_to_string("/proc/self/limits")
            .ok()
            .and_then(|s| parse_fd_limit(&s)),
    }
}

/// Extracts `VmRSS` (KiB) from `/proc/self/status`.
#[must_use]
pub fn parse_rss_kib(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Extracts the soft "Max open files" limit from `/proc/self/limits` (`unlimited` = `None`).
#[must_use]
pub fn parse_fd_limit(limits: &str) -> Option<u64> {
    limits
        .lines()
        .find_map(|l| l.strip_prefix("Max open files"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Reads the database facts. Each query is independent; a failure only blanks its own row.
pub async fn gather_db(db: &nzb_store::Store, now: i64) -> DbFacts {
    let (w, r, schema, totals, logs, sec, last, chain, outbox) = tokio::join!(
        db.ping_writer(),
        db.ping(),
        db.schema_info(),
        db.release_totals(),
        db.log_counts(),
        db.security_facts(now, now.saturating_sub(86_400)),
        db.last_ok_ingest_ts(),
        db.audit_chain_quick(),
        db.search_outbox_lag(),
    );
    DbFacts {
        writer_ok: w.is_ok(),
        reader_ok: r.is_ok(),
        schema: schema.ok(),
        totals: totals.ok(),
        logs: logs.ok(),
        pools: db.pool_info(),
        security: sec.ok(),
        last_ok_ingest: last.ok().flatten(),
        audit_chain: chain.ok(),
        outbox: outbox.ok(),
    }
}

// ---------------------------------------------------------------------------------------------
// Engine

/// Handles to the running ingest side.
#[derive(Clone)]
pub struct LiveHandles {
    /// Scan-loop heartbeat.
    pub heartbeat: ing::Heartbeat,
    /// Filled once the workers run.
    pub pipeline: Arc<OnceLock<ing::Pipeline>>,
    /// The scanner's index-lag gate (SEC-092).
    pub lag_gate: Option<ing::LagGate>,
}

/// Everything the checks need, cheap to clone into `'static` closures.
#[derive(Clone)]
pub struct Engine {
    cfg: Arc<Config>,
    db: Option<nzb_store::Store>,
    live: Option<LiveHandles>,
    started: Instant,
    dev_tools: bool,
    recovery: Arc<OnceLock<RecoverySummary>>,
    last_deep: Arc<Mutex<Option<DeepSummary>>>,
}

impl Engine {
    /// Engine for the server process.
    #[must_use]
    pub fn server(
        cfg: &Config,
        db: nzb_store::Store,
        live: LiveHandles,
        recovery: Arc<OnceLock<RecoverySummary>>,
        dev_tools: bool,
    ) -> Self {
        Self {
            cfg: Arc::new(cfg.clone()),
            db: Some(db),
            live: Some(live),
            started: Instant::now(),
            dev_tools,
            recovery,
            last_deep: Arc::new(Mutex::new(None)),
        }
    }

    /// Engine for the CLI: files and database only, no live state.
    #[must_use]
    pub fn offline(cfg: &Config, db: Option<nzb_store::Store>, dev_tools: bool) -> Self {
        Self {
            cfg: Arc::new(cfg.clone()),
            db,
            live: None,
            started: Instant::now(),
            dev_tools,
            recovery: Arc::new(OnceLock::new()),
            last_deep: Arc::new(Mutex::new(None)),
        }
    }

    fn live_facts(&self) -> Option<LiveFacts> {
        let h = self.live.as_ref()?;
        let st = h.pipeline.get().map(ing::Pipeline::stats);
        Some(LiveFacts {
            heartbeat: h.heartbeat.last(),
            ok: st.map_or(0, |s| s.ingested_ok),
            duplicates: st.map_or(0, |s| s.duplicates),
            failed: st.map_or(0, |s| s.failed),
            last_success: st.map(|s| s.last_success_at).filter(|t| *t > 0),
            commit_groups: st.map_or(0, |s| s.commit_groups),
            inflight_bytes: st.map_or(0, |s| s.inflight_bytes),
            lag_paused: h.lag_gate.as_ref().is_some_and(ing::LagGate::is_paused),
        })
    }

    /// Facts for the metrics listener (T105): database aggregates, `/proc/self` and, for SQLite, two `stat` calls. Unlike
    /// [`Engine::inputs`] it never writes a probe file.
    pub async fn metrics_facts(&self, now: i64) -> crate::metrics::MetricsFacts {
        let db = match &self.db {
            Some(db) => Some(gather_db(db, now).await),
            None => None,
        };
        let (db_bytes, wal_bytes) = match self.cfg.db.backend {
            nzb_store::DbBackend::Sqlite => {
                let size = |p: &Path| fs::metadata(p).ok().map(|m| m.len());
                (
                    size(&self.cfg.paths.db),
                    size(&path_with_suffix(&self.cfg.paths.db, "-wal")),
                )
            }
            nzb_store::DbBackend::Postgres => (None, None),
        };
        crate::metrics::MetricsFacts {
            uptime: self.live.as_ref().map(|_| self.started.elapsed().as_secs()),
            db,
            proc: tokio::task::spawn_blocking(gather_proc)
                .await
                .unwrap_or_default(),
            live: self.live_facts(),
            db_bytes,
            wal_bytes,
        }
    }

    /// Gathers the facts for the cheap checks.
    pub async fn inputs(&self, now: i64, http_probe: Option<bool>) -> Inputs {
        let cfg = Arc::clone(&self.cfg);
        let fs_task = tokio::task::spawn_blocking(move || (gather_fs(&cfg), gather_proc()));
        let db = match &self.db {
            Some(db) => Some(gather_db(db, now).await),
            None => None,
        };
        let (fs, proc) = fs_task.await.unwrap_or_else(|_| {
            (
                FsFacts {
                    dirs: Vec::new(),
                    db_bytes: None,
                    wal_bytes: None,
                    same_fs: None,
                    layout_ok: false,
                    anchor_same_fs: false,
                    key_ok: false,
                    waiting: Err(()),
                    failed: Err(()),
                    duplicates: Err(()),
                    leftovers: 0,
                    gc_trash: None,
                    backups: Err(()),
                },
                ProcFacts::default(),
            )
        });
        Inputs {
            now,
            uptime: self.live.as_ref().map(|_| self.started.elapsed().as_secs()),
            live: self.live_facts(),
            dev_tools: self.dev_tools,
            debug_build: cfg!(debug_assertions),
            cfg: CfgFacts::of(&self.cfg),
            proc,
            db,
            fs,
            recovery: self.recovery.get().copied(),
            deep: *self
                .last_deep
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            http_probe,
        }
    }

    /// The cheap checks.
    pub async fn collect(&self, now: i64) -> Vec<Check> {
        build(&self.inputs(now, None).await)
    }

    /// The deep, on-demand checks. Read-only: a reader connection, a passive store handle (it
    /// never touches `.tmp/`), `stat`/`read_dir` and a dry-run GC plan. The web monitor bounds
    /// the displayed response while this collector retains ownership until filesystem work
    /// actually finishes; an operating-system filesystem call cannot be cancelled safely.
    pub async fn deep(&self, now: i64) -> Vec<Check> {
        self.deep_with_fs_timeout(now, DEEP_FS_DEADLINE).await
    }

    #[allow(clippy::too_many_lines)] // one linear sequence of independent checks
    async fn deep_with_fs_timeout(&self, now: i64, fs_timeout: Duration) -> Vec<Check> {
        let g = Group::Deep;
        let mut v = Vec::new();
        let Some(db) = self.db.clone() else {
            return vec![mk(
                g,
                "Deep check",
                Status::Fail,
                "database unavailable",
                "Check paths.db and the server log.",
            )];
        };
        let db_ok;
        match tokio::time::timeout(DEEP_DB_DEADLINE, db.deep_db_check()).await {
            Ok(Ok(r)) => {
                db_ok = r.quick_check_ok && r.fk_violations == 0;
                v.push(if r.quick_check_ok {
                    mk(g, "Database integrity (quick_check)", Status::Ok, "ok", "")
                } else {
                    mk(
                        g,
                        "Database integrity (quick_check)",
                        Status::Fail,
                        format!("{} problem(s) reported", r.quick_check_issues),
                        "Stop the server, restore the newest good backup (see the deployment guide).",
                    )
                });
                v.push(if r.fk_violations == 0 {
                    mk(g, "Foreign keys", Status::Ok, "no violations", "")
                } else {
                    mk(
                        g,
                        "Foreign keys",
                        Status::Fail,
                        format!("{} violation(s)", r.fk_violations),
                        "Restore the newest good backup (see the deployment guide).",
                    )
                });
            }
            Ok(Err(_)) => {
                db_ok = false;
                v.push(mk(
                    g,
                    "Database integrity (quick_check)",
                    Status::Fail,
                    "could not run",
                    "See the server log.",
                ));
            }
            Err(_) => {
                db_ok = false;
                v.push(mk(
                    g,
                    "Database integrity (quick_check)",
                    Status::Warn,
                    "timed out",
                    "The database is large or busy. Run the check again later.",
                ));
            }
        }
        v.push(audit_chain_deep(&db).await);
        let store_dir = self.cfg.paths.store.clone();
        let failed_dir = self.cfg.paths.failed.clone();
        let shas = db.release_shas_limited(DEEP_RELEASE_CAP).await;
        let mut missing = 0usize;
        // Only a completed comparison may claim consistency. Errors and unfinished walks
        // remain visible in the cheap summary after the detailed rows have expired.
        let mut partial = true;
        match shas {
            Err(_) => v.push(mk(
                g,
                "Releases vs store",
                Status::Warn,
                "release list could not be read",
                "See the server log.",
            )),
            Ok((set, was_partial)) => {
                let looked = set.len();
                let dir = store_dir.clone();
                let res = tokio::task::spawn_blocking(move || {
                    deep_store_blocking(&dir, set, Instant::now() + fs_timeout)
                })
                .await
                .unwrap_or(Err(()));
                match res {
                    Ok(s) => {
                        missing = s.missing;
                        partial = was_partial || s.timed_out;
                        v.push(store_lookup_check(
                            looked,
                            s.missing,
                            s.timed_out,
                            was_partial,
                        ));
                        v.push(mk(g, "Blobs in store", Status::Info, s.blobs.show(), ""));
                    }
                    Err(()) => v.push(mk(
                        g,
                        "Releases vs store",
                        Status::Warn,
                        "store could not be read",
                        "Check the store mount and permissions.",
                    )),
                }
                v.push(self.orphan_check(&db, &store_dir, now, was_partial).await);
            }
        }
        let fd = failed_dir;
        let cons = tokio::task::spawn_blocking(move || failed_consistency(&fd)).await;
        v.push(match cons {
            Ok(Ok((no_sidecar, orphans))) if no_sidecar == 0 && orphans == 0 => {
                mk(g, "Failed folder consistency", Status::Ok, "consistent", "")
            }
            Ok(Ok((no_sidecar, orphans))) => mk(
                g,
                "Failed folder consistency",
                Status::Warn,
                format!("{no_sidecar} file(s) without a reason record, {orphans} orphan record(s)"),
                "Harmless. Restarting the server runs recovery; `nzbd failed list` shows details.",
            ),
            _ => mk(
                g,
                "Failed folder consistency",
                Status::Warn,
                "could not be read",
                "Check the failed folder mount.",
            ),
        });
        *self
            .last_deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(DeepSummary {
            at: now,
            missing,
            partial,
            db_ok,
        });
        v
    }

    /// Dry-run GC plan: orphans are counted, never moved. Skipped on a partial run, because a
    /// release list cut at the cap would make referenced blobs look like orphans.
    async fn orphan_check(
        &self,
        db: &nzb_store::Store,
        store_dir: &Path,
        now: i64,
        partial: bool,
    ) -> Check {
        let g = Group::Deep;
        let name = "Orphan blobs (dry run)";
        if partial {
            return mk(
                g,
                name,
                Status::Info,
                "skipped (partial run)",
                "Run `nzbd store gc` on the host for a full plan.",
            );
        }
        let dir = store_dir.to_path_buf();
        let opened = tokio::task::spawn_blocking(move || {
            if !dir.join(".tmp").is_dir() {
                return Err("store not initialised");
            }
            FsStore::open_passive(&dir).map_err(|_| "store could not be opened")
        })
        .await;
        let store = match opened {
            Ok(Ok(store)) => store,
            Ok(Err(reason)) => return mk(g, name, Status::Warn, reason, ""),
            Err(_) => return mk(g, name, Status::Warn, "store could not be opened", ""),
        };
        // gc_plan awaits a blocking filesystem walk. An inner timeout would detach that
        // walk and let the outer collector release its permit too early. The web monitor
        // publishes its deadline independently while this owned collector awaits real completion.
        match ing::gc_plan(db, &store, now, ing::DEFAULT_GC_GRACE_SECS).await {
            Ok(plan) if plan.candidates.is_empty() => {
                mk(g, name, Status::Ok, "none older than 24 h", "")
            }
            Ok(plan) => mk(
                g,
                name,
                Status::Warn,
                format!(
                    "{} blob(s), {}{}",
                    plan.candidates.len(),
                    human_bytes(plan.bytes),
                    if plan.suspicious.is_empty() {
                        ""
                    } else {
                        "; some look newer than the database (stale restore?)"
                    }
                ),
                "Orphans are harmless. Do not delete blobs after a database restore before `nzbd store gc` (dry run).",
            ),
            _ => mk(
                g,
                name,
                Status::Warn,
                "could not be computed",
                "See the server log.",
            ),
        }
    }
}

/// Full verification of the audit hash chain under the deep deadline (T105). Read-only (one read snapshot).
async fn audit_chain_deep(db: &nzb_store::Store) -> Check {
    let g = Group::Deep;
    let name = "Audit log chain (full verification)";
    match tokio::time::timeout(DEEP_DB_DEADLINE, db.audit_walk(None, &mut |_| {})).await {
        Ok(Ok(r)) => match r.first_break {
            None => mk(
                g,
                name,
                Status::Ok,
                format!(
                    "{} row(s) verified",
                    group_thousands(usize::try_from(r.rows).unwrap_or(usize::MAX))
                ),
                "",
            ),
            Some(b) => mk(
                g,
                name,
                Status::Fail,
                format!(
                    "broken at id {} ({}), {} problem(s)",
                    b.id,
                    b.kind.code(),
                    r.breaks
                ),
                "Run `nzbd audit export --verify` on the host and compare with a backup; do not delete rows by hand.",
            ),
        },
        Ok(Err(_)) => mk(
            g,
            name,
            Status::Warn,
            "could not run",
            "Start the server once so pre-upgrade rows are chained, then run it again.",
        ),
        Err(_) => mk(
            g,
            name,
            Status::Warn,
            "timed out",
            "Run `nzbd audit verify` on the host.",
        ),
    }
}

/// Outcome of the blocking store pass of the deep check.
struct StoreDeep {
    missing: usize,
    timed_out: bool,
    blobs: Count,
}

/// Looks up every digest in the store (`stat` only) and counts blobs, both under a deadline.
fn deep_store_blocking(
    root: &Path,
    shas: HashSet<nzb_core::Sha256>,
    deadline: Instant,
) -> Result<StoreDeep, ()> {
    if !root.join(".tmp").is_dir() {
        return Err(());
    }
    // Passive: this handle must not clean `.tmp/`, which the running server uses.
    let store = FsStore::open_passive(root).map_err(|_| ())?;
    let all: Vec<_> = shas.into_iter().collect();
    let (mut missing, mut timed_out) = (0usize, false);
    for chunk in all.chunks(1000) {
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        missing =
            missing.saturating_add(store.missing(chunk.iter().copied()).map_err(|_| ())?.len());
    }
    Ok(StoreDeep {
        missing,
        timed_out,
        blobs: count_blobs(root, deadline),
    })
}

fn store_lookup_check(looked: usize, missing: usize, timed_out: bool, partial: bool) -> Check {
    let name = "Releases vs store";
    let scope = if partial {
        format!("first {looked} releases (partial)")
    } else {
        format!("{looked} releases")
    };
    if missing > 0 {
        mk(
            Group::Deep,
            name,
            Status::Fail,
            format!("{missing} of {scope} have no blob"),
            "Run `nzbd store verify` on the host; re-add the missing NZBs (a duplicate upload heals them).",
        )
    } else if timed_out || partial {
        mk(
            Group::Deep,
            name,
            Status::Warn,
            format!("all present in {scope}; incomplete run"),
            "The run was cut short. Use `nzbd store verify --quick` on the host for a full pass.",
        )
    } else {
        mk(
            Group::Deep,
            name,
            Status::Ok,
            format!("all present ({scope})"),
            "",
        )
    }
}

/// Counts blob files (`xx/yy/<sha>.nzb`) with `read_dir` only, bounded by cap and deadline.
fn count_blobs(root: &Path, deadline: Instant) -> Count {
    let mut n = 0usize;
    let is_hex2 = |s: &std::ffi::OsStr| {
        s.to_str()
            .is_some_and(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let dirs = |p: &Path| -> Vec<PathBuf> {
        fs::read_dir(p)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()) && is_hex2(&e.file_name()))
            .map(|e| e.path())
            .collect()
    };
    for a in dirs(root) {
        for b in dirs(&a) {
            let Ok(rd) = fs::read_dir(&b) else { continue };
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_file()) {
                    n = n.saturating_add(1);
                }
                if n >= COUNT_CAP * 100 || Instant::now() > deadline {
                    return Count { n, capped: true };
                }
            }
        }
    }
    Count { n, capped: false }
}

/// `(failed files without a sidecar, sidecars without a file)` in `failed/`.
fn failed_consistency(dir: &Path) -> io::Result<(usize, usize)> {
    let mut files = HashSet::new();
    let mut sidecars = HashSet::new();
    for e in fs::read_dir(dir)?.take(COUNT_CAP.saturating_mul(2)) {
        let Ok(e) = e else { continue };
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if let Some(base) = name.strip_suffix(ing::failure::REASON_SUFFIX) {
            sidecars.insert(base.to_owned());
        } else if ing::is_failed_name(&name) {
            files.insert(name);
        }
    }
    Ok((
        files.iter().filter(|f| !sidecars.contains(*f)).count(),
        sidecars.iter().filter(|s| !files.contains(*s)).count(),
    ))
}

// ---------------------------------------------------------------------------------------------
// CLI rendering

/// Text table for `nzbd health`: group headers, then `STATUS  NAME  VALUE` and an indented
/// hint for anything not OK. Values come from this module only (no paths, no secrets) and are
/// still sanitized so terminal control sequences cannot appear.
#[must_use]
pub fn render_text(checks: &[Check]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for g in Group::ALL {
        let rows: Vec<&Check> = checks.iter().filter(|c| c.group == g).collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(out, "{}", g.title().to_uppercase());
        for c in rows {
            let _ = writeln!(
                out,
                "  {:<5} {:<42} {}",
                c.status.label(),
                nzb_core::sanitize_text(c.name, 80),
                nzb_core::sanitize_text(&c.value, 300)
            );
            if c.status != Status::Ok && c.status != Status::Info && !c.hint.is_empty() {
                let _ = writeln!(out, "        -> {}", nzb_core::sanitize_text(&c.hint, 300));
            }
        }
    }
    let s = nzb_web::health::Summary::of(checks);
    let _ = writeln!(
        out,
        "\n{}",
        match s.exit_code() {
            0 => "ALL OK".to_owned(),
            1 => format!("{} warning(s)", s.warnings),
            _ => format!("{} failure(s), {} warning(s)", s.failures, s.warnings),
        }
    );
    out
}

// ---------------------------------------------------------------------------------------------
// Wiring

/// Dependencies of `GET /admin/health` for the web layer.
#[must_use]
pub fn web_deps(engine: &Engine) -> nzb_web::health::HealthDeps {
    use nzb_web::health::{BoxFut, CollectFn};
    let cheap_engine = engine.clone();
    let cheap: CollectFn = Arc::new(move |now| {
        let e = cheap_engine.clone();
        let fut: BoxFut<Vec<Check>> = Box::pin(async move { e.collect(now).await });
        fut
    });
    let deep_engine = engine.clone();
    let deep: CollectFn = Arc::new(move |now| {
        let e = deep_engine.clone();
        let fut: BoxFut<Vec<Check>> = Box::pin(async move { e.deep(now).await });
        fut
    });
    nzb_web::health::HealthDeps::new(Arc::new(nzb_web::auth::SystemWallClock), cheap, Some(deep))
}

/// `nzbd health`: opens the database read-only when it exists, runs the cheap checks and
/// prints the table. Returns the process exit code (0 all OK, 1 warnings, 2 failures).
///
/// # Errors
/// Only when the runtime cannot be built.
pub fn run_cli(cfg: &Config) -> Result<std::process::ExitCode, String> {
    let (text, code) = cli_report(cfg)?;
    print!("{text}");
    Ok(std::process::ExitCode::from(code))
}

/// The table text and exit code of `nzbd health`.
fn cli_report(cfg: &Config) -> Result<(String, u8), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let checks = rt.block_on(async {
        // Read-only handles: the CLI must not migrate, seed or create anything.
        let db = if crate::dbopen::exists(cfg) {
            crate::dbopen::open_read_only(cfg).await.ok()
        } else {
            None
        };
        let engine = Engine::offline(cfg, db.clone(), cfg!(feature = "dev-tools"));
        let probe = {
            let addr = crate::probe_addr(cfg.server.listen);
            tokio::task::spawn_blocking(move || {
                matches!(crate::healthcheck(addr), crate::Probe::Healthy)
            })
            .await
            .ok()
        };
        let now = crate::now_unix();
        let checks = build(&engine.inputs(now, probe).await);
        if let Some(db) = db {
            db.close().await;
        }
        checks
    });
    Ok((
        render_text(&checks),
        nzb_web::health::Summary::of(&checks).exit_code(),
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod resource_followup_tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn incomplete_deep_summary_never_claims_consistency() {
        let summary = DeepSummary {
            at: NOW,
            missing: 0,
            partial: true,
            db_ok: true,
        };
        let check = deep_summary_check(Some(summary), NOW + 1);
        assert_eq!(
            check.status,
            Status::Warn,
            "incomplete store checks must not be healthy"
        );
        assert!(!check.value.contains("consistent"));
        assert!(check.value.contains("incomplete"));
        let complete = DeepSummary {
            partial: false,
            ..summary
        };
        assert_eq!(deep_summary_check(Some(complete), NOW).status, Status::Ok);
        assert_eq!(
            deep_summary_check(
                Some(DeepSummary {
                    missing: 1,
                    ..summary
                }),
                NOW
            )
            .status,
            Status::Fail
        );
        assert_eq!(
            deep_summary_check(
                Some(DeepSummary {
                    db_ok: false,
                    ..summary
                }),
                NOW
            )
            .status,
            Status::Fail
        );
    }

    #[tokio::test]
    async fn timed_out_store_does_not_publish_a_consistent_deep_summary() {
        use nzb_store::{CategorySource, NewRelease, NzbStore, SceneColumns};
        use sha2::Digest as _;

        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let mut cfg = Config::default();
        cfg.paths.store = dir.path().join("store");
        cfg.paths.failed = dir.path().join("failed");
        fs::create_dir(&cfg.paths.failed).unwrap();
        let store = FsStore::open(&cfg.paths.store).unwrap();
        let bytes = b"health timeout fixture";
        let sha = nzb_core::Sha256(sha2::Sha256::digest(bytes).into());
        store.put(sha, bytes).await.unwrap();
        let analysis = nzb_core::Analysis {
            sha256: sha,
            name_candidates: Vec::new(),
            meta_name_candidates: 0,
            title: "health timeout fixture".to_owned(),
            poster: None,
            posted_at: None,
            total_bytes: 0,
            file_count: 0,
            segment_count: 0,
            duplicate_segments: 0,
            par2_blocks: 0,
            flags: nzb_core::ReleaseFlags::EMPTY,
            meta_category: None,
            repairable_estimate: None,
            files: Vec::new(),
        };
        ts.store
            .insert_release(&NewRelease {
                analysis: &analysis,
                nzb_size_bytes: u64::try_from(bytes.len()).unwrap(),
                source_name: None,
                source_label: None,
                category_id: 8010,
                category_source: CategorySource::Fallback,
                meta_json: None,
                scene: SceneColumns::default(),
                ingested_at: NOW,
            })
            .await
            .unwrap();
        let engine = Engine::offline(&cfg, Some(ts.store.clone()), false);
        let checks = engine.deep_with_fs_timeout(NOW, Duration::ZERO).await;
        assert!(
            checks
                .iter()
                .any(|c| c.name == "Releases vs store" && c.value.contains("incomplete run"))
        );
        let summary = *engine
            .last_deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let check = deep_summary_check(summary, NOW + 601);
        assert_eq!(
            check.status,
            Status::Warn,
            "timed out store traversal was recorded as consistent"
        );
        assert!(!check.value.contains("consistent"));
        engine.deep(NOW + 602).await;
        let summary = *engine
            .last_deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(deep_summary_check(summary, NOW + 603).status, Status::Ok);
    }

    #[tokio::test]
    async fn unreadable_store_does_not_publish_a_consistent_deep_summary() {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let mut cfg = Config::default();
        cfg.paths.store = dir.path().join("uninitialized-store");
        cfg.paths.failed = dir.path().join("failed");
        fs::create_dir(&cfg.paths.store).unwrap();
        fs::create_dir(&cfg.paths.failed).unwrap();
        let engine = Engine::offline(&cfg, Some(ts.store.clone()), false);
        let checks = engine.deep(NOW).await;
        assert!(
            checks
                .iter()
                .any(|c| c.name == "Releases vs store" && c.value == "store could not be read")
        );
        let summary = *engine
            .last_deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let check = deep_summary_check(summary, NOW + 601);
        assert_eq!(
            check.status,
            Status::Warn,
            "failed store traversal was recorded as consistent"
        );
        assert!(!check.value.contains("consistent"));
        // Recovering the store makes a subsequent complete check healthy again.
        let _store = FsStore::open(&cfg.paths.store).unwrap();
        engine.deep(NOW + 602).await;
        let summary = *engine
            .last_deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(deep_summary_check(summary, NOW + 603).status, Status::Ok);
    }
}

#[cfg(test)]
mod metrics_backend_regressions {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn file_size_metrics_belong_to_the_selected_database_backend() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("metrics.sqlite");
        let wal_path = path_with_suffix(&db_path, "-wal");
        let ts = nzb_store::test_backend::TestStore::open_file(&db_path).await;
        let mut cfg = Config::default();
        cfg.db.backend = ts.backend();
        cfg.paths.db = db_path.clone();
        let foreign_db = b"foreign database file";
        let foreign_wal = b"foreign journal";
        if ts.backend() == nzb_store::DbBackend::Postgres {
            // These belong to no library: PostgreSQL uses its real isolated test database.
            assert!(!db_path.exists() && !wal_path.exists());
            fs::write(&db_path, foreign_db).unwrap();
            fs::write(&wal_path, foreign_wal).unwrap();
        }
        let engine = Engine::offline(&cfg, Some(ts.store.clone()), false);
        let facts =
            tokio::time::timeout(Duration::from_secs(60), engine.metrics_facts(1_800_000_000))
                .await
                .expect("real metrics collection must finish");
        let rendered = crate::metrics::render(&facts);
        let db = facts
            .db
            .as_ref()
            .expect("real database facts must be collected");
        assert!(
            db.writer_ok && db.reader_ok,
            "real database connections must answer"
        );
        assert!(
            db.totals.is_some(),
            "real database aggregates must be collected"
        );
        match ts.backend() {
            nzb_store::DbBackend::Postgres => {
                assert_eq!(fs::read(&db_path).unwrap(), foreign_db);
                assert_eq!(fs::read(&wal_path).unwrap(), foreign_wal);
                assert_eq!(
                    (facts.db_bytes, facts.wal_bytes),
                    (None, None),
                    "PostgreSQL metrics must not report unrelated SQLite path sizes"
                );
                assert!(!rendered.contains("nzbd_db_file_bytes"));
                assert!(!rendered.contains("nzbd_db_wal_bytes"));
            }
            nzb_store::DbBackend::Sqlite => {
                let db_bytes = fs::metadata(&db_path).unwrap().len();
                let wal_bytes = fs::metadata(&wal_path).unwrap().len();
                assert!(db_bytes > 0 && wal_bytes > 0);
                assert_eq!(
                    (facts.db_bytes, facts.wal_bytes),
                    (Some(db_bytes), Some(wal_bytes))
                );
                assert!(
                    rendered
                        .lines()
                        .any(|line| line == format!("nzbd_db_file_bytes {db_bytes}"))
                );
                assert!(
                    rendered
                        .lines()
                        .any(|line| line == format!("nzbd_db_wal_bytes {wal_bytes}"))
                );
            }
        }
    }
}

#[cfg(test)]
mod health_backend_regressions {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::{Read as _, Write as _};

    const DB_SENTINEL: &[u8] = b"unrelated local database file";
    const WAL_SENTINEL: &[u8] = b"unrelated local journal";

    fn filesystem_config(root: &Path) -> Config {
        let mut cfg = Config::default();
        for (slot, name) in [
            (&mut cfg.paths.watch, "watch"),
            (&mut cfg.paths.store, "store"),
            (&mut cfg.paths.failed, "failed"),
            (&mut cfg.paths.duplicates, "duplicates"),
            (&mut cfg.paths.tmp, "tmp"),
            (&mut cfg.paths.backups, "backups"),
        ] {
            *slot = root.join(name);
            fs::create_dir(&*slot).unwrap();
        }
        fs::create_dir(root.join("store/.tmp")).unwrap();
        for name in ["sqlite-only", "state", "index"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        cfg.paths.db = root.join("sqlite-only/unused.sqlite");
        cfg.paths.state = Some(root.join("state"));
        cfg.search.index_dir = Some(root.join("index"));
        cfg.security.totp_key_file = root.join("unused-test-key");
        cfg
    }

    fn health_checks(cfg: &Config, facts: FsFacts) -> Vec<Check> {
        // Connection facts are held constant: this regression exercises real filesystem
        // collection and the public health evaluator, not a PostgreSQL connection fixture.
        build(&Inputs {
            now: 1_800_000_000,
            uptime: None,
            live: None,
            dev_tools: false,
            debug_build: false,
            cfg: CfgFacts::of(cfg),
            proc: ProcFacts::default(),
            db: Some(DbFacts {
                writer_ok: true,
                reader_ok: true,
                schema: None,
                totals: None,
                logs: None,
                pools: PoolInfo {
                    writer_open: 1,
                    readers_open: 1,
                    readers_idle: 1,
                    readers_max: 1,
                    closed: false,
                },
                security: None,
                last_ok_ingest: None,
                audit_chain: None,
                outbox: None,
            }),
            fs: facts,
            recovery: None,
            deep: None,
            http_probe: None,
        })
    }

    fn file_rows(checks: Vec<Check>) -> Vec<Check> {
        checks
            .into_iter()
            .filter(|check| matches!(check.name, "Database file size" | "WAL file size"))
            .collect()
    }

    #[test]
    fn filesystem_health_belongs_to_selected_database_backend() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = filesystem_config(dir.path());
        let wal_path = path_with_suffix(&cfg.paths.db, "-wal");
        fs::write(&cfg.paths.db, DB_SENTINEL).unwrap();
        let mut wal = fs::File::create(&wal_path).unwrap();
        wal.write_all(WAL_SENTINEL).unwrap();
        // A sparse file crosses the real warning threshold without allocating 256 MiB.
        wal.set_len(WAL_WARN_BYTES + 1).unwrap();
        drop(wal);
        let db_meta = fs::metadata(&cfg.paths.db).unwrap();
        let wal_meta = fs::metadata(&wal_path).unwrap();

        cfg.db.backend = nzb_store::DbBackend::Sqlite;
        let sqlite_fs = gather_fs(&cfg);
        assert_eq!(
            (sqlite_fs.db_bytes, sqlite_fs.wal_bytes),
            (Some(db_meta.len()), Some(wal_meta.len()))
        );
        assert!(sqlite_fs.dirs.iter().any(|d| d.name == "Database folder"));
        let sqlite_checks = health_checks(&cfg, sqlite_fs);
        assert!(sqlite_checks.iter().any(|c| c.name == "Database folder"));
        let sqlite_rows = file_rows(sqlite_checks);
        assert_eq!(sqlite_rows.len(), 2);
        let sqlite_wal = sqlite_rows
            .iter()
            .find(|c| c.name == "WAL file size")
            .expect("SQLite must retain its real WAL row");
        assert_eq!(sqlite_wal.status, Status::Warn);
        assert_eq!(sqlite_wal.value, human_bytes(wal_meta.len()));
        let sqlite_summary = nzb_web::health::Summary::of(&sqlite_rows);
        assert_eq!((sqlite_summary.warnings, sqlite_summary.failures), (1, 0));
        assert_eq!(sqlite_summary.exit_code(), 1);
        assert!(render_text(&sqlite_rows).contains("Restart the server to checkpoint."));

        cfg.db.backend = nzb_store::DbBackend::Postgres;
        let pg_fs = gather_fs(&cfg);
        let pg_sizes = (pg_fs.db_bytes, pg_fs.wal_bytes);
        let pg_has_directory = pg_fs.dirs.iter().any(|d| d.name == "Database folder");
        let pg_checks = health_checks(&cfg, pg_fs);
        let pg_has_directory_row = pg_checks.iter().any(|c| c.name == "Database folder");
        let pg_rows = file_rows(pg_checks);
        let pg_summary = nzb_web::health::Summary::of(&pg_rows);

        assert_eq!(fs::read(&cfg.paths.db).unwrap(), DB_SENTINEL);
        let mut journal_prefix = [0; WAL_SENTINEL.len()];
        fs::File::open(&wal_path)
            .unwrap()
            .read_exact(&mut journal_prefix)
            .unwrap();
        assert_eq!(journal_prefix, WAL_SENTINEL);
        let after_db = fs::metadata(&cfg.paths.db).unwrap();
        let after_wal = fs::metadata(&wal_path).unwrap();
        assert_eq!(after_db.len(), db_meta.len());
        assert_eq!(after_wal.len(), wal_meta.len());
        assert_eq!(after_db.modified().unwrap(), db_meta.modified().unwrap());
        assert_eq!(after_wal.modified().unwrap(), wal_meta.modified().unwrap());
        assert_eq!(
            fs::read_dir(dir.path().join("sqlite-only"))
                .unwrap()
                .count(),
            2
        );

        assert_eq!(
            pg_sizes,
            (None, None),
            "PostgreSQL health must not report unrelated SQLite file sizes"
        );
        assert!(
            !pg_has_directory && !pg_has_directory_row,
            "PostgreSQL health must not probe the unrelated SQLite database directory"
        );
        assert!(
            pg_rows
                .iter()
                .all(|c| c.status == Status::Info && c.value == "n/a")
        );
        assert_eq!((pg_summary.warnings, pg_summary.failures), (0, 0));
        assert_eq!(pg_summary.exit_code(), 0);
        assert!(!render_text(&pg_rows).contains("checkpoint"));
    }
}
