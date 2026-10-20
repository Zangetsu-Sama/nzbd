//! Configuration: TOML file, `NZBD__section__key` env overrides, startup validation (SEC-042).

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

/// Hard ceiling for `limits.max_file_bytes` (`PARSER_SPEC`); config may only lower it.
pub const MAX_FILE_BYTES_CEILING: u64 = 64 * 1024 * 1024;
/// Hard ceiling for `limits.parse_deadline_secs`; config may only lower it.
pub const PARSE_DEADLINE_CEILING: u64 = 20;
/// Hard ceiling for the per-key / per-session upload budget (SEC-029); config may only lower it.
pub const UPLOADS_PER_MIN_CEILING: u32 = 30;
/// Required TOTP key length in bytes.
pub const TOTP_KEY_LEN: usize = 32;

const ENV_PREFIX: &str = "NZBD__";
/// A custom `security.invite_path` shorter than this (with the `/`) gets a `config check` warning.
const SHORT_INVITE_PATH: usize = 10;

/// Configuration problems. Messages never include secret material.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Config file could not be read.
    #[error("cannot read config file {0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// TOML syntax/type error (including unknown keys).
    #[error("invalid config: {0}")]
    Parse(String),
    /// A semantic validation failure.
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

/// The pipeline moves files into failed/ and duplicates/ and writes store/ and tmp/: if any of
/// them lay inside the watch folder (or the watch folder inside one of them) the pipeline would
/// re-ingest its own output forever (`SECURITY_REVIEW` T031 M2). Compared after
/// canonicalization so symlinks and `..` cannot hide an overlap.
fn check_no_overlap(paths: &Paths) -> Result<(), ConfigError> {
    let canon = |d: &Path| {
        std::fs::canonicalize(d).map_err(|e| {
            ConfigError::Invalid(format!("cannot resolve {}: {}", d.display(), e.kind()))
        })
    };
    let watch = canon(&paths.watch)?;
    for (name, dir) in [
        ("store", &paths.store),
        ("failed", &paths.failed),
        ("duplicates", &paths.duplicates),
        ("tmp", &paths.tmp),
        ("backups", &paths.backups),
    ] {
        let other = canon(dir)?;
        if other.starts_with(&watch) || watch.starts_with(&other) {
            return invalid(format!(
                "paths.{name} and paths.watch must not overlap (one lies inside the other)"
            ));
        }
    }
    Ok(())
}

/// SEC-102: the SQLite database must not live inside a directory whose files other parts of nzbd create, move or
/// delete (the watch folder is scanned and moved from, `paths.tmp` is cleared at startup, backups are rotated, the
/// index directory is rebuilt). Compared after canonicalization so symlinks and `..` cannot hide it; an index
/// directory that does not exist yet is skipped (it is created later, by default next to the database).
fn check_db_location(paths: &Paths, index_dir: &Path) -> Result<(), ConfigError> {
    let db_dir = match paths.db.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let Ok(db_dir) = std::fs::canonicalize(db_dir) else {
        return Ok(());
    };
    for (name, dir) in [
        ("paths.watch", paths.watch.as_path()),
        ("paths.tmp", paths.tmp.as_path()),
        ("paths.backups", paths.backups.as_path()),
        ("search.index_dir", index_dir),
    ] {
        if let Ok(d) = std::fs::canonicalize(dir)
            && db_dir.starts_with(&d)
        {
            return invalid(format!(
                "DB_PATH_LOCATION: paths.db must not be inside {name}"
            ));
        }
    }
    Ok(())
}

/// Resolves `p` for placement checks while it may not exist yet: the nearest existing ancestor is canonicalized and the
/// missing rest appended (only plain components: a `..` or `.` in the missing part is refused, it could not be resolved
/// safely).
fn resolve_maybe_missing(p: &Path) -> Result<PathBuf, ConfigError> {
    let mut missing = Vec::new();
    let mut cur = p;
    loop {
        if std::fs::symlink_metadata(cur).is_ok() {
            let mut base = std::fs::canonicalize(cur).map_err(|e| {
                ConfigError::Invalid(format!("cannot resolve {}: {}", cur.display(), e.kind()))
            })?;
            for c in missing.iter().rev() {
                base.push(c);
            }
            return Ok(base);
        }
        match (cur.file_name(), cur.parent()) {
            (Some(name), Some(parent)) => {
                missing.push(name.to_os_string());
                cur = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
            }
            _ => {
                return invalid(format!(
                    "cannot resolve {}: only plain directory names may be missing",
                    p.display()
                ));
            }
        }
    }
}

/// True when `a` and `b` are the same directory or one lies inside the other: by canonical path, and by device and
/// inode of every existing ancestor, so a bind mount or a second path to the same directory cannot hide it.
fn same_or_nested(a: &Path, b: &Path) -> bool {
    if a.starts_with(b) || b.starts_with(a) {
        return true;
    }
    let ident = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let inside = |x: &Path, target: Option<(u64, u64)>| {
        target.is_some() && x.ancestors().any(|y| ident(y) == target)
    };
    inside(a, ident(b)) || inside(b, ident(a))
}

/// Review 39 L1 (SEC-091): `search.index_dir` is derived data that the indexer creates, chmods 0700 and garbage
/// collects, and `paths.state` holds the serve lock and the restore anchor; neither may be, contain or lie inside a
/// data directory (watch, store, failed, duplicates, tmp, backups) or each other, on either backend.
fn check_index_and_state(
    paths: &Paths,
    index_dir: &Path,
    state_dir: &Path,
) -> Result<(), ConfigError> {
    let index = resolve_maybe_missing(index_dir)?;
    let state = resolve_maybe_missing(state_dir)?;
    for (name, dir) in [
        ("paths.watch", &paths.watch),
        ("paths.store", &paths.store),
        ("paths.failed", &paths.failed),
        ("paths.duplicates", &paths.duplicates),
        ("paths.tmp", &paths.tmp),
        ("paths.backups", &paths.backups),
    ] {
        let other = std::fs::canonicalize(dir).map_err(|e| {
            ConfigError::Invalid(format!("cannot resolve {}: {}", dir.display(), e.kind()))
        })?;
        if same_or_nested(&index, &other) {
            return invalid(format!(
                "INDEX_DIR_LOCATION: search.index_dir and {name} must not be the same directory or nested"
            ));
        }
        if same_or_nested(&state, &other) {
            return invalid(format!(
                "STATE_DIR_LOCATION: paths.state and {name} must not be the same directory or nested"
            ));
        }
    }
    if same_or_nested(&index, &state) {
        return invalid(
            "INDEX_DIR_LOCATION: search.index_dir and paths.state must not be the same directory or nested",
        );
    }
    Ok(())
}

impl Config {
    /// `paths.db`: its directory exists and, for SQLite, it is not inside a managed directory (SEC-102).
    fn check_db_path(&self) -> Result<(), ConfigError> {
        let paths = &self.paths;
        match paths.db.parent() {
            Some(parent) if parent.as_os_str().is_empty() || parent.is_dir() => {}
            _ => {
                return invalid(format!(
                    "paths.db parent directory does not exist: {}",
                    paths.db.display()
                ));
            }
        }
        if self.db.backend == nzb_store::DbBackend::Sqlite {
            check_db_location(paths, &self.index_dir())?;
        }
        Ok(())
    }

    /// The directory next to the database file (default parent of `paths.state` and `search.index_dir`).
    fn data_dir(&self) -> PathBuf {
        self.paths
            .db
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    /// `paths.state` (see [`Paths::state`]).
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.paths
            .state
            .clone()
            .unwrap_or_else(|| self.data_dir().join("state"))
    }

    /// `search.index_dir` (see [`Search::index_dir`]).
    #[must_use]
    pub fn index_dir(&self) -> PathBuf {
        self.search
            .index_dir
            .clone()
            .unwrap_or_else(|| self.data_dir().join("index"))
    }

    /// The two directory-layout rules of `validate` (no overlap with the watch folder, staging
    /// directory isolation), for the health page. The error messages contain paths: callers
    /// must map the result to a fixed string and never display the error.
    pub(crate) fn check_layout(&self) -> Result<(), ConfigError> {
        check_no_overlap(&self.paths)?;
        check_tmp_isolated(&self.paths, &self.security.totp_key_file)
    }
}

/// `paths.tmp` is the upload staging area and startup clears generated staging files in it
/// (`SECURITY_REVIEW` T032 M1): it must therefore share nothing with the directories that hold
/// user data. Any equality or nesting (either direction, after canonicalization, so symlinks
/// and `..` cannot hide it) with store/failed/duplicates/backups/watch is refused; it must
/// not be, or contain, the directory holding the database or the key file. (Having tmp
/// *inside* the database's directory, the default `/data` layout, is fine.)
fn check_tmp_isolated(paths: &Paths, key_file: &Path) -> Result<(), ConfigError> {
    let canon = |d: &Path| {
        std::fs::canonicalize(d).map_err(|e| {
            ConfigError::Invalid(format!("cannot resolve {}: {}", d.display(), e.kind()))
        })
    };
    let tmp = canon(&paths.tmp)?;
    for (name, dir) in [
        ("store", &paths.store),
        ("failed", &paths.failed),
        ("duplicates", &paths.duplicates),
        ("backups", &paths.backups),
        ("watch", &paths.watch),
    ] {
        let other = canon(dir)?;
        if other.starts_with(&tmp) || tmp.starts_with(&other) {
            return invalid(format!(
                "paths.tmp and paths.{name} must not be the same directory or nested \
                 (startup clears staging files in paths.tmp)"
            ));
        }
    }
    for (name, file) in [
        ("paths.db", paths.db.as_path()),
        ("security.totp_key_file", key_file),
    ] {
        let dir = match file.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dir = canon(dir)?;
        if dir.starts_with(&tmp) {
            return invalid(format!(
                "paths.tmp must not be, or contain, the directory of {name}"
            ));
        }
    }
    Ok(())
}

/// Root configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// HTTP listener settings.
    pub server: Server,
    /// Filesystem locations.
    pub paths: Paths,
    /// Ingest settings.
    pub ingest: Ingest,
    /// Parser limits.
    pub limits: Limits,
    /// Security settings.
    pub security: Security,
    /// Database settings.
    pub db: Db,
    /// Scheduled backup and log purges inside `serve`.
    pub maintenance: Maintenance,
    /// Display options.
    pub ui: Ui,
    /// NZB blob store backend.
    pub store: Store,
    /// Internal-only metrics listener (T105).
    pub metrics: Metrics,
    /// The Tantivy search index (v3, both backends).
    pub search: Search,
}

/// `[search]` (ARCHITECTURE v3 section 7): the Tantivy index of both backends. Values are clamped into the hard
/// ranges of `nzb_search::config` (configuration may only lower a bound).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Search {
    /// Index directory (derived data, rebuildable; created 0700; must not nest with any `paths.*`). Default:
    /// `index/` next to `paths.db`.
    pub index_dir: Option<PathBuf>,
    /// The indexer commits pending changes at least this often, ms (index lag target ~2 s, owner Q4).
    pub commit_interval_ms: u64,
    /// Outbox rows per indexer round.
    pub commit_max_docs: usize,
    /// Indexing heap of the steady-state writer, MiB.
    pub writer_heap_mib: usize,
    /// Indexing threads of the steady-state writer.
    pub writer_threads: usize,
    /// Indexing heap of the rebuild writer, MiB.
    pub rebuild_heap_mib: usize,
    /// Concurrent engine searches; more wait up to 1 s, then the uniform `503 BUSY`.
    pub max_concurrent_searches: usize,
    /// Deadline of one search, ms (uniform `503` past it).
    pub query_deadline_ms: u64,
    /// Counting budget, ms; past it lists say "more than n" (owner Q1).
    pub count_budget_ms: u64,
    /// Numbered paging stops at this offset; keyset links are unbounded (owner Q2).
    pub max_offset: u32,
    /// `"off"`, `"fallback"` (default: typo tolerance only when the exact query has no hit) or `"toggle"` (Q5).
    pub fuzzy: FuzzySetting,
    /// Prefix matching of the last token (bounded by the expansion budgets, Q5).
    pub prefix: bool,
    /// The watch-folder scanner pauses while the search outbox holds more than this many changes and resumes below
    /// half of it (ARCHITECTURE v3 3.2, SEC-092); `0` never pauses. Uploads are not paused.
    pub lag_pause_rows: u64,
    /// Health turns WARN when the oldest unindexed change is older than this, seconds (>= 1).
    pub lag_warn_secs: u64,
}

/// `[search] fuzzy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzySetting {
    /// Never.
    Off,
    /// Only when the exact query has no hit (default).
    Fallback,
    /// Only when the search form asks for it.
    Toggle,
}

impl Default for Search {
    fn default() -> Self {
        let d = nzb_search::config::SearchConfig::default();
        Self {
            index_dir: None,
            commit_interval_ms: d.commit_interval_ms,
            commit_max_docs: d.commit_max_docs,
            writer_heap_mib: d.writer_heap_mib,
            writer_threads: d.writer_threads,
            rebuild_heap_mib: d.rebuild_heap_mib,
            max_concurrent_searches: d.max_concurrent_searches,
            query_deadline_ms: d.query_deadline_ms,
            count_budget_ms: d.count_budget_ms,
            max_offset: d.max_offset,
            fuzzy: FuzzySetting::Fallback,
            prefix: d.prefix,
            lag_pause_rows: 1_000_000,
            lag_warn_secs: 60,
        }
    }
}

impl Search {
    /// The engine settings (clamped into the hard ranges).
    #[must_use]
    pub fn engine(&self) -> nzb_search::config::SearchConfig {
        use nzb_search::config::FuzzyMode;
        nzb_search::config::SearchConfig {
            commit_interval_ms: self.commit_interval_ms,
            commit_max_docs: self.commit_max_docs,
            writer_heap_mib: self.writer_heap_mib,
            writer_threads: self.writer_threads,
            rebuild_heap_mib: self.rebuild_heap_mib,
            max_concurrent_searches: self.max_concurrent_searches,
            query_deadline_ms: self.query_deadline_ms,
            count_budget_ms: self.count_budget_ms,
            max_offset: self.max_offset,
            fuzzy: match self.fuzzy {
                FuzzySetting::Off => FuzzyMode::Off,
                FuzzySetting::Fallback => FuzzyMode::Fallback,
                FuzzySetting::Toggle => FuzzyMode::Toggle,
            },
            prefix: self.prefix,
            ..nzb_search::config::SearchConfig::default()
        }
        .clamped()
    }
}

/// `[metrics]`: the plaintext metrics listener (T105, SEC-083/084). Off unless `listen` is set. It is a SECOND
/// listener, never a route of the application, so nothing the proxy forwards to `server.listen` can reach it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    /// Address of the metrics listener, for example `127.0.0.1:9100`. Unset = disabled.
    pub listen: Option<SocketAddr>,
    /// Required when `listen` is not loopback (the container's `back` network): an explicit statement that this
    /// address is only reachable by a scraper on the internal network and is never routed by the proxy.
    pub allow_back_network: bool,
}

impl Metrics {
    fn validate(&self, server: &Server) -> Result<Vec<String>, ConfigError> {
        let Some(addr) = self.listen else {
            return Ok(Vec::new());
        };
        if addr.port() == server.listen.port() {
            return invalid("metrics.listen must use a different port than server.listen");
        }
        if addr.ip().is_loopback() {
            return Ok(Vec::new());
        }
        if !self.allow_back_network {
            return invalid(
                "metrics.listen is not loopback: set metrics.allow_back_network = true to confirm it is bound \
                 only on the internal network and never routed by the proxy",
            );
        }
        Ok(vec![format!(
            "metrics.listen {addr} is not loopback: make sure the port is never published and the proxy has no \
             route to it"
        )])
    }
}

/// Where new NZB blobs are written (`[store] backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreBackend {
    /// Content-addressed files under `paths.store` (default).
    #[default]
    Fs,
    /// The 2.x database blob backend: refused in 3.x (`STORE_DB_BACKEND_REMOVED`, D36 a: NZB files live on the
    /// filesystem only). Parsed only so the refusal can name it.
    Db,
}

/// `[store]`: the blob backend; only `"fs"` is accepted in 3.x (D36 a, D37).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Store {
    /// `"fs"` (default) or `"db"`.
    pub backend: StoreBackend,
}

/// `[ui]`: display-only options (changing them needs a restart).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ui {
    /// Display the `XXX` category and its children. `false` hides every release in them from
    /// the index, search, tiles, selects and direct URLs; ingest is unchanged.
    pub show_xxx: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self { show_xxx: true }
    }
}

/// `[server]`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    /// Listen address.
    pub listen: SocketAddr,
    /// IPs whose `X-Forwarded-*` headers are honored.
    pub trusted_proxies: Vec<IpAddr>,
    /// Allow plain-HTTP cookies (dev only, D16).
    pub insecure_cookies: bool,
    /// Extra accepted `Host` names (lowercase, no port), e.g. `["nzbd.lan"]`. `localhost` and
    /// IP literals are always accepted; anything else is refused (DNS-rebinding defence).
    pub allowed_hosts: Vec<String>,
    /// Address printed on invitation and recovery pages (v2): `https://host[:port]`, no path.
    /// Unset = `https://<first allowed_hosts entry>`; the request `Host` header is never used.
    pub public_url: Option<String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            trusted_proxies: Vec::new(),
            insecure_cookies: false,
            allowed_hosts: Vec::new(),
            public_url: None,
        }
    }
}

/// Validates and normalizes `server.public_url`: `https` (`http` only with `insecure_cookies`),
/// a plain host (letters, digits, `.`, `-`) or a bracketed IPv6 literal, an optional port, and
/// nothing else (no userinfo, path, query or fragment). Returns `scheme://host[:port]`.
fn normalize_public_url(raw: &str, insecure_cookies: bool) -> Result<String, ConfigError> {
    let bad = |why: &str| invalid(format!("server.public_url {why}"));
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        if !insecure_cookies {
            return bad("must be https (http needs server.insecure_cookies)");
        }
        ("http", r)
    } else {
        return bad("must start with https://");
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.len() > 253 {
        return bad("needs a host");
    }
    if rest.contains(['/', '?', '#', '@', ' ', '\\']) || !rest.is_ascii() {
        return bad("must be scheme://host[:port] only");
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let Some((addr, tail)) = v6.split_once(']') else {
            return bad("has an unterminated IPv6 literal");
        };
        if addr.parse::<std::net::Ipv6Addr>().is_err() {
            return bad("has an invalid IPv6 literal");
        }
        (format!("[{addr}]"), tail.strip_prefix(':'))
    } else {
        let (h, p) = match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let ok = !h.is_empty()
            && h.split('.').all(|l| {
                !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !ok {
            return bad("has an invalid host");
        }
        (h.to_ascii_lowercase(), p)
    };
    let mut out = format!("{scheme}://{host}");
    if let Some(p) = port {
        match p.parse::<u16>() {
            Ok(n) if n > 0 && p.bytes().all(|b| b.is_ascii_digit()) => {
                out = format!("{out}:{n}");
            }
            _ => return bad("has an invalid port"),
        }
    }
    Ok(out)
}

/// `[paths]`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    /// Watch folder.
    pub watch: PathBuf,
    /// NZB store.
    pub store: PathBuf,
    /// Failed NZBs.
    pub failed: PathBuf,
    /// Duplicates.
    pub duplicates: PathBuf,
    /// Staging directory.
    pub tmp: PathBuf,
    /// `SQLite` database file.
    pub db: PathBuf,
    /// Backups directory.
    pub backups: PathBuf,
    /// Process state (v3): `serve.lock` (one `serve` per library) and `db-anchor.json` (restore detection, library
    /// identity). 0700. Default: `state/` next to `paths.db`. Put it on its own volume (review 34 M3).
    pub state: Option<PathBuf>,
}

impl Default for Paths {
    fn default() -> Self {
        let d = |p: &str| PathBuf::from(format!("/data/{p}"));
        Self {
            watch: d("watch"),
            store: d("store"),
            failed: d("failed"),
            duplicates: d("duplicates"),
            tmp: d("tmp"),
            db: d("nzbd.sqlite"),
            backups: d("backups"),
            state: None,
        }
    }
}

/// What to do with duplicate files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DuplicatesAction {
    /// Move to the duplicates directory (default; never delete in v1).
    Move,
    /// Delete the duplicate.
    Delete,
}

/// `[ingest]`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ingest {
    /// Watch-folder scan interval.
    pub scan_interval_secs: u64,
    /// File must be unchanged this long before ingest.
    pub stable_secs: u64,
    /// Parallel ingest workers (read, hash, parse, blob put); `0` = automatic: available cores - 1,
    /// at least 1 (ARCHITECTURE v3 5.3). At most 32.
    pub workers: u32,
    /// Jobs that may wait in the ingest queue (1..=8192; the scanner offers at most the free slots
    /// per cycle, uploads beyond it get `503 QUEUE_FULL`).
    pub queue_cap: usize,
    /// NZB bytes in flight at once (read, parsed, waiting for the commit): bounds ingest memory
    /// whatever the queue length. 1 MiB..=16 GiB.
    pub max_inflight_bytes: u64,
    /// NZBs committed per database transaction (commit group), 1..=1024.
    pub group_max_jobs: usize,
    /// How long a commit group waits for more prepared NZBs, ms (1..=1000).
    pub group_window_ms: u64,
    /// SQLite: the longest a commit group holds the single writer before it commits the rest in a
    /// later group, so logins and account writes never wait behind a bulk ingest (review 34 L5), ms
    /// (1..=1000). Postgres writers run in parallel and ignore it.
    pub writer_hold_ms: u64,
    /// Duplicate handling.
    pub duplicates_action: DuplicatesAction,
    /// Days to keep failed files (0 = forever).
    pub failed_retention_days: u32,
    /// Require watch/store/failed on one filesystem so moves are atomic renames.
    pub atomic_moves: bool,
    /// Descend into watch sub-folders (depth <= 4, symlinks never followed).
    pub recursive: bool,
    /// A first-level sub-folder named exactly like a category slug provides the category hint.
    /// Requires `recursive = true`.
    pub category_from_subfolder: bool,
    /// Keep at most this many rejected uploads in `failed/` (oldest first; 0 = unlimited).
    /// Watch-folder files are never rotated away.
    pub failed_uploads_max_files: usize,
    /// Keep at most this many bytes of rejected uploads in `failed/` (0 = unlimited).
    pub failed_uploads_max_bytes: u64,
    /// `[[ingest.rules]]` (T126): watch-folder rules, first match wins, at most 64.
    pub rules: Vec<WatchRuleConfig>,
}

/// One `[[ingest.rules]]` entry (T126, `INGEST_SPEC` §Watch-folder rules): exactly one matcher
/// (`subfolder` or `filename`) and at least one action (`category`, `source_label`). Validated by
/// [`Config::watch_rules`]; refusals carry a stable `RULE_*` code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRuleConfig {
    /// First-level sub-folder name, compared as a string (needs `ingest.recursive = true`).
    pub subfolder: Option<String>,
    /// Regular expression matched against the sanitized file name.
    pub filename: Option<String>,
    /// Taxonomy slug used as the category hint (`category_source = upload`).
    pub category: Option<String>,
    /// Source label written when the release row is created (sanitized, 64 bytes).
    pub source_label: Option<String>,
}

impl Default for Ingest {
    fn default() -> Self {
        Self {
            scan_interval_secs: 5,
            stable_secs: 5,
            workers: 0,
            queue_cap: 1024,
            max_inflight_bytes: nzb_ingest::DEFAULT_MAX_INFLIGHT_BYTES,
            group_max_jobs: nzb_ingest::DEFAULT_GROUP_MAX_JOBS,
            group_window_ms: 50,
            writer_hold_ms: 50,
            duplicates_action: DuplicatesAction::Move,
            failed_retention_days: 0,
            atomic_moves: true,
            recursive: false,
            category_from_subfolder: false,
            failed_uploads_max_files: 1000,
            failed_uploads_max_bytes: 1024 * 1024 * 1024,
            rules: Vec::new(),
        }
    }
}

impl Ingest {
    /// The worker count in force: the configured one, or available cores - 1 (at least 1) for `0`.
    #[must_use]
    pub fn effective_workers(&self) -> u32 {
        let n = if self.workers == 0 {
            std::thread::available_parallelism()
                .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX))
                .saturating_sub(1)
        } else {
            self.workers
        };
        n.clamp(1, MAX_INGEST_WORKERS)
    }

    /// The pipeline settings (T114).
    #[must_use]
    pub fn settings(&self) -> nzb_ingest::IngestSettings {
        nzb_ingest::IngestSettings {
            workers: usize::try_from(self.effective_workers()).unwrap_or(1),
            queue_cap: self.queue_cap,
            max_inflight_bytes: self.max_inflight_bytes,
            group_max_jobs: self.group_max_jobs,
            group_window: std::time::Duration::from_millis(self.group_window_ms),
            writer_hold: std::time::Duration::from_millis(self.writer_hold_ms),
        }
    }

    fn validate_scale(&self) -> Result<(), ConfigError> {
        if self.workers > MAX_INGEST_WORKERS || self.scan_interval_secs == 0 {
            return invalid(
                "ingest.workers must be 0 (automatic) or 1..=32 and scan_interval_secs >= 1",
            );
        }
        if !(1..=nzb_ingest::MAX_QUEUE_CAP).contains(&self.queue_cap) {
            return invalid("ingest.queue_cap must be 1..=8192");
        }
        if !(1 << 20..=16 << 30).contains(&self.max_inflight_bytes) {
            return invalid("ingest.max_inflight_bytes must be 1 MiB..=16 GiB");
        }
        if !(1..=nzb_store::MAX_GROUP_JOBS).contains(&self.group_max_jobs) {
            return invalid("ingest.group_max_jobs must be 1..=1024");
        }
        if !(1..=1000).contains(&self.group_window_ms) || !(1..=1000).contains(&self.writer_hold_ms)
        {
            return invalid("ingest.group_window_ms and ingest.writer_hold_ms must be 1..=1000");
        }
        Ok(())
    }
}

/// Upper bound of `ingest.workers`.
const MAX_INGEST_WORKERS: u32 = 32;

/// `[limits]`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum NZB size in bytes.
    pub max_file_bytes: u64,
    /// Parse deadline in seconds.
    pub parse_deadline_secs: u64,
    /// Uploads (files) per minute per API key (SEC-029); may only be lowered from 30.
    pub upload_per_key_per_min: u32,
    /// Uploads (files) per minute per UI session (SEC-029); may only be lowered from 30.
    pub upload_per_session_per_min: u32,
    /// Uploads are refused (`507`) while `paths.tmp` or `paths.store` has less free space than
    /// `max(upload_min_free_bytes, upload_min_free_percent % of the volume)`.
    pub upload_min_free_bytes: u64,
    /// See `upload_min_free_bytes` (0..=50).
    pub upload_min_free_percent: u8,
}

impl Limits {
    /// Range checks of the upload budgets and the free-space floor.
    fn validate_uploads(&self) -> Result<(), ConfigError> {
        let budget = |n: u32| (1..=UPLOADS_PER_MIN_CEILING).contains(&n);
        if !budget(self.upload_per_key_per_min) || !budget(self.upload_per_session_per_min) {
            return invalid(format!(
                "limits.upload_per_key_per_min and upload_per_session_per_min must be 1..={UPLOADS_PER_MIN_CEILING}"
            ));
        }
        if self.upload_min_free_percent > 50 {
            return invalid("limits.upload_min_free_percent must be 0..=50");
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_FILE_BYTES_CEILING,
            parse_deadline_secs: PARSE_DEADLINE_CEILING,
            upload_per_key_per_min: UPLOADS_PER_MIN_CEILING,
            upload_per_session_per_min: UPLOADS_PER_MIN_CEILING,
            upload_min_free_bytes: 1024 * 1024 * 1024,
            upload_min_free_percent: 5,
        }
    }
}

impl Config {
    /// The validated, normalized `server.public_url` (`None` when unset or empty).
    #[must_use]
    pub fn public_url(&self) -> Option<String> {
        self.server
            .public_url
            .as_deref()
            .filter(|u| !u.is_empty())
            .and_then(|u| normalize_public_url(u, self.server.insecure_cookies).ok())
    }
}

impl Config {
    /// The validated invitation path (`security.invite_path`, T135).
    ///
    /// # Errors
    /// `INVITE_PATH_INVALID` (the same refusal as [`Config::validate`]).
    pub fn invite_path(&self) -> Result<nzb_web::invite_path::InvitePath, ConfigError> {
        self.security.parsed_invite_path()
    }

    /// The full address of the invitation page handed to an invitee (CLI and `config check`):
    /// [`Config::public_address`] + the path, or the path alone without an address.
    ///
    /// # Errors
    /// `INVITE_PATH_INVALID`.
    pub fn invite_url(&self) -> Result<String, ConfigError> {
        Ok(self.invite_path()?.url(self.public_address().as_deref()))
    }

    /// The address printed on invitation pages and by `user invite`: `server.public_url`, else
    /// `https://<first allowed host>` (`http://` only with `insecure_cookies`), else `None`.
    #[must_use]
    pub fn public_address(&self) -> Option<String> {
        self.public_url().or_else(|| {
            let scheme = if self.server.insecure_cookies {
                "http"
            } else {
                "https"
            };
            self.server
                .allowed_hosts
                .first()
                .map(|h| format!("{scheme}://{h}"))
        })
    }
}

/// `[security]`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Security {
    /// File holding the base64 32-byte TOTP encryption key.
    pub totp_key_file: PathBuf,
    /// Idle session timeout.
    pub session_idle_mins: u32,
    /// Absolute session lifetime.
    pub session_max_hours: u32,
    /// v2 opt-in for several accounts (default `false`, `AUTH_SPEC` `security.multi_user`).
    pub multi_user: bool,
    /// v2 (D28, default `true`): `false` removes the invitation surface; no effect while
    /// `multi_user` is off. Recovery codes keep working.
    pub registration_enabled: bool,
    /// Lifetime of an invitation code in hours (1..=168).
    pub invite_ttl_hours: u32,
    /// Lifetime of an admin-issued recovery code in hours (1..=24).
    pub recover_ttl_hours: u32,
    /// Live accounts allowed (1..=100).
    pub max_accounts: u32,
    /// T135: path of the invitation page (default `/invite`), e.g. `"/join-7f3k9q"`. Validated
    /// at startup (`INVITE_PATH_INVALID`, see [`nzb_web::invite_path::InvitePath::parse`]). Hides
    /// the page from scanners only; not a secret.
    pub invite_path: String,
}

impl Security {
    /// Range checks for the v2 account keys.
    fn validate_accounts(&self) -> Result<(), ConfigError> {
        if self.session_idle_mins == 0 || self.session_max_hours == 0 {
            return invalid("security.session_idle_mins and session_max_hours must be >= 1");
        }
        if !(1..=168).contains(&self.invite_ttl_hours) {
            return invalid("security.invite_ttl_hours must be 1..=168");
        }
        if !(1..=24).contains(&self.recover_ttl_hours) {
            return invalid("security.recover_ttl_hours must be 1..=24");
        }
        if !(1..=100).contains(&self.max_accounts) {
            return invalid("security.max_accounts must be 1..=100");
        }
        self.parsed_invite_path()?;
        Ok(())
    }

    /// Non-fatal advice on `security.invite_path` (T135, review 49 L1/I5): the well-known default
    /// while invitations are served, or a custom path short enough to guess. Never a refusal.
    fn invite_path_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.multi_user {
            return out;
        }
        if self.invite_path == nzb_web::invite_path::DEFAULT_INVITE_PATH {
            out.push(
                "INVITE_PATH_DEFAULT: security.multi_user = true and security.invite_path is still /invite; \
                 set a random path (e.g. \"/join-\" + 12 letters/digits) to keep scanners off the invitation page"
                    .to_owned(),
            );
        } else if self.invite_path.len() < SHORT_INVITE_PATH {
            out.push(format!(
                "INVITE_PATH_SHORT: security.invite_path is shorter than {SHORT_INVITE_PATH} characters; \
                 a longer random path is harder to guess"
            ));
        }
        out
    }

    /// The validated `security.invite_path`.
    fn parsed_invite_path(&self) -> Result<nzb_web::invite_path::InvitePath, ConfigError> {
        nzb_web::invite_path::InvitePath::parse(&self.invite_path).map_err(|e| {
            // The path is not a secret (T135): naming the value helps the operator find it.
            ConfigError::Invalid(format!(
                "{}: security.invite_path {:?} {e}",
                e.code(),
                self.invite_path
            ))
        })
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            totp_key_file: PathBuf::from("/run/secrets/nzbd_totp_key"),
            session_idle_mins: 30,
            session_max_hours: 12,
            multi_user: false,
            registration_enabled: true,
            invite_ttl_hours: 48,
            recover_ttl_hours: 2,
            max_accounts: 100,
            invite_path: nzb_web::invite_path::DEFAULT_INVITE_PATH.to_owned(),
        }
    }
}

/// `[db]` (ARCHITECTURE v3 7 and 13.5). `backend` selects the store; the Postgres keys apply only to `postgres` (and
/// are a warning with `sqlite`, `DB_KEY_FOR_OTHER_BACKEND`). The SQLite file is `paths.db`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Db {
    /// `"sqlite"` (default) or `"postgres"`: a closed set, any other value (`"pg"`, `"postgresql"`, ...) is refused,
    /// also through `NZBD__db__backend` (SEC-101).
    #[serde(deserialize_with = "de_backend")]
    pub backend: nzb_store::DbBackend,
    /// How much of the file `serve` reads before listening for real (T088). Pending migrations
    /// always force `full` first. SQLite only.
    pub startup_check: StartupCheck,
    /// Postgres: absolute socket directory or an internal IP literal (never a hostname).
    pub host: Option<String>,
    /// Postgres port.
    pub port: u16,
    /// Postgres database name (`^[a-z_][a-z0-9_]{0,62}$`).
    pub name: String,
    /// Postgres application role (DML only).
    pub user: String,
    /// Postgres password file (0400, owned by the service uid, SEC-042 rules).
    pub password_file: Option<PathBuf>,
    /// Postgres pool of the HTTP handlers.
    pub pool_web: u32,
    /// Postgres pool of the ingest writers.
    pub pool_ingest: u32,
    /// Postgres pool of the indexer, maintenance and health.
    pub pool_background: u32,
    /// Postgres pool acquire timeout, ms (past it: the uniform `503 BUSY`).
    pub acquire_timeout_ms: u64,
    /// Postgres `statement_timeout` of the web pool, ms.
    pub statement_timeout_ms: u64,
}

impl Default for Db {
    fn default() -> Self {
        Self {
            backend: nzb_store::DbBackend::Sqlite,
            startup_check: StartupCheck::default(),
            host: None,
            port: 5432,
            name: "nzbd".to_owned(),
            user: "nzbd_app".to_owned(),
            password_file: None,
            pool_web: nzb_store::pg::config::POOL_WEB.1,
            pool_ingest: nzb_store::pg::config::POOL_INGEST.1,
            pool_background: nzb_store::pg::config::POOL_BACKGROUND.1,
            acquire_timeout_ms: 3000,
            statement_timeout_ms: 5000,
        }
    }
}

/// SEC-086 (Postgres backend only; `serve` and every Postgres connection, review 35 I4): refuses `PG*` and `SSL_CERT_*` variables in the process
/// environment; they would otherwise silently steer a database connection or a trust store.
///
/// # Errors
/// `DB_ENV_AMBIGUOUS` naming the variables (never their values).
pub fn check_process_environment() -> Result<(), ConfigError> {
    nzb_store::pg::config::check_environment(
        std::env::vars_os().filter(|(k, _)| !ignored_in_unit_tests(k)),
    )
    .map_err(|e| ConfigError::Invalid(format!("{}: {e}", e.code())))
}

/// `cargo` exports `SSL_CERT_FILE`/`SSL_CERT_DIR` to every test process it starts, and Rust 2024 makes removing an
/// environment variable `unsafe` (forbidden here). The unit tests of this crate that open the Postgres backend
/// in-process therefore ignore exactly those two; the shipped binary (`cfg(not(test))`) never does, and the refusal
/// itself is proven by `sec_086_pg_and_ssl_cert_environment_variables_are_refused` and by the spawned-binary suites.
#[cfg(test)]
fn ignored_in_unit_tests(k: &std::ffi::OsStr) -> bool {
    k == "SSL_CERT_FILE" || k == "SSL_CERT_DIR"
}

#[cfg(not(test))]
const fn ignored_in_unit_tests(_: &std::ffi::OsStr) -> bool {
    false
}

fn de_backend<'de, D: serde::Deserializer<'de>>(d: D) -> Result<nzb_store::DbBackend, D::Error> {
    let s = String::deserialize(d)?;
    s.parse()
        .map_err(|e: nzb_store::UnknownBackend| serde::de::Error::custom(e))
}

impl Db {
    /// The validated Postgres settings (`backend = "postgres"` only).
    ///
    /// # Errors
    /// A missing `host`/`password_file` or the first violated rule of `RawPgSettings::validate` (stable code).
    pub fn pg_settings(&self) -> Result<nzb_store::pg::PgSettings, ConfigError> {
        let host = self.host.as_deref().ok_or_else(|| {
            ConfigError::Invalid(
                "DB_HOST_MISSING: db.host is required with backend = \"postgres\"".into(),
            )
        })?;
        let password_file = self.password_file.as_deref().ok_or_else(|| {
            ConfigError::Invalid(
                "DB_PASSWORD_FILE_MISSING: db.password_file is required with backend = \"postgres\"".into(),
            )
        })?;
        nzb_store::pg::RawPgSettings {
            host,
            port: self.port,
            name: &self.name,
            user: &self.user,
            password_file,
            pool_web: self.pool_web,
            pool_ingest: self.pool_ingest,
            pool_background: self.pool_background,
            acquire_timeout_ms: self.acquire_timeout_ms,
            statement_timeout_ms: self.statement_timeout_ms,
        }
        .validate()
        .map_err(|e| ConfigError::Invalid(format!("{}: {e}", e.code())))
    }

    /// Backend-specific checks: the Postgres settings must validate with `postgres`; Postgres keys set with
    /// `sqlite` are a warning. (The libpq/`SSL_CERT_*` environment refusal reads the process environment and runs
    /// where a process starts: `serve` and every Postgres connection, see [`check_process_environment`].)
    fn check(&self) -> Result<Vec<String>, ConfigError> {
        let mut w = Vec::new();
        match self.backend {
            nzb_store::DbBackend::Postgres => {
                self.pg_settings()?;
            }
            nzb_store::DbBackend::Sqlite => {
                if self.host.is_some() || self.password_file.is_some() {
                    w.push(
                        "DB_KEY_FOR_OTHER_BACKEND: db.host/db.password_file are ignored with backend = \"sqlite\""
                            .to_owned(),
                    );
                }
            }
        }
        Ok(w)
    }
}

/// `[db] startup_check`: see [`nzb_store::StartupCheck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartupCheck {
    /// Schema plus the small critical tables; independent of library size (default).
    #[default]
    Fast,
    /// `PRAGMA quick_check` over the whole file.
    Quick,
    /// `integrity_check` + `foreign_key_check` over the whole file (the pre-1.1 behaviour).
    Full,
}

impl From<StartupCheck> for nzb_store::StartupCheck {
    fn from(c: StartupCheck) -> Self {
        match c {
            StartupCheck::Fast => Self::Fast,
            StartupCheck::Quick => Self::Quick,
            StartupCheck::Full => Self::Full,
        }
    }
}

/// `[maintenance]`: the in-process daily job (T061 L-3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Maintenance {
    /// Hours between backup+purge runs; `0` disables the whole job (use `nzbd backup` from cron).
    pub backup_interval_hours: u32,
    /// Backups kept by rotation.
    pub keep_backups: u32,
    /// Optional file with the base64 32-byte key that encrypts backups at rest (T104, SEC-052).
    /// Same rules as the TOTP key file (regular file, mode 0400, owned by the process uid) and it
    /// must be a DIFFERENT key kept outside `paths.backups`. Unset = plaintext snapshots.
    pub backup_encryption_key_file: Option<PathBuf>,
}

impl Maintenance {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.backup_interval_hours > 24 * 366
            || self.keep_backups == 0
            || self.keep_backups > 3650
        {
            return invalid(
                "maintenance.backup_interval_hours must be 0..=8784 and keep_backups 1..=3650",
            );
        }
        Ok(())
    }
}

impl Default for Maintenance {
    fn default() -> Self {
        Self {
            backup_interval_hours: 24,
            keep_backups: 14,
            backup_encryption_key_file: None,
        }
    }
}

/// 32-byte key whose `Debug` never shows the bytes; wiped from memory on drop.
#[derive(Clone)]
pub struct SecretKey(pub [u8; TOTP_KEY_LEN]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Applies `NZBD__section__key=value` overrides from `vars` onto a TOML table.
/// Values are parsed as TOML scalars/arrays when possible, else kept as strings.
fn apply_env(table: &mut toml::Table, vars: impl IntoIterator<Item = (String, String)>) {
    for (k, raw) in vars {
        let Some(rest) = k.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let parts: Vec<String> = rest.split("__").map(str::to_ascii_lowercase).collect();
        let value = format!("v = {raw}")
            .parse::<toml::Table>()
            .ok()
            .and_then(|mut t| t.remove("v"))
            .unwrap_or(toml::Value::String(raw));
        let Some((leaf, path)) = parts.split_last() else {
            continue;
        };
        insert_path(table, path, leaf, value);
    }
}

/// Reads only configuration overrides. `env::vars` panics on any non-Unicode value and
/// includes that value in the panic, even when the variable is unrelated to configuration.
fn config_environment(
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Result<Vec<(String, String)>, ConfigError> {
    let mut overrides = Vec::new();
    for (key, value) in vars {
        if !key.as_encoded_bytes().starts_with(ENV_PREFIX.as_bytes()) {
            continue;
        }
        let error =
            || ConfigError::Invalid("NZBD__ configuration overrides must use valid UTF-8".into());
        overrides.push((
            key.into_string().map_err(|_| error())?,
            value.into_string().map_err(|_| error())?,
        ));
    }
    Ok(overrides)
}

/// Sets `table[path...][leaf] = value`, creating (or replacing non-table) intermediates.
fn insert_path(table: &mut toml::Table, path: &[String], leaf: &str, value: toml::Value) {
    match path.split_first() {
        None => {
            table.insert(leaf.to_owned(), value);
        }
        Some((head, rest)) => {
            let entry = table
                .entry(head.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if !entry.is_table() {
                *entry = toml::Value::Table(toml::Table::new());
            }
            if let toml::Value::Table(t) = entry {
                insert_path(t, rest, leaf, value);
            }
        }
    }
}

impl Config {
    /// Loads config from an optional file, then applies process-environment overrides.
    ///
    /// # Errors
    /// Unreadable file, bad TOML, unknown keys or wrong types.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        Self::load_with_env(path, config_environment(std::env::vars_os())?)
    }

    /// Like [`Config::load`] with an explicit environment (deterministic tests).
    ///
    /// # Errors
    /// See [`Config::load`].
    pub fn load_with_env(
        path: Option<&Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut table = match path {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| ConfigError::Read(p.to_path_buf(), e))?
                .parse::<toml::Table>()
                .map_err(|e| ConfigError::Parse(e.message().to_owned()))?,
            None => toml::Table::new(),
        };
        apply_env(&mut table, env);
        table
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse(e.message().to_owned()))
    }

    /// T104: the optional backup key file follows the TOTP key rules and must stay separate.
    fn validate_backup_key(&self, totp_key: &SecretKey) -> Result<(), ConfigError> {
        let Some(p) = &self.maintenance.backup_encryption_key_file else {
            return Ok(());
        };
        let backup_key = load_key_file_as(p, "maintenance.backup_encryption_key_file")?;
        // A leaked backup must not come with the means to unseal TOTP secrets, and vice versa.
        if ct_eq(&backup_key.0, &totp_key.0) {
            return invalid(
                "maintenance.backup_encryption_key_file must hold a different key than \
                 security.totp_key_file",
            );
        }
        // Keeping the key next to the ciphertext (or in a directory that is cleared) defeats it.
        let inside = |dir: &Path| match (std::fs::canonicalize(p), std::fs::canonicalize(dir)) {
            (Ok(f), Ok(d)) => f.starts_with(d),
            _ => false,
        };
        for (name, dir) in [("backups", &self.paths.backups), ("tmp", &self.paths.tmp)] {
            if inside(dir) {
                return invalid(format!(
                    "maintenance.backup_encryption_key_file must not be inside paths.{name}"
                ));
            }
        }
        Ok(())
    }

    /// Settings of 2.x that 3.x does not carry (fresh start): refused with a stable code, never ignored.
    fn refuse_removed(&self) -> Result<(), ConfigError> {
        if self.store.backend == StoreBackend::Db {
            return invalid(
                "STORE_DB_BACKEND_REMOVED: store.backend = \"db\" is not supported in 3.x; NZB files live on the \
                 filesystem only (store.backend = \"fs\")",
            );
        }
        Ok(())
    }

    /// The validated `[[ingest.rules]]` (T126), compiled against the built-in taxonomy.
    ///
    /// # Errors
    /// `RULE_TOO_MANY`, `RULE_NO_MATCHER`, `RULE_TWO_MATCHERS`, `RULE_BAD_SUBFOLDER`, `RULE_BAD_REGEX`,
    /// `RULE_UNKNOWN_CATEGORY` or `RULE_NO_ACTION` (first refused rule, numbered from 1 in file order).
    pub fn watch_rules(&self) -> Result<nzb_ingest::WatchRules, ConfigError> {
        let tax = nzb_core::Taxonomy::builtin()
            .map_err(|e| ConfigError::Invalid(format!("taxonomy: {e}")))?;
        let specs: Vec<nzb_ingest::RuleSpec> = self
            .ingest
            .rules
            .iter()
            .map(|r| nzb_ingest::RuleSpec {
                subfolder: r.subfolder.clone(),
                filename: r.filename.clone(),
                category: r.category.clone(),
                source_label: r.source_label.clone(),
            })
            .collect();
        nzb_ingest::WatchRules::compile(&specs, self.ingest.recursive, &tax)
            .map_err(|e| ConfigError::Invalid(format!("{}: ingest.rules: {e}", e.code())))
    }

    /// Validates the configuration against the filesystem. Returns non-fatal warnings.
    ///
    /// # Errors
    /// Any condition listed in ARCHITECTURE §Configuration plus range checks.
    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        self.refuse_removed()?;
        let mut warnings = self.db.check()?;
        let lim = &self.limits;
        if lim.max_file_bytes == 0 || lim.max_file_bytes > MAX_FILE_BYTES_CEILING {
            return invalid(format!(
                "limits.max_file_bytes must be 1..={MAX_FILE_BYTES_CEILING}"
            ));
        }
        if lim.parse_deadline_secs == 0 || lim.parse_deadline_secs > PARSE_DEADLINE_CEILING {
            return invalid(format!(
                "limits.parse_deadline_secs must be 1..={PARSE_DEADLINE_CEILING}"
            ));
        }
        lim.validate_uploads()?;
        self.maintenance.validate()?;
        let ing = &self.ingest;
        ing.validate_scale()?;
        if self.search.lag_warn_secs == 0 {
            return invalid("search.lag_warn_secs must be >= 1");
        }
        if ing.category_from_subfolder && !ing.recursive {
            return invalid("ingest.category_from_subfolder requires ingest.recursive = true");
        }
        self.watch_rules()?;
        let sec = &self.security;
        sec.validate_accounts()?;
        warnings.extend(sec.invite_path_warnings());
        warnings.extend(self.metrics.validate(&self.server)?);
        if let Some(u) = self.server.public_url.as_deref().filter(|u| !u.is_empty()) {
            normalize_public_url(u, self.server.insecure_cookies)?;
        }

        let paths = &self.paths;
        for (name, dir) in [
            ("watch", &paths.watch),
            ("store", &paths.store),
            ("failed", &paths.failed),
            ("duplicates", &paths.duplicates),
            ("tmp", &paths.tmp),
            ("backups", &paths.backups),
        ] {
            if !dir.is_dir() {
                return invalid(format!(
                    "paths.{name} is not an existing directory: {}",
                    dir.display()
                ));
            }
        }
        check_no_overlap(paths)?;
        check_tmp_isolated(paths, &self.security.totp_key_file)?;
        self.check_db_path()?;
        check_index_and_state(paths, &self.index_dir(), &self.state_dir())?;

        if ing.atomic_moves {
            let dev = |d: &Path| std::fs::metadata(d).map(|m| m.dev());
            let devs = [dev(&paths.watch), dev(&paths.store), dev(&paths.failed)];
            match devs {
                [Ok(a), Ok(b), Ok(c)] if a == b && b == c => {}
                _ => {
                    return invalid(
                        "paths.watch, paths.store and paths.failed must share one filesystem \
                         when ingest.atomic_moves = true",
                    );
                }
            }
        }

        let totp_key = load_key_file(&sec.totp_key_file)?;
        self.validate_backup_key(&totp_key)?;

        if let Some(bad) = self
            .server
            .allowed_hosts
            .iter()
            .find(|h| !nzb_web::csrf::valid_allowed_host(h))
        {
            return invalid(format!(
                "server.allowed_hosts entry {bad:?} must be a lowercase host name without port"
            ));
        }

        if !self.server.listen.ip().is_loopback() && self.server.trusted_proxies.is_empty() {
            warnings.push(
                "server.listen is not loopback and server.trusted_proxies is empty; \
                 forwarded headers will be ignored"
                    .to_owned(),
            );
        }
        if ing.duplicates_action == DuplicatesAction::Delete {
            warnings.push(
                "ingest.duplicates_action = delete: duplicate files in the watch folder are \
                 deleted once the identical NZB is confirmed in the store"
                    .to_owned(),
            );
        }
        if self.server.insecure_cookies {
            warnings.push(
                "server.insecure_cookies = true: cookies are sent over plain HTTP".to_owned(),
            );
        }
        Ok(warnings)
    }
}

/// Reads and validates the TOTP key file (SEC-042): must be a regular file, not accessible by
/// group/other, and hold 32 bytes of base64.
///
/// # Errors
/// Missing file, permissive mode, or malformed content. Content is never echoed.
pub fn load_key_file(path: &Path) -> Result<SecretKey, ConfigError> {
    load_key_file_as(path, "security.totp_key_file")
}

/// Constant-time equality of two 32-byte keys.
#[must_use]
pub fn ct_eq(a: &[u8; TOTP_KEY_LEN], b: &[u8; TOTP_KEY_LEN]) -> bool {
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// [`load_key_file`] for any key file; `label` names the setting or option in error messages.
///
/// # Errors
/// Missing file, permissive mode, wrong owner, or malformed content. Content is never echoed.
pub fn load_key_file_as(path: &Path, label: &str) -> Result<SecretKey, ConfigError> {
    // SEC-042 (T107 I3): refuse a symlink outright. `metadata` would follow it and report the
    // target's mode and owner; the shipped layout (a named volume written by `keygen`) has none.
    let link = std::fs::symlink_metadata(path).map_err(|e| {
        ConfigError::Invalid(format!(
            "{label} {} is not readable: {}",
            path.display(),
            e.kind()
        ))
    })?;
    if link.file_type().is_symlink() {
        return invalid(format!(
            "{label} {} is a symbolic link; point the setting at the key file itself",
            path.display()
        ));
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        ConfigError::Invalid(format!(
            "{label} {} is not readable: {}",
            path.display(),
            e.kind()
        ))
    })?;
    if !meta.is_file() {
        return invalid(format!("{label} {} is not a regular file", path.display()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return invalid(format!(
            "{label} {} has insecure mode {mode:03o}; require 0400 (no group/other access)",
            path.display()
        ));
    }
    // Ownership: a 0400 file owned by another uid would pass the mode check yet be controlled
    // by someone else. The effective uid comes from the kernel: the owner of `/proc/self` is root
    // once nzbd has made itself non-dumpable (review 44 M1).
    let proc_uid = Some(rustix::process::geteuid().as_raw());
    check_key_owner(path, label, meta.uid(), proc_uid)?;
    // Text and decoded bytes are wiped on drop (best effort; the key must live in memory).
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        ConfigError::Invalid(format!("cannot read key file {label}: {}", e.kind()))
    })?);
    let bytes = Zeroizing::new(
        B64.decode(text.trim())
            .map_err(|_| ConfigError::Invalid(format!("key file {label} is not valid base64")))?,
    );
    let key: [u8; TOTP_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        ConfigError::Invalid(format!(
            "key file {label} must decode to exactly {TOTP_KEY_LEN} bytes"
        ))
    })?;
    // A key of all zero bytes is what an uninitialised buffer or a failed generator leaves behind;
    // no honest `keygen` produces it (probability 2^-256).
    if key.iter().all(|b| *b == 0) {
        return invalid(format!("key file {label} holds an all-zero key"));
    }
    Ok(SecretKey(key))
}

/// SEC-042: the key file must belong to the user running the process.
fn check_key_owner(
    path: &Path,
    label: &str,
    file_uid: u32,
    proc_uid: Option<u32>,
) -> Result<(), ConfigError> {
    match proc_uid {
        Some(p) if p != file_uid => invalid(format!(
            "{label} {} is owned by uid {file_uid}, expected the process uid {p}",
            path.display()
        )),
        _ => Ok(()),
    }
}

/// Generates a fresh random key as base64 (reads the OS CSPRNG via `/dev/urandom`).
///
/// # Errors
/// I/O failure reading the random device.
pub fn generate_key_b64() -> std::io::Result<String> {
    use std::io::Read as _;
    let mut buf = [0_u8; TOTP_KEY_LEN];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(B64.encode(buf))
}

/// Writes `contents` to a new file with mode 0400; refuses to overwrite.
///
/// # Errors
/// I/O failure, or the file already exists.
pub fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    // Durable or absent: a crash must not leave an empty 0400 file that `create_new` then refuses to
    // replace. On any write/sync failure the half-written file is removed.
    let written = f
        .write_all(contents.as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    // Persist the directory entry too.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_unicode_unrelated_environment_is_ignored_without_reading_its_value() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let vars = config_environment([
            (
                OsString::from("UNRELATED_SECRET"),
                OsString::from_vec(b"AUDIT_FAKE_SECRET\xff".to_vec()),
            ),
            (
                OsString::from_vec(b"UNRELATED\xff".to_vec()),
                OsString::from("AUDIT_FAKE_VALUE"),
            ),
            (
                OsString::from("NZBD__limits__max_file_bytes"),
                OsString::from("2048"),
            ),
        ])
        .unwrap();
        assert_eq!(vars.len(), 1);
        let config = Config::load_with_env(None, vars).unwrap();
        assert_eq!(config.limits.max_file_bytes, 2048);
    }

    #[test]
    fn non_unicode_config_overrides_fail_without_disclosing_names_or_values() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        for entry in [
            (
                OsString::from("NZBD__db__password_file"),
                OsString::from_vec(b"AUDIT_FAKE_VALUE\xff".to_vec()),
            ),
            (
                OsString::from_vec(b"NZBD__AUDIT_FAKE_NAME\xff".to_vec()),
                OsString::from("AUDIT_FAKE_VALUE"),
            ),
        ] {
            let error = config_environment([entry]).unwrap_err();
            let output = format!("{error} {error:?}");
            assert!(!output.contains("AUDIT_FAKE"));
            assert!(output.contains("valid UTF-8"));
        }
    }

    fn tmp_cfg(dir: &Path, key_mode: u32) -> Config {
        for d in ["watch", "store", "failed", "duplicates", "tmp", "backups"] {
            std::fs::create_dir_all(dir.join(d)).unwrap_or_default();
        }
        let key = dir.join("key");
        std::fs::write(
            &key,
            format!("{}\n", generate_key_b64().unwrap_or_default()),
        )
        .unwrap_or_default();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(key_mode))
            .unwrap_or_default();
        let mut c = Config {
            paths: Paths {
                watch: dir.join("watch"),
                store: dir.join("store"),
                failed: dir.join("failed"),
                duplicates: dir.join("duplicates"),
                tmp: dir.join("tmp"),
                db: dir.join("db.sqlite"),
                backups: dir.join("backups"),
                state: None,
            },
            ..Config::default()
        };
        c.security.totp_key_file = key;
        c
    }

    #[test]
    fn v2_account_keys_default_to_the_single_user_behaviour() {
        let s = Security::default();
        assert!(!s.multi_user, "SEC-069: the flag is explicit opt-in");
        assert!(s.registration_enabled);
        assert_eq!(
            (s.invite_ttl_hours, s.recover_ttl_hours, s.max_accounts),
            (48, 2, 100)
        );
        let c: Config = toml::from_str("").unwrap();
        assert!(!c.security.multi_user && c.security.registration_enabled);
        assert!(c.public_url().is_none() && c.public_address().is_none());
    }

    #[test]
    fn v2_account_keys_are_range_checked() {
        let d = tempfile::tempdir().unwrap();
        for (set, needle) in [
            ("invite_ttl_hours", "invite_ttl_hours"),
            ("recover_ttl_hours", "recover_ttl_hours"),
            ("max_accounts", "max_accounts"),
        ] {
            for bad in [0_u32, 1000] {
                let mut c = tmp_cfg(d.path(), 0o400);
                match set {
                    "invite_ttl_hours" => c.security.invite_ttl_hours = bad,
                    "recover_ttl_hours" => c.security.recover_ttl_hours = bad,
                    _ => c.security.max_accounts = bad,
                }
                let e = c.validate().unwrap_err().to_string();
                assert!(e.contains(needle), "{set}={bad}: {e}");
            }
        }
        let mut c = tmp_cfg(d.path(), 0o400);
        c.security.recover_ttl_hours = 25;
        assert!(c.validate().is_err(), "recovery codes live at most 24 h");
        let mut c = tmp_cfg(d.path(), 0o400);
        c.security.multi_user = true;
        c.security.recover_ttl_hours = 24;
        c.security.invite_ttl_hours = 168;
        assert!(c.validate().is_ok());
    }

    /// T135: `security.invite_path` defaults to `/invite`, is settable through the env override
    /// (any case), and every refused shape or collision stops `validate` with the stable code.
    #[test]
    fn sec_028_invite_path_is_validated_at_startup() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.security.invite_path, "/invite");
        assert!(c.invite_path().unwrap().is_default());
        assert_eq!(c.invite_url().unwrap(), "/invite");
        let env = vec![(
            "NZBD__SECURITY__INVITE_PATH".to_owned(),
            "/join-7f3k9q".to_owned(),
        )];
        let c = Config::load_with_env(None, env).unwrap();
        assert_eq!(c.security.invite_path, "/join-7f3k9q");
        let mut c2 = c.clone();
        c2.server.public_url = Some("https://nzbd.example".to_owned());
        assert_eq!(c2.invite_url().unwrap(), "https://nzbd.example/join-7f3k9q");
        let c: Config = toml::from_str("[security]\ninvite_path = \"/join-abc123\"\n").unwrap();
        assert_eq!(c.invite_path().unwrap().as_str(), "/join-abc123");

        let d = tempfile::tempdir().unwrap();
        let mut ok = tmp_cfg(d.path(), 0o400);
        ok.security.invite_path = "/join-7f3k9q".to_owned();
        assert!(ok.validate().is_ok());
        // Review 49 L1/I5: advice, never a refusal, and only while invitations are served.
        let warns = |c: &Config| -> Vec<String> {
            c.validate()
                .unwrap()
                .into_iter()
                .filter(|w| w.starts_with("INVITE_PATH_"))
                .collect()
        };
        assert_eq!(
            warns(&ok),
            Vec::<String>::new(),
            "multi_user off: no advice"
        );
        let mut mu = tmp_cfg(d.path(), 0o400);
        mu.security.multi_user = true;
        let w = warns(&mu);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].starts_with("INVITE_PATH_DEFAULT: "), "{w:?}");
        mu.security.invite_path = "/join-7f3".to_owned();
        let w = warns(&mu);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].starts_with("INVITE_PATH_SHORT: "), "{w:?}");
        mu.security.invite_path = "/join-7f3k9q".to_owned();
        assert_eq!(warns(&mu), Vec::<String>::new());
        for bad in [
            "/invite-x1",
            "/Invite",
            "",
            "join-7f3k9q",
            "/join/7f3k9q",
            "/abc",
            "/../etc",
            "/abc.def1",
            "/login",
            "/login-page",
            "/admin-x1",
            "/static",
            "/api-v1-x",
            "/releases",
            "/search-x",
            "/stats-page",
            "/upload",
            "/healthz",
            "/account-new",
            "/mfa-enrol",
        ] {
            let mut c = tmp_cfg(d.path(), 0o400);
            c.security.invite_path = bad.to_owned();
            let e = c.validate().unwrap_err().to_string();
            assert!(e.starts_with("INVITE_PATH_INVALID: "), "{bad:?}: {e}");
            assert!(e.contains("security.invite_path"), "{bad:?}: {e}");
            assert!(c.invite_url().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sec_083_metrics_listener_is_off_by_default_and_internal_unless_confirmed() {
        let d = tempfile::tempdir().unwrap();
        let mut c = tmp_cfg(d.path(), 0o400);
        assert!(c.metrics.listen.is_none());
        assert!(c.validate().is_ok());
        // Loopback: accepted.
        c.metrics.listen = Some("127.0.0.1:9100".parse().unwrap());
        assert!(c.validate().unwrap().iter().all(|w| !w.contains("metrics")));
        // Not loopback without the explicit confirmation: refused.
        c.metrics.listen = Some("0.0.0.0:9100".parse().unwrap());
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("allow_back_network"), "{e}");
        // Confirmed: accepted with a warning.
        c.metrics.allow_back_network = true;
        assert!(
            c.validate()
                .unwrap()
                .iter()
                .any(|w| w.contains("metrics.listen"))
        );
        // Never on the application's own port.
        c.metrics.listen = Some(SocketAddr::new(
            [127, 0, 0, 1].into(),
            c.server.listen.port(),
        ));
        assert!(c.validate().is_err());
    }

    #[test]
    fn public_url_is_normalized_and_never_taken_from_a_request() {
        for (raw, insecure, want) in [
            (
                "https://Nzb.Example.net",
                false,
                Some("https://nzb.example.net"),
            ),
            (
                "https://nzb.example.net:8443",
                false,
                Some("https://nzb.example.net:8443"),
            ),
            ("http://nas.lan:8080", true, Some("http://nas.lan:8080")),
            ("http://nas.lan", false, None),
            ("https://nzb.example.net/path", false, None),
            ("https://user@nzb.example.net", false, None),
            ("https://nzb.example.net?x=1", false, None),
            ("ftp://nzb.example.net", false, None),
            ("https://", false, None),
            ("https://nzb.example.net:0", false, None),
        ] {
            let got = normalize_public_url(raw, insecure).ok();
            assert_eq!(got.as_deref(), want, "{raw}");
        }
    }

    /// SEC-102: a SQLite database inside a directory nzbd moves, clears, rotates or rebuilds is refused (also through
    /// a symlink alias); the default layout (the database next to those directories) passes.
    #[test]
    fn sec_102_database_is_not_inside_watch_tmp_backups_or_the_index() {
        let d = tempfile::tempdir().unwrap();
        let c = tmp_cfg(d.path(), 0o400);
        c.validate().unwrap();
        for which in ["watch", "tmp", "backups", "index"] {
            let mut c = tmp_cfg(d.path(), 0o400);
            let dir = match which {
                "watch" => c.paths.watch.clone(),
                "tmp" => c.paths.tmp.clone(),
                "backups" => c.paths.backups.clone(),
                _ => {
                    let i = d.path().join("idx");
                    std::fs::create_dir_all(&i).unwrap();
                    c.search.index_dir = Some(i.clone());
                    i
                }
            };
            c.paths.db = dir.join("nzbd.sqlite");
            let e = c.validate().unwrap_err().to_string();
            assert!(
                e.contains("DB_PATH_LOCATION") || e.contains("paths.tmp"),
                "{which}: {e}"
            );
        }
        // Through an alias of the backups directory.
        let mut c = tmp_cfg(d.path(), 0o400);
        let alias = d.path().join("bk-alias");
        std::os::unix::fs::symlink(&c.paths.backups, &alias).unwrap();
        c.paths.db = alias.join("nzbd.sqlite");
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("DB_PATH_LOCATION"), "{e}");
    }

    /// Review 39 L1: `search.index_dir` and `paths.state` may not be, contain or lie inside a data directory or each
    /// other (equal, nested either way, not yet existing, through a symlink alias); the default layout passes.
    #[test]
    fn sec_091_index_dir_must_not_nest_with_data_paths() {
        let d = tempfile::tempdir().unwrap();
        tmp_cfg(d.path(), 0o400).validate().unwrap();
        let alias = d.path().join("watch-alias");
        std::os::unix::fs::symlink(d.path().join("watch"), &alias).unwrap();
        for data in ["watch", "store", "failed", "duplicates", "tmp", "backups"] {
            let dir = d.path().join(data);
            for candidate in [dir.clone(), dir.join("index"), dir.join("a").join("b")] {
                for state in [false, true] {
                    let mut c = tmp_cfg(d.path(), 0o400);
                    if state {
                        c.paths.state = Some(candidate.clone());
                    } else {
                        c.search.index_dir = Some(candidate.clone());
                    }
                    let e = c.validate().unwrap_err().to_string();
                    let code = if state {
                        "STATE_DIR_LOCATION"
                    } else {
                        "INDEX_DIR_LOCATION"
                    };
                    assert!(e.contains(code), "{data} {}: {e}", candidate.display());
                }
            }
        }
        // A directory that contains the data directories (the database is elsewhere, so only this rule applies).
        let mut c = tmp_cfg(d.path(), 0o400);
        let elsewhere = tempfile::tempdir().unwrap();
        c.paths.db = elsewhere.path().join("db.sqlite");
        c.search.index_dir = Some(d.path().to_path_buf());
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("INDEX_DIR_LOCATION")
        );
        // Through a symlink alias of the watch folder.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.search.index_dir = Some(alias.join("idx"));
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("INDEX_DIR_LOCATION")
        );
        // Index and state nested in each other.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.paths.state = Some(d.path().join("index").join("state"));
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("INDEX_DIR_LOCATION")
        );
        // A `..` in the part that does not exist yet is refused rather than guessed.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.search.index_dir = Some(d.path().join("new").join("..").join("watch"));
        assert!(c.validate().is_err());
        // Separate, not yet existing directories next to the data directories pass.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.search.index_dir = Some(d.path().join("idx2"));
        c.paths.state = Some(d.path().join("st2"));
        c.validate().unwrap();
    }

    #[test]
    fn t031_m2_rejects_any_overlap_with_the_watch_folder() {
        let d = tempfile::tempdir().unwrap();
        for which in ["store", "failed", "duplicates", "tmp", "backups"] {
            // Nested inside watch (the recursive quarantine loop).
            let mut c = tmp_cfg(d.path(), 0o400);
            let inner = c.paths.watch.join(which);
            std::fs::create_dir_all(&inner).unwrap();
            match which {
                "store" => c.paths.store = inner,
                "failed" => c.paths.failed = inner,
                "duplicates" => c.paths.duplicates = inner,
                "tmp" => c.paths.tmp = inner,
                _ => c.paths.backups = inner,
            }
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains(which) && e.contains("overlap"), "{which}: {e}");
        }
        // Watch inside another directory, equal paths, and a symlink/`..` disguise.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.paths.failed = c.paths.watch.clone();
        assert!(c.validate().is_err());
        let mut c = tmp_cfg(d.path(), 0o400);
        let nested = c.paths.store.join("w");
        std::fs::create_dir_all(&nested).unwrap();
        c.paths.watch = nested;
        assert!(c.validate().is_err());
        let mut c = tmp_cfg(d.path(), 0o400);
        std::os::unix::fs::symlink(&c.paths.watch, d.path().join("alias")).unwrap();
        c.paths.duplicates = d.path().join("alias");
        assert!(c.validate().is_err());
        let mut c = tmp_cfg(d.path(), 0o400);
        c.paths.failed = c
            .paths
            .watch
            .join("..")
            .join("watch")
            .join("..")
            .join("failed");
        c.paths.tmp = c.paths.watch.join("../watch");
        assert!(c.validate().is_err());
    }

    fn set_dir(c: &mut Config, which: &str, p: PathBuf) {
        match which {
            "store" => c.paths.store = p,
            "failed" => c.paths.failed = p,
            "duplicates" => c.paths.duplicates = p,
            _ => c.paths.backups = p,
        }
    }

    #[test]
    fn t032_m1_tmp_must_not_equal_or_nest_with_data_directories() {
        let d = tempfile::tempdir().unwrap();
        for which in ["store", "failed", "duplicates", "backups"] {
            let base = tmp_cfg(d.path(), 0o400);
            let other = match which {
                "store" => base.paths.store.clone(),
                "failed" => base.paths.failed.clone(),
                "duplicates" => base.paths.duplicates.clone(),
                _ => base.paths.backups.clone(),
            };
            // tmp == X
            let mut c = tmp_cfg(d.path(), 0o400);
            c.paths.tmp = other.clone();
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains("paths.tmp") && e.contains(which), "{which}: {e}");
            // tmp inside X
            let mut c = tmp_cfg(d.path(), 0o400);
            let inner = other.join("t");
            std::fs::create_dir_all(&inner).unwrap();
            c.paths.tmp = inner;
            assert!(c.validate().is_err(), "tmp inside {which}");
            // X inside tmp
            let mut c = tmp_cfg(d.path(), 0o400);
            let inner = c.paths.tmp.join(which);
            std::fs::create_dir_all(&inner).unwrap();
            set_dir(&mut c, which, inner);
            assert!(c.validate().is_err(), "{which} inside tmp");
            // tmp is a symlink to X
            let mut c = tmp_cfg(d.path(), 0o400);
            let link = d.path().join(format!("tmp-link-{which}"));
            std::os::unix::fs::symlink(&other, &link).unwrap();
            c.paths.tmp = link;
            assert!(c.validate().is_err(), "symlinked tmp -> {which}");
        }
        // The database or the key file living inside tmp.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.paths.db = c.paths.tmp.join("db.sqlite");
        assert!(c.validate().unwrap_err().to_string().contains("paths.db"));
        let mut c = tmp_cfg(d.path(), 0o400);
        c.security.totp_key_file = c.paths.tmp.join("key");
        assert!(c.validate().unwrap_err().to_string().contains("key_file"));
    }

    #[test]
    fn valid_config_passes() {
        let d = tempfile::tempdir().unwrap();
        let c = tmp_cfg(d.path(), 0o400);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn sec_042_refuses_group_or_world_readable_key_file() {
        let d = tempfile::tempdir().unwrap();
        for mode in [0o440, 0o404, 0o640, 0o644, 0o604] {
            let c = tmp_cfg(d.path(), mode);
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains("insecure mode"), "mode {mode:o}: {e}");
        }
        for mode in [0o400, 0o600] {
            assert!(tmp_cfg(d.path(), mode).validate().is_ok());
        }
    }

    #[test]
    fn sec_042_key_file_must_be_owned_by_process_uid() {
        let p = Path::new("/run/secrets/k");
        assert!(check_key_owner(p, "k", 10001, Some(10001)).is_ok());
        let e = check_key_owner(p, "k", 0, Some(10001))
            .unwrap_err()
            .to_string();
        assert!(e.contains("owned by uid 0"), "{e}");
        // Where the process uid cannot be determined the check is skipped, not failed.
        assert!(check_key_owner(p, "k", 0, None).is_ok());
        // The real file created by this process passes through load_key_file.
        let d = tempfile::tempdir().unwrap();
        assert!(tmp_cfg(d.path(), 0o400).validate().is_ok());
    }

    #[test]
    fn sec_042_secret_key_has_a_wiping_drop() {
        // Observing freed memory needs unsafe; assert the Drop impl exists instead.
        assert!(std::mem::needs_drop::<SecretKey>());
        let mut b = [9_u8; 4];
        b.zeroize();
        assert_eq!(b, [0; 4]);
    }

    #[test]
    fn sec_042_key_content_never_in_errors_and_length_checked() {
        let d = tempfile::tempdir().unwrap();
        let c = tmp_cfg(d.path(), 0o400);
        let key = &c.security.totp_key_file;
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(key, "c2VjcmV0LXNob3J0\n").unwrap(); // "secret-short"
        let e = load_key_file(key).unwrap_err().to_string();
        assert!(
            !e.contains("c2VjcmV0") && !e.contains("secret-short"),
            "{e}"
        );
        assert!(e.contains("32 bytes"));
        let k = SecretKey([7; 32]);
        assert_eq!(format!("{k:?}"), "SecretKey([REDACTED])");
    }

    #[test]
    fn sec_042_key_file_refuses_symlinks_zero_keys_and_names_the_label_on_bad_base64() {
        let d = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
            p
        };
        // A real file with a non-zero key loads.
        let good = write("good", &B64.encode([7_u8; 32]));
        assert!(load_key_file_as(&good, "k").is_ok());
        // A symlink to it is refused although the target is a valid 0400 file.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let e = load_key_file_as(&link, "my.label").unwrap_err().to_string();
        assert!(e.contains("symbolic link") && e.contains("my.label"), "{e}");
        // All-zero key.
        let zero = write("zero", &B64.encode([0_u8; 32]));
        let e = load_key_file_as(&zero, "k").unwrap_err().to_string();
        assert!(e.contains("all-zero"), "{e}");
        // The label is interpolated in the base64 error (it used to print a literal `{label}`).
        let bad = write("bad", "!!!not base64!!!");
        let e = load_key_file_as(&bad, "security.totp_key_file")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("security.totp_key_file") && !e.contains("{label}"),
            "{e}"
        );
    }

    #[test]
    fn t061_l3_maintenance_defaults_and_bounds() {
        let m = Maintenance::default();
        assert_eq!((m.backup_interval_hours, m.keep_backups), (24, 14));
        assert!(m.validate().is_ok());
        assert!(
            Maintenance {
                backup_interval_hours: 0,
                ..m.clone()
            }
            .validate()
            .is_ok()
        );
        assert!(
            Maintenance {
                keep_backups: 0,
                ..m.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Maintenance {
                backup_interval_hours: 24 * 366 + 1,
                ..m
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn missing_dir_and_limit_ceilings_rejected() {
        let d = tempfile::tempdir().unwrap();
        let mut c = tmp_cfg(d.path(), 0o400);
        c.limits.max_file_bytes = MAX_FILE_BYTES_CEILING + 1;
        assert!(c.validate().is_err());
        c.limits.max_file_bytes = 1;
        c.limits.parse_deadline_secs = PARSE_DEADLINE_CEILING + 1;
        assert!(c.validate().is_err());
        c.limits.parse_deadline_secs = 1;
        c.paths.tmp = d.path().join("missing");
        assert!(c.validate().unwrap_err().to_string().contains("paths.tmp"));
    }

    #[test]
    fn sec_029_upload_budgets_may_only_be_lowered() {
        let d = tempfile::tempdir().unwrap();
        let mut c = tmp_cfg(d.path(), 0o400);
        assert_eq!(c.limits.upload_per_key_per_min, 30);
        assert_eq!(c.limits.upload_per_session_per_min, 30);
        assert!(c.validate().is_ok());
        c.limits.upload_per_key_per_min = 31;
        assert!(c.validate().is_err());
        c.limits.upload_per_key_per_min = 0;
        assert!(c.validate().is_err());
        c.limits.upload_per_key_per_min = 5;
        c.limits.upload_per_session_per_min = 31;
        assert!(c.validate().is_err());
        c.limits.upload_per_session_per_min = 1;
        assert!(c.validate().is_ok());
        c.limits.upload_min_free_percent = 51;
        assert!(c.validate().is_err());
    }

    #[test]
    fn non_loopback_without_proxies_warns() {
        let d = tempfile::tempdir().unwrap();
        let mut c = tmp_cfg(d.path(), 0o400);
        c.server.listen = SocketAddr::from(([0, 0, 0, 0], 8080));
        assert_eq!(c.validate().map(|w| w.len()).ok(), Some(1));
    }

    #[test]
    fn env_overrides_and_unknown_keys() {
        let env = vec![
            ("NZBD__server__listen".to_owned(), "0.0.0.0:9000".to_owned()),
            (
                "NZBD__server__trusted_proxies".to_owned(),
                "[\"10.0.0.2\"]".to_owned(),
            ),
            (
                "NZBD__server__insecure_cookies".to_owned(),
                "true".to_owned(),
            ),
            ("NZBD__limits__max_file_bytes".to_owned(), "1000".to_owned()),
            ("OTHER".to_owned(), "x".to_owned()),
        ];
        let c = Config::load_with_env(None, env).unwrap();
        assert_eq!(c.server.listen.port(), 9000);
        assert_eq!(c.server.trusted_proxies.len(), 1);
        assert!(c.server.insecure_cookies);
        assert_eq!(c.limits.max_file_bytes, 1000);
        let bad = vec![("NZBD__server__bogus".to_owned(), "1".to_owned())];
        assert!(matches!(
            Config::load_with_env(None, bad),
            Err(ConfigError::Parse(_))
        ));
    }

    /// `NZBD_CONFIG_FILE` (single underscore) names the file; it must never be read as a
    /// `NZBD__section__key` override. Unknown keys are refused, so a mis-parse would be an error.
    #[test]
    fn config_file_variable_is_not_an_override() {
        let env = vec![
            (
                "NZBD_CONFIG_FILE".to_owned(),
                "/etc/nzbd/config.toml".to_owned(),
            ),
            ("NZBD_".to_owned(), "x".to_owned()),
            (
                "NZBD__server__insecure_cookies".to_owned(),
                "true".to_owned(),
            ),
        ];
        let c = Config::load_with_env(None, env).unwrap();
        assert!(c.server.insecure_cookies);
        assert_eq!(c.server.listen, Config::default().server.listen);
        // Control: the double-underscore spelling IS an override (of a key that does not exist).
        let bad = vec![("NZBD__CONFIG_FILE".to_owned(), "/x".to_owned())];
        assert!(matches!(
            Config::load_with_env(None, bad),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn t080_store_backend_defaults_to_fs_and_accepts_only_fs_or_db() {
        let load = |v: &str| {
            Config::load_with_env(
                None,
                vec![("NZBD__store__backend".to_owned(), format!("\"{v}\""))],
            )
        };
        assert_eq!(Config::default().store.backend, StoreBackend::Fs);
        assert_eq!(load("fs").unwrap().store.backend, StoreBackend::Fs);
        assert_eq!(load("db").unwrap().store.backend, StoreBackend::Db);
        for bad in ["", "DB", "sqlite", "s3", "fs "] {
            assert!(matches!(load(bad), Err(ConfigError::Parse(_))), "{bad:?}");
        }
        let unknown = vec![("NZBD__store__path".to_owned(), "\"x\"".to_owned())];
        assert!(matches!(
            Config::load_with_env(None, unknown),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn ui_show_xxx_defaults_true_and_parses_from_file_and_env() {
        assert!(Config::default().ui.show_xxx);
        assert!(Config::load_with_env(None, Vec::new()).unwrap().ui.show_xxx);
        let off = vec![("NZBD__ui__show_xxx".to_owned(), "false".to_owned())];
        assert!(!Config::load_with_env(None, off).unwrap().ui.show_xxx);
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("c.toml");
        std::fs::write(&f, "[ui]\nshow_xxx = false\n").unwrap();
        assert!(
            !Config::load_with_env(Some(&f), Vec::new())
                .unwrap()
                .ui
                .show_xxx
        );
        // Env beats the file.
        let on = vec![("NZBD__ui__show_xxx".to_owned(), "true".to_owned())];
        assert!(Config::load_with_env(Some(&f), on).unwrap().ui.show_xxx);
    }

    #[test]
    fn ui_show_xxx_rejects_non_booleans_and_unknown_ui_keys() {
        for bad in ["\"no\"", "1", "yes"] {
            let env = vec![("NZBD__ui__show_xxx".to_owned(), bad.to_owned())];
            assert!(
                matches!(Config::load_with_env(None, env), Err(ConfigError::Parse(_))),
                "{bad}"
            );
        }
        let env = vec![("NZBD__ui__show_xx".to_owned(), "true".to_owned())];
        assert!(matches!(
            Config::load_with_env(None, env),
            Err(ConfigError::Parse(_))
        ));
    }

    /// SEC-101: `db.backend` is a closed set, from the file and from the environment; nothing else is defaulted.
    #[test]
    fn sec_101_unknown_backend_value_is_refused() {
        assert_eq!(Config::default().db.backend, nzb_store::DbBackend::Sqlite);
        let env = |v: &str| vec![("NZBD__db__backend".to_owned(), v.to_owned())];
        assert_eq!(
            Config::load_with_env(None, env("postgres"))
                .unwrap()
                .db
                .backend,
            nzb_store::DbBackend::Postgres
        );
        for bad in [
            "pg",
            "postgresql",
            "Postgres",
            "SQLITE",
            "sqlite3",
            "",
            "mysql",
        ] {
            let e = Config::load_with_env(None, env(bad)).unwrap_err();
            assert!(matches!(e, ConfigError::Parse(_)), "{bad}: {e:?}");
            assert!(e.to_string().contains("UNKNOWN_DB_BACKEND"), "{bad}: {e}");
        }
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("c.toml");
        std::fs::write(&f, "[db]\nbackend = \"postgresql\"\n").unwrap();
        assert!(Config::load_with_env(Some(&f), Vec::new()).is_err());
    }

    /// `backend = "postgres"` needs the connection settings; `store.backend = "db"` is refused in 3.x.
    #[test]
    fn postgres_settings_are_required_and_the_db_blob_backend_is_refused() {
        let mut c = Config::default();
        c.db.backend = nzb_store::DbBackend::Postgres;
        let e = c.db.pg_settings().unwrap_err().to_string();
        assert!(e.contains("DB_HOST_MISSING"), "{e}");
        c.db.host = Some("/run/postgresql".into());
        let e = c.db.pg_settings().unwrap_err().to_string();
        assert!(e.contains("DB_PASSWORD_FILE_MISSING"), "{e}");
        c.db.password_file = Some("/run/secrets/pw".into());
        assert!(c.db.pg_settings().is_ok());
        c.db.host = Some("db.example.org".into());
        assert!(c.db.pg_settings().is_err(), "never a hostname");
        let mut c = Config::default();
        c.store.backend = StoreBackend::Db;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("STORE_DB_BACKEND_REMOVED"), "{e}");
    }

    #[test]
    fn t088_db_startup_check_defaults_to_fast_and_parses_the_three_modes() {
        let load = |v: Option<&str>| {
            let env: Vec<(String, String)> = v
                .map(|v| ("NZBD__db__startup_check".to_owned(), v.to_owned()))
                .into_iter()
                .collect();
            Config::load_with_env(None, env)
        };
        assert_eq!(load(None).unwrap().db.startup_check, StartupCheck::Fast);
        assert_eq!(
            load(Some("fast")).unwrap().db.startup_check,
            StartupCheck::Fast
        );
        assert_eq!(
            load(Some("quick")).unwrap().db.startup_check,
            StartupCheck::Quick
        );
        assert_eq!(
            load(Some("full")).unwrap().db.startup_check,
            StartupCheck::Full
        );
        assert!(matches!(load(Some("off")), Err(ConfigError::Parse(_))));
        assert_eq!(
            nzb_store::StartupCheck::from(StartupCheck::Full),
            nzb_store::StartupCheck::Full
        );
    }

    #[test]
    fn keygen_roundtrip_and_no_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        write_secret_file(&p, &generate_key_b64().unwrap()).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(load_key_file(&p).is_ok());
        assert!(write_secret_file(&p, "x").is_err());
    }

    #[test]
    fn sec_052_backup_key_file_is_validated_like_the_totp_key_and_kept_separate() {
        let d = tempfile::tempdir().unwrap();
        let mk = |name: &str, mode: u32, contents: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, contents).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let good = generate_key_b64().unwrap();
        // Valid, separate key.
        let mut c = tmp_cfg(d.path(), 0o400);
        c.maintenance.backup_encryption_key_file = Some(mk("bk-good", 0o400, &good));
        assert!(c.validate().is_ok());
        // Group/world accessible.
        c.maintenance.backup_encryption_key_file = Some(mk("bk-open", 0o440, &good));
        let e = c.validate().unwrap_err().to_string();
        assert!(
            e.contains("backup_encryption_key_file") && e.contains("insecure mode"),
            "{e}"
        );
        // Not 32 bytes of base64; the content is never echoed.
        c.maintenance.backup_encryption_key_file = Some(mk("bk-short", 0o400, "c2VjcmV0LXNob3J0"));
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("32 bytes") && !e.contains("c2VjcmV0"), "{e}");
        // Same key as the TOTP key: refused.
        let totp_text = std::fs::read_to_string(&c.security.totp_key_file).unwrap();
        c.maintenance.backup_encryption_key_file = Some(mk("bk-same", 0o400, totp_text.trim()));
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("different key"), "{e}");
        // Inside the backups directory: refused.
        let inside = c.paths.backups.join("key");
        std::fs::write(&inside, &good).unwrap();
        std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o400)).unwrap();
        c.maintenance.backup_encryption_key_file = Some(inside);
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("paths.backups"), "{e}");
        // Missing file.
        c.maintenance.backup_encryption_key_file = Some(d.path().join("nope"));
        assert!(c.validate().is_err());
    }
}
