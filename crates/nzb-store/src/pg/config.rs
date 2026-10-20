//! `[db]` settings of v3 and their validation (ARCHITECTURE v3 section 7, `SECURITY_DELTA` 2.1, SEC-086/087).
//!
//! The only outbound connection nzbd ever opens is to the Postgres server named here (D33 d). Everything that could
//! make that connection go somewhere else, or carry extra startup parameters, is refused before a socket is opened:
//! hostnames (no DNS lookup can happen), global IP addresses (review L2), identifiers outside a strict charset (review
//! L1: sqlx writes them NUL-terminated into the startup packet), and any libpq environment variable (sqlx-postgres
//! reads most of them even when every option is set) or certificate-store variable (review M5).

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

/// Pool size bounds `(min, default, max)` per pool (ARCHITECTURE v3 section 4).
pub const POOL_WEB: (u32, u32, u32) = (1, 16, 64);
/// See [`POOL_WEB`].
pub const POOL_INGEST: (u32, u32, u32) = (2, 4, 16);
/// See [`POOL_WEB`].
pub const POOL_BACKGROUND: (u32, u32, u32) = (2, 4, 8);
/// Largest accepted password file (a SCRAM password needs far less).
pub const MAX_PASSWORD_BYTES: u64 = 1024;

/// Environment variables that must not be present in the process (`DB_ENV_AMBIGUOUS`): every libpq variable that
/// sqlx-postgres 0.8 reads, plus the certificate-store variables (no TLS trust input may exist, review M5).
pub const REFUSED_ENV_VARS: [&str; 17] = [
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGAPPNAME",
    "PGOPTIONS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// A refused `[db]` setting. [`PgConfigError::code`] is the stable identifier; messages never contain the password
/// or file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PgConfigError {
    /// `db.host` is neither an absolute socket directory nor an IP literal.
    #[error("db.host must be an absolute socket directory or an IP literal (no hostnames)")]
    HostNotLiteral,
    /// The socket path contains NUL or a `..` component.
    #[error("db.host socket path must not contain NUL or a '..' component")]
    SocketPathInvalid,
    /// The IP literal is not loopback, RFC 1918, RFC 6598 or an IPv6 ULA.
    #[error("db.host must be a loopback, private (RFC 1918/6598) or ULA address")]
    HostNotInternal,
    /// `db.name` or `db.user` does not match `^[a-z_][a-z0-9_]{0,62}$`.
    #[error("{0} must match ^[a-z_][a-z0-9_]{{0,62}}$")]
    IdentifierInvalid(&'static str),
    /// A libpq or certificate-store variable is set (names only, never values).
    #[error("environment variables not allowed with nzbd: {0}")]
    EnvAmbiguous(String),
    /// A pool size or timeout is outside its range.
    #[error("{0} is out of range")]
    OutOfRange(&'static str),
    /// An owner-role secret is readable by the `serve` process (review M4).
    #[error(
        "the database owner secret {0} is readable by this process; it belongs to the setup service only"
    )]
    OwnerSecretVisible(String),
    /// The password file breaks a SEC-042 rule (the reason is a fixed text).
    #[error("db.password_file {path}: {reason}")]
    PasswordFile {
        /// The configured path (operator data, not a secret).
        path: String,
        /// What is wrong.
        reason: &'static str,
    },
}

impl PgConfigError {
    /// Stable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::HostNotLiteral => "DB_HOST_NOT_LITERAL",
            Self::SocketPathInvalid => "DB_SOCKET_PATH_INVALID",
            Self::HostNotInternal => "DB_HOST_NOT_INTERNAL",
            Self::IdentifierInvalid(_) => "DB_IDENTIFIER_INVALID",
            Self::EnvAmbiguous(_) => "DB_ENV_AMBIGUOUS",
            Self::OutOfRange(_) => "DB_SETTING_OUT_OF_RANGE",
            Self::PasswordFile { .. } => "DB_PASSWORD_FILE",
            Self::OwnerSecretVisible(_) => "OWNER_SECRET_VISIBLE",
        }
    }
}

/// Where the server is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgHost {
    /// Absolute directory holding the server's Unix socket (the default and recommended mode).
    Socket(PathBuf),
    /// A loopback, private or ULA address on the internal network (plaintext, no TLS in 3.0).
    Ip(IpAddr),
}

/// Validated `[db]` settings (no password: it is read from [`PgSettings::password_file`] by
/// [`read_password_file`] at connect time and never stored here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgSettings {
    /// Server location.
    pub host: PgHost,
    /// TCP port, or the socket file suffix (`.s.PGSQL.<port>`).
    pub port: u16,
    /// Database name.
    pub name: String,
    /// Login role (`nzbd_app` for `serve` and the CLI).
    pub user: String,
    /// Secret file holding the role password (SEC-042 rules).
    pub password_file: PathBuf,
    /// `web` pool size.
    pub pool_web: u32,
    /// `ingest` pool size.
    pub pool_ingest: u32,
    /// `background` pool size.
    pub pool_background: u32,
    /// Pool acquire timeout (exceeded: uniform `503 BUSY` in the web layer).
    pub acquire_timeout: Duration,
    /// `statement_timeout` of the `web` pool (the other pools use their own fixed values).
    pub statement_timeout: Duration,
}

/// Unvalidated `[db]` values as they come from the config file.
#[derive(Debug, Clone)]
pub struct RawPgSettings<'a> {
    /// `db.host`.
    pub host: &'a str,
    /// `db.port`.
    pub port: u16,
    /// `db.name`.
    pub name: &'a str,
    /// `db.user`.
    pub user: &'a str,
    /// `db.password_file`.
    pub password_file: &'a Path,
    /// `db.pool_web`.
    pub pool_web: u32,
    /// `db.pool_ingest`.
    pub pool_ingest: u32,
    /// `db.pool_background`.
    pub pool_background: u32,
    /// `db.acquire_timeout_ms`.
    pub acquire_timeout_ms: u64,
    /// `db.statement_timeout_ms`.
    pub statement_timeout_ms: u64,
}

impl RawPgSettings<'_> {
    /// Validates every field (SEC-086). Pure: no filesystem or environment access (see [`check_environment`] and
    /// [`read_password_file`]).
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<PgSettings, PgConfigError> {
        let host = parse_host(self.host)?;
        check_identifier(self.name, "db.name")?;
        check_identifier(self.user, "db.user")?;
        if self.port == 0 {
            return Err(PgConfigError::OutOfRange("db.port"));
        }
        let in_range = |v: u32, (lo, _, hi): (u32, u32, u32), name| {
            if (lo..=hi).contains(&v) {
                Ok(v)
            } else {
                Err(PgConfigError::OutOfRange(name))
            }
        };
        if !(100..=60_000).contains(&self.acquire_timeout_ms) {
            return Err(PgConfigError::OutOfRange("db.acquire_timeout_ms"));
        }
        if !(100..=600_000).contains(&self.statement_timeout_ms) {
            return Err(PgConfigError::OutOfRange("db.statement_timeout_ms"));
        }
        Ok(PgSettings {
            host,
            port: self.port,
            name: self.name.to_owned(),
            user: self.user.to_owned(),
            password_file: self.password_file.to_path_buf(),
            pool_web: in_range(self.pool_web, POOL_WEB, "db.pool_web")?,
            pool_ingest: in_range(self.pool_ingest, POOL_INGEST, "db.pool_ingest")?,
            pool_background: in_range(self.pool_background, POOL_BACKGROUND, "db.pool_background")?,
            acquire_timeout: Duration::from_millis(self.acquire_timeout_ms),
            statement_timeout: Duration::from_millis(self.statement_timeout_ms),
        })
    }
}

/// `db.host`: an absolute socket directory (no NUL, no `..`) or an internal IP literal. Never a hostname.
///
/// # Errors
/// [`PgConfigError::HostNotLiteral`], [`PgConfigError::SocketPathInvalid`], [`PgConfigError::HostNotInternal`].
pub fn parse_host(host: &str) -> Result<PgHost, PgConfigError> {
    if host.starts_with('/') {
        let p = Path::new(host);
        if host.contains('\0') || p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(PgConfigError::SocketPathInvalid);
        }
        return Ok(PgHost::Socket(p.to_path_buf()));
    }
    let ip: IpAddr = host.parse().map_err(|_| PgConfigError::HostNotLiteral)?;
    if ip_is_internal(ip) {
        Ok(PgHost::Ip(ip))
    } else {
        Err(PgConfigError::HostNotInternal)
    }
}

/// Loopback, RFC 1918, RFC 6598 (100.64/10), IPv6 loopback or ULA (`fc00::/7`). Everything else, including
/// unspecified, multicast, broadcast, link-local and IPv4-mapped addresses, is refused (review L2).
#[must_use]
pub fn ip_is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_internal(v4),
        IpAddr::V6(v6) => v6_is_internal(v6),
    }
}

fn v4_is_internal(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    let shared = a == 100 && (64..=127).contains(&b); // RFC 6598
    (ip.is_loopback() || ip.is_private() || shared)
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
}

fn v6_is_internal(ip: Ipv6Addr) -> bool {
    let first = ip.segments().first().copied().unwrap_or(0);
    ip.is_loopback() || (first & 0xfe00) == 0xfc00
}

/// `^[a-z_][a-z0-9_]{0,62}$` (review L1).
///
/// # Errors
/// [`PgConfigError::IdentifierInvalid`] naming the setting.
pub fn check_identifier(v: &str, setting: &'static str) -> Result<(), PgConfigError> {
    let mut bytes = v.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_');
    let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if first_ok && rest_ok && v.len() <= 63 {
        Ok(())
    } else {
        Err(PgConfigError::IdentifierInvalid(setting))
    }
}

/// Refuses to run when any [`REFUSED_ENV_VARS`] entry is present (even empty). Takes the environment as an iterator
/// so tests need no process-global mutation; production passes `std::env::vars_os()`.
///
/// # Errors
/// [`PgConfigError::EnvAmbiguous`] listing the variable NAMES found (values are never read or printed).
pub fn check_environment(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), PgConfigError> {
    let mut found: Vec<&'static str> = vars
        .into_iter()
        .filter_map(|(k, _)| REFUSED_ENV_VARS.iter().copied().find(|r| k == **r))
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    found.sort_unstable();
    found.dedup();
    Err(PgConfigError::EnvAmbiguous(found.join(",")))
}

/// Reads a database password file under the SEC-042 rules: not a symbolic link, a regular file, no group/other
/// permission bits, owned by the process's effective uid, at most [`MAX_PASSWORD_BYTES`], UTF-8,
/// no NUL or line break inside, not empty. One trailing newline is removed. The value is returned in a zeroizing
/// buffer and never appears in an error.
///
/// # Errors
/// [`PgConfigError::PasswordFile`] with a fixed reason.
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>, PgConfigError> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let err = |reason: &'static str| PgConfigError::PasswordFile {
        path: path.display().to_string(),
        reason,
    };
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(err("is a symbolic link"));
    }
    // Opened `O_NOFOLLOW|O_NONBLOCK` and checked through the descriptor (review 31 I4, like the 2.x key reader): a
    // swap of the path between the check and the read cannot substitute another file, and a FIFO cannot block.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                err("is a symbolic link")
            } else {
                err("not readable")
            }
        })?;
    let link = f.metadata().map_err(|_| err("not readable"))?;
    if !link.is_file() {
        return Err(err("is not a regular file"));
    }
    if link.permissions().mode() & 0o077 != 0 {
        return Err(err("has group/other permissions; require 0400"));
    }
    // The effective uid from the kernel, not the owner of `/proc/self` (root once nzbd is non-dumpable, review 44 M1).
    if rustix::process::geteuid().as_raw() != link.uid() {
        return Err(err("is not owned by the process uid"));
    }
    if link.len() > MAX_PASSWORD_BYTES {
        return Err(err("is too large"));
    }
    let mut raw = Zeroizing::new(Vec::new());
    (&mut f)
        .take(MAX_PASSWORD_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|_| err("not readable"))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_PASSWORD_BYTES {
        return Err(err("is too large"));
    }
    let text = std::str::from_utf8(&raw).map_err(|_| err("is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() {
        return Err(err("is empty"));
    }
    if text.contains(['\0', '\n', '\r']) {
        return Err(err("holds a NUL or line break"));
    }
    Ok(Zeroizing::new(text.to_owned()))
}

/// The documented location of the owner secret in the `setup` service (ARCHITECTURE v3 section 7).
pub const OWNER_SECRET_PATH: &str = "/run/setup-secrets/nzbd_db_owner_password";

/// `serve` refuses to start when an owner secret is readable by the service uid (review M4, SEC-087): the owner
/// credential is mounted only into the one-shot `setup` service. Checks the documented path plus any extra paths
/// (an `--owner-password-file` found in the environment). Absent or unreadable files are fine.
///
/// # Errors
/// [`PgConfigError::OwnerSecretVisible`] naming the path (never its content).
pub fn refuse_readable_owner_secret(extra: &[&Path]) -> Result<(), PgConfigError> {
    for p in std::iter::once(Path::new(OWNER_SECRET_PATH)).chain(extra.iter().copied()) {
        if std::fs::File::open(p).is_ok() {
            return Err(PgConfigError::OwnerSecretVisible(p.display().to_string()));
        }
    }
    Ok(())
}
