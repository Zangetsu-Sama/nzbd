//! `nzbd audit export [--since T] [--verify]` and `nzbd audit verify` (T105; SEC-080..082, `DATA_MODEL` "Audit hash
//! chain", RUNBOOK "Audit export and verification").
//!
//! Output contract:
//!
//! * **stdout** carries only the rows, one JSON object per line, **pure ASCII**: every character outside printable
//!   ASCII is written as a `\uXXXX` escape, so a hostile value (a user name, an NZB-derived label, an `X-Forwarded-For`
//!   remnant) can neither forge another line, nor smuggle terminal control sequences or bidirectional overrides into
//!   an operator's terminal or a log viewer;
//! * long opaque tokens in free-text columns are replaced by `[redacted]` (belt and braces: audit details are written
//!   without secrets by construction, SEC-033);
//! * **stderr** carries one summary line of the verification;
//! * exit code 0 = exported and (with `--verify`) the chain is intact, 2 = the chain is broken (first broken id on
//!   stderr), 1 = any other error (bad arguments, database unreadable, chain not bootstrapped yet).
//!
//! The database is opened read-only, so the command never changes anything and is safe next to a running server.

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

use clap::Subcommand;
use nzb_store::{AuditExportRow, ChainBreak, ChainReport};

use crate::config::Config;

/// `nzbd audit <action>`.
#[derive(Subcommand)]
pub enum AuditAction {
    /// Export audit rows as JSON Lines (ASCII only) on stdout. With `--verify` the whole hash chain is verified too
    /// (always the whole chain, not only the exported part) and a summary goes to stderr. Exit code 0 = ok,
    /// 2 = chain broken, 1 = error.
    Export {
        /// Only rows at or after this time: unix seconds, `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ` (UTC).
        #[arg(long)]
        since: Option<String>,
        /// Verify the hash chain and fail with exit code 2 when it is broken.
        #[arg(long)]
        verify: bool,
        /// Run even as root (see `nzbd db check --allow-root`).
        #[arg(long)]
        allow_root: bool,
    },
    /// Verify the hash chain without exporting rows. Exit code 0 = ok, 2 = broken, 1 = error.
    Verify {
        /// Run even as root (see `nzbd db check --allow-root`).
        #[arg(long)]
        allow_root: bool,
    },
}

/// Logs the recorded chain heads (T105 M1): `head_log`, `head_account`, `rows`. They are hashes and a count, no
/// secret. Called at startup, after every backup and after every purge so the container log (and whatever ships it off
/// the host) holds an anchor an attacker with write access to the database file cannot rewrite. `when` is a fixed
/// word. A failure is logged and never stops the caller.
pub async fn log_anchor(db: &nzb_store::Store, when: &'static str) {
    match db.audit_anchor().await {
        Ok(a) => tracing::info!(
            when,
            head_log = %hex(&a.head_log),
            head_account = %hex(&a.head_account),
            rows = a.rows,
            "audit chain anchor"
        ),
        Err(e) => tracing::warn!(when, error = %e, "audit chain anchor unavailable"),
    }
}

/// Runs an `nzbd audit` action.
///
/// # Errors
/// Bad arguments, an unreadable database, or a chain that has not been bootstrapped yet.
pub fn run_audit(cfg: &Config, action: &AuditAction) -> Result<ExitCode, String> {
    let (since, export, verify, allow_root) = match action {
        AuditAction::Export {
            since,
            verify,
            allow_root,
        } => (
            since.as_deref().map(parse_since).transpose()?,
            true,
            *verify,
            *allow_root,
        ),
        AuditAction::Verify { allow_root } => (None, false, true, *allow_root),
    };
    if !allow_root && crate::dbcheck::running_as_root() {
        return Err("refusing to run as root: opening the database can create root-owned -wal/-shm files the \
                    service user cannot write. Run it as the service user, e.g. `docker compose exec nzbd /nzbd \
                    audit verify`, or pass --allow-root if the server is stopped"
            .to_owned());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = crate::dbopen::open_read_only(cfg)
            .await
            .map_err(|e| format!("database: {e}"))?;
        let mut stdout_broken = false;
        let res = db
            .audit_walk(since, &mut |row| {
                if export && !stdout_broken {
                    let line = row_json(row);
                    let mut out = std::io::stdout().lock();
                    if writeln!(out, "{line}").is_err() {
                        stdout_broken = true;
                    }
                }
            })
            .await;
        db.close().await;
        let report = res.map_err(|e| format!("audit: {e}"))?;
        if stdout_broken {
            return Err("cannot write to standard output".to_owned());
        }
        if verify {
            eprintln!("{}", summary(&report));
            if !report.is_ok() {
                return Ok(ExitCode::from(2));
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// The one-line verdict (stable identifiers, no row content).
#[must_use]
pub fn summary(r: &ChainReport) -> String {
    let [head_log, head_account] = r.heads;
    match r.first_break {
        None => format!(
            "audit chain OK: rows={} head_log={} head_account={}",
            r.rows,
            hex(&head_log),
            hex(&head_account)
        ),
        Some(ChainBreak { id, kind }) => format!(
            "audit chain BROKEN: first_broken_id={id} kind={} problems={} rows={}",
            kind.code(),
            r.breaks,
            r.rows
        ),
    }
}

/// Lowercase hex.
#[must_use]
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Parses `--since`: unix seconds, `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ`.
///
/// # Errors
/// A fixed message when the value is none of these.
#[allow(clippy::many_single_char_names)] // y/m/d/h are the calendar fields
pub fn parse_since(s: &str) -> Result<i64, String> {
    let bad = || "--since: expected unix seconds, YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ".to_owned();
    if let Ok(n) = s.parse::<i64>() {
        return if n >= 0 { Ok(n) } else { Err(bad()) };
    }
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut it = date.split('-');
    let (Some(y), Some(m), Some(d), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(bad());
    };
    let (y, m, d): (i64, i64, i64) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=days_in_month(y, m)).contains(&d)
    {
        return Err(bad());
    }
    let secs = match time {
        None => 0,
        Some(t) => {
            let t = t.strip_suffix('Z').ok_or_else(bad)?;
            let mut it = t.split(':');
            let (Some(h), Some(mi), Some(se), None) = (it.next(), it.next(), it.next(), it.next())
            else {
                return Err(bad());
            };
            let (h, mi, se): (i64, i64, i64) = (
                h.parse().map_err(|_| bad())?,
                mi.parse().map_err(|_| bad())?,
                se.parse().map_err(|_| bad())?,
            );
            if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&se) {
                return Err(bad());
            }
            h * 3600 + mi * 60 + se
        }
    };
    Ok(days_from_civil(y, m, d) * 86_400 + secs)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Howard Hinnant's `days_from_civil` (inputs range-checked by the caller).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Minimum length of a run of token characters that is treated as a secret-looking value and redacted.
const TOKEN_RUN: usize = 32;

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// Replaces every run of at least [`TOKEN_RUN`] token characters (base64/base32/hex-looking values: keys, codes,
/// hashes) with `[redacted]`.
#[must_use]
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |out: &mut String, run: &mut String| {
        if run.chars().count() >= TOKEN_RUN {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if is_token_char(c) {
            run.push(c);
        } else {
            flush(&mut out, &mut run);
            out.push(c);
        }
    }
    flush(&mut out, &mut run);
    out
}

/// JSON string literal, ASCII only: `"`, `\` and everything outside `0x20..=0x7e` are escaped (non-BMP characters as
/// surrogate pairs), so no input can break out of the line or reach a terminal as a control sequence.
#[must_use]
pub fn json_string(s: &str) -> String {
    let mut o = String::with_capacity(s.len().saturating_add(2));
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            ' '..='~' => o.push(c),
            _ => {
                let mut buf = [0_u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(o, "\\u{u:04x}");
                }
            }
        }
    }
    o.push('"');
    o
}

fn opt_text(v: Option<&str>, redact_it: bool) -> String {
    match v {
        None => "null".to_owned(),
        Some(s) if redact_it => json_string(&redact(s)),
        Some(s) => json_string(s),
    }
}

fn opt_int(v: Option<i64>) -> String {
    v.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

/// One export line (no trailing newline).
#[must_use]
pub fn row_json(r: &AuditExportRow) -> String {
    let class = match r.chain_class {
        Some(0) => "log",
        Some(1) => "account",
        _ => "none",
    };
    format!(
        "{{\"id\":{},\"ts\":{},\"actor\":{},\"event\":{},\"detail\":{},\"ip\":{},\"actor_id\":{},\"actor_kind\":{},\
         \"actor_role\":{},\"target_id\":{},\"chain\":\"{class}\",\"hash\":{}}}",
        r.id,
        r.ts,
        opt_text(r.actor.as_deref(), true),
        json_string(&redact(&r.event)),
        opt_text(r.detail.as_deref(), true),
        opt_text(r.ip.as_deref(), true),
        opt_int(r.actor_id),
        opt_text(r.actor_kind.as_deref(), false),
        opt_text(r.actor_role.as_deref(), false),
        opt_int(r.target_id),
        r.chain_hash
            .map_or_else(|| "null".to_owned(), |h| format!("\"{}\"", hex(&h))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(detail: &str) -> AuditExportRow {
        AuditExportRow {
            id: 7,
            ts: 1_700_000_000,
            actor: Some("alice".into()),
            event: "download".into(),
            detail: Some(detail.into()),
            ip: Some("192.0.2.1".into()),
            actor_id: Some(1),
            actor_kind: Some("user".into()),
            actor_role: Some("uploader".into()),
            target_id: None,
            chain_class: Some(0),
            chain_hash: Some([0xab; 32]),
        }
    }

    #[test]
    fn sec_082_hostile_values_cannot_break_the_line_or_reach_a_terminal() {
        let hostile = "x\"}\n{\"id\":99,\"event\":\"forged\"}\r\u{1b}[2J\u{202e}\u{2028}\u{0}\u{7f}\u{1f600}é\\";
        let line = row_json(&row(hostile));
        assert!(line.is_ascii(), "{line}");
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        // Still one well-formed object: quotes are balanced outside escapes.
        let mut in_str = false;
        let mut esc = false;
        for c in line.chars() {
            if esc {
                esc = false;
            } else if c == '\\' && in_str {
                esc = true;
            } else if c == '"' {
                in_str = !in_str;
            }
        }
        assert!(!in_str, "{line}");
        assert!(line.starts_with("{\"id\":7,") && line.ends_with('}'));
        // The astral character is a surrogate pair.
        assert!(line.contains("\\ud83d\\ude00"), "{line}");
        assert!(line.contains("\\u202e") && line.contains("\\u2028") && line.contains("\\u001b"));
    }

    #[test]
    fn sec_082_secret_looking_tokens_are_redacted_in_exports() {
        let key = "A".repeat(52); // an invite/recovery code or API key shape
        let b64 = "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq83=";
        let line = row_json(&row(&format!(
            "code={key} key={b64} prefix=abcdef sha8=deadbeef"
        )));
        assert!(!line.contains(&key) && !line.contains(b64), "{line}");
        assert!(line.contains("[redacted]"));
        assert!(line.contains("prefix=abcdef") && line.contains("sha8=deadbeef"));
        // The chain hash column is a hash, never redacted.
        assert!(line.contains(&"ab".repeat(32)));
    }

    #[test]
    fn since_accepts_unix_date_and_datetime() {
        assert_eq!(parse_since("1700000000"), Ok(1_700_000_000));
        assert_eq!(parse_since("1970-01-02"), Ok(86_400));
        assert_eq!(parse_since("2023-11-14T22:13:20Z"), Ok(1_700_000_000));
        for bad in [
            "",
            "yesterday",
            "2023-13-01",
            "2023-11-14T25:00:00Z",
            "2023-11-14T10:00:00",
            "-5",
            "2023-11",
        ] {
            assert!(parse_since(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn summary_names_the_first_broken_id_only() {
        let ok = ChainReport {
            rows: 3,
            heads: [[1; 32], [2; 32]],
            breaks: 0,
            first_break: None,
        };
        assert!(summary(&ok).starts_with("audit chain OK: rows=3 "));
        let bad = ChainReport {
            first_break: Some(ChainBreak {
                id: 42,
                kind: nzb_store::ChainBreakKind::Gap,
            }),
            breaks: 2,
            ..ok
        };
        assert_eq!(
            summary(&bad),
            "audit chain BROKEN: first_broken_id=42 kind=gap problems=2 rows=3"
        );
    }
}

#[cfg(test)]
mod calendar_tests {
    use super::parse_since;

    #[test]
    fn since_rejects_days_outside_their_month() {
        for date in [
            "2026-04-31",
            "2026-06-31",
            "2026-09-31",
            "2026-11-31",
            "2024-02-30",
            "2024-02-31",
        ] {
            for value in [date.to_owned(), format!("{date}T12:34:56Z")] {
                assert!(
                    parse_since(&value).is_err(),
                    "impossible calendar date was accepted: {value}"
                );
            }
        }
    }

    #[test]
    fn since_rejects_non_leap_february_29() {
        for year in [2023, 1970, 2001, 2100, 2200, 2300, 9999] {
            let date = format!("{year}-02-29");
            for value in [date.clone(), format!("{date}T23:59:59Z")] {
                assert!(
                    parse_since(&value).is_err(),
                    "non-leap February 29 was accepted: {value}"
                );
            }
        }
    }

    #[test]
    fn since_preserves_valid_dates_times_and_unix_seconds() {
        for (value, expected) in [
            ("0", 0),
            ("1700000000", 1_700_000_000),
            ("9223372036854775807", i64::MAX),
            ("1970-01-01", 0),
            ("1970-01-01T00:00:01Z", 1),
            ("2000-02-29", 951_782_400),
            ("2024-02-29", 1_709_164_800),
            ("2100-02-28", 4_107_456_000),
            ("2100-03-01", 4_107_542_400),
            ("2400-02-29", 13_574_563_200),
            ("9999-12-31T23:59:59Z", 253_402_300_799),
        ] {
            assert_eq!(parse_since(value), Ok(expected), "{value}");
        }
        for date in [
            "2026-01-31",
            "2026-02-28",
            "2026-03-31",
            "2026-04-30",
            "2026-05-31",
            "2026-06-30",
            "2026-07-31",
            "2026-08-31",
            "2026-09-30",
            "2026-10-31",
            "2026-11-30",
            "2026-12-31",
        ] {
            assert!(parse_since(date).is_ok(), "{date}");
            let timestamp = format!("{date}T23:59:59Z");
            assert!(parse_since(&timestamp).is_ok(), "{timestamp}");
        }
        for invalid in [
            "-1",
            "9223372036854775808",
            "1969-12-31",
            "10000-01-01",
            "2026-01-00",
            "2026-00-01",
            "2026-13-01",
            "2024-02-29T24:00:00Z",
            "2024-02-29T23:60:00Z",
            "2024-02-29T23:59:60Z",
            "2024-02-29T23:59:59",
        ] {
            assert!(parse_since(invalid).is_err(), "{invalid}");
        }
    }
}
