//! SEC-104: both backends are proven equal, on runtime test names (review 34 M4).
//!
//! * [`sec_104_both_backend_names_are_present`] lists the tests compiled into this binary (it re-runs itself with
//!   `--list`, so `cfg`-dropped or renamed tests are seen as they really are) and requires every SEC test of a paired
//!   suite to exist on the other backend too: `<suite>_tests::<name>` with `pg_<suite>_tests::<name>`, and the seam
//!   suite's `sqlite::<name>` with `postgres::<name>`. Names that are backend-specific by design are listed with a
//!   reason in `scripts/sec_backend_specific.list`; a stale entry fails as well. The web, ingest and nzbd binaries are
//!   one suite run once per CI leg; `scripts/ci.sh` compares their lists across the legs.
//! * [`sec_104_postgres_leg_opened_postgres`] proves the leg's harness opened the backend the leg names (on the
//!   Postgres leg: a `pg_stat_activity` row of an nzbd pool on the test database).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::DbBackend;
use crate::test_backend::{TestStore, sql, test_backend};

/// The test paths compiled into this binary.
fn compiled_tests() -> BTreeSet<String> {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--list", "--format", "terse"])
        .env_remove("RUST_TEST_THREADS")
        .output()
        .unwrap();
    assert!(out.status.success(), "listing the tests failed");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(str::to_owned)
        .collect()
}

fn is_sec(path: &str) -> bool {
    let name = path.rsplit("::").next().unwrap_or_default();
    name.len() > 8
        && name.starts_with("sec_")
        && name.as_bytes()[4..7].iter().all(u8::is_ascii_digit)
}

/// The other backend's path of `path`, when `path` belongs to a paired suite.
fn counterpart(path: &str, all_modules: &BTreeSet<String>) -> Option<String> {
    let parts: Vec<&str> = path.split("::").collect();
    if let Some(i) = parts
        .iter()
        .position(|p| *p == "sqlite" || *p == "postgres")
    {
        let mut v = parts.clone();
        v[i] = if parts[i] == "sqlite" {
            "postgres"
        } else {
            "sqlite"
        };
        return Some(v.join("::"));
    }
    let first = parts[0];
    let other = match first.strip_prefix("pg_") {
        Some(rest) => rest.to_owned(),
        None => format!("pg_{first}"),
    };
    // A suite is paired when the other module exists (`pg_tests` and `pg_sec_tests` have no SQLite twin: every name
    // in them is backend-specific and must be listed).
    let paired = all_modules.contains(&other) || first.starts_with("pg_");
    if !paired || !first.ends_with("tests") {
        return None;
    }
    let mut v = parts;
    v[0] = &other;
    Some(v.join("::"))
}

/// `scripts/sec_backend_specific.list`: path -> (backend, reason).
fn specific_list() -> BTreeMap<String, (String, String)> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sec_backend_specific.list");
    let text = std::fs::read_to_string(&p).unwrap();
    let mut m = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        let (Some(path), Some(backend), Some(reason)) = (it.next(), it.next(), it.next()) else {
            panic!("line {}: want `<path> <backend> <reason>`: {line}", n + 1);
        };
        assert!(
            ["sqlite", "postgres", "none"].contains(&backend),
            "line {}: backend must be sqlite|postgres|none: {line}",
            n + 1
        );
        assert!(!reason.trim().is_empty(), "line {}: no reason", n + 1);
        assert!(
            m.insert(path.to_owned(), (backend.to_owned(), reason.to_owned()))
                .is_none(),
            "line {}: duplicate entry {path}",
            n + 1
        );
    }
    m
}

#[test]
fn sec_104_both_backend_names_are_present() {
    let tests = compiled_tests();
    assert!(
        tests.len() > 100,
        "the listing found only {} tests",
        tests.len()
    );
    let modules: BTreeSet<String> = tests
        .iter()
        .filter_map(|t| t.split("::").next().map(str::to_owned))
        .collect();
    let listed = specific_list();
    let mut missing = Vec::new();
    let mut unpaired = BTreeSet::new();
    for t in tests.iter().filter(|t| is_sec(t)) {
        if let Some(other) = counterpart(t, &modules)
            && !tests.contains(&other)
        {
            unpaired.insert(t.clone());
            if !listed.contains_key(t) {
                missing.push(format!("{t} (no {other})"));
            }
        }
    }
    let stale: Vec<&String> = listed.keys().filter(|k| !unpaired.contains(*k)).collect();
    assert!(
        missing.is_empty(),
        "SEC tests that run on one backend only; add the other backend's test or list the name with a reason in \
         scripts/sec_backend_specific.list:\n{}",
        missing.join("\n")
    );
    assert!(
        stale.is_empty(),
        "stale entries in scripts/sec_backend_specific.list (the test has a counterpart now, or no longer exists): \
         {stale:?}"
    );
    // The seam suite really is instantiated on both backends.
    assert!(tests.iter().any(|t| t.starts_with("seam_tests::sqlite::")));
    assert!(
        tests
            .iter()
            .any(|t| t.starts_with("seam_tests::postgres::"))
    );
}

#[tokio::test]
async fn sec_104_postgres_leg_opened_postgres() {
    let dir = tempfile::tempdir().unwrap();
    let leg = test_backend();
    let t = TestStore::open(dir.path()).await;
    assert_eq!(
        t.backend(),
        leg,
        "the harness opened another backend than the leg names"
    );
    match leg {
        DbBackend::Sqlite => {
            assert!(t.pg().is_none());
            assert!(dir.path().join("t.sqlite").is_file());
        }
        DbBackend::Postgres => {
            // A session of an nzbd pool (fixed `application_name`, never the harness's `nzbd-test`) on this test's
            // own database: the queries of the leg really reach the server.
            let n = sql::i64(
                &t.store,
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
                 AND application_name IN ('nzbd-web', 'nzbd-ingest', 'nzbd-background')",
            )
            .await;
            assert!(n >= 1, "no nzbd session on the test database");
        }
    }
}

/// Test code of the web, ingest and nzbd crates that may open a backend directly instead of through
/// [`TestStore`], each with its reason (review 35 M1 c). Paths are relative to the workspace root.
const DIRECT_OPEN_ALLOWED: [(&str, &str); 4] = [
    (
        "crates/nzbd/src/dbcheck.rs",
        "t088_db_check_exit_codes_for_every_mode: `nzbd db check` modes of a SQLite file (quick/full/damaged bytes)",
    ),
    (
        "crates/nzbd/src/library.rs",
        "sec_101_*: the library identity rule needs a SQLite and a Postgres library side by side in one test",
    ),
    (
        "crates/nzbd/src/dbopen.rs",
        "upkeep_regressions: PostgreSQL-only startup partition routing, tableoid and owner/app permissions require TestDb",
    ),
    (
        "crates/nzbd/src/maintenance.rs",
        "upkeep_regressions: PostgreSQL-only monthly partition upkeep and permission failure require TestDb; ordinary maintenance tests still use TestStore",
    ),
];

/// Calls that open a backend without the leg's harness (a `Store::Sqlite(..)` needs one of the SQLite opens).
const DIRECT_OPENS: [&str; 6] = [
    "Store::open_sqlite(",
    "SqliteDb::open(",
    "SqliteDb::open_with(",
    "SqliteDb::open_read_only(",
    "PgDb::connect(",
    "TestDb::new(",
];

/// The test-code part of a source file: a whole test file, or what follows `#[cfg(test)]` in a module file.
fn test_part(path: &Path, src: &str) -> Option<String> {
    let s = path.to_string_lossy();
    let name = path.file_name()?.to_string_lossy().into_owned();
    if s.contains("/tests/") || name.ends_with("_tests.rs") || name == "tests.rs" {
        return Some(src.to_owned());
    }
    src.find("#[cfg(test)]").map(|i| src[i..].to_owned())
}

/// SEC-104 / review 35 M1 (c): the web, ingest and nzbd suites run on the leg's backend, so their test code opens a
/// library only through `nzb_store::test_backend::TestStore` (and the nzbd binary through `config_db_section`). A
/// direct `open_sqlite` or Postgres connect there would silently run one backend on both legs; it fails here
/// unless the file is in [`DIRECT_OPEN_ALLOWED`] with a reason.
#[test]
fn sec_104_harness_test_code_opens_the_leg_backend_only() {
    fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "fixtures") {
                    continue;
                }
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for c in ["nzb-web", "nzb-ingest", "nzbd"] {
        for d in ["src", "tests"] {
            rs_files(&root.join("crates").join(c).join(d), &mut files);
        }
    }
    assert!(files.len() > 50, "scan found {} files", files.len());
    let mut bad = Vec::new();
    let mut allowed_hit = BTreeSet::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let src = std::fs::read_to_string(f).unwrap();
        let Some(test) = test_part(f, &src) else {
            continue;
        };
        for call in DIRECT_OPENS {
            if test.contains(call) {
                if DIRECT_OPEN_ALLOWED.iter().any(|(p, _)| *p == rel) {
                    allowed_hit.insert(rel.clone());
                } else {
                    bad.push(format!("{rel}: {call}"));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "test code opens a backend directly; use nzb_store::test_backend::TestStore (or list the file with a \
         reason in DIRECT_OPEN_ALLOWED):\n{}",
        bad.join("\n")
    );
    for (p, why) in DIRECT_OPEN_ALLOWED {
        assert!(
            allowed_hit.contains(p),
            "stale DIRECT_OPEN_ALLOWED entry {p} ({why})"
        );
    }
}
