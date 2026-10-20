//! Unit tests of the health engine: thresholds with injected inputs, gathering against a
//! temporary directory tree (hostile names included), no-secret/no-path guarantees and the
//! CLI exit codes.

use std::os::unix::fs::PermissionsExt;

use nzb_web::health::{Status, Summary};

use super::*;

const NOW: i64 = 1_800_000_000;

fn find<'a>(v: &'a [Check], name: &str) -> &'a Check {
    v.iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no check named {name}"))
}

fn dir(name: &'static str) -> DirFacts {
    DirFacts {
        name,
        exists: true,
        is_dir: true,
        writable: Some(true),
        free: Some((50 << 30, 100 << 30)),
    }
}

fn cfg_facts() -> CfgFacts {
    CfgFacts {
        workers: 2,
        queue_cap: 1024,
        lag_warn_secs: 60,
        scan_interval: 5,
        atomic_moves: true,
        recursive: false,
        insecure_cookies: false,
        loopback: true,
        has_proxies: false,
        allowed_hosts: 0,
        multi_user: false,
    }
}

#[allow(clippy::too_many_lines)] // one literal fixture
fn good_inputs() -> Inputs {
    Inputs {
        now: NOW,
        uptime: Some(7200),
        live: Some(LiveFacts {
            heartbeat: Some(NOW - 2),
            ok: 5,
            duplicates: 1,
            failed: 0,
            last_success: Some(NOW - 60),
            commit_groups: 2,
            inflight_bytes: 0,
            lag_paused: false,
        }),
        dev_tools: false,
        debug_build: false,
        cfg: cfg_facts(),
        proc: ProcFacts {
            rss_kib: Some(80_000),
            open_fds: Some(40),
            fd_limit: Some(1024),
        },
        db: Some(DbFacts {
            writer_ok: true,
            reader_ok: true,
            schema: Some(SchemaInfo {
                latest_applied: 6,
                applied: 6,
                embedded_latest: 6,
                embedded: 6,
            }),
            totals: Some(ReleaseTotals {
                releases: 10,
                files: 100,
                segments: 1000,
                bytes: 1 << 30,
            }),
            logs: Some(LogCounts {
                ingest_rows: 12,
                audit_rows: 30,
                ingest_oldest: Some(NOW - 1000),
                ingest_newest: Some(NOW - 60),
            }),
            pools: PoolInfo {
                writer_open: 1,
                readers_open: 2,
                readers_idle: 2,
                readers_max: 4,
                closed: false,
            },
            security: Some(SecurityFacts {
                user_exists: true,
                totp_enabled: true,
                failed_logins: 0,
                locked: false,
                active_sessions: 1,
                active_api_keys: 1,
                failed_logins_recent: 0,
                live_accounts: 1,
                reserved_names: 0,
                throttled_accounts: 0,
            }),
            last_ok_ingest: Some(NOW - 60),
            audit_chain: Some(nzb_store::ChainQuick {
                rows: 30,
                unchained: 0,
                consistent: true,
                bootstrapped: true,
            }),
            outbox: Some(nzb_store::OutboxLag::default()),
        }),
        fs: FsFacts {
            dirs: vec![
                dir("Watch folder"),
                dir("Blob store"),
                dir("Failed folder"),
                dir("Duplicates folder"),
                dir("Upload staging folder"),
                dir("Backups folder"),
                dir("Database folder"),
            ],
            db_bytes: Some(1 << 20),
            wal_bytes: Some(0),
            same_fs: Some(true),
            layout_ok: true,
            anchor_same_fs: false,
            key_ok: true,
            waiting: Ok(Count {
                n: 0,
                capped: false,
            }),
            failed: Ok(Count {
                n: 0,
                capped: false,
            }),
            duplicates: Ok(Count {
                n: 2,
                capped: false,
            }),
            leftovers: 0,
            gc_trash: Some(0),
            backups: Ok((Some(NOW - 3600), 3)),
        },
        recovery: Some(RecoverySummary::default()),
        deep: None,
        http_probe: None,
    }
}

#[test]
fn all_good_inputs_give_exit_code_zero() {
    let v = build(&good_inputs());
    let s = Summary::of(&v);
    assert_eq!((s.warnings, s.failures), (0, 0), "{v:#?}");
    assert_eq!(s.exit_code(), 0);
    assert!(render_text(&v).contains("ALL OK"));
}

#[test]
fn a_warning_gives_one_and_a_failure_gives_two() {
    let mut i = good_inputs();
    i.fs.backups = Ok((None, 0));
    let v = build(&i);
    assert_eq!(Summary::of(&v).exit_code(), 1);
    assert_eq!(find(&v, "Database backups").status, Status::Warn);
    i.fs.key_ok = false;
    let v = build(&i);
    assert_eq!(Summary::of(&v).exit_code(), 2);
    let text = render_text(&v);
    assert!(text.contains("FAIL") && text.contains("failure(s)"));
}

/// T114: the index lag line (ARCHITECTURE v3 3.2): OK while the oldest pending change is younger than
/// `search.lag_warn_secs`, WARN past it, WARN while the scanner is paused for the lag, WARN when unreadable.
#[test]
fn t114_index_lag_line_warns_past_the_threshold_and_while_paused() {
    let mut i = good_inputs();
    let v = build(&i);
    let c = find(&v, "Search index lag");
    assert_eq!((c.status, c.value.as_str()), (Status::Ok, "up to date"));
    let d = i.db.as_mut().unwrap();
    d.outbox = Some(nzb_store::OutboxLag {
        depth: 1_500,
        lag_secs: 2,
    });
    let v = build(&i);
    let c = find(&v, "Search index lag");
    assert_eq!(c.status, Status::Ok);
    assert_eq!(c.value, "1 500 change(s) pending, oldest 2 s old");
    i.db.as_mut().unwrap().outbox = Some(nzb_store::OutboxLag {
        depth: 9,
        lag_secs: 61,
    });
    assert_eq!(find(&build(&i), "Search index lag").status, Status::Warn);
    i.db.as_mut().unwrap().outbox = Some(nzb_store::OutboxLag::default());
    i.live.as_mut().unwrap().lag_paused = true;
    let v = build(&i);
    let c = find(&v, "Search index lag");
    assert_eq!(c.status, Status::Warn);
    assert!(c.value.ends_with("watch-folder scanning paused"));
    i.db.as_mut().unwrap().outbox = None;
    assert_eq!(find(&build(&i), "Search index lag").status, Status::Warn);
}

#[test]
fn every_group_is_present() {
    let v = build(&good_inputs());
    for g in Group::ALL {
        assert!(v.iter().any(|c| c.group == g), "{g:?}");
    }
}

#[test]
fn scan_thresholds_follow_three_intervals() {
    assert_eq!(scan_check(Some(NOW - 5), NOW, 5).status, Status::Ok);
    assert_eq!(scan_check(Some(NOW - 10), NOW, 5).status, Status::Ok);
    assert_eq!(scan_check(Some(NOW - 11), NOW, 5).status, Status::Warn);
    assert_eq!(scan_check(Some(NOW - 15), NOW, 5).status, Status::Warn);
    assert_eq!(scan_check(Some(NOW - 16), NOW, 5).status, Status::Fail);
    assert_eq!(scan_check(None, NOW, 5).status, Status::Fail);
    assert_ne!(scan_check(Some(NOW - 16), NOW, 5).hint, "");
}

#[test]
fn fd_thresholds() {
    assert_eq!(fd_check(Some(100), Some(1000)).status, Status::Ok);
    assert_eq!(fd_check(Some(800), Some(1000)).status, Status::Warn);
    assert_eq!(fd_check(Some(949), Some(1000)).status, Status::Warn);
    assert_eq!(fd_check(Some(950), Some(1000)).status, Status::Fail);
    assert_eq!(fd_check(None, Some(1000)).status, Status::Info);
    assert_eq!(fd_check(Some(5), None).status, Status::Ok);
}

#[test]
fn memory_thresholds() {
    assert_eq!(memory_check(Some(500_000)).status, Status::Ok);
    assert_eq!(memory_check(Some(RSS_WARN_KIB)).status, Status::Ok);
    assert_eq!(memory_check(Some(RSS_WARN_KIB + 1)).status, Status::Warn);
    let n = memory_check(None);
    assert_eq!((n.status, n.value.as_str()), (Status::Info, "n/a"));
}

#[test]
fn clock_thresholds() {
    assert_eq!(clock_check(NOW, Some(NOW - 5)).status, Status::Ok);
    assert_eq!(clock_check(NOW, None).status, Status::Ok);
    assert_eq!(clock_check(NOW, Some(NOW + 300)).status, Status::Ok);
    assert_eq!(clock_check(NOW, Some(NOW + 301)).status, Status::Warn);
    assert_eq!(clock_check(1_600_000_000, None).status, Status::Fail);
    assert_eq!(clock_check(CLOCK_FLOOR, None).status, Status::Ok);
}

#[test]
fn build_profile() {
    assert_eq!(build_check(true).status, Status::Warn);
    assert_eq!(build_check(false).status, Status::Ok);
}

#[test]
fn schema_states() {
    let s = |latest, applied, elatest, embedded| SchemaInfo {
        latest_applied: latest,
        applied,
        embedded_latest: elatest,
        embedded,
    };
    assert_eq!(schema_check(Some(s(6, 6, 6, 6))).status, Status::Ok);
    assert_eq!(schema_check(Some(s(5, 5, 6, 6))).status, Status::Fail);
    assert_eq!(schema_check(Some(s(7, 7, 6, 6))).status, Status::Fail);
    assert_eq!(schema_check(None).status, Status::Fail);
}

#[test]
fn wal_threshold_is_256_mib() {
    let wal = |w| wal_checks(Some(1), w).remove(1).status;
    assert_eq!(wal(Some(0)), Status::Ok);
    assert_eq!(wal(Some(WAL_WARN_BYTES)), Status::Ok);
    assert_eq!(wal(Some(WAL_WARN_BYTES + 1)), Status::Warn);
    assert_eq!(wal(None), Status::Info);
}

#[test]
fn pools_and_ping() {
    let mut p = good_inputs().db.unwrap().pools;
    assert_eq!(pools_check(p).status, Status::Ok);
    p.closed = true;
    assert_eq!(pools_check(p).status, Status::Fail);
    assert_eq!(ping_check("x", true).status, Status::Ok);
    assert_eq!(ping_check("x", false).status, Status::Fail);
}

#[test]
fn log_table_size_threshold() {
    let logs = |rows| LogCounts {
        ingest_rows: rows,
        ..LogCounts::default()
    };
    let st = |l| count_checks(None, Some(l))[1].status;
    assert_eq!(st(logs(LOG_ROWS_WARN)), Status::Ok);
    assert_eq!(st(logs(LOG_ROWS_WARN + 1)), Status::Warn);
}

#[test]
fn watch_folder_backlog_thresholds() {
    let c = |n, capped| Ok(Count { n, capped });
    assert_eq!(waiting_check(c(0, false), false).status, Status::Ok);
    assert_eq!(waiting_check(c(100, false), false).status, Status::Ok);
    assert_eq!(waiting_check(c(101, false), false).status, Status::Warn);
    let capped = waiting_check(c(COUNT_CAP, true), false);
    assert_eq!(capped.status, Status::Warn);
    assert_eq!(capped.value, "10 000+");
    assert_eq!(waiting_check(Err(()), false).status, Status::Fail);
}

#[test]
fn failed_and_duplicate_folders() {
    let c = |n| Ok(Count { n, capped: false });
    assert_eq!(failed_dir_check(c(0)).status, Status::Ok);
    assert_eq!(failed_dir_check(c(1)).status, Status::Warn);
    assert_eq!(failed_dir_check(Err(())).status, Status::Fail);
    assert_eq!(duplicates_dir_check(c(9)).status, Status::Info);
    assert_eq!(duplicates_dir_check(Err(())).status, Status::Warn);
}

#[test]
fn leftovers_and_recovery() {
    assert_eq!(leftovers_check(0).status, Status::Ok);
    assert_eq!(leftovers_check(1).status, Status::Warn);
    assert_eq!(recovery_check(None).status, Status::Info);
    let mut r = RecoverySummary::default();
    assert_eq!(recovery_check(Some(r)).status, Status::Ok);
    r.repaired = 3;
    assert_eq!(recovery_check(Some(r)).status, Status::Ok);
    r.missing_blobs = 1;
    assert_eq!(recovery_check(Some(r)).status, Status::Warn);
    r.missing_blobs = 0;
    r.errors = 1;
    assert_eq!(recovery_check(Some(r)).status, Status::Warn);
}

#[test]
fn free_space_thresholds() {
    const GIB: u64 = 1 << 30;
    assert_eq!(free_status(50 * GIB, 100 * GIB), Status::Ok);
    assert_eq!(free_status(9 * GIB, 100 * GIB), Status::Warn);
    assert_eq!(free_status(GIB / 2, 100 * GIB), Status::Fail);
    assert_eq!(free_status(1 << 20, 100 * GIB), Status::Fail);
    // Small volume with plenty of percent but under 1 GiB is only a warning.
    assert_eq!(free_status(GIB / 2, GIB), Status::Warn);
    assert_eq!(free_status(0, 0), Status::Fail);
}

#[test]
fn directory_states() {
    assert_eq!(dir_check(&dir("Watch folder")).status, Status::Ok);
    let mut d = dir("Watch folder");
    d.exists = false;
    assert_eq!(dir_check(&d).status, Status::Fail);
    let mut d = dir("Watch folder");
    d.is_dir = false;
    assert_eq!(dir_check(&d).value, "not a directory");
    let mut d = dir("Failed folder");
    d.writable = Some(false);
    let c = dir_check(&d);
    assert_eq!(c.status, Status::Fail);
    assert!(c.value.contains("NOT writable") && !c.hint.is_empty());
    let mut d = dir("Failed folder");
    d.free = Some((5 << 30, 100 << 30));
    assert_eq!(dir_check(&d).status, Status::Warn);
    d.free = Some((1 << 20, 100 << 30));
    assert_eq!(dir_check(&d).status, Status::Fail);
    d.free = None;
    let c = dir_check(&d);
    assert_eq!(c.status, Status::Ok);
    assert!(c.value.contains("free space n/a"));
    d.writable = None;
    assert!(dir_check(&d).value.contains("writability n/a"));
}

#[test]
fn filesystem_and_layout_checks() {
    assert_eq!(same_fs_check(Some(true), true).status, Status::Ok);
    assert_eq!(same_fs_check(Some(false), true).status, Status::Fail);
    assert_eq!(same_fs_check(Some(false), false).status, Status::Warn);
    assert_eq!(same_fs_check(None, true).status, Status::Info);
    assert_eq!(layout_check(true).status, Status::Ok);
    assert_eq!(layout_check(false).status, Status::Fail);
}

#[test]
fn backup_age_thresholds() {
    let ok = |t| backup_check(Ok((Some(t), 14)), NOW).status;
    assert_eq!(ok(NOW - 3600), Status::Ok);
    assert_eq!(ok(NOW - BACKUP_MAX_AGE_SECS), Status::Ok);
    assert_eq!(ok(NOW - BACKUP_MAX_AGE_SECS - 1), Status::Warn);
    assert_eq!(backup_check(Ok((None, 0)), NOW).status, Status::Warn);
    assert_eq!(backup_check(Err(()), NOW).status, Status::Warn);
    assert!(
        backup_check(Ok((Some(NOW), 14)), NOW)
            .value
            .contains("policy: 14")
    );
}

#[test]
fn deep_summary_row() {
    assert_eq!(deep_summary_check(None, NOW).status, Status::Info);
    let d = DeepSummary {
        at: NOW - 60,
        missing: 0,
        partial: false,
        db_ok: true,
    };
    assert_eq!(deep_summary_check(Some(d), NOW).status, Status::Ok);
    assert_eq!(
        deep_summary_check(Some(DeepSummary { missing: 2, ..d }), NOW).status,
        Status::Fail
    );
    assert_eq!(
        deep_summary_check(Some(DeepSummary { db_ok: false, ..d }), NOW).status,
        Status::Fail
    );
}

#[test]
fn deep_store_lookup_states() {
    assert_eq!(store_lookup_check(10, 0, false, false).status, Status::Ok);
    assert_eq!(store_lookup_check(10, 1, false, false).status, Status::Fail);
    assert_eq!(store_lookup_check(10, 0, true, false).status, Status::Warn);
    let p = store_lookup_check(50_000, 0, false, true);
    assert_eq!(p.status, Status::Warn);
    assert!(p.value.contains("partial") || p.value.contains("incomplete"));
}

#[test]
fn security_rows_and_thresholds() {
    let sec = good_inputs().db.unwrap().security;
    let rows = |cfg, key, s, dev| security_checks(cfg, key, s, dev);
    let st = |v: &[Check], n: &str| find(v, n).status;

    let v = rows(cfg_facts(), true, sec, false);
    assert_eq!(Summary::of(&v), Summary::default());
    assert!(
        find(&v, "Outbound network")
            .value
            .contains("no outbound connections")
    );

    assert_eq!(
        st(&rows(cfg_facts(), false, sec, false), "TOTP encryption key"),
        Status::Fail
    );
    assert_eq!(
        st(&rows(cfg_facts(), true, sec, true), "Build features"),
        Status::Fail
    );
    let mut c = cfg_facts();
    c.insecure_cookies = true;
    assert_eq!(st(&rows(c, true, sec, false), "Cookies"), Status::Warn);
    let mut c = cfg_facts();
    c.loopback = false;
    assert_eq!(
        st(&rows(c, true, sec, false), "Listen address"),
        Status::Warn
    );
    c.has_proxies = true;
    assert_eq!(st(&rows(c, true, sec, false), "Listen address"), Status::Ok);
    let mut c = cfg_facts();
    c.allowed_hosts = 2;
    assert_eq!(
        st(&rows(c, true, sec, false), "Extra allowed hosts"),
        Status::Info
    );

    let base = sec.unwrap();
    let with = |f: &dyn Fn(&mut SecurityFacts)| {
        let mut s = base;
        f(&mut s);
        rows(cfg_facts(), true, Some(s), false)
    };
    let v = with(&|s| s.user_exists = false);
    assert_eq!(st(&v, "User account"), Status::Fail);
    let v = with(&|s| s.totp_enabled = false);
    assert_eq!(st(&v, "Two-factor sign-in (TOTP)"), Status::Warn);
    let v = with(&|s| s.failed_logins_recent = FAILED_LOGIN_WARN);
    assert_eq!(st(&v, "Failed sign-ins (24 h)"), Status::Ok);
    let v = with(&|s| s.failed_logins_recent = FAILED_LOGIN_WARN + 1);
    assert_eq!(st(&v, "Failed sign-ins (24 h)"), Status::Warn);
    let v = with(&|s| s.locked = true);
    assert_eq!(st(&v, "Account lock"), Status::Warn);
    let v = rows(cfg_facts(), true, None, false);
    assert_eq!(st(&v, "Account"), Status::Info);
}

#[test]
fn http_probe_rows() {
    assert_eq!(http_check(Some(true), None).status, Status::Ok);
    assert_eq!(http_check(Some(false), None).status, Status::Fail);
    assert_eq!(http_check(None, Some(true)).status, Status::Ok);
    assert_eq!(http_check(None, Some(false)).status, Status::Fail);
    assert_eq!(http_check(None, None).status, Status::Info);
}

#[test]
fn offline_mode_has_no_live_rows_failing() {
    let mut i = good_inputs();
    i.live = None;
    i.uptime = None;
    i.recovery = None;
    i.http_probe = Some(true);
    let v = build(&i);
    assert_eq!(Summary::of(&v).exit_code(), 0, "{v:#?}");
    assert_eq!(find(&v, "Uptime").status, Status::Info);
    assert_eq!(find(&v, "Watch-folder scan").status, Status::Info);
}

#[test]
fn missing_database_is_a_failure_not_a_panic() {
    let mut i = good_inputs();
    i.db = None;
    let v = build(&i);
    assert_eq!(find(&v, "Database").status, Status::Fail);
}

#[test]
fn proc_parsers() {
    assert_eq!(
        parse_rss_kib("Name:\tnzbd\nVmRSS:\t   12345 kB\nThreads:\t4\n"),
        Some(12_345)
    );
    assert_eq!(parse_rss_kib("Name:\tnzbd\n"), None);
    let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                  Max open files            1024                 1048576              files\n";
    assert_eq!(parse_fd_limit(limits), Some(1024));
    assert_eq!(
        parse_fd_limit(
            "Max open files            unlimited            unlimited            files\n"
        ),
        None
    );
    assert_eq!(parse_fd_limit(""), None);
}

#[test]
fn backup_names_parse_to_the_clock_that_wrote_them() {
    for t in [
        0_i64,
        1_700_000_000,
        1_800_000_000,
        951_782_400,
        4_102_444_799,
    ] {
        let name = nzb_store::backup_name(t);
        assert_eq!(parse_backup_ts(&name), Some(t), "{name}");
    }
    for bad in [
        "nzbd-20231114T221320Z.sqlite.tmp",
        "nzbd-2023111T2213200Z.sqlite",
        "nzbd-20231314T221320Z.sqlite",
        "nzbd-20231114T251320Z.sqlite",
        "x-20231114T221320Z.sqlite",
        "nzbd-2023111aT221320Z.sqlite",
        "",
    ] {
        assert_eq!(parse_backup_ts(bad), None, "{bad}");
    }
}

#[test]
fn thousands_grouping() {
    assert_eq!(group_thousands(0), "0");
    assert_eq!(group_thousands(999), "999");
    assert_eq!(group_thousands(1000), "1 000");
    assert_eq!(group_thousands(10_000), "10 000");
    assert_eq!(group_thousands(1_234_567), "1 234 567");
}

// ---------------------------------------------------------------------------------------------
// Filesystem gathering

struct Tree {
    root: tempfile::TempDir,
    cfg: Config,
}

fn tree() -> Tree {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    let p = root.path();
    for (slot, name) in [
        (&mut cfg.paths.watch, "watch"),
        (&mut cfg.paths.store, "store"),
        (&mut cfg.paths.failed, "failed"),
        (&mut cfg.paths.duplicates, "duplicates"),
        (&mut cfg.paths.tmp, "tmp"),
        (&mut cfg.paths.backups, "backups"),
    ] {
        *slot = p.join(name);
        std::fs::create_dir(&*slot).unwrap();
    }
    std::fs::create_dir(p.join("store").join(".tmp")).unwrap();
    cfg.paths.db = p.join("nzbd.sqlite");
    cfg.security.totp_key_file = p.join("totp.key");
    std::fs::write(
        &cfg.security.totp_key_file,
        crate::config::generate_key_b64().unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(
        &cfg.security.totp_key_file,
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    Tree { root, cfg }
}

fn names_in(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn gather_fs_on_a_healthy_tree() {
    let t = tree();
    let f = gather_fs(&t.cfg);
    assert_eq!(f.dirs.len(), 7);
    for d in &f.dirs {
        assert!(d.exists && d.is_dir, "{}", d.name);
        assert_eq!(d.writable, Some(true), "{}", d.name);
        assert!(d.free.is_some(), "statvfs {}", d.name);
    }
    assert_eq!(f.same_fs, Some(true));
    assert!(f.layout_ok);
    assert!(f.key_ok);
    assert_eq!(f.waiting.unwrap().n, 0);
    assert_eq!(f.failed.unwrap().n, 0);
    assert_eq!(f.backups, Ok((None, 0)));
    assert_eq!(f.wal_bytes, Some(0));
    assert_eq!(f.gc_trash, Some(0));
}

/// T141 (review 54 I6, L2): an NFO that followed its NZB into `duplicates/` is not a duplicate of its own, and an
/// interrupted NFO sidecar removal (`.nzbd-trash.nfo.*`) counts as a leftover like any other trash name.
#[test]
fn t141_nfo_sidecars_are_not_duplicates_and_their_trash_is_a_leftover() {
    let t = tree();
    let dups = &t.cfg.paths.duplicates;
    std::fs::write(dups.join("20231114T221320Z-0123abcd.nzb"), b"x").unwrap();
    std::fs::write(dups.join("20231114T221320Z-0123abcd.nfo"), b"art").unwrap();
    std::fs::write(dups.join("20231114T221320Z-0123abce.NFO"), b"art").unwrap();
    std::fs::write(t.cfg.paths.watch.join(".nzbd-trash.nfo.1-2-3"), b"art").unwrap();
    std::fs::write(t.cfg.paths.failed.join(".nzbd-trash.4-5-6"), b"x").unwrap();
    let f = gather_fs(&t.cfg);
    assert_eq!(f.duplicates.unwrap().n, 1);
    assert_eq!(f.leftovers, 2);
}

#[test]
fn gather_fs_never_leaves_probe_files_and_never_writes_into_watch() {
    let t = tree();
    let before: Vec<_> = ["watch", "store", "failed", "duplicates", "tmp", "backups"]
        .iter()
        .map(|d| names_in(&t.root.path().join(d)))
        .collect();
    let root_before = names_in(t.root.path());
    for _ in 0..3 {
        let _ = gather_fs(&t.cfg);
    }
    let after: Vec<_> = ["watch", "store", "failed", "duplicates", "tmp", "backups"]
        .iter()
        .map(|d| names_in(&t.root.path().join(d)))
        .collect();
    assert_eq!(before, after);
    assert_eq!(names_in(t.root.path()), root_before);
    assert_eq!(names_in(&t.root.path().join("store").join(".tmp")).len(), 0);
}

#[test]
fn watch_folder_is_never_probed_by_writing() {
    let t = tree();
    let d = dir_facts("Watch folder", &t.cfg.paths.watch, Probe::Access);
    assert_eq!(d.writable, Some(true));
    assert_eq!(names_in(&t.cfg.paths.watch).len(), 0);
    // Not writable according to access(2) when the mode forbids it (skipped for root).
    std::fs::set_permissions(&t.cfg.paths.watch, std::fs::Permissions::from_mode(0o500)).unwrap();
    let ro = dir_facts("Watch folder", &t.cfg.paths.watch, Probe::Access);
    let is_root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if !is_root {
        assert_eq!(ro.writable, Some(false));
        let wf = dir_facts("Failed folder", &t.cfg.paths.watch, Probe::Write);
        assert_eq!(wf.writable, Some(false));
    }
    std::fs::set_permissions(&t.cfg.paths.watch, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn missing_and_non_directory_paths() {
    let t = tree();
    let m = dir_facts("Backups folder", &t.root.path().join("nope"), Probe::Write);
    assert!(!m.exists && !m.is_dir && m.writable.is_none() && m.free.is_none());
    assert_eq!(dir_check(&m).status, Status::Fail);
    let file = t.root.path().join("afile");
    std::fs::write(&file, b"x").unwrap();
    let f = dir_facts("Backups folder", &file, Probe::Write);
    assert!(f.exists && !f.is_dir);
    assert_eq!(dir_check(&f).value, "not a directory");
}

#[test]
fn hostile_names_are_counted_not_interpreted() {
    let t = tree();
    let w = &t.cfg.paths.watch;
    for n in [
        "ok.nzb",
        "UPPER.NZB",
        "<script>alert(1)<&sol;script>.nzb",
        "new\nline.nzb",
        "\u{202e}gpj.nzb",
        "..%2f..%2fetc%2fpasswd.nzb",
        "notes.txt",
        ".hidden.nzb",
    ] {
        std::fs::write(w.join(n), b"x").unwrap();
    }
    std::os::unix::fs::symlink("/etc/passwd", w.join("link.nzb")).unwrap();
    std::fs::create_dir(w.join("dir.nzb")).unwrap();
    std::fs::write(w.join(".nzbd-trash.abc"), b"x").unwrap();
    std::fs::write(w.join(".draft.part"), b"x").unwrap();
    std::fs::write(
        t.cfg.paths.failed.join("20240101T000000Z-deadbeef.nzb"),
        b"x",
    )
    .unwrap();
    std::fs::write(t.cfg.paths.failed.join("<b>evil.nzb"), b"x").unwrap();
    let f = gather_fs(&t.cfg);
    // ok, UPPER, <script>, newline, rtl: the dot-leading traversal-looking name, the symlink, directory, .txt and
    // hidden names are not candidates.
    assert_eq!(f.waiting.unwrap().n, 5);
    assert_eq!(f.failed.unwrap().n, 1);
    assert_eq!(f.leftovers, 2);
    // The values shown never contain any of those names.
    let v = build(&Inputs {
        fs: f,
        ..good_inputs()
    });
    let all = v
        .iter()
        .map(|c| format!("{} {} {}", c.name, c.value, c.hint))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "<script>", "passwd", "evil", "\u{202e}", "deadbeef", "link.nzb",
    ] {
        assert!(!all.contains(needle), "{needle}");
    }
    assert_eq!(find(&v, "Leftover temporary files").status, Status::Warn);
}

#[test]
fn counts_are_capped() {
    let t = tree();
    let w = &t.cfg.paths.watch;
    for i in 0..(COUNT_CAP + 5) {
        std::fs::File::create(w.join(format!("{i}.nzb"))).unwrap();
    }
    let c = count_dir(w, &is_nzb_candidate).unwrap();
    assert_eq!(
        c,
        Count {
            n: COUNT_CAP,
            capped: true
        }
    );
    assert_eq!(c.show(), "10 000+");
}

#[test]
fn backups_are_found_by_generated_name_only() {
    let t = tree();
    let b = &t.cfg.paths.backups;
    for ts in [1_700_000_000_i64, 1_700_086_400, 1_699_000_000] {
        std::fs::write(b.join(nzb_store::backup_name(ts)), b"x").unwrap();
    }
    std::fs::write(b.join("nzbd-garbage.sqlite"), b"x").unwrap();
    std::fs::write(
        b.join(format!(".{}.tmp", nzb_store::backup_name(1_800_000_000))),
        b"x",
    )
    .unwrap();
    assert_eq!(scan_backups(b), Ok((Some(1_700_086_400), 3)));
    assert_eq!(scan_backups(&b.join("missing")), Err(()));
}

#[test]
fn layout_overlap_is_detected() {
    let mut t = tree();
    assert!(gather_fs(&t.cfg).layout_ok);
    let inner = t.cfg.paths.watch.join("failed-inside");
    std::fs::create_dir(&inner).unwrap();
    t.cfg.paths.failed = inner;
    assert!(!gather_fs(&t.cfg).layout_ok);
}

#[test]
fn key_file_problems_fail_without_leaking_the_path() {
    let t = tree();
    std::fs::set_permissions(
        &t.cfg.security.totp_key_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let f = gather_fs(&t.cfg);
    assert!(!f.key_ok);
    let v = build(&Inputs {
        fs: f,
        ..good_inputs()
    });
    let c = find(&v, "TOTP encryption key");
    assert_eq!(c.status, Status::Fail);
    let shown = format!("{c:?}");
    assert!(!shown.contains("totp.key") && !shown.contains(t.root.path().to_str().unwrap()));
}

#[test]
fn failed_consistency_counts_orphans_both_ways() {
    let t = tree();
    let d = &t.cfg.paths.failed;
    let a = "20240101T000000Z-aaaaaaaa.nzb";
    let b = "20240101T000000Z-bbbbbbbb.nzb";
    std::fs::write(d.join(a), b"x").unwrap();
    std::fs::write(d.join(format!("{a}{}", ing::failure::REASON_SUFFIX)), b"{}").unwrap();
    std::fs::write(d.join(b), b"x").unwrap();
    std::fs::write(
        d.join(format!(
            "20240101T000000Z-cccccccc.nzb{}",
            ing::failure::REASON_SUFFIX
        )),
        b"{}",
    )
    .unwrap();
    assert_eq!(failed_consistency(d).unwrap(), (1, 1));
}

#[test]
fn blob_counter_walks_only_the_hex_layout() {
    let t = tree();
    let s = &t.cfg.paths.store;
    std::fs::create_dir_all(s.join("ab").join("cd")).unwrap();
    std::fs::write(s.join("ab").join("cd").join("blob1.nzb"), b"x").unwrap();
    std::fs::write(s.join("ab").join("cd").join("blob2.nzb"), b"x").unwrap();
    std::fs::create_dir_all(s.join("zz").join("cd")).unwrap();
    std::fs::write(s.join("zz").join("cd").join("ignored.nzb"), b"x").unwrap();
    let c = count_blobs(s, Instant::now() + Duration::from_secs(5));
    assert_eq!(
        c,
        Count {
            n: 2,
            capped: false
        }
    );
    // An expired deadline stops the walk and says so.
    let c = count_blobs(s, Instant::now());
    assert!(c.capped || c.n <= 2);
}

// ---------------------------------------------------------------------------------------------
// Engine with a real database

/// Points `cfg` at the leg's library: nothing to do on SQLite (`paths.db`); the app role over the test server's
/// socket on Postgres.
fn use_leg_backend(
    cfg: &mut Config,
    ts: &nzb_store::test_backend::TestStore,
    dir: &std::path::Path,
) {
    if let Some(s) = ts.pg_settings_with_password_file(dir) {
        cfg.db.backend = nzb_store::DbBackend::Postgres;
        cfg.db.host = Some(match &s.host {
            nzb_store::pg::PgHost::Socket(p) => p.display().to_string(),
            nzb_store::pg::PgHost::Ip(ip) => ip.to_string(),
        });
        cfg.db.port = s.port;
        cfg.db.name = s.name;
        cfg.db.user = s.user;
        cfg.db.password_file = Some(s.password_file);
    }
}

/// The leg's library (`NZBD_TEST_BACKEND`; SQLite at `paths.db`).
async fn open_db(t: &Tree) -> nzb_store::test_backend::TestStore {
    nzb_store::test_backend::TestStore::open_file(&t.cfg.paths.db).await
}

#[tokio::test]
async fn gather_db_reads_a_fresh_database() {
    let t = tree();
    let ts = open_db(&t).await;
    let db = ts.store.clone();
    let f = gather_db(&db, NOW).await;
    assert!(f.writer_ok && f.reader_ok);
    let s = f.schema.unwrap();
    assert_eq!(s.applied, s.embedded);
    assert_eq!(s.latest_applied, s.embedded_latest);
    assert_eq!(schema_check(f.schema).status, Status::Ok);
    assert_eq!(f.totals.unwrap().releases, 0);
    let sec = f.security.unwrap();
    assert!(!sec.user_exists);
    assert_eq!(sec.active_api_keys, 0);
    assert!(!f.pools.closed);
}

#[tokio::test]
async fn engine_inputs_and_collect_cover_all_groups_without_paths() {
    let t = tree();
    let ts = open_db(&t).await;
    let db = ts.store.clone();
    db.create_user("alice", "$argon2id$secret-looking-hash", NOW)
        .await
        .unwrap();
    let engine = Engine::offline(&t.cfg, Some(db), false);
    let v = engine.collect(NOW).await;
    for g in Group::ALL {
        assert!(v.iter().any(|c| c.group == g), "{g:?}");
    }
    let all = v
        .iter()
        .map(|c| format!("{} | {} | {}", c.name, c.value, c.hint))
        .collect::<Vec<_>>()
        .join("\n");
    let root = t.root.path().to_str().unwrap();
    assert!(!all.contains(root), "full path leaked:\n{all}");
    assert!(!all.contains("argon2"), "{all}");
    assert!(!all.contains("alice"), "{all}");
    assert_eq!(find(&v, "User account").status, Status::Ok);
    assert_eq!(find(&v, "Two-factor sign-in (TOTP)").status, Status::Warn);
}

#[tokio::test]
async fn deep_check_is_read_only_and_reports_missing_blobs() {
    let t = tree();
    let ts = open_db(&t).await;
    let db = ts.store.clone();
    let store = FsStore::open(&t.cfg.paths.store).unwrap();
    let engine = Engine::offline(&t.cfg, Some(db.clone()), false);

    // Empty index: everything ok.
    let v = engine.deep(NOW).await;
    assert_eq!(Summary::of(&v), Summary::default(), "{v:#?}");
    assert_eq!(
        find(&v, "Database integrity (quick_check)").status,
        Status::Ok
    );
    assert_eq!(find(&v, "Foreign keys").status, Status::Ok);
    assert_eq!(find(&v, "Orphan blobs (dry run)").status, Status::Ok);
    drop(store);

    // An unreferenced blob (older than the grace) and nothing else: snapshot, run, compare.
    let snap = |p: &Path| -> Vec<(String, u64)> {
        fn walk(p: &Path, out: &mut Vec<(String, u64)>) {
            for e in std::fs::read_dir(p).unwrap().flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push((
                        path.to_string_lossy().into_owned(),
                        e.metadata().unwrap().len(),
                    ));
                }
            }
        }
        let mut v = Vec::new();
        walk(p, &mut v);
        v.sort();
        v
    };
    let before = (
        snap(&t.cfg.paths.store),
        snap(&t.cfg.paths.failed),
        snap(&t.cfg.paths.watch),
    );
    let rows_before = db.release_totals().await.unwrap();
    let audit_before = db.recent_audit(100).await.unwrap().len();
    let v = engine.deep(NOW + 1).await;
    assert_ne!(v.len(), 0);
    let after = (
        snap(&t.cfg.paths.store),
        snap(&t.cfg.paths.failed),
        snap(&t.cfg.paths.watch),
    );
    assert_eq!(before, after, "deep check changed files");
    assert_eq!(db.release_totals().await.unwrap(), rows_before);
    assert_eq!(db.recent_audit(100).await.unwrap().len(), audit_before);
    // The cheap Storage row now reflects the last deep run.
    let cheap = engine.collect(NOW + 2).await;
    assert_eq!(
        find(&cheap, "Store vs database (last deep check)").status,
        Status::Ok
    );
}

// ---------------------------------------------------------------------------------------------
// CLI

#[test]
fn cli_exits_two_when_the_server_is_not_listening() {
    let t = tree();
    let mut cfg = t.cfg.clone();
    // A port nothing listens on.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    cfg.server.listen = l.local_addr().unwrap();
    drop(l);
    let (text, code) = cli_report(&cfg).unwrap();
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("FAIL") && text.contains("Liveness probe"));
    assert!(text.contains("APPLICATION") && text.contains("STORAGE"));
    assert!(!text.contains(t.root.path().to_str().unwrap()));
}

#[test]
fn cli_without_a_database_fails_and_creates_nothing() {
    let t = tree();
    // A real listener that answers /healthz with 200.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s in l.incoming().take(1) {
            let mut s = s.unwrap();
            let mut buf = [0_u8; 256];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n");
        }
    });
    let mut cfg = t.cfg.clone();
    cfg.server.listen = addr;
    assert!(!cfg.paths.db.exists());
    let (text, code) = cli_report(&cfg).unwrap();
    // No database file: a FAIL, and the CLI did not conjure one.
    assert_eq!(code, 2, "{text}");
    assert!(!cfg.paths.db.exists());
    assert!(text.contains("cannot be opened"));
}

#[test]
fn cli_with_a_database_and_a_live_listener_reports_expected_build_diagnostics() {
    let t = tree();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ts = rt.block_on(async {
        let ts = open_db(&t).await;
        ts.store
            .create_user("alice", "$argon2id$x", NOW)
            .await
            .unwrap();
        ts
    });
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s in l.incoming().take(1) {
            let mut s = s.unwrap();
            let mut buf = [0_u8; 256];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n");
        }
    });
    let mut cfg = t.cfg.clone();
    cfg.server.listen = addr;
    use_leg_backend(&mut cfg, &ts, t.root.path());
    let (text, code) = cli_report(&cfg).unwrap();
    drop(ts);
    // Production builds report no development helpers; --all-features intentionally reports
    // dev-tools as a security failure, including exit code 2. Neither diagnostic may disappear.
    let build_rows: Vec<_> = text
        .lines()
        .filter(|l| l.contains("Build features"))
        .collect();
    assert_eq!(build_rows.len(), 1, "{text}");
    let build_row = build_rows[0];
    let expected = if cfg!(feature = "dev-tools") {
        "FAIL Build features dev-tools compiled in"
    } else {
        "OK Build features no development tools"
    };
    assert_eq!(
        build_row.split_whitespace().collect::<Vec<_>>().join(" "),
        expected
    );
    // Debug build, no backup and MFA not enrolled yield warnings. A small test volume may
    // additionally report low free space; every other unexpected failure must still fail the test.
    let failures: Vec<_> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("FAIL"))
        .collect();
    for l in &failures {
        if cfg!(feature = "dev-tools") && *l == build_row {
            continue;
        }
        assert!(l.contains("% free"), "{l}");
    }
    assert_eq!(code, if failures.is_empty() { 1 } else { 2 }, "{text}");
    assert!(text.contains("WARN"));
}

#[test]
fn render_text_neutralises_control_sequences() {
    let c = Check::new(
        Group::App,
        "x",
        Status::Warn,
        "a\u{1b}[31mred\nline",
        "h\u{1b}[0m",
    );
    let t = render_text(&[c]);
    assert!(!t.contains('\u{1b}'));
    assert_eq!(t.lines().filter(|l| l.contains("red")).count(), 1);
}

/// T061 L-3: a backup written by the in-process maintenance task is what the "Database backups"
/// row reports, and it is fresh (OK), not the "no backup found" warning.
#[tokio::test]
async fn t061_l3_maintenance_backup_satisfies_the_backup_freshness_check() {
    let d = tempfile::tempdir().unwrap();
    let ts = nzb_store::test_backend::TestStore::open(d.path()).await;
    let db = ts.store.clone();
    let backups = d.path().join("backups");
    std::fs::create_dir(&backups).unwrap();
    assert_eq!(
        backup_check(scan_backups(&backups), NOW).status,
        Status::Warn,
        "nothing yet"
    );
    let p = crate::maintenance::Params {
        first_delay: std::time::Duration::ZERO,
        interval: std::time::Duration::from_hours(24),
        backups_dir: backups.clone(),
        keep: 14,
        backup_key: None,
    };
    let r = crate::maintenance::run_once(&db, &p, NOW).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(scan_backups(&backups), Ok((Some(NOW), 1)));
    assert_eq!(
        backup_check(scan_backups(&backups), NOW + 60).status,
        Status::Ok
    );
}

#[test]
fn sec_080_health_reports_an_inconsistent_chain() {
    let q = |consistent, unchained, bootstrapped| {
        Some(nzb_store::ChainQuick {
            rows: 1200,
            unchained,
            consistent,
            bootstrapped,
        })
    };
    let ok = audit_chain_check(q(true, 0, true));
    assert_eq!(ok.status, Status::Ok);
    assert!(ok.value.starts_with("1 200 row(s)"), "{}", ok.value);
    assert_eq!(audit_chain_check(q(false, 0, true)).status, Status::Fail);
    assert_eq!(audit_chain_check(q(true, 2, true)).status, Status::Fail);
    assert_eq!(audit_chain_check(q(true, 0, false)).status, Status::Warn);
    assert_eq!(audit_chain_check(None).status, Status::Warn);
    // Nothing from the database content reaches the text: counts only.
    let bad = audit_chain_check(q(false, 3, true));
    assert!(
        bad.value.contains("3 row(s) without a chain"),
        "{}",
        bad.value
    );
}
