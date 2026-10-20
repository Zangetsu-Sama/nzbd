//! Pipeline tests: happy path, duplicates, races, crash points (SEC-005/006/007/008).
//! Everything runs on tempdirs with a fake wall clock and a fake scanner clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::needless_pass_by_value,
    clippy::panic
)]

use nzb_store::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use nzb_core::{Limits, Sha256, Taxonomy};
use nzb_store::{CategorySource, FsStore, LogOutcome, NewRelease, NzbStore, SceneColumns, Store};
use nzb_testkit::{FileSpec, NzbBuilder};
use tokio::sync::mpsc;

use crate::pipeline::{CrashPoint, Queued};
use crate::*;

const T0: i64 = 1_700_000_000;

struct FakeWall(AtomicI64);
impl WallClock for FakeWall {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Default)]
struct FakeScan(Arc<AtomicU64>);
impl Clock for FakeScan {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Env {
    tmpdir: tempfile::TempDir,
    watch: PathBuf,
    failed: PathBuf,
    dups: PathBuf,
    staging: PathBuf,
    store_root: PathBuf,
    db: Store,
    _test_store: nzb_store::test_backend::TestStore,
    store: Arc<FsStore>,
    wall: Arc<FakeWall>,
    scan_clock: FakeScan,
    scanner: Scanner<FakeScan>,
    pipeline: Pipeline,
}

#[derive(Clone, Copy)]
struct Opts {
    action: DuplicatesAction,
    from_subfolder: bool,
}

const OPTS: Opts = Opts {
    action: DuplicatesAction::Move,
    from_subfolder: false,
};

fn cfg(env_watch: &Path, failed: &Path, dups: &Path, o: Opts) -> PipelineConfig {
    PipelineConfig {
        limits: Limits {
            max_file_bytes: 64 * 1024,
            ..Limits::default()
        },
        watch_dir: env_watch.to_path_buf(),
        failed_dir: failed.to_path_buf(),
        duplicates_dir: dups.to_path_buf(),
        duplicates_action: o.action,
        category_from_subfolder: o.from_subfolder,
        failed_uploads_max_files: 0,
        failed_uploads_max_bytes: 0,
    }
}

fn scanner(watch: &Path, clock: &FakeScan, recursive: bool) -> Scanner<FakeScan> {
    Scanner::new(
        ScannerConfig {
            watch_dir: watch.to_path_buf(),
            recursive,
            max_file_bytes: 64 * 1024,
            stable_secs: 5,
            backoff_secs: 600,
            max_entries_per_scan: 1000,
        },
        clock.clone(),
    )
}

async fn env(o: Opts) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let mk = |n: &str| {
        let p = root.join(n);
        fs::create_dir(&p).unwrap();
        p
    };
    let (watch, failed, dups, staging, store_root) = (
        mk("watch"),
        mk("failed"),
        mk("dups"),
        mk("tmp"),
        mk("store"),
    );
    // The backend of this CI leg (NZBD_TEST_BACKEND, no default).
    let test_store = nzb_store::test_backend::TestStore::open(&root).await;
    let db = test_store.store.clone();
    let store = Arc::new(FsStore::open(&store_root).unwrap());
    let wall = Arc::new(FakeWall(AtomicI64::new(T0)));
    let scan_clock = FakeScan::default();
    let pipeline = Pipeline::new(
        cfg(&watch, &failed, &dups, o),
        db.clone(),
        store.clone(),
        wall.clone(),
    )
    .unwrap();
    let scanner = scanner(&watch, &scan_clock, o.from_subfolder);
    Env {
        tmpdir: tmp,
        watch,
        failed,
        dups,
        staging,
        store_root,
        db,
        _test_store: test_store,
        store,
        wall,
        scan_clock,
        scanner,
        pipeline,
    }
}

impl Env {
    /// Two scans 6 s apart: everything present is stable.
    fn candidates(&mut self) -> Vec<Candidate> {
        let _ = self.scanner.scan(100);
        self.scan_clock.0.fetch_add(6, Ordering::SeqCst);
        self.scanner.scan(100)
    }

    fn put_watch(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.watch.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    /// A pipeline over the same directories/DB/store: what a restarted process would build.
    fn restart(&mut self, o: Opts) {
        self.pipeline = Pipeline::new(
            cfg(&self.watch, &self.failed, &self.dups, o),
            self.db.clone(),
            self.store.clone(),
            self.wall.clone(),
        )
        .unwrap();
        self.scanner = scanner(&self.watch, &self.scan_clock, o.from_subfolder);
    }

    fn blobs(&self) -> Vec<PathBuf> {
        fn walk(d: &Path, out: &mut Vec<PathBuf>) {
            for e in fs::read_dir(d).unwrap() {
                let e = e.unwrap();
                if e.file_name() == ".tmp" || e.file_name() == ".gc-trash" {
                    continue;
                }
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    walk(&e.path(), out);
                } else {
                    out.push(e.path());
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.store_root, &mut out);
        out
    }

    async fn release_count(&self) -> i64 {
        sqlx_count(&self.db).await
    }
}

async fn sqlx_count(db: &Store) -> i64 {
    i64::try_from(db.release_totals().await.unwrap().releases).unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn nzb_names(dir: &Path) -> Vec<String> {
    names(dir)
        .into_iter()
        .filter(|n| !n.ends_with(".reason.json"))
        .collect()
}

fn nzb(file: &str) -> Vec<u8> {
    NzbBuilder::new()
        .file(
            FileSpec::new(&format!("\"{file}\" yEnc (1/2)"))
                .segments(2)
                .declared(2),
        )
        .build()
}

const SHOW: &str = "Some.Show.S01E02.1080p.WEB-DL.x264-GRP.mkv";

fn sha_of(b: &[u8]) -> Sha256 {
    crate::fsops::digest(b)
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_stores_indexes_then_removes_source() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("My Show.nzb", &bytes);
    let mut c = e.candidates();
    assert_eq!(c.len(), 1);
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();

    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert_eq!(out.sha256, sha_of(&bytes));
    // Step 5: the blob is in the store, byte-identical, under the sha-only name.
    assert_eq!(e.store.get(&out.sha256).await.unwrap(), bytes);
    let blobs = e.blobs();
    assert_eq!(blobs.len(), 1);
    assert!(
        blobs[0]
            .to_string_lossy()
            .ends_with(&format!("{}.nzb", out.sha256.to_hex()))
    );
    // Step 6: row with scene category + ok log row linked to it.
    let row =
        e.db.get_release_by_sha(&out.sha256.to_hex())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.category_source, CategorySource::Scene);
    assert_ne!(row.category_id, 8010);
    assert_eq!(row.ingested_at, T0);
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, LogOutcome::Ok);
    assert_eq!(log[0].release_id, Some(row.id));
    assert_eq!(log[0].source, "watch");
    // Step 7: source gone; nothing in failed/ or duplicates/.
    assert!(!src.exists());
    assert!(names(&e.failed).is_empty() && names(&e.dups).is_empty());
    assert_eq!(e.pipeline.stats().ingested_ok, 1);
    assert_eq!(e.pipeline.stats().last_success_at, T0);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_is_moved_with_collision_free_hash_names() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    for (i, name) in ["a.nzb", "b.nzb", "c.nzb"].into_iter().enumerate() {
        e.put_watch(name, &bytes);
        let mut c = e.candidates();
        let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
        let want = if i == 0 {
            OutcomeKind::Ingested
        } else {
            OutcomeKind::Duplicate
        };
        assert_eq!(out.kind, want);
        assert!(!e.watch.join(name).exists());
        e.scanner.finish(&e.watch.join(name));
    }
    let sha8 = sha_of(&bytes).short();
    let stamp = "20231114T221320Z";
    assert_eq!(
        names(&e.dups),
        vec![
            format!("{stamp}-{sha8}-1.nzb"),
            format!("{stamp}-{sha8}.nzb")
        ]
    );
    assert_eq!(e.release_count().await, 1);
    assert_eq!(e.blobs().len(), 1);
    let log = e.db.list_ingest_log(10).await.unwrap();
    let outcomes: Vec<_> = log.iter().map(|l| l.outcome).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == LogOutcome::Duplicate)
            .count(),
        2
    );
    assert_eq!(e.pipeline.stats().duplicates, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_delete_action_removes_only_after_blob_confirmed() {
    let mut e = env(Opts {
        action: DuplicatesAction::Delete,
        from_subfolder: false,
    })
    .await;
    let bytes = nzb(SHOW);
    e.put_watch("a.nzb", &bytes);
    let mut c = e.candidates();
    e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();

    // The blob vanishes (disk damage): the duplicate path heals it from the incoming copy
    // before the watch file is deleted.
    e.store.delete(&sha_of(&bytes)).await.unwrap();
    e.put_watch("b.nzb", &bytes);
    e.scanner.finish(&e.watch.join("a.nzb"));
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    assert!(!e.watch.join("b.nzb").exists());
    assert!(names(&e.dups).is_empty());
    assert_eq!(e.store.get(&out.sha256).await.unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_identical_content_yields_one_row_and_one_blob() {
    for round in 0..10u8 {
        let mut e = env(OPTS).await;
        let bytes = nzb(&format!("{SHOW}.{round}"));
        for i in 0..6 {
            e.put_watch(&format!("f{i}.nzb"), &bytes);
        }
        let cands = e.candidates();
        assert_eq!(cands.len(), 6);
        let (handle, workers) = e.pipeline.spawn_workers(4);
        let mut set = tokio::task::JoinSet::new();
        for c in cands {
            let h = handle.clone();
            set.spawn(async move { h.submit(Job::watch(c)).await });
        }
        let mut kinds = Vec::new();
        while let Some(r) = set.join_next().await {
            kinds.push(r.unwrap().unwrap().kind);
        }
        assert_eq!(
            kinds
                .iter()
                .filter(|k| **k == OutcomeKind::Ingested)
                .count(),
            1
        );
        assert_eq!(e.release_count().await, 1);
        assert_eq!(e.blobs().len(), 1);
        assert!(names(&e.watch).is_empty());
        assert_eq!(names(&e.dups).len(), 5);
        drop(handle);
        for w in workers {
            w.await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn race_lost_at_commit_is_a_duplicate_not_an_error() {
    // Deterministic: another writer commits the same sha after our blob is stored but before
    // our transaction (hook runs at AfterPut), so `insert_release_logged` hits UNIQUE.
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    e.put_watch("a.nzb", &bytes);
    let db = e.db.clone();
    let b2 = bytes.clone();
    e.pipeline.set_hook(Some(Arc::new(move |p| {
        if p == CrashPoint::AfterPut {
            let analysis = nzb_core::analyze(
                &b2,
                &Limits::default(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            let new = NewRelease {
                analysis: &analysis,
                nzb_size_bytes: 1,
                source_name: None,
                source_label: None,
                category_id: 8010,
                category_source: CategorySource::Fallback,
                meta_json: None,
                scene: SceneColumns::default(),
                ingested_at: 1,
            };
            let db = db.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    db.insert_release(&new).await.unwrap();
                });
            });
        }
        false
    })));
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    assert_eq!(e.release_count().await, 1);
    assert_eq!(e.blobs().len(), 1);
    assert_eq!(names(&e.dups).len(), 1);
    assert!(names(&e.watch).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_before_put_leaves_source_and_nothing_else() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::BeforePut)));
    let mut c = e.candidates();
    assert!(e.pipeline.process(Job::watch(c.remove(0))).await.is_err());
    assert!(src.exists());
    assert!(e.blobs().is_empty());
    assert_eq!(e.release_count().await, 0);
    assert!(e.db.list_ingest_log(10).await.unwrap().is_empty());

    e.restart(OPTS);
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert_eq!(e.release_count().await, 1);
    assert!(!src.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_after_put_leaves_gc_able_orphan_and_reprocesses() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterPut)));
    let mut c = e.candidates();
    assert!(e.pipeline.process(Job::watch(c.remove(0))).await.is_err());
    // Orphan blob, no row, source untouched, store consistent.
    assert!(src.exists());
    assert_eq!(e.blobs().len(), 1);
    assert_eq!(e.release_count().await, 0);
    let v = e.store.verify().unwrap();
    assert_eq!((v.ok, v.corrupt.len(), v.unexpected), (1, 0, 0));
    // GC reclaims it once past the grace period (and not before).
    let referenced = e.db.list_shas().await.unwrap();
    let grace = e
        .store
        .gc(
            &referenced,
            SystemTime::now() - Duration::from_secs(3600),
            true,
        )
        .unwrap();
    assert!(grace.removed.is_empty());

    e.restart(OPTS);
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert_eq!(e.blobs().len(), 1);
    assert_eq!(e.release_count().await, 1);
    assert!(!src.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_orphan_blob_is_collected_by_checked_gc() {
    let mut e = env(OPTS).await;
    e.put_watch("a.nzb", &nzb(SHOW));
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterPut)));
    let mut c = e.candidates();
    assert!(e.pipeline.process(Job::watch(c.remove(0))).await.is_err());
    let referenced = e.db.list_shas().await.unwrap();
    let rep = e
        .store
        .gc_checked(
            &referenced,
            SystemTime::now() + Duration::from_secs(3600),
            false,
            &|_| true,
        )
        .unwrap();
    assert_eq!(rep.removed.len(), 1);
    assert!(e.blobs().is_empty());
    // Quarantined, not destroyed.
    assert_eq!(e.store.gc_trash_len().unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_after_commit_reprocesses_into_duplicates() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterCommit)));
    let mut c = e.candidates();
    assert!(e.pipeline.process(Job::watch(c.remove(0))).await.is_err());
    // Committed (row + ok log), source still present: the only duplicate-prone window.
    assert!(src.exists());
    assert_eq!(e.release_count().await, 1);
    assert_eq!(e.db.list_ingest_log(10).await.unwrap().len(), 1);

    e.restart(OPTS);
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    assert!(!src.exists());
    assert_eq!(names(&e.dups).len(), 1);
    assert_eq!(e.release_count().await, 1);
    assert_eq!(e.blobs().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_nzb_is_rejected_quarantined_and_logged() {
    let mut e = env(OPTS).await;
    let bad = b"<nzb><file subject='x'>".to_vec();
    let src = e.put_watch("bad.nzb", &bad);
    let mut c = e.candidates();
    let err = e
        .pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::Reject);
    assert!(err.code().starts_with("NZB_"), "{}", err.code());
    assert!(!src.exists());
    let sha8 = sha_of(&bad).short();
    assert_eq!(
        nzb_names(&e.failed),
        vec![format!("20231114T221320Z-{sha8}.nzb")]
    );
    assert!(e.blobs().is_empty());
    assert_eq!(e.release_count().await, 0);
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log[0].outcome, LogOutcome::Failed);
    assert_eq!(log[0].error_code.as_deref(), Some(err.code()));
    assert_eq!(e.pipeline.stats().failed, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_growth_past_limit_after_scan_preserves_unvalidated_source() {
    let mut e = env(OPTS).await;
    let src = e.put_watch("growing.nzb", b"small dummy input");
    let mut candidates = e.candidates();
    let grown = vec![b'x'; 64 * 1024 + 1];
    fs::write(&src, &grown).unwrap();
    let err = e
        .pipeline
        .process(Job::watch(candidates.remove(0)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "FILE_TOO_LARGE");
    assert_eq!(fs::read(&src).unwrap(), grown);
    assert!(names(&e.failed).is_empty(), "no quarantine or reason file");
    assert!(e.blobs().is_empty());
    assert_eq!(e.release_count().await, 0);
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].error_code.as_deref(), Some("FILE_TOO_LARGE"));

    // A normally read malformed watch input still has an identity and must be quarantined.
    let bad = b"<nzb><file subject='x'>";
    let malformed = e.put_watch("malformed.nzb", bad);
    let mut candidates = e.candidates();
    assert_eq!(
        candidates.len(),
        1,
        "the oversized source is not re-admitted"
    );
    let err = e
        .pipeline
        .process(Job::watch(candidates.remove(0)))
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::Reject);
    assert!(!malformed.exists());
    let quarantined = nzb_names(&e.failed);
    assert_eq!(quarantined.len(), 1);
    assert_eq!(fs::read(e.failed.join(&quarantined[0])).unwrap(), bad);
    assert_eq!(fs::read(&src).unwrap(), grown);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec005_hostile_names_never_reach_the_filesystem() {
    let e = env(OPTS).await;
    let bytes = nzb("../../../etc/evil.mkv");
    let (handle, _w) = e.pipeline.spawn_workers(1);
    let staged = e.staging.join("up1");
    fs::write(&staged, &bytes).unwrap();
    let out = handle
        .submit(
            Job::upload(nzb_store::LogSource::UploadApi, Payload::Staged(staged))
                .with_source_name(Some("../../../tmp/evil.nzb".into())),
        )
        .await
        .unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    let blobs = e.blobs();
    assert_eq!(blobs.len(), 1);
    let rel = blobs[0].strip_prefix(&e.store_root).unwrap();
    assert_eq!(rel.components().count(), 3, "aa/bb/<sha>.nzb");
    assert_eq!(
        rel.file_name().unwrap().to_string_lossy(),
        format!("{}.nzb", out.sha256.to_hex())
    );
    // Nothing was created next to the temp root.
    let top: Vec<String> = names(e.tmpdir.path())
        .into_iter()
        .filter(|n| !n.starts_with("t.sqlite"))
        .collect();
    assert_eq!(top, vec!["dups", "failed", "store", "tmp", "watch"]);
    assert!(names(&e.staging).is_empty(), "staged file consumed");
    let row = e.db.get_release(out.release_id).await.unwrap().unwrap();
    assert_eq!(row.source_name.as_deref(), Some("../../../tmp/evil.nzb"));
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_duplicate_is_acknowledged_without_a_second_copy() {
    let e = env(OPTS).await;
    let bytes = nzb(SHOW);
    for i in 0..2 {
        let staged = e.staging.join(format!("u{i}"));
        fs::write(&staged, &bytes).unwrap();
        let out = e
            .pipeline
            .process(Job::upload(
                nzb_store::LogSource::UploadUi,
                Payload::Staged(staged.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(
            out.kind,
            if i == 0 {
                OutcomeKind::Ingested
            } else {
                OutcomeKind::Duplicate
            }
        );
        assert!(!staged.exists());
    }
    assert!(names(&e.dups).is_empty());
    assert_eq!(e.blobs().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversize_and_invalid_hint_uploads_land_in_failed() {
    let e = env(OPTS).await;
    let big = e.staging.join("big");
    fs::write(&big, vec![b'x'; 64 * 1024 + 1]).unwrap();
    let err = e
        .pipeline
        .process(Job::upload(
            nzb_store::LogSource::UploadApi,
            Payload::Staged(big.clone()),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "FILE_TOO_LARGE");
    assert!(!big.exists());

    let ok = e.staging.join("ok");
    fs::write(&ok, nzb("blob.bin")).unwrap();
    let err = e
        .pipeline
        .process(
            Job::upload(nzb_store::LogSource::UploadApi, Payload::Staged(ok.clone()))
                .with_hint(Some("no.such.slug".into())),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "INVALID_CATEGORY");
    assert!(!ok.exists());
    assert_eq!(nzb_names(&e.failed).len(), 2);
    assert_eq!(e.release_count().await, 0);
    assert!(e.blobs().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn subfolder_hint_uses_slug_allowlist_only() {
    let mut e = env(Opts {
        action: DuplicatesAction::Move,
        from_subfolder: true,
    })
    .await;
    let tax = Taxonomy::builtin().unwrap();
    let anime = u32::from(tax.resolve("anime").unwrap());
    fs::create_dir(e.watch.join("anime")).unwrap();
    fs::create_dir(e.watch.join("8010")).unwrap(); // an id is not a slug
    fs::create_dir(e.watch.join("Anime")).unwrap(); // slug match is exact
    for (dir, file) in [
        ("anime", "one.bin"),
        ("8010", "two.bin"),
        ("Anime", "three.bin"),
    ] {
        fs::write(e.watch.join(dir).join("x.nzb"), nzb(file)).unwrap();
    }
    let cands = e.candidates();
    assert_eq!(cands.len(), 3);
    let mut by_dir = std::collections::HashMap::new();
    for c in cands {
        let sub = c.subfolder.clone().unwrap();
        let out = e.pipeline.process(Job::watch(c)).await.unwrap();
        let row = e.db.get_release(out.release_id).await.unwrap().unwrap();
        by_dir.insert(sub, (row.category_id, row.category_source));
    }
    assert_eq!(by_dir["anime"], (anime, CategorySource::Upload));
    assert_eq!(by_dir["8010"], (8010, CategorySource::Fallback));
    assert_eq!(by_dir["Anime"], (8010, CategorySource::Fallback));
}

#[tokio::test(flavor = "multi_thread")]
async fn hint_disagreement_is_recorded_and_scene_wins() {
    let e = env(OPTS).await;
    let staged = e.staging.join("u");
    fs::write(&staged, nzb(SHOW)).unwrap();
    let out = e
        .pipeline
        .process(
            Job::upload(nzb_store::LogSource::UploadUi, Payload::Staged(staged))
                .with_hint(Some("anime".into())),
        )
        .await
        .unwrap();
    let row = e.db.get_release(out.release_id).await.unwrap().unwrap();
    assert_eq!(row.category_source, CategorySource::Scene);
    let log = e.db.list_ingest_log(1).await.unwrap();
    assert!(
        log[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.starts_with("hint_disagreement")),
        "{:?}",
        log[0].detail
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sec007_file_changed_after_observation_is_not_ingested_or_moved() {
    let mut e = env(OPTS).await;
    let src = e.put_watch("a.nzb", &nzb(SHOW));
    let mut c = e.candidates();
    assert_eq!(c.len(), 1);
    // The writer touches the file after the scanner declared it stable.
    fs::write(&src, nzb("other.mkv")).unwrap();
    let err = e
        .pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "SOURCE_CHANGED");
    assert_eq!(err.disposition(), Disposition::Retry);
    // Retryable: the file stays where it is, nothing stored or indexed.
    assert!(src.exists());
    assert!(names(&e.failed).is_empty());
    assert!(e.blobs().is_empty());
    assert_eq!(e.release_count().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_cycle_ingests_stable_files_and_backs_off_leftovers() {
    let e = env(OPTS).await;
    let (handle, _w) = e.pipeline.spawn_workers(2);
    let scanner = Arc::new(std::sync::Mutex::new(scanner(
        &e.watch,
        &e.scan_clock,
        false,
    )));
    e.put_watch("a.nzb", &nzb(SHOW));
    let r1 = scan_cycle(&scanner, &handle, 10).await;
    assert_eq!(r1.submitted, 0, "first sight is never stable");
    e.scan_clock.0.fetch_add(6, Ordering::SeqCst);
    let r2 = scan_cycle(&scanner, &handle, 10).await;
    assert_eq!(r2.submitted, 1);
    assert_eq!(r2.backed_off, 0);
    assert!(names(&e.watch).is_empty());
    assert_eq!(e.release_count().await, 1);
    assert_eq!(scanner.lock().unwrap().tracked(), 0);

    // A failure that keeps the source (retryable: the destination dir is gone) is backed off.
    fs::remove_dir(&e.dups).unwrap();
    e.put_watch("dup.nzb", &nzb(SHOW));
    let _ = scan_cycle(&scanner, &handle, 10).await;
    e.scan_clock.0.fetch_add(6, Ordering::SeqCst);
    let r3 = scan_cycle(&scanner, &handle, 10).await;
    assert_eq!(r3.submitted, 1);
    assert_eq!(r3.backed_off, 1, "move failed: file stays, path backs off");
    assert!(e.watch.join("dup.nzb").exists());
    e.scan_clock.0.fetch_add(60, Ordering::SeqCst);
    let r4 = scan_cycle(&scanner, &handle, 10).await;
    assert_eq!(r4.submitted, 0, "no hot loop while backed off");
}

#[tokio::test(flavor = "multi_thread")]
async fn queue_is_bounded_and_reports_full() {
    let (tx, mut rx) = mpsc::channel::<Queued>(QUEUE_CAP);
    let handle = IngestHandle::from_sender(tx);
    assert_eq!(handle.free_slots(), QUEUE_CAP);
    let mut tasks = Vec::new();
    for _ in 0..QUEUE_CAP {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            h.submit(Job::upload(
                nzb_store::LogSource::UploadApi,
                Payload::Bytes(Vec::new()),
            ))
            .await
        }));
    }
    while handle.queue_len() < QUEUE_CAP {
        tokio::task::yield_now().await;
    }
    let err = handle
        .submit(Job::upload(
            nzb_store::LogSource::UploadApi,
            Payload::Bytes(Vec::new()),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "QUEUE_FULL");
    assert_eq!(handle.free_slots(), 0);
    // Closing the consumer turns waiting submitters into SHUTTING_DOWN. Drain until `None` instead of
    // dropping the receiver (review 34.4): `try_send` takes its permit before it pushes the message, and
    // `Drop for Rx` drains only messages already pushed, so a late push would own its `reply` inside a
    // channel the test's `handle` keeps alive and that submitter would wait forever. After `close`,
    // `recv` returns `None` only once no permit is outstanding, so every reply sender is dropped.
    rx.close();
    while rx.recv().await.is_some() {}
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap_err().code(), "SHUTTING_DOWN");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_loop_enforces_minimum_gap_despite_wakeups() {
    let e = env(OPTS).await;
    let (handle, _w) = e.pipeline.spawn_workers(1);
    let wake = Arc::new(WatchHandle::disabled());
    let beats = Arc::new(CountingWall::default());
    let scanner = Arc::new(std::sync::Mutex::new(scanner(
        &e.watch,
        &e.scan_clock,
        false,
    )));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let hb = Heartbeat::new();
    let start = Instant::now(); // before the loop starts: cycle 1 cannot predate it
    let task = tokio::spawn(run_scan_loop(
        scanner,
        handle,
        wake.clone(),
        RunnerConfig {
            scan_interval: Duration::from_secs(60),
            max_batch: 10,
        },
        hb.clone(),
        beats.clone(),
        async move {
            let _ = stop_rx.await;
        },
    ));
    // Poke for at least 2.3 s and until two cycles ran; the pacing check below only uses the
    // direction a loaded host cannot violate (the loop is never early).
    let give_up = Instant::now() + Duration::from_secs(60);
    loop {
        wake.poke();
        tokio::time::sleep(Duration::from_millis(20)).await;
        if start.elapsed() >= Duration::from_millis(2300) && beats.0.load(Ordering::SeqCst) >= 2 {
            break;
        }
        assert!(Instant::now() < give_up, "fewer than 2 cycles in 60 s");
    }
    let cycles = beats.0.load(Ordering::SeqCst);
    let elapsed = start.elapsed();
    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap();
    // Cycle k+1 starts >= k * MIN_SCAN_GAP after the first; a hot loop would be in the hundreds.
    // MIN_SCAN_GAP is 1 s, so at most floor(elapsed) + 1 cycles fit.
    let max = elapsed.as_secs() + 1;
    assert!(
        (2..=max).contains(&cycles),
        "cycles = {cycles} in {elapsed:?}"
    );
    assert!(hb.last().is_some());
}

#[derive(Default)]
struct CountingWall(AtomicU64);
impl WallClock for CountingWall {
    fn now_unix(&self) -> i64 {
        i64::try_from(self.0.fetch_add(1, Ordering::SeqCst) + 1).unwrap()
    }
}

#[test]
fn heartbeat_freshness_is_three_intervals() {
    let hb = Heartbeat::new();
    assert!(!hb.is_fresh(100, Duration::from_secs(5)));
    hb.beat(100);
    assert!(hb.is_fresh(114, Duration::from_secs(5)));
    assert!(!hb.is_fresh(115, Duration::from_secs(5)));
}

/// Waits (no sleeping) until the kernel's coarse ctime clock has ticked past `path`'s ctime.
fn pause(path: &std::path::Path) {
    assert!(nzb_testkit::wait_for_ctime_tick(path));
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_m1_same_length_rewrite_after_commit_leaves_the_users_file() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    let mtime = fs::metadata(&src).unwrap().modified().unwrap();
    let (p2, b2) = (src.clone(), bytes.clone());
    e.pipeline.set_hook(Some(Arc::new(move |p| {
        if p == CrashPoint::AfterCommit {
            // The user re-saves the file in place: same length, mtime restored.
            pause(&p2);
            let mut other = b2.clone();
            other[0] ^= 1;
            let f = fs::File::options().write(true).open(&p2).unwrap();
            std::io::Write::write_all(&mut &f, &other).unwrap();
            f.set_modified(mtime).unwrap();
        }
        false
    })));
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert!(src.exists(), "the changed file must survive");
    assert_ne!(fs::read(&src).unwrap(), bytes);
    assert_eq!(names(&e.watch), vec!["a.nzb"], "no trash left");
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l2_staged_upload_is_removed_when_the_job_never_runs() {
    let e = env(OPTS).await;
    let (tx, mut rx) = mpsc::channel::<Queued>(QUEUE_CAP);
    let handle = IngestHandle::from_sender(tx);
    let mut tasks = Vec::new();
    for _ in 0..QUEUE_CAP {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            h.submit(Job::upload(
                nzb_store::LogSource::UploadApi,
                Payload::Bytes(Vec::new()),
            ))
            .await
        }));
    }
    while handle.queue_len() < QUEUE_CAP {
        tokio::task::yield_now().await;
    }
    let staged = e.staging.join("full");
    fs::write(&staged, b"x").unwrap();
    let err = handle
        .submit(Job::upload(
            nzb_store::LogSource::UploadApi,
            Payload::Staged(staged.clone()),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "QUEUE_FULL");
    assert!(!staged.exists(), "QueueFull must not leak the staged file");
    // Close and drain instead of dropping (the race of `queue_is_bounded_and_reports_full`): a submitter whose push
    // lands after `Drop for Rx` drained would wait for its reply forever (seen once in CI as a 360 s hang).
    rx.close();
    while rx.recv().await.is_some() {}
    let staged = e.staging.join("closed");
    fs::write(&staged, b"x").unwrap();
    let err = handle
        .submit(Job::upload(
            nzb_store::LogSource::UploadApi,
            Payload::Staged(staged.clone()),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "SHUTTING_DOWN");
    assert!(
        !staged.exists(),
        "ShuttingDown must not leak the staged file"
    );
    for t in tasks {
        let _ = t.await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l4_panicking_job_is_logged_internal_and_quarantined_after_bounded_retries() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    // A commit panic retains the identity established by the successful source read.
    e.pipeline.panic_on_commit(sha_of(&bytes));
    let (handle, _w) = e.pipeline.spawn_workers(1);
    for attempt in 1..=3 {
        e.scanner = scanner(&e.watch, &e.scan_clock, false);
        let mut c = e.candidates();
        let err = handle.submit(Job::watch(c.remove(0))).await.unwrap_err();
        assert_eq!(err.code(), "INTERNAL");
        // The first two panics keep the file for another try; the third quarantines it.
        assert_eq!(src.exists(), attempt < 3, "attempt {attempt}");
    }
    assert_eq!(nzb_names(&e.failed).len(), 1);
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log.len(), 3);
    assert!(
        log.iter()
            .all(|l| l.error_code.as_deref() == Some("INTERNAL"))
    );
    // The worker survived: a healthy job still runs.
    e.put_watch("b.nzb", &nzb("other.mkv"));
    e.scanner = scanner(&e.watch, &e.scan_clock, false);
    let mut c = e.candidates();
    assert_eq!(
        handle.submit(Job::watch(c.remove(0))).await.unwrap().kind,
        OutcomeKind::Ingested
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preparation_panic_without_recovered_identity_preserves_watch_source() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    let src = e.put_watch("a.nzb", &bytes);
    e.pipeline.set_hook(Some(Arc::new(|p| {
        assert!(p != CrashPoint::BeforePut, "injected");
        false
    })));
    let (handle, _w) = e.pipeline.spawn_workers(1);
    for _ in 0..3 {
        e.scanner = scanner(&e.watch, &e.scan_clock, false);
        let mut candidates = e.candidates();
        let err = handle
            .submit(Job::watch(candidates.remove(0)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INTERNAL");
        assert_eq!(fs::read(&src).unwrap(), bytes);
        assert!(names(&e.failed).is_empty());
    }
    // These are retry-only failures: repeated panics without identity cannot flood ingest_log.
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].error_code.as_deref(), Some("INTERNAL"));
    assert_eq!(e.pipeline.stats().failed, 1);

    // Once the fault is removed, the worker can process the original file normally.
    e.pipeline.set_hook(None);
    e.scanner = scanner(&e.watch, &e.scan_clock, false);
    let mut candidates = e.candidates();
    assert_eq!(
        handle
            .submit(Job::watch(candidates.remove(0)))
            .await
            .unwrap()
            .kind,
        OutcomeKind::Ingested
    );
    assert!(!src.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l4_panicking_staged_upload_goes_to_failed() {
    let e = env(OPTS).await;
    e.pipeline.set_hook(Some(Arc::new(|p| {
        assert!(p != CrashPoint::AfterPut, "injected");
        false
    })));
    let (handle, _w) = e.pipeline.spawn_workers(1);
    let staged = e.staging.join("p");
    fs::write(&staged, nzb(SHOW)).unwrap();
    let err = handle
        .submit(Job::upload(
            nzb_store::LogSource::UploadApi,
            Payload::Staged(staged.clone()),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "INTERNAL");
    assert!(!staged.exists());
    assert_eq!(nzb_names(&e.failed).len(), 1);
    assert!(nzb_names(&e.failed)[0].contains("-up"));
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l6_retry_class_failures_are_logged_once_per_ten_attempts() {
    let mut e = env(OPTS).await;
    let src = e.put_watch("a.nzb", &nzb(SHOW));
    for _ in 0..12 {
        e.scanner = scanner(&e.watch, &e.scan_clock, false);
        let mut c = e.candidates();
        // Touch the file after observation: SOURCE_CHANGED (retry class).
        pause(&src);
        fs::write(&src, nzb(SHOW)).unwrap();
        let err = e
            .pipeline
            .process(Job::watch(c.remove(0)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "SOURCE_CHANGED");
    }
    assert_eq!(e.db.list_ingest_log(100).await.unwrap().len(), 2);
    assert_eq!(e.pipeline.stats().failed, 2);
    assert!(src.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l2_rejected_uploads_rotate_oldest_first_but_watch_files_never() {
    let mut e = env(OPTS).await;
    let mut cfg2 = cfg(&e.watch, &e.failed, &e.dups, OPTS);
    cfg2.failed_uploads_max_files = 3;
    e.pipeline = Pipeline::new(cfg2, e.db.clone(), e.store.clone(), e.wall.clone()).unwrap();
    // A rejected watch file and a stranger's file already sit in failed/.
    e.put_watch("bad.nzb", b"<nzb>");
    let mut c = e.candidates();
    e.pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap_err();
    fs::write(e.failed.join("users-own-file.nzb"), b"mine").unwrap();
    let watch_reject = nzb_names(&e.failed)
        .into_iter()
        .find(|n| !n.contains("-up") && n != "users-own-file.nzb")
        .unwrap();
    for i in 0..6u8 {
        e.wall.0.fetch_add(1, Ordering::SeqCst);
        let staged = e.staging.join(format!("s{i}"));
        fs::write(&staged, [b'<', i]).unwrap();
        e.pipeline
            .process(Job::upload(
                nzb_store::LogSource::UploadApi,
                Payload::Staged(staged),
            ))
            .await
            .unwrap_err();
    }
    let n = nzb_names(&e.failed);
    assert_eq!(n.iter().filter(|x| x.contains("-up")).count(), 3);
    assert!(n.contains(&watch_reject) && n.contains(&"users-own-file.nzb".to_owned()));
    // The three newest uploads (stamps ...:19, :20, :21 after the start) survived.
    let mut ups: Vec<_> = n.into_iter().filter(|x| x.contains("-up")).collect();
    ups.sort();
    assert!(ups[0].as_str() > "20231114T221323Z", "{ups:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_l7_restart_removes_stale_part_files() {
    let mut e = env(OPTS).await;
    fs::write(
        e.dups.join(".20231114T221320Z-abcdef12.1-2-3.part"),
        b"partial",
    )
    .unwrap();
    fs::write(
        e.failed.join(".20231114T221320Z-abcdef12.1-2-4.part"),
        b"partial",
    )
    .unwrap();
    fs::write(e.failed.join("keep.nzb"), b"x").unwrap();
    e.restart(OPTS);
    assert!(names(&e.dups).is_empty());
    assert_eq!(names(&e.failed), vec!["keep.nzb"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn t031_m3_scan_cycle_flags_gone_workers() {
    let e = env(OPTS).await;
    let (tx, rx) = mpsc::channel::<Queued>(QUEUE_CAP);
    let handle = IngestHandle::from_sender(tx);
    drop(rx);
    let scanner = Arc::new(std::sync::Mutex::new(scanner(
        &e.watch,
        &e.scan_clock,
        false,
    )));
    let src = e.put_watch("a.nzb", &nzb(SHOW));
    let _ = scan_cycle(&scanner, &handle, 10).await;
    e.scan_clock.0.fetch_add(6, Ordering::SeqCst);
    let rep = scan_cycle(&scanner, &handle, 10).await;
    assert!(rep.workers_gone);
    assert!(src.exists(), "the user's file is untouched");

    // The loop itself reports it and does not beat the heartbeat.
    let hb = Heartbeat::new();
    let exit = run_scan_loop(
        scanner,
        handle,
        Arc::new(WatchHandle::disabled()),
        RunnerConfig {
            scan_interval: Duration::from_secs(1),
            max_batch: 10,
        },
        hb.clone(),
        e.wall.clone(),
        std::future::pending::<()>(),
    )
    .await;
    assert_eq!(exit, ScanExit::WorkersGone);
    assert!(hb.last().is_none());
}

#[path = "failure_tests.rs"]
mod failure_tests;

#[path = "group_tests.rs"]
mod group_tests;

#[path = "import_tests.rs"]
mod import_tests;

#[path = "sidecar_tests.rs"]
mod sidecar_tests;

#[cfg(test)]
mod scan_interval_regressions {
    use super::*;

    async fn await_cycles(
        beats: &CountingWall,
        task: &tokio::task::JoinHandle<ScanExit>,
        wanted: u64,
    ) -> bool {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if task.is_finished() {
                    return false;
                }
                if beats.0.load(Ordering::SeqCst) >= wanted {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or(false)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unrepresentable_scan_interval_keeps_wakeups_and_shutdown_working() {
        let interval = Duration::from_secs(u64::try_from(i64::MAX).unwrap());
        assert!(
            tokio::time::Instant::now().checked_add(interval).is_none(),
            "the regression fixture must exceed this platform's Instant range"
        );
        let e = env(OPTS).await;
        let (handle, workers) = e.pipeline.spawn_workers(1);
        let wake = Arc::new(WatchHandle::disabled());
        let beats = Arc::new(CountingWall::default());
        let scanner = Arc::new(std::sync::Mutex::new(scanner(
            &e.watch,
            &e.scan_clock,
            false,
        )));
        let heartbeat = Heartbeat::new();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let started = Instant::now();
        let mut task = tokio::spawn(run_scan_loop(
            scanner,
            handle,
            Arc::clone(&wake),
            RunnerConfig {
                scan_interval: interval,
                max_batch: 10,
            },
            heartbeat.clone(),
            beats.clone(),
            async move {
                let _ = stop_rx.await;
            },
        ));

        let first_completed = await_cycles(&beats, &task, 1).await;
        // Without an event the extreme periodic interval must not turn into a hot loop.
        if first_completed {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let before_wake = beats.0.load(Ordering::SeqCst);
        wake.poke();
        let second_completed = await_cycles(&beats, &task, 2).await;
        let elapsed = started.elapsed();
        let cycles = beats.0.load(Ordering::SeqCst);

        // Always stop and collect the real runner before asserting its behavior. A broken
        // runner yields its actual JoinError (including the overflow panic) on the baseline.
        let _ = stop_tx.send(());
        let exit = tokio::time::timeout(Duration::from_secs(3), &mut task).await;
        if exit.is_err() {
            task.abort();
            let _ = task.await;
        }
        for worker in workers {
            tokio::time::timeout(Duration::from_secs(3), worker)
                .await
                .expect("idle ingest worker stops after the scan handle is dropped")
                .unwrap();
        }
        assert!(
            matches!(&exit, Ok(Ok(ScanExit::Shutdown))),
            "unrepresentable scan interval must preserve the real runner until shutdown: {exit:?}"
        );
        assert!(
            first_completed && second_completed,
            "watcher wake must complete a second scan"
        );
        assert_eq!(
            before_wake, 1,
            "no periodic rescan before the watcher event"
        );
        assert_eq!(
            cycles, 2,
            "one watcher event starts exactly one additional scan"
        );
        assert!(
            elapsed >= MIN_SCAN_GAP,
            "watcher event must respect the minimum scan gap"
        );
        assert_eq!(heartbeat.last(), Some(2));
    }
}
