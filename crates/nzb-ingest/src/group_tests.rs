//! T114: commit groups, the in-flight byte budget and crash safety at group boundaries (SEC-008), on the backend of
//! the CI leg.

use super::*;

/// Submits every candidate at once and returns the outcomes in candidate order.
async fn submit_all(
    handle: &IngestHandle,
    cands: Vec<Candidate>,
) -> Vec<Result<IngestOutcome, IngestError>> {
    let mut set = tokio::task::JoinSet::new();
    for (i, c) in cands.into_iter().enumerate() {
        let h = handle.clone();
        set.spawn(async move { (i, h.submit(Job::watch(c)).await) });
    }
    let mut out: Vec<(usize, Result<IngestOutcome, IngestError>)> = Vec::new();
    while let Some(r) = set.join_next().await {
        out.push(r.unwrap());
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

async fn stop(handle: IngestHandle, workers: Vec<tokio::task::JoinHandle<()>>) {
    drop(handle);
    for w in workers {
        w.await.unwrap();
    }
}

fn put_many(e: &Env, n: usize) -> Vec<PathBuf> {
    (0..n)
        .map(|i| e.put_watch(&format!("f{i:03}.nzb"), &nzb(&format!("{SHOW}.{i}"))))
        .collect()
}

fn settings(workers: usize) -> IngestSettings {
    IngestSettings {
        workers,
        queue_cap: 256,
        ..IngestSettings::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t114_concurrent_jobs_share_commit_groups() {
    let mut e = env(OPTS).await;
    let srcs = put_many(&e, 60);
    let cands = e.candidates();
    assert_eq!(cands.len(), 60);
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap().kind == OutcomeKind::Ingested)
    );
    assert_eq!(e.release_count().await, 60);
    assert!(
        srcs.iter().all(|p| !p.exists()),
        "sources go after the commit"
    );
    let st = e.pipeline.stats();
    assert_eq!(st.ingested_ok, 60);
    // Groups, not one transaction per NZB (the exact count depends on scheduling).
    assert!(
        (1..60).contains(&st.commit_groups),
        "{} groups for 60 jobs",
        st.commit_groups
    );
    assert_eq!(st.inflight_bytes, 0, "every job returned its bytes");
    assert_eq!(e.db.list_ingest_log(100).await.unwrap().len(), 60);
    stop(handle, workers).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_008_crash_before_the_group_commit_keeps_every_source() {
    let mut e = env(OPTS).await;
    let srcs = put_many(&e, 12);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::BeforeGroupCommit)));
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap_err().code() == "INTERNAL")
    );
    stop(handle, workers).await;
    // Every blob is durable (orphans, reclaimable by GC), nothing is committed, every source is still there.
    assert!(srcs.iter().all(|p| p.exists()));
    assert_eq!(e.blobs().len(), 12);
    assert_eq!(e.release_count().await, 0);
    assert!(e.db.list_ingest_log(10).await.unwrap().is_empty());
    assert!(names(&e.failed).is_empty() && names(&e.dups).is_empty());

    e.restart(OPTS);
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap().kind == OutcomeKind::Ingested)
    );
    stop(handle, workers).await;
    assert_eq!(e.release_count().await, 12);
    assert_eq!(e.blobs().len(), 12);
    assert!(srcs.iter().all(|p| !p.exists()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_008_crash_after_the_group_commit_reprocesses_into_duplicates() {
    let mut e = env(OPTS).await;
    let srcs = put_many(&e, 12);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterCommit)));
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    assert!(out.iter().all(Result::is_err));
    stop(handle, workers).await;
    // The group committed (rows and ok log rows), the sources were not removed yet.
    assert_eq!(e.release_count().await, 12);
    assert_eq!(e.db.list_ingest_log(100).await.unwrap().len(), 12);
    assert!(srcs.iter().all(|p| p.exists()));

    e.restart(OPTS);
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap().kind == OutcomeKind::Duplicate)
    );
    stop(handle, workers).await;
    assert_eq!(e.release_count().await, 12);
    assert_eq!(nzb_names(&e.dups).len(), 12);
    assert!(srcs.iter().all(|p| !p.exists()));
    assert_eq!(e.blobs().len(), 12);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t114_identical_content_in_one_group_yields_one_row() {
    let mut e = env(OPTS).await;
    let bytes = nzb(SHOW);
    for i in 0..8 {
        e.put_watch(&format!("same{i}.nzb"), &bytes);
    }
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(settings(4));
    let out = submit_all(&handle, cands).await;
    let kinds: Vec<OutcomeKind> = out.into_iter().map(|r| r.unwrap().kind).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == OutcomeKind::Ingested)
            .count(),
        1
    );
    stop(handle, workers).await;
    assert_eq!(e.release_count().await, 1);
    assert_eq!(e.blobs().len(), 1);
    assert!(names(&e.watch).is_empty());
    assert_eq!(nzb_names(&e.dups).len(), 7);
}

/// Review 34 L5 through the pipeline: with a zero writer hold every SQLite group commits one job and defers the rest,
/// which lead the next group; nothing is lost or reordered into a failure. Postgres ignores the hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t114_deferred_jobs_are_committed_by_later_groups() {
    let mut e = env(OPTS).await;
    let srcs = put_many(&e, 30);
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(IngestSettings {
        writer_hold: Duration::ZERO,
        ..settings(4)
    });
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap().kind == OutcomeKind::Ingested)
    );
    stop(handle, workers).await;
    assert_eq!(e.release_count().await, 30);
    assert!(srcs.iter().all(|p| !p.exists()));
    if e.db.backend() == nzb_store::DbBackend::Sqlite {
        assert!(e.pipeline.stats().commit_groups >= 30);
    }
}

/// ARCHITECTURE v3 5.2: memory is bounded by bytes. A 2 KiB budget admits at most two of these (~1 KiB) NZBs between
/// read and finish whatever the worker count; a job larger than the whole budget takes all of it and still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t114_inflight_bytes_stay_within_the_budget() {
    let mut e = env(OPTS).await;
    put_many(&e, 16);
    let mut big = NzbBuilder::new();
    for i in 0..30 {
        big = big.file(FileSpec::new(&format!("\"big.part{i:02}.rar\" yEnc (1/2)")).segments(2));
    }
    let big = big.build();
    assert!(big.len() > 4096);
    e.put_watch("big.nzb", &big);
    let seen = Arc::new(AtomicU64::new(0));
    let p = e.pipeline.clone();
    let s2 = Arc::clone(&seen);
    e.pipeline.set_hook(Some(Arc::new(move |point| {
        if point == CrashPoint::AfterPut {
            s2.fetch_max(p.inflight_bytes(), Ordering::SeqCst);
            // Let the other workers try to read more while this job holds its share.
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    })));
    let cands = e.candidates();
    let (handle, workers) = e.pipeline.spawn(IngestSettings {
        max_inflight_bytes: 2048,
        ..settings(4)
    });
    let out = submit_all(&handle, cands).await;
    assert!(
        out.iter()
            .all(|r| r.as_ref().unwrap().kind == OutcomeKind::Ingested)
    );
    e.pipeline.set_hook(None);
    stop(handle, workers).await;
    assert_eq!(e.release_count().await, 17);
    let max = seen.load(Ordering::SeqCst);
    assert!((1024..=2048).contains(&max), "max in flight {max}");
    assert_eq!(e.pipeline.stats().inflight_bytes, 0);
}

/// SEC-092 / ARCHITECTURE v3 3.2: the scanner offers nothing while the outbox depth is above the limit and resumes
/// below half of it; the files wait in the watch folder untouched. Then the store probe of `serve` on the leg's
/// backend: rows nobody indexes yet are outbox depth.
#[tokio::test(flavor = "multi_thread")]
async fn sec_092_scanner_pauses_at_lag_limit() {
    let e = env(OPTS).await;
    let srcs = put_many(&e, 3);
    let depth = Arc::new(AtomicU64::new(150));
    let d2 = Arc::clone(&depth);
    let gate = LagGate::new(
        100,
        Arc::new(move || {
            let d = d2.load(Ordering::SeqCst);
            Box::pin(async move { Some(d) })
        }),
    );
    let (handle, workers) = e.pipeline.spawn(settings(2));
    let scanner = Arc::new(std::sync::Mutex::new(scanner(
        &e.watch,
        &e.scan_clock,
        false,
    )));
    let cycle = || scan_cycle_gated(&scanner, &handle, 10, Some(&gate));
    let r = cycle().await;
    assert!(r.paused && r.submitted == 0 && gate.is_paused());
    e.scan_clock.0.fetch_add(6, Ordering::SeqCst);
    // Still above half the limit: stays paused (no flapping at the limit).
    depth.store(80, Ordering::SeqCst);
    let r = cycle().await;
    assert!(r.paused && r.submitted == 0);
    assert!(srcs.iter().all(|p| p.exists()));
    // Below half: resumes and ingests (two observations for stability).
    depth.store(40, Ordering::SeqCst);
    let _ = cycle().await;
    e.scan_clock.0.fetch_add(6, Ordering::SeqCst);
    let r = cycle().await;
    assert!(!r.paused && !gate.is_paused());
    assert_eq!(r.submitted, 3);
    assert!(srcs.iter().all(|p| !p.exists()));
    // `pause_at = 0` never pauses.
    assert!(
        LagGate::new(0, Arc::new(|| Box::pin(async { Some(u64::MAX) })))
            .admit()
            .await
    );

    // The store probe: three new releases are three outbox rows nobody consumed.
    let store_gate = LagGate::for_store(e.db.clone(), 2);
    assert!(!store_gate.admit().await);
    let lag = e.db.search_outbox_lag().await.unwrap();
    assert_eq!(lag.depth, 3);
    stop(handle, workers).await;
}

#[tokio::test]
async fn sec_092_lag_gate_resumes_at_small_odd_and_extreme_thresholds() {
    for limit in [1_u64, 2, 3, 5, 100, u64::MAX - 1] {
        let depth = Arc::new(AtomicU64::new(limit + 1));
        let probe = Arc::clone(&depth);
        let gate = LagGate::new(
            limit,
            Arc::new(move || {
                let current = probe.load(Ordering::SeqCst);
                Box::pin(async move { Some(current) })
            }),
        );
        assert!(!gate.admit().await, "pause above {limit}");
        depth.store(limit.div_ceil(2), Ordering::SeqCst);
        assert!(
            !gate.admit().await,
            "stay paused at or above half of {limit}"
        );
        depth.store(limit.div_ceil(2) - 1, Ordering::SeqCst);
        assert!(gate.admit().await, "resume below half of {limit}");
        assert!(!gate.is_paused());
        depth.store(limit, Ordering::SeqCst);
        assert!(
            gate.admit().await,
            "do not flap at the pause boundary {limit}"
        );
        depth.store(limit + 1, Ordering::SeqCst);
        assert!(!gate.admit().await, "pause again above {limit}");
    }
}

/// Review 38 L5: a group that fails as a whole (not one job: a deadlock, a lost connection, a CHECK) is committed job
/// by job; every job ends inserted, every source goes, and each job has exactly one `ok` log row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t114_a_failed_group_is_committed_job_by_job() {
    let mut e = env(OPTS).await;
    let srcs = put_many(&e, 6);
    let cands = e.candidates();
    let mut group = Vec::new();
    for c in cands {
        match e.pipeline.prepare(Job::watch(c)).await {
            crate::pipeline::Prepared::Ready(r) => group.push(*r),
            crate::pipeline::Prepared::Done(r) => panic!("not prepared: {r:?}"),
        }
    }
    assert_eq!(group.len(), 6);
    e.pipeline.fail_next_group();
    let done = e.pipeline.commit(group, DEFAULT_WRITER_HOLD).await;
    assert_eq!(e.pipeline.stats().commit_groups, 1);
    for (ready, c) in done {
        assert!(matches!(c, crate::pipeline::Committed::Inserted(_)));
        let out = e.pipeline.finish(ready, c).await.unwrap();
        assert_eq!(out.kind, OutcomeKind::Ingested);
    }
    assert_eq!(e.release_count().await, 6);
    assert!(srcs.iter().all(|p| !p.exists()));
    let log = e.db.list_ingest_log(100).await.unwrap();
    assert_eq!(log.len(), 6);
    assert!(log.iter().all(|l| l.outcome == LogOutcome::Ok));
    let shas: std::collections::HashSet<_> = log.iter().map(|l| l.sha256).collect();
    assert_eq!(shas.len(), 6, "exactly one ok row per job");
}

/// A session can expire while a failed batch waits for its individual retries. The injected
/// clock advances only after preparation, so a retry using the original batch time is rejected
/// by this regression even though the account itself remains enabled.
#[tokio::test]
async fn sec_036_upload_commit_retries_refresh_session_expiry() {
    struct RetryClock {
        wall: Arc<FakeWall>,
        step: AtomicI64,
    }
    impl WallClock for RetryClock {
        fn now_unix(&self) -> i64 {
            self.wall
                .0
                .fetch_add(self.step.load(Ordering::SeqCst), Ordering::SeqCst)
        }
    }

    let mut e = env(OPTS).await;
    let clock = Arc::new(RetryClock {
        wall: Arc::clone(&e.wall),
        step: AtomicI64::new(0),
    });
    e.pipeline = Pipeline::new(
        cfg(&e.watch, &e.failed, &e.dups, OPTS),
        e.db.clone(),
        e.store.clone(),
        clock.clone(),
    )
    .unwrap();
    let user_id =
        e.db.create_account_operator(
            &nzb_store::NewAccount {
                username: "uploader",
                password_hash: "unused-test-hash",
                role: None,
            },
            nzb_store::AccountPolicy::default(),
            T0,
        )
        .await
        .unwrap();
    let id_hash = [7; 32];
    e.db.insert_session(
        &nzb_store::NewSession {
            id_hash,
            user_id,
            stage: nzb_store::SessionStage::Active,
            csrf_token: [8; 32],
            now: T0,
            expires_at: T0 + 1,
            ip: None,
            user_agent: None,
        },
        5,
    )
    .await
    .unwrap();
    let mut group = Vec::new();
    for n in 0..2 {
        let job = Job::upload(
            nzb_store::LogSource::UploadUi,
            Payload::Bytes(nzb(&format!("{SHOW}.{n}"))),
        )
        .with_uploader(nzb_store::Uploader::Session { user_id, id_hash });
        match e.pipeline.prepare(job).await {
            crate::pipeline::Prepared::Ready(r) => group.push(*r),
            crate::pipeline::Prepared::Done(r) => panic!("not prepared: {r:?}"),
        }
    }
    assert_eq!(group.len(), 2);
    assert_eq!(clock.now_unix(), T0);
    e.pipeline.fail_next_group();
    clock.step.store(1, Ordering::SeqCst);
    let done = e.pipeline.commit(group, DEFAULT_WRITER_HOLD).await;
    assert_eq!(done.len(), 2);
    for (ready, result) in done {
        assert!(matches!(
            result,
            crate::pipeline::Committed::Failed(IngestError::UploaderRefused)
        ));
        assert!(matches!(
            e.pipeline.finish(ready, result).await,
            Err(IngestError::UploaderRefused)
        ));
    }
    assert_eq!(e.release_count().await, 0);
    assert_eq!(e.db.search_outbox_lag().await.unwrap().depth, 0);
    assert_eq!(e.db.list_ingest_log(10).await.unwrap().len(), 0);
}

/// A panic inside a group commit is contained: the group (rolled back) is committed job by job, the
/// other jobs are inserted and only the job that panics alone fails, counted as a panic; the writer
/// (and so the process) keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_group_commit_is_committed_job_by_job() {
    let mut e = env(OPTS).await;
    let _srcs = put_many(&e, 4);
    let cands = e.candidates();
    let mut group = Vec::new();
    for c in cands {
        match e.pipeline.prepare(Job::watch(c)).await {
            crate::pipeline::Prepared::Ready(r) => group.push(*r),
            crate::pipeline::Prepared::Done(r) => panic!("not prepared: {r:?}"),
        }
    }
    assert_eq!(group.len(), 4);
    let poison = group[1].sha256();
    e.pipeline.panic_on_commit(poison);
    let done = e.pipeline.commit(group, DEFAULT_WRITER_HOLD).await;
    let (mut inserted, mut failed) = (0, 0);
    for (ready, c) in done {
        let sha = ready.sha256();
        let panicked = ready.panicked();
        match c {
            crate::pipeline::Committed::Inserted(_) => {
                assert_ne!(sha, poison);
                inserted += 1;
                e.pipeline.finish(ready, c).await.unwrap();
            }
            crate::pipeline::Committed::Failed(IngestError::Internal) => {
                assert_eq!(sha, poison);
                assert!(panicked);
                failed += 1;
                assert!(matches!(
                    e.pipeline.finish(ready, c).await,
                    Err(IngestError::Internal)
                ));
            }
            _ => panic!("unexpected commit outcome"),
        }
    }
    assert_eq!((inserted, failed), (3, 1));
    assert_eq!(e.release_count().await, 3);
}
