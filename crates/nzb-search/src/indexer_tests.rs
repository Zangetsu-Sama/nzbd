//! Indexer: outbox semantics (SEC-092), crash at every step, rebuild by generation with replay
//! (review L6 a), servability checks (SEC-091, review M2 a), writer failures (review I3).
#![allow(
    clippy::cast_possible_wrap,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::Arc;

use crate::clock::{StepClock, SystemClock};
use crate::config::SearchConfig;
use crate::engine::{Engine, IndexDir, Payload, WriterSettings};
use crate::error::SearchError;
use crate::index::{SearchService, ServiceStatus};
use crate::indexer::{Fault, Indexer, IndexerSettings, QUARANTINE_DOC_BUILD};
use crate::testkit::{EPOCH, MemSource};

fn settings() -> IndexerSettings {
    let w = WriterSettings {
        heap_bytes: 32 << 20,
        threads: 1,
    };
    IndexerSettings {
        batch: 3,
        scan_batch: 2,
        scan_commit_docs: 2,
        writer: w,
        rebuild_writer: w,
    }
}

async fn start(dir: &std::path::Path, src: &MemSource) -> (Arc<SearchService>, Indexer<MemSource>) {
    let svc = SearchService::new(SearchConfig::default(), Arc::new(SystemClock::new()));
    let ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(dir).unwrap(),
        settings(),
    )
    .await
    .unwrap();
    (svc, ix)
}

/// The index holds exactly the database's rows (by id and version), and it is served.
fn assert_consistent(svc: &SearchService, src: &MemSource, ctx: &str) {
    assert_eq!(svc.status(), ServiceStatus::Serving, "{ctx}");
    let engine = svc.engine().unwrap();
    assert_eq!(
        engine.live_versions().unwrap(),
        src.db().expected(),
        "{ctx}"
    );
    assert!(src.db().outbox.is_empty(), "{ctx}");
    assert!(!src.db().replay, "{ctx}");
    assert!(src.db().replay_ids.is_empty(), "{ctx}");
    assert!(engine.payload().max_seq <= src.db().last_seq, "{ctx}");
}

fn seed(src: &MemSource, n: i64) {
    let mut db = src.db();
    for id in 1..=n {
        db.upsert(id, &format!("release {id}"));
    }
}

/// A batch of changes: edits, deletes, inserts, duplicate and out-of-order outbox rows.
fn churn(src: &MemSource, round: i64) {
    let mut db = src.db();
    db.upsert(2, &format!("edited {round}"));
    db.delete(3 + round);
    db.upsert(100 + round, "new");
    db.enqueue(1);
    db.enqueue(100 + round);
}

#[tokio::test]
async fn sec_092_outbox_rows_carry_no_payload() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 2);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "seeded");
    // The row says only "release 1 changed"; the indexer reads whatever is current when it runs.
    src.db().enqueue(1);
    src.db().rows.get_mut(&1).unwrap().title = "current title".into();
    src.db().rows.get_mut(&1).unwrap().version = 9;
    let r = ix.run_once().await.unwrap();
    assert_eq!((r.rows, r.upserts, r.deletes), (1, 1, 0));
    assert_eq!(
        svc.engine().unwrap().live_versions().unwrap(),
        [(1, 9), (2, 1)]
    );
    // Exactly the rows read are consumed: a batch of 3 out of 5 leaves 2.
    for id in [1, 2, 1, 2, 1] {
        src.db().enqueue(id);
    }
    let r = ix.run_once().await.unwrap();
    assert_eq!(r.rows, 3);
    assert_eq!(src.db().outbox.len(), 2);
    ix.settle().await.unwrap();
    assert!(src.db().outbox.is_empty());
}

#[tokio::test]
async fn sec_092_replayed_and_reordered_rows_are_harmless() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 6);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    // Rows for vanished ids, duplicates, and rows whose seq order is the reverse of the changes.
    {
        let mut db = src.db();
        db.delete(4);
        db.upsert(5, "five again");
        let rows: Vec<(i64, i64)> = db.outbox.iter().map(|(s, i)| (*s, *i)).collect();
        db.outbox.clear();
        for (k, (_, id)) in rows.iter().rev().enumerate() {
            db.outbox.insert(1000 - k as i64, *id);
        }
        db.last_seq = 1000;
        for id in [4, 4, 5, 999, 5] {
            db.enqueue(id);
        }
    }
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "reordered");
    // Applying everything again changes nothing.
    for id in 1..=6 {
        src.db().enqueue(id);
    }
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "replayed");
}

#[tokio::test]
async fn sec_092_poison_release_is_quarantined_and_queue_continues() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 3);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    {
        let mut db = src.db();
        db.poison.insert(2);
        db.upsert(2, "poison");
        db.upsert(3, "fine");
    }
    // Attempts 1 and 2: release 3 is applied, release 2's row stays for a retry.
    for attempt in 1..=2 {
        let r = ix.run_once().await.unwrap();
        assert_eq!(r.quarantined, 0, "attempt {attempt}");
        assert_eq!(src.db().outbox.values().copied().collect::<Vec<_>>(), [2]);
    }
    // Attempt 3: quarantined with a fixed code, row consumed, queue empty.
    let r = ix.run_once().await.unwrap();
    assert_eq!(r.quarantined, 1);
    assert_eq!(src.db().quarantine.get(&2), Some(&QUARANTINE_DOC_BUILD));
    assert!(src.db().outbox.is_empty());
    // Later changes still flow.
    src.db().upsert(1, "after");
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "after quarantine");
}

/// Review 55: a release whose load fails every time (the outbox itself answers) must not stall the
/// queue forever. After `MAX_STORE_ERROR_ROUNDS` failed rounds the batch is bisected with
/// per-document loads; the rest is indexed, and the release is quarantined after `MAX_DOC_ATTEMPTS`.
#[tokio::test]
async fn sec_092_unloadable_release_does_not_stall_the_outbox() {
    use crate::indexer::{MAX_DOC_ATTEMPTS, MAX_STORE_ERROR_ROUNDS};

    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 6);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    {
        let mut db = src.db();
        for id in 1..=6 {
            db.upsert(id, "changed");
        }
        db.load_error_for = Some(2);
    }
    // Below the threshold a source error never bisects and never quarantines.
    for _ in 1..MAX_STORE_ERROR_ROUNDS {
        assert!(matches!(ix.run_once().await, Err(SearchError::Store(_))));
        assert!(src.db().quarantine.is_empty());
        assert_eq!(src.db().outbox.len(), 6);
    }
    let bound = MAX_STORE_ERROR_ROUNDS * (MAX_DOC_ATTEMPTS + 2);
    let mut rounds = 0;
    while !src.db().outbox.is_empty() {
        rounds += 1;
        assert!(
            rounds <= bound,
            "the outbox must drain within a bounded number of rounds"
        );
        let _ = ix.run_once().await;
    }
    assert_eq!(src.db().quarantine.get(&2), Some(&QUARANTINE_DOC_BUILD));
    assert_eq!(
        src.db().quarantine.len(),
        1,
        "healthy releases are never quarantined"
    );
    let engine = svc.engine().unwrap();
    let live: Vec<(i64, u64)> = engine
        .live_versions()
        .unwrap()
        .into_iter()
        .filter(|(id, _)| *id != 2)
        .collect();
    assert_eq!(live, [(1, 2), (3, 2), (4, 2), (5, 2), (6, 2)]);
    assert_eq!(svc.status(), ServiceStatus::Serving);
    // Later changes still flow.
    src.db().load_error_for = None;
    src.db().upsert(1, "after");
    ix.settle().await.unwrap();
    assert!(src.db().outbox.is_empty());
}

pub(crate) const LIVE_FAULTS: [Fault; 5] = [
    Fault::AfterRead,
    Fault::AfterLoad,
    Fault::AfterApply,
    Fault::AfterCommit,
    Fault::AfterConsume,
];

/// A source timeout after one chunk was queued is not a bad document or a broken index writer.
/// Keep the committed generation available, discard all pending changes and retry the same outbox.
#[tokio::test]
async fn store_failure_after_first_chunk_preserves_outbox_and_recovers_without_rebuild() {
    use crate::indexer::{LOAD_CHUNK, MAX_WRITER_FAILURES};

    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    let count = LOAD_CHUNK + 3;
    let last_id = i64::try_from(count).unwrap();
    {
        let mut db = src.db();
        for id in 1..=last_id {
            if id != 3 {
                db.upsert(id, "before source failure");
            }
        }
    }
    // A large enough round really crosses the load boundary; small scan settings would only
    // spend time repeatedly committing the seed data and do not help this failure scenario.
    let mut config = settings();
    config.batch = count;
    config.scan_batch = count;
    config.scan_commit_docs = count;
    let svc = SearchService::new(SearchConfig::default(), Arc::new(StepClock::new(0)));
    let mut ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(d.path()).unwrap(),
        config,
    )
    .await
    .unwrap();
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "before source failure");
    let engine = svc.engine().unwrap();
    let before_versions = engine.live_versions().unwrap();
    let before_payload = engine.payload();
    let before_generation = IndexDir::read_only(d.path()).current();
    let pending = {
        let mut db = src.db();
        // All three mutation kinds are in the successful first chunk: delete 1, insert 3,
        // replace the other rows. The timeout occurs only when loading the last three ids.
        db.delete(1);
        for id in 2..=last_id {
            db.upsert(id, "changed while source is unavailable");
        }
        db.load_error_for = Some(last_id);
        db.outbox.clone()
    };
    assert_eq!(pending.len(), count);
    for _ in 0..=MAX_WRITER_FAILURES {
        src.db().load_calls.clear();
        let err = ix.run_once().await.unwrap_err();
        assert!(
            matches!(err, SearchError::Store(nzb_store::StoreError::Io(ref e))
            if e.kind() == std::io::ErrorKind::TimedOut)
        );
        {
            let db = src.db();
            assert_eq!(
                db.load_calls.len(),
                2,
                "a store outage must not trigger bisection"
            );
            assert_eq!(db.load_calls[0].0, LOAD_CHUNK);
            assert!(
                db.load_calls[0].1 > 0,
                "the first chunk was actually loaded"
            );
            assert_eq!(db.load_calls[1], (3, 0));
            assert_eq!(
                db.outbox, pending,
                "no uncommitted change may be acknowledged"
            );
            assert!(
                db.quarantine.is_empty(),
                "healthy documents must not be quarantined"
            );
        }
        assert_eq!(svc.status(), ServiceStatus::Serving);
        assert!(
            !ix.rebuild_needed(),
            "source failures must not exhaust the writer failure budget"
        );
        assert_eq!(engine.payload(), before_payload);
        assert_eq!(engine.live_versions().unwrap(), before_versions);
        // Looking at the old reader alone cannot prove that queued deletes/adds were discarded.
        // A later unrelated commit must not publish any part of the failed round either.
        engine.commit(&engine.payload()).unwrap();
        assert_eq!(engine.live_versions().unwrap(), before_versions);
    }
    {
        let mut db = src.db();
        db.load_error_for = None;
        db.load_calls.clear();
        // Retry must load the latest source, rather than reuse the chunk from the failed attempt.
        db.upsert(2, "latest value after source recovery");
    }
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "source recovered in the same process");
    assert_eq!(IndexDir::read_only(d.path()).current(), before_generation);
    assert!(src.db().quarantine.is_empty());
    assert_eq!(engine.payload().max_seq, src.db().last_seq);
    assert!(engine.live_versions().unwrap().contains(&(2, 3)));
}

/// Source failures during writer diagnosis must not turn healthy releases into poison documents.
#[tokio::test]
async fn store_failure_during_writer_isolation_preserves_outbox_and_discards_pending() {
    use crate::indexer::{LOAD_CHUNK, MAX_WRITER_FAILURES};

    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    let count = LOAD_CHUNK + 3;
    let last_id = i64::try_from(count).unwrap();
    seed(&src, last_id);
    let mut config = settings();
    config.batch = count;
    config.scan_batch = count;
    config.scan_commit_docs = count;
    let svc = SearchService::new(SearchConfig::default(), Arc::new(StepClock::new(0)));
    let mut ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(d.path()).unwrap(),
        config,
    )
    .await
    .unwrap();
    ix.settle().await.unwrap();
    let engine = svc.engine().unwrap();
    let before_versions = engine.live_versions().unwrap();
    let before_payload = engine.payload();
    let before_generation = IndexDir::read_only(d.path()).current();
    let pending = {
        let mut db = src.db();
        db.delete(1);
        for id in 2..=last_id {
            db.upsert(id, "changed before writer diagnosis");
        }
        db.load_error_for = Some(last_id);
        db.outbox.clone()
    };

    for _ in 0..=MAX_WRITER_FAILURES {
        src.db().load_calls.clear();
        // The first load succeeds, but its apply finds a lost writer. Isolation reopens it,
        // queues the first chunk, then hits the source timeout while loading the next chunk.
        engine.poison_writer();
        let err = ix.run_once().await.unwrap_err();
        assert!(
            matches!(err, SearchError::Store(nzb_store::StoreError::Io(ref e))
            if e.kind() == std::io::ErrorKind::TimedOut)
        );
        {
            let db = src.db();
            assert_eq!(db.load_calls.len(), 3, "source errors must stop bisection");
            for call in &db.load_calls[..2] {
                assert_eq!(call.0, LOAD_CHUNK);
                assert!(call.1 > 0);
            }
            assert_eq!(db.load_calls[2], (3, 0));
            assert_eq!(db.outbox, pending, "every event must remain replayable");
            assert!(db.quarantine.is_empty(), "all source documents are healthy");
        }
        assert_eq!(svc.status(), ServiceStatus::Serving);
        assert!(
            !ix.rebuild_needed(),
            "source errors are not writer failures"
        );
        assert_eq!(engine.payload(), before_payload);
        assert_eq!(engine.live_versions().unwrap(), before_versions);
        // Prove queued replacements and the delete did not survive the interrupted diagnosis.
        engine.commit(&engine.payload()).unwrap();
        assert_eq!(engine.live_versions().unwrap(), before_versions);
    }

    src.db().load_error_for = None;
    ix.settle().await.unwrap();
    assert_consistent(
        &svc,
        &src,
        "source recovered after interrupted writer diagnosis",
    );
    assert!(src.db().quarantine.is_empty());
    assert_eq!(IndexDir::read_only(d.path()).current(), before_generation);
}

pub(crate) const REBUILD_FAULTS: [Fault; 9] = [
    Fault::RebuildAfterBegin,
    Fault::RebuildAfterCreate,
    Fault::RebuildAfterScanCommit,
    Fault::RebuildAfterScan,
    Fault::RebuildAfterReplay,
    Fault::RebuildAfterDrainCommit,
    Fault::RebuildAfterCurrent,
    Fault::RebuildAfterInstall,
    Fault::RebuildAfterFinish,
];

/// Crash (drop everything without cleanup) at every step of a live round and of a rebuild, restart
/// from disk + database, settle: the index equals the database every time, and it is served.
#[tokio::test]
async fn crash_at_every_step_keeps_index_and_database_consistent() {
    for fault in LIVE_FAULTS {
        let d = tempfile::tempdir().unwrap();
        let src = MemSource::with(EPOCH);
        seed(&src, 8);
        {
            let (_svc, mut ix) = start(d.path(), &src).await;
            ix.settle().await.unwrap();
            churn(&src, 1);
            ix.inject(fault);
            let e = ix.run_once().await.unwrap_err();
            assert!(matches!(e, SearchError::Injected), "{fault:?} {e:?}");
        } // crash: indexer, service and engines dropped, uncommitted work lost
        churn(&src, 2);
        let (svc, mut ix) = start(d.path(), &src).await;
        assert!(
            !ix.rebuild_needed(),
            "{fault:?}: a live crash needs no rebuild"
        );
        ix.settle().await.unwrap();
        assert_consistent(&svc, &src, &format!("{fault:?}"));
    }

    for fault in REBUILD_FAULTS {
        let d = tempfile::tempdir().unwrap();
        let src = MemSource::with(EPOCH);
        seed(&src, 9);
        {
            let (_svc, mut ix) = start(d.path(), &src).await;
            ix.settle().await.unwrap();
            // The operator asks for a rebuild; writes keep arriving during the scan.
            src.db().rebuild_requested = true;
            src.db().scan_hook = Some(Box::new(|db, after| {
                if after == 2 {
                    db.upsert(1, "edited below the scan position");
                    db.upsert(50, "inserted during the scan");
                    db.delete(7);
                }
            }));
            churn(&src, 1);
            ix.inject(fault);
            let e = ix.rebuild().await.unwrap_err();
            assert!(matches!(e, SearchError::Injected), "{fault:?} {e:?}");
        }
        src.db().scan_hook = None;
        churn(&src, 2);
        let (svc, mut ix) = start(d.path(), &src).await;
        ix.settle().await.unwrap();
        assert_consistent(&svc, &src, &format!("{fault:?}"));
        assert!(!src.db().rebuild_requested, "{fault:?}");
        // One generation left, and it is the active one.
        let dir = IndexDir::open(d.path()).unwrap();
        assert_eq!(
            dir.generations().unwrap(),
            [dir.current().unwrap()],
            "{fault:?}"
        );
    }
}

#[tokio::test]
async fn sec_091_rebuild_loses_no_change_committed_during_the_scan() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 10);
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    // While the scan is at id 4, release 2 (already scanned) changes and 3 (scanned) is trashed. The
    // live round on the old generation consumes those outbox rows; the replay flag (committed before
    // the scan) copies their ids into search_replay, so the new generation gets them too.
    src.db().scan_hook = Some(Box::new(|db, after| {
        if after == 4 {
            db.upsert(2, "changed during the scan");
            db.delete(3);
        }
    }));
    let g = ix.rebuild().await.unwrap();
    assert_eq!(g, 2);
    assert_consistent(&svc, &src, "after rebuild");
    assert_eq!(svc.engine().unwrap().live_versions().unwrap()[1], (2, 2));
}

#[tokio::test]
async fn sec_091_stale_epoch_index_is_not_served() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 4);
    {
        let (_svc, mut ix) = start(d.path(), &src).await;
        ix.settle().await.unwrap();
    }
    // `db restore-finish` rotated the epoch: the old index belongs to another database state.
    src.db().epoch = [9; 16];
    let (svc, mut ix) = start(d.path(), &src).await;
    assert_eq!(svc.status(), ServiceStatus::Degraded("epoch mismatch"));
    assert!(svc.engine().is_err());
    assert!(ix.rebuild_needed());
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "rebuilt");
    assert_eq!(svc.engine().unwrap().payload().epoch, [9; 16]);
}

#[tokio::test]
async fn old_index_schema_is_rebuilt_before_being_served() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 4);
    {
        let (_svc, mut ix) = start(d.path(), &src).await;
        ix.settle().await.unwrap();
    }
    let meta_path = d.path().join("gen-1/meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    let mut payload: serde_json::Value =
        serde_json::from_str(meta["payload"].as_str().unwrap()).unwrap();
    payload["schema"] = serde_json::Value::from(crate::schema::INDEX_SCHEMA_VERSION - 1);
    meta["payload"] = serde_json::Value::from(payload.to_string());
    std::fs::write(meta_path, meta.to_string()).unwrap();
    let (svc, mut ix) = start(d.path(), &src).await;
    assert!(matches!(svc.status(), ServiceStatus::Degraded(_)));
    assert!(svc.engine().is_err());
    assert!(ix.rebuild_needed());
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "rebuilt after index format upgrade");
    assert_eq!(
        svc.engine().unwrap().payload().schema,
        crate::schema::INDEX_SCHEMA_VERSION
    );
}

#[tokio::test]
async fn sec_091_index_ahead_of_database_is_not_served() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 4);
    {
        let (_svc, mut ix) = start(d.path(), &src).await;
        ix.settle().await.unwrap();
        src.db()
            .upsert(4, "applied, then the database is rolled back");
        ix.settle().await.unwrap();
    }
    // A physical restore / volume rollback nzbd did not perform: same epoch, but the outbox sequence
    // is behind what the index has applied (and would reissue ids).
    {
        let mut db = src.db();
        db.last_seq -= 1;
        db.rows.get_mut(&4).unwrap().version = 1;
        db.rows.get_mut(&4).unwrap().title = "release 4".into();
    }
    let (svc, mut ix) = start(d.path(), &src).await;
    assert_eq!(
        svc.status(),
        ServiceStatus::Degraded("index ahead of the database")
    );
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "rebuilt");
}

#[tokio::test]
async fn sec_091_corrupt_index_triggers_degraded_mode_and_rebuild() {
    for corruption in ["meta", "payload", "current", "segment"] {
        let d = tempfile::tempdir().unwrap();
        let src = MemSource::with(EPOCH);
        seed(&src, 5);
        {
            let (_svc, mut ix) = start(d.path(), &src).await;
            ix.settle().await.unwrap();
        }
        let gen_dir = d.path().join("gen-1");
        match corruption {
            "meta" => std::fs::write(gen_dir.join("meta.json"), b"{not json").unwrap(),
            "payload" => {
                let meta = std::fs::read_to_string(gen_dir.join("meta.json")).unwrap();
                let mut v: serde_json::Value = serde_json::from_str(&meta).unwrap();
                v["payload"] = serde_json::Value::from("{\"v\":1,\"epoch\":\"zz\"}");
                std::fs::write(gen_dir.join("meta.json"), v.to_string()).unwrap();
            }
            "current" => std::fs::write(d.path().join("CURRENT"), b"../../etc\n").unwrap(),
            _ => {
                for e in std::fs::read_dir(&gen_dir).unwrap() {
                    let p = e.unwrap().path();
                    if p.extension().is_some_and(|x| x == "idx") {
                        std::fs::remove_file(p).unwrap();
                    }
                }
            }
        }
        let (svc, mut ix) = start(d.path(), &src).await;
        if corruption != "segment" {
            assert!(
                matches!(svc.status(), ServiceStatus::Degraded(_)),
                "{corruption}"
            );
            assert!(ix.rebuild_needed(), "{corruption}");
        }
        ix.settle()
            .await
            .unwrap_or_else(|e| panic!("{corruption}: {e:?}"));
        if corruption == "segment" && svc.status() != ServiceStatus::Serving {
            ix.settle().await.unwrap();
        }
        assert_consistent(&svc, &src, corruption);
    }
}

#[tokio::test]
async fn sec_091_writer_panic_does_not_crash_loop() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 3);
    let clock = Arc::new(StepClock::new(0));
    let svc = SearchService::new(SearchConfig::default(), clock.clone());
    let mut ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(d.path()).unwrap(),
        settings(),
    )
    .await
    .unwrap();
    ix.settle().await.unwrap();
    // A panic in the writer task: the round fails, the writer is reopened, nothing is lost.
    src.db().upsert(1, "x");
    ix.inject(Fault::WriterPanic);
    assert!(matches!(ix.run_once().await, Err(SearchError::Task)));
    assert_eq!(svc.status(), ServiceStatus::Serving);
    // Two more failures far apart (outside the 10-minute window): still serving.
    for _ in 0..2 {
        clock.advance(11 * 60 * 1000);
        assert!(ix.run_once().await.is_err());
        assert_eq!(svc.status(), ServiceStatus::Serving);
    }
    // Three within the window: degraded mode and a rebuild, never a process exit.
    assert!(ix.run_once().await.is_err());
    assert!(ix.run_once().await.is_err());
    assert!(matches!(
        svc.status(),
        ServiceStatus::Degraded("index writer failed")
    ));
    assert!(ix.rebuild_needed());
    // The same indexer (same process) recovers by rebuilding once the fault is gone.
    ix.clear_faults();
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "after writer failures");
}

#[tokio::test]
async fn sec_091_second_indexer_refuses_to_start() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 2);
    let (svc1, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    let svc2 = SearchService::new(SearchConfig::default(), Arc::new(SystemClock::new()));
    let r = Indexer::start(
        svc2,
        src.clone(),
        IndexDir::open(d.path()).unwrap(),
        settings(),
    )
    .await;
    assert!(
        matches!(
            r,
            Err(SearchError::Engine(tantivy::TantivyError::LockFailure(..)))
        ),
        "{r:?}"
    );
    drop(ix);
    drop(svc1);
    // Once the first one is gone (process exit releases the lock), a new one starts.
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "restarted");
}

#[tokio::test]
async fn interrupted_rebuild_resumes_after_its_last_scan_commit() {
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    seed(&src, 12);
    {
        let (_svc, mut ix) = start(d.path(), &src).await;
        ix.inject(Fault::RebuildAfterScanCommit);
        assert!(ix.rebuild().await.is_err());
    }
    // The first scan commit recorded scan_upto_id = 2; the resumed scan starts after it.
    src.db().scan_calls.clear();
    let (svc, mut ix) = start(d.path(), &src).await;
    ix.settle().await.unwrap();
    assert_eq!(src.db().scan_calls.first(), Some(&2));
    assert_consistent(&svc, &src, "resumed");
}

/// Review 39 L1: generation GC deletes only directories nzbd created (they carry the marker); a `gen-<n>` directory
/// with user files (an index directory configured onto data) survives, and the read-only open changes no mode.
#[test]
fn sec_091_unmarked_generation_directories_are_never_removed() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let ro = IndexDir::read_only(d.path());
    assert_eq!(ro.current(), None);
    let mode = std::fs::metadata(d.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "read_only changes no mode");
    let dir = IndexDir::open(d.path()).unwrap();
    let user = dir.generation(7);
    std::fs::create_dir(&user).unwrap();
    std::fs::write(user.join("user-owned.nzb"), b"<nzb/>").unwrap();
    let w = WriterSettings {
        heap_bytes: 32 << 20,
        threads: 1,
    };
    let ours = dir.generation(8);
    drop(Engine::create(&ours, Payload::new(EPOCH), w).unwrap());
    assert_eq!(dir.generations().unwrap(), vec![7, 8]);
    dir.remove(7).unwrap();
    dir.remove(8).unwrap();
    assert!(
        user.join("user-owned.nzb").is_file(),
        "a directory nzbd did not make survives"
    );
    assert!(!ours.exists(), "an nzbd generation is removed");
}

#[test]
fn payload_round_trips_and_rejects_anything_else() {
    let mut p = Payload::new([0xab; 16]);
    p.max_seq = 42;
    assert_eq!(Payload::decode(&p.encode()).unwrap(), p);
    p.scan_upto_id = Some(7);
    assert_eq!(Payload::decode(&p.encode()).unwrap(), p);
    for bad in [
        "",
        "{}",
        "[]",
        "{\"v\":2,\"epoch\":\"abababababababababababababababab\",\"schema\":1,\"max_seq\":0}",
        "{\"v\":1,\"epoch\":\"ABABABABABABABABABABABABABABABAB\",\"schema\":1,\"max_seq\":0}",
        "{\"v\":1,\"epoch\":\"ab\",\"schema\":1,\"max_seq\":0}",
        "{\"v\":1,\"epoch\":\"abababababababababababababababab\",\"schema\":1,\"max_seq\":-1}",
        "{\"v\":1,\"epoch\":\"abababababababababababababababab\",\"schema\":1,\"max_seq\":0,\"x\":1}",
    ] {
        assert!(Payload::decode(bad).is_err(), "{bad}");
    }
    assert!(Payload::decode(&"x".repeat(5000)).is_err());
    // An in-RAM engine starts with the payload it was given.
    let e = Engine::in_ram(Payload::new(EPOCH)).unwrap();
    assert_eq!(e.payload(), Payload::new(EPOCH));
}

#[tokio::test]
async fn sec_095_indexer_batch_memory_is_bounded() {
    use crate::indexer::{BATCH_TEXT_BYTES, LOAD_CHUNK, MAX_DOC_TEXT_BYTES};
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    // 300 releases with 10,000-file-sized name lists (~1 MiB of text each, 4x the index cap).
    let names = "f".repeat(100) + " ";
    {
        let mut db = src.db();
        for id in 1..=300 {
            db.upsert(id, &format!("big {id}"));
            db.rows.get_mut(&id).unwrap().files = names.repeat(10_000);
        }
    }
    let w = WriterSettings {
        heap_bytes: 64 << 20,
        threads: 1,
    };
    let svc = SearchService::new(SearchConfig::default(), Arc::new(SystemClock::new()));
    let mut ix = Indexer::start(
        Arc::clone(&svc),
        src.clone(),
        IndexDir::open(d.path()).unwrap(),
        IndexerSettings {
            batch: 10_000,
            scan_batch: 10_000,
            scan_commit_docs: 1_000_000,
            writer: w,
            rebuild_writer: w,
        },
    )
    .await
    .unwrap();
    // Rebuild (scan) and then a live round over every release (load).
    ix.settle().await.unwrap();
    for id in 1..=300 {
        src.db().enqueue(id);
    }
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "big releases");
    let db = src.db();
    // No load call asked for more than LOAD_CHUNK ids or returned more than the batch budget.
    assert_ne!(db.load_calls.len(), 0);
    for (ids, bytes) in &db.load_calls {
        assert!(*ids <= LOAD_CHUNK, "{ids}");
        assert!(*bytes <= BATCH_TEXT_BYTES, "{bytes}");
    }
    // Each scan call stops once the budget is reached (one document may cross it).
    assert!(db.scan_bytes.len() > 1);
    for b in &db.scan_bytes {
        assert!(*b <= BATCH_TEXT_BYTES + MAX_DOC_TEXT_BYTES, "{b}");
    }
}

#[tokio::test]
async fn a_document_that_breaks_the_writer_is_quarantined_not_retried_forever() {
    use crate::engine::FAIL_ON;
    use crate::indexer::QUARANTINE_DOC_INDEX;
    // Ids unique to this test (FAIL_ON is process-wide).
    const BAD_LIVE: i64 = 9_100_005;
    const BAD_SCAN: i64 = 9_100_017;
    let d = tempfile::tempdir().unwrap();
    let src = MemSource::with(EPOCH);
    {
        let mut db = src.db();
        for id in 9_100_001..=9_100_020 {
            db.upsert(id, &format!("release {id}"));
        }
    }
    FAIL_ON.lock().unwrap().insert(BAD_SCAN);
    let (svc, mut ix) = start(d.path(), &src).await;
    // Rebuild: the scan batch with the bad document fails, bisection finds it, the scan goes on.
    ix.settle().await.unwrap();
    assert_eq!(svc.status(), ServiceStatus::Serving);
    assert_eq!(
        src.db().quarantine.get(&BAD_SCAN),
        Some(&QUARANTINE_DOC_INDEX)
    );
    assert_consistent(&svc, &src, "after rebuild");
    // Live round: the batch fails once, the culprit is quarantined, its neighbours are indexed.
    FAIL_ON.lock().unwrap().insert(BAD_LIVE);
    {
        let mut db = src.db();
        for id in [9_100_004, BAD_LIVE, 9_100_006] {
            db.upsert(id, "edited");
        }
    }
    let r = ix.run_once().await.unwrap();
    assert_eq!(r.quarantined, 1);
    assert_eq!(
        src.db().quarantine.get(&BAD_LIVE),
        Some(&QUARANTINE_DOC_INDEX)
    );
    assert_eq!(svc.status(), ServiceStatus::Serving);
    ix.settle().await.unwrap();
    assert_consistent(&svc, &src, "after live round");
    let mut f = FAIL_ON.lock().unwrap();
    f.remove(&BAD_LIVE);
    f.remove(&BAD_SCAN);
}

#[test]
fn search_readers_have_no_doc_store_cache() {
    // `NonZeroUsize::new(0)` is `None`: tantivy builds no `LruCache` for our searchers (review 32 L1).
    assert_eq!(crate::engine::DOC_STORE_CACHE_BLOCKS, 0);
    let src = include_str!("engine.rs");
    assert!(src.contains(".doc_store_cache_num_blocks(DOC_STORE_CACHE_BLOCKS)"));
    let e = Engine::in_ram(Payload::new(EPOCH)).unwrap();
    let stats = e.searcher().doc_store_cache_stats();
    assert_eq!(stats.num_entries, 0);
}
