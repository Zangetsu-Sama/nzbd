//! T081 store tests: `release_trash` moves, the `TrashStore` contract on `FsStore`, and the
//! refusal rules of the identity-checked purge. Names carry their SEC id (`sec_050` =
//! destructive actions, `sec_051` = purge scope, see `docs/SECURITY.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names
)]

use std::fs;
use std::os::unix::fs::symlink;
use std::sync::Arc;

use nzb_core::Sha256;

use crate::fs_store::digest;
use crate::release_tests::{analysis, count, new, open, sha};
use crate::{
    FsStore, NzbStore, StillUnreferenced, StoreError, TrashFinish, TrashPurge, TrashStore, sha8,
};

fn setup() -> (tempfile::TempDir, FsStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::open(dir.path().join("store")).unwrap();
    (dir, store)
}

fn blob(n: u8) -> (Sha256, Vec<u8>) {
    let bytes = format!("<nzb>trash {n}</nzb>").into_bytes();
    (digest(&bytes), bytes)
}

/// A delete start time later than any mtime written by the test (no race to model).
fn later() -> std::time::SystemTime {
    std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
}

fn yes() -> StillUnreferenced {
    Arc::new(|_| true)
}

fn no() -> StillUnreferenced {
    Arc::new(|_| false)
}

fn trash_file(dir: &tempfile::TempDir, sha: &Sha256) -> std::path::PathBuf {
    dir.path()
        .join("store/.trash")
        .join(format!("{}.nzb", sha.to_hex()))
}

#[tokio::test]
async fn sec_050_trash_release_moves_every_row_and_frees_the_sha() {
    let (_d, db) = open().await;
    let a = analysis(1, "Gone.1080p", 100, Some(5));
    let id = db.insert_release(&new(&a)).await.unwrap();
    sqlx::query(
        "INSERT INTO ingest_log (ts, source, outcome, release_id) VALUES (1,'watch','ok',?)",
    )
    .bind(id)
    .execute(db.writer())
    .await
    .unwrap();

    let row = db
        .trash_release(id, 1_800_000_000, "user:1", Some("192.0.2.1"))
        .await
        .unwrap();
    assert_eq!(row.sha256, sha(1));
    assert_eq!(row.title, a.title);
    assert_eq!(row.original_id, id);
    assert_eq!(row.deleted_at, 1_800_000_000);

    // Gone from every table the UI reads.
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);
    assert_eq!(db.get_release(id).await.unwrap(), None);
    assert!(db.list_shas().await.unwrap().is_empty());
    // The log keeps its row, unlinked; the audit row has no title and only a sha prefix.
    assert_eq!(count(&db, "ingest_log").await, 1);
    let linked: Option<i64> = sqlx::query_scalar("SELECT release_id FROM ingest_log")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(linked, None);
    let audit = db.recent_audit(5).await.unwrap();
    let ev = audit.iter().find(|r| r.event == "release_delete").unwrap();
    assert_eq!(ev.actor.as_deref(), Some("user:1"));
    assert_eq!(
        ev.detail.as_deref(),
        Some(&*format!(
            "release={id} sha8=01010101 added_by=none title=Gone.1080p"
        ))
    );
    // T138: the title is kept in the row so the delete stays explainable.
    assert!(ev.detail.as_deref().unwrap().contains("Gone"));

    // Trash listing and lookups.
    assert_eq!(db.list_trash(10).await.unwrap(), vec![row.clone()]);
    assert_eq!(db.get_trash(row.id).await.unwrap(), Some(row.clone()));
    assert_eq!(db.trash_shas().await.unwrap(), [sha(1)].into());

    // The same bytes can be ingested again (fresh release), and trashed again: one trash row
    // per digest, refreshed.
    let id2 = db.insert_release(&new(&a)).await.unwrap();
    // (SQLite may hand out the freed rowid again; nothing relies on ids being unique over time.)
    let again = db
        .trash_release(id2, 1_800_000_500, "user:1", None)
        .await
        .unwrap();
    assert_eq!(again.id, row.id);
    assert_eq!(again.deleted_at, 1_800_000_500);
    assert_eq!(count(&db, "release_trash").await, 1);

    // Unknown id: typed error, nothing written.
    let audits = count(&db, "audit_log").await;
    assert!(matches!(
        db.trash_release(999, 1, "user:1", None).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(count(&db, "audit_log").await, audits);

    assert!(db.forget_trash(row.id).await.unwrap());
    assert!(!db.forget_trash(row.id).await.unwrap());
}

#[tokio::test]
async fn sec_050_stage_then_finish_moves_the_blob_and_keeps_it_readable() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(1);
    s.put(sha, &bytes).await.unwrap();

    s.trash_stage(&sha).await.unwrap();
    // Staging adds a name, it never takes the live blob away (crash-safe order).
    assert!(s.exists(&sha).await.unwrap());
    assert!(trash_file(&dir, &sha).is_file());
    s.trash_stage(&sha).await.unwrap(); // idempotent

    assert_eq!(
        s.trash_finish(&sha, later(), yes()).await.unwrap(),
        TrashFinish::Removed
    );
    assert!(!s.exists(&sha).await.unwrap());
    assert!(matches!(s.get(&sha).await, Err(StoreError::NotFound)));
    assert_eq!(s.trash_read(&sha).await.unwrap(), bytes);
    let l = s.trash_list(100).await.unwrap();
    assert_eq!((l.items.len(), l.foreign), (1, 0));
    assert_eq!(l.items[0].sha, sha);
    assert_eq!(l.items[0].size, u64::try_from(bytes.len()).unwrap());
    // `store verify` does not treat the trash area as unexpected entries.
    let rep = s.verify().unwrap();
    assert_eq!((rep.ok, rep.unexpected), (0, 0));

    // Re-ingest of the same bytes: a fresh live blob, the trash copy is independent.
    s.put(sha, &bytes).await.unwrap();
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(s.trash_read(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn sec_050_finish_keeps_the_live_blob_when_it_is_referenced_again() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(2);
    s.put(sha, &bytes).await.unwrap();
    s.trash_stage(&sha).await.unwrap();
    // A re-ingest raced the delete: the closure says "referenced".
    assert_eq!(
        s.trash_finish(&sha, later(), no()).await.unwrap(),
        TrashFinish::Kept
    );
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert!(trash_file(&dir, &sha).is_file());
    // No scratch file is left in `.tmp/`.
    assert_eq!(
        fs::read_dir(dir.path().join("store/.tmp")).unwrap().count(),
        0
    );
}

/// T085-L1: a dedup `put` of the same bytes after the delete started refreshes the live mtime;
/// the "still unreferenced" answer of the database cannot be trusted yet (the re-ingest has
/// not inserted its release), so the live name must stay.
#[tokio::test]
async fn sec_050_finish_keeps_a_blob_refreshed_by_a_racing_reingest() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(20);
    s.put(sha, &bytes).await.unwrap();
    let started = std::time::SystemTime::now();
    s.trash_stage(&sha).await.unwrap();
    // Re-ingest wins the race: AlreadyExists, mtime refreshed, release not inserted yet.
    s.put(sha, &bytes).await.unwrap();
    // The database still says "unreferenced".
    assert_eq!(
        s.trash_finish(&sha, started, yes()).await.unwrap(),
        TrashFinish::Kept
    );
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(
        fs::read_dir(dir.path().join("store/.tmp")).unwrap().count(),
        0
    );
    // Without a refresh since the start the same call drops the live name.
    assert_eq!(
        s.trash_finish(&sha, later(), yes()).await.unwrap(),
        TrashFinish::Removed
    );
}

/// T085-L4: after `Kept` both names are one inode; purging the trash entry only drops the name.
#[tokio::test]
async fn sec_051_purge_drops_a_trash_name_that_is_a_second_name_of_the_live_blob() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(21);
    s.put(sha, &bytes).await.unwrap();
    s.trash_stage(&sha).await.unwrap();
    assert_eq!(
        s.trash_finish(&sha, later(), no()).await.unwrap(),
        TrashFinish::Kept
    );
    let want = u64::try_from(bytes.len()).unwrap();
    assert_eq!(
        s.trash_purge(&sha).await.unwrap(),
        TrashPurge::Removed { bytes: want }
    );
    assert!(!trash_file(&dir, &sha).exists());
    // The live blob is untouched and still intact.
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(s.trash_purge(&sha).await.unwrap(), TrashPurge::Absent);
}

#[tokio::test]
async fn sec_050_finish_refuses_without_a_trash_copy_and_stage_needs_a_blob() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(3);
    assert!(matches!(
        s.trash_stage(&sha).await,
        Err(StoreError::NotFound)
    ));
    s.put(sha, &bytes).await.unwrap();
    // Finish without stage must not drop the only copy.
    assert!(matches!(
        s.trash_finish(&sha, later(), yes()).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn sec_050_finish_refuses_a_corrupt_trash_copy() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(4);
    s.put(sha, &bytes).await.unwrap();
    // A different inode with the right length but wrong content sits in the trash.
    fs::create_dir_all(dir.path().join("store/.trash")).unwrap();
    fs::write(trash_file(&dir, &sha), vec![b'x'; bytes.len()]).unwrap();
    assert!(matches!(
        s.trash_finish(&sha, later(), yes()).await,
        Err(StoreError::Corrupt)
    ));
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn sec_051_purge_removes_only_plain_single_link_regular_files() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(5);
    s.put(sha, &bytes).await.unwrap();
    s.trash_stage(&sha).await.unwrap();
    // A third name (not the live blob) makes the trash name "not ours alone": refused.
    let extra = dir.path().join("extra-link.nzb");
    fs::hard_link(trash_file(&dir, &sha), &extra).unwrap();
    assert_eq!(s.trash_purge(&sha).await.unwrap(), TrashPurge::Refused);
    assert!(trash_file(&dir, &sha).is_file());
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    fs::remove_file(&extra).unwrap();
    // Staged but not finished, live blob is the other name: it is just a name (T085-L4).
    // Re-stage below so the rest of the test starts from "finished".
    let want = u64::try_from(bytes.len()).unwrap();
    assert_eq!(
        s.trash_purge(&sha).await.unwrap(),
        TrashPurge::Removed { bytes: want }
    );
    assert!(!trash_file(&dir, &sha).exists());
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    s.trash_stage(&sha).await.unwrap();

    s.trash_finish(&sha, later(), yes()).await.unwrap();
    assert_eq!(
        s.trash_purge(&sha).await.unwrap(),
        TrashPurge::Removed { bytes: want }
    );
    assert!(!trash_file(&dir, &sha).exists());
    assert_eq!(s.trash_purge(&sha).await.unwrap(), TrashPurge::Absent);

    // A symlink under a valid blob name is refused and left alone (target untouched).
    let (sha2, bytes2) = blob(6);
    let outside = dir.path().join("outside.nzb");
    fs::write(&outside, &bytes2).unwrap();
    symlink(&outside, trash_file(&dir, &sha2)).unwrap();
    assert_eq!(s.trash_purge(&sha2).await.unwrap(), TrashPurge::Refused);
    assert!(outside.is_file());
    assert!(fs::symlink_metadata(trash_file(&dir, &sha2)).is_ok());
    // ... and it is not listed as a trash blob, only counted as foreign.
    let l = s.trash_list(100).await.unwrap();
    assert!(l.items.is_empty());
    assert_eq!(l.foreign, 1);

    // A FIFO is refused without blocking.
    let (sha3, _) = blob(7);
    let fifo = trash_file(&dir, &sha3);
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(s.trash_purge(&sha3).await.unwrap(), TrashPurge::Refused);
    assert!(fs::symlink_metadata(&fifo).is_ok());
}

#[tokio::test]
async fn sec_051_trash_listing_ignores_foreign_names() {
    let (dir, s) = setup();
    let t = dir.path().join("store/.trash");
    fs::create_dir_all(&t).unwrap();
    fs::write(t.join("notes.txt"), b"x").unwrap();
    fs::write(t.join(".hidden"), b"x").unwrap();
    fs::create_dir(t.join(format!("{}.nzb", "a".repeat(64)))).unwrap();
    let (sha, bytes) = blob(8);
    fs::write(t.join(format!("{}.nzb", sha.to_hex())), &bytes).unwrap();
    let l = s.trash_list(100).await.unwrap();
    assert_eq!(l.items.len(), 1);
    assert_eq!(l.foreign, 3);
    // Nothing foreign is ever purged through the listing.
    assert_eq!(
        s.trash_purge(&sha).await.unwrap(),
        TrashPurge::Removed {
            bytes: u64::try_from(bytes.len()).unwrap()
        }
    );
    assert!(t.join("notes.txt").is_file());
}

#[tokio::test]
async fn sec_051_quarantine_purge_honours_the_age_and_skips_foreign_entries() {
    let (dir, s) = setup();
    let q = dir.path().join("store/.gc-trash");
    fs::create_dir_all(&q).unwrap();
    let (a, ab) = blob(10);
    let (b, bb) = blob(11);
    let old = q.join(format!("{}.1000.0.trash", a.to_hex()));
    let young = q.join(format!("{}.9000.1.trash", b.to_hex()));
    fs::write(&old, &ab).unwrap();
    fs::write(&young, &bb).unwrap();
    fs::write(q.join("readme.txt"), b"mine").unwrap();
    let target = dir.path().join("elsewhere");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, q.join(format!("{}.1.2.trash", a.to_hex()))).unwrap();

    let list = s.quarantine_list(100).await.unwrap();
    assert_eq!(list.items.len(), 2);
    assert_eq!(list.foreign, 2);

    let rep = s.quarantine_purge(5000).await.unwrap();
    assert_eq!(rep.removed, 1);
    assert_eq!(rep.bytes, u64::try_from(ab.len()).unwrap());
    assert_eq!(rep.kept_recent, 1);
    assert_eq!(rep.skipped, 2);
    assert!(!old.exists());
    assert!(young.is_file());
    assert!(q.join("readme.txt").is_file());
    assert!(target.is_file());
    assert_eq!(sha8(&a).len(), 8);
}

#[tokio::test]
async fn sec_051_quarantine_purge_refuses_hard_linked_files() {
    let (dir, s) = setup();
    let q = dir.path().join("store/.gc-trash");
    fs::create_dir_all(&q).unwrap();
    let (a, ab) = blob(12);
    let kept = dir.path().join("other-name");
    fs::write(&kept, &ab).unwrap();
    fs::hard_link(&kept, q.join(format!("{}.1.0.trash", a.to_hex()))).unwrap();
    let rep = s.quarantine_purge(i64::MAX).await.unwrap();
    assert_eq!((rep.removed, rep.skipped), (0, 1));
    assert!(kept.is_file());
}

#[tokio::test]
async fn sec_051_quarantine_purge_checks_authority_before_the_first_file() {
    let (dir, s) = setup();
    let quarantine = dir.path().join("store/.gc-trash");
    fs::create_dir(&quarantine).unwrap();
    let (sha, bytes) = blob(13);
    let old = quarantine.join(format!("{}.1.0.trash", sha.to_hex()));
    fs::write(&old, &bytes).unwrap();
    let rep = s
        .quarantine_purge_checked(i64::MAX, None, Some(Arc::new(|| false)))
        .await
        .unwrap();
    assert!(rep.aborted);
    assert_eq!((rep.removed, rep.remaining), (0, 1));
    assert_eq!(fs::read(old).unwrap(), bytes);
}

#[tokio::test]
async fn sec_051_quarantine_purge_stops_when_authority_is_revoked_between_batches() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (dir, s) = setup();
    let quarantine = dir.path().join("store/.gc-trash");
    fs::create_dir(&quarantine).unwrap();
    let (sha, bytes) = blob(14);
    let batch = crate::QuarantinePurge::BATCH_SIZE;
    for counter in 0..batch + 3 {
        fs::write(
            quarantine.join(format!("{}.1.{counter}.trash", sha.to_hex())),
            &bytes,
        )
        .unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let gate = Arc::new(move || observed.fetch_add(1, Ordering::SeqCst) == 0);
    let rep = s
        .quarantine_purge_checked(i64::MAX, None, Some(gate))
        .await
        .unwrap();
    assert!(rep.aborted);
    assert_eq!((rep.removed, rep.remaining), (batch, 3));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read_dir(quarantine).unwrap().count(), 3);
}
