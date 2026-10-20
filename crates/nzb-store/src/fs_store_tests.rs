//! `FsStore` tests: layout, idempotence, crash injection (SEC-005/008), verify, gc.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::fs;
use std::time::{Duration, SystemTime};

use nzb_core::Sha256;

use crate::fs_store::{Step, digest};
use crate::{FsStore, NzbStore, PutOutcome, StoreError};

fn setup() -> (tempfile::TempDir, FsStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::open(dir.path().join("store")).unwrap();
    (dir, store)
}

fn blob(n: u8) -> (Sha256, Vec<u8>) {
    let bytes = format!("<nzb>{n}</nzb>").into_bytes();
    (digest(&bytes), bytes)
}

fn tmp_files(dir: &tempfile::TempDir) -> usize {
    fs::read_dir(dir.path().join("store/.tmp")).unwrap().count()
}

#[tokio::test]
async fn put_get_exists_roundtrip_and_layout() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(1);
    assert!(!s.exists(&sha).await.unwrap());
    assert!(matches!(s.get(&sha).await, Err(StoreError::NotFound)));
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert!(s.exists(&sha).await.unwrap());
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    let hex = sha.to_hex();
    let expected = dir
        .path()
        .join("store")
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(format!("{hex}.nzb"));
    assert!(expected.is_file());
    assert_eq!(tmp_files(&dir), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn permissions_are_0600_files_0700_dirs() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, s) = setup();
    let (sha, bytes) = blob(2);
    s.put(sha, &bytes).await.unwrap();
    let p = s.blob_path(&sha);
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for d in [
        p.parent().unwrap(),
        p.parent().unwrap().parent().unwrap(),
        &dir.path().join("store"),
    ] {
        assert_eq!(
            fs::metadata(d).unwrap().permissions().mode() & 0o777,
            0o700,
            "{d:?}"
        );
    }
}

#[tokio::test]
async fn put_is_idempotent() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(3);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::AlreadyExists);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn put_rejects_content_not_matching_sha() {
    let (_d, s) = setup();
    let (sha, _) = blob(4);
    let (_, other) = blob(5);
    assert!(matches!(
        s.put(sha, &other).await,
        Err(StoreError::HashMismatch)
    ));
    assert!(!s.exists(&sha).await.unwrap());
}

/// SEC-005: the path depends on the digest only and contains nothing but `[0-9a-f]` components.
#[test]
fn path_is_derived_only_from_sha() {
    let (dir, s) = setup();
    // Hostile text is irrelevant to the API: the only input is the 32-byte digest.
    let sha = digest(b"../../etc/passwd");
    let p = s.blob_path(&sha);
    let rel = p.strip_prefix(dir.path().join("store")).unwrap();
    let comps: Vec<_> = rel
        .components()
        .map(|c| c.as_os_str().to_str().unwrap().to_owned())
        .collect();
    assert_eq!(comps.len(), 3);
    assert!(comps.iter().all(|c| c.bytes().all(|b| b.is_ascii_digit()
        || (b'a'..=b'f').contains(&b)
        || b == b'.'
        || b == b'n'
        || b == b'z'
        || b == b'b')));
    assert!(!comps.iter().any(|c| c == ".." || c == "."));
    assert_eq!(comps[2], format!("{}.nzb", sha.to_hex()));
}

/// SEC-008: crash at every step of the protocol: the partial file is never visible under the
/// final name, restart cleans `.tmp`, and a retry succeeds with a complete blob.
#[tokio::test]
async fn crash_at_every_step_never_exposes_partial_blob() {
    for step in [Step::TmpCreated, Step::Written, Step::FileSynced] {
        let (dir, s) = setup();
        let (sha, bytes) = blob(6);
        s.set_crash_point(Some(step));
        assert!(
            matches!(s.put(sha, &bytes).await, Err(StoreError::Injected)),
            "{step:?}"
        );
        // Simulated kill left the tmp file behind, but nothing is visible.
        assert_eq!(tmp_files(&dir), 1, "{step:?}");
        assert!(!s.exists(&sha).await.unwrap(), "{step:?}");
        assert!(matches!(s.get(&sha).await, Err(StoreError::NotFound)));
        let rep = s.verify().unwrap();
        assert_eq!(
            (rep.ok, rep.corrupt.len(), rep.unexpected),
            (0, 0, 0),
            "{step:?}"
        );

        // Restart.
        let s2 = FsStore::open(dir.path().join("store")).unwrap();
        assert_eq!(tmp_files(&dir), 0, "{step:?}");
        assert_eq!(s2.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
        assert_eq!(s2.get(&sha).await.unwrap(), bytes);
        assert_eq!(s2.verify().unwrap().corrupt.len(), 0);
    }
}

#[tokio::test]
async fn crash_after_rename_leaves_complete_blob() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(7);
    s.set_crash_point(Some(Step::Renamed));
    assert!(matches!(
        s.put(sha, &bytes).await,
        Err(StoreError::Injected)
    ));
    assert_eq!(tmp_files(&dir), 0);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    s.set_crash_point(None);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::AlreadyExists);
}

#[tokio::test]
async fn real_failure_cleans_up_tmp() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(8);
    // Make the final path a directory so rename fails.
    fs::create_dir_all(s.blob_path(&sha)).unwrap();
    assert!(s.put(sha, &bytes).await.is_err());
    assert_eq!(tmp_files(&dir), 0);
}

#[tokio::test]
async fn symlink_in_place_of_blob_is_not_followed() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(9);
    let secret = dir.path().join("secret");
    fs::write(&secret, &bytes).unwrap();
    let p = s.blob_path(&sha);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &p).unwrap();
    assert!(!s.exists(&sha).await.unwrap());
    assert!(matches!(s.get(&sha).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn delete_removes_and_is_idempotent() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(10);
    s.put(sha, &bytes).await.unwrap();
    s.delete(&sha).await.unwrap();
    assert!(!s.exists(&sha).await.unwrap());
    s.delete(&sha).await.unwrap();
}

#[tokio::test]
async fn verify_reports_corrupt_and_unexpected_without_modifying() {
    let (dir, s) = setup();
    let (a, ab) = blob(11);
    let (b, bb) = blob(12);
    s.put(a, &ab).await.unwrap();
    s.put(b, &bb).await.unwrap();
    fs::write(s.blob_path(&b), b"tampered").unwrap();
    fs::write(dir.path().join("store/stray.txt"), b"x").unwrap();
    fs::write(s.blob_path(&a).parent().unwrap().join("notasha.nzb"), b"x").unwrap();
    let rep = s.verify().unwrap();
    assert_eq!(rep.ok, 1);
    assert_eq!(rep.corrupt, vec![b]);
    assert_eq!(rep.unexpected, 2);
    assert_eq!(fs::read(s.blob_path(&b)).unwrap(), b"tampered");
}

#[tokio::test]
async fn missing_lists_absent_blobs() {
    let (_d, s) = setup();
    let (a, ab) = blob(13);
    let (b, _) = blob(14);
    s.put(a, &ab).await.unwrap();
    assert_eq!(s.missing([a, b]).unwrap(), vec![b]);
}

#[tokio::test]
async fn gc_removes_only_unreferenced_old_blobs() {
    let (_d, s) = setup();
    let (a, ab) = blob(15);
    let (b, bb) = blob(16);
    s.put(a, &ab).await.unwrap();
    s.put(b, &bb).await.unwrap();
    let refs: HashSet<_> = [a].into();
    let past = SystemTime::now() - Duration::from_secs(3600);
    let future = SystemTime::now() + Duration::from_secs(3600);

    // Grace period protects a fresh blob (put done, DB row not yet committed).
    let r = s.gc(&refs, past, false).unwrap();
    assert_eq!((r.removed.len(), r.kept, r.too_new), (0, 1, 1));
    assert!(s.exists(&b).await.unwrap());

    // Dry run reports but keeps.
    let r = s.gc(&refs, future, true).unwrap();
    assert_eq!(r.removed, vec![b]);
    assert!(s.exists(&b).await.unwrap());

    let r = s.gc(&refs, future, false).unwrap();
    assert_eq!(r.removed, vec![b]);
    assert!(!s.exists(&b).await.unwrap());
    assert!(s.exists(&a).await.unwrap());
}

fn age(path: &std::path::Path, secs: u64) {
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

#[tokio::test]
async fn sec_008_put_on_existing_blob_refreshes_mtime_so_gc_spares_it() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(20);
    s.put(sha, &bytes).await.unwrap();
    age(&s.blob_path(&sha), 7200);
    let cutoff = SystemTime::now() - Duration::from_secs(3600);
    // Dedup re-upload of an old, unreferenced blob...
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::AlreadyExists);
    // ...makes it young again, so a GC that walks afterwards leaves it alone.
    let r = s.gc(&HashSet::new(), cutoff, false).unwrap();
    assert_eq!((r.removed.len(), r.too_new), (0, 1));
    assert!(s.exists(&sha).await.unwrap());
}

#[tokio::test]
async fn sec_008_gc_rechecks_references_right_before_removal() {
    let (d, s) = setup();
    let (sha, bytes) = blob(21);
    s.put(sha, &bytes).await.unwrap();
    age(&s.blob_path(&sha), 7200);
    let cutoff = SystemTime::now() - Duration::from_secs(3600);
    // The walk saw it unreferenced; by removal time a release row exists.
    let r = s
        .gc_checked(&HashSet::new(), cutoff, false, &|_| false)
        .unwrap();
    assert_eq!(r.removed.len(), 0);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(tmp_files(&d), 0);
    // Still unreferenced -> removed.
    let r = s
        .gc_checked(&HashSet::new(), cutoff, false, &|_| true)
        .unwrap();
    assert_eq!(r.removed, vec![sha]);
    assert!(!s.exists(&sha).await.unwrap());
    assert_eq!(tmp_files(&d), 0);
}

#[tokio::test]
async fn sec_008_gc_does_not_lose_blob_readopted_after_the_walk() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(22);
    s.put(sha, &bytes).await.unwrap();
    let path = s.blob_path(&sha);
    age(&path, 7200);
    let cutoff = SystemTime::now() - Duration::from_secs(3600);
    // A dedup put lands while GC holds the blob in quarantine: it sees no blob and writes a
    // fresh one, which GC must not clobber or delete.
    let readopt = || {
        fs::write(&path, &bytes).unwrap();
        true
    };
    let r = s
        .gc_checked(&HashSet::new(), cutoff, false, &|_| readopt())
        .unwrap();
    assert!(r.removed.is_empty() || s.exists(&sha).await.unwrap());
    assert!(path.is_file(), "the re-adopted blob must survive");
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[tokio::test]
async fn sec_008_gc_veto_preserves_a_concurrent_repair_of_a_corrupt_blob() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(28);
    s.put(sha, &bytes).await.unwrap();
    let path = s.blob_path(&sha);
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    age(&path, 7200);
    let cutoff = SystemTime::now() - Duration::from_secs(3600);
    let worker_store = s.clone();
    let healthy = bytes.clone();
    let runtime = tokio::runtime::Handle::current();
    let report = tokio::task::spawn_blocking(move || {
        worker_store.gc_checked(&HashSet::new(), cutoff, false, &|_| {
            // GC has moved the old inode away. A real put publishes a verified replacement
            // before the last database check discovers that the digest is referenced again.
            assert_eq!(
                runtime.block_on(worker_store.put(sha, &healthy)).unwrap(),
                PutOutcome::Created
            );
            false
        })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(report.removed.len(), 0);
    assert_eq!(report.too_new, 1);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(tmp_files(&dir), 0);
    assert_eq!(s.gc_trash_len().unwrap(), 1);
    let quarantined = fs::read_dir(dir.path().join("store/.gc-trash"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(fs::read(quarantined.path()).unwrap(), corrupt);
}

#[tokio::test]
async fn sec_008_put_rewrites_a_truncated_existing_blob() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(23);
    s.put(sha, &bytes).await.unwrap();
    fs::write(s.blob_path(&sha), &bytes[..3]).unwrap();
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn sec_008_get_refuses_content_that_does_not_match_its_address() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(24);
    s.put(sha, &bytes).await.unwrap();
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    fs::write(s.blob_path(&sha), &bad).unwrap();
    assert!(matches!(s.get(&sha).await, Err(StoreError::Corrupt)));
}

#[tokio::test]
async fn sec_008_put_repairs_same_size_corruption_before_acknowledging_a_duplicate() {
    let (_d, s) = setup();
    let (sha, bytes) = blob(27);
    s.put(sha, &bytes).await.unwrap();
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    fs::write(s.blob_path(&sha), bad).unwrap();
    assert!(matches!(s.get(&sha).await, Err(StoreError::Corrupt)));
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::AlreadyExists);
}

#[tokio::test]
async fn sec_005_fifo_blob_never_blocks_get_or_put() {
    use std::os::unix::fs::OpenOptionsExt as _;
    let (_d, s) = setup();
    let (sha, bytes) = blob(28);
    let path = s.blob_path(&sha);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    // Unblock a regressed blocking open before failing, so the blocking pool can still shut down.
    let release_fifo = || {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap()
    };
    let got = tokio::time::timeout(Duration::from_secs(1), s.get(&sha)).await;
    let unblock = got.is_err().then(release_fifo);
    assert!(matches!(got, Ok(Err(StoreError::NotFound))));
    drop(unblock);
    let put = tokio::time::timeout(Duration::from_secs(1), s.put(sha, &bytes)).await;
    let unblock = put.is_err().then(release_fifo);
    assert!(matches!(put, Ok(Ok(PutOutcome::Created))));
    drop(unblock);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
}

#[tokio::test]
async fn sec_005_symlinked_shard_directory_is_refused() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(25);
    let hex = sha.to_hex();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("store").join(&hex[0..2])).unwrap();
    assert!(s.put(sha, &bytes).await.is_err());
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[tokio::test]
async fn sec_005_populated_symlinked_shards_are_never_read_refreshed_or_deleted() {
    for level in [0, 1] {
        let (dir, s) = setup();
        let (sha, bytes) = blob(29);
        let hex = sha.to_hex();
        let elsewhere = dir.path().join("elsewhere");
        let outside_parent = if level == 0 {
            elsewhere.join(&hex[2..4])
        } else {
            elsewhere.clone()
        };
        fs::create_dir_all(&outside_parent).unwrap();
        let outside_blob = outside_parent.join(format!("{hex}.nzb"));
        fs::write(&outside_blob, &bytes).unwrap();
        age(&outside_blob, 7200);
        let before = fs::metadata(&outside_blob).unwrap().modified().unwrap();
        let first = dir.path().join("store").join(&hex[..2]);
        let link = if level == 0 {
            first
        } else {
            fs::create_dir(&first).unwrap();
            first.join(&hex[2..4])
        };
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        assert!(matches!(s.put(sha, &bytes).await, Err(StoreError::Corrupt)));
        assert!(matches!(s.get(&sha).await, Err(StoreError::Corrupt)));
        assert!(matches!(
            crate::TrashStore::trash_stage(&s, &sha).await,
            Err(StoreError::Corrupt)
        ));
        assert!(!s.exists(&sha).await.unwrap());
        assert_eq!(s.missing([sha]).unwrap(), vec![sha]);
        assert!(matches!(s.delete(&sha).await, Err(StoreError::Corrupt)));
        assert_eq!(fs::read(&outside_blob).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&outside_blob).unwrap().modified().unwrap(),
            before
        );
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }
}

#[tokio::test]
async fn sec_005_operator_configured_symlinked_store_root_remains_supported() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real-store");
    fs::create_dir(&real).unwrap();
    let alias = dir.path().join("store");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let s = FsStore::open(&alias).unwrap();
    let (sha, bytes) = blob(30);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::AlreadyExists);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    s.delete(&sha).await.unwrap();
    assert!(!s.exists(&sha).await.unwrap());
}

#[tokio::test]
async fn sec_005_symlinked_blob_is_not_read_or_refreshed() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(26);
    let secret = dir.path().join("outside");
    fs::write(&secret, &bytes).unwrap();
    age(&secret, 7200);
    let before = fs::metadata(&secret).unwrap().modified().unwrap();
    let p = s.blob_path(&sha);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &p).unwrap();
    // put replaces the symlink with a real blob and never touches the link target.
    assert_eq!(s.put(sha, &bytes).await.unwrap(), PutOutcome::Created);
    assert_eq!(fs::metadata(&secret).unwrap().modified().unwrap(), before);
    assert!(fs::symlink_metadata(&p).unwrap().file_type().is_file());
}

#[tokio::test]
async fn t032_m2_gc_quarantines_instead_of_unlinking_and_restore_and_purge_work() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(40);
    s.put(sha, &bytes).await.unwrap();
    age(&s.blob_path(&sha), 3600);
    let rep = s
        .gc_checked(
            &HashSet::new(),
            SystemTime::now() - Duration::from_secs(60),
            false,
            &|_| true,
        )
        .unwrap();
    assert_eq!(rep.removed, vec![sha]);
    assert!(!s.exists(&sha).await.unwrap());
    assert_eq!(s.gc_trash_len().unwrap(), 1);
    // The quarantine is not "unexpected" for verify, and tmp is clean.
    assert_eq!(s.verify().unwrap().unexpected, 0);
    assert_eq!(tmp_files(&dir), 0);

    // Purge only deletes entries quarantined before the cutoff.
    assert_eq!(
        s.purge_gc_trash(SystemTime::now() - Duration::from_hours(24))
            .unwrap(),
        0
    );
    assert_eq!(s.restore_gc_trash().unwrap(), 1);
    assert_eq!(s.get(&sha).await.unwrap(), bytes);
    assert_eq!(s.gc_trash_len().unwrap(), 0);

    // Quarantine again, then purge past the grace: the only place data is destroyed.
    age(&s.blob_path(&sha), 3600);
    s.gc_checked(
        &HashSet::new(),
        SystemTime::now() - Duration::from_secs(60),
        false,
        &|_| true,
    )
    .unwrap();
    let later = SystemTime::now() + Duration::from_hours(8 * 24);
    assert_eq!(s.purge_gc_trash(later).unwrap(), 1);
    assert_eq!(s.gc_trash_len().unwrap(), 0);
}

#[tokio::test]
async fn t032_l1_open_restores_gc_quarantine_files_and_passive_open_leaves_tmp_alone() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(41);
    s.put(sha, &bytes).await.unwrap();
    // gc crashed right after the rename into `.tmp/` (decision pending): blob path is empty.
    let trash = dir
        .path()
        .join("store/.tmp")
        .join(format!("gc-{}.123.0.trash", sha.to_hex()));
    fs::rename(s.blob_path(&sha), &trash).unwrap();
    let stale_put = dir.path().join("store/.tmp").join("x.1.0.tmp");
    fs::write(&stale_put, b"partial").unwrap();

    // The CLI-style open does not touch `.tmp/` at all.
    let _passive = FsStore::open_passive(dir.path().join("store")).unwrap();
    assert!(trash.exists() && stale_put.exists());

    // The serve-style open restores the blob and removes only the stale put file.
    let s2 = FsStore::open(dir.path().join("store")).unwrap();
    assert_eq!(s2.get(&sha).await.unwrap(), bytes);
    assert!(!trash.exists() && !stale_put.exists());

    // A quarantine file whose blob is already back is redundant and removed; a corrupt one is
    // moved to the quarantine, never deleted.
    fs::write(&trash, &bytes).unwrap();
    let (bad_sha, _) = blob(42);
    let bad = dir
        .path()
        .join("store/.tmp")
        .join(format!("gc-{}.1.1.trash", bad_sha.to_hex()));
    fs::write(&bad, b"not the right bytes").unwrap();
    let s3 = FsStore::open(dir.path().join("store")).unwrap();
    assert!(!trash.exists() && !bad.exists());
    assert_eq!(s3.gc_trash_len().unwrap(), 1);
    assert_eq!(s3.get(&sha).await.unwrap(), bytes);
}

/// Review 55: a GC scratch file whose shard directory is now a symlink is skipped by the startup
/// cleanup (never restored through the link), and the store still opens.
#[tokio::test]
async fn sec_005_open_skips_gc_scratch_of_a_symlinked_shard() {
    let (dir, s) = setup();
    let (sha, bytes) = blob(46);
    s.put(sha, &bytes).await.unwrap();
    let hex = sha.to_hex();
    let store = dir.path().join("store");
    let trash = store.join(".tmp").join(format!("gc-{hex}.123.0.trash"));
    fs::rename(s.blob_path(&sha), &trash).unwrap();
    fs::remove_dir_all(store.join(&hex[..2])).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, store.join(&hex[..2])).unwrap();
    let s2 = FsStore::open(&store).unwrap();
    assert!(trash.exists(), "the scratch copy is kept, never deleted");
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert!(matches!(s2.get(&sha).await, Err(StoreError::Corrupt)));
}

/// Review 55: the GC "wanted" restore falls back to a rename only on a filesystem without hard links.
#[test]
fn gc_restore_falls_back_only_when_hard_links_are_unsupported() {
    use crate::fs_store::hard_link_unsupported;
    for errno in [libc::EPERM, libc::EOPNOTSUPP, libc::ENOSYS] {
        assert!(hard_link_unsupported(&std::io::Error::from_raw_os_error(
            errno
        )));
    }
    for errno in [libc::EEXIST, libc::EACCES, libc::EIO, libc::ENOSPC] {
        assert!(!hard_link_unsupported(&std::io::Error::from_raw_os_error(
            errno
        )));
    }
}

#[tokio::test]
async fn t032_gc_candidates_report_timestamps_and_respect_references() {
    let (_dir, s) = setup();
    let (a, ba) = blob(43);
    let (b, bb) = blob(44);
    s.put(a, &ba).await.unwrap();
    s.put(b, &bb).await.unwrap();
    age(&s.blob_path(&a), 7200);
    age(&s.blob_path(&b), 7200);
    let refs: HashSet<Sha256> = [b].into_iter().collect();
    let c = s
        .gc_candidates(&refs, SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].sha, a);
    assert_eq!(c[0].size, u64::try_from(ba.len()).unwrap());
    assert!(c[0].ctime >= c[0].mtime, "ctime is the later status change");
}

/// T061 L-5: `get` refuses a blob above the configured cap before reading it.
#[tokio::test]
async fn t061_l5_get_refuses_blobs_over_the_size_cap() {
    let (_dir, s) = setup();
    let (sha, bytes) = blob(7);
    s.put(sha, &bytes).await.unwrap();
    let len = u64::try_from(bytes.len()).unwrap();
    s.set_max_blob_bytes(len);
    assert_eq!(
        s.get(&sha).await.unwrap(),
        bytes,
        "exactly at the cap is served"
    );
    s.set_max_blob_bytes(len - 1);
    assert!(matches!(s.get(&sha).await, Err(StoreError::Corrupt)));
}
