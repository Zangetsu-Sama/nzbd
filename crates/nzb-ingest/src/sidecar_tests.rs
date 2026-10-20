//! T141 / SEC-106: the NFO sidecar of a watch-folder NZB, end to end on the backend of the CI leg
//! (`NZBD_TEST_BACKEND`): attached after the commit, moved with its NZB, refused safely, never a candidate, and
//! crash-safe at both new crash points.

use super::*;
use nzb_core::MAX_NFO_BYTES;
use nzb_store::NfoAttach;

const STAMP: &str = "20231114T221320Z";
const ART: &[u8] = b"\xc9\xcd\xbb  T141 <b>art</b>\r\n\xc8\xcd\xbc\x1a SAUCE";

fn show(n: u32) -> Vec<u8> {
    nzb(&format!("Some.Show.S01E{n:02}.1080p.WEB-DL.x264-GRP.mkv"))
}

async fn nfo_of(e: &Env, release_id: i64) -> Option<Vec<u8>> {
    e.db.release_nfo(release_id).await.unwrap().map(|n| n.bytes)
}

/// The `nfo_attach` audit rows (all written by the process for the watch folder).
async fn attach_audits(e: &Env) -> Vec<nzb_store::AuditRow> {
    e.db.recent_audit(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.event == "nfo_attach")
        .collect()
}

async fn ingest_one(e: &mut Env) -> Result<IngestOutcome, IngestError> {
    let mut c = e.candidates();
    assert_eq!(c.len(), 1, "exactly one candidate (an .nfo never is one)");
    let path = c[0].path.clone();
    let r = e.pipeline.process(Job::watch(c.remove(0))).await;
    e.scanner.finish(&path);
    r
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_sidecar_is_attached_audited_and_removed_with_the_nzb() {
    let mut e = env(OPTS).await;
    let bytes = show(1);
    e.put_watch("Foo.Bar-GRP.nzb", &bytes);
    e.put_watch("Foo.Bar-GRP.nfo", ART);
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert_eq!(nfo_of(&e, out.release_id).await.as_deref(), Some(ART));
    let stored = e.db.release_nfo(out.release_id).await.unwrap().unwrap();
    assert_eq!(stored.added_by, None, "the watch folder is unattributed");
    assert_eq!(stored.added_at, T0);
    // Both sources are gone (the NZB is in the store, the NFO in the database); nothing in failed/ or duplicates/.
    assert!(names(&e.watch).is_empty(), "{:?}", names(&e.watch));
    assert!(names(&e.failed).is_empty());
    assert!(names(&e.dups).is_empty());
    let audits = attach_audits(&e).await;
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].actor_kind.as_deref(), Some("system"));
    let detail: serde_json::Value =
        serde_json::from_str(audits[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["source"], "watch");
    assert_eq!(detail["release"], out.release_id);
    assert_eq!(detail["bytes"], ART.len());
    assert!(!audits[0].detail.as_deref().unwrap().contains("art"));
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_extension_case_does_not_matter_but_the_stem_does() {
    let mut e = env(OPTS).await;
    // Upper-case `.NFO` with an upper-case `.NZB`.
    e.put_watch("Up.Case-GRP.NZB", &show(2));
    e.put_watch("Up.Case-GRP.NFO", ART);
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, out.release_id).await.as_deref(), Some(ART));
    assert!(names(&e.watch).is_empty());
    // A different stem is never paired: the NZB ingests without NFO, the other file is left alone, byte for byte.
    e.put_watch("Foo.Bar-GRP.nzb", &show(3));
    let other = e.put_watch("Foo.Bar-GRP2.nfo", b"not mine");
    let before = fs::symlink_metadata(&other).unwrap();
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, out.release_id).await, None);
    assert_eq!(names(&e.watch), vec!["Foo.Bar-GRP2.nfo".to_owned()]);
    let after = fs::symlink_metadata(&other).unwrap();
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    assert_eq!(fs::read(&other).unwrap(), b"not mine");
    assert!(names(&e.failed).is_empty());
    assert_eq!(attach_audits(&e).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_an_orphan_nfo_is_never_a_candidate_and_never_moved() {
    let mut e = env(OPTS).await;
    let orphan = e.put_watch("Lonely-GRP.nfo", ART);
    e.put_watch("Lonely-GRP.NfO.part", b"x");
    for _ in 0..3 {
        assert!(e.candidates().is_empty());
    }
    for name in ["a.nfo", "A.NFO", "a.nzb.nfo"] {
        assert!(!crate::scanner::name_is_candidate(name), "{name}");
    }
    assert_eq!(fs::read(&orphan).unwrap(), ART);
    assert!(names(&e.failed).is_empty());
    assert!(names(&e.dups).is_empty());
    assert_eq!(e.release_count().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_refused_sidecars_never_stop_the_nzb() {
    let mut e = env(OPTS).await;
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.nfo");
    fs::write(&secret, b"outside the watch folder").unwrap();
    // Oversize (cap + 1) and empty: regular files, moved out of the watch folder into failed/ (BETA: never deleted).
    let big = vec![b'x'; MAX_NFO_BYTES + 1];
    for (n, name, content) in [
        (10u32, "Big", big.as_slice()),
        (11, "Empty", b"".as_slice()),
    ] {
        let bytes = show(n);
        e.put_watch(&format!("{name}.nzb"), &bytes);
        e.put_watch(&format!("{name}.nfo"), content);
        let out = ingest_one(&mut e).await.unwrap();
        assert_eq!(out.kind, OutcomeKind::Ingested, "{name}");
        assert_eq!(nfo_of(&e, out.release_id).await, None, "{name}");
        let kept = e
            .failed
            .join(format!("{STAMP}-{}.nfo", sha_of(&bytes).short()));
        assert_eq!(fs::read(&kept).unwrap(), content, "{name}");
    }
    // A symlink (to a file outside the watch folder) and a hard-linked file are never opened, moved or removed.
    e.put_watch("Link.nzb", &show(12));
    std::os::unix::fs::symlink(&secret, e.watch.join("Link.nfo")).unwrap();
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, out.release_id).await, None);
    assert!(
        fs::symlink_metadata(e.watch.join("Link.nfo"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    e.put_watch("Hard.nzb", &show(13));
    let hard = e.put_watch("Hard.nfo", ART);
    fs::hard_link(&hard, outside.path().join("second-name")).unwrap();
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, out.release_id).await, None);
    assert_eq!(fs::read(&hard).unwrap(), ART);
    assert_eq!(fs::read(&secret).unwrap(), b"outside the watch folder");
    assert_eq!(e.release_count().await, 4);
    assert!(attach_audits(&e).await.is_empty());
    let mut left = names(&e.watch);
    left.sort();
    assert_eq!(left, vec!["Hard.nfo".to_owned(), "Link.nfo".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_sidecar_follows_a_rejected_nzb_into_failed_and_back_on_retry() {
    let mut e = env(OPTS).await;
    let bad = b"<nzb><file subject='x'>".to_vec();
    e.put_watch("Bad-GRP.nzb", &bad);
    e.put_watch("Bad-GRP.nfo", ART);
    let err = ingest_one(&mut e).await.unwrap_err();
    assert_eq!(err.disposition(), Disposition::Reject);
    let stem = format!("{STAMP}-{}", sha_of(&bad).short());
    assert_eq!(
        names(&e.failed),
        vec![
            format!("{stem}.nfo"),
            format!("{stem}.nzb"),
            format!("{stem}.nzb.reason.json"),
        ]
    );
    assert_eq!(fs::read(e.failed.join(format!("{stem}.nfo"))).unwrap(), ART);
    assert!(names(&e.watch).is_empty());
    assert!(attach_audits(&e).await.is_empty());
    // `failed retry` brings the pair back under one new stem, so the next ingest pairs them again.
    let rep = retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert_eq!(rep.moved.len(), 1);
    assert_eq!(
        names(&e.watch),
        vec![format!("retry-{stem}.nfo"), format!("retry-{stem}.nzb")]
    );
    assert!(names(&e.failed).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_duplicate_attaches_only_while_the_release_has_none() {
    let mut e = env(OPTS).await;
    let bytes = show(20);
    let sha8 = sha_of(&bytes).short();
    e.put_watch("First.nzb", &bytes);
    let first = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, first.release_id).await, None);
    // The same NZB again, now with an NFO: attached to the existing release, both moved to duplicates/.
    e.put_watch("Second.nzb", &bytes);
    e.put_watch("Second.nfo", ART);
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    assert_eq!(nfo_of(&e, first.release_id).await.as_deref(), Some(ART));
    assert_eq!(
        names(&e.dups),
        vec![format!("{STAMP}-{sha8}.nfo"), format!("{STAMP}-{sha8}.nzb")]
    );
    // A third copy with another NFO: AlreadyPresent, the stored one stays, the file is kept next to its NZB.
    e.put_watch("Third.nzb", &bytes);
    e.put_watch("Third.nfo", b"another art");
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    assert_eq!(nfo_of(&e, first.release_id).await.as_deref(), Some(ART));
    assert_eq!(
        fs::read(e.dups.join(format!("{STAMP}-{sha8}-1.nfo"))).unwrap(),
        b"another art"
    );
    assert!(e.dups.join(format!("{STAMP}-{sha8}-1.nzb")).exists());
    assert!(names(&e.watch).is_empty());
    assert_eq!(attach_audits(&e).await.len(), 1);
    assert_eq!(e.release_count().await, 1);
    // The store rule seen from the pipeline: the watch attach reports AlreadyPresent.
    assert_eq!(
        e.db.attach_watch_nfo(first.release_id, &sha_of(&bytes), b"x", T0)
            .await
            .unwrap(),
        NfoAttach::AlreadyPresent
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sec_106_duplicates_delete_removes_only_a_stored_sidecar() {
    let mut e = env(Opts {
        action: DuplicatesAction::Delete,
        from_subfolder: false,
    })
    .await;
    let bytes = show(30);
    e.put_watch("A.nzb", &bytes);
    e.put_watch("A.nfo", ART);
    ingest_one(&mut e).await.unwrap();
    // Same NZB, same NFO bytes: both deleted (the database holds them).
    e.put_watch("B.nzb", &bytes);
    e.put_watch("B.nfo", ART);
    assert_eq!(
        ingest_one(&mut e).await.unwrap().kind,
        OutcomeKind::Duplicate
    );
    assert!(names(&e.watch).is_empty());
    assert!(names(&e.dups).is_empty());
    // Same NZB, another NFO: the NZB is deleted, its NFO is not stored anywhere, so it is moved, not deleted.
    e.put_watch("C.nzb", &bytes);
    e.put_watch("C.nfo", b"different");
    assert_eq!(
        ingest_one(&mut e).await.unwrap().kind,
        OutcomeKind::Duplicate
    );
    assert!(names(&e.watch).is_empty());
    let sha8 = sha_of(&bytes).short();
    assert_eq!(names(&e.dups), vec![format!("{STAMP}-{sha8}.nfo")]);
    assert_eq!(
        fs::read(e.dups.join(format!("{STAMP}-{sha8}.nfo"))).unwrap(),
        b"different"
    );
}

/// SEC-008 with a sidecar: a crash after the release commit (before the attach) or after the attach (before any
/// source is disposed) loses nothing and duplicates nothing; the re-run attaches once and moves both to duplicates/.
#[tokio::test(flavor = "multi_thread")]
async fn sec_008_t141_crash_around_the_sidecar_attach_is_healed_by_the_rerun() {
    for point in [CrashPoint::AfterCommit, CrashPoint::AfterNfoAttach] {
        let mut e = env(OPTS).await;
        let bytes = show(40);
        let sha8 = sha_of(&bytes).short();
        e.put_watch("Crash.nzb", &bytes);
        e.put_watch("Crash.nfo", ART);
        e.pipeline.set_hook(Some(Arc::new(move |p| p == point)));
        assert!(ingest_one(&mut e).await.is_err(), "{point:?}");
        // Committed, both sources still in the watch folder.
        assert_eq!(e.release_count().await, 1);
        assert_eq!(
            names(&e.watch),
            vec!["Crash.nfo".to_owned(), "Crash.nzb".to_owned()]
        );
        let rel =
            e.db.get_release_by_sha(&sha_of(&bytes).to_hex())
                .await
                .unwrap()
                .unwrap()
                .id;
        let attached_before = nfo_of(&e, rel).await.is_some();
        assert_eq!(attached_before, point == CrashPoint::AfterNfoAttach);

        e.restart(OPTS);
        let out = ingest_one(&mut e).await.unwrap();
        assert_eq!(out.kind, OutcomeKind::Duplicate, "{point:?}");
        assert_eq!(nfo_of(&e, rel).await.as_deref(), Some(ART));
        assert!(names(&e.watch).is_empty());
        assert_eq!(
            names(&e.dups),
            vec![format!("{STAMP}-{sha8}.nfo"), format!("{STAMP}-{sha8}.nzb")]
        );
        assert_eq!(attach_audits(&e).await.len(), 1, "{point:?}");
        assert_eq!(e.release_count().await, 1);
    }
}

fn case_sensitive(dir: &Path) -> bool {
    fs::write(dir.join("probe.x"), b"1").unwrap();
    let cs = fs::symlink_metadata(dir.join("PROBE.X")).is_err();
    fs::remove_file(dir.join("probe.x")).unwrap();
    cs
}

/// Review 54 L1 (X1): a sub-folder swapped for a symlink to an outside directory after the NZB was read. The
/// sidecar there is never read, attached or moved; the outside file stays where it is.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_a_sidecar_outside_the_root_is_never_moved() {
    let mut e = env(Opts {
        action: DuplicatesAction::Move,
        from_subfolder: true,
    })
    .await;
    let outside = tempfile::tempdir().unwrap();
    let sub = e.watch.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("Victim.nzb"), show(70)).unwrap();
    let victim = outside.path().join("Victim.nfo");
    fs::write(&victim, b"operator file outside the watch root").unwrap();
    let (w, o) = (e.watch.clone(), outside.path().to_path_buf());
    e.pipeline.set_hook(Some(Arc::new(move |p| {
        if p == CrashPoint::AfterCommit {
            fs::rename(w.join("sub"), w.join("sub.real")).unwrap();
            std::os::unix::fs::symlink(&o, w.join("sub")).unwrap();
        }
        false
    })));
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);
    assert_eq!(nfo_of(&e, out.release_id).await, None);
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"operator file outside the watch root"
    );
    assert!(names(&e.failed).is_empty(), "{:?}", names(&e.failed));
    assert!(attach_audits(&e).await.is_empty());
}

/// Review 54 L2 (X2): an interrupted sidecar unlink leaves `.nzbd-trash.nfo.*`; startup recovery moves it to
/// `failed/` as an `.nfo`, never back into the watch folder as an NZB.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_an_interrupted_sidecar_unlink_is_recovered_as_an_nfo() {
    let mut e = env(OPTS).await;
    fs::write(e.watch.join(".nzbd-trash.nfo.123-1-1"), ART).unwrap();
    let cfg = crate::recovery::RecoveryConfig {
        watch_dir: e.watch.clone(),
        failed_dir: e.failed.clone(),
        duplicates_dir: e.dups.clone(),
        tmp_dir: None,
        recursive: false,
        max_file_bytes: 64 * 1024,
    };
    let rep = crate::recovery::recover(&cfg, &e.db, &*e.store, T0).await;
    assert_eq!(rep.nfo_trash_to_failed, 1);
    assert_eq!(rep.trash_restored, 0);
    assert!(names(&e.watch).is_empty(), "{:?}", names(&e.watch));
    assert!(e.candidates().is_empty());
    let want = format!("{STAMP}-{}.nfo", sha_of(ART).short());
    assert_eq!(names(&e.failed), vec![want.clone()]);
    assert_eq!(fs::read(e.failed.join(want)).unwrap(), ART);
    // Idempotent.
    let again = crate::recovery::recover(&cfg, &e.db, &*e.store, T0).await;
    assert_eq!(again.nfo_trash_to_failed, 0);
}

/// Review 54 I1 (X3): `Pair.nzb` and `Pair.NZB` never both get `Pair.nfo`; while both exist the sidecar is
/// ambiguous and stays in place.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_two_nzbs_sharing_a_stem_never_share_the_sidecar() {
    let mut e = env(OPTS).await;
    if !case_sensitive(&e.watch) {
        return;
    }
    e.put_watch("Pair.nzb", &show(71));
    e.put_watch("Pair.NZB", &show(72));
    e.put_watch("Pair.nfo", ART);
    let c = e.candidates();
    assert_eq!(c.len(), 2);
    let mut attached = Vec::new();
    for cand in c {
        let p = cand.path.clone();
        let out = e.pipeline.process(Job::watch(cand)).await.unwrap();
        e.scanner.finish(&p);
        attached.push(nfo_of(&e, out.release_id).await.is_some());
    }
    // The first sees both NZBs (ambiguous, untouched); the second is then the only NZB of that stem.
    assert_eq!(attached, vec![false, true]);
    assert_eq!(attach_audits(&e).await.len(), 1);
}

/// Review 54 L3 (X4): a stale `failed/<name>.nfo` never pairs with a newly rejected NZB: the NZB takes a name whose
/// `.nfo` is free, its own NFO follows it exactly, and `failed retry` brings back the right one.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_a_stale_nfo_never_pairs_with_another_nzb() {
    let mut e = env(OPTS).await;
    let bad = b"<nzb><file subject='x'>".to_vec();
    let stem = format!("{STAMP}-{}", sha_of(&bad).short());
    fs::write(e.failed.join(format!("{stem}.nfo")), b"stale").unwrap();
    e.put_watch("Bad.nzb", &bad);
    e.put_watch("Bad.nfo", ART);
    assert!(ingest_one(&mut e).await.is_err());
    assert_eq!(
        names(&e.failed),
        vec![
            format!("{stem}-1.nfo"),
            format!("{stem}-1.nzb"),
            format!("{stem}-1.nzb.reason.json"),
            format!("{stem}.nfo"),
        ]
    );
    assert_eq!(
        fs::read(e.failed.join(format!("{stem}-1.nfo"))).unwrap(),
        ART
    );
    retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert_eq!(
        fs::read(e.watch.join(format!("retry-{stem}-1.nfo"))).unwrap(),
        ART
    );
    assert!(e.watch.join(format!("retry-{stem}-1.nzb")).exists());
    assert_eq!(names(&e.failed), vec![format!("{stem}.nfo")]);
    // Retry into a watch folder where `retry-<name>.nfo` is taken: the NZB takes the next name, never the taken one.
    let mut e = env(OPTS).await;
    e.put_watch("Bad.nzb", &bad);
    e.put_watch("Bad.nfo", ART);
    assert!(ingest_one(&mut e).await.is_err());
    fs::write(e.watch.join(format!("retry-{stem}.nfo")), b"someone else's").unwrap();
    retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert_eq!(
        fs::read(e.watch.join(format!("retry-{stem}-1.nfo"))).unwrap(),
        ART
    );
    assert!(e.watch.join(format!("retry-{stem}-1.nzb")).exists());
    assert_eq!(
        fs::read(e.watch.join(format!("retry-{stem}.nfo"))).unwrap(),
        b"someone else's"
    );
}

/// Review 54 L3: expiry and the explicit purge of a failed NZB take its NFO along.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_expiry_and_purge_carry_the_nfo() {
    let mut e = env(OPTS).await;
    let bad = b"<nzb><file subject='x'>".to_vec();
    let stem = format!("{STAMP}-{}", sha_of(&bad).short());
    e.put_watch("Bad.nzb", &bad);
    e.put_watch("Bad.nfo", ART);
    assert!(ingest_one(&mut e).await.is_err());
    let rep = apply_retention(&e.failed, 1, T0 + 2 * 86_400);
    assert_eq!(rep.expired, 1);
    let xd = e.failed.join(EXPIRED_DIR);
    assert_eq!(
        names(&xd),
        vec![
            format!("{stem}.nfo"),
            format!("{stem}.nzb"),
            format!("{stem}.nzb.reason.json"),
        ]
    );
    assert_eq!(names(&e.failed), vec![EXPIRED_DIR.to_owned()]);
    // A second rejected copy is purged with its NFO.
    e.put_watch("Bad2.nzb", &bad);
    e.put_watch("Bad2.nfo", ART);
    assert!(ingest_one(&mut e).await.is_err());
    assert!(e.failed.join(format!("{stem}.nfo")).exists());
    let env = crate::cleanup::CleanupEnv {
        db: e.db.clone(),
        store: e.store.clone(),
        failed_dir: e.failed.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut removed = 0;
    for b in [
        crate::cleanup::Bucket::Failed,
        crate::cleanup::Bucket::Blocked,
    ] {
        removed += crate::cleanup::purge(&env, b, T0, deadline)
            .await
            .unwrap()
            .removed;
    }
    // The purge covers `failed/` and `failed/expired/`: both copies go, each with its NFO.
    assert_eq!(removed, 2);
    assert_eq!(names(&e.failed), vec![EXPIRED_DIR.to_owned()]);
    assert!(names(&xd).is_empty(), "{:?}", names(&xd));
}

/// Review 54 I7: two distinct sidecars differing only by case are both left in place, the NZB ingests.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_two_distinct_sidecars_are_ambiguous_and_untouched() {
    let mut e = env(OPTS).await;
    if !case_sensitive(&e.watch) {
        return;
    }
    e.put_watch("Amb.nzb", &show(80));
    e.put_watch("Amb.nfo", b"one");
    e.put_watch("Amb.NFO", b"two");
    let out = ingest_one(&mut e).await.unwrap();
    assert_eq!(nfo_of(&e, out.release_id).await, None);
    assert_eq!(
        names(&e.watch),
        vec!["Amb.NFO".to_owned(), "Amb.nfo".to_owned()]
    );
    assert!(names(&e.failed).is_empty());
}

/// Review 54 I7: a sidecar swapped after it was read is neither removed nor moved: the database keeps what was
/// read, the swapped-in file stays in the watch folder untouched.
#[tokio::test(flavor = "multi_thread")]
async fn sec_106_a_sidecar_swapped_during_disposal_is_left_alone() {
    for big in [false, true] {
        let mut e = env(OPTS).await;
        e.put_watch("Swap.nzb", &show(81));
        let original = if big {
            vec![b'x'; MAX_NFO_BYTES + 1]
        } else {
            ART.to_vec()
        };
        e.put_watch("Swap.nfo", &original);
        let w = e.watch.clone();
        e.pipeline.set_hook(Some(Arc::new(move |p| {
            if p == CrashPoint::AfterNfoAttach {
                fs::rename(w.join("Swap.nfo"), w.join("Swap.nfo.old")).unwrap();
                fs::write(w.join("Swap.nfo"), b"swapped in").unwrap();
            }
            false
        })));
        let out = ingest_one(&mut e).await.unwrap();
        let want = if big { None } else { Some(ART.to_vec()) };
        assert_eq!(nfo_of(&e, out.release_id).await, want, "big={big}");
        assert_eq!(fs::read(e.watch.join("Swap.nfo")).unwrap(), b"swapped in");
        assert!(names(&e.failed).is_empty(), "big={big}");
        assert!(!e.watch.join("Swap.nzb").exists());
    }
}
