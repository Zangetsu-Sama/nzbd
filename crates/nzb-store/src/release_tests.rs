//! Release repository tests (FTS injection, pagination, filters, atomicity).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::elidable_lifetime_names,
    clippy::type_complexity
)]

use nzb_core::{Analysis, FileInfo, FileKind, ReleaseFlags, Sha256};

use crate::{CategorySource, DbConfig, NewRelease, SceneColumns, SqliteDb, StoreError};

pub(crate) async fn open() -> (tempfile::TempDir, SqliteDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    (dir, db)
}

pub(crate) fn sha(n: u8) -> Sha256 {
    Sha256([n; 32])
}

fn file(idx: u32, name: &str) -> FileInfo {
    FileInfo {
        idx,
        subject: format!("subject {name}"),
        filename: Some(name.to_owned()),
        kind: FileKind::Video,
        poster: None,
        posted_at: Some(100),
        bytes: 10,
        segment_count: 3,
        declared_segments: Some(5),
        missing_ranges: vec![(2, 2), (5, 5)],
        missing_truncated: true,
        par2_blocks: None,
        groups: vec!["alt.binaries.test".into()],
    }
}

pub(crate) fn analysis(n: u8, title: &str, bytes: u64, posted: Option<i64>) -> Analysis {
    Analysis {
        sha256: sha(n),
        name_candidates: vec![],
        meta_name_candidates: 0,
        title: title.to_owned(),
        poster: Some("poster <p@x>".into()),
        posted_at: posted,
        total_bytes: bytes,
        file_count: 1,
        segment_count: 3,
        duplicate_segments: 0,
        par2_blocks: 0,
        flags: ReleaseFlags::EMPTY,
        meta_category: None,
        repairable_estimate: None,
        files: vec![file(0, &format!("{title}.mkv"))],
    }
}

pub(crate) fn new<'a>(a: &'a Analysis) -> NewRelease<'a> {
    NewRelease {
        analysis: a,
        nzb_size_bytes: 1234,
        source_name: Some("orig.nzb"),
        source_label: None,
        category_id: 8010,
        category_source: CategorySource::Fallback,
        meta_json: None,
        scene: SceneColumns::default(),
        ingested_at: 1_700_000_000,
    }
}

pub(crate) async fn count(db: &SqliteDb, table: &str) -> i64 {
    // Table names are literals in this test file only.
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(db.readers())
        .await
        .unwrap()
}

#[tokio::test]
async fn newest_ingested_at_tracks_insertion_order_when_the_clock_moves_backwards() {
    let (_dir, db) = open().await;
    assert_eq!(db.newest_ingested_at().await.unwrap(), None);
    let older = analysis(1, "Before clock correction", 1, None);
    let newer = analysis(2, "After clock correction", 1, None);
    let mut before = new(&older);
    before.ingested_at = 1_700_000_100;
    let first = db.insert_release(&before).await.unwrap();
    let mut after = new(&newer);
    after.ingested_at = 1_700_000_000;
    let last = db.insert_release(&after).await.unwrap();
    assert!(last > first);
    // GC must regard a blob dated between these timestamps as suspicious. Taking MAX
    // would hide that signal after an operator corrects a clock that was running ahead.
    let newest = db.newest_ingested_at().await.unwrap().unwrap();
    assert_eq!(newest, after.ingested_at);
    db.delete_release(last).await.unwrap();
    assert_eq!(
        db.newest_ingested_at().await.unwrap(),
        Some(before.ingested_at)
    );
    db.delete_release(first).await.unwrap();
    assert_eq!(db.newest_ingested_at().await.unwrap(), None);
}

#[tokio::test]
async fn list_shas_returns_every_referenced_digest() {
    let (_d, db) = open().await;
    assert!(db.list_shas().await.unwrap().is_empty());
    let (a, b) = (
        analysis(1, "One.1080p", 100, None),
        analysis(2, "Two.720p", 100, None),
    );
    let id = db.insert_release(&new(&a)).await.unwrap();
    db.insert_release(&new(&b)).await.unwrap();
    let all = db.list_shas().await.unwrap();
    assert_eq!(all, [sha(1), sha(2)].into());
    db.delete_release(id).await.unwrap();
    assert_eq!(db.list_shas().await.unwrap(), [sha(2)].into());
}

#[tokio::test]
async fn insert_and_get_roundtrip() {
    let (_d, db) = open().await;
    let a = analysis(1, "Show.S01E01.1080p", 500, Some(1000));
    let mut n = new(&a);
    n.category_source = CategorySource::Scene;
    n.category_id = 5040;
    n.scene = SceneColumns {
        family: Some("tv".into()),
        year: Some(2020),
        season: Some(1),
        episode: Some(1),
        resolution: Some("1080p".into()),
        source: Some("WEB-DL".into()),
        codec: Some("x264".into()),
        group: Some("GRP".into()),
        languages_json: Some("[\"en\"]".into()),
        json: Some("{}".into()),
    };
    let id = db.insert_release(&n).await.unwrap();

    let r = db.get_release(id).await.unwrap().unwrap();
    assert_eq!(r.title, a.title);
    assert_eq!(r.sha256, sha(1));
    assert_eq!(r.category_id, 5040);
    assert_eq!(r.category_source, CategorySource::Scene);
    assert!(!r.category_overridden);
    assert_eq!(r.scene, n.scene);
    assert_eq!(r.total_bytes, 500);
    assert_eq!(r.ingested_at, 1_700_000_000);
    // ranges (1+1) vs declared gap (2): max per file.
    assert_eq!(r.missing_segment_count, 2);
    assert_eq!(
        db.get_release_by_sha(&sha(1).to_hex())
            .await
            .unwrap()
            .unwrap()
            .id,
        id
    );
    assert!(db.get_release_by_sha("zz").await.unwrap().is_none());
    assert!(
        db.get_release_by_sha(&sha(9).to_hex())
            .await
            .unwrap()
            .is_none()
    );

    let files = db.list_files(id).await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].kind, "video");
    assert_eq!(files[0].groups.as_deref(), Some("[\"alt.binaries.test\"]"));
    assert_eq!(
        files[0].missing_ranges.as_deref(),
        Some("{\"more\":true,\"ranges\":[[2,2],[5,5]]}")
    );
    // T046 M1: single-file lookup, SQL paging and the groups aggregate.
    assert_eq!(db.get_file(id, 0).await.unwrap().unwrap().kind, "video");
    assert!(db.get_file(id, 5).await.unwrap().is_none());
    assert!(db.get_file(id + 99, 0).await.unwrap().is_none());
    assert_eq!(db.list_files_page(id, 0, 10).await.unwrap().len(), 1);
    assert!(db.list_files_page(id, 1, 10).await.unwrap().is_empty());
    assert_eq!(
        db.list_release_groups(id, 20).await.unwrap(),
        vec!["alt.binaries.test".to_owned()]
    );
}

#[tokio::test]
async fn duplicate_sha_is_typed_and_writes_nothing() {
    let (_d, db) = open().await;
    let a = analysis(1, "A", 1, None);
    db.insert_release(&new(&a)).await.unwrap();
    let b = analysis(1, "B", 1, None);
    assert!(matches!(
        db.insert_release(&new(&b)).await,
        Err(StoreError::Duplicate)
    ));
    assert_eq!(count(&db, "release").await, 1);
    assert_eq!(count(&db, "nzb_file").await, 1);
    assert_eq!(count(&db, "search_outbox").await, 1);
}

#[tokio::test]
async fn insert_is_atomic_on_late_failure() {
    let (_d, db) = open().await;
    let mut a = analysis(1, "A", 1, None);
    a.files.push(file(0, "dup-idx.mkv")); // violates UNIQUE(release_id, idx) after release insert
    assert!(db.insert_release(&new(&a)).await.is_err());
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);

    let ok = analysis(2, "ok", 1, None);
    let mut n = new(&ok);
    n.category_id = 1; // not in taxonomy
    assert!(matches!(
        db.insert_release(&n).await,
        Err(StoreError::UnknownCategory)
    ));
    assert_eq!(count(&db, "release").await, 0);
    // The writer is still usable after the failed transactions.
    db.insert_release(&new(&ok)).await.unwrap();
}

#[tokio::test]
async fn set_category_and_delete() {
    let (_d, db) = open().await;
    let a = analysis(1, "Gone", 1, Some(1));
    let id = db.insert_release(&new(&a)).await.unwrap();

    db.set_category(id, 5040).await.unwrap();
    let r = db.get_release(id).await.unwrap().unwrap();
    assert_eq!((r.category_id, r.category_overridden), (5040, true));
    assert_eq!(r.category_source, CategorySource::Manual);
    assert!(matches!(
        db.set_category(id, 1).await,
        Err(StoreError::UnknownCategory)
    ));
    assert!(matches!(
        db.set_category(999, 5040).await,
        Err(StoreError::NotFound)
    ));

    sqlx::query(
        "INSERT INTO ingest_log (ts, source, outcome, release_id) VALUES (1,'watch','ok',?)",
    )
    .bind(id)
    .execute(db.writer())
    .await
    .unwrap();
    db.delete_release(id).await.unwrap();
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);
    assert_eq!(count(&db, "ingest_log").await, 1);
    assert!(matches!(
        db.delete_release(id).await,
        Err(StoreError::NotFound)
    ));
    // The removal reached the outbox (the index drops the release in its next round).
    let out: Vec<i64> = db
        .search_outbox_read(10)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.release_id)
        .collect();
    assert_eq!(out.last(), Some(&id));
}

#[tokio::test]
async fn sec_020_source_label_is_sanitized_capped_and_empty_is_null() {
    let (_d, db) = open().await;
    let long = format!("ab\u{202e}c\0\u{200b} {}", "\u{e9}".repeat(100));
    let cases: [(Option<&str>, Option<&str>); 3] = [
        (Some("  personal \n archive "), Some("personal archive")),
        (Some("\u{200b}\u{7}  "), None),
        (None, None),
    ];
    for (i, (raw_label, want)) in cases.into_iter().enumerate() {
        let a = analysis(u8::try_from(i).unwrap() + 50, "t", 1, None);
        let mut n = new(&a);
        n.source_label = raw_label;
        let id = db.insert_release(&n).await.unwrap();
        let got = db.get_release(id).await.unwrap().unwrap().source_label;
        assert_eq!(got.as_deref(), want, "{raw_label:?}");
    }
    let a = analysis(90, "long", 1, None);
    let mut n = new(&a);
    n.source_label = Some(&long);
    let id = db.insert_release(&n).await.unwrap();
    let got = db
        .get_release(id)
        .await
        .unwrap()
        .unwrap()
        .source_label
        .unwrap();
    assert!(got.starts_with("abc \u{e9}") && got.len() <= 64, "{got:?}");
    // The hydration path returns it too, and the segment total aggregate sees all rows.
    let rows = db.hydrate(&[1, 2, 3, 4], &[]).await.unwrap();
    assert!(
        rows.iter()
            .any(|r| r.source_label.as_deref() == Some("personal archive"))
    );
    assert_eq!(db.release_totals().await.unwrap().segments, 12);
}

/// SEC-092: the SQLite outbox has the same payload-free, transactional contract as Postgres.
#[tokio::test]
async fn sec_092_outbox_rows_carry_no_payload() {
    let e = crate::acct_testkit::env().await;
    let db = e.db.clone();
    let cols: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('search_outbox') ORDER BY cid")
            .fetch_all(db.readers())
            .await
            .unwrap();
    assert_eq!(cols, ["seq", "release_id", "enqueued_at"]);
    let admin = e.admin("root").await;
    let act = e.actor(admin).await;
    let outbox = |db: SqliteDb| async move {
        sqlx::query_scalar::<_, i64>("SELECT release_id FROM search_outbox ORDER BY seq")
            .fetch_all(db.readers())
            .await
            .unwrap()
    };
    let a = analysis(1, "One", 1, None);
    let id = db.insert_release(&new(&a)).await.unwrap();
    assert_eq!(outbox(db.clone()).await, [id]);
    db.set_source_label_as(&act, id, Some("lbl"), None, 2)
        .await
        .unwrap();
    db.set_category_as(&act, id, 5040, None, 3).await.unwrap();
    db.bulk_set_source_label_as(&act, &[id], "x", &[], None, 4)
        .await
        .unwrap();
    assert_eq!(
        db.get_release(id)
            .await
            .unwrap()
            .unwrap()
            .source_label
            .as_deref(),
        Some("x")
    );
    let version: i64 = sqlx::query_scalar("SELECT index_version FROM release WHERE id = ?1")
        .bind(id)
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(version, 4, "each indexed change bumps index_version");
    db.trash_release_as(&act, id, 5, None).await.unwrap();
    assert_eq!(outbox(db.clone()).await, [id, id, id, id, id]);

    let b = analysis(2, "Two", 1, None);
    let id2 = db.insert_release(&new(&b)).await.unwrap();
    assert!(db.set_category_as(&act, id2, 1, None, 6).await.is_err());
    let v = e.viewer("v").await;
    let viewer = e.actor(v).await;
    assert!(
        db.set_source_label_as(&viewer, id2, Some("x"), None, 6)
            .await
            .is_err()
    );
    assert!(db.insert_release(&new(&b)).await.is_err());
    // Fail after the release insert and its trigger have run: the outbox row rolls back too.
    let mut broken = analysis(3, "Broken", 1, None);
    broken.files.push(file(0, "duplicate-index.mkv"));
    assert!(db.insert_release(&new(&broken)).await.is_err());
    assert_eq!(outbox(db.clone()).await.len(), 6);
    db.enqueue_reindex(&[id2, 424_242]).await.unwrap();
    assert_eq!(outbox(db).await.len(), 8);
}

/// Display rule `ui.show_xxx = false`: excluded categories vanish from the aggregates and the ingest
/// timeline (listing pages: the search index's conformance suite).
#[tokio::test]
async fn exclude_categories_applies_to_search_totals_and_log() {
    use crate::{IngestLogEntry, LogOutcome, LogSource};
    let (_d, db) = open().await;
    // 6000 (XXX parent), 5000 + 5040 (a parent and its child standing in for XXX + child).
    let cats = [(1_u8, 6000_u32), (2, 5000), (3, 5040), (4, 8010), (5, 8010)];
    let mut ids = Vec::new();
    for (n, cat) in cats {
        let a = analysis(n, &format!("Rel{n}"), 100, Some(i64::from(n)));
        let mut r = new(&a);
        r.category_id = cat;
        let id = db.insert_release(&r).await.unwrap();
        ids.push(id);
        let name = format!("file{n}.nzb");
        db.log_ingest(
            &IngestLogEntry {
                ts: i64::from(n),
                source: LogSource::Watch,
                api_key_id: None,
                source_name: Some(&name),
                sha256: Some(sha(n)),
                outcome: LogOutcome::Ok,
                error_code: None,
                detail: None,
            },
            Some(id),
        )
        .await
        .unwrap();
    }
    // A failed row without any release identity remains visible.
    db.log_ingest(
        &IngestLogEntry {
            ts: 9,
            source: LogSource::Watch,
            api_key_id: None,
            source_name: Some("bad.nzb"),
            sha256: None,
            outcome: LogOutcome::Failed,
            error_code: Some("NZB_XML"),
            detail: None,
        },
        None,
    )
    .await
    .unwrap();

    // Aggregates.
    assert_eq!(db.release_totals().await.unwrap().releases, 5);
    let t = db.release_totals_excluding(&[6000]).await.unwrap();
    assert_eq!(t.releases, 4);
    assert_eq!(t.segments, 12);
    assert_eq!(t.bytes, 400);

    // Timeline: hidden rows are dropped in SQL, so the limit still fills with visible ones.
    let log = db.list_ingest_log_excluding(3, &[6000]).await.unwrap();
    let names: Vec<_> = log.iter().map(|r| r.source_name.clone().unwrap()).collect();
    assert_eq!(names, ["bad.nzb", "file5.nzb", "file4.nzb"]);
    let unfiltered = db.list_ingest_log_excluding(10, &[]).await.unwrap();
    assert_eq!(unfiltered.len(), 6);

    // Operator view helper.
    let hidden = db.release_ids_in_categories(&ids, &[6000]).await.unwrap();
    assert_eq!(hidden.len(), 1);
    assert!(hidden.contains(&ids[0]));
    assert!(
        db.release_ids_in_categories(&ids, &[])
            .await
            .unwrap()
            .is_empty()
    );
}

/// Duplicate rows carry no release id, only the sha256 of the hidden release's NZB: they must be hidden
/// with it. Unresolved digest-bearing failures are also hidden when categories are excluded.
/// Both legs of the exclusion (id and sha256) are
/// probed per log row, not materialised.
#[tokio::test]
async fn excluded_log_hides_rows_by_release_id_and_by_sha256() {
    use crate::{IngestLogEntry, LogOutcome, LogSource};
    let (_d, db) = open().await;
    let hidden = analysis(1, "Hidden", 1, Some(1));
    let mut r = new(&hidden);
    r.category_id = 6000;
    let hidden_id = db.insert_release(&r).await.unwrap();
    let shown = analysis(2, "Shown", 1, Some(2));
    let mut r = new(&shown);
    r.category_id = 8010;
    let shown_id = db.insert_release(&r).await.unwrap();
    let entry = |ts: i64, n: u8, outcome| IngestLogEntry {
        ts,
        source: LogSource::Watch,
        api_key_id: None,
        source_name: Some("x.nzb"),
        sha256: Some(sha(n)),
        outcome,
        error_code: None,
        detail: None,
    };
    db.log_ingest(&entry(1, 1, LogOutcome::Ok), Some(hidden_id))
        .await
        .unwrap();
    db.log_ingest(&entry(2, 1, LogOutcome::Duplicate), None)
        .await
        .unwrap();
    db.log_ingest(&entry(3, 2, LogOutcome::Ok), Some(shown_id))
        .await
        .unwrap();
    db.log_ingest(&entry(4, 2, LogOutcome::Duplicate), None)
        .await
        .unwrap();
    db.log_ingest(&entry(5, 77, LogOutcome::Failed), None)
        .await
        .unwrap();
    let ts: Vec<i64> = db
        .list_ingest_log_excluding(10, &[6000])
        .await
        .unwrap()
        .iter()
        .map(|r| r.ts)
        .collect();
    assert_eq!(ts, [4, 3]);
}

/// SEC-095 (degraded mode, review 30 L5, review 35 L5): on SQLite too, one page never walks more than
/// `DEGRADED_SCAN_BUDGET` primary-key entries; a rare category behind more filler than the budget yields an empty
/// page flagged `budget_exhausted` with a cursor, and continuing from it reaches the rare row.
#[tokio::test]
async fn sec_095_degraded_browse_is_bounded() {
    let (_d, db) = open().await;
    let a = analysis(1, "Rare", 1, None);
    let mut r = new(&a);
    r.category_id = 5040;
    let rare = db.insert_release(&r).await.unwrap();
    // 200,010 newer rows in another category (bulk filler; the triggers keep outbox and totals as usual).
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 200010) \
         INSERT INTO release (sha256, title, category_id, ingested_at, total_bytes, file_count, segment_count, \
         nzb_size_bytes) SELECT randomblob(32), 'filler', 2040, 1, 0, 0, 0, 0 FROM n",
    )
    .execute(db.writer())
    .await
    .unwrap();
    let p = db.degraded_browse(None, &[5040], &[], 50).await.unwrap();
    assert!(p.items.is_empty());
    assert!(p.budget_exhausted, "the walk must stop at the budget");
    let next = p.next_before.unwrap();
    let p = db
        .degraded_browse(Some(next), &[5040], &[], 50)
        .await
        .unwrap();
    assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [rare]);
    assert!(!p.budget_exhausted);
}

fn group_item<'a>(a: &'a Analysis) -> crate::GroupItem<'a> {
    crate::GroupItem {
        new: NewRelease {
            analysis: a,
            nzb_size_bytes: 1,
            source_name: None,
            source_label: None,
            category_id: 8010,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: SceneColumns::default(),
            ingested_at: 1,
        },
        log: crate::IngestLogEntry {
            ts: 1,
            source: crate::LogSource::Watch,
            api_key_id: None,
            source_name: None,
            sha256: Some(a.sha256),
            outcome: crate::LogOutcome::Ok,
            error_code: None,
            detail: None,
        },
        uploader: crate::Uploader::Unattributed,
    }
}

/// SEC-095 / review 34 L5 (SQLite only: Postgres writers run in parallel under `statement_timeout`): a commit group
/// holds the single writer at most its cap. Once the cap is spent the rest of the group is `Deferred`, nothing of it
/// is written, the transaction commits, and an account write waiting for the writer gets it before the next group.
/// The first job always runs, so a zero cap still makes progress.
#[tokio::test(flavor = "multi_thread")]
async fn sec_095_commit_group_writer_hold_is_capped() {
    let (_d, db) = open().await;
    let all: Vec<Analysis> = (60..64).map(|n| analysis(n, "t", 1, None)).collect();
    let items: Vec<crate::GroupItem<'_>> = all.iter().map(group_item).collect();
    let out = db
        .insert_release_group(&items, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert!(matches!(out[0], crate::GroupOutcome::Inserted(_)));
    assert!(
        out[1..]
            .iter()
            .all(|o| matches!(o, crate::GroupOutcome::Deferred))
    );
    assert_eq!(db.release_totals().await.unwrap().releases, 1);
    // The deferred jobs go through in later groups (each again at least one job).
    let mut rest = items[1..].to_vec();
    let mut rounds = 0;
    while !rest.is_empty() {
        let out = db
            .insert_release_group(&rest, std::time::Duration::ZERO)
            .await
            .unwrap();
        rest = rest
            .into_iter()
            .zip(out)
            .filter(|(_, o)| matches!(o, crate::GroupOutcome::Deferred))
            .map(|(it, _)| it)
            .collect();
        rounds += 1;
    }
    assert_eq!(rounds, 3);
    assert_eq!(db.release_totals().await.unwrap().releases, 4);
    // A generous cap takes the whole group in one transaction.
    let more: Vec<Analysis> = (70..80).map(|n| analysis(n, "t", 1, None)).collect();
    let items: Vec<crate::GroupItem<'_>> = more.iter().map(group_item).collect();
    let out = db
        .insert_release_group(&items, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        out.iter()
            .all(|o| matches!(o, crate::GroupOutcome::Inserted(_)))
    );
    // Oversized groups are refused before anything is written.
    let many: Vec<Analysis> = (0..=crate::MAX_GROUP_JOBS)
        .map(|n| analysis(u8::try_from(n % 250).unwrap(), "t", 1, None))
        .collect();
    let items: Vec<crate::GroupItem<'_>> = many.iter().map(group_item).collect();
    assert!(matches!(
        db.insert_release_group(&items, std::time::Duration::ZERO)
            .await,
        Err(StoreError::OutOfRange(_))
    ));
}
