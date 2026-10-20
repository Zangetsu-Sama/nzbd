//! Release repository tests on the v3 Postgres store (T112): the 2.x `release_tests` minus the listing/search/plan
//! tests, which move with the search engine to `nzb-search` (T113, conformance suite); plus the v3 contract: outbox
//! rows in the same transaction, exact `category_stats`, hydration and the bounded degraded browse.
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

use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::{CategorySource, NewRelease, SceneColumns, StoreError};

pub(crate) async fn open() -> (TestDb, PgDb) {
    let t = TestDb::new().await;
    let db = t.db.clone();
    (t, db)
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

pub(crate) async fn count(db: &PgDb, table: &str) -> i64 {
    // Table names are literals in this test file only.
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(db.web())
        .await
        .unwrap()
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
    assert_eq!(
        count(&db, "search_outbox").await,
        1,
        "only the first insert announced a release"
    );
}

#[tokio::test]
async fn insert_is_atomic_on_late_failure() {
    let (_d, db) = open().await;
    let mut a = analysis(1, "A", 1, None);
    a.files.push(file(0, "dup-idx.mkv")); // violates UNIQUE(release_id, idx) after release insert
    assert!(db.insert_release(&new(&a)).await.is_err());
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);
    assert_eq!(count(&db, "search_outbox").await, 0);

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
        "INSERT INTO ingest_log (ts, source, outcome, release_id) VALUES (1,'watch','ok',$1)",
    )
    .bind(id)
    .execute(db.web())
    .await
    .unwrap();
    db.delete_release(id).await.unwrap();
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);
    assert_eq!(count(&db, "ingest_log").await, 1);
    // 2.x set the log's release_id to NULL; v3 keeps the id and readers report it only while the release exists.
    assert_eq!(db.list_ingest_log(10).await.unwrap()[0].release_id, None);
    assert!(matches!(
        db.delete_release(id).await,
        Err(StoreError::NotFound)
    ));
    // The insert, the category change and the delete each announced the release (no FTS in v3: the index follows the
    // outbox).
    assert_eq!(count(&db, "search_outbox").await, 3);
    assert!(db.hydrate(&[id], &[]).await.unwrap().is_empty());
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
    // Hydration returns it too, and the segment total aggregate sees all rows.
    let all: Vec<i64> = (1..=id).collect();
    let rows = db.hydrate(&all, &[]).await.unwrap();
    assert!(
        rows.iter()
            .any(|r| r.source_label.as_deref() == Some("personal archive"))
    );
    assert_eq!(db.release_totals().await.unwrap().segments, 12);
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

/// Display rule `ui.show_xxx = false` on the store side of v3: totals from `category_stats`, the ingest timeline and
/// the operator helper (the listing half of the 2.x test is the search engine's, T113).
#[tokio::test]
async fn exclude_categories_applies_to_totals_and_log() {
    use crate::{IngestLogEntry, LogOutcome, LogSource};
    let (_d, db) = open().await;
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
    assert_eq!(db.release_totals().await.unwrap().releases, 5);
    let t = db.release_totals_excluding(&[6000]).await.unwrap();
    assert_eq!(t.releases, 4);
    assert_eq!(t.segments, 12);
    assert_eq!(t.bytes, 400);
    assert_eq!(t.files, 4);
    let log = db.list_ingest_log_excluding(3, &[6000]).await.unwrap();
    let names: Vec<_> = log.iter().map(|r| r.source_name.clone().unwrap()).collect();
    assert_eq!(names, ["bad.nzb", "file5.nzb", "file4.nzb"]);
    assert_eq!(
        db.list_ingest_log_excluding(10, &[]).await.unwrap().len(),
        6
    );
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

/// Recomputes the per-category totals from `release` (what `nzbd db check --full` compares).
async fn stats_match(db: &PgDb) {
    let bad: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM category_stats s FULL JOIN \
         (SELECT category_id, count(*) AS n, sum(file_count) AS f, sum(segment_count) AS sg, sum(total_bytes) AS b \
          FROM release GROUP BY category_id) r ON r.category_id = s.category_id \
         WHERE coalesce(s.releases, 0) <> coalesce(r.n, 0) OR coalesce(s.files, 0) <> coalesce(r.f, 0) \
            OR coalesce(s.segments, 0) <> coalesce(r.sg, 0) OR coalesce(s.bytes, 0) <> coalesce(r.b, 0)",
    )
    .fetch_one(db.web())
    .await
    .unwrap();
    assert_eq!(bad, 0, "category_stats drifted from release");
}

#[tokio::test]
async fn category_stats_stay_exact_through_every_change() {
    let e = crate::pg_testkit::env().await;
    let db = e.db.clone();
    let admin = e.admin("root").await;
    let act = e.actor(admin).await;
    let mut ids = Vec::new();
    for n in 1..=6_u8 {
        let a = analysis(n, &format!("R{n}"), u64::from(n) * 10, Some(i64::from(n)));
        let mut r = new(&a);
        r.category_id = if n % 2 == 0 { 5040 } else { 2040 };
        ids.push(db.insert_release(&r).await.unwrap());
        stats_match(&db).await;
    }
    db.set_category(ids[0], 5040).await.unwrap();
    stats_match(&db).await;
    db.set_category_as(&act, ids[1], 2040, None, 5)
        .await
        .unwrap();
    stats_match(&db).await;
    db.bulk_set_category_as(&act, &ids[2..5], 6000, &[], None, 6)
        .await
        .unwrap();
    stats_match(&db).await;
    db.trash_release_as(&act, ids[3], 7, None).await.unwrap();
    stats_match(&db).await;
    db.delete_release(ids[5]).await.unwrap();
    stats_match(&db).await;
    let t = db.release_totals().await.unwrap();
    assert_eq!((t.releases, t.bytes), (4, 10 + 20 + 30 + 50));
}

/// SEC-092 / SEC-008 (v3): every release change writes one payload-free outbox row in its own transaction; a rolled
/// back change writes none.
#[tokio::test]
async fn sec_092_outbox_rows_carry_no_payload() {
    let e = crate::pg_testkit::env().await;
    let db = e.db.clone();
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_schema = 'nzbd' AND table_name = 'search_outbox' ORDER BY ordinal_position",
    )
    .fetch_all(db.web())
    .await
    .unwrap();
    assert_eq!(cols, ["seq", "release_id", "enqueued_at"]);
    let admin = e.admin("root").await;
    let act = e.actor(admin).await;
    let outbox = |db: PgDb| async move {
        let v: Vec<i64> = sqlx::query_scalar("SELECT release_id FROM search_outbox ORDER BY seq")
            .fetch_all(db.web())
            .await
            .unwrap();
        v
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
    let v = db.get_release(id).await.unwrap().unwrap();
    assert_eq!(v.source_label.as_deref(), Some("x"));
    let version: i64 = sqlx::query_scalar("SELECT index_version FROM release WHERE id = $1")
        .bind(id)
        .fetch_one(db.web())
        .await
        .unwrap();
    assert_eq!(version, 4, "each indexed change bumps index_version");
    db.trash_release_as(&act, id, 5, None).await.unwrap();
    assert_eq!(outbox(db.clone()).await, [id, id, id, id, id]);
    // Refused changes write nothing: unknown category, forbidden actor, duplicate.
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
    assert_eq!(outbox(db.clone()).await.len(), 6);
    // The reconciliation hook announces without changing anything.
    db.enqueue_reindex(&[id2, 424_242]).await.unwrap();
    assert_eq!(outbox(db.clone()).await.len(), 8);
}

#[tokio::test]
async fn hydrate_keeps_index_order_and_drops_gone_and_hidden_rows() {
    let (_d, db) = open().await;
    let mut ids = Vec::new();
    for (n, cat) in [(1_u8, 8010_u32), (2, 6000), (3, 5030), (4, 2040)] {
        let a = analysis(n, &format!("H{n}"), 1, None);
        let mut r = new(&a);
        r.category_id = cat;
        ids.push(db.insert_release(&r).await.unwrap());
    }
    let order = [ids[3], 999_999, ids[0], ids[1], ids[2]];
    let got: Vec<i64> = db
        .hydrate(&order, &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(got, [ids[3], ids[0], ids[1], ids[2]]);
    // The CURRENT category decides (SEC-090: the index may lag a re-categorization).
    let got: Vec<i64> = db
        .hydrate(&order, &[6000, 5030])
        .await
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(got, [ids[3], ids[0]]);
    db.set_category(ids[0], 5030).await.unwrap();
    let got: Vec<i64> = db
        .hydrate(&order, &[6000, 5030])
        .await
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(got, [ids[3]]);
    assert!(db.hydrate(&[], &[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn degraded_browse_pages_newest_first_and_respects_categories() {
    let (_d, db) = open().await;
    let mut ids = Vec::new();
    for n in 1..=7_u8 {
        let a = analysis(n, &format!("D{n}"), 1, None);
        let mut r = new(&a);
        r.category_id = if n % 3 == 0 { 6000 } else { 2040 };
        ids.push(db.insert_release(&r).await.unwrap());
    }
    let p1 = db.degraded_browse(None, &[], &[6000], 2).await.unwrap();
    let got: Vec<i64> = p1.items.iter().map(|r| r.id).collect();
    assert_eq!(got, [ids[6], ids[4]]);
    assert!(!p1.budget_exhausted);
    let p2 = db
        .degraded_browse(p1.next_before, &[], &[6000], 2)
        .await
        .unwrap();
    let got: Vec<i64> = p2.items.iter().map(|r| r.id).collect();
    assert_eq!(got, [ids[3], ids[1]]);
    let p3 = db
        .degraded_browse(p2.next_before, &[], &[6000], 2)
        .await
        .unwrap();
    let got: Vec<i64> = p3.items.iter().map(|r| r.id).collect();
    assert_eq!(got, [ids[0]]);
    assert_eq!(p3.next_before, None);
    let only: Vec<i64> = db
        .degraded_browse(None, &[6000], &[], 10)
        .await
        .unwrap()
        .items
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(only, [ids[5], ids[2]]);
}

/// SEC-095 (degraded mode, review L5): one page never walks more than `DEGRADED_SCAN_BUDGET` primary-key entries; a
/// rare category below the budget says so instead of scanning the table.
#[tokio::test]
async fn sec_095_degraded_browse_is_bounded() {
    let e = crate::pg_testkit::env().await;
    let db = e.db.clone();
    let a = analysis(1, "Rare", 1, None);
    let mut r = new(&a);
    r.category_id = 5040;
    let rare = db.insert_release(&r).await.unwrap();
    // 200,010 newer rows in another category, inserted in bulk as the superuser (they are only PK filler).
    e.superuser_exec(
        "INSERT INTO nzbd.release (sha256, title, category_id, ingested_at, total_bytes, file_count, segment_count, \
         nzb_size_bytes) SELECT sha256(int8send(g)), 'filler', 2040, 1, 0, 0, 0, 0 FROM generate_series(1, 200010) g",
    )
    .await;
    let p = db.degraded_browse(None, &[5040], &[], 50).await.unwrap();
    assert!(p.items.is_empty());
    assert!(p.budget_exhausted, "the walk must stop at the budget");
    let next = p.next_before.unwrap();
    // Continuing from where the budget stopped reaches the rare row.
    let p = db
        .degraded_browse(Some(next), &[5040], &[], 50)
        .await
        .unwrap();
    assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [rare]);
    assert!(!p.budget_exhausted);
}

#[tokio::test]
async fn file_partitions_are_created_ahead_of_the_ids() {
    let e = crate::pg_testkit::env().await;
    let db = e.db.clone();
    let parts = || async {
        let v: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
             WHERE i.inhparent = 'nzbd.nzb_file'::regclass ORDER BY 1",
        )
        .fetch_all(e.db.web())
        .await
        .unwrap();
        v
    };
    let a = analysis(1, "first", 1, None);
    db.insert_release(&new(&a)).await.unwrap();
    // The first insert makes sure the NEXT range exists too (`upto + 10M`).
    assert_eq!(parts().await, ["nzb_file_p000000", "nzb_file_p000001"]);
    // Jump the identity close to the partition boundary (as `migrate` can, with original ids).
    e.superuser_exec("SELECT setval(pg_get_serial_sequence('nzbd.release', 'id'), 9500000)")
        .await;
    let b = analysis(2, "near the bound", 1, None);
    let id = db.insert_release(&new(&b)).await.unwrap();
    assert_eq!(id, 9_500_001);
    assert_eq!(parts().await, ["nzb_file_p000000", "nzb_file_p000001"]);
    e.superuser_exec("SELECT setval(pg_get_serial_sequence('nzbd.release', 'id'), 19999999)")
        .await;
    let c = analysis(3, "across the bound", 1, None);
    let id = db.insert_release(&new(&c)).await.unwrap();
    // The jump bypassed this process's cache: the first attempt found no partition for 20,000,000 and rolled back
    // (consuming that sequence value), the partitions were created in their own transaction, the retry landed.
    assert_eq!(id, 20_000_001);
    assert_eq!(db.list_files(id).await.unwrap().len(), 1);
    // Created ahead: the span of the sequence + 1M and the next one.
    assert_eq!(
        parts().await,
        [
            "nzb_file_p000000",
            "nzb_file_p000001",
            "nzb_file_p000002",
            "nzb_file_p000003"
        ]
    );
}

/// `SECURITY_REVIEW` 31 M1: partitions are created in their own short transaction BEFORE an insert, never inside an
/// ingest transaction, and the creator locks `release` before `nzb_file`. (1) The reviewer's interleaving: an ingest
/// transaction holds an uncommitted release insert while another process needs the next partition; the creation
/// waits for that ingest, which finishes its file rows and commits; no deadlock, and readers of `nzb_file` are not
/// blocked while the creator waits. (2) Many concurrent inserts from several processes across a 10M boundary all
/// succeed with their files.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn sec_095_concurrent_ingests_across_a_partition_boundary_do_not_deadlock() {
    use sqlx::Connection as _;
    let e = crate::pg_testkit::env().await;
    let a = analysis(1, "existing", 1, None);
    let existing = e.db.insert_release(&new(&a)).await.unwrap();
    e.superuser_exec("SELECT setval('nzbd.release_id_seq', 19999990)")
        .await;
    // (1) An ingest in flight (raw app connection: release written, files not yet).
    let mut ingest = e.t.app_conn().await;
    let mut tx = ingest.begin().await.unwrap();
    let held: i64 = sqlx::query_scalar(
        "INSERT INTO release (sha256, title, category_id, ingested_at, total_bytes, file_count, segment_count, \
         nzb_size_bytes) VALUES (sha256('held'::bytea), 'held', 8010, 1, 0, 1, 0, 0) RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(held, 19_999_991);
    let other = e.second().await;
    let creator = tokio::spawn(async move { other.ensure_file_partitions_ahead().await });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(
        !creator.is_finished(),
        "the creation waits for the in-flight ingest"
    );
    // A reader of nzb_file is not blocked meanwhile (the creator holds no lock on it yet).
    let reader = tokio::time::timeout(std::time::Duration::from_secs(3), e.db.list_files(existing))
        .await
        .expect("reader stalled behind the partition creation")
        .unwrap();
    assert_eq!(reader.len(), 1);
    // The ingest finishes (its partition exists) and commits; then the creation proceeds.
    sqlx::query(
        "INSERT INTO nzb_file (release_id, idx, subject, kind, bytes, segment_count) VALUES ($1, 0, 's', 'other', 0, 0)",
    )
    .bind(held)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let created = tokio::time::timeout(std::time::Duration::from_secs(10), creator)
        .await
        .expect("creation finished")
        .unwrap()
        .unwrap();
    assert!(
        created >= 1,
        "the next spans are created ahead of the boundary"
    );
    let p2: bool = sqlx::query_scalar("SELECT to_regclass('nzbd.nzb_file_p000002') IS NOT NULL")
        .fetch_one(e.db.web())
        .await
        .unwrap();
    assert!(p2);
    // (2) Several processes insert concurrently across the 30M boundary.
    e.superuser_exec("SELECT setval('nzbd.release_id_seq', 29999995)")
        .await;
    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(e.second().await);
    }
    let mut tasks = Vec::new();
    for n in 0..24_u8 {
        let db = handles[usize::from(n % 3)].clone();
        tasks.push(tokio::spawn(async move {
            let a = analysis(100 + n, &format!("burst {n}"), 1, None);
            db.insert_release(&new(&a)).await
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap().expect("no insert fails at the boundary"));
    }
    assert!(ids.iter().any(|id| *id >= 30_000_000));
    assert_eq!(
        count(&e.db, "nzb_file").await,
        26,
        "every release kept its file (1 existing, 1 held, 24 burst)"
    );
}
