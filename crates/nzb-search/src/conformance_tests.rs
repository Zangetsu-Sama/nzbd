//! The 2.x `SearchIndex` conformance suite (`nzb-store/src/search_index_tests.rs`, T091), ported
//! verbatim and run against [`TantivyIndex`]. (T113 ran it against the 2.x FTS5 engine too and the 3,840-page
//! parity matrix was identical; T122 retired FTS5 from the 3.x line, so the FTS5 instantiation and the parity
//! matrix went with it.)
//!
//! Why a port: the original is crate-private test code of `nzb-store`, which T112 is rewriting for
//! Postgres in parallel. The only change is a `settle` hook after the 2.x write path's
//! writes: 2.x indexes in the release transaction, v3 after one indexer cycle (ARCHITECTURE v3 3.5
//! item 1); for FTS5 `settle` does nothing. When T112 lands, both copies should move into one shared
//! `conformance` feature of `nzb-store`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::assert_is_empty,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cloned_ref_to_slice_refs,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::manual_is_multiple_of,
    clippy::some_filter,
    clippy::uninlined_format_args,
    clippy::unused_async_trait_impl
)]

use std::cmp::Ordering;
use std::future::Future;

use nzb_store::{
    PageCursor, SearchDoc, SearchIndex, SearchQuery, SeekDir, SortKey, SqliteDb, StoreError,
};

use crate::testkit::{Row, open_db, seed_ordered, settle, tantivy_over};

pub(crate) const SORTS: [SortKey; 6] = [
    SortKey::DateDesc,
    SortKey::DateAsc,
    SortKey::SizeDesc,
    SortKey::SizeAsc,
    SortKey::TitleAsc,
    SortKey::TitleDesc,
];

/// The documented total order of a sort, independent of any engine (2.x `keyset_tests::cmp`).
pub(crate) fn cmp(sort: SortKey, a: &Row, b: &Row) -> Ordering {
    let undated_last = a.3.is_none().cmp(&b.3.is_none());
    let (la, lb) = (a.1.to_lowercase(), b.1.to_lowercase());
    match sort {
        SortKey::DateDesc => undated_last.then(b.3.cmp(&a.3)).then(b.0.cmp(&a.0)),
        SortKey::DateAsc => undated_last.then(a.3.cmp(&b.3)).then(a.0.cmp(&b.0)),
        SortKey::SizeDesc => b.2.cmp(&a.2).then(b.0.cmp(&a.0)),
        SortKey::SizeAsc => a.2.cmp(&b.2).then(a.0.cmp(&b.0)),
        SortKey::TitleAsc => la.cmp(&lb).then(a.0.cmp(&b.0)),
        SortKey::TitleDesc => lb.cmp(&la).then(b.0.cmp(&a.0)),
    }
}

pub(crate) fn reference(rows: &[Row], sort: SortKey, keep: &dyn Fn(&Row) -> bool) -> Vec<Row> {
    let mut v: Vec<Row> = rows.iter().filter(|r| keep(r)).cloned().collect();
    v.sort_by(|a, b| cmp(sort, a, b));
    v
}

/// What the `upsert`/`remove` maintenance hooks mean for the engine under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hooks {
    /// 2.x FTS5: write the given text at once.
    #[allow(dead_code)] // 2.x semantics; kept so another engine can run the same suite
    Direct,
    /// v3: enqueue a reindex of the release's database state (review 32 L5).
    Reindex,
}

/// The 2.x suite; `settle` runs after writes that went through the store's write path.
pub(crate) async fn search_index_conformance<I, S, F>(
    db: &SqliteDb,
    index: &I,
    hooks: Hooks,
    settle: S,
) where
    I: SearchIndex,
    S: Fn() -> F,
    F: Future<Output = ()>,
{
    let rows = seed_ordered(db).await;
    settle().await;
    let all = |_r: &Row| true;
    let tv = |r: &Row| r.4 == 5040 || r.4 == 5030;
    let not_movies = |r: &Row| r.4 != 2040;
    let rel03 = |r: &Row| r.1.ends_with("rel03");
    let a_not_8010 = |r: &Row| r.1.starts_with("A ") && r.4 != 8010;
    const LIMIT: usize = 7;

    for sort in SORTS {
        let cases: [(Option<&str>, Vec<u32>, Vec<u32>, &dyn Fn(&Row) -> bool); 5] = [
            (None, vec![], vec![], &all),
            (None, vec![5000], vec![], &tv),
            (None, vec![], vec![2040], &not_movies),
            (Some("rel03"), vec![], vec![], &rel03),
            (Some("a"), vec![], vec![8010], &a_not_8010),
        ];
        for (text, cats, excl, keep) in &cases {
            let want: Vec<i64> = reference(&rows, sort, keep).iter().map(|r| r.0).collect();
            let ctx = format!("{sort:?} {text:?} {cats:?} {excl:?}");
            let q = SearchQuery {
                q: text.map(str::to_owned),
                categories: cats.clone(),
                exclude_categories: excl.clone(),
                sort,
                limit: LIMIT as u32,
                ..SearchQuery::default()
            };
            assert_eq!(
                index.count(&q).await.unwrap(),
                want.len() as u64,
                "count {ctx}"
            );

            // Offset paging: every page of the listing.
            let mut got = Vec::new();
            let mut offset = 0u32;
            loop {
                let p = index
                    .search(&SearchQuery {
                        offset,
                        ..q.clone()
                    })
                    .await
                    .unwrap();
                assert_eq!(p.total, want.len() as u64, "total {ctx}");
                if p.items.is_empty() {
                    break;
                }
                got.extend(p.items.iter().map(|r| r.id));
                offset += LIMIT as u32;
            }
            assert_eq!(got, want, "offset pages {ctx}");

            // Keyset: every position is a cursor, both directions; `offset` is ignored.
            let first = index.search(&q).await.unwrap();
            let by_id = |id: i64| rows.iter().find(|r| r.0 == id).cloned().unwrap();
            for (k, id) in want.iter().enumerate() {
                let row = db.get_release(by_id(*id).0).await.unwrap().unwrap();
                let at = PageCursor::for_row(sort, &row);
                let after = index
                    .search_keyset(
                        &SearchQuery {
                            offset: 3,
                            ..q.clone()
                        },
                        SeekDir::After,
                        &at,
                    )
                    .await
                    .unwrap();
                let lo = (k + 1).min(want.len());
                let hi = (k + 1 + LIMIT).min(want.len());
                let ids: Vec<i64> = after.items.iter().map(|r| r.id).collect();
                assert_eq!(ids, want[lo..hi], "after k={k} {ctx}");
                assert_eq!(after.has_more, k + 1 + LIMIT < want.len(), "more {ctx}");
                assert_eq!(after.total, want.len() as u64, "after total {ctx}");
                let before = index.search_keyset(&q, SeekDir::Before, &at).await.unwrap();
                let ids: Vec<i64> = before.items.iter().map(|r| r.id).collect();
                assert_eq!(ids, want[k.saturating_sub(LIMIT)..k], "before k={k} {ctx}");
                assert_eq!(before.has_more, k > LIMIT, "before more {ctx}");
            }
            assert_eq!(first.items.len(), want.len().min(LIMIT), "first page {ctx}");
        }
    }

    // Hidden categories are excluded by the engine, also past a cursor taken from a hidden row.
    for sort in SORTS {
        let q = SearchQuery {
            sort,
            exclude_categories: vec![2040],
            limit: 100,
            ..SearchQuery::default()
        };
        let visible = rows.iter().filter(|r| r.4 != 2040).count() as u64;
        let hidden_row = rows.iter().find(|r| r.4 == 2040).unwrap();
        let row = db.get_release(hidden_row.0).await.unwrap().unwrap();
        let at = PageCursor::for_row(sort, &row);
        for dir in [SeekDir::After, SeekDir::Before] {
            let p = index.search_keyset(&q, dir, &at).await.unwrap();
            assert_eq!(p.total, visible);
            assert!(p.items.iter().all(|r| r.category_id != 2040));
        }
        let p = index.search(&q).await.unwrap();
        assert!(p.items.iter().all(|r| r.category_id != 2040));
    }

    // A cursor made for another sort order is an error, never a page.
    let row = db.get_release(rows[0].0).await.unwrap().unwrap();
    let foreign = PageCursor::for_row(SORTS[2], &row);
    let q = SearchQuery {
        sort: SORTS[0],
        ..SearchQuery::default()
    };
    let e = index
        .search_keyset(&q, SeekDir::After, &foreign)
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::OutOfRange(_)), "{e:?}");

    // Hostile text is data: no error, no rows.
    for text in [
        "\" OR 1=1 --",
        "NEAR(",
        "a*b*(",
        "'); DROP TABLE release;--",
    ] {
        let q = SearchQuery {
            q: Some(text.to_owned()),
            ..SearchQuery::default()
        };
        assert!(index.search(&q).await.is_ok(), "{text:?}");
        assert!(index.count(&q).await.is_ok(), "{text:?}");
    }

    // A page past the end is empty and still carries the total.
    let p = index
        .search(&SearchQuery {
            offset: 10_000,
            ..SearchQuery::default()
        })
        .await
        .unwrap();
    assert!(p.items.is_empty());
    assert_eq!(p.total, rows.len() as u64);

    // Maintenance hooks, both idempotent. 2.x (`Hooks::Direct`): upsert replaces the text at once,
    // remove drops it. v3 (`Hooks::Reindex`, review 32 L5): both only ask the source of truth to
    // re-index, so after a cycle the release shows its **database** state: nothing that is not in the
    // database is ever indexed, and a live release is never dropped.
    let target = rows[0].0;
    let probe = |token: &str| SearchQuery {
        q: Some(token.to_owned()),
        ..SearchQuery::default()
    };
    let by_title = |t: &str| SearchQuery {
        q: Some(t.to_owned()),
        limit: 100,
        ..SearchQuery::default()
    };
    assert_eq!(index.count(&probe("zzqxprobe")).await.unwrap(), 0);
    let doc = SearchDoc {
        release_id: target,
        title: "zzqxprobe",
        filenames: "f.mkv",
        poster: "",
    };
    index.upsert(&doc).await.unwrap();
    index.upsert(&doc).await.unwrap();
    settle().await;
    let p = index.search(&probe("zzqxprobe")).await.unwrap();
    match hooks {
        Hooks::Direct => assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [target]),
        Hooks::Reindex => {
            assert!(p.items.is_empty());
            let p = index.search(&by_title(&rows[0].1)).await.unwrap();
            assert!(p.items.iter().any(|r| r.id == target));
        }
    }
    index.remove(target).await.unwrap();
    index.remove(target).await.unwrap();
    index.remove(i64::MAX).await.unwrap();
    settle().await;
    assert_eq!(index.count(&probe("zzqxprobe")).await.unwrap(), 0);
    if hooks == Hooks::Reindex {
        let p = index.search(&by_title(&rows[0].1)).await.unwrap();
        assert!(
            p.items.iter().any(|r| r.id == target),
            "a live release is re-indexed"
        );
    }

    // A deleted release is gone from every listing and count (after the store's write path has been
    // indexed: same transaction in 2.x, one indexer cycle in v3).
    let gone = rows[1].0;
    db.delete_release(gone).await.unwrap();
    settle().await;
    let p = index
        .search(&SearchQuery {
            limit: 100,
            ..SearchQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(p.total, rows.len() as u64 - 1);
    assert!(p.items.iter().all(|r| r.id != gone));
}

#[tokio::test]
async fn the_tantivy_index_passes_the_conformance_suite() {
    let (_d, db) = open_db().await;
    let (index, engine, h) = tantivy_over(&db).await;
    search_index_conformance(&db, &index, Hooks::Reindex, || settle(&h, &engine)).await;
}
