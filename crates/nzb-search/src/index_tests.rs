//! `TantivyIndex` behaviour beyond the 2.x contract: reference order on random multi-segment corpora,
//! v3 filters, facets, the count budget (Q1), the offset cap (Q2), hydration drops and cursors (L3,
//! SEC-090), the search semaphore and deadline (M6, SEC-095), prefix and fuzzy fallback (Q5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
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

use std::sync::Arc;
use std::time::Duration;

use nzb_core::Taxonomy;
use nzb_store::{PageCursor, SearchIndex, SearchQuery, SeekDir, SortKey};
use proptest::prelude::*;

use crate::clock::{StepClock, SystemClock};
use crate::config::{FuzzyMode, SearchConfig};
use crate::conformance_tests::{SORTS, cmp};
use crate::doc::IndexDoc;
use crate::error::SearchError;
use crate::index::SearchIndexV3;
use crate::request::{MatchMode, SearchRequest, Total, exclusion_set};
use crate::testkit::{Row, doc, mem_index, row_of};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn sys() -> Arc<SystemClock> {
    Arc::new(SystemClock::new())
}

fn as_row(d: &IndexDoc) -> Row {
    (
        d.id,
        d.title.clone(),
        d.total_bytes,
        d.posted_at,
        d.category_id,
    )
}

fn arb_doc() -> impl Strategy<Value = (String, u64, Option<i64>, u32)> {
    (
        "[aAbB][a-c ]{0,3}",
        0u64..4,
        prop::option::of(0i64..4),
        prop::sample::select(vec![5040u32, 5030, 2040, 8010]),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Every sort, every offset and keyset position, multi-segment: equal to the reference order
    /// (ties in every key, undated rows, mixed case titles), hidden categories excluded.
    #[test]
    fn pages_follow_the_reference_order(
        raw in prop::collection::vec(arb_doc(), 1..40),
        split in 1usize..5,
        hide_movies in any::<bool>(),
    ) {
        let docs: Vec<IndexDoc> = raw
            .iter()
            .enumerate()
            .map(|(i, (t, size, posted, cat))| {
                let mut d = doc(i as i64 + 1, t);
                d.total_bytes = *size * 100;
                d.posted_at = *posted;
                d.category_id = *cat;
                d
            })
            .collect();
        let batches: Vec<Vec<IndexDoc>> = docs.chunks(docs.len().div_ceil(split)).map(<[_]>::to_vec).collect();
        let (index, _h, _e) = mem_index(SearchConfig::default(), sys(), &batches);
        let rows: Vec<Row> = docs.iter().map(as_row).collect();
        let excl = if hide_movies { vec![2040] } else { vec![] };
        rt().block_on(async {
            for sort in SORTS {
                let mut want: Vec<Row> = rows.iter().filter(|r| !excl.contains(&r.4)).cloned().collect();
                want.sort_by(|a, b| cmp(sort, a, b));
                let want: Vec<i64> = want.iter().map(|r| r.0).collect();
                let q = SearchQuery { sort, limit: 3, exclude_categories: excl.clone(), ..SearchQuery::default() };
                let mut got = Vec::new();
                for off in (0..=want.len()).step_by(3) {
                    let p = index.search(&SearchQuery { offset: off as u32, ..q.clone() }).await.unwrap();
                    prop_assert_eq!(p.total, want.len() as u64);
                    got.extend(p.items.iter().map(|r| r.id));
                }
                prop_assert_eq!(&got, &want);
                for (k, id) in want.iter().enumerate() {
                    let at = PageCursor::for_row(sort, &row_of(&docs[(*id - 1) as usize]));
                    let a = index.search_keyset(&q, SeekDir::After, &at).await.unwrap();
                    let ids: Vec<i64> = a.items.iter().map(|r| r.id).collect();
                    prop_assert_eq!(&ids[..], &want[(k + 1).min(want.len())..(k + 4).min(want.len())]);
                    let b = index.search_keyset(&q, SeekDir::Before, &at).await.unwrap();
                    let ids: Vec<i64> = b.items.iter().map(|r| r.id).collect();
                    prop_assert_eq!(&ids[..], &want[k.saturating_sub(3)..k]);
                }
            }
            Ok(())
        })?;
    }
}

#[test]
fn v3_filters_and_facets() {
    let mut docs = Vec::new();
    for i in 1..=12 {
        let mut d = doc(i, &format!("Show.Name.S01E{i:02}.1080p-GRP"));
        d.category_id = [5040u32, 5030, 2040, 6000][(i % 4) as usize];
        d.category_parent = [5000u32, 5000, 2000, 6000][(i % 4) as usize];
        d.added_by = Some(i % 3);
        d.source_label = Some(if i % 2 == 0 {
            "Torrent".into()
        } else {
            "personal".into()
        });
        docs.push(d);
    }
    let (index, _h, _e) = mem_index(SearchConfig::default(), sys(), &[docs.clone()]);
    rt().block_on(async {
        let base = SearchQuery {
            limit: 100,
            exclude_categories: vec![6000],
            ..SearchQuery::default()
        };
        // Facets count the query's matches per category, hidden ones excluded (SEC-090).
        let p = index
            .search_page(&SearchRequest {
                query: base.clone(),
                want_facets: true,
                ..SearchRequest::default()
            })
            .await
            .unwrap();
        assert_eq!(p.total, Total::Exact(9));
        assert_eq!(p.facets, vec![(2040, 3), (5030, 3), (5040, 3)]);
        // added_by and source label (ASCII case-insensitive).
        let p = index
            .search_page(&SearchRequest {
                query: base.clone(),
                added_by: Some(1),
                source_label: Some("TORRENT".into()),
                ..SearchRequest::default()
            })
            .await
            .unwrap();
        let want: Vec<i64> = docs
            .iter()
            .filter(|d| d.added_by == Some(1) && d.id % 2 == 0 && d.category_id != 6000)
            .map(|d| d.id)
            .rev()
            .collect();
        assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), want);
        // A negative uploader id matches nothing (never "no filter").
        let p = index
            .search_page(&SearchRequest {
                query: base,
                added_by: Some(-5),
                ..SearchRequest::default()
            })
            .await
            .unwrap();
        assert_eq!(p.total, Total::Exact(0));
    });
}

/// T127: `ingested_since` keeps releases ingested at or after the time (inclusive) (the saved-search "new" badge), on the
/// `added` fast column, combined with text, filters and the hidden-category exclusion; with and without text (the
/// walk path declines it), across segments, for counts and pages alike.
#[test]
fn ingested_since_keeps_only_newer_releases() {
    let docs: Vec<IndexDoc> = (1..=12)
        .map(|i| {
            let mut d = doc(i, &format!("Show.Name.S01E{i:02}.1080p"));
            d.ingested_at = 1_000 + i * 10;
            d.category_id = if i % 4 == 0 { 6000 } else { 5040 };
            d.category_parent = if i % 4 == 0 { 6000 } else { 5000 };
            d
        })
        .collect();
    let (first, second) = docs.split_at(6);
    let (index, _h, _e) = mem_index(
        SearchConfig::default(),
        sys(),
        &[first.to_vec(), second.to_vec()],
    );
    rt().block_on(async {
        for text in [None, Some("show")] {
            let req = |after: Option<i64>, exclude: Vec<u32>| SearchRequest {
                query: SearchQuery {
                    q: text.map(str::to_owned),
                    exclude_categories: exclude,
                    limit: 50,
                    ..SearchQuery::default()
                },
                match_mode: MatchMode::Prefix,
                ingested_since: after,
                ..SearchRequest::default()
            };
            // At or after 1_070 (doc 7 exactly: inclusive, review 42 I2): docs 7..=12; 1_061 gives the same.
            let all = req(Some(1_070), vec![]);
            assert_eq!(index.count_total(&all).await.unwrap(), Total::Exact(6));
            let p = index.search_page(&all).await.unwrap();
            let mut ids: Vec<i64> = p.items.iter().map(|r| r.id).collect();
            ids.sort_unstable();
            assert_eq!(ids, vec![7, 8, 9, 10, 11, 12], "{text:?}");
            // Hidden categories stay out of the count (docs 8 and 12 are XXX).
            let hidden = req(Some(1_061), vec![6000]);
            assert_eq!(index.count_total(&hidden).await.unwrap(), Total::Exact(4));
            // Nothing newer, everything newer.
            assert_eq!(
                index.count_total(&req(Some(1_121), vec![])).await.unwrap(),
                Total::Exact(0)
            );
            assert_eq!(
                index
                    .count_total(&req(Some(i64::MIN), vec![]))
                    .await
                    .unwrap(),
                Total::Exact(12)
            );
            assert_eq!(
                index.count_total(&req(None, vec![])).await.unwrap(),
                Total::Exact(12)
            );
        }
    });
}

#[test]
fn count_budget_gives_at_least_and_pages_stay_exact() {
    let docs: Vec<IndexDoc> = (1..=50).map(|i| doc(i, "common")).collect();
    let clock = Arc::new(StepClock::new(0));
    let cfg = SearchConfig {
        count_budget_ms: 5,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, clock.clone(), &[docs]);
    index.service().set_check_every(1);
    rt().block_on(async {
        let req = SearchRequest::from(SearchQuery {
            q: Some("common".into()),
            ..SearchQuery::default()
        });
        assert_eq!(index.count_total(&req).await.unwrap(), Total::Exact(50));
        // Every clock reading now takes 1 ms: the count stops at the 5 ms budget (D35, Q1).
        clock.set_step(1);
        let t = index.count_total(&req).await.unwrap();
        assert!(matches!(t, Total::AtLeast(n) if n > 0 && n < 50), "{t:?}");
        // A page is never cut by the count budget (its order needs every match); the deadline is far.
        let p = index.search_page(&req).await.unwrap();
        assert_eq!(p.total, Total::Exact(50));
        // The trait count is exact too.
        assert_eq!(index.count(&req.query).await.unwrap(), 50);
    });
}

#[test]
fn sec_095_deadline_covers_collection() {
    let batches: Vec<Vec<IndexDoc>> = (0..4)
        .map(|s| (1..=20).map(|i| doc(s * 20 + i, "x")).collect())
        .collect();
    let clock = Arc::new(StepClock::new(0));
    let cfg = SearchConfig {
        query_deadline_ms: 30,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, clock.clone(), &batches);
    index.service().set_check_every(1);
    rt().block_on(async {
        // A text query takes the collect pass (a browse would walk ~limit docs and be done).
        let q = SearchQuery {
            q: Some("x".into()),
            limit: 10,
            ..SearchQuery::default()
        };
        assert_eq!(index.count(&q).await.unwrap(), 80);
        clock.set_step(1);
        let e = index
            .search_page(&SearchRequest::from(q.clone()))
            .await
            .unwrap_err();
        assert!(matches!(e, SearchError::Deadline), "{e:?}");
        // Through the 2.x trait it is a TimedOut I/O error (uniform 503 in the web layer).
        let e = index.search(&q).await.unwrap_err();
        assert!(e.to_string().contains("search deadline"), "{e}");
        // The sorted walk checks the same deadline while it walks (every match filtered away here).
        index
            .service()
            .force_path(Some(crate::index::PathChoice::Walk));
        let walk = SearchQuery {
            min_bytes: Some(1_000_000),
            limit: 10,
            ..SearchQuery::default()
        };
        let e = index
            .search_page(&SearchRequest::from(walk))
            .await
            .unwrap_err();
        assert!(matches!(e, SearchError::Deadline), "{e:?}");
    });
}

#[test]
fn offset_cap_serves_the_end_and_refuses_the_middle() {
    let docs: Vec<IndexDoc> = (1..=40).map(|i| doc(i, "x")).collect();
    let cfg = SearchConfig {
        max_offset: 10,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, sys(), &[docs]);
    rt().block_on(async {
        let q = |offset| SearchQuery {
            offset,
            limit: 5,
            ..SearchQuery::default()
        };
        // Within the cap: normal pages (date desc: ids 40, 39, ...).
        let p = index.search(&q(10)).await.unwrap();
        assert_eq!(
            p.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            [30, 29, 28, 27, 26]
        );
        // Beyond the cap and far from the end: refused (D35, Q2).
        let e = index
            .search_page(&SearchRequest::from(q(20)))
            .await
            .unwrap_err();
        assert!(matches!(e, SearchError::OutOfRange(_)), "{e:?}");
        // Near the end ("Last"): served from the end.
        let p = index.search(&q(35)).await.unwrap();
        assert_eq!(
            p.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            [5, 4, 3, 2, 1]
        );
        assert_eq!(p.total, 40);
        let p = index.search(&q(38)).await.unwrap();
        assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1]);
        let p = index.search(&q(40)).await.unwrap();
        assert!(p.items.is_empty());
        assert_eq!(p.total, 40);
        // Keyset paging is not capped.
        let at = PageCursor::for_row(SortKey::DateDesc, &row_of(&doc(25, "x")));
        let p = index
            .search_keyset(&q(0), SeekDir::After, &at)
            .await
            .unwrap();
        assert_eq!(
            p.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            [24, 23, 22, 21, 20]
        );
    });
}

#[test]
fn sec_090_category_moved_into_hidden_is_not_rendered_during_index_lag() {
    let docs: Vec<IndexDoc> = (1..=6).map(|i| doc(i, "x")).collect();
    let (index, h, _e) = mem_index(SearchConfig::default(), sys(), &[docs.clone()]);
    // Release 4 was moved into XXX (6000) and release 2 trashed; the index has not caught up yet.
    let mut moved = row_of(&docs[3]);
    moved.category_id = 6000;
    h.put(moved);
    h.remove(2);
    rt().block_on(async {
        let q = SearchQuery {
            exclude_categories: vec![6000],
            limit: 10,
            ..SearchQuery::default()
        };
        let p = index
            .search_page(&SearchRequest::from(q.clone()))
            .await
            .unwrap();
        assert_eq!(
            p.items.iter().map(|r| r.id).collect::<Vec<_>>(),
            [6, 5, 3, 1]
        );
        assert_eq!(p.dropped, 2);
        // Accepted lag effect (ARCHITECTURE v3 3.5): the total may still count them for one cycle.
        assert_eq!(p.total, Total::Exact(6));
    });
}

#[test]
fn sec_090_cursor_never_comes_from_a_dropped_row() {
    let docs: Vec<IndexDoc> = (1..=9).map(|i| doc(i, &format!("title {i}"))).collect();
    let (index, h, _e) = mem_index(SearchConfig::default(), sys(), &[docs.clone()]);
    // Index lag: release 7 is now hidden. It sits at the end of the first page (date desc: 9, 8, 7).
    let mut moved = row_of(&docs[6]);
    moved.category_id = 6000;
    moved.title = "hidden title".into();
    h.put(moved);
    rt().block_on(async {
        let q = SearchQuery {
            exclude_categories: vec![6000],
            limit: 3,
            sort: SortKey::TitleAsc,
            ..SearchQuery::default()
        };
        // Title order: "title 1" .. "title 9"; page 1 holds 1, 2, 3 -> nothing dropped; walk until the
        // page that would contain 7.
        let mut at: Option<PageCursor> = None;
        let mut seen = Vec::new();
        loop {
            let p = match &at {
                None => index
                    .search_page(&SearchRequest::from(q.clone()))
                    .await
                    .unwrap(),
                Some(c) => index
                    .search_keyset_page(&SearchRequest::from(q.clone()), SeekDir::After, c)
                    .await
                    .unwrap(),
            };
            // Rows shown are the only cursor sources; a dropped row's title never reaches a cursor.
            for r in &p.items {
                assert_ne!(r.id, 7);
                seen.push(r.id);
            }
            let Some(last) = p.items.last() else { break };
            let c = PageCursor::for_row(q.sort, last);
            assert!(!c.encode().unwrap().contains(&hex("hidden")));
            at = Some(c);
            if !p.has_more {
                break;
            }
        }
        assert_eq!(seen, [1, 2, 3, 4, 5, 6, 8, 9]);
    });
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sec_090_user_pref_cannot_unhide_instance_hidden() {
    let tax = Taxonomy::builtin().unwrap();
    let xxx: Vec<u32> = tax
        .subtree_ids(nzb_core::XXX_CATEGORY)
        .into_iter()
        .map(u32::from)
        .collect();
    assert!(!xxx.is_empty());
    assert_eq!(exclusion_set(&tax, true, false), Vec::<u32>::new());
    // The instance hides: whatever the preference says.
    assert_eq!(exclusion_set(&tax, false, false), xxx);
    assert_eq!(exclusion_set(&tax, false, true), xxx);
    // The preference can only add.
    assert_eq!(exclusion_set(&tax, true, true), xxx);
}

#[test]
fn sec_090_hidden_rows_absent_from_hits_totals_facets_and_cursors() {
    let mut docs = Vec::new();
    for i in 1..=10 {
        let mut d = doc(i, "same words");
        d.category_id = if i % 2 == 0 { 6000 } else { 5040 };
        docs.push(d);
    }
    let (index, _h, _e) = mem_index(SearchConfig::default(), sys(), &[docs.clone()]);
    rt().block_on(async {
        for sort in SORTS {
            let req = SearchRequest {
                query: SearchQuery {
                    q: Some("same".into()),
                    exclude_categories: vec![6000],
                    sort,
                    limit: 2,
                    ..SearchQuery::default()
                },
                want_facets: true,
                ..SearchRequest::default()
            };
            let p = index.search_page(&req).await.unwrap();
            assert_eq!(p.total, Total::Exact(5));
            assert_eq!(p.facets, vec![(5040, 5)]);
            assert_eq!(p.dropped, 0, "the engine never returned a hidden hit");
            // A cursor taken from a hidden row (forged or stale) still yields visible rows only.
            for hidden in docs.iter().filter(|d| d.category_id == 6000) {
                let at = PageCursor::for_row(sort, &row_of(hidden));
                for dir in [SeekDir::After, SeekDir::Before] {
                    let k = index.search_keyset_page(&req, dir, &at).await.unwrap();
                    assert!(k.items.iter().all(|r| r.category_id != 6000));
                    assert_eq!(k.dropped, 0);
                    assert_eq!(k.total, Total::Exact(5));
                }
            }
            assert_eq!(index.count_total(&req).await.unwrap(), Total::Exact(5));
        }
    });
}

#[test]
fn prefix_mode_and_fuzzy_fallback() {
    let docs = vec![
        doc(1, "Matrix.Reloaded.1080p"),
        doc(2, "Matrimony"),
        doc(3, "Other"),
    ];
    let run = |cfg: SearchConfig, text: &str, mode: MatchMode, toggled: bool| {
        let (index, _h, _e) = mem_index(cfg, sys(), &[docs.clone()]);
        rt().block_on(async move {
            let p = index
                .search_page(&SearchRequest {
                    query: SearchQuery {
                        q: Some(text.into()),
                        limit: 10,
                        ..SearchQuery::default()
                    },
                    match_mode: mode,
                    fuzzy_requested: toggled,
                    ..SearchRequest::default()
                })
                .await
                .unwrap();
            let mut ids: Vec<i64> = p.items.iter().map(|r| r.id).collect();
            ids.sort_unstable();
            (ids, p.fuzzy_fallback)
        })
    };
    let d = SearchConfig::default;
    assert_eq!(run(d(), "matri", MatchMode::Exact, false), (vec![], false));
    assert_eq!(
        run(d(), "matri", MatchMode::Prefix, false),
        (vec![1, 2], false)
    );
    // Prefix disabled by config: exact only, then the fuzzy fallback ("matri" -> "matrix").
    let no_prefix = SearchConfig {
        prefix: false,
        ..d()
    };
    assert_eq!(
        run(no_prefix.clone(), "matri", MatchMode::Prefix, false),
        (vec![1], true)
    );
    // Fuzzy only when nothing matched exactly (D35, Q5: "fallback").
    assert_eq!(
        run(d(), "matrx reloaded", MatchMode::Prefix, false),
        (vec![1], true)
    );
    assert_eq!(
        run(d(), "matrix", MatchMode::Prefix, false),
        (vec![1], false)
    );
    let off = SearchConfig {
        fuzzy: FuzzyMode::Off,
        ..d()
    };
    assert_eq!(
        run(off, "matrx reloaded", MatchMode::Fuzzy, true),
        (vec![], false)
    );
    let toggle = SearchConfig {
        fuzzy: FuzzyMode::Toggle,
        ..d()
    };
    assert_eq!(
        run(toggle.clone(), "matrx reloaded", MatchMode::Prefix, false),
        (vec![], false)
    );
    assert_eq!(
        run(toggle, "matrx reloaded", MatchMode::Prefix, true),
        (vec![1], true)
    );
    // The 2.x trait path is always exact (FTS5 parity): checked by the parity test.
    let _ = no_prefix;
}

/// Review 42 L1: a caller deadline bounds the engine work itself (not only the caller's wait): the count stops at it,
/// whatever the configured query deadline and count budget, and its slot is free again right after.
#[test]
fn sec_095_caller_deadline_stops_the_count_and_frees_its_slot() {
    let docs: Vec<IndexDoc> = (1..=200).map(|i| doc(i, "common")).collect();
    let clock = Arc::new(StepClock::new(0));
    let cfg = SearchConfig {
        query_deadline_ms: 60_000,
        count_budget_ms: 60_000,
        max_concurrent_searches: 2,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, clock.clone(), &[docs]);
    index.service().set_check_every(1);
    rt().block_on(async {
        let req = |caller: Option<u64>| SearchRequest {
            query: SearchQuery {
                q: Some("common".into()),
                ..SearchQuery::default()
            },
            caller_deadline_ms: caller,
            ..SearchRequest::default()
        };
        // Every clock reading takes 1 ms: counting 200 documents takes well over 20 ms of engine time.
        clock.set_step(1);
        assert_eq!(
            index.count_total(&req(None)).await.unwrap(),
            Total::Exact(200)
        );
        let cut = index.count_total(&req(Some(20))).await;
        // Stopped early: either the deadline error or the lower bound of a cut count, never the full count.
        assert!(
            matches!(cut, Err(SearchError::Deadline) | Ok(Total::AtLeast(_))),
            "{cut:?}"
        );
        assert_eq!(index.service().available_slots(), 2);
    });
}

/// Review 42 L1: best-effort work with a caller deadline never queues for a slot: with every slot taken it is `Busy`
/// at once (no `semaphore_wait_ms`), and it never delays the searches waiting for the slot.
#[test]
fn sec_095_caller_deadline_never_queues_for_a_search_slot() {
    let cfg = SearchConfig {
        max_concurrent_searches: 1,
        semaphore_wait_ms: 5_000,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, sys(), &[vec![doc(1, "x")]]);
    let svc = Arc::clone(index.service());
    rt().block_on(async move {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let s2 = Arc::clone(&svc);
        let held = tokio::spawn(async move {
            s2.run_blocking(move |_e, _d, _c| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
        });
        started_rx.await.unwrap();
        let started = std::time::Instant::now();
        let e = index
            .count_total(&SearchRequest {
                caller_deadline_ms: Some(150),
                ..SearchRequest::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(e, SearchError::Busy), "{e:?}");
        assert!(
            started.elapsed() < Duration::from_millis(1_000),
            "{:?}",
            started.elapsed()
        );
        release_tx.send(()).unwrap();
        held.await.unwrap().unwrap();
        assert_eq!(svc.available_slots(), 1);
    });
}

#[test]
fn sec_095_search_semaphore_bounds_concurrent_engine_work() {
    let docs = vec![doc(1, "x")];
    let cfg = SearchConfig {
        max_concurrent_searches: 1,
        semaphore_wait_ms: 50,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, sys(), &[docs]);
    let svc = Arc::clone(index.service());
    rt().block_on(async move {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        // A search whose engine work blocks until released.
        let s2 = Arc::clone(&svc);
        let req = tokio::spawn(async move {
            s2.run_blocking(move |_e, _d, _c| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
        });
        started_rx.await.unwrap();
        assert_eq!(svc.available_slots(), 0);
        // The HTTP request is dropped (client gone, timeout): its engine work still runs, so the slot
        // stays taken (the owned permit lives inside the blocking closure, review M6 b).
        req.abort();
        let _ = req.await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(svc.available_slots(), 0);
        // Another search waits, then gets the uniform Busy.
        let e = index
            .search_page(&SearchRequest::default())
            .await
            .unwrap_err();
        assert!(matches!(e, SearchError::Busy), "{e:?}");
        // Through the 2.x trait: ResourceBusy I/O error.
        assert!(index.search(&SearchQuery::default()).await.is_err());
        // The work ends: the slot is free again and searches run.
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if svc.available_slots() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(svc.available_slots(), 1);
        assert_eq!(index.count(&SearchQuery::default()).await.unwrap(), 1);
    });
}

#[test]
fn sec_091_index_contains_no_account_data() {
    let (schema, _) = crate::schema::build();
    let names: Vec<String> = schema.fields().map(|(_, e)| e.name().to_owned()).collect();
    // No stored field at all: the doc store stays empty (and its LRU cache is never filled).
    assert!(schema.fields().all(|(_, e)| !e.is_stored()), "{names:?}");
    for banned in [
        "user", "name", "email", "password", "session", "key", "token", "secret", "ip",
    ] {
        assert!(
            names
                .iter()
                .all(|n| n != banned && !n.starts_with(&format!("{banned}_"))),
            "{banned} in {names:?}"
        );
    }
    // `added_by` is an account id (u64), never a login or display name.
    let added_by = schema.get_field("added_by").unwrap();
    assert!(matches!(
        schema.get_field_entry(added_by).field_type(),
        tantivy::schema::FieldType::U64(_)
    ));
}

#[test]
fn sec_095_deadline_is_checked_between_segment_scorers() {
    // No per-document clock reading at all: the deadline still stops the search between the
    // per-segment scorer builds (where term sets decode their postings).
    let batches: Vec<Vec<IndexDoc>> = (0..8)
        .map(|s| (1..=5).map(|i| doc(s * 5 + i, "x")).collect())
        .collect();
    let clock = Arc::new(StepClock::new(0));
    let cfg = SearchConfig {
        query_deadline_ms: 3,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, clock.clone(), &batches);
    index.service().set_check_every(u64::MAX);
    rt().block_on(async {
        let q = SearchQuery {
            q: Some("x".into()),
            limit: 10,
            ..SearchQuery::default()
        };
        assert_eq!(index.count(&q).await.unwrap(), 40);
        clock.set_step(1);
        let e = index.search(&q).await.unwrap_err();
        assert!(e.to_string().contains("search deadline"), "{e}");
    });
}

#[test]
fn reconciliation_hooks_enqueue_instead_of_writing() {
    let docs = vec![doc(1, "original")];
    let (index, h, engine) = mem_index(SearchConfig::default(), sys(), &[docs]);
    rt().block_on(async {
        let d = nzb_store::SearchDoc {
            release_id: 1,
            title: "injected",
            filenames: "",
            poster: "",
        };
        index.upsert(&d).await.unwrap();
        index.remove(1).await.unwrap();
        index.remove(77).await.unwrap();
        // Outbox rows requested; the index itself is untouched (no write around the outbox, no
        // text that is not in the database).
        assert_eq!(*h.1.lock().unwrap(), [1, 1, 77]);
        assert_eq!(engine.live_versions().unwrap(), [(1, 1)]);
        let q = SearchQuery {
            q: Some("injected".into()),
            ..SearchQuery::default()
        };
        assert_eq!(index.count(&q).await.unwrap(), 0);
    });
}

#[test]
fn hidden_only_vocabulary_does_not_narrow_or_displace_visible_search() {
    rt().block_on(async {
        for expansion_category in [None, Some(6000), Some(8010)] {
            let mut docs = vec![doc(1, "public neutral")];
            if let Some(cat) = expansion_category {
                docs.extend((0..64).map(|n| {
                    let mut d = doc(n + 2, &format!("par{n:03}"));
                    d.category_id = cat;
                    d.category_parent = cat / 1000 * 1000;
                    d
                }));
            }
            let (index, _, _) = mem_index(SearchConfig::default(), sys(), &[docs.clone()]);
            let req = |q: &str, mode| SearchRequest {
                query: SearchQuery {
                    q: Some(q.into()),
                    exclude_categories: vec![6000],
                    limit: 100,
                    ..SearchQuery::default()
                },
                match_mode: mode,
                want_facets: true,
                ..SearchRequest::default()
            };
            let par = index
                .search_page(&req("par", MatchMode::Prefix))
                .await
                .unwrap();
            assert!(par.expansion_bounded);
            assert_eq!(par.narrowed, expansion_category == Some(8010));
            if expansion_category == Some(8010) {
                assert_eq!(par.total, Total::Exact(63));
                assert_eq!(par.items.len(), 63);
            } else {
                assert_eq!(par.total, Total::Exact(0));
                assert!(par.items.is_empty());
                assert!(par.facets.is_empty());
                assert!(par.fuzzy_fallback);
            }
            let public = index
                .search_page(&req("public", MatchMode::Prefix))
                .await
                .unwrap();
            assert_eq!(public.items.iter().map(|r| r.id).collect::<Vec<_>>(), [1]);
            assert!(!public.narrowed);
            for (q, mode) in [
                ("public", MatchMode::Exact),
                ("", MatchMode::Prefix),
                ("pa", MatchMode::Prefix),
            ] {
                let p = index.search_page(&req(q, mode)).await.unwrap();
                assert!(!p.expansion_bounded, "no expansion for {q:?}/{mode:?}");
            }
            if expansion_category == Some(6000) {
                // With a full default-sized hidden vocabulary, the visible alternative sorted
                // after those terms must still be found by the ordinary prefix request.
                docs.push(doc(100, "parzzvisible"));
                let (mixed, _, _) = mem_index(SearchConfig::default(), sys(), &[docs]);
                let p = mixed
                    .search_page(&req("par", MatchMode::Prefix))
                    .await
                    .unwrap();
                assert_eq!(p.items.iter().map(|r| r.id).collect::<Vec<_>>(), [100]);
                assert!(!p.narrowed);
            }
        }
    });
}

#[test]
fn expansion_policy_flag_and_visibility_work_survive_fallback_limits() {
    let mut hidden = doc(1, "parhidden");
    hidden.category_id = 6000;
    hidden.category_parent = 6000;
    let cfg = SearchConfig {
        expansion_postings_budget: 1,
        expansion_dict_entries: 1,
        ..SearchConfig::default()
    };
    let (index, _, engine) = mem_index(cfg.clone(), sys(), &[vec![hidden]]);
    let req = SearchRequest {
        query: SearchQuery {
            q: Some("par".into()),
            exclude_categories: vec![6000],
            ..SearchQuery::default()
        },
        match_mode: MatchMode::Prefix,
        ..SearchRequest::default()
    };
    let result = crate::engine_search(
        &engine,
        &req,
        None,
        &cfg,
        &crate::clock::Deadline::after(sys(), 60_000),
        None,
    )
    .unwrap();
    // The first pass spends the single posting visit. The fallback must not replenish it.
    assert!(result.fuzzy_fallback);
    assert_eq!(result.stats.visibility_postings, 0);
    assert_eq!(result.total, 0);
    assert!(result.narrowed);
    rt().block_on(async {
        let p = index.search_page(&req).await.unwrap();
        assert!(p.expansion_bounded);
        assert!(p.items.is_empty());
        let off = SearchConfig {
            prefix: false,
            fuzzy: FuzzyMode::Off,
            ..cfg
        };
        let (index, _, _) = mem_index(off, sys(), &[vec![doc(2, "parvisible")]]);
        assert!(!index.search_page(&req).await.unwrap().expansion_bounded);
    });
}
