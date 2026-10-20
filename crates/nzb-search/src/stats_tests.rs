//! T132: the Statistics aggregations on in-memory multi-segment indexes: exact numbers, hidden categories
//! (SEC-090), output bounds and the search deadline/slots (SEC-095). Names carry their SEC id for
//! `scripts/sec_coverage.sh`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::sync::Arc;

use crate::clock::{Deadline, StepClock, SystemClock};
use crate::config::SearchConfig;
use crate::doc::IndexDoc;
use crate::error::SearchError;
use crate::index::SearchIndexV3;
use crate::stats::{MAX_MONTHS, MAX_TOP, Ranked, StatsRequest};
use crate::testkit::{doc, mem_index};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

const DAY: i64 = 86_400;
const T0: i64 = 1_700_000_000;

#[allow(clippy::too_many_arguments)]
fn release(
    id: i64,
    cat: u32,
    group: Option<&str>,
    res: Option<&str>,
    src: Option<&str>,
    fam: Option<&str>,
    year: Option<u32>,
    ingested: i64,
) -> IndexDoc {
    let mut d = doc(id, &format!("Release.{id}"));
    d.category_id = cat;
    d.category_parent = cat / 1000 * 1000;
    d.group = group.map(str::to_owned);
    d.resolution = res.map(str::to_owned);
    d.source = src.map(str::to_owned);
    d.family = fam.map(str::to_owned);
    d.year = year;
    d.ingested_at = ingested;
    d
}

/// Twelve visible releases in three segments plus three XXX ones (one with a group that exists only there).
fn corpus() -> Vec<Vec<IndexDoc>> {
    vec![
        vec![
            release(
                1,
                5040,
                Some("Alpha"),
                Some("1080p"),
                Some("WEBDL"),
                Some("tv"),
                Some(2020),
                T0,
            ),
            release(
                2,
                5040,
                Some("ALPHA"),
                Some("1080p"),
                Some("WEBDL"),
                Some("tv"),
                Some(2020),
                T0 - DAY,
            ),
            release(
                3,
                2040,
                Some("beta"),
                Some("2160p"),
                Some("BluRay"),
                Some("movie"),
                Some(2019),
                T0 - 10 * DAY,
            ),
            release(4, 2040, None, None, None, None, None, T0 - 40 * DAY),
        ],
        vec![
            release(
                5,
                5040,
                Some("alpha"),
                Some("720p"),
                Some("HDTV"),
                Some("tv"),
                Some(2021),
                T0 - 2 * DAY,
            ),
            release(
                6,
                3010,
                Some("gamma"),
                None,
                None,
                Some("music"),
                Some(2020),
                T0 - 70 * DAY,
            ),
            release(
                7,
                3010,
                Some("beta"),
                None,
                None,
                Some("music"),
                None,
                T0 - 75 * DAY,
            ),
            release(8, 8010, None, None, None, None, None, T0 - 400 * DAY),
            // The three hidden ones: one group ("onlyhidden") exists nowhere else.
            release(
                13,
                6040,
                Some("OnlyHidden"),
                Some("2160p"),
                Some("WEBDL"),
                Some("movie"),
                Some(1999),
                T0,
            ),
            release(
                14,
                6010,
                Some("alpha"),
                Some("480p"),
                Some("DVD"),
                Some("movie"),
                Some(1999),
                T0 - DAY,
            ),
        ],
        vec![
            release(
                9,
                5040,
                Some("delta"),
                Some("1080p"),
                Some("BluRay"),
                Some("anime"),
                Some(2022),
                T0 - 3 * DAY,
            ),
            release(
                10,
                2040,
                Some("gamma"),
                Some("1080p"),
                Some("BluRay"),
                Some("movie"),
                Some(2022),
                T0 - 35 * DAY,
            ),
            release(
                11,
                2040,
                None,
                Some("720p"),
                Some("WEBRip"),
                Some("movie"),
                Some(2021),
                T0 - 36 * DAY,
            ),
            release(
                12,
                8010,
                Some("epsilon"),
                None,
                None,
                None,
                None,
                T0 - 800 * DAY,
            ),
            release(
                15,
                6040,
                Some("OnlyHidden"),
                None,
                None,
                None,
                None,
                T0 - 5 * DAY,
            ),
        ],
    ]
}

const XXX: [u32; 3] = [6000, 6010, 6040];

fn request(exclude: &[u32]) -> StatsRequest {
    StatsRequest {
        exclude: exclude.to_vec(),
        top_groups: 10,
        top_years: 10,
        // Three 30-day buckets ending at T0 + 1 day.
        month_bounds: vec![T0 - 89 * DAY, T0 - 59 * DAY, T0 - 29 * DAY, T0 + DAY],
        recent_since: vec![T0 - 7 * DAY, T0 - 30 * DAY],
    }
}

fn top(r: &Ranked) -> Vec<(&str, u64)> {
    r.top.iter().map(|(v, n)| (v.as_str(), *n)).collect()
}

#[test]
fn stats_numbers_are_exact_across_segments() {
    let (index, _h, _e) = mem_index(
        SearchConfig::default(),
        Arc::new(SystemClock::new()),
        &corpus(),
    );
    rt().block_on(async {
        let s = index.library_stats(&request(&XXX)).await;
        let g = s.groups.unwrap();
        // Group names are folded to ASCII lower case at indexing: Alpha/ALPHA/alpha are one group.
        assert_eq!(
            top(&g),
            vec![
                ("alpha", 3),
                ("beta", 2),
                ("gamma", 2),
                ("delta", 1),
                ("epsilon", 1)
            ]
        );
        assert_eq!((g.without, g.distinct, g.total), (3, 5, 12));

        let q = s.quality.unwrap();
        assert_eq!(
            top(&q.resolution),
            vec![("1080p", 4), ("720p", 2), ("2160p", 1)]
        );
        assert_eq!(q.resolution.without, 5);
        assert_eq!(
            top(&q.source),
            vec![("BluRay", 3), ("WEBDL", 2), ("HDTV", 1), ("WEBRip", 1)]
        );
        assert_eq!(
            top(&q.family),
            vec![("movie", 3), ("tv", 3), ("music", 2), ("anime", 1)]
        );
        assert_eq!(q.family.without, 3);
        assert_eq!(
            top(&q.year),
            vec![("2020", 3), ("2022", 2), ("2021", 2), ("2019", 1)]
        );
        assert_eq!((q.year.without, q.year.total), (4, 12));

        let t = s.timeline.unwrap();
        // [T0-89d, T0-59d): 6, 7 (70 and 75 days); [T0-59d, T0-29d): 4, 10, 11; [T0-29d, T0+1d): 1, 2, 3, 5, 9.
        assert_eq!(t.months, vec![2, 3, 5]);
        assert_eq!(t.recent, vec![4, 5]);
        assert_eq!(t.total, 12);
    });
}

#[test]
fn sec_090_stats_never_count_a_hidden_release() {
    // The same corpus without the hidden releases gives exactly the same numbers with or without the exclusion set:
    // a hidden release changes nothing, and a group that exists only in hidden releases is never named.
    let visible: Vec<Vec<IndexDoc>> = corpus()
        .into_iter()
        .map(|b| {
            b.into_iter()
                .filter(|d| !XXX.contains(&d.category_id))
                .collect()
        })
        .collect();
    let (with_hidden, _h, _e) = mem_index(
        SearchConfig::default(),
        Arc::new(SystemClock::new()),
        &corpus(),
    );
    let (without, _h2, _e2) = mem_index(
        SearchConfig::default(),
        Arc::new(SystemClock::new()),
        &visible,
    );
    rt().block_on(async {
        let a = with_hidden.library_stats(&request(&XXX)).await;
        let b = without.library_stats(&request(&[])).await;
        let ga = a.groups.unwrap();
        assert_eq!(ga, b.groups.unwrap());
        assert!(ga.top.iter().all(|(g, _)| g != "onlyhidden"), "{ga:?}");
        assert_eq!(a.quality.unwrap(), b.quality.unwrap());
        assert_eq!(a.timeline.unwrap(), b.timeline.unwrap());
        // And the exclusion really did something: without it the hidden group shows up.
        let all = with_hidden.library_stats(&request(&[])).await;
        let g = all.groups.unwrap();
        assert!(
            g.top.iter().any(|(n, c)| n == "onlyhidden" && *c == 2),
            "{g:?}"
        );
        assert_eq!(g.total, 15);
    });
}

#[test]
fn stats_output_is_bounded() {
    let docs: Vec<IndexDoc> = (1..=60)
        .map(|i| {
            release(
                i,
                5040,
                Some(&format!("grp{i:02}")),
                None,
                None,
                None,
                Some(1950 + i as u32),
                T0 - i * DAY,
            )
        })
        .collect();
    let (index, _h, _e) = mem_index(
        SearchConfig::default(),
        Arc::new(SystemClock::new()),
        &[docs],
    );
    rt().block_on(async {
        let s = index
            .library_stats(&StatsRequest {
                exclude: vec![],
                top_groups: 1_000,
                top_years: 1_000,
                month_bounds: (0..100).map(|i| T0 - (100 - i) * DAY).collect(),
                recent_since: vec![T0; 10],
            })
            .await;
        let g = s.groups.unwrap();
        assert_eq!(g.top.len(), MAX_TOP);
        assert_eq!(g.distinct, 60);
        assert_eq!(s.quality.unwrap().year.top.len(), MAX_TOP);
        let t = s.timeline.unwrap();
        assert_eq!(t.months.len(), MAX_MONTHS);
        assert_eq!(t.recent.len(), crate::stats::MAX_RECENT);
        // Boundaries that are not ascending are cut at the first step back (no misplaced counts).
        let s = index
            .library_stats(&StatsRequest {
                month_bounds: vec![T0 - 10 * DAY, T0 + DAY, T0 - 5 * DAY, T0 + 2 * DAY],
                ..StatsRequest::default()
            })
            .await;
        assert_eq!(s.timeline.unwrap().months, vec![10]);
    });
}

#[test]
fn sec_095_stats_sections_stop_at_the_deadline_and_free_their_slots() {
    let batches: Vec<Vec<IndexDoc>> = (0..3)
        .map(|s| {
            (1..=50)
                .map(|i| release(s * 50 + i, 5040, Some("g"), None, None, None, None, T0))
                .collect()
        })
        .collect();
    let clock = Arc::new(StepClock::new(0));
    let cfg = SearchConfig {
        query_deadline_ms: 20,
        max_concurrent_searches: 2,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(cfg, clock.clone(), &batches);
    index.service().set_check_every(1);
    rt().block_on(async {
        // Fast clock: every section completes.
        let s = index.library_stats(&request(&[])).await;
        assert_eq!(s.groups.unwrap().total, 150);
        // Every clock reading takes 1 ms: no section can visit 150 documents within 20 ms.
        clock.set_step(1);
        let s = index.library_stats(&request(&[])).await;
        assert!(
            matches!(s.groups, Err(SearchError::Deadline)),
            "{:?}",
            s.groups
        );
        assert!(
            matches!(s.quality, Err(SearchError::Deadline)),
            "{:?}",
            s.quality
        );
        assert!(
            matches!(s.timeline, Err(SearchError::Deadline)),
            "{:?}",
            s.timeline
        );
        assert_eq!(index.service().available_slots(), 2);
    });
}

#[test]
fn sec_095_stats_wait_for_a_slot_like_a_search_and_give_up() {
    let cfg = SearchConfig {
        max_concurrent_searches: 1,
        semaphore_wait_ms: 20,
        ..SearchConfig::default()
    };
    let (index, _h, _e) = mem_index(
        cfg,
        Arc::new(SystemClock::new()),
        &[vec![release(
            1,
            5040,
            Some("g"),
            None,
            None,
            None,
            None,
            T0,
        )]],
    );
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
        let s = index.library_stats(&request(&[])).await;
        assert!(matches!(s.groups, Err(SearchError::Busy)), "{:?}", s.groups);
        assert!(
            matches!(s.quality, Err(SearchError::Busy)),
            "{:?}",
            s.quality
        );
        assert!(
            matches!(s.timeline, Err(SearchError::Busy)),
            "{:?}",
            s.timeline
        );
        release_tx.send(()).unwrap();
        held.await.unwrap().unwrap();
        assert_eq!(svc.available_slots(), 1);
        // With the slot back, the same request is answered.
        assert_eq!(
            index
                .library_stats(&request(&[]))
                .await
                .groups
                .unwrap()
                .total,
            1
        );
    });
}

/// Review 47 M1: merging a segment with many distinct groups is part of the pass: it checks the deadline while it
/// resolves the terms (here the per-document checks are effectively off, so only the merge can stop it).
#[test]
fn sec_095_stats_group_merge_checks_the_deadline() {
    let docs: Vec<IndexDoc> = (1..=20_000)
        .map(|i| {
            release(
                i,
                5040,
                Some(&format!("g{i:05}")),
                None,
                None,
                None,
                None,
                T0,
            )
        })
        .collect();
    let engine = crate::testkit::engine_with(&[docs]);
    let req = request(&[]);
    // A real clock and a far deadline: the whole merge runs and every group is counted.
    let far = Deadline::after(Arc::new(SystemClock::new()), 60_000);
    let (g, allocated) = crate::stats::groups_with_cap_and_ordinal_capacity(
        &engine,
        &req,
        &far,
        u64::MAX,
        crate::stats::MAX_DISTINCT_VALUES,
    )
    .unwrap();
    assert_eq!((g.distinct, g.total, g.capped), (20_000, 20_000, false));
    assert!(
        allocated <= 8_192,
        "visible group cardinality must not determine ordinal allocation: {allocated}"
    );
    // Every clock reading takes 1 ms and the budget is 3 ms. The scan reads the clock once for the segment (the
    // per-document checks never fire with `u64::MAX`), so only the checks inside the merge can hit the deadline.
    let slow = Deadline::after(Arc::new(StepClock::new(1)), 3);
    let e = crate::stats::groups(&engine, &req, &slow, u64::MAX).unwrap_err();
    assert!(matches!(e, SearchError::Deadline), "{e:?}");
    // Control: with fewer terms than one merge check interval the same slow budget is enough, so the failure above
    // came from the merge and not from the scan.
    let few: Vec<IndexDoc> = (1..=2_000)
        .map(|i| {
            release(
                i,
                5040,
                Some(&format!("g{i:05}")),
                None,
                None,
                None,
                None,
                T0,
            )
        })
        .collect();
    let small = crate::testkit::engine_with(&[few]);
    let slow = Deadline::after(Arc::new(StepClock::new(1)), 3);
    assert_eq!(
        crate::stats::groups(&small, &req, &slow, u64::MAX)
            .unwrap()
            .distinct,
        2_000
    );
}

/// Review 47 M1: the values held in memory are capped; past the cap the list says it is incomplete and the distinct
/// count is a lower bound.
#[test]
fn sec_095_stats_distinct_values_are_capped() {
    let docs: Vec<IndexDoc> = (1..=300)
        .map(|i| {
            release(
                i,
                5040,
                Some(&format!("g{i:03}")),
                None,
                None,
                None,
                None,
                T0,
            )
        })
        .collect();
    let engine = crate::testkit::engine_with(&[docs]);
    let far = Deadline::after(Arc::new(SystemClock::new()), 60_000);
    let (g, held) = crate::stats::groups_with_cap(&engine, &request(&[]), &far, 1, 100).unwrap();
    assert_eq!(held, 100);
    assert!(g.capped);
    assert_eq!((g.distinct, g.total), (100, 300));
    assert!(g.top.len() <= MAX_TOP);
    // Under the cap nothing is flagged.
    let (g, held) = crate::stats::groups_with_cap(&engine, &request(&[]), &far, 1, 1_000).unwrap();
    assert_eq!((held, g.distinct, g.capped), (300, 300, false));
}

/// Hidden dictionary terms must neither allocate counters nor consume the visible distinct-value budget.
/// Retained groups must keep receiving counts across segments and after a batch containing a discarded group.
#[test]
fn sec_095_stats_ordinal_memory_is_bounded_after_visibility_filtering() {
    let batches: Vec<Vec<IndexDoc>> = (0..3)
        .map(|s| {
            let mut docs: Vec<IndexDoc> = (1..=512)
                .map(|i| {
                    release(
                        s * 1_000 + i,
                        6040,
                        Some(&format!("hidden{s}-{i:03}")),
                        None,
                        None,
                        None,
                        None,
                        T0,
                    )
                })
                .collect();
            // Visible terms sort after every hidden term, so truncating the dictionary would lose them.
            let visible: &[Option<&str>] = match s {
                0 => &[Some("z-alpha"), Some("z-alpha"), Some("z-beta"), None],
                1 => &[
                    Some("z-alpha"),
                    Some("z-beta"),
                    Some("z-gamma"),
                    Some("z-alpha"),
                    Some("z-alpha"),
                    Some("z-beta"),
                    Some("z-alpha"),
                    Some("z-beta"),
                    None,
                ],
                _ => &[],
            };
            docs.extend(visible.iter().enumerate().map(|(i, group)| {
                release(
                    s * 1_000 + 600 + i as i64,
                    5040,
                    *group,
                    None,
                    None,
                    None,
                    None,
                    T0,
                )
            }));
            docs
        })
        .collect();
    let engine = crate::testkit::engine_with(&batches);
    let far = Deadline::after(Arc::new(SystemClock::new()), 60_000);
    let (exact, allocated) =
        crate::stats::groups_with_cap_and_ordinal_capacity(&engine, &request(&XXX), &far, 1, 3)
            .unwrap();
    assert_eq!(
        top(&exact),
        vec![("z-alpha", 6), ("z-beta", 4), ("z-gamma", 1)]
    );
    assert_eq!(
        (exact.without, exact.distinct, exact.total, exact.capped),
        (2, 3, 13, false)
    );
    assert!(
        allocated <= 16,
        "three visible groups allocated {allocated} ordinal counters"
    );

    // With those 1,536 hidden groups now visible, the counter storage stays bounded too.
    let (all, allocated) =
        crate::stats::groups_with_cap_and_ordinal_capacity(&engine, &request(&[]), &far, 1, 3)
            .unwrap();
    assert_eq!(
        (all.without, all.distinct, all.total, all.capped),
        (2, 3, 1_549, true)
    );
    assert!(
        allocated <= 16,
        "visible terms allocated {allocated} ordinal counters"
    );

    let (capped, allocated) =
        crate::stats::groups_with_cap_and_ordinal_capacity(&engine, &request(&XXX), &far, 1, 2)
            .unwrap();
    assert_eq!(top(&capped), vec![("z-alpha", 6), ("z-beta", 4)]);
    assert_eq!(
        (capped.without, capped.distinct, capped.total, capped.capped),
        (2, 2, 13, true)
    );
    assert!(
        allocated <= 16,
        "two retained groups allocated {allocated} ordinal counters"
    );

    let (empty, allocated) = crate::stats::groups_with_cap_and_ordinal_capacity(
        &engine,
        &request(&[5000, 5040, 6000, 6040]),
        &far,
        1,
        3,
    )
    .unwrap();
    assert_eq!(empty, Ranked::default());
    assert_eq!(
        allocated, 0,
        "excluded dictionary terms must allocate no ordinal counters"
    );
}
