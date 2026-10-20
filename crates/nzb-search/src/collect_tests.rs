//! The cross-segment merge of a collect pass keeps only the global `k` best ranks (memory O(k)).
#![allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]

use crate::collect::{GlobalRank, Prim, keep_best};

fn rank(n: i128) -> GlobalRank {
    (0, Prim::Num(n), n)
}

fn ids(w: &[(GlobalRank, i64)]) -> Vec<i64> {
    w.iter().map(|(_, id)| *id).collect()
}

#[test]
fn keeps_the_k_smallest_in_order() {
    let mut w: Vec<_> = [5, 1, 4, 2, 3]
        .into_iter()
        .map(|n| (rank(n), n as i64))
        .collect();
    keep_best(&mut w, 3, false);
    assert_eq!(ids(&w), [1, 2, 3]);
}

#[test]
fn keeps_the_k_largest_in_order() {
    let mut w: Vec<_> = [5, 1, 4, 2, 3]
        .into_iter()
        .map(|n| (rank(n), n as i64))
        .collect();
    keep_best(&mut w, 2, true);
    assert_eq!(ids(&w), [4, 5]);
}

#[test]
fn leaves_short_lists_alone() {
    let mut w: Vec<_> = [3, 1].into_iter().map(|n| (rank(n), n as i64)).collect();
    keep_best(&mut w, 2, false);
    assert_eq!(ids(&w), [3, 1]);
}

#[test]
fn repeated_merges_match_one_final_sort() {
    // Segments of 7 rows each, merged one by one, give the same page as sorting everything at once.
    let all: Vec<i128> = (0..70).map(|i| (i * 37) % 70).collect();
    for largest in [false, true] {
        let mut merged = Vec::new();
        for seg in all.chunks(7) {
            merged.extend(seg.iter().map(|&n| (rank(n), n as i64)));
            keep_best(&mut merged, 10, largest);
            assert!(merged.len() <= 10);
        }
        let mut full: Vec<_> = all.iter().map(|&n| (rank(n), n as i64)).collect();
        keep_best(&mut full, 10, largest);
        assert_eq!(ids(&merged), ids(&full));
    }
}
