//! Query construction from hostile input (SEC-089) and the expansion budgets of review M6.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
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

use nzb_store::SearchQuery;
use tantivy::collector::Count;

use crate::clock::{Deadline, StepClock, SystemClock};
use crate::config::{MAX_Q_CHARS, MAX_Q_TOKENS};
use crate::engine::Engine;
use crate::error::SearchError;
use crate::query::{Budgets, Built, Expand, build};
use crate::request::SearchRequest;
use crate::testkit::{doc, engine_with};

fn req(text: &str) -> SearchRequest {
    SearchRequest::from(SearchQuery {
        q: Some(text.to_owned()),
        ..SearchQuery::default()
    })
}

fn far() -> Deadline {
    Deadline::after(Arc::new(SystemClock::new()), 60_000)
}

fn built(e: &Engine, text: &str, expand: Expand, budgets: Budgets) -> Built {
    build(
        &e.searcher(),
        e.fields(),
        &req(text),
        expand,
        budgets,
        &far(),
    )
    .unwrap()
}

fn hits(e: &Engine, b: &Built) -> usize {
    e.searcher().search(&*b.query, &Count).unwrap()
}

fn count(e: &Engine, text: &str) -> usize {
    hits(e, &built(e, text, Expand::default(), Budgets::default()))
}

const PREFIX: Expand = Expand {
    prefix: true,
    fuzzy: false,
};
const FUZZY: Expand = Expand {
    prefix: false,
    fuzzy: true,
};

#[test]
fn sec_089_query_syntax_is_inert() {
    let e = engine_with(&[vec![
        doc(1, "foo bar"),
        doc(2, "title foo and bar"),
        doc(3, "re gex"),
        doc(4, "x OR y"),
    ]]);
    // Field syntax, boolean operators, negation, wildcards, phrases, regex, ranges, boosts: all plain
    // separators or words; each query equals the AND of its tokens.
    assert_eq!(count(&e, "title:foo AND -bar"), 1); // title foo and bar -> doc 2 only
    assert_eq!(count(&e, "-bar"), 2); // "bar": docs 1 and 2, never "NOT bar"
    assert_eq!(count(&e, "foo*"), 2);
    assert_eq!(count(&e, "\"foo bar\"~^"), 2);
    assert_eq!(count(&e, "\"foo bar\"~5^3"), 0); // "5" and "3" are words too
    assert_eq!(count(&e, "/re.*gex/"), 1);
    assert_eq!(count(&e, "[a TO z]"), 0); // "a", "to", "z" are words no doc has
    assert_eq!(count(&e, "x OR y"), 1); // AND of x, or, y
    assert_eq!(count(&e, "x || y && !z"), 0);
    // Nothing searchable left: no text clause at all (2.x: the listing without text).
    assert_eq!(count(&e, "*:* () \"\" ~ ^"), 4);
    // Control characters, bidi overrides and NULs are separators.
    assert_eq!(count(&e, "foo\u{0}\u{202e}bar\t"), 2);
}

#[test]
fn sec_089_token_and_expansion_caps_hold() {
    let words: Vec<String> = (0..300).map(|i| format!("w{i}")).collect();
    let e = engine_with(&[vec![doc(1, &words.join(" "))]]);
    // At most 16 tokens are kept (the 17th and later are dropped, like 2.x).
    let b = built(&e, &words.join(" "), Expand::default(), Budgets::default());
    assert_eq!(b.stats.tokens, MAX_Q_TOKENS);
    assert_eq!(hits(&e, &b), 1);
    // At most 256 characters are read.
    let long = format!("{} zzzz", "a".repeat(MAX_Q_CHARS));
    let b = built(&e, &long, Expand::default(), Budgets::default());
    assert_eq!(b.stats.tokens, 1, "the token after 256 chars is never seen");
    // A 64-byte token cap on both sides: a 300-char word is found by any query sharing its first 64.
    let e = engine_with(&[vec![doc(1, &"q".repeat(300))]]);
    assert_eq!(count(&e, &"q".repeat(64)), 1);
    assert_eq!(count(&e, &"q".repeat(90)), 1);

    // Prefix: <= 64 terms per token and field after the cross-segment union, rarest first after the
    // exact-length term; fuzzy and prefix alike. 200 terms over 4 segments.
    let batches: Vec<Vec<_>> = (0..4)
        .map(|s| {
            (0..50)
                .map(|i| {
                    let id = s * 50 + i + 1;
                    doc(id, &format!("par{id:03}"))
                })
                .collect()
        })
        .collect();
    let e = engine_with(&batches);
    let b = built(&e, "par", PREFIX, Budgets::default());
    assert!(b.narrowed);
    // 64 terms: the exact token (always queried) + the 63 rarest/first candidates.
    assert_eq!(b.stats.max_terms_per_field, 64);
    assert_eq!(hits(&e, &b), 63);
    let title_terms = &b.expanded[0][0].1;
    assert_eq!(title_terms.len(), 63);
    // Dictionary entries visited per token, field and segment are bounded.
    let tight = Budgets {
        dict_entries: 10,
        ..Budgets::default()
    };
    let b = built(&e, "par", PREFIX, tight);
    assert!(b.narrowed);
    assert_eq!(b.stats.max_dict_visits, 10);
    assert_eq!(hits(&e, &b), 40, "10 entries from each of the 4 segments");

    // Prefix applies to the last token only and needs 3 characters.
    let e = engine_with(&[vec![doc(1, "matrix reloaded"), doc(2, "mat rel")]]);
    assert_eq!(
        hits(&e, &built(&e, "mat rel", PREFIX, Budgets::default())),
        1
    );
    assert_eq!(
        hits(&e, &built(&e, "matrix rel", PREFIX, Budgets::default())),
        1
    );
    assert_eq!(hits(&e, &built(&e, "mat", PREFIX, Budgets::default())), 2);
    assert_eq!(hits(&e, &built(&e, "ma", PREFIX, Budgets::default())), 0);
    assert_eq!(
        hits(&e, &built(&e, "matr reloaded", PREFIX, Budgets::default())),
        0
    );
    // Fuzzy: distance 1, tokens of 5+ characters, at most 4 tokens.
    assert_eq!(hits(&e, &built(&e, "matrx", FUZZY, Budgets::default())), 1);
    assert_eq!(hits(&e, &built(&e, "mtrx", FUZZY, Budgets::default())), 0);
    assert_eq!(
        hits(&e, &built(&e, "matirx", FUZZY, Budgets::default())),
        1,
        "transposition"
    );
    assert_eq!(hits(&e, &built(&e, "mxtrix", FUZZY, Budgets::default())), 1);
    assert_eq!(hits(&e, &built(&e, "mxtrxx", FUZZY, Budgets::default())), 0);
    let e = engine_with(&[vec![doc(1, "aaaaa bbbbb ccccc ddddd eeeee")]]);
    let b = built(
        &e,
        "aaaax bbbbx ccccx ddddx eeeex",
        FUZZY,
        Budgets::default(),
    );
    assert_eq!(b.stats.expanded_tokens, 4);
    assert_eq!(hits(&e, &b), 0, "the fifth token gets no fuzzy alternative");
}

#[test]
fn sec_089_expansion_respects_the_postings_budget() {
    // "rar" prefixes: one very common term and a few rare ones.
    let mut docs: Vec<_> = (1..=300).map(|i| doc(i, "rarcommon")).collect();
    docs.extend((301..=305).map(|i| doc(i, &format!("rarx{i}"))));
    docs.push(doc(400, "rar"));
    let e = engine_with(&[docs]);
    let all = built(&e, "rar", PREFIX, Budgets::default());
    assert!(!all.narrowed);
    assert_eq!(hits(&e, &all), 306);
    assert_eq!(
        all.stats.postings, 305,
        "the exact term is not an expansion"
    );
    // A budget below the summed document frequency: the token matches its exact term only.
    let small = Budgets {
        postings: 100,
        ..Budgets::default()
    };
    let b = built(&e, "rar", PREFIX, small);
    assert!(b.narrowed);
    assert_eq!(b.stats.postings, 0);
    assert_eq!(hits(&e, &b), 1);
    assert!(b.expanded[0].is_empty());
    // The budget is per query: two expandable tokens share it (fuzzy on both).
    let e = engine_with(&[(1..=60)
        .map(|i| {
            doc(
                i,
                if i % 2 == 0 {
                    "alpha1 bravo"
                } else {
                    "alpha2 bravo1"
                },
            )
        })
        .collect()]);
    let both = Budgets {
        postings: 70,
        ..Budgets::default()
    };
    let b = built(
        &e,
        "alpha bravo",
        Expand {
            prefix: true,
            fuzzy: true,
        },
        both,
    );
    assert!(b.narrowed, "the second token exceeds what the first left");
}

#[test]
fn expanded_terms_are_never_displayed() {
    let e = engine_with(&[vec![doc(1, "secretterm visible")]]);
    let b = built(&e, "secr", PREFIX, Budgets::default());
    assert_eq!(hits(&e, &b), 1);
    // Diagnostics carry counts only.
    assert!(!format!("{b:?}").contains("secretterm"));
}

#[test]
fn sec_095_deadline_covers_expansion_and_weight_builds() {
    let batches: Vec<Vec<_>> = (0..6)
        .map(|s| vec![doc(s + 1, &format!("abc{s}"))])
        .collect();
    let e = engine_with(&batches);
    // Each clock reading advances 10 ms; the deadline is 50 ms away: expansion reads the clock once
    // per segment and field, so it runs out before any weight exists.
    let clock = Arc::new(StepClock::new(10));
    let d = Deadline::after(clock, 50);
    let r = build(
        &e.searcher(),
        e.fields(),
        &req("abc"),
        PREFIX,
        Budgets::default(),
        &d,
    );
    assert!(matches!(r, Err(SearchError::Deadline)), "{r:?}");
    // Without expansion the build reads no clock: the collection checks it per segment instead
    // (covered by the index tests).
    let clock = Arc::new(StepClock::new(10));
    let d = Deadline::after(clock, 50);
    assert!(
        build(
            &e.searcher(),
            e.fields(),
            &req("abc0"),
            Expand::default(),
            Budgets::default(),
            &d
        )
        .is_ok()
    );
}

#[test]
fn the_exact_term_is_not_charged_to_the_budget_and_stays_lazy() {
    // Review 32 L2 probe: 2,000 `abc` and one `abcd`; the only expansion costs 1 posting.
    let mut docs: Vec<_> = (1..=2000).map(|i| doc(i, "abc")).collect();
    docs.push(doc(3000, "abcd"));
    let e = engine_with(&[docs]);
    let b = built(
        &e,
        "abc",
        PREFIX,
        Budgets {
            postings: 2,
            ..Budgets::default()
        },
    );
    assert!(!b.narrowed);
    assert_eq!(b.stats.postings, 1);
    assert_eq!(hits(&e, &b), 2001);
    // The exact term is its own TermQuery in every field (a single expansion is one too); no eager
    // term set is built here.
    let dbg = format!("{:?}", b.query);
    assert_eq!(dbg.matches("TermSetQuery").count(), 0, "{dbg}");
    // Four text fields: title, files, poster, source_name (T131).
    assert_eq!(dbg.matches("\"abc\")").count(), 4, "{dbg}");
}

/// T131: the `.nzb` file name (without its extension) and the release group are free text, with the same
/// AND semantics across fields and the same prefix and fuzzy expansion as the title.
#[test]
fn source_name_and_group_are_searchable_text() {
    let mut toto = doc(1, "toto");
    toto.source_name = "toto.PcGame-Mephisto.nzb".to_owned();
    let mut grouped = doc(2, "a8f3c9e1b7d24f6a9c0e");
    grouped.group = Some("GRPNAME".to_owned());
    let mut double = doc(3, "other");
    double.source_name = "Twice.NZB.nzb".to_owned();
    let e = engine_with(&[vec![toto, grouped, double, doc(4, "unrelated")]]);
    assert_eq!(count(&e, "Mephisto"), 1);
    assert_eq!(count(&e, "mephisto pcgame"), 1);
    // AND across fields: one token from the title, one from the file name.
    assert_eq!(count(&e, "toto mephisto"), 1);
    assert_eq!(count(&e, "unrelated mephisto"), 0);
    assert_eq!(count(&e, "grpname"), 1);
    assert_eq!(count(&e, "twice"), 1);
    // The stripped extension is not a term (it would match every release).
    assert_eq!(count(&e, "nzb"), 0);
    assert_eq!(hits(&e, &built(&e, "mephi", PREFIX, Budgets::default())), 1);
    assert_eq!(
        hits(&e, &built(&e, "mephisti", FUZZY, Budgets::default())),
        1
    );
    assert_eq!(
        hits(&e, &built(&e, "grpnamx", FUZZY, Budgets::default())),
        1
    );
}

/// T131: hidden categories stay excluded when the match comes from the file name only.
#[test]
fn sec_090_source_name_match_respects_the_exclusion_set() {
    let mut hidden = doc(1, "x");
    hidden.source_name = "Secret.Words.nzb".to_owned();
    hidden.category_id = 6000;
    hidden.category_parent = 6000;
    let e = engine_with(&[vec![hidden]]);
    let mut r = req("secret");
    r.query.exclude_categories = vec![6000];
    let b = build(
        &e.searcher(),
        e.fields(),
        &r,
        Expand::default(),
        Budgets::default(),
        &far(),
    )
    .unwrap();
    assert_eq!(hits(&e, &b), 0);
    assert_eq!(count(&e, "secret"), 1);
}

#[test]
fn hidden_terms_do_not_crowd_out_visible_prefix_or_fuzzy_alternatives() {
    for (text, expand, visible, hidden) in [
        ("par", PREFIX, "parzzvisible", ["paraaa", "parbbb"]),
        ("matrx", FUZZY, "matrix", ["matra", "matrb"]),
    ] {
        let mut docs = vec![doc(1, visible)];
        docs.extend(hidden.iter().enumerate().map(|(i, text)| {
            let mut d = doc(i as i64 + 2, text);
            d.category_id = 6000;
            d.category_parent = 6000;
            d
        }));
        let e = engine_with(&[docs]);
        let mut r = req(text);
        r.query.exclude_categories = vec![6000];
        let b = build(
            &e.searcher(),
            e.fields(),
            &r,
            expand,
            Budgets {
                terms_max: 2,
                ..Budgets::default()
            },
            &far(),
        )
        .unwrap();
        assert_eq!(hits(&e, &b), 1, "visible {text} alternative must survive");
        assert!(!b.narrowed, "only one visible alternative exists");
        assert_eq!(b.stats.max_terms_per_field, 2);
    }
}

#[test]
fn visibility_checks_share_a_hard_budget_across_tokens_fields_and_segments() {
    let mut first = doc(1, "alpha1 bravo1");
    first.source_name = "alpha1 bravo1".into();
    let mut second = doc(2, "alpha2 bravo2");
    second.source_name = "alpha2 bravo2".into();
    let e = engine_with(&[vec![first], vec![second]]);
    let mut r = req("alpha bravo");
    r.query.exclude_categories = vec![6000];
    let b = build(
        &e.searcher(),
        e.fields(),
        &r,
        Expand {
            prefix: true,
            fuzzy: true,
        },
        Budgets {
            visibility_postings: 3,
            ..Budgets::default()
        },
        &far(),
    )
    .unwrap();
    assert_eq!(b.stats.visibility_postings, 3);
    assert!(b.narrowed);
    assert!(b.stats.max_dict_visits <= Budgets::default().dict_entries);
    assert!(b.stats.max_terms_per_field <= Budgets::default().terms_max);
    // The separate posting scan must not accidentally charge or eagerly read an exact term.
    r.query.q = Some("alpha1".into());
    let exact = build(
        &e.searcher(),
        e.fields(),
        &r,
        PREFIX,
        Budgets {
            visibility_postings: 0,
            ..Budgets::default()
        },
        &far(),
    )
    .unwrap();
    assert_eq!(hits(&e, &exact), 1);
    assert_eq!(exact.stats.visibility_postings, 0);
}

#[test]
fn excluded_postings_still_count_toward_decoding_work() {
    let mut docs = vec![doc(1, "parvisible")];
    docs.extend((2..=20).map(|id| {
        let mut d = doc(id, "parvisible");
        d.category_id = 6000;
        d.category_parent = 6000;
        d
    }));
    let e = engine_with(&[docs]);
    let mut r = req("par");
    r.query.exclude_categories = vec![6000];
    let b = build(
        &e.searcher(),
        e.fields(),
        &r,
        PREFIX,
        Budgets {
            postings: 5,
            ..Budgets::default()
        },
        &far(),
    )
    .unwrap();
    assert!(b.narrowed);
    assert_eq!(
        hits(&e, &b),
        0,
        "a raw 20-posting alternative exceeds the work budget"
    );
    assert_eq!(
        b.stats.visibility_postings, 0,
        "oversized postings are not scanned"
    );
    assert_eq!(b.stats.postings, 0);
}
