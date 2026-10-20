//! SEC-089: Tantivy's query syntax and regex/unbounded automaton queries are unreachable from our code.
//! The compiler-side guard is the `disallowed-types` / `disallowed-methods` list in `clippy.toml` (CI runs
//! clippy with `-D warnings`); this test keeps that list from being weakened and catches a local
//! `allow` of the lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/nzb-search has a workspace root")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn sec_089_query_parser_and_regex_are_not_reachable() {
    let clippy = std::fs::read_to_string(workspace_root().join("clippy.toml")).unwrap();
    for banned in [
        "tantivy::query::QueryParser\"",
        "tantivy::query::RegexQuery\"",
        "tantivy::query::RegexPhraseQuery\"",
        "tantivy::query::FuzzyTermQuery\"",
        "tantivy::query::PhrasePrefixQuery\"",
        "tantivy::query::QueryParser::parse_query\"",
        "tantivy::query::RegexQuery::from_pattern\"",
        "tantivy::query::RegexQuery::from_regex\"",
        "tantivy::query::wildcard_query_to_regex_str\"",
        "tantivy::query::QueryParser::for_index\"",
    ] {
        assert!(
            clippy.contains(banned),
            "clippy.toml lost the ban on {banned}"
        );
    }
    // No source file of any crate or fuzz target opts out of the bans or names the banned items
    // (review 32 I2: the ban covers every crate). Exempt: this file (it names them in the clippy.toml
    // check) and `ban_probe.rs` (the compile-time proof that every banned path still resolves).
    let root = workspace_root();
    let mut files = Vec::new();
    for e in std::fs::read_dir(root.join("crates")).unwrap() {
        let src = e.unwrap().path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    // A source bundle without the separate fuzz project (the public export) sets
    // NZBD_SOURCE_BUNDLE=1 to run this test; anywhere else a missing fuzz/ must fail, so the scan
    // can never be skipped silently (review 55).
    let fuzz_targets = root.join("fuzz").join("fuzz_targets");
    if fuzz_targets.is_dir() {
        rust_files(&fuzz_targets, &mut files);
    } else {
        assert_eq!(
            std::env::var("NZBD_SOURCE_BUNDLE").as_deref(),
            Ok("1"),
            "fuzz/fuzz_targets is missing; set NZBD_SOURCE_BUNDLE=1 only in a source bundle without fuzz/"
        );
    }
    assert!(files.len() > 100, "{}", files.len());
    let needles = [
        "disallowed_types",
        "disallowed_methods",
        "QueryParser",
        "RegexQuery",
        "RegexPhraseQuery",
        "FuzzyTermQuery",
        "PhrasePrefixQuery",
        "query_grammar",
    ];
    let exempt = |f: &PathBuf| {
        f.ends_with("nzb-search/src/lint_tests.rs") || f.ends_with("nzb-search/src/ban_probe.rs")
    };
    for f in files.iter().filter(|f| !exempt(f)) {
        let text = std::fs::read_to_string(f).unwrap();
        for n in needles {
            assert!(!text.contains(n), "{} mentions {n}", f.display());
        }
    }
}
