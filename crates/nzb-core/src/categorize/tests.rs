#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use super::*;
use crate::types::Sha256;

const TV: &str = "Show.Name.S01E02.1080p.WEB.h264-GRP"; // 5040
const MOVIE: &str = "Movie.Title.2018.1080p.BluRay.x264-GRP"; // 2040
const UHD: &str = "Movie.Title.2018.2160p.UHD.BluRay.x265-GRP"; // 2045
const JUNK: &str = "qwertyuiop asdf";

fn rules() -> CategoryRules {
    CategoryRules::builtin(2100).unwrap()
}

fn analysis(cands: &[&str], meta_n: u8, meta_cat: Option<&str>) -> Analysis {
    Analysis {
        sha256: Sha256([0; 32]),
        name_candidates: cands.iter().map(|s| (*s).to_owned()).collect(),
        meta_name_candidates: meta_n,
        title: "t".into(),
        poster: None,
        posted_at: None,
        total_bytes: 0,
        file_count: 0,
        segment_count: 0,
        duplicate_segments: 0,
        par2_blocks: 0,
        flags: ReleaseFlags::EMPTY,
        meta_category: meta_cat.map(str::to_owned),
        repairable_estimate: None,
        files: vec![],
    }
}

fn run(
    a: &Analysis,
    hint: Option<&str>,
    stem: Option<&str>,
) -> Result<Categorization, CategorizeError> {
    categorize(
        a,
        &CategorizeRequest {
            hint,
            source_stem: stem,
        },
        &rules(),
    )
}

#[test]
fn builtin_rules_load() {
    let r = rules();
    assert_eq!(r.taxonomy.len(), 36);
}

#[test]
fn table_every_branch() {
    struct Case {
        name: &'static str,
        cands: &'static [&'static str],
        meta_n: u8,
        meta_cat: Option<&'static str>,
        hint: Option<&'static str>,
        stem: Option<&'static str>,
        want: Result<(u16, CategorySource, bool), CategorizeError>,
    }
    use CategorySource::{Fallback, Meta, Scene, Upload};
    let c = |name, cands, meta_n, meta_cat, hint, stem, want| Case {
        name,
        cands,
        meta_n,
        meta_cat,
        hint,
        stem,
        want,
    };
    let cases = [
        c(
            "scene only",
            &[TV],
            0,
            None,
            None,
            None,
            Ok((5040, Scene, false)),
        ),
        c(
            "scene beats meta",
            &[TV],
            0,
            Some("movies"),
            None,
            None,
            Ok((5040, Scene, false)),
        ),
        c(
            "scene agrees with hint",
            &[TV],
            0,
            None,
            Some("tv.hd"),
            None,
            Ok((5040, Scene, false)),
        ),
        c(
            "scene agrees, hint by id",
            &[TV],
            0,
            None,
            Some("5040"),
            None,
            Ok((5040, Scene, false)),
        ),
        c(
            "scene/hint disagree: scene wins",
            &[TV],
            0,
            None,
            Some("movies"),
            None,
            Ok((5040, Scene, true)),
        ),
        c(
            "hint when scene inconclusive",
            &[JUNK],
            0,
            None,
            Some("pc"),
            None,
            Ok((4000, Upload, false)),
        ),
        c(
            "hint by id",
            &[JUNK],
            0,
            None,
            Some("6000"),
            None,
            Ok((6000, Upload, false)),
        ),
        c(
            "hint beats meta",
            &[JUNK],
            0,
            Some("books"),
            Some("anime"),
            None,
            Ok((5070, Upload, false)),
        ),
        c(
            "meta when no hint",
            &[JUNK],
            0,
            Some("Books"),
            None,
            None,
            Ok((7000, Meta, false)),
        ),
        c(
            "meta by id",
            &[],
            0,
            Some("5045"),
            None,
            None,
            Ok((5045, Meta, false)),
        ),
        c(
            "unknown meta ignored",
            &[JUNK],
            0,
            Some("Mystery"),
            None,
            None,
            Ok((8010, Fallback, false)),
        ),
        c(
            "fallback",
            &[],
            0,
            None,
            None,
            None,
            Ok((8010, Fallback, false)),
        ),
        c(
            "invalid hint, scene would win",
            &[TV],
            0,
            None,
            Some("nope"),
            None,
            Err(CategorizeError::InvalidCategory),
        ),
        c(
            "invalid hint, nothing else",
            &[],
            0,
            None,
            Some("9999"),
            None,
            Err(CategorizeError::InvalidCategory),
        ),
        c(
            "empty hint is invalid",
            &[JUNK],
            0,
            None,
            Some(""),
            None,
            Err(CategorizeError::InvalidCategory),
        ),
        c(
            "path-like hint is invalid",
            &[JUNK],
            0,
            None,
            Some("../tv"),
            None,
            Err(CategorizeError::InvalidCategory),
        ),
        c(
            "source stem is a candidate",
            &[JUNK],
            0,
            None,
            None,
            Some("Show.Name.S01E02.1080p.WEB.h264-GRP.nzb"),
            Ok((5040, Scene, false)),
        ),
    ];
    for case in cases {
        let a = analysis(case.cands, case.meta_n, case.meta_cat);
        let got = run(&a, case.hint, case.stem);
        let got = got.map(|g| (g.category_id, g.source, g.hint_disagreement.is_some()));
        assert_eq!(got, case.want, "{}", case.name);
    }
}

#[test]
fn disagreement_is_reported_with_ids() {
    let a = analysis(&[TV], 0, None);
    let g = run(&a, Some("movies"), None).unwrap();
    assert_eq!(
        g.hint_disagreement,
        Some(HintDisagreement {
            hint_id: 2000,
            scene_id: 5040
        })
    );
    assert_eq!(g.scene_candidate.as_deref(), Some(TV));
    assert!(g.scene.is_conclusive());
}

#[test]
fn uncategorized_flag_only_on_fallback() {
    let a = analysis(&[JUNK], 0, None);
    let g = run(&a, None, None).unwrap();
    assert_eq!(g.source, CategorySource::Fallback);
    assert!(g.flags.contains(ReleaseFlags::UNCATEGORIZED));
    assert!(!g.scene.is_conclusive());
    for g in [
        run(&a, Some("pc"), None).unwrap(),
        run(&analysis(&[TV], 0, None), None, None).unwrap(),
        run(&analysis(&[JUNK], 0, Some("pc")), None, None).unwrap(),
    ] {
        assert!(g.flags.is_empty());
    }
}

#[test]
fn candidate_order_usable_stem_then_meta_then_stem_then_derived() {
    // meta name (junk), meta title (TV), derived (MOVIE); stem is a UHD movie.
    // D39 (T131): a stem usable as the title is the first candidate, before the meta candidates.
    let a = analysis(&[JUNK, TV, MOVIE], 2, None);
    let g = run(&a, None, Some(&format!("{UHD}.nzb"))).unwrap();
    assert_eq!(g.category_id, 2045);
    assert_eq!(g.scene_candidate.as_deref(), Some(UHD));
    // A stem that is not usable as a title (generic, digits, hash) keeps its place after the meta: TV wins.
    for unusable in ["download (1).nzb", "12345.nzb", "a8f3c9e1b7d24f6a9c0e.nzb"] {
        let g = run(&a, None, Some(unusable)).unwrap();
        assert_eq!(g.category_id, 5040, "{unusable}");
    }
    // No usable meta: the stem comes before the derived title.
    let a = analysis(&[MOVIE], 0, None);
    let g = run(&a, None, Some(&format!("{UHD}.nzb"))).unwrap();
    assert_eq!(g.category_id, 2045);
    assert_eq!(g.scene_candidate.as_deref(), Some(UHD));
    // Meta candidates present but inconclusive: stem still before derived title.
    let a = analysis(&[JUNK, MOVIE], 1, None);
    let g = run(&a, None, Some(&format!("{UHD}.nzb"))).unwrap();
    assert_eq!(g.category_id, 2045);
    // Stem inconclusive: falls through to the derived title.
    let g = run(&a, None, Some("random.nzb")).unwrap();
    assert_eq!(g.category_id, 2040);
}

#[test]
fn meta_count_larger_than_list_is_safe() {
    let a = analysis(&[TV], 200, None);
    assert_eq!(run(&a, None, None).unwrap().category_id, 5040);
}

#[test]
fn stem_cleaning() {
    assert_eq!(clean_stem("A.B.2020.nzb"), "A.B.2020");
    assert_eq!(clean_stem("A.B.2020.NZB.nzb"), "A.B.2020");
    assert_eq!(clean_stem("A.B.2020.part01.rar"), "A.B.2020");
    assert_eq!(clean_stem("../../etc/A.B.nzb"), "A.B");
    assert_eq!(clean_stem("C:\\x\\A.B.nzb"), "A.B");
    assert_eq!(clean_stem("A.B.mkv"), "A.B.mkv");
    assert_eq!(clean_stem(".nzb"), "");
    assert_eq!(clean_stem(""), "");
}

#[test]
fn sec_004_hostile_stem_and_candidates_do_not_panic_or_leak() {
    let a = analysis(
        &["\u{202e}evil\0".repeat(500).as_str()],
        0,
        Some(&"x".repeat(10_000)),
    );
    let stem = "\u{202e}\0../..\\".repeat(2000);
    let g = run(&a, None, Some(&stem)).unwrap();
    assert_eq!(g.category_id, 8010);
    assert!(g.scene_candidate.is_none());
}

#[test]
fn sec_hint_never_echoed_in_result() {
    // Only resolved ids leave categorize; the hint text is not part of any output type.
    let a = analysis(&[JUNK], 0, None);
    let g = run(&a, Some("anime"), None).unwrap();
    assert_eq!(g.category_id, 5070);
    assert!(!format!("{g:?}").contains("\"anime\""));
}

#[test]
fn source_strings_match_schema() {
    for (s, want) in [
        (CategorySource::Scene, "scene"),
        (CategorySource::Upload, "upload"),
        (CategorySource::Meta, "meta"),
        (CategorySource::Fallback, "fallback"),
    ] {
        assert_eq!(s.as_str(), want);
    }
    assert_eq!(CategorizeError::InvalidCategory.code(), "INVALID_CATEGORY");
}

#[test]
fn scene_category_ids_are_all_in_taxonomy() {
    // Defense in depth: whatever the scene parser emits must be seedable.
    let r = rules();
    for n in [
        TV,
        MOVIE,
        UHD,
        "[G] Show - 01",
        "Artist-Album-CD-FLAC-2020-GRP",
    ] {
        if let Some(c) = parse_scene(n, &r.scene).category {
            assert!(r.taxonomy.contains(c), "{n} -> {c}");
        }
    }
}

/// Review 45 I1: a valid hint inside the XXX subtree wins over a non-XXX Scene result (hiding XXX fails
/// closed); other hints still lose to Scene (D19).
#[test]
fn sec_090_xxx_hint_wins_over_a_scene_name() {
    let a = analysis(&[MOVIE], 1, None);
    let g = run(&a, Some("xxx"), Some(&format!("{UHD}.nzb"))).unwrap();
    assert_eq!(g.category_id, 6000);
    assert_eq!(g.source, CategorySource::Upload);
    assert!(g.scene.is_conclusive(), "scene attributes are kept");
    assert_eq!(
        g.hint_disagreement,
        Some(HintDisagreement {
            hint_id: 6000,
            scene_id: 2045
        })
    );
    let g = run(&a, Some("6000"), None).unwrap();
    assert_eq!(g.category_id, 6000);
    // A non-XXX hint still loses to Scene.
    let g = run(&a, Some("tv"), None).unwrap();
    assert_eq!((g.category_id, g.source), (2040, CategorySource::Scene));
}
