#![allow(
    clippy::assert_is_empty,
    clippy::format_push_string,
    clippy::field_reassign_with_default,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used
)]

use super::*;
use std::cell::Cell;

struct Fake {
    elapsed: Duration,
    ticks: Cell<u32>,
}

impl Fake {
    fn at(secs: u64) -> Self {
        Self {
            elapsed: Duration::from_secs(secs),
            ticks: Cell::new(0),
        }
    }
}

impl Clock for Fake {
    fn elapsed(&self) -> Duration {
        self.ticks.set(self.ticks.get() + 1);
        self.elapsed
    }
    fn now_unix(&self) -> i64 {
        1_700_000_000
    }
}

fn doc(body: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\"?><nzb>{body}</nzb>").into_bytes()
}

fn seg(n: u64, b: u64) -> String {
    format!("<segment bytes=\"{b}\" number=\"{n}\">m{n}@h</segment>")
}

fn file(subject: &str, segs: &str) -> String {
    format!(
        "<file poster=\"p\" date=\"1700000000\" subject=\"{subject}\"><groups><group>g</group></groups><segments>{segs}</segments></file>"
    )
}

fn run_ok(body: &str) -> ParsedNzb {
    parse(&doc(body), &Limits::default(), &Fake::at(0)).unwrap()
}

fn run_err(body: &str, l: &Limits) -> NzbError {
    parse(&doc(body), l, &Fake::at(0)).unwrap_err()
}

#[test]
fn missing_ranges_fast_paths() {
    let mut bits = Vec::new();
    for n in (1..=200u32).filter(|n| !(70..=140).contains(n) && *n != 5) {
        test_and_set(&mut bits, n).unwrap();
    }
    let (r, t) = missing_ranges(&bits, 200);
    assert_eq!(r, vec![(5, 5), (70, 140)]);
    assert!(!t);
    let (r, _) = missing_ranges(&bits, 205);
    assert_eq!(r.last(), Some(&(201, 205)));
    assert_eq!(missing_ranges(&[], 0), (vec![], false));
    assert_eq!(missing_ranges(&[], 3), (vec![(1, 3)], false));
}

#[test]
fn missing_ranges_capped() {
    let mut bits = Vec::new();
    for n in (1..=2000u32).filter(|n| n % 2 == 0) {
        test_and_set(&mut bits, n).unwrap();
    }
    let (r, t) = missing_ranges(&bits, 2000);
    assert_eq!(r.len(), MAX_MISSING_RANGES);
    assert!(t);
}

#[test]
fn declared_total_comes_from_parse_subject_for_every_form() {
    let declared = |subject: &str| {
        let f = file(subject, &seg(1, 1));
        run_ok(&f).files[0].declared_segments
    };
    assert_eq!(declared("&quot;a.mkv&quot; yEnc (1/10)"), Some(10));
    assert_eq!(
        declared("[01/03] - &quot;a.rar&quot; yEnc (1/10) 123"),
        Some(10)
    );
    // PARSER_SPEC fallback forms declare the total too.
    assert_eq!(declared("name.ext (1/57)"), Some(57));
    assert_eq!(declared("name.ext [1/57]"), Some(57));
    // n must not exceed m; m must be within 1..=max_segments_per_file.
    assert_eq!(declared("name.ext (58/57)"), None);
    assert_eq!(declared("&quot;a&quot; yEnc (1/10000000)"), None);
    assert_eq!(declared("&quot;a&quot; yEnc (1/0)"), None);
    assert_eq!(declared("&quot;a&quot; yEnc (0/5)"), None);
    assert_eq!(declared("&quot;a&quot; yEnc (x/5)"), None);
    assert_eq!(declared("&quot;a&quot; yEnc (1/5"), None);
}

#[test]
fn entities_and_char_refs() {
    let f = file("a&amp;b &#65;&#x42; &lt;", &seg(1, 1));
    assert_eq!(run_ok(&f).files[0].subject, "a&b AB <");
    for bad in [
        "&nbsp;",
        "&#0;",
        "&#xD800;",
        "&#;",
        "&amp",
        "&#x110000;",
        "&lol4;",
    ] {
        let f = file(bad, &seg(1, 1));
        assert!(
            matches!(run_err(&f, &Limits::default()), NzbError::Malformed { .. }),
            "{bad}"
        );
    }
}

#[test]
fn entities_in_text_nodes() {
    let f = "<file subject=\"s\"><groups><group>alt.&lt;x&gt;</group></groups><segments><segment bytes=\"1\" number=\"1\"> a&#64;b </segment></segments></file>";
    assert_eq!(run_ok(f).files[0].groups, vec!["alt.<x>".to_owned()]);
    let bad = "<file subject=\"s\"><groups><group>&xxe;</group></groups></file>";
    assert!(matches!(
        run_err(bad, &Limits::default()),
        NzbError::Malformed { .. }
    ));
}

#[test]
fn cdata_is_text() {
    let f = "<file subject=\"s\"><segments><segment bytes=\"1\" number=\"1\"><![CDATA[a@b]]></segment></segments></file>";
    assert_eq!(run_ok(f).segment_count, 1);
}

#[test]
fn date_clamping() {
    let now = 1_700_000_000;
    assert_eq!(parse_date("1700000000", now), Some(1_700_000_000));
    assert_eq!(parse_date("1700086400", now), Some(1_700_086_400));
    assert_eq!(parse_date("1700086401", now), None);
    assert_eq!(parse_date("946684799", now), None);
    assert_eq!(parse_date("-5", now), None);
    assert_eq!(parse_date("abc", now), None);
    assert_eq!(parse_date("99999999999999999999", now), None);
}

#[test]
fn utf8_bom_is_accepted() {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend(doc(&file("s", &seg(1, 1))));
    assert!(parse(&v, &Limits::default(), &Fake::at(0)).is_ok());
}

#[test]
fn nested_file_elements_inside_unknown_are_ignored() {
    let big = "x".repeat(200_000);
    let f = format!(
        "<foo>{big}{}</foo>{}",
        file("hidden", &seg(1, 1)),
        file("shown", &seg(1, 1))
    );
    let p = run_ok(&f);
    assert_eq!(p.files.len(), 1);
    assert_eq!(p.files[0].subject, "shown");
}

#[test]
fn second_root_is_malformed() {
    let mut v = doc(&file("s", &seg(1, 1)));
    v.extend_from_slice(b"<nzb/>");
    assert!(matches!(
        parse(&v, &Limits::default(), &Fake::at(0)),
        Err(NzbError::Malformed { .. })
    ));
}

#[test]
fn sec_107_content_outside_the_root_is_rejected_in_every_parse_mode() {
    let root = format!("<nzb>{}</nzb>", file("s", &seg(1, 1)));
    let limits = Limits::default();
    for invalid in [
        "junk",
        "\u{a0}",
        "<![CDATA[ ]]>",
        "<![CDATA[]]>",
        "&amp;",
        "&#32;",
    ] {
        for input in [format!("{invalid}{root}"), format!("{root}{invalid}")] {
            let bytes = input.as_bytes();
            assert!(
                matches!(
                    parse(bytes, &limits, &Fake::at(0)),
                    Err(NzbError::Malformed { .. })
                ),
                "full: {input}"
            );
            assert!(
                matches!(
                    list_segments(bytes, &limits, &Fake::at(0), 0, 0, 10),
                    Err(NzbError::Malformed { .. })
                ),
                "segments: {input}"
            );
            assert!(
                matches!(
                    extract_files(bytes, &limits, &Fake::at(0), &[0]),
                    Err(NzbError::Malformed { .. })
                ),
                "subset: {input}"
            );
        }
    }
}

#[test]
fn xml_whitespace_comments_and_instructions_outside_the_root_are_allowed() {
    let input = format!(
        " \t\r\n<!--before--><?before data?><nzb>{}</nzb> \t\r\n<!--after--><?after data?>",
        file("s", &seg(1, 1))
    );
    let bytes = input.as_bytes();
    let limits = Limits::default();
    assert_eq!(parse(bytes, &limits, &Fake::at(0)).unwrap().files.len(), 1);
    assert_eq!(
        list_segments(bytes, &limits, &Fake::at(0), 0, 0, 10)
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        extract_files(bytes, &limits, &Fake::at(0), &[0])
            .unwrap()
            .files
            .len(),
        1
    );
}

#[test]
fn lowered_limits_trip_the_right_code() {
    let one = file("s", &seg(1, 10));
    let l = |f: fn(&mut Limits)| {
        let mut l = Limits::default();
        f(&mut l);
        l
    };
    let two_segs = file("s", &format!("{}{}", seg(1, 1), seg(2, 1)));
    let cases: Vec<(Limits, String, LimitName)> = vec![
        (
            l(|l| l.max_total_segments = 2),
            format!("{two_segs}{}", file("s", &seg(1, 1))),
            LimitName::TotalSegments,
        ),
        (
            l(|l| l.max_total_bytes = 15),
            format!("{one}{one}"),
            LimitName::TotalBytes,
        ),
        (
            l(|l| l.max_files = 1),
            format!("{one}{one}"),
            LimitName::Files,
        ),
        (
            l(|l| l.max_groups_per_file = 1),
            "<file subject=\"s\"><groups><group>a</group><group>b</group></groups></file>".into(),
            LimitName::GroupsPerFile,
        ),
        (
            l(|l| l.max_group_bytes = 3),
            "<file subject=\"s\"><groups><group>abcd</group></groups></file>".into(),
            LimitName::GroupBytes,
        ),
        (
            l(|l| l.max_meta_entries = 1),
            "<head><meta type=\"a\">1</meta><meta type=\"b\">2</meta></head><file/>".into(),
            LimitName::MetaEntries,
        ),
        (
            l(|l| l.max_meta_value_bytes = 3),
            "<head><meta type=\"a\">12345</meta></head><file/>".into(),
            LimitName::MetaValueBytes,
        ),
        (
            l(|l| l.max_message_id_bytes = 1),
            one.clone(),
            LimitName::MessageIdBytes,
        ),
        (
            l(|l| l.max_segments_per_file = 5),
            file("s", &seg(6, 1)),
            LimitName::SegmentsPerFile,
        ),
        (
            l(|l| l.max_segment_bytes = 9),
            one.clone(),
            LimitName::SegmentBytes,
        ),
        (l(|l| l.max_xml_depth = 3), one.clone(), LimitName::XmlDepth),
        (
            l(|l| l.max_subject_bytes = 1),
            "<file subject=\"ab\"/>".into(),
            LimitName::SubjectBytes,
        ),
        (
            l(|l| l.max_poster_bytes = 1),
            "<file poster=\"ab\"/>".into(),
            LimitName::PosterBytes,
        ),
    ];
    for (limits, body, which) in cases {
        assert_eq!(
            run_err(&body, &limits),
            NzbError::LimitExceeded { which },
            "{which:?}"
        );
    }
}

#[test]
fn total_bytes_overflow_is_a_limit_error() {
    let mut l = Limits::default();
    // Limits are clamped to the hard ceilings, so overflow is reached through the total cap.
    l.max_segment_bytes = u64::MAX;
    l.max_total_bytes = 10;
    let body = file("s", &format!("{}{}", seg(1, 6), seg(2, 6)));
    assert_eq!(
        run_err(&body, &l),
        NzbError::LimitExceeded {
            which: LimitName::TotalBytes
        }
    );
}

#[test]
fn escaped_subject_cap_applies_to_raw_form() {
    let mut l = Limits::default();
    l.max_subject_bytes = 8;
    // 3 raw "&amp;" = 15 raw bytes, only 3 unescaped.
    assert_eq!(
        run_err("<file subject=\"&amp;&amp;&amp;\"/>", &l),
        NzbError::LimitExceeded {
            which: LimitName::SubjectBytes
        }
    );
}

#[test]
fn timeout_checked_every_interval() {
    // > 1024 events, deadline already exceeded on the fake clock.
    let body: String = "<x/>".repeat(1100) + &file("s", &seg(1, 1));
    let mut l = Limits::default();
    l.parse_deadline = Duration::from_secs(1);
    let clock = Fake::at(5);
    assert_eq!(parse(&doc(&body), &l, &clock), Err(NzbError::Timeout));
    // The clock is consulted only every DEADLINE_CHECK_INTERVAL events, not per event.
    assert_eq!(clock.ticks.get(), 1);
    // Same document with time left parses fine.
    assert!(parse(&doc(&body), &l, &Fake::at(0)).is_ok());
    // A small document never reaches the in-loop check but is checked once at the end (F2).
    let small = Fake::at(5);
    assert_eq!(
        parse(&doc(&file("s", &seg(1, 1))), &l, &small),
        Err(NzbError::Timeout)
    );
    assert_eq!(small.ticks.get(), 1);
    assert!(parse(&doc(&file("s", &seg(1, 1))), &l, &Fake::at(0)).is_ok());
}

#[test]
fn sec_003_deadline_with_many_events_and_final_check() {
    // 5000 events, deadline passed: Timeout comes from the in-loop check, after exactly
    // floor(events / 1024) clock reads at most.
    let body: String = "<x/>".repeat(5000) + &file("s", &seg(1, 1));
    let mut l = Limits::default();
    l.parse_deadline = Duration::from_secs(1);
    let clock = Fake::at(2);
    assert_eq!(parse(&doc(&body), &l, &clock), Err(NzbError::Timeout));
    assert_eq!(clock.ticks.get(), 1);
}

#[test]
fn sec_002_limits_are_clamped_to_hard_ceilings() {
    let mut l = Limits::default();
    l.max_xml_depth = u32::MAX;
    l.max_files = u32::MAX;
    l.max_segments_per_file = u32::MAX;
    l.max_subject_bytes = u32::MAX;
    l.max_file_bytes = u64::MAX;
    let c = Limits::hard_ceilings();
    assert_eq!(l.clamped_to_ceilings().max_files, c.max_files);
    // 17 nested unknown elements exceed the ceiling (16) even though the caller allowed more.
    let deep = "<a>".repeat(17) + &"</a>".repeat(17);
    assert_eq!(
        parse(
            &doc(&format!("{deep}{}", file("s", &seg(1, 1)))),
            &l,
            &Fake::at(0)
        ),
        Err(NzbError::LimitExceeded {
            which: LimitName::XmlDepth
        })
    );
    // A subject over 2x the default is rejected although the caller asked for u32::MAX.
    let long = "a".repeat(4097);
    assert_eq!(
        parse(&doc(&file(&long, &seg(1, 1))), &l, &Fake::at(0)),
        Err(NzbError::LimitExceeded {
            which: LimitName::SubjectBytes
        })
    );
    // Segment number above the ceiling (200 000) is rejected.
    let f = file("s", &seg(200_001, 1));
    assert!(parse(&doc(&f), &l, &Fake::at(0)).is_err());
}

#[test]
fn sec_001_nul_char_reference_rejected_everywhere() {
    for r in ["&#0;", "&#x0;", "&#00;"] {
        // attribute (subject), element text (group, segment, meta) and stray text.
        let attr = file(&format!("a{r}b"), &seg(1, 1));
        assert!(matches!(
            run_err(&attr, &Limits::default()),
            NzbError::Malformed { .. }
        ));
        let grp = format!("<file subject=\"s\"><groups><group>g{r}</group></groups></file>");
        assert!(matches!(
            run_err(&grp, &Limits::default()),
            NzbError::Malformed { .. }
        ));
        let sgm = format!(
            "<file subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">m{r}</segment></segments></file>"
        );
        assert!(matches!(
            run_err(&sgm, &Limits::default()),
            NzbError::Malformed { .. }
        ));
        let meta = format!(
            "<head><meta type=\"title\">t{r}</meta></head>{}",
            file("s", &seg(1, 1))
        );
        assert!(matches!(
            run_err(&meta, &Limits::default()),
            NzbError::Malformed { .. }
        ));
        let stray = format!("{r}{}", file("s", &seg(1, 1)));
        assert!(matches!(
            run_err(&stray, &Limits::default()),
            NzbError::Malformed { .. }
        ));
    }
}

#[test]
fn sec_004_invisible_chars_in_parsed_text_are_stripped() {
    let f = file("a&#xE0041;b&#x2060;c&#xAD;d", &seg(1, 1));
    assert_eq!(run_ok(&f).files[0].subject, "abcd");
}

#[test]
fn list_segments_offset_u32_max_is_empty_not_a_panic() {
    let body = file("s", &(seg(1, 1) + &seg(2, 1)));
    let p = page(&body, 0, u32::MAX, 500).unwrap();
    assert!(p.items.is_empty());
    assert_eq!(p.total, 2);
    let p = page(&body, 0, u32::MAX - 1, u32::MAX).unwrap();
    assert!(p.items.is_empty());
}

fn page(body: &str, idx: u32, off: u32, lim: u32) -> Result<SegmentPage, NzbError> {
    list_segments(&doc(body), &Limits::default(), &Fake::at(0), idx, off, lim)
}

#[test]
fn list_segments_sorted_paged_and_deduped() {
    let segs: String = [5u64, 3, 1, 4, 2, 3]
        .iter()
        .map(|n| seg(*n, *n * 10))
        .collect();
    let body = format!("{}{}", file("other", &seg(1, 1)), file("s", &segs));
    let p = page(&body, 1, 0, 100).unwrap();
    assert_eq!(p.total, 5);
    let nums: Vec<u32> = p.items.iter().map(|e| e.number).collect();
    assert_eq!(nums, vec![1, 2, 3, 4, 5]);
    assert_eq!(p.items[2].bytes, 30); // first occurrence of the duplicate wins
    assert_eq!(p.items[2].message_id, "m3@h");
    let p = page(&body, 1, 1, 2).unwrap();
    assert_eq!(
        p.items.iter().map(|e| e.number).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(page(&body, 1, 5, 10).unwrap().items.is_empty());
    assert!(page(&body, 1, 0, 0).unwrap().items.is_empty());
    assert_eq!(page(&body, 0, 0, 10).unwrap().items.len(), 1);
    assert!(matches!(
        page(&body, 2, 0, 10),
        Err(NzbError::Malformed { .. })
    ));
}

#[test]
fn list_segments_limit_is_capped_at_500() {
    let segs: String = (1..=700u64).map(|n| seg(n, 1)).collect();
    let p = page(&file("s", &segs), 0, 0, 10_000).unwrap();
    assert_eq!(p.items.len(), 500);
    assert_eq!(p.total, 700);
    let p = page(&file("s", &segs), 0, 600, 500).unwrap();
    assert_eq!(p.items.len(), 100);
    assert_eq!(p.items[0].number, 601);
}

#[test]
fn list_segments_sanitizes_ids_and_enforces_errors() {
    let body = file(
        "s",
        "<segment bytes=\"1\" number=\"1\">a\u{202e}b@h</segment>",
    );
    assert_eq!(page(&body, 0, 0, 5).unwrap().items[0].message_id, "ab@h");
    assert!(matches!(
        list_segments(
            b"<!DOCTYPE x><nzb/>",
            &Limits::default(),
            &Fake::at(0),
            0,
            0,
            5
        ),
        Err(NzbError::DoctypeForbidden)
    ));
}

// Small real-parser fixtures: the lowered per-file bound makes the duplicate-element
// regression deterministic without allocating a production-sized document.
mod segment_limit_regressions {
    use super::*;

    fn assert_limit_in_all_modes(input: &[u8], limits: &Limits, which: LimitName, why: &str) {
        let expected = Err(NzbError::LimitExceeded { which });
        assert_eq!(
            parse(input, limits, &Fake::at(0)).map(|_| ()),
            expected,
            "{why}: full parse"
        );
        assert_eq!(
            list_segments(input, limits, &Fake::at(0), 0, 0, 10).map(|_| ()),
            expected,
            "{why}: segment page"
        );
        assert_eq!(
            extract_files(input, limits, &Fake::at(0), &[0]).map(|_| ()),
            expected,
            "{why}: selected file"
        );
    }

    #[test]
    fn sec_107_segments_per_file_counts_duplicate_and_empty_elements() {
        let limits = Limits {
            max_segments_per_file: 2,
            max_total_segments: 10,
            ..Limits::default()
        };
        let full = seg(1, 1);
        let empty = "<segment bytes=\"1\" number=\"1\"/>";
        for segments in [
            full.repeat(3),
            empty.repeat(3),
            format!("{full}{empty}{full}"),
        ] {
            let input = doc(&file("duplicates.bin", &segments));
            assert_limit_in_all_modes(
                &input,
                &limits,
                LimitName::SegmentsPerFile,
                "per-file segment limit must count duplicate and empty XML elements",
            );
        }
    }

    #[test]
    fn per_file_boundary_resets_and_preserves_first_duplicate() {
        let limits = Limits {
            max_segments_per_file: 2,
            max_total_segments: 4,
            ..Limits::default()
        };
        let first = "<segment bytes=\"11\" number=\"1\">first-a@h</segment><segment bytes=\"99\" number=\"1\">second-a@h</segment>";
        let second = "<segment bytes=\"13\" number=\"1\">first-b@h</segment><segment bytes=\"101\" number=\"1\"/>";
        let input = doc(&format!(
            "{}{}",
            file("a.bin", first),
            file("b.bin", second)
        ));
        let parsed = parse(&input, &limits, &Fake::at(0)).unwrap();
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.segment_count, 2);
        assert_eq!(parsed.duplicate_segments, 2);
        assert_eq!(parsed.total_bytes, 24);
        for (idx, bytes, message_id) in [(0, 11, "first-a@h"), (1, 13, "first-b@h")] {
            let f = &parsed.files[usize::try_from(idx).unwrap()];
            assert_eq!(f.segment_count, 1);
            assert_eq!(f.duplicate_segments, 1);
            assert_eq!(f.bytes, bytes);
            let page = list_segments(&input, &limits, &Fake::at(0), idx, 0, 10).unwrap();
            assert_eq!(page.total, 1);
            assert_eq!(
                page.items,
                vec![SegmentEntry {
                    number: 1,
                    bytes,
                    message_id: message_id.to_owned(),
                }]
            );
        }
        let subset = extract_files(&input, &limits, &Fake::at(0), &[0, 1]).unwrap();
        assert_eq!(subset.files.len(), 2);
        assert_eq!(subset.files[0].segments.len(), 2);
        assert_eq!(subset.files[1].segments.len(), 2);
        assert_eq!(subset.files[0].segments[0].message_id, "first-a@h");
        assert_eq!(subset.files[0].segments[1].message_id, "second-a@h");
        assert_eq!(subset.files[0].segments[1].bytes, 99);
        assert_eq!(subset.files[1].segments[1].message_id, "");
        assert_eq!(subset.files[1].segments[1].bytes, 101);
    }

    #[test]
    fn total_segment_limit_still_counts_duplicates_across_files() {
        let two = file("duplicates.bin", &seg(1, 1).repeat(2));
        let limits = Limits {
            max_segments_per_file: 2,
            max_total_segments: 1,
            ..Limits::default()
        };
        assert_limit_in_all_modes(
            &doc(&two),
            &limits,
            LimitName::TotalSegments,
            "global segment limit must count duplicate XML elements",
        );

        let limits = Limits {
            max_total_segments: 3,
            ..limits
        };
        let input = doc(&two.repeat(2));
        let expected = Err(NzbError::LimitExceeded {
            which: LimitName::TotalSegments,
        });
        assert_eq!(parse(&input, &limits, &Fake::at(0)).map(|_| ()), expected);
        assert_eq!(
            extract_files(&input, &limits, &Fake::at(0), &[0, 1]).map(|_| ()),
            expected
        );
        // Targeted parsing intentionally skips the other file's segment work. Its own
        // two elements fit both bounds, even though a full parse exceeds the global cap.
        let page = list_segments(&input, &limits, &Fake::at(0), 1, 0, 10).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items.len(), 1);
    }
}
