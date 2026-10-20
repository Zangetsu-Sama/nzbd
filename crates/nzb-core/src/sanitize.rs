//! Text sanitizer for every NZB-derived string (SEC-004).
//!
//! Order matters for idempotence: strip first (removal can make characters adjacent and
//! composable), then NFC, then collapse whitespace, then truncate on a char boundary.

use unicode_normalization::UnicodeNormalization;

/// Characters removed besides C0/C1 controls: every invisible format character (Unicode general
/// category Cf, which includes bidi controls, zero-width space, BOM, soft hyphen, word joiner,
/// invisible operators and the tag block) except ZWJ/ZWNJ, plus the non-Cf characters that
/// render as blanks or only alter glyph selection (SEC-004, review F1).
///
/// ZWJ (U+200D) and ZWNJ (U+200C) stay: they are required by Indic and Persian scripts and by
/// emoji sequences, and are not usable on their own to spoof text.
pub(crate) fn is_stripped(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}' // soft hyphen
                | '\u{034F}' // combining grapheme joiner
                | '\u{0600}'..='\u{0605}' // Arabic number signs (Cf)
                | '\u{061C}' // Arabic letter mark
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}' // Hangul fillers
                | '\u{17B4}'..='\u{17B5}' // Khmer inherent vowels
                | '\u{180B}'..='\u{180F}' // Mongolian variation selectors, vowel separator
                | '\u{200B}' // zero width space
                | '\u{200E}'..='\u{200F}' // LRM, RLM
                | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
                | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidi isolates
                | '\u{2800}' // Braille blank
                | '\u{3164}' // Hangul filler
                | '\u{FE00}'..='\u{FE0F}' // variation selectors
                | '\u{FEFF}' // BOM / zero width no-break space
                | '\u{FFA0}' // halfwidth Hangul filler
                | '\u{FFF9}'..='\u{FFFC}' // interlinear annotation, object replacement
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}' // tag characters ("ASCII smuggling")
                | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
        )
}

/// Sanitizes an untrusted string for storage and display.
///
/// Strips C0/C1 controls (incl. NUL), bidi controls and other invisible format characters
/// (everything in `is_stripped`; ZWJ/ZWNJ are kept), normalizes to NFC, collapses every
/// whitespace run to a single space, trims, and truncates to at most `max_bytes` bytes on a
/// char boundary. Idempotent, never panics.
#[must_use]
pub fn sanitize_text(s: &str, max_bytes: usize) -> String {
    // ASCII whitespace controls become spaces; all other stripped chars vanish.
    let cleaned: String = s
        .chars()
        .filter_map(|c| {
            if matches!(c, '\t' | '\n' | '\r' | '\u{0B}' | '\u{0C}') {
                Some(' ')
            } else if is_stripped(c) {
                None
            } else {
                Some(c)
            }
        })
        .nfc()
        .collect();

    let mut out = String::with_capacity(cleaned.len().min(max_bytes));
    let mut pending_space = false;
    for c in cleaned.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        let extra = c.len_utf8().saturating_add(usize::from(pending_space));
        if out.len().saturating_add(extra) > max_bytes {
            break;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize_text;
    use proptest::prelude::*;

    #[test]
    fn sec_004_strips_controls_and_nul() {
        assert_eq!(sanitize_text("a\0b\u{1}c\u{7f}d\u{85}e", 100), "abcde");
    }

    #[test]
    fn sec_004_strips_bidi() {
        let s = "a\u{202E}b\u{2066}c\u{2069}d\u{200E}e\u{200F}f\u{202A}g";
        assert_eq!(sanitize_text(s, 100), "abcdefg");
    }

    #[test]
    fn sec_004_strips_invisible_format_chars() {
        // Review F1: tag characters, word joiner & friends, soft hyphen, fillers, CGJ,
        // Mongolian selectors, variation selectors.
        let hidden = [
            '\u{E0041}',
            '\u{E0001}',
            '\u{E007F}',
            '\u{2060}',
            '\u{2064}',
            '\u{206A}',
            '\u{00AD}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{034F}',
            '\u{180B}',
            '\u{180E}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{E0100}',
            '\u{E01EF}',
            '\u{115F}',
            '\u{FFF9}',
        ];
        for h in hidden {
            let s = format!("a{h}b");
            assert_eq!(sanitize_text(&s, 100), "ab", "U+{:04X}", u32::from(h));
        }
        let all: String = hidden.iter().collect();
        assert_eq!(sanitize_text(&format!("x{all}y"), 100), "xy");
    }

    /// Unicode general category Cf (Unicode 16), written out by hand so the sanitizer's list
    /// cannot rot silently. A new Unicode version adding Cf characters means extending this list
    /// and `is_stripped` together (review L3).
    const CF_RANGES: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];

    #[test]
    fn sec_004_every_cf_char_is_stripped_except_zwj_zwnj() {
        for &(lo, hi) in CF_RANGES {
            for cp in lo..=hi {
                let Some(c) = char::from_u32(cp) else {
                    continue;
                };
                let out = sanitize_text(&format!("a{c}b"), 100);
                if cp == 0x200C || cp == 0x200D {
                    assert_eq!(out, format!("a{c}b"), "U+{cp:04X} must be kept");
                } else {
                    assert_eq!(out, "ab", "U+{cp:04X} must be stripped");
                }
            }
        }
        // Residual blank found by review.
        assert_eq!(sanitize_text("a\u{2800}b", 100), "ab");
    }

    #[test]
    fn sec_004_keeps_zwj_and_zwnj() {
        let s = "\u{1F468}\u{200D}\u{1F469}";
        assert_eq!(sanitize_text(s, 100), s);
        let p = "\u{0645}\u{200C}\u{06CC}";
        assert_eq!(sanitize_text(p, 100), p);
    }

    #[test]
    fn sec_004_collapses_whitespace() {
        assert_eq!(sanitize_text("  a \t\n b\u{a0}\u{2028} c  ", 100), "a b c");
    }

    #[test]
    fn sec_004_nfc() {
        assert_eq!(sanitize_text("e\u{301}", 100), "\u{e9}");
        // Stripping a control between base and mark must still compose.
        assert_eq!(sanitize_text("e\0\u{301}", 100), "\u{e9}");
    }

    #[test]
    fn sec_004_truncates_on_char_boundary() {
        assert_eq!(sanitize_text("a\u{e9}", 2), "a");
        assert_eq!(sanitize_text("a\u{e9}", 3), "a\u{e9}");
        assert_eq!(sanitize_text("a b", 2), "a");
        assert_eq!(sanitize_text("abc", 0), "");
        assert_eq!(sanitize_text("\u{65e5}\u{672c}\u{8a9e}", 4), "\u{65e5}");
    }

    #[test]
    fn sec_004_empty_and_blank() {
        assert_eq!(sanitize_text("", 10), "");
        assert_eq!(sanitize_text(" \t\0 ", 10), "");
    }

    proptest! {
        #[test]
        fn sec_004_prop_invariants(s in any::<String>(), max in 0usize..64) {
            let out = sanitize_text(&s, max);
            prop_assert!(out.len() <= max);
            prop_assert!(!out.chars().any(super::is_stripped));
            prop_assert!(!out.contains("  "));
            prop_assert_eq!(out.trim(), out.as_str());
            prop_assert_eq!(sanitize_text(&out, max), out);
        }

        #[test]
        fn sec_004_prop_idempotent_hostile(
            s in proptest::collection::vec(
                prop_oneof![
                    Just('e'), Just(' '), Just('\0'), Just('\u{301}'), Just('\u{202E}'),
                    Just('\u{a0}'), Just('\u{1100}'), Just('\u{1161}'), Just('\u{11a8}'),
                    Just('\u{e9}'), Just('\u{65e5}'), Just('\u{E0041}'), Just('\u{2060}'),
                    Just('\u{AD}'), Just('\u{3164}'), Just('\u{FE0F}'), Just('\u{200D}')
                ], 0..40),
            max in 0usize..40,
        ) {
            let s: String = s.into_iter().collect();
            let once = sanitize_text(&s, max);
            prop_assert_eq!(sanitize_text(&once, max), once);
        }
    }
}
