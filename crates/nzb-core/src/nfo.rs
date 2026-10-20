//! NFO decoder (T140, D41 (d), SEC-105): turns the raw bytes of an `.nfo` file into display text.
//!
//! NFO files are DOS-era text art: by default every byte is read as code page 437 (the IBM PC
//! glyph set), so `0xDB` is `█` and `0x01` is `☺`. UTF-8 is used only when the file announces it
//! (a BOM) or is valid UTF-8 that actually uses box-drawing/block characters, which is what a
//! modern UTF-8 NFO looks like; a plain ASCII file stays CP437 (identical output either way).
//!
//! The output is display data only: it never holds a control character other than LF and TAB,
//! nor a bidi or zero-width format character, so it can be put in a `<pre>` once HTML-escaped.

use crate::sanitize::is_stripped;

/// Largest NFO accepted anywhere (HTTP layer and database CHECK).
pub const MAX_NFO_BYTES: usize = 256 * 1024;

/// DOS end-of-file marker; text after it (SAUCE / COMNT records) is never shown.
const DOS_EOF: u8 = 0x1A;

/// UTF-8 byte order mark.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Width of a TAB stop when measuring columns.
const TAB_WIDTH: usize = 8;

/// Text encoding used to decode an NFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfoEncoding {
    /// IBM PC code page 437 (the default for NFO files).
    Cp437,
    /// UTF-8.
    Utf8,
}

impl NfoEncoding {
    /// Stable identifier, as used in the `?enc=` query parameter: `"cp437"` or `"utf8"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cp437 => "cp437",
            Self::Utf8 => "utf8",
        }
    }

    /// Parses the identifier returned by [`NfoEncoding::as_str`] (exact match, case-sensitive).
    #[must_use]
    pub fn from_param(s: &str) -> Option<Self> {
        match s {
            "cp437" => Some(Self::Cp437),
            "utf8" => Some(Self::Utf8),
            _ => None,
        }
    }

    /// Human-readable label: `"CP437"` or `"UTF-8"`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cp437 => "CP437",
            Self::Utf8 => "UTF-8",
        }
    }
}

/// A decoded NFO, ready to be HTML-escaped and shown in a `<pre>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfoText {
    /// Decoded text: lines separated by `\n`, no trailing newline, no control character other
    /// than `\n` and `\t`, no bidi or zero-width format character.
    pub text: String,
    /// Encoding the text was decoded with.
    pub encoding: NfoEncoding,
    /// Number of lines in `text` (0 when empty).
    pub lines: usize,
    /// Widest line in chars, a TAB advancing to the next multiple of 8.
    pub columns: usize,
}

/// CP437 to Unicode. TAB, LF and CR keep their control meaning (CR is folded into LF by the
/// decoder before this table is consulted); `0x00` shows as a space; `0x1A` is never reached
/// because the text is cut there, its glyph is kept for completeness.
const CP437: [char; 256] = [
    // 0x00
    ' ', '☺', '☻', '♥', '♦', '♣', '♠', '•', '◘', '\t', '\n', '♂', '♀', '\r', '♫', '☼',
    // 0x10
    '►', '◄', '↕', '‼', '¶', '§', '▬', '↨', '↑', '↓', '→', '←', '∟', '↔', '▲', '▼',
    // 0x20
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    // 0x30
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    // 0x40
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    // 0x50
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    // 0x60
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    // 0x70
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '⌂',
    // 0x80
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    // 0x90
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    // 0xA0
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    // 0xB0
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    // 0xC0
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    // 0xD0
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    // 0xE0
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    // 0xF0
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{A0}',
];

/// The bytes that are decoded: at most [`MAX_NFO_BYTES`], cut at the first DOS EOF byte.
fn effective(bytes: &[u8]) -> &[u8] {
    let capped = bytes.get(..MAX_NFO_BYTES).unwrap_or(bytes);
    match capped.iter().position(|&b| b == DOS_EOF) {
        Some(end) => capped.get(..end).unwrap_or(capped),
        None => capped,
    }
}

/// Box drawing (U+2500..U+257F) and block elements (U+2580..U+259F).
fn is_box_or_block(c: char) -> bool {
    matches!(c, '\u{2500}'..='\u{259F}')
}

/// Picks the encoding of an NFO: UTF-8 when it starts with a UTF-8 BOM, or when it is valid
/// UTF-8 holding at least one box-drawing/block character; CP437 otherwise.
///
/// Only the bytes [`decode_nfo`] would decode are looked at (first [`MAX_NFO_BYTES`], up to the
/// first `0x1A`). A plain ASCII file is CP437: both decodings give the same text for it, and
/// CP437 is the NFO default.
#[must_use]
pub fn detect_nfo_encoding(bytes: &[u8]) -> NfoEncoding {
    let b = effective(bytes);
    if b.starts_with(UTF8_BOM) {
        return NfoEncoding::Utf8;
    }
    let text = match std::str::from_utf8(b) {
        Ok(s) => Some(s),
        // The size cap may have split the last character of an otherwise valid UTF-8 file.
        Err(e) if e.error_len().is_none() && bytes.len() > MAX_NFO_BYTES => b
            .get(..e.valid_up_to())
            .and_then(|head| std::str::from_utf8(head).ok()),
        Err(_) => None,
    };
    match text {
        Some(s) if s.chars().any(is_box_or_block) => NfoEncoding::Utf8,
        _ => NfoEncoding::Cp437,
    }
}

/// Decodes an NFO for display, with `force` overriding [`detect_nfo_encoding`].
///
/// Only the first [`MAX_NFO_BYTES`] are read (callers refuse larger files; this is a backstop)
/// and the text ends at the first `0x1A` byte. CRLF and lone CR become LF; trailing newlines
/// are trimmed (leading blank lines are kept, they are part of the art). On the UTF-8 path a
/// leading BOM is dropped, invalid sequences become U+FFFD, and every character the text
/// sanitizer strips (controls, bidi, zero-width and other invisible format characters) is
/// removed except LF and TAB. Never panics.
#[must_use]
pub fn decode_nfo(bytes: &[u8], force: Option<NfoEncoding>) -> NfoText {
    let encoding = force.unwrap_or_else(|| detect_nfo_encoding(bytes));
    let b = effective(bytes);
    let mut text = match encoding {
        NfoEncoding::Cp437 => decode_cp437(b),
        NfoEncoding::Utf8 => decode_utf8(b.strip_prefix(UTF8_BOM).unwrap_or(b)),
    };
    while text.ends_with('\n') {
        text.pop();
    }
    let (lines, columns) = measure(&text);
    NfoText {
        text,
        encoding,
        lines,
        columns,
    }
}

fn decode_cp437(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut iter = b.iter().copied().peekable();
    while let Some(byte) = iter.next() {
        if byte == b'\r' {
            // CRLF: the LF that follows produces the newline.
            if iter.peek() != Some(&b'\n') {
                out.push('\n');
            }
            continue;
        }
        out.push(CP437.get(usize::from(byte)).copied().unwrap_or(' '));
    }
    out
}

fn decode_utf8(b: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(b);
    let mut out = String::with_capacity(lossy.len());
    let mut iter = lossy.chars().peekable();
    while let Some(c) = iter.next() {
        match c {
            '\r' => {
                if iter.peek() != Some(&'\n') {
                    out.push('\n');
                }
            }
            '\n' | '\t' => out.push(c),
            _ if is_stripped(c) => {}
            _ => out.push(c),
        }
    }
    out
}

/// Line count and widest line (chars, TAB to the next multiple of [`TAB_WIDTH`]).
fn measure(text: &str) -> (usize, usize) {
    if text.is_empty() {
        return (0, 0);
    }
    let mut lines: usize = 1;
    let mut widest: usize = 0;
    let mut col: usize = 0;
    for c in text.chars() {
        match c {
            '\n' => {
                lines = lines.saturating_add(1);
                col = 0;
            }
            '\t' => col = col.saturating_add(TAB_WIDTH - col % TAB_WIDTH),
            _ => col = col.saturating_add(1),
        }
        widest = widest.max(col);
    }
    (lines, widest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn is_bad(c: char) -> bool {
        c != '\n' && c != '\t' && is_stripped(c)
    }

    #[test]
    fn sec_105_every_byte_decodes_to_a_displayable_char() {
        for byte in 0..=255u8 {
            let t = decode_nfo(&[b'x', byte, b'y'], Some(NfoEncoding::Cp437));
            assert!(
                !t.text.chars().any(is_bad),
                "byte {byte:#04x} -> {:?}",
                t.text
            );
            if byte != DOS_EOF {
                assert!(
                    t.text.starts_with('x') && t.text.ends_with('y'),
                    "{byte:#04x}"
                );
            }
        }
        for (i, c) in CP437.iter().enumerate() {
            assert!(
                !c.is_control() || matches!(c, '\t' | '\n' | '\r'),
                "entry {i:#04x}"
            );
            assert!(
                !is_stripped(*c) || matches!(c, '\t' | '\n' | '\r'),
                "entry {i:#04x}"
            );
        }
    }

    #[test]
    fn cp437_table_is_a_bijection_on_glyph_bytes() {
        let mut seen = std::collections::HashSet::new();
        for byte in 0x01..=0xFFu8 {
            if matches!(byte, 0x09 | 0x0A | 0x0D | 0x1A) {
                continue;
            }
            let c = CP437[usize::from(byte)];
            assert!(seen.insert(c), "duplicate glyph {c:?} at {byte:#04x}");
        }
        assert_eq!(seen.len(), 251);
        assert_eq!(CP437[0], ' ');
        assert_eq!(CP437[0x7F], '⌂');
        assert_eq!(CP437[0xFF], '\u{A0}');
        assert_eq!(CP437[0x01], '☺');
        assert_eq!(CP437[0x1F], '▼');
    }

    #[test]
    fn cp437_known_samples() {
        let t = decode_nfo(&[0xC9, 0xCD, 0xBB], None);
        assert_eq!(t.encoding, NfoEncoding::Cp437);
        assert_eq!(t.text, "╔═╗");
        assert_eq!(decode_nfo(&[0xDB, 0xB0, 0xB1, 0xB2], None).text, "█░▒▓");
        assert_eq!(decode_nfo(&[0x00, 0x01, 0x7F], None).text, " ☺⌂");
        assert_eq!(decode_nfo(b"Caf\x82 \x9c", None).text, "Café £");
    }

    #[test]
    fn sec_105_dos_eof_hides_sauce() {
        let mut b = b"art\r\n\x1aSAUCE00 title".to_vec();
        let t = decode_nfo(&b, None);
        assert_eq!(t.text, "art");
        b.splice(0..0, [0xEF, 0xBB, 0xBF]);
        let t = decode_nfo(&b, None);
        assert_eq!(t.encoding, NfoEncoding::Utf8);
        assert_eq!(t.text, "art");
        assert_eq!(decode_nfo(b"\x1a\xdb", None).text, "");
        assert_eq!(
            decode_nfo(b"a\x1a\xe2\x96\x88", None).encoding,
            NfoEncoding::Cp437
        );
    }

    #[test]
    fn line_endings_normalized() {
        for enc in [NfoEncoding::Cp437, NfoEncoding::Utf8] {
            let t = decode_nfo(b"a\r\nb\rc\nd\r\r\ne", Some(enc));
            assert_eq!(t.text, "a\nb\nc\nd\n\ne", "{enc:?}");
            assert_eq!(t.lines, 6);
        }
    }

    #[test]
    fn trailing_newlines_trimmed_leading_kept() {
        let t = decode_nfo(b"\r\n\r\n  x\r\n\r\n\r\n", None);
        assert_eq!(t.text, "\n\n  x");
        assert_eq!(t.lines, 3);
        assert_eq!(t.columns, 3);
        let empty = decode_nfo(b"\r\n\n", None);
        assert_eq!(empty.text, "");
        assert_eq!((empty.lines, empty.columns), (0, 0));
        assert_eq!(decode_nfo(b"", None).lines, 0);
    }

    #[test]
    fn bom_selects_utf8_and_is_stripped() {
        let t = decode_nfo("\u{FEFF}héllo".as_bytes(), None);
        assert_eq!(t.encoding, NfoEncoding::Utf8);
        assert_eq!(t.text, "héllo");
        // Forced CP437 shows the BOM bytes as glyphs, which is what the user asked for.
        let t = decode_nfo("\u{FEFF}a".as_bytes(), Some(NfoEncoding::Cp437));
        assert_eq!(t.text, "∩╗┐a");
    }

    #[test]
    fn detection() {
        assert_eq!(
            detect_nfo_encoding("║ █▓ ║\nok".as_bytes()),
            NfoEncoding::Utf8
        );
        assert_eq!(
            detect_nfo_encoding(b"plain ascii\r\nfile"),
            NfoEncoding::Cp437
        );
        assert_eq!(detect_nfo_encoding("héllo".as_bytes()), NfoEncoding::Cp437);
        // C4 BF is valid UTF-8 (U+013F) but holds no box char: CP437.
        let t = decode_nfo(&[0xC4, 0xBF], None);
        assert_eq!(t.encoding, NfoEncoding::Cp437);
        assert_eq!(t.text, "─┐");
        // Box chars but an invalid sequence elsewhere: CP437.
        let mut b = "█".as_bytes().to_vec();
        b.push(0xFF);
        assert_eq!(detect_nfo_encoding(&b), NfoEncoding::Cp437);
        assert_eq!(detect_nfo_encoding(&[0xEF, 0xBB, 0xBF]), NfoEncoding::Utf8);
    }

    #[test]
    fn sec_105_bidi_and_zero_width_stripped_on_utf8() {
        let s = "█ a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}e\u{0}f\u{7}g\u{85}h\u{E0041}i\u{200D}j\tk";
        let t = decode_nfo(s.as_bytes(), None);
        assert_eq!(t.encoding, NfoEncoding::Utf8);
        assert_eq!(t.text, "█ abcdefghi\u{200D}j\tk");
    }

    #[test]
    fn forced_encodings() {
        let utf8 = "█▀".as_bytes();
        assert_eq!(decode_nfo(utf8, Some(NfoEncoding::Utf8)).text, "█▀");
        let t = decode_nfo(utf8, Some(NfoEncoding::Cp437));
        assert_eq!(t.encoding, NfoEncoding::Cp437);
        assert_eq!(t.text.chars().count(), 6);
        let t = decode_nfo(&[0xDB, b'a', 0xC4], Some(NfoEncoding::Utf8));
        assert_eq!(t.encoding, NfoEncoding::Utf8);
        assert_eq!(t.text, "\u{FFFD}a\u{FFFD}");
    }

    #[test]
    fn sec_105_oversize_input_truncated_without_panic() {
        let big = vec![0xDBu8; MAX_NFO_BYTES + 1000];
        let t = decode_nfo(&big, None);
        assert_eq!(t.text.chars().count(), MAX_NFO_BYTES);
        assert_eq!(t.lines, 1);
        assert_eq!(t.columns, MAX_NFO_BYTES);
        // A UTF-8 file whose last char is split by the cap is still detected as UTF-8.
        let mut u = "█".repeat(MAX_NFO_BYTES / 3 + 1).into_bytes();
        assert!(u.len() > MAX_NFO_BYTES);
        u.truncate(MAX_NFO_BYTES + 1);
        let t = decode_nfo(&u, None);
        assert_eq!(t.encoding, NfoEncoding::Utf8);
        assert_eq!(
            t.text.chars().filter(|&c| c == '█').count(),
            MAX_NFO_BYTES / 3
        );
        let t = decode_nfo(&big, Some(NfoEncoding::Utf8));
        assert!(!t.text.chars().any(is_bad));
    }

    #[test]
    fn lines_and_columns_with_tabs() {
        let t = decode_nfo(b"ab\tc\n\t\nabcdefgh\tx\n1234567", None);
        // "ab\tc" = 9, "\t" = 8, "abcdefgh\tx" = 17, "1234567" = 7.
        assert_eq!(t.lines, 4);
        assert_eq!(t.columns, 17);
        let t = decode_nfo("╔═╗\n║x║".as_bytes(), None);
        assert_eq!((t.lines, t.columns), (2, 3));
    }

    #[test]
    fn encoding_params() {
        for e in [NfoEncoding::Cp437, NfoEncoding::Utf8] {
            assert_eq!(NfoEncoding::from_param(e.as_str()), Some(e));
        }
        assert_eq!(NfoEncoding::from_param("UTF8"), None);
        assert_eq!(NfoEncoding::from_param("utf-8"), None);
        assert_eq!(NfoEncoding::from_param(""), None);
        assert_eq!(NfoEncoding::Cp437.label(), "CP437");
        assert_eq!(NfoEncoding::Utf8.label(), "UTF-8");
    }

    proptest! {
        #[test]
        fn sec_105_output_invariant(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            for force in [None, Some(NfoEncoding::Cp437), Some(NfoEncoding::Utf8)] {
                let t = decode_nfo(&bytes, force);
                prop_assert!(!t.text.chars().any(is_bad));
                prop_assert!(!t.text.ends_with('\n'));
                let expected_lines = if t.text.is_empty() { 0 } else { t.text.split('\n').count() };
                prop_assert_eq!(t.lines, expected_lines);
                // Decoded text is a fixed point of the UTF-8 decoder.
                let again = decode_nfo(t.text.as_bytes(), Some(NfoEncoding::Utf8));
                prop_assert_eq!(&again.text, &t.text);
            }
        }
    }
}
