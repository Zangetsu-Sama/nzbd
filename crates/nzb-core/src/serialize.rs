//! Escaping NZB serializer for partial downloads (T125, D38 a).
//!
//! The output is rebuilt from the values the hardened parser produced ([`NzbSubset`], every
//! string already sanitized); no byte of the input document is ever copied through. Every text
//! node and attribute value is escaped here, so a hostile subject, poster, group or message-id
//! (`<`, `>`, `&`, quotes, control characters) can only ever come out as character data.
//!
//! # Size (review 43 M1)
//! Escaping is minimal, so no value is written longer than the shortest encoding a source
//! document could have used for it:
//! - text escapes `&` (`&amp;`), `<` (`&lt;`) and `>` only where it would close `]]>`;
//! - attribute values escape `&`, `<` and the delimiting quote as `&#34;` / `&#39;` (5 bytes,
//!   the shortest reference), the delimiter being whichever quote occurs less often;
//! - TAB/LF/CR become references (the sanitizer already turns them into spaces).
//!
//! [`write_nzb`] first computes the exact output length ([`written_len`]), refuses a document
//! longer than the caller's cap ([`OutputTooLarge`]), then writes into a buffer of exactly that
//! size: no reallocation peak, no spare capacity held while the body is sent.
//!
//! # Round trip
//! `parse(write_nzb(s))` reports the same metas and files as `s` (with `idx` renumbered from 0),
//! up to two documented exceptions:
//! - XML 1.0 cannot carry U+FFFE or U+FFFF in any form; the sanitizer keeps them, so the
//!   serializer writes U+FFFD instead ([`xml_safe_text`]). Every other character the sanitizer
//!   lets through is legal XML.
//! - The parser caps the *raw* (escaped) length of the `subject`, `poster` and `<meta type>`
//!   attributes (the last one by `max_meta_value_bytes`, before it is sanitized to 64 bytes). Because
//!   the escaping above is never longer than the source's, an attribute value equal to its
//!   unescaped source always fits again. The only value that can exceed the cap is one the
//!   sanitizer made longer than its source (NFC normalization expands a few characters) while the
//!   source sat right at the cap: [`escaped_attr_len`] of that value is then above the cap. The
//!   output is still well-formed XML; only *our* parser at the same limit would refuse it.
//!
//! With the cap set to the parser's `max_file_bytes` (as the web layer does), the whole output is
//! always within our parser's document limit as well.
//!
//! No DOCTYPE is written: downloaders do not need it and the output then references no external
//! identifier at all. The `xmlns` value is the conventional NZB namespace name (an identifier,
//! never fetched).

use crate::parser::NzbSubset;
use std::fmt::Write;

/// The XML declaration and the opening root element of every written NZB.
const PROLOG: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n";

/// The document [`write_nzb`] would produce is longer than the caller's cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputTooLarge {
    /// Exact length the document would have had, in bytes.
    pub len: u64,
}

impl std::fmt::Display for OutputTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("rebuilt NZB exceeds the size cap")
    }
}

impl std::error::Error for OutputTooLarge {}

/// True for characters XML 1.0 can represent (`Char` production).
const fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// `s` with every character XML 1.0 cannot represent replaced by U+FFFD: the exact character
/// mapping [`write_nzb`] applies (useful to compare a round trip).
#[must_use]
pub fn xml_safe_text(s: &str) -> String {
    s.chars()
        .map(|c| if is_xml_char(c) { c } else { '\u{FFFD}' })
        .collect()
}

/// Byte counter with the `fmt::Write` interface: the length pass runs the same code as the
/// writing pass, so the two cannot disagree.
struct Count(u64);

impl Write for Count {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0 = self
            .0
            .saturating_add(u64::try_from(s.len()).unwrap_or(u64::MAX));
        Ok(())
    }
}

/// Appends `s` as escaped character data. Writing to a `String` or a [`Count`] cannot fail, so
/// the `fmt::Result`s are ignored.
fn push_text<W: Write>(out: &mut W, s: &str) {
    // `>` needs escaping only as the end of `]]>`; `]` itself is written verbatim, so tracking
    // the source characters is tracking the output.
    let mut brackets = 0_u8;
    for c in s.chars() {
        let _ = match c {
            '&' => out.write_str("&amp;"),
            '<' => out.write_str("&lt;"),
            '>' if brackets >= 2 => out.write_str("&gt;"),
            '\t' => out.write_str("&#9;"),
            '\n' => out.write_str("&#10;"),
            '\r' => out.write_str("&#13;"),
            c if is_xml_char(c) => out.write_char(c),
            _ => out.write_char('\u{FFFD}'),
        };
        brackets = if c == ']' {
            brackets.saturating_add(1)
        } else {
            0
        };
    }
}

/// The delimiting quote and its (shortest) reference for `value`.
fn quote_for(value: &str) -> (char, &'static str) {
    let dq = value.chars().filter(|c| *c == '"').count();
    let sq = value.chars().filter(|c| *c == '\'').count();
    if dq <= sq {
        ('"', "&#34;")
    } else {
        ('\'', "&#39;")
    }
}

/// Appends the escaped attribute value of `value` (without name or quotes) for delimiter `quote`.
fn push_attr_value<W: Write>(out: &mut W, value: &str, quote: char, quote_ref: &str) {
    for c in value.chars() {
        let _ = match c {
            '&' => out.write_str("&amp;"),
            '<' => out.write_str("&lt;"),
            '\t' => out.write_str("&#9;"),
            '\n' => out.write_str("&#10;"),
            '\r' => out.write_str("&#13;"),
            c if c == quote => out.write_str(quote_ref),
            c if is_xml_char(c) => out.write_char(c),
            _ => out.write_char('\u{FFFD}'),
        };
    }
}

/// Appends ` name="value"` (or with `'` when that needs fewer escapes), the value escaped.
fn push_attr<W: Write>(out: &mut W, name: &str, value: &str) {
    let (quote, quote_ref) = quote_for(value);
    let _ = write!(out, " {name}={quote}");
    push_attr_value(out, value, quote, quote_ref);
    let _ = out.write_char(quote);
}

/// Length in bytes of `value` once escaped as an attribute value by [`write_nzb`] (quotes
/// excluded): the raw length our parser checks against its attribute caps.
#[must_use]
pub fn escaped_attr_len(value: &str) -> u64 {
    let (quote, quote_ref) = quote_for(value);
    let mut n = Count(0);
    push_attr_value(&mut n, value, quote, quote_ref);
    n.0
}

/// The whole document, into any `fmt::Write` sink.
fn emit<W: Write>(subset: &NzbSubset, out: &mut W) {
    let _ = out.write_str(PROLOG);
    if !subset.meta.is_empty() {
        let _ = out.write_str("<head>\n");
        for m in &subset.meta {
            let _ = out.write_str("<meta");
            push_attr(out, "type", &m.kind);
            let _ = out.write_char('>');
            push_text(out, &m.value);
            let _ = out.write_str("</meta>\n");
        }
        let _ = out.write_str("</head>\n");
    }
    for f in &subset.files {
        let file = &f.file;
        let _ = out.write_str("<file");
        push_attr(out, "poster", file.poster.as_deref().unwrap_or_default());
        if let Some(d) = file.posted_at {
            let _ = write!(out, " date=\"{d}\"");
        }
        push_attr(out, "subject", &file.subject);
        let _ = out.write_str(">\n<groups>\n");
        for g in &file.groups {
            let _ = out.write_str("<group>");
            push_text(out, g);
            let _ = out.write_str("</group>\n");
        }
        let _ = out.write_str("</groups>\n<segments>\n");
        for s in &f.segments {
            let _ = write!(
                out,
                "<segment bytes=\"{}\" number=\"{}\">",
                s.bytes, s.number
            );
            push_text(out, &s.message_id);
            let _ = out.write_str("</segment>\n");
        }
        let _ = out.write_str("</segments>\n</file>\n");
    }
    let _ = out.write_str("</nzb>\n");
}

/// Exact length in bytes of the document [`write_nzb`] writes for `subset`.
#[must_use]
pub fn written_len(subset: &NzbSubset) -> u64 {
    let mut n = Count(0);
    emit(subset, &mut n);
    n.0
}

/// Writes `subset` as a complete NZB document: the head metas (when there are any), then each
/// file with its poster, date (when known) and subject, its groups and every segment, all in the
/// order of `subset`. The buffer is allocated once with the exact length. Never panics.
///
/// # Errors
/// [`OutputTooLarge`] when the document would be longer than `max_bytes` (nothing is allocated
/// for it then).
pub fn write_nzb(subset: &NzbSubset, max_bytes: u64) -> Result<String, OutputTooLarge> {
    let len = written_len(subset);
    if len > max_bytes {
        return Err(OutputTooLarge { len });
    }
    let cap = usize::try_from(len).map_err(|_| OutputTooLarge { len })?;
    let mut out = String::with_capacity(cap);
    emit(subset, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{MetaEntry, ParsedFile, SegmentEntry, SubsetFile};

    fn file(subject: &str, poster: Option<&str>) -> ParsedFile {
        ParsedFile {
            idx: 0,
            subject: subject.to_owned(),
            poster: poster.map(str::to_owned),
            posted_at: Some(1_700_000_000),
            bytes: 10,
            segment_count: 1,
            duplicate_segments: 0,
            declared_segments: None,
            missing_ranges: Vec::new(),
            missing_truncated: false,
            groups: vec!["a.b&<c>".to_owned()],
        }
    }

    fn write(s: &NzbSubset) -> String {
        write_nzb(s, u64::MAX).unwrap()
    }

    #[test]
    fn sec_030_serializer_escapes_every_value() {
        let s = NzbSubset {
            meta: vec![MetaEntry {
                kind: "pass\"word'".to_owned(),
                value: "<x>&</x>]]>]>]]]>".to_owned(),
            }],
            files: vec![SubsetFile {
                file: file("a\"b<c>&d'", Some("p<o>&\"'")),
                segments: vec![SegmentEntry {
                    number: 1,
                    bytes: 10,
                    message_id: "<id&\"'>@x".to_owned(),
                }],
            }],
        };
        let out = write(&s);
        assert!(
            out.contains("<meta type=\"pass&#34;word'\">&lt;x>&amp;&lt;/x>]]&gt;]>]]]&gt;</meta>"),
            "{out}"
        );
        assert!(out.contains(" subject=\"a&#34;b&lt;c>&amp;d'\""));
        assert!(out.contains(" poster=\"p&lt;o>&amp;&#34;'\""));
        assert!(out.contains("<group>a.b&amp;&lt;c></group>"));
        assert!(out.contains(">&lt;id&amp;\"'>@x</segment>"));
        assert!(!out.contains("]]>"));
        // Single quotes win when they need fewer escapes.
        let mut t = String::new();
        push_attr(&mut t, "subject", "say \"hi\" it's");
        assert_eq!(t, " subject='say \"hi\" it&#39;s'");
        let mut t = String::new();
        push_attr(&mut t, "x", "a\tb\nc\rd");
        assert_eq!(t, " x=\"a&#9;b&#10;c&#13;d\"");
        assert_eq!(escaped_attr_len("a\"'&"), 1 + 5 + 1 + 5);
    }

    #[test]
    fn sec_030_serializer_maps_non_xml_characters() {
        assert_eq!(
            xml_safe_text("a\u{FFFE}b\u{FFFF}\u{1}"),
            "a\u{FFFD}b\u{FFFD}\u{FFFD}"
        );
        let mut t = String::new();
        push_text(&mut t, "x\u{FFFF}\u{0}y\u{10FFFF}");
        assert_eq!(t, "x\u{FFFD}\u{FFFD}y\u{10FFFF}");
    }

    #[test]
    fn sec_030_serializer_length_pass_is_exact_and_capped() {
        let s = NzbSubset {
            meta: Vec::new(),
            files: vec![SubsetFile {
                file: file("\u{65e5}>\"'&<", Some("p")),
                segments: vec![
                    SegmentEntry {
                        number: 1,
                        bytes: 10,
                        message_id: "]]>>&\u{FFFE}".to_owned(),
                    };
                    3
                ],
            }],
        };
        let out = write(&s);
        let len = written_len(&s);
        assert_eq!(u64::try_from(out.len()).unwrap(), len);
        assert_eq!(out.capacity(), out.len());
        assert_eq!(write_nzb(&s, len).unwrap(), out);
        assert_eq!(write_nzb(&s, len - 1), Err(OutputTooLarge { len }));
    }

    #[test]
    fn empty_head_and_unknown_date_are_omitted() {
        let mut f = file("s", None);
        f.posted_at = None;
        let out = write(&NzbSubset {
            meta: Vec::new(),
            files: vec![SubsetFile {
                file: f,
                segments: Vec::new(),
            }],
        });
        assert!(!out.contains("<head>"));
        assert!(!out.contains("date="));
        assert!(out.contains(" poster=\"\""));
        assert!(!out.contains("DOCTYPE"));
    }
}
