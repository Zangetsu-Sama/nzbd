//! The `scene` analyzer (`docs/v3/DATA_MODEL.md` 5.2): the same code tokenizes documents at index time
//! and query text at search time, so both sides always agree.
//!
//! 1. **Split** on every character that is not Unicode alphanumeric (`char::is_alphanumeric`), the 2.x
//!    rule of `build_fts_query` and FTS5 `unicode61`: `Show.Name-GRP` -> `Show`, `Name`, `GRP`; `S01E02`,
//!    `1080p`, `x265` stay single tokens. Hand-written, no regex engine, one pass.
//! 2. **Lower-case** (Unicode, Tantivy's `LowerCaser`).
//! 3. **ASCII folding** (`AsciiFoldingFilter`: `é` -> `e`, `Æ` -> `ae`, `ß` -> `ss`), then lower-case once
//!    more because a few folds produce upper-case ASCII (modifier letters such as `ᴺ` -> `N`).
//! 4. **Truncate** every token to [`MAX_TOKEN_BYTES`] at a char boundary (after folding, which can grow a
//!    token): a long garbage token stays findable by its first 64 bytes instead of being dropped.
//!
//! Work is linear in the input and the input is capped by the callers ([`cap_bytes`]); no stemming, no
//! stop words (scene names are not prose).

use std::str::CharIndices;

use tantivy::tokenizer::{
    AsciiFoldingFilter, LowerCaser, TextAnalyzer, Token, TokenFilter, TokenStream, Tokenizer,
};

/// Name the analyzer is registered under in the index's tokenizer manager.
pub const SCENE_ANALYZER: &str = "scene";

/// Longest token kept, in bytes (longer ones are cut at a char boundary; same rule on both sides).
pub const MAX_TOKEN_BYTES: usize = 64;

/// Input caps per indexed field, applied before analysis (bytes, cut at a char boundary).
pub const MAX_TITLE_BYTES: usize = 512;
/// Poster cap (bytes).
pub const MAX_POSTER_BYTES: usize = 512;
/// Source-name text cap (bytes): the `.nzb` file name (stored at most 255 bytes) plus the release group.
pub const MAX_SOURCE_NAME_BYTES: usize = 512;
/// File-name text cap per release (bytes).
pub const MAX_FILES_BYTES: usize = 256 * 1024;

/// The analyzer used for `title`, `files`, `poster` and `source_name` and for query text.
#[must_use]
pub fn scene_analyzer() -> TextAnalyzer {
    TextAnalyzer::builder(SceneSplitter)
        .filter(LowerCaser)
        .filter(AsciiFoldingFilter)
        // Folding can yield upper-case ASCII (`ᴺ` -> `N`): lower-case again so every term is lower-case.
        .filter(LowerCaser)
        .filter(Truncate)
        .build()
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a char boundary.
#[must_use]
pub fn cap_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or("")
}

/// Tokens of `text` as the index sees them, at most `max_tokens` (the rest are not produced).
#[must_use]
pub fn analyze(text: &str, max_tokens: usize) -> Vec<String> {
    let mut analyzer = scene_analyzer();
    let mut stream = analyzer.token_stream(text);
    let mut out = Vec::new();
    while out.len() < max_tokens && stream.advance() {
        out.push(stream.token().text.clone());
    }
    out
}

/// ASCII lower-casing for raw keyword fields compared like SQLite `NOCASE` (group, label, title order).
#[must_use]
pub fn nocase(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Splits on non-alphanumeric characters (step 1).
#[derive(Clone, Copy, Debug, Default)]
pub struct SceneSplitter;

/// Token stream of [`SceneSplitter`].
pub struct SceneSplitStream<'a> {
    text: &'a str,
    chars: CharIndices<'a>,
    token: Token,
    next_position: usize,
}

impl Tokenizer for SceneSplitter {
    type TokenStream<'a> = SceneSplitStream<'a>;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> SceneSplitStream<'a> {
        SceneSplitStream {
            text,
            chars: text.char_indices(),
            token: Token::default(),
            next_position: 0,
        }
    }
}

impl TokenStream for SceneSplitStream<'_> {
    fn advance(&mut self) -> bool {
        self.token.text.clear();
        // Skip separators up to the first alphanumeric char.
        let start = loop {
            match self.chars.next() {
                Some((i, c)) if c.is_alphanumeric() => break i,
                Some(_) => {}
                None => return false,
            }
        };
        // The run ends at the next separator (or the end of the text).
        let mut end = self.text.len();
        for (i, c) in self.chars.by_ref() {
            if !c.is_alphanumeric() {
                end = i;
                break;
            }
        }
        self.token.offset_from = start;
        self.token.offset_to = end;
        self.token.position = self.next_position;
        self.token.position_length = 1;
        self.next_position = self.next_position.saturating_add(1);
        self.token
            .text
            .push_str(self.text.get(start..end).unwrap_or(""));
        true
    }

    fn token(&self) -> &Token {
        &self.token
    }

    fn token_mut(&mut self) -> &mut Token {
        &mut self.token
    }
}

/// Cuts tokens to [`MAX_TOKEN_BYTES`] (step 4).
#[derive(Clone, Copy, Debug, Default)]
pub struct Truncate;

impl TokenFilter for Truncate {
    type Tokenizer<T: Tokenizer> = TruncateFilter<T>;

    fn transform<T: Tokenizer>(self, tokenizer: T) -> TruncateFilter<T> {
        TruncateFilter { inner: tokenizer }
    }
}

/// Tokenizer wrapper of [`Truncate`].
#[derive(Clone)]
pub struct TruncateFilter<T> {
    inner: T,
}

impl<T: Tokenizer> Tokenizer for TruncateFilter<T> {
    type TokenStream<'a> = TruncateStream<T::TokenStream<'a>>;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        TruncateStream {
            tail: self.inner.token_stream(text),
        }
    }
}

/// Token stream of [`TruncateFilter`].
pub struct TruncateStream<T> {
    tail: T,
}

impl<T: TokenStream> TokenStream for TruncateStream<T> {
    fn advance(&mut self) -> bool {
        if !self.tail.advance() {
            return false;
        }
        let text = &mut self.tail.token_mut().text;
        let keep = cap_bytes(text, MAX_TOKEN_BYTES).len();
        text.truncate(keep);
        true
    }

    fn token(&self) -> &Token {
        self.tail.token()
    }

    fn token_mut(&mut self) -> &mut Token {
        self.tail.token_mut()
    }
}
