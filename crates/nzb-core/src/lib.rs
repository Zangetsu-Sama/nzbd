//! `nzb-core`: pure NZB logic (no I/O, no async, no unsafe).
//!
//! This module set currently provides the shared vocabulary: [`Limits`], [`NzbError`] and the
//! analysis result types. Parser, sanitizer and scene logic are added by later tasks.
#![forbid(unsafe_code)]

mod analyzer;
mod categorize;
mod error;
mod limits;
mod nfo;
mod parser;
mod sanitize;
mod scene;
mod serialize;
mod source_title;
mod subject;
mod taxonomy;
mod types;

pub use analyzer::{analyze, analyze_with_clock};
pub use categorize::{
    Categorization, CategorizeError, CategorizeRequest, CategoryRules, CategoryRulesError,
    CategorySource, HintDisagreement, categorize,
};
pub use error::{LimitName, NzbError};
pub use limits::{DEADLINE_CHECK_INTERVAL, Limits, LimitsError};
pub use nfo::{MAX_NFO_BYTES, NfoEncoding, NfoText, decode_nfo, detect_nfo_encoding};
pub use parser::{
    Clock, MAX_MISSING_RANGES, MAX_PAGE_LIMIT, MetaEntry, NzbSubset, ParsedFile, ParsedNzb,
    SegmentEntry, SegmentPage, SubsetFile, SystemClock, extract_files, list_segments, parse,
};
pub use sanitize::sanitize_text;
pub use scene::{
    Family, MAX_SCENE_NAME_BYTES, Resolution, SceneFlags, SceneInfo, SceneRules, SceneRulesError,
    Source, parse_scene,
};
pub use serialize::{OutputTooLarge, escaped_attr_len, write_nzb, written_len, xml_safe_text};
pub use source_title::{SOURCE_TITLE_BYTES, apply_source_title, source_stem, source_title};
pub use subject::{ParsedSubject, classify_kind, looks_obfuscated, par2_blocks, parse_subject};
pub use taxonomy::{
    Category, FALLBACK_CATEGORY, MAX_CATEGORIES, MAX_TAXONOMY_BYTES, Taxonomy, TaxonomyError,
    XXX_CATEGORY,
};
pub use types::{Analysis, FileInfo, FileKind, ReleaseFlags, Sha256, Sha256ParseError};

/// Crate name, used by the skeleton smoke test.
pub const CRATE_NAME: &str = "nzb-core";

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        assert_eq!(super::CRATE_NAME, "nzb-core");
    }
}
