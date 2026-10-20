//! Tantivy schema, index schema version 3 (`docs/v3/DATA_MODEL.md` 5.1).
//!
//! No stored fields and no doc store content: the index holds ids, sort/filter columns and the analyzed
//! display text that Postgres also holds (sanitized NZB data). Nothing secret, no account data
//! (SEC-091); `added_by` is an account id, never a name.

use tantivy::schema::{
    BytesOptions, FAST, Field, IndexRecordOption, NumericOptions, STRING, Schema,
    TextFieldIndexing, TextOptions,
};

use crate::analyzer::SCENE_ANALYZER;

/// Version of the document layout and analyzer. A binary whose version is newer than an index's
/// payload `schema` rebuilds it (ARCHITECTURE 3.3); bump it with every change of fields or analysis.
///
/// History: 1 = v3.0 layout; 2 = T131 adds `source_name` (the `.nzb` file name and the release group as text);
/// 3 = Tantivy 0.27's index format (and its fixed LRU dependency). Existing indexes rebuild automatically.
pub const INDEX_SCHEMA_VERSION: u32 = 3;

/// Handles of every field.
#[derive(Debug, Clone, Copy)]
pub struct Fields {
    /// `release.id`: document key (`delete_term`), tie-break, hydration. i64, INDEXED + FAST.
    pub id: Field,
    /// `release.index_version` (verify, no-op skip). u64, FAST.
    pub version: Field,
    /// Title, analyzer `scene`, freqs + positions.
    pub title: Field,
    /// File names, analyzer `scene`, doc ids only.
    pub files: Field,
    /// Poster, analyzer `scene`, doc ids only.
    pub poster: Field,
    /// `.nzb` source file name (extension stripped) and the parsed release group, analyzer `scene`, doc ids
    /// only (T131): free text finds a word of the file name or the group even when the title has neither.
    pub source_name: Field,
    /// ASCII-lower-cased title bytes (SQLite NOCASE order), FAST only.
    pub title_sort: Field,
    /// Category id. u64, INDEXED + FAST.
    pub cat: Field,
    /// Direct parent of the category, or the category itself when it has none. u64, INDEXED + FAST.
    /// The 2.x filter is "the id or its direct children" (`id IN (..) OR parent_id IN (..)`); with the
    /// built-in two-level taxonomy this is the root the design calls `cat_root`.
    pub cat_parent: Field,
    /// Posted date; `None` is [`UNDATED`]. i64, INDEXED + FAST.
    pub posted: Field,
    /// Ingest time. i64, FAST.
    pub added: Field,
    /// Total bytes. u64, INDEXED + FAST.
    pub size: Field,
    /// One raw term per set release flag (see [`crate::doc::flag_terms`]).
    pub flag: Field,
    /// Scene family (raw keyword, FAST).
    pub family: Field,
    /// Scene resolution (raw keyword, FAST).
    pub resolution: Field,
    /// Scene source (raw keyword, FAST).
    pub source: Field,
    /// Scene year. u64, INDEXED + FAST.
    pub year: Field,
    /// Release group, ASCII lower-cased (raw keyword, FAST).
    pub group: Field,
    /// Scene season. u64, INDEXED + FAST.
    pub season: Field,
    /// Scene episode. u64, INDEXED + FAST.
    pub episode: Field,
    /// Normalized scene title (+ year for movies) for grouped views (raw keyword, FAST).
    pub series_key: Field,
    /// Source label, ASCII lower-cased (raw keyword, FAST).
    pub label: Field,
    /// Uploader account id. u64, INDEXED + FAST.
    pub added_by: Field,
}

/// Sentinel stored in `posted` for an undated release: excluded from date ranges (they start above
/// it) and placed last in both date orders by the collector.
pub const UNDATED: i64 = i64::MIN;

/// Builds the schema and its field handles.
#[must_use]
pub fn build() -> (Schema, Fields) {
    let mut b = Schema::builder();
    let int = NumericOptions::default().set_indexed().set_fast();
    let fast_only = NumericOptions::default().set_fast();
    let text = |record| {
        TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer(SCENE_ANALYZER)
                // Results are ordered by fields, never by relevance: no field norms needed.
                .set_fieldnorms(false)
                .set_index_option(record),
        )
    };
    let keyword = STRING | FAST;
    let fields = Fields {
        id: b.add_i64_field("id", int.clone()),
        version: b.add_u64_field("version", fast_only.clone()),
        title: b.add_text_field("title", text(IndexRecordOption::WithFreqsAndPositions)),
        files: b.add_text_field("files", text(IndexRecordOption::Basic)),
        poster: b.add_text_field("poster", text(IndexRecordOption::Basic)),
        source_name: b.add_text_field("source_name", text(IndexRecordOption::Basic)),
        title_sort: b.add_bytes_field("title_sort", BytesOptions::default().set_fast()),
        cat: b.add_u64_field("cat", int.clone()),
        cat_parent: b.add_u64_field("cat_parent", int.clone()),
        posted: b.add_i64_field("posted", int.clone()),
        added: b.add_i64_field("added", fast_only),
        size: b.add_u64_field("size", int.clone()),
        flag: b.add_text_field("flag", STRING),
        family: b.add_text_field("family", keyword.clone()),
        resolution: b.add_text_field("resolution", keyword.clone()),
        source: b.add_text_field("source", keyword.clone()),
        year: b.add_u64_field("year", int.clone()),
        group: b.add_text_field("group", keyword.clone()),
        season: b.add_u64_field("season", int.clone()),
        episode: b.add_u64_field("episode", int.clone()),
        series_key: b.add_text_field("series_key", keyword.clone()),
        label: b.add_text_field("label", keyword),
        added_by: b.add_u64_field("added_by", int),
    };
    (b.build(), fields)
}

/// Fast-field column names read by the collectors (kept next to the schema so a rename breaks here).
pub mod col {
    /// `id` column.
    pub const ID: &str = "id";
    /// `version` column.
    pub const VERSION: &str = "version";
    /// `posted` column.
    pub const POSTED: &str = "posted";
    /// `size` column.
    pub const SIZE: &str = "size";
    /// `title_sort` column.
    pub const TITLE_SORT: &str = "title_sort";
    /// `cat` column.
    pub const CAT: &str = "cat";
    /// `cat_parent` column.
    pub const CAT_PARENT: &str = "cat_parent";
}
