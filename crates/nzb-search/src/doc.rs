//! The indexer's document builder (replaces the 2.x `SearchDoc` for v3, ARCHITECTURE 3.5 item 4).
//!
//! An [`IndexDoc`] is the current state of one release as read from the source of truth. Every string
//! in it is already sanitized NZB display data; here it is only capped and analyzed, never interpreted.

use nzb_core::ReleaseFlags;
use nzb_store::ReleaseRow;
use tantivy::TantivyDocument;

use crate::analyzer::{
    MAX_FILES_BYTES, MAX_POSTER_BYTES, MAX_SOURCE_NAME_BYTES, MAX_TITLE_BYTES, cap_bytes, nocase,
};
use crate::schema::{Fields, UNDATED};

/// Longest raw keyword value indexed (family, resolution, source, group, label, series key), bytes.
pub const MAX_KEYWORD_BYTES: usize = 128;

/// Current state of one release, as the indexer writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDoc {
    /// `release.id` (> 0).
    pub id: i64,
    /// `release.index_version`.
    pub version: u64,
    /// Display title.
    pub title: String,
    /// File names, space separated (capped at [`MAX_FILES_BYTES`] when indexed).
    pub files: String,
    /// Poster (empty when unknown).
    pub poster: String,
    /// `release.source_name`, the sanitized `.nzb` file name as stored (empty when unknown). Indexed as text
    /// without its `.nzb` extension, together with [`IndexDoc::group`] (T131).
    pub source_name: String,
    /// Category id.
    pub category_id: u32,
    /// Direct parent of the category (the category itself when it has none).
    pub category_parent: u32,
    /// Posted date, `None` = undated.
    pub posted_at: Option<i64>,
    /// Ingest time.
    pub ingested_at: i64,
    /// Total bytes.
    pub total_bytes: u64,
    /// Release flags.
    pub flags: ReleaseFlags,
    /// Scene family.
    pub family: Option<String>,
    /// Scene resolution.
    pub resolution: Option<String>,
    /// Scene source.
    pub source: Option<String>,
    /// Scene year.
    pub year: Option<u32>,
    /// Release group.
    pub group: Option<String>,
    /// Scene season.
    pub season: Option<u32>,
    /// Scene episode.
    pub episode: Option<u32>,
    /// Normalized scene title for grouped views (`release.scene_title`, v3).
    pub series_key: Option<String>,
    /// Source label.
    pub source_label: Option<String>,
    /// Uploader account id.
    pub added_by: Option<i64>,
}

impl IndexDoc {
    /// The document of a hydrated row: `files` are its file names, `category_parent` comes from the
    /// taxonomy (or the `category` table) and `version`/`added_by` from columns the 2.x row lacks.
    #[must_use]
    pub fn from_row(
        row: &ReleaseRow,
        category_parent: u32,
        files: &str,
        version: u64,
        added_by: Option<i64>,
    ) -> Self {
        Self {
            id: row.id,
            version,
            title: row.title.clone(),
            files: files.to_owned(),
            poster: row.poster.clone().unwrap_or_default(),
            source_name: row.source_name.clone().unwrap_or_default(),
            category_id: row.category_id,
            category_parent,
            posted_at: row.posted_at,
            ingested_at: row.ingested_at,
            total_bytes: row.total_bytes,
            // T148: a manual category is not "uncategorized"; mask the stale bit of rows overridden
            // before the store cleared it (their documents refresh on the next reindex or edit).
            flags: if row.category_overridden {
                ReleaseFlags::from_bits_truncate(
                    row.flags.bits() & !ReleaseFlags::UNCATEGORIZED.bits(),
                )
            } else {
                row.flags
            },
            family: row.scene.family.clone(),
            resolution: row.scene.resolution.clone(),
            source: row.scene.source.clone(),
            year: row.scene.year,
            group: row.scene.group.clone(),
            season: row.scene.season,
            episode: row.scene.episode,
            series_key: None,
            source_label: row.source_label.clone(),
            added_by,
        }
    }

    /// The Tantivy document. Only fails for values the database CHECKs exclude (id or version not
    /// positive): such a release is retried and then quarantined by the indexer.
    ///
    /// # Errors
    /// [`DocError`].
    pub fn to_document(&self, f: &Fields) -> Result<TantivyDocument, DocError> {
        if self.id < 1 {
            return Err(DocError::BadId);
        }
        if self.version < 1 {
            return Err(DocError::BadVersion);
        }
        let mut d = TantivyDocument::default();
        d.add_i64(f.id, self.id);
        d.add_u64(f.version, self.version);
        d.add_text(f.title, cap_bytes(&self.title, MAX_TITLE_BYTES));
        d.add_text(f.files, cap_bytes(&self.files, MAX_FILES_BYTES));
        d.add_text(f.poster, cap_bytes(&self.poster, MAX_POSTER_BYTES));
        d.add_text(f.source_name, self.source_text());
        d.add_bytes(
            f.title_sort,
            nocase(cap_bytes(&self.title, MAX_TITLE_BYTES)).as_bytes(),
        );
        d.add_u64(f.cat, u64::from(self.category_id));
        d.add_u64(f.cat_parent, u64::from(self.category_parent));
        d.add_i64(
            f.posted,
            self.posted_at
                .map_or(UNDATED, |p| p.max(UNDATED.saturating_add(1))),
        );
        d.add_i64(f.added, self.ingested_at);
        d.add_u64(f.size, self.total_bytes);
        for t in flag_terms(self.flags) {
            d.add_text(f.flag, t);
        }
        let keyword = |d: &mut TantivyDocument, field, v: &Option<String>, fold: bool| {
            if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                let v = cap_bytes(v, MAX_KEYWORD_BYTES);
                if fold {
                    d.add_text(field, nocase(v));
                } else {
                    d.add_text(field, v);
                }
            }
        };
        keyword(&mut d, f.family, &self.family, false);
        keyword(&mut d, f.resolution, &self.resolution, false);
        keyword(&mut d, f.source, &self.source, false);
        keyword(&mut d, f.group, &self.group, true);
        keyword(&mut d, f.series_key, &self.series_key, true);
        keyword(&mut d, f.label, &self.source_label, true);
        if let Some(y) = self.year {
            d.add_u64(f.year, u64::from(y));
        }
        if let Some(s) = self.season {
            d.add_u64(f.season, u64::from(s));
        }
        if let Some(e) = self.episode {
            d.add_u64(f.episode, u64::from(e));
        }
        if let Some(a) = self.added_by.and_then(|a| u64::try_from(a).ok()) {
            d.add_u64(f.added_by, a);
        }
        Ok(d)
    }
}

impl IndexDoc {
    /// The `source_name` text: the file name without its `.nzb` extension(s), then the release group, capped at
    /// [`MAX_SOURCE_NAME_BYTES`]. The extension is dropped so `nzb` does not become a term of every release; the
    /// group is added because it is a keyword filter only and may be in neither the title nor the file names.
    #[must_use]
    pub fn source_text(&self) -> String {
        let mut text =
            strip_nzb_ext(cap_bytes(&self.source_name, MAX_SOURCE_NAME_BYTES)).to_owned();
        if let Some(g) = self.group.as_deref().filter(|g| !g.is_empty()) {
            text.push(' ');
            text.push_str(cap_bytes(g, MAX_KEYWORD_BYTES));
        }
        cap_bytes(&text, MAX_SOURCE_NAME_BYTES).to_owned()
    }
}

/// `name` without trailing `.nzb` extensions (ASCII case-insensitive, at most four: `x.nzb.nzb`).
fn strip_nzb_ext(name: &str) -> &str {
    const EXT: &str = ".nzb";
    let mut s = name;
    for _ in 0..4 {
        let Some(cut) = s.len().checked_sub(EXT.len()) else {
            break;
        };
        match (s.get(..cut), s.get(cut..)) {
            (Some(head), Some(tail)) if tail.eq_ignore_ascii_case(EXT) => s = head,
            _ => break,
        }
    }
    s
}

/// A document that cannot be built (the indexer quarantines its release after retries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DocError {
    /// Release id not positive.
    #[error("invalid release id")]
    BadId,
    /// `index_version` not positive (the column CHECK makes it impossible).
    #[error("invalid index version")]
    BadVersion,
}

/// Raw `flag` terms, one per known flag bit (stable names: they are index content).
const FLAG_NAMES: [(ReleaseFlags, &str); 10] = [
    (ReleaseFlags::OBFUSCATED, "obfuscated"),
    (ReleaseFlags::HAS_PAR2, "par2"),
    (ReleaseFlags::PAR2_BLOCKS, "par2_blocks"),
    (ReleaseFlags::INCOMPLETE, "incomplete"),
    (ReleaseFlags::DUPLICATE_SEGMENTS, "duplicate_segments"),
    (ReleaseFlags::HAS_EXECUTABLE, "executable"),
    (ReleaseFlags::MULTIVOLUME_GAP, "multivolume_gap"),
    (ReleaseFlags::PASSWORD_HINT, "password_hint"),
    (ReleaseFlags::NO_ARCHIVE_OR_VIDEO, "no_archive_or_video"),
    (ReleaseFlags::UNCATEGORIZED, "uncategorized"),
];

/// The `flag` terms of `flags` (unknown bits have none).
pub fn flag_terms(flags: ReleaseFlags) -> impl Iterator<Item = &'static str> {
    FLAG_NAMES
        .iter()
        .filter(move |(f, _)| flags.contains(*f))
        .map(|(_, n)| *n)
}

#[cfg(test)]
mod t148_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::testkit::{doc, row_of};

    /// T148: a manually categorised row is not indexed as `uncategorized`, the untouched fallback is.
    #[test]
    fn manual_category_masks_the_uncategorized_term() {
        let mut d = doc(1, "x");
        d.flags = ReleaseFlags::UNCATEGORIZED | ReleaseFlags::HAS_PAR2;
        let mut row = row_of(&d);
        let terms = |r: &ReleaseRow| -> Vec<&'static str> {
            flag_terms(IndexDoc::from_row(r, 8000, "", 1, None).flags).collect()
        };
        assert_eq!(terms(&row), vec!["par2", "uncategorized"]);
        row.category_overridden = true;
        assert_eq!(terms(&row), vec!["par2"]);
    }
}
