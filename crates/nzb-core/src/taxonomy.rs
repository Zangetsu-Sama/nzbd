//! Category taxonomy and slug allowlist (`config/categories.toml`, `PARSER_SPEC` §Taxonomy).
//!
//! The file is embedded at build time and is the single source of truth: nzb-store seeds the
//! `category` table from it and `nzbd categories` prints it. Hints from the outside world
//! (`X-Category`, upload dropdown, watch sub-folder) and `<meta type="category">` values are
//! hostile; they are only ever *compared* against this allowlist and never used as paths.

use std::collections::HashMap;

use serde::Deserialize;

/// The embedded default taxonomy.
const BUILTIN: &str = include_str!("../../../config/categories.toml");

/// Largest accepted taxonomy file.
pub const MAX_TAXONOMY_BYTES: usize = 64 * 1024;
/// Most categories accepted.
pub const MAX_CATEGORIES: usize = 256;
const MAX_SLUG_BYTES: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_DIAGNOSTIC_CHARS: usize = 300;
/// Id of the fallback category (`Other/Misc`); it must exist in every taxonomy.
pub const FALLBACK_CATEGORY: u16 = 8010;
/// Id of the top-level `XXX` category (the one `ui.show_xxx` hides together with its children).
pub const XXX_CATEGORY: u16 = 6000;

/// Error loading or validating a taxonomy file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TaxonomyError {
    /// The TOML did not parse into the expected shape.
    #[error("taxonomy syntax: {0}")]
    Syntax(String),
    /// The TOML parsed but a value is not acceptable.
    #[error("taxonomy invalid: {0}")]
    Invalid(String),
}

fn invalid(msg: &str) -> TaxonomyError {
    TaxonomyError::Invalid(msg.to_owned())
}

/// One category.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    /// Numeric id (Torznab style).
    pub id: u16,
    /// Parent id; parents are declared before their children.
    #[serde(default)]
    pub parent: Option<u16>,
    /// Lowercase slug (`tv.hd`); `[a-z0-9.]`, unique.
    pub slug: String,
    /// Display name (`TV/HD`), stored in the `category` table.
    pub name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    category: Vec<Category>,
}

/// Validated category list with O(1) lookup by id and slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taxonomy {
    entries: Vec<Category>,
    by_id: HashMap<u16, usize>,
    by_slug: HashMap<String, usize>,
}

impl Taxonomy {
    /// Loads the taxonomy embedded in the binary.
    ///
    /// # Errors
    /// Only if the embedded file is broken (covered by a unit test).
    pub fn builtin() -> Result<Self, TaxonomyError> {
        Self::from_toml_str(BUILTIN)
    }

    /// Parses and validates a taxonomy file.
    ///
    /// # Errors
    /// [`TaxonomyError`] on syntax errors, duplicate ids or slugs, a parent that is unknown or
    /// declared later, malformed slugs or names, too many entries, or a missing fallback id.
    pub fn from_toml_str(src: &str) -> Result<Self, TaxonomyError> {
        if src.len() > MAX_TAXONOMY_BYTES {
            return Err(invalid("taxonomy file too large"));
        }
        let raw: Raw = toml::from_str(src).map_err(|e| {
            TaxonomyError::Syntax(e.to_string().chars().take(MAX_DIAGNOSTIC_CHARS).collect())
        })?;
        if raw.category.len() > MAX_CATEGORIES {
            return Err(invalid("too many categories"));
        }
        let mut by_id = HashMap::new();
        let mut by_slug = HashMap::new();
        for (i, c) in raw.category.iter().enumerate() {
            if c.id == 0 {
                return Err(invalid("id 0 is reserved"));
            }
            if !valid_slug(&c.slug) {
                return Err(invalid("slug must be 1..=32 chars of [a-z0-9.]"));
            }
            // An all-digit slug would be ambiguous with numeric ids.
            if c.slug.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("slug must not be numeric"));
            }
            if c.name.is_empty()
                || c.name.len() > MAX_NAME_BYTES
                || crate::sanitize_text(&c.name, MAX_NAME_BYTES) != c.name
            {
                return Err(invalid("category name empty, too long or not clean text"));
            }
            if let Some(p) = c.parent
                && !by_id.contains_key(&p)
            {
                return Err(invalid("parent unknown or declared after its child"));
            }
            if by_id.insert(c.id, i).is_some() {
                return Err(invalid("duplicate category id"));
            }
            if by_slug.insert(c.slug.clone(), i).is_some() {
                return Err(invalid("duplicate category slug"));
            }
        }
        if !by_id.contains_key(&FALLBACK_CATEGORY) {
            return Err(invalid("fallback category 8010 missing"));
        }
        Ok(Self {
            entries: raw.category,
            by_id,
            by_slug,
        })
    }

    /// All categories, parents before children, in file order.
    #[must_use]
    pub fn entries(&self) -> &[Category] {
        &self.entries
    }

    /// Number of categories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always false for a validated taxonomy (the fallback must exist).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Categories in the order every UI list shows them: tree (file) order, except that the XXX category and its
    /// descendants come last (T146). The one place that rule lives; menus, dropdowns and stats all call it.
    #[must_use]
    pub fn display_order(&self) -> Vec<&Category> {
        let xxx = self.subtree_ids(XXX_CATEGORY);
        let (last, first): (Vec<&Category>, Vec<&Category>) =
            self.entries.iter().partition(|c| xxx.contains(&c.id));
        first.into_iter().chain(last).collect()
    }

    /// Looks a category up by id.
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&Category> {
        self.by_id.get(&id).and_then(|&i| self.entries.get(i))
    }

    /// True if `id` is in the taxonomy.
    #[must_use]
    pub fn contains(&self, id: u16) -> bool {
        self.by_id.contains_key(&id)
    }

    /// `id` together with every transitive child of it, in file order; empty when `id` is not
    /// in the taxonomy. Used to derive the set of categories a display rule hides.
    #[must_use]
    pub fn subtree_ids(&self, id: u16) -> Vec<u16> {
        if !self.contains(id) {
            return Vec::new();
        }
        let mut out = vec![id];
        // Parents are declared before their children (validated), so one pass is enough.
        for c in &self.entries {
            if let Some(p) = c.parent
                && out.contains(&p)
                && !out.contains(&c.id)
            {
                out.push(c.id);
            }
        }
        out
    }

    /// Resolves an untrusted hint: a decimal id (`5040`: digits only, no sign, no leading zero,
    /// no whitespace) or an exact slug (`tv.hd`). Anything else is `None`. The input is never
    /// echoed or used as a path.
    #[must_use]
    pub fn resolve(&self, hint: &str) -> Option<u16> {
        if hint.is_empty() || hint.len() > MAX_SLUG_BYTES {
            return None;
        }
        if hint.bytes().all(|b| b.is_ascii_digit()) {
            if hint.len() > 5 || hint.starts_with('0') {
                return None;
            }
            let id: u16 = hint.parse().ok()?;
            return self.contains(id).then_some(id);
        }
        self.by_slug
            .get(hint)
            .and_then(|&i| self.entries.get(i))
            .map(|c| c.id)
    }

    /// Like [`Self::resolve`] but trims and ignores ASCII case; used for `<meta type="category">`
    /// values, which real NZBs write loosely (`"Movies"`).
    #[must_use]
    pub fn resolve_loose(&self, value: &str) -> Option<u16> {
        self.resolve(&value.trim().to_ascii_lowercase())
    }
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SLUG_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn t() -> Taxonomy {
        Taxonomy::builtin().unwrap()
    }

    #[test]
    fn subtree_ids_covers_parent_and_transitive_children() {
        let src = r#"
[[category]]
id = 6000
slug = "xxx"
name = "XXX"
[[category]]
id = 6010
parent = 6000
slug = "xxx.a"
name = "XXX/A"
[[category]]
id = 6011
parent = 6010
slug = "xxx.a.b"
name = "XXX/A/B"
[[category]]
id = 7000
slug = "books"
name = "Books"
[[category]]
id = 8010
parent = 7000
slug = "other.misc"
name = "Other/Misc"
"#;
        let t = Taxonomy::from_toml_str(src).unwrap();
        assert_eq!(t.subtree_ids(XXX_CATEGORY), vec![6000, 6010, 6011]);
        assert_eq!(t.subtree_ids(7000), vec![7000, 8010]);
        assert_eq!(t.subtree_ids(9999), Vec::<u16>::new());
        let b = Taxonomy::builtin().unwrap();
        assert_eq!(b.get(XXX_CATEGORY).unwrap().slug, "xxx");
        assert!(b.subtree_ids(XXX_CATEGORY).contains(&XXX_CATEGORY));
    }

    #[test]
    fn display_order_puts_xxx_last_and_keeps_the_rest() {
        let t = t();
        let order: Vec<u16> = t.display_order().iter().map(|c| c.id).collect();
        assert_eq!(order.len(), t.len());
        assert_eq!(order.last(), Some(&XXX_CATEGORY));
        let rest: Vec<u16> = t
            .entries()
            .iter()
            .map(|c| c.id)
            .filter(|i| *i != XXX_CATEGORY)
            .collect();
        assert_eq!(order.get(..rest.len()), Some(rest.as_slice()));
    }

    #[test]
    fn new_categories_have_unique_ids_and_existing_parents() {
        let t = t();
        for (id, parent, slug) in [
            (1010, 1000, "console.microsoft"),
            (1020, 1000, "console.nintendo"),
            (1030, 1000, "console.sony"),
            (4010, 4000, "pc.appz"),
            (4020, 4000, "pc.games"),
            (7040, 7000, "books.mangas"),
            (4510, 4500, "mac.macappz"),
            (4520, 4500, "mac.macgames"),
        ] {
            let c = t.get(id).unwrap();
            assert_eq!((c.parent, c.slug.as_str()), (Some(parent), slug));
        }
        for (slug, id) in [
            ("audio.mp3", 3010),
            ("audio.audiobook", 3030),
            ("audio.lossless", 3040),
        ] {
            assert_eq!(t.resolve(slug), Some(id));
        }
    }

    #[test]
    fn builtin_loads_and_matches_spec_table() {
        let t = t();
        assert_eq!(t.len(), 36);
        for (slug, id) in [
            ("console", 1000),
            ("movies", 2000),
            ("movies.uhd", 2045),
            ("audio.lossless", 3040),
            ("console.sony", 1030),
            ("pc", 4000),
            ("pc.appz", 4010),
            ("pc.games", 4020),
            ("tv.hd", 5040),
            ("tv.sport", 5060),
            ("anime", 5070),
            ("tv.documentary", 5080),
            ("xxx", 6000),
            ("books.comics", 7030),
            ("other", 8000),
            ("other.misc", 8010),
        ] {
            assert_eq!(t.resolve(slug), Some(id), "{slug}");
            assert_eq!(t.resolve(&id.to_string()), Some(id));
        }
        assert_eq!(t.get(5040).map(|c| c.name.as_str()), Some("TV/HD"));
        assert_eq!(t.get(5040).and_then(|c| c.parent), Some(5000));
    }

    #[test]
    fn sec_hint_resolution_is_exact() {
        let t = t();
        let long = "a".repeat(10_000);
        for bad in [
            "",
            " ",
            "5040 ",
            " tv.hd",
            "TV.HD",
            "Tv.hd",
            "05040",
            "+5040",
            "-5040",
            "5041",
            "0",
            "65536",
            "99999999999999999999",
            "tv.hd\0",
            "tv.hd\n",
            "../etc/passwd",
            "tv/hd",
            "tv.hd;",
            "%35040",
            "5040.0",
            "０５０４０",
            "tv..hd",
            long.as_str(),
        ] {
            assert_eq!(t.resolve(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn loose_resolution_for_meta() {
        let t = t();
        assert_eq!(t.resolve_loose("  Movies "), Some(2000));
        assert_eq!(t.resolve_loose("TV.HD"), Some(5040));
        assert_eq!(t.resolve_loose("TV > HD"), None);
    }

    #[test]
    fn validation_rejects_bad_files() {
        let ok = "[[category]]\nid = 8010\nslug = \"other.misc\"\nname = \"Other/Misc\"\n";
        assert!(Taxonomy::from_toml_str(ok).is_ok());
        let extra = |body: &str| format!("{ok}[[category]]\n{body}");
        let cases = [
            (
                "[[category]]\nid = 1\nslug = \"a\"\nname = \"A\"\n".to_owned(),
                "no fallback",
            ),
            (format!("{ok}{ok}"), "duplicate id"),
            (
                extra("id = 9\nslug = \"other.misc\"\nname = \"X\"\n"),
                "duplicate slug",
            ),
            (extra("id = 9\nslug = \"Up\"\nname = \"X\"\n"), "bad slug"),
            (
                extra("id = 9\nslug = \"123\"\nname = \"X\"\n"),
                "numeric slug",
            ),
            (
                extra("id = 9\nparent = 77\nslug = \"x\"\nname = \"X\"\n"),
                "unknown parent",
            ),
            (
                format!("[[category]]\nid = 9\nparent = 8010\nslug = \"x\"\nname = \"X\"\n{ok}"),
                "parent after child",
            ),
            (extra("id = 0\nslug = \"x\"\nname = \"X\"\n"), "id 0"),
            (
                extra("id = 9\nslug = \"x\"\nname = \"X\\u202e\"\n"),
                "bidi in name",
            ),
            (
                extra("id = 9\nslug = \"x\"\nname = \"X\"\nextra = 1\n"),
                "unknown key",
            ),
            ("not toml [".to_owned(), "syntax"),
        ];
        for (src, why) in cases {
            assert!(Taxonomy::from_toml_str(&src).is_err(), "{why}");
        }
        assert!(Taxonomy::from_toml_str(&" ".repeat(MAX_TAXONOMY_BYTES + 1)).is_err());
    }
}
