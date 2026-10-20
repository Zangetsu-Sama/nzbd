//! Per-account preferences (T120, `DATA_MODEL` v3 3.2 `user_pref`): "Hide XXX for me" and the theme.
//!
//! One row per account, absent row = defaults. The row is read by `session_actor` in the same statement as the
//! session and the account (LEFT JOIN), so a page pays no extra query for it. Writes are the account's own
//! (`set_user_prefs` takes no target id: the actor is the target), re-validate the actor inside the transaction and
//! write one audit row that names only the changed keys (`pref_change keys=hide_xxx,theme`), never the values.
//!
//! The preference is a display rule within one shared library (SEC-090): it can only ADD the XXX tree to the
//! instance's exclusions; `ui.show_xxx = false` wins whatever the preference says.

//! Account-id mutation methods are for trusted internal callers; HTTP handlers use the `*_as`
//! methods, which bind the transaction to the authenticated session as well as its account.

use sqlx::Row;

use crate::account::{
    AccountActor, AuditActor, Role, require_actor, require_session_actor, write_audit,
};
use crate::{SqliteDb, StoreError};

/// Display theme of the web UI (`user_pref.theme`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// Follow the operating system (`prefers-color-scheme`); the default.
    #[default]
    Auto,
    /// Always the light palette.
    Light,
    /// Always the dark palette.
    Dark,
}

impl Theme {
    /// Stable lowercase name (database value, form value, `data-theme` attribute value).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// Parses the stable name (exact, lowercase).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

/// Defines a page-size newtype over a fixed allowlist (T133). A value outside the list cannot be built, so a page size
/// that reaches a query is always one of the listed numbers (never a raw number from a request).
macro_rules! page_size {
    ($(#[$doc:meta])* $name:ident, [$($n:literal),+], default = $d:literal, column = $col:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(u32);

        impl $name {
            /// The allowlist, ascending (the `CHECK` of the column holds the same numbers).
            pub const CHOICES: &'static [u32] = &[$($n),+];
            /// The size used when the account made no choice.
            pub const DEFAULT: Self = Self($d);

            /// The size `n` when it is on the allowlist.
            #[must_use]
            pub fn new(n: u32) -> Option<Self> {
                Self::CHOICES.contains(&n).then_some(Self(n))
            }

            /// Parses a form value: exactly the decimal text of an allowlisted size (no sign, no leading zero, no
            /// whitespace); anything else is `None`.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                Self::CHOICES
                    .iter()
                    .find(|n| n.to_string() == s)
                    .map(|n| Self(*n))
            }

            /// The number of rows per page.
            #[must_use]
            pub const fn get(self) -> u32 {
                self.0
            }

            /// Builds the size from a stored column value.
            ///
            /// # Errors
            /// [`StoreError::OutOfRange`] for a value the `CHECK` constraint should have refused.
            pub(crate) fn from_column(v: i64) -> Result<Self, StoreError> {
                u32::try_from(v)
                    .ok()
                    .and_then(Self::new)
                    .ok_or(StoreError::OutOfRange($col))
            }

            /// The value as stored.
            pub(crate) fn column(self) -> i64 {
                i64::from(self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::DEFAULT
            }
        }
    };
}

page_size!(
    /// Rows per page of the release list (`user_pref.page_size_releases`): 25, 50 (default) or 100. The largest is
    /// the bulk-action maximum ([`crate::MAX_BULK_IDS`]), so "select all on this page" never exceeds what a bulk
    /// action accepts.
    ReleasePageSize,
    [25, 50, 100],
    default = 50,
    column = "user_pref.page_size_releases"
);

page_size!(
    /// Rows per page of a release's files table (`user_pref.page_size_files`): 50, 100 (default), 250 or 500.
    FilePageSize,
    [50, 100, 250, 500],
    default = 100,
    column = "user_pref.page_size_files"
);

/// The preferences of one account (defaults when the account has no `user_pref` row).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserPrefs {
    /// Hide the XXX category and its children from every user-facing view of THIS account.
    pub hide_xxx: bool,
    /// Theme of the web UI.
    pub theme: Theme,
    /// Rows per page of the release list (T133).
    pub page_size_releases: ReleasePageSize,
    /// Rows per page of a release's files table (T133).
    pub page_size_files: FilePageSize,
}

/// The `user_pref` columns of one row as read, nullable for the LEFT JOIN (`None` = no row = defaults).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PrefColumns<'a> {
    pub(crate) hide_xxx: Option<bool>,
    pub(crate) theme: Option<&'a str>,
    pub(crate) page_size_releases: Option<i64>,
    pub(crate) page_size_files: Option<i64>,
}

impl UserPrefs {
    /// Builds the preferences from the nullable LEFT JOIN columns (`None` = no row = defaults).
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a theme or page size the CHECK constraints should have refused.
    pub(crate) fn from_columns(c: PrefColumns<'_>) -> Result<Self, StoreError> {
        let theme = match c.theme {
            None => Theme::Auto,
            Some(t) => Theme::parse(t).ok_or(StoreError::OutOfRange("user_pref.theme"))?,
        };
        Ok(Self {
            hide_xxx: c.hide_xxx.unwrap_or(false),
            theme,
            page_size_releases: c
                .page_size_releases
                .map(ReleasePageSize::from_column)
                .transpose()?
                .unwrap_or_default(),
            page_size_files: c
                .page_size_files
                .map(FilePageSize::from_column)
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// The audit detail for a change from `old` to `self`: the changed key names only, `None` when nothing changed.
    pub(crate) fn change_detail(self, old: Self) -> Option<String> {
        let mut keys = Vec::new();
        if self.hide_xxx != old.hide_xxx {
            keys.push("hide_xxx");
        }
        if self.theme != old.theme {
            keys.push("theme");
        }
        if self.page_size_releases != old.page_size_releases {
            keys.push("page_size_releases");
        }
        if self.page_size_files != old.page_size_files {
            keys.push("page_size_files");
        }
        (!keys.is_empty()).then(|| format!("keys={}", keys.join(",")))
    }
}

/// Audit event of a preference change (detail `keys=<changed key names>`, no values).
pub const PREF_CHANGE_EVENT: &str = "pref_change";

/// One page size to store (T133, `POST /page-size`): which list, with an allowlisted value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    /// The release list (`user_pref.page_size_releases`).
    Releases(ReleasePageSize),
    /// A release's files table (`user_pref.page_size_files`).
    Files(FilePageSize),
}

impl PageSize {
    /// The preferences `old` with only this page size replaced.
    #[must_use]
    pub const fn applied_to(self, old: UserPrefs) -> UserPrefs {
        let mut p = old;
        match self {
            Self::Releases(n) => p.page_size_releases = n,
            Self::Files(n) => p.page_size_files = n,
        }
        p
    }
}

/// A partial change of the preferences (T133 review 48 L1): only the `Some` fields are applied, to the row as it is
/// inside the write transaction, so two concurrent saves of different fields never revert each other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrefsPatch {
    /// New "Hide XXX for me", when changed.
    pub hide_xxx: Option<bool>,
    /// New theme, when changed.
    pub theme: Option<Theme>,
    /// New release page size, when changed.
    pub page_size_releases: Option<ReleasePageSize>,
    /// New files page size, when changed.
    pub page_size_files: Option<FilePageSize>,
}

impl PrefsPatch {
    /// The patch that turns `old` into `new`: exactly the fields that differ.
    #[must_use]
    pub fn between(old: UserPrefs, new: UserPrefs) -> Self {
        Self {
            hide_xxx: (old.hide_xxx != new.hide_xxx).then_some(new.hide_xxx),
            theme: (old.theme != new.theme).then_some(new.theme),
            page_size_releases: (old.page_size_releases != new.page_size_releases)
                .then_some(new.page_size_releases),
            page_size_files: (old.page_size_files != new.page_size_files)
                .then_some(new.page_size_files),
        }
    }

    /// The patch that sets every field to `prefs` (a whole-row save).
    #[must_use]
    pub const fn all(prefs: UserPrefs) -> Self {
        Self {
            hide_xxx: Some(prefs.hide_xxx),
            theme: Some(prefs.theme),
            page_size_releases: Some(prefs.page_size_releases),
            page_size_files: Some(prefs.page_size_files),
        }
    }

    /// `current` with the `Some` fields of this patch applied.
    #[must_use]
    pub fn applied_to(self, current: UserPrefs) -> UserPrefs {
        UserPrefs {
            hide_xxx: self.hide_xxx.unwrap_or(current.hide_xxx),
            theme: self.theme.unwrap_or(current.theme),
            page_size_releases: self
                .page_size_releases
                .unwrap_or(current.page_size_releases),
            page_size_files: self.page_size_files.unwrap_or(current.page_size_files),
        }
    }
}

/// Decodes one optional SQLite `user_pref` row (`SELECT hide_xxx, theme, page_size_releases, page_size_files`).
fn sqlite_prefs(row: Option<sqlx::sqlite::SqliteRow>) -> Result<UserPrefs, StoreError> {
    let Some(r) = row else {
        return Ok(UserPrefs::default());
    };
    let theme: String = r.try_get("theme")?;
    UserPrefs::from_columns(PrefColumns {
        hide_xxx: Some(r.try_get::<i64, _>("hide_xxx")? != 0),
        theme: Some(&theme),
        page_size_releases: Some(r.try_get("page_size_releases")?),
        page_size_files: Some(r.try_get("page_size_files")?),
    })
}

/// Single-column upserts of one page size (T133 review 48 L1); the column is chosen by the [`PageSize`] variant, never
/// by request text. The other columns keep their stored value (or the defaults for a new row).
const SQLITE_SET_RELEASES: &str = "INSERT INTO user_pref (account_id, page_size_releases, updated_at) VALUES (?1, ?2, ?3) \
     ON CONFLICT (account_id) DO UPDATE SET page_size_releases = excluded.page_size_releases, \
     updated_at = excluded.updated_at";
const SQLITE_SET_FILES: &str = "INSERT INTO user_pref (account_id, page_size_files, updated_at) VALUES (?1, ?2, ?3) \
     ON CONFLICT (account_id) DO UPDATE SET page_size_files = excluded.page_size_files, \
     updated_at = excluded.updated_at";

impl SqliteDb {
    /// The stored preferences of `account_id` (defaults when there is no row).
    ///
    /// # Errors
    /// Database failure.
    pub async fn user_prefs(&self, account_id: i64) -> Result<UserPrefs, StoreError> {
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = ?1",
        )
        .bind(account_id)
        .fetch_optional(self.writer())
        .await?;
        sqlite_prefs(row)
    }

    /// Stores the caller's OWN preferences (any role; the actor is the target). The actor is re-validated in the
    /// transaction (live, enabled); a change writes `pref_change keys=...` (key names only). Returns whether
    /// anything changed (no change: no write, no audit row).
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn set_user_prefs(
        &self,
        actor_id: i64,
        prefs: UserPrefs,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs(actor_id, PrefsPatch::all(prefs), ip, now)
            .await
    }

    /// Applies `patch` to the caller's OWN preferences as stored inside the write transaction (`BEGIN IMMEDIATE`), so
    /// a concurrent change of another field is kept (T133 review 48 L1). Same rules and audit as
    /// [`SqliteDb::set_user_prefs`]; returns whether anything changed.
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn patch_user_prefs(
        &self,
        actor_id: i64,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs_inner(actor_id, None, patch, ip, now)
            .await
    }

    /// Session-bound form of [`Self::patch_user_prefs`]; rechecks the session in the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn patch_user_prefs_as(
        &self,
        actor: &AccountActor,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.patch_user_prefs_inner(actor.user_id, Some(actor), patch, ip, now)
            .await
    }

    async fn patch_user_prefs_inner(
        &self,
        actor_id: i64,
        actor: Option<&AccountActor>,
        patch: PrefsPatch,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, actor_id, Role::Viewer).await?,
        };
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = ?1",
        )
        .bind(s.id)
        .fetch_optional(&mut *tx)
        .await?;
        let old = sqlite_prefs(row)?;
        let prefs = patch.applied_to(old);
        let Some(detail) = prefs.change_detail(old) else {
            return Ok(false);
        };
        sqlx::query(
            "INSERT INTO user_pref (account_id, hide_xxx, theme, page_size_releases, page_size_files, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (account_id) DO UPDATE SET hide_xxx = excluded.hide_xxx, theme = excluded.theme, \
             page_size_releases = excluded.page_size_releases, page_size_files = excluded.page_size_files, \
             updated_at = excluded.updated_at",
        )
        .bind(s.id)
        .bind(i64::from(prefs.hide_xxx))
        .bind(prefs.theme.as_str())
        .bind(prefs.page_size_releases.column())
        .bind(prefs.page_size_files.column())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let who = AuditActor::account(s.id, s.role, &s.username);
        write_audit(
            &mut tx,
            &who,
            now,
            PREF_CHANGE_EVENT,
            Some(&detail),
            ip,
            Some(s.id),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Stores ONE page size of the caller's own preferences (T133 `POST /page-size`), writing only that column, so it
    /// never reverts another preference saved at the same time. Audited like any preference change; returns whether
    /// the value changed.
    ///
    /// # Errors
    /// [`crate::AccountError::Forbidden`] for a disabled or deleted actor; database failure.
    pub async fn set_page_size(
        &self,
        actor_id: i64,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.set_page_size_inner(actor_id, None, size, ip, now)
            .await
    }

    /// Session-bound form of [`Self::set_page_size`]; rechecks the session in the write transaction.
    ///
    /// # Errors
    /// As the trusted account-id form, plus [`crate::AccountError::Forbidden`] for a revoked, expired,
    /// pending, or foreign session. `now` is the caller's clock at the start of this write attempt.
    pub async fn set_page_size_as(
        &self,
        actor: &AccountActor,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.set_page_size_inner(actor.user_id, Some(actor), size, ip, now)
            .await
    }

    async fn set_page_size_inner(
        &self,
        actor_id: i64,
        actor: Option<&AccountActor>,
        size: PageSize,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let s = match actor {
            Some(a) => require_session_actor(&mut tx, a, Role::Viewer, now).await?,
            None => require_actor(&mut tx, actor_id, Role::Viewer).await?,
        };
        let row = sqlx::query(
            "SELECT hide_xxx, theme, page_size_releases, page_size_files FROM user_pref WHERE account_id = ?1",
        )
        .bind(s.id)
        .fetch_optional(&mut *tx)
        .await?;
        let old = sqlite_prefs(row)?;
        let Some(detail) = size.applied_to(old).change_detail(old) else {
            return Ok(false);
        };
        let query = match size {
            PageSize::Releases(n) => sqlx::query(SQLITE_SET_RELEASES).bind(s.id).bind(n.column()),
            PageSize::Files(n) => sqlx::query(SQLITE_SET_FILES).bind(s.id).bind(n.column()),
        };
        query.bind(now).execute(&mut *tx).await?;
        let who = AuditActor::account(s.id, s.role, &s.username);
        write_audit(
            &mut tx,
            &who,
            now,
            PREF_CHANGE_EVENT,
            Some(&detail),
            ip,
            Some(s.id),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_names_round_trip_and_unknown_is_refused() {
        for t in [Theme::Auto, Theme::Light, Theme::Dark] {
            assert_eq!(Theme::parse(t.as_str()), Some(t));
        }
        for bad in ["", "Auto", "DARK", "system", "dark "] {
            assert_eq!(Theme::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn change_detail_names_keys_only() {
        let old = UserPrefs::default();
        assert_eq!(old.change_detail(old), None);
        let both = UserPrefs {
            hide_xxx: true,
            theme: Theme::Dark,
            ..old
        };
        assert_eq!(
            both.change_detail(old).as_deref(),
            Some("keys=hide_xxx,theme")
        );
        let theme = UserPrefs {
            theme: Theme::Light,
            ..old
        };
        assert_eq!(theme.change_detail(old).as_deref(), Some("keys=theme"));
        let sizes = UserPrefs {
            page_size_releases: ReleasePageSize::new(100).unwrap(),
            page_size_files: FilePageSize::new(500).unwrap(),
            ..old
        };
        assert_eq!(
            sizes.change_detail(old).as_deref(),
            Some("keys=page_size_releases,page_size_files")
        );
    }

    #[test]
    fn t133_page_sizes_are_a_fixed_allowlist() {
        assert_eq!(ReleasePageSize::default().get(), 50);
        assert_eq!(FilePageSize::default().get(), 100);
        assert_eq!(ReleasePageSize::CHOICES, &[25, 50, 100]);
        assert_eq!(FilePageSize::CHOICES, &[50, 100, 250, 500]);
        // The largest release page is the bulk maximum: select-all can never exceed it.
        assert_eq!(
            ReleasePageSize::CHOICES.last().copied(),
            u32::try_from(crate::MAX_BULK_IDS).ok()
        );
        for n in ReleasePageSize::CHOICES {
            assert_eq!(ReleasePageSize::parse(&n.to_string()).unwrap().get(), *n);
        }
        for n in FilePageSize::CHOICES {
            assert_eq!(FilePageSize::parse(&n.to_string()).unwrap().get(), *n);
        }
        for bad in [
            "",
            "0",
            "1",
            "24",
            "26",
            "050",
            "+50",
            "-50",
            " 50",
            "50 ",
            "5e1",
            "1000",
            "250",
            "500",
            "99999999999999999999",
        ] {
            assert_eq!(ReleasePageSize::parse(bad), None, "{bad:?}");
        }
        for bad in ["", "25", "0100", "100.0", "1000", "-100", "١٠٠"] {
            assert_eq!(FilePageSize::parse(bad), None, "{bad:?}");
        }
        assert!(ReleasePageSize::from_column(75).is_err());
        assert!(FilePageSize::from_column(-1).is_err());
        assert!(FilePageSize::from_column(i64::MAX).is_err());
        let none = UserPrefs::from_columns(PrefColumns::default()).unwrap();
        assert_eq!(none, UserPrefs::default());
    }
}
