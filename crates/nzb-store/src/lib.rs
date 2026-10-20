//! `nzb-store` — the storage seam (SQLite and PostgreSQL repositories) and the NZB file store.
#![forbid(unsafe_code)]

/// Release columns read by the SQLite row decoder (a macro so complete statements stay compile-time literals in
/// `concat!`, SEC-088). Declared before the modules that use it (`macro_rules!` scoping is textual).
macro_rules! sqlite_release_cols {
    () => {
        "r.id, r.sha256, r.title, r.category_id, r.category_overridden, r.category_source, r.posted_at, \
         r.ingested_at, r.total_bytes, r.poster, r.file_count, r.segment_count, r.missing_segment_count, \
         r.par2_blocks, r.flags, r.nzb_size_bytes, r.source_name, r.source_label, r.origin, r.meta_json, \
         r.scene_family, r.scene_year, r.scene_season, r.scene_episode, r.scene_resolution, r.scene_source, \
         r.scene_codec, r.scene_group, r.scene_languages, r.scene_json"
    };
}

mod account;
mod anchor;
mod apikey;
mod attribution;
mod audit_chain;
mod auth;
mod backup;
mod backup_crypto;
mod blobs;
mod bulk;
pub mod busy;
mod db;
mod error;
mod fs_store;
mod health;
mod ingest_log;
mod invite;
mod mfa;
mod nfo;
pub mod pg;
mod pref;
mod profile;
mod release;
pub mod repo;
/// The repository traits in one import (`use nzb_store::prelude::*;`): method calls on [`Store`] need them in scope.
pub mod prelude {
    /// The test-only fixture methods (review 35 I3), present only with `cfg(test)` / `pg-test-support`.
    #[cfg(any(test, feature = "pg-test-support"))]
    pub use crate::repo::FixtureRepo as _;
    pub use crate::repo::{AccountRepo as _, AuditRepo as _, LibraryRepo as _, OpsRepo as _};
}
mod restore_finish;
mod retention;
mod saved_search;
mod search_index;
mod search_source;
pub mod store;
mod taxonomy;
#[cfg(any(test, feature = "pg-test-support"))]
pub mod test_backend;
mod throttle;
mod totp_rotate;
mod trash;
mod user;

pub use account::{
    AccountActor, AccountError, AccountPolicy, AccountRow, AuditActor, AuditEntry,
    DEFAULT_MAX_ACCOUNTS, FAILURE_EVENTS, GrantableRole, ID_EVENTS, MAX_DISPLAY_NAME_CHARS,
    NAME_EVENTS, NewAccount, RESERVED_ACTOR_NAMES, ReservedKind, ReservedLoginAccount, Role,
    TOMBSTONE_PASSWORD_HASH, check_login_name, default_handle, display_name_is_valid,
    is_reserved_actor_name, is_reserved_handle_form,
};
pub use anchor::{AnchorVerdict, DbAnchor, read_anchor, write_anchor};
pub use apikey::{
    Actor, ApiKeyAuth, ApiKeyRow, CreateKey, MAX_ACTIVE_KEYS_INSTANCE, MAX_ACTIVE_KEYS_PER_OWNER,
    MAX_LABEL_CHARS, MAX_RATE_PER_MIN, NewApiKey, SCOPE_UPLOAD, sanitize_label,
};
pub use attribution::{ReleaseAttribution, Uploader};
pub use audit_chain::{
    AuditAnchor, AuditExportRow, ChainBreak, ChainBreakKind, ChainQuick, ChainReport,
    class_of as audit_chain_class,
};
pub use auth::{
    AuditFilter, AuditRow, LOCKOUT_BASE_SECS, LOCKOUT_CAP_SECS, LOCKOUT_DECAY_SECS,
    LOCKOUT_THRESHOLD, LoginUser, NewSession, SessionRow, SessionStage, lock_secs_for,
};
pub use backup::{
    ACCOUNT_AUDIT_EVENTS, BackupReport, DEFAULT_ACCOUNT_AUDIT_DAYS, DEFAULT_KEEP, ENC_SUFFIX,
    PurgeReport, backup_file, backup_file_with, backup_name,
};
pub use backup_crypto::{
    BackupCryptoError, BackupKey, decrypt_file, decrypt_stream, encrypt_stream, looks_encrypted,
};
pub use blobs::BlobMaintenance;
pub use bulk::{BulkItem, MAX_BULK_IDS};
pub use db::{
    CRITICAL_TABLES, DbConfig, OpenEvent, PROGRESS_EVERY, READER_CONNECTIONS, SqliteDb,
    StartupCheck,
};
pub use error::StoreError;
pub use fs_store::{
    FsStore, GcCandidate, GcReport, MIGRATED_DIR, NzbStore, PutOutcome, VerifyReport,
};
pub use health::{DeepDbReport, LogCounts, PoolInfo, SchemaInfo, SecurityFacts};
pub use ingest_log::{
    CategoryTotals, IngestLogEntry, IngestLogRow, LogOutcome, LogSource, ReleaseTotals,
};
pub use invite::{
    AccountPurgeReport, CODE_ENTROPY_BYTES, CommitRecovery, INVITE_TTL_RANGE, InviteCode,
    InvitePurpose, InviteRow, MAX_NAME_REFUSALS, MAX_OPEN_INVITES, NewInvite, NewRecovery,
    RECOVER_TTL_RANGE, Redeemed, Redemption, STAGING_TTL_SECS, StagedSwap,
};
pub use mfa::{FactorAttempt, MfaState, SecondFactor, SessionInfo};
pub use nfo::{MAX_NFO_LOOKUP_IDS, MAX_NFO_STORED_BYTES, NfoAttach, ReleaseNfo};
pub use pref::{
    FilePageSize, PREF_CHANGE_EVENT, PageSize, PrefsPatch, ReleasePageSize, Theme, UserPrefs,
};
pub use profile::{
    MAX_EMAIL_LEN, MAX_EMAIL_LOCAL_LEN, MAX_SELF_DISPLAY_NAME_CHARS, MIN_SELF_DISPLAY_NAME_CHARS,
    RegistrationProfile, display_name_skeleton, normalize_email, self_display_name_is_valid,
};
pub use release::{
    CategorySource, CursorError, GroupItem, GroupOutcome, IngestOrigin, KeysetPage,
    MAX_CURSOR_CHARS, MAX_GROUP_JOBS, MAX_LIMIT, MAX_SOURCE_LABEL_BYTES, NewRelease, Page,
    PageCursor, ReleaseFile, ReleaseRow, SceneColumns, SearchQuery, SeekDir, SortKey,
    clean_source_label,
};
#[cfg(any(test, feature = "pg-test-support"))]
pub use repo::FixtureRepo;
pub use repo::{AccountRepo, AuditRepo, LibraryRepo, OpsRepo};
pub use restore_finish::{RESTORE_FINISH_EVENT, RestoreFinishReport, RestoredAccount};
pub use retention::{RETENTION_FLOORS, RetentionPolicy};
pub use saved_search::{
    MAX_SAVED_SEARCH_FILTER_BYTES, MAX_SAVED_SEARCH_NAME_CHARS, MAX_SAVED_SEARCHES, SavedSearch,
    SavedSearchError, clean_saved_search_name,
};
pub use search_index::{SearchDoc, SearchIndex};
pub use search_source::{
    DEGRADED_SCAN_BUDGET, DegradedPage, IndexRow, OutboxEntry, OutboxLag, SearchSourceState,
    cut_utf8,
};
pub use store::{DbBackend, Store, UnknownBackend};
pub use taxonomy::seed_rows;
pub use throttle::{
    ADMIN_LOCK_CAP_SECS, AGGREGATE_LIMIT, AttemptContext, DAILY_MFA_LIMIT, EnrollConfirm,
    FactorVerdict, FailureEffect, FailureKind, LOGIN_LOCK_MAX_ROWS, PENDING_SESSION_MAX_FAILURES,
    ThrottleState,
};
pub use totp_rotate::{Reseal, ResealReport};
pub use trash::{
    QuarantineBlob, QuarantineListing, QuarantinePurge, StillUnreferenced, TrashBlob, TrashFinish,
    TrashListing, TrashPurge, TrashRow, TrashStore, sha8,
};
pub use user::{MAX_USERNAME_LEN, UserRow, username_is_valid};

#[cfg(test)]
mod account_tests;
#[cfg(test)]
mod acct_testkit;
#[cfg(test)]
mod apikey_tests;
#[cfg(test)]
mod attribution_tests;
#[cfg(test)]
mod audit_chain_tests;
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod backup_enc_tests;
#[cfg(test)]
mod backup_tests;
#[cfg(test)]
mod bulk_tests;
#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod fs_store_tests;
#[cfg(test)]
mod ingest_log_tests;
#[cfg(test)]
mod invite_tests;
#[cfg(test)]
mod matrix_tests;
#[cfg(test)]
mod mfa_tests;
#[cfg(test)]
mod parity_tests;
#[cfg(test)]
mod pg_account_tests;
#[cfg(test)]
mod pg_apikey_tests;
#[cfg(test)]
mod pg_attribution_tests;
#[cfg(test)]
mod pg_audit_chain_tests;
#[cfg(test)]
mod pg_auth_tests;
#[cfg(test)]
mod pg_backup_enc_tests;
#[cfg(test)]
mod pg_backup_tests;
#[cfg(test)]
mod pg_bulk_tests;
#[cfg(test)]
mod pg_ingest_log_tests;
#[cfg(test)]
mod pg_invite_tests;
#[cfg(test)]
mod pg_mfa_tests;
#[cfg(test)]
mod pg_registration_tests;
#[cfg(test)]
mod pg_release_tests;
#[cfg(test)]
mod pg_restore_finish_tests;
#[cfg(test)]
mod pg_sec_tests;
#[cfg(test)]
mod pg_testkit;
#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod pg_throttle_tests;
#[cfg(test)]
mod pg_trash_tests;
#[cfg(test)]
mod pg_user_tests;
#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod registration_tests;
#[cfg(test)]
mod release_tests;
#[cfg(test)]
mod restore_finish_tests;
#[cfg(test)]
mod seam_tests;
#[cfg(test)]
mod sqlite_v3_tests;
#[cfg(test)]
mod startup_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod throttle_tests;
#[cfg(test)]
mod trash_tests;
#[cfg(test)]
mod upgrade_tests;
#[cfg(test)]
mod user_tests;
