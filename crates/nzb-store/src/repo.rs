//! The storage seam (ARCHITECTURE v3 13.1, T122): four domain traits implemented by both backends
//! ([`SqliteDb`], [`PgDb`]) and by the [`Store`] enum that production code holds. The indexer's contract is
//! the merged `nzb_search::IndexSource` (review 34 L4), implemented on [`Store`] in `nzb-search`; it is not
//! redefined here.
//!
//! Seam rules (review 34 I2), enforced by the shape of this file:
//! * (a) **No default method bodies.** Every trait is declared and implemented by [`repo!`]: each method is
//!   forwarded to the inherent method of the same name on each backend, so a backend that lacks a method
//!   does not compile (the forward would recurse into the trait, which `unconditional_recursion` denies).
//! * (b) **No transaction handle crosses the seam.** Every method takes plain values and is one transaction
//!   in the backend, with its own authorization re-checks inside it (N9, bulk resolve, review 30.3 a, D32).
//! * (c) Tests assert the exact [`StoreError`] variant on both backends (`seam_tests`).
//! * (d) The backend is a closed enum ([`DbBackend`]).
//!
//! Native `async fn` style (`impl Future + Send`, like `SearchIndex`): static dispatch only, no `dyn`.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::time::Duration;

use nzb_core::Sha256;

use crate::pg::PgDb;
use crate::pref::{PageSize, PrefsPatch};
use crate::store::Store;
use crate::{
    AccountActor, AccountPolicy, AccountPurgeReport, AccountRow, Actor, ApiKeyAuth, ApiKeyRow,
    AttemptContext, AuditActor, AuditAnchor, AuditEntry, AuditExportRow, AuditFilter, AuditRow,
    BulkItem, CategoryTotals, ChainQuick, ChainReport, CommitRecovery, CreateKey, DeepDbReport,
    DegradedPage, EnrollConfirm, FactorAttempt, FactorVerdict, FailureEffect, FailureKind,
    GrantableRole, GroupItem, GroupOutcome, IndexRow, IngestLogEntry, IngestLogRow, InviteRow,
    LogCounts, LoginUser, MfaState, NewAccount, NewApiKey, NewInvite, NewRecovery, NewRelease,
    NewSession, NfoAttach, OutboxEntry, OutboxLag, PurgeReport, Redeemed, Redemption,
    RegistrationProfile, ReleaseAttribution, ReleaseFile, ReleaseNfo, ReleaseRow, ReleaseTotals,
    Reseal, ResealReport, ReservedLoginAccount, RestoreFinishReport, RestoredAccount,
    RetentionPolicy, Role, SavedSearch, SchemaInfo, SearchSourceState, SecurityFacts, SessionInfo,
    SessionRow, SqliteDb, StagedSwap, StoreError, ThrottleState, TrashRow, Uploader, UserPrefs,
    UserRow,
};
use crate::{AnchorVerdict, DbAnchor};

/// Declares one repository trait and its three implementations (SQLite, Postgres, [`Store`]).
///
/// Each backend implementation forwards to the backend's **inherent** method of the same name (inherent
/// methods take precedence over trait methods in path resolution). The [`Store`] implementation matches
/// once per call.
macro_rules! repo {
    (
        $(#[$tm:meta])*
        pub trait $Trait:ident {
            $(
                $(#[$fm:meta])*
                fn $name:ident(&self $(, $arg:ident : $ty:ty)* $(,)?) -> $ret:ty;
            )*
        }
    ) => {
        $(#[$tm])*
        // The 2.x signatures are kept as they are (same names and semantics on both backends).
        #[allow(clippy::too_many_arguments)]
        pub trait $Trait: Clone + Send + Sync + 'static {
            $(
                $(#[$fm])*
                ///
                /// # Errors
                /// The backend's errors for this operation (same [`StoreError`] variant on both backends).
                fn $name(&self $(, $arg: $ty)*) -> impl Future<Output = $ret> + Send;
            )*
        }

        #[allow(clippy::too_many_arguments)]
        impl $Trait for SqliteDb {
            $(
                fn $name(&self $(, $arg: $ty)*) -> impl Future<Output = $ret> + Send {
                    SqliteDb::$name(self $(, $arg)*)
                }
            )*
        }

        #[allow(clippy::too_many_arguments)]
        impl $Trait for PgDb {
            $(
                fn $name(&self $(, $arg: $ty)*) -> impl Future<Output = $ret> + Send {
                    PgDb::$name(self $(, $arg)*)
                }
            )*
        }

        #[allow(clippy::too_many_arguments)]
        impl $Trait for Store {
            $(
                fn $name(&self $(, $arg: $ty)*) -> impl Future<Output = $ret> + Send {
                    async move {
                        let r = match self {
                            Store::Sqlite(db) => SqliteDb::$name(db $(, $arg)*).await,
                            Store::Postgres(db) => PgDb::$name(db $(, $arg)*).await,
                        };
                        // SEC-095: a busy database becomes the uniform 503 in the web layer.
                        if let Err(e) = &r {
                            crate::busy::note(e);
                        }
                        r
                    }
                }
            )*
        }
    };
}

repo! {
    /// Accounts, sessions, MFA, throttling, invitations/recovery/staging, API keys (the 2.x names and semantics).
    pub trait AccountRepo {
        /// Number of live (unexpired) sessions per account, for the Users page (T101b).
        fn active_session_counts(&self, now: i64) -> Result<Vec<(i64, i64)>, StoreError>;
        /// Ids of the accounts with an `active` session seen at or after `since` (the Users page "Online" badge).
        fn online_account_ids(&self, now: i64, since: i64) -> Result<Vec<i64>, StoreError>;
        /// Cancels a redeemed-but-uncommitted recovery (admin session, CSRF only.
        fn cancel_recovery(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Replaces the password hash after an authenticated, re-verified change, revokes EVERY
        /// session of the user and inserts `new_session`; `NotFound` (nothing written) when
        /// `session_hash`, the session that re-authenticated, is gone.
        fn change_password(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            password_hash: &str,
            new_session: &NewSession,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Per-address counterpart of `check_enrollment_token`: the token is not consumed; wrong
        /// attempts feed the hard lock, the aggregate, the daily cap and the pending session's
        /// 5-failure cap.
        fn check_enrollment_token_v2(
            &self,
            user_id: i64,
            token_hash: Option<[u8; 32]>,
            ctx: &AttemptContext<'_>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// The commit point of a staged recovery (M3, N4): every re-check, the credential replacement
        /// and its effects in one transaction.
        fn commit_staged_recovery(
            &self,
            c: &CommitRecovery<'_>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Per-address counterpart of `confirm_totp_enrollment` (the enrollment token is waived only
        /// for an invitation session).
        fn confirm_totp_enrollment_v2(
            &self,
            c: &EnrollConfirm<'_>,
            ctx: &AttemptContext<'_>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Number of unrevoked keys (for the cap check that precedes re-authentication).
        fn count_active_api_keys(&self) -> Result<i64, StoreError>;
        /// Number of unrevoked keys owned by `owner_id` (the per-owner cap).
        fn count_active_api_keys_of(&self, owner_id: i64) -> Result<i64, StoreError>;
        /// Number of live accounts (the CLI's "is this the first account" question, I-5).
        fn count_live_accounts(&self) -> Result<u64, StoreError>;
        /// Number of accounts whose aggregate or daily cap is in force (health WARN input).
        fn count_throttled_accounts(&self, now: i64) -> Result<u64, StoreError>;
        /// Number of recovery codes that can still be used.
        fn count_unused_recovery_codes(&self, user_id: i64) -> Result<i64, StoreError>;
        /// Creates an account on the operator's authority (`nzbd user create`).
        fn create_account_operator(
            &self,
            new: &NewAccount<'_>,
            policy: AccountPolicy,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Stores a new key hash unless `max_active` unrevoked keys exist already (check and insert are
        /// one transaction on the single writer connection).
        fn create_api_key(
            &self,
            key: NewApiKey<'_>,
            max_active: u32,
            now: i64,
            actor: Actor<'_>,
        ) -> Result<CreateKey, StoreError>;
        /// Like [`Self::create_api_key`] with an explicit OWNER (`nzbd apikey create --user`, and the
        /// per-user key management of T103).
        fn create_api_key_for(
            &self,
            key: NewApiKey<'_>,
            owner_id: i64,
            max_active: u32,
            now: i64,
            who: &AuditActor,
            ip: Option<&str>,
        ) -> Result<CreateKey, StoreError>;
        /// Like [`Self::create_api_key_for`], bound to the web session that re-authenticated:
        /// `NotFound` (nothing written) when `session_hash` is no longer a live session of the owner.
        fn create_api_key_for_session(
            &self,
            key: NewApiKey<'_>,
            owner_id: i64,
            session_hash: &[u8; 32],
            max_active: u32,
            now: i64,
            who: &AuditActor,
            ip: Option<&str>,
        ) -> Result<CreateKey, StoreError>;
        /// Issues an invitation (admin session; the caller re-authenticated).
        fn create_invite(
            &self,
            actor: &AccountActor,
            new: &NewInvite<'_>,
            policy: AccountPolicy,
            ip: Option<&str>,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Operator `nzbd user invite` (uploader/viewer only; there is no admin invite, D27).
        fn create_invite_operator(
            &self,
            new: &NewInvite<'_>,
            policy: AccountPolicy,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Saves a search for the caller's own account (T127, any live enabled role; the actor is the owner): at most
        /// 25 per account, unique name, both checked in the write transaction. Returns the new id.
        fn create_saved_search(
            &self,
            account_id: i64,
            name: &str,
            filters: &str,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn create_saved_search_as(
            &self,
            actor: &AccountActor,
            name: &str,
            filters: &str,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Tombstones a DISABLED uploader/viewer (admin session, re-authenticated by the caller).
        fn delete_account(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator tombstone of a disabled account (last-usable-admin rule applies to admins).
        fn delete_account_operator(&self, target_id: i64, now: i64) -> Result<(), StoreError>;
        /// Deletes one of the caller's own saved searches (T127); anybody else's id is `NotFound`, like an unknown one.
        fn delete_saved_search(&self, account_id: i64, id: i64) -> Result<(), StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn delete_saved_search_as(&self, actor: &AccountActor, id: i64, now: i64) -> Result<(), StoreError>;
        /// Revokes one session.
        fn delete_session(&self, id_hash: &[u8; 32]) -> Result<bool, StoreError>;
        /// Disables a uploader/viewer (admin session).
        fn disable_account(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator disable of any account (last-usable-admin rule applies).
        fn disable_account_operator(&self, target_id: i64, now: i64) -> Result<(), StoreError>;
        /// Re-enables a disabled uploader/viewer (admin session, re-authenticated by the caller).
        fn enable_account(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator enable of any account.
        fn enable_account_operator(&self, target_id: i64, now: i64) -> Result<(), StoreError>;
        /// Looks a key up by the hash of the presented secret (read pool; no write).
        fn find_api_key(&self, hash: &[u8; 32]) -> Result<Option<ApiKeyAuth>, StoreError>;
        /// One account (live or tombstoned) by id.
        fn get_account(&self, id: i64) -> Result<Option<AccountRow>, StoreError>;
        /// A LIVE account by login name (NOCASE).
        fn get_account_by_username(&self, username: &str) -> Result<Option<AccountRow>, StoreError>;
        /// One code by id.
        fn get_invite(&self, id: i64) -> Result<Option<InviteRow>, StoreError>;
        /// Case-insensitive lookup of the login-relevant user fields of a LIVE account (a tombstone is
        /// "unknown", L7).
        fn get_login_user(&self, username: &str) -> Result<Option<LoginUser>, StoreError>;
        /// Login-relevant fields by user id (used to re-check the account behind a session).
        fn get_login_user_by_id(&self, id: i64) -> Result<Option<LoginUser>, StoreError>;
        /// MFA columns of a user.
        fn get_mfa_state(&self, user_id: i64) -> Result<Option<MfaState>, StoreError>;
        /// The oldest live user, if one exists.
        fn get_only_user(&self) -> Result<Option<UserRow>, StoreError>;
        /// Looks a session up by `SHA-256(id)`.
        fn get_session(&self, id_hash: &[u8; 32]) -> Result<Option<SessionRow>, StoreError>;
        /// Looks a live user up by name (case-insensitive).
        fn get_user_by_username(&self, username: &str) -> Result<Option<UserRow>, StoreError>;
        /// Inserts a session and revokes the oldest of the same stage beyond `max_per_stage`.
        fn insert_session(&self, s: &NewSession, max_per_stage: u32) -> Result<(), StoreError>;
        /// Issues a pending login only if the observed credentials still match, atomically with
        /// optional cookie replacement and the per-stage cap. Stale state returns `NotFound`.
        fn insert_login_session(
            &self,
            seen: &LoginUser,
            s: &NewSession,
            replacing: Option<&[u8; 32]>,
            max_per_stage: u32,
        ) -> Result<(), StoreError>;
        /// Issues a single-use recovery code for a uploader/viewer (admin session, re-authenticated by
        /// the caller).
        fn issue_recovery(
            &self,
            actor: &AccountActor,
            new: &NewRecovery<'_>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<i64, StoreError>;
        /// Operator-issued recovery code for a uploader/viewer (admins are recovered with `reset-
        /// password`/`enroll-token`, never with a code).
        fn issue_recovery_operator(&self, new: &NewRecovery<'_>, now: i64) -> Result<i64, StoreError>;
        /// All accounts, oldest first; tombstones only when `include_deleted`.
        fn list_accounts(&self, include_deleted: bool) -> Result<Vec<AccountRow>, StoreError>;
        /// Unexpired `active` sessions of the user, newest first.
        fn list_active_sessions(&self, user_id: i64, now: i64) -> Result<Vec<SessionInfo>, StoreError>;
        /// All keys, newest first (operator CLI).
        fn list_api_keys(&self) -> Result<Vec<ApiKeyRow>, StoreError>;
        /// Every unrevoked key plus only the `max_revoked` most recently created revoked ones, newest
        /// first, optionally restricted to one `owner`.
        fn list_api_keys_recent(
            &self,
            owner: Option<i64>,
            max_revoked: u32,
        ) -> Result<Vec<ApiKeyRow>, StoreError>;
        /// Open (unused, unrevoked, unexpired) codes, newest first, with their issuers.
        fn list_open_invites(&self, now: i64) -> Result<Vec<InviteRow>, StoreError>;
        /// Ids of the accounts that are throttled or locked right now (a hard lock at any address, the
        /// aggregate or the daily second-factor refusal).
        fn locked_account_ids(&self, now: i64) -> Result<Vec<i64>, StoreError>;
        /// The 2.0 password verdict with per-address locks; `seen` is the account the password was
        /// verified against, and its credential state is re-read inside the transaction (review 30.3 a).
        fn login_password_step_v2(
            &self,
            seen: Option<&LoginUser>,
            verified: bool,
            fail_reason: &str,
            ctx: &AttemptContext<'_>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Opens one of the caller's own saved searches (T127): moves `last_seen_at` forward to `now` and returns the
        /// row as it was; `None` for anybody else's id or an unknown one.
        fn open_saved_search(
            &self,
            account_id: i64,
            id: i64,
            now: i64,
        ) -> Result<Option<SavedSearch>, StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn open_saved_search_as(
            &self,
            actor: &AccountActor,
            id: i64,
            now: i64,
        ) -> Result<Option<SavedSearch>, StoreError>;
        /// The login name an OPEN code would apply to (the reserved name of an invitation, the target's
        /// login name of a recovery code), or `None` for any other code.
        fn open_code_login_name(
            &self,
            code_hash: &[u8; 32],
            now: i64,
        ) -> Result<Option<String>, StoreError>;
        /// Daily maintenance of the account tables.
        fn purge_account_state(&self, now: i64) -> Result<AccountPurgeReport, StoreError>;
        /// Delete sessions whose `expires_at` is at or before `now`.
        fn purge_expired_sessions(&self, now: i64) -> Result<u64, StoreError>;
        /// Deletes keys revoked more than `days` days before `now` (maintenance purge; the audit rows
        /// stay, `ingest_log.api_key_id` becomes NULL).
        fn purge_revoked_api_keys(&self, now: i64, days: u32) -> Result<u64, StoreError>;
        /// Purges sessions past their idle/pending deadline or created before `created_before` (the
        /// absolute lifetime cutoff).
        fn purge_sessions(&self, now: i64, created_before: i64) -> Result<u64, StoreError>;
        /// Records one failed attempt that the store did not see decided (for example an enrollment-
        /// token check done elsewhere).
        fn record_failure(
            &self,
            user_id: i64,
            ip_key: &str,
            kind: FailureKind,
            session: Option<&[u8; 32]>,
            now: i64,
        ) -> Result<FailureEffect, StoreError>;
        /// The completed-login bookkeeping (call exactly once when the second factor, or the enrollment
        /// commit, succeeded and the `active` session is about to be issued).
        fn record_login_success_v2(
            &self,
            user_id: i64,
            ip_key: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Redeems a code at `/invite` (anonymous, token-gated) with the registration profile of D32
        /// (T109).
        fn redeem_code_with_profile(
            &self,
            r: &Redemption<'_>,
            profile: &RegistrationProfile<'_>,
            policy: AccountPolicy,
            ip: Option<&str>,
            now: i64,
        ) -> Result<Redeemed, StoreError>;
        /// Renames one of the caller's own saved searches (T127); anybody else's id is `NotFound`, a name the
        /// account already uses is `SavedSearch(Duplicate)`.
        fn rename_saved_search(&self, account_id: i64, id: i64, name: &str) -> Result<(), StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn rename_saved_search_as(&self, actor: &AccountActor, id: i64, name: &str, now: i64) -> Result<(), StoreError>;
        /// Replaces all recovery codes (old ones, used or not, stop working); `NotFound` when
        /// `session_hash`, the session that re-authenticated, is gone.
        fn replace_recovery_codes(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            hashes: &[[u8; 32]],
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Re-seals every sealed TOTP secret through `f(account_id, blob)` in one transaction with one
        /// audit row; `dry_run` writes nothing.
        fn reseal_totp_secrets(
            &self,
            now: i64,
            dry_run: bool,
            f: &mut (dyn FnMut(i64, &[u8],
        ) -> Reseal + Send), ) -> Result<ResealReport, StoreError>;
        /// Live 1.x accounts whose login name is reserved (flagged for the startup WARN and the health
        /// WARN; never renamed).
        fn reserved_login_accounts(&self) -> Result<Vec<ReservedLoginAccount>, StoreError>;
        /// Operator `user reset-mfa <name>`.
        fn reset_mfa_for(&self, user_id: i64, now: i64) -> Result<(), StoreError>;
        /// Operator `user reset-password <name>`.
        fn reset_password_for(
            &self,
            user_id: i64,
            password_hash: &str,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Revokes every session of another account (admin session; the web layer re-authenticates when
        /// the target is an admin, the only HTTP action on an admin).
        fn revoke_account_sessions(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<u64, StoreError>;
        /// Operator `user revoke-sessions`.
        fn revoke_account_sessions_operator(&self, target_id: i64, now: i64) -> Result<u64, StoreError>;
        /// Revokes an active key.
        fn revoke_api_key(&self, id: i64, now: i64, actor: Actor<'_>) -> Result<bool, StoreError>;
        /// Revokes one active key on behalf of a signed-in account (T103).
        fn revoke_api_key_by(
            &self,
            actor: &AccountActor,
            id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Revokes an open invitation or recovery code (admin session).
        fn revoke_invite(
            &self,
            actor: &AccountActor,
            invite_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Revokes every active key owned by `owner_id` (an owner's own revocation, or an admin acting
        /// on owned keys only).
        fn revoke_keys_of_owner(
            &self,
            owner_id: i64,
            now: i64,
            who: &AuditActor,
            ip: Option<&str>,
        ) -> Result<u64, StoreError>;
        /// Revokes every open code (startup while `security.multi_user` is off, I-5).
        fn revoke_open_invites_system(&self, now: i64) -> Result<u64, StoreError>;
        /// [`Self::revoke_open_invites_system`] with the audit reason (`multi_user_off`,
        /// `registration_disabled`).
        fn revoke_open_invites_system_for(
            &self,
            now: i64,
            reason: &'static str,
        ) -> Result<u64, StoreError>;
        /// Revokes every session of the user except the still-active calling session `keep`.
        fn revoke_other_sessions(
            &self,
            user_id: i64,
            keep: &[u8; 32],
            ip: Option<&str>,
            now: i64,
        ) -> Result<u64, StoreError>;
        /// Revokes one session owned by `user_id`, while the calling session is still active.
        fn revoke_user_session(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            id_hash: &[u8; 32],
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Replaces `old_hash` with a brand-new session (id rotation.
        fn rotate_session(
            &self,
            old_hash: &[u8; 32],
            s: &NewSession,
            max_per_stage: u32,
        ) -> Result<(), StoreError>;
        /// Like [`Self::rotate_session`] but refuses (and rolls back) when the old session no longer
        /// exists.
        fn rotate_session_strict(
            &self,
            old_hash: &[u8; 32],
            s: &NewSession,
            max_per_stage: u32,
        ) -> Result<(), StoreError>;
        /// The saved searches of `account_id` only (the caller's own; T127), by name.
        fn saved_searches(&self, account_id: i64) -> Result<Vec<SavedSearch>, StoreError>;
        /// Decides one second-factor attempt with per-address locks, the persisted aggregate and the
        /// pending session's 5-failure cap.
        fn second_factor_step_v2(
            &self,
            a: FactorAttempt<'_>,
            ctx: &AttemptContext<'_>,
        ) -> Result<FactorVerdict, StoreError>;
        /// The caller behind a session.
        fn session_actor(
            &self,
            id_hash: &[u8; 32],
            now: i64,
        ) -> Result<Option<AccountActor>, StoreError>;
        /// Sets (or with `None` resets to the default handle) an account's display name.
        fn set_display_name(
            &self,
            actor: &AccountActor,
            target_id: i64,
            name: Option<&str>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator `user set-display-name` (any account, admins included).
        fn set_display_name_operator(
            &self,
            target_id: i64,
            name: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator `user enroll-token <name>`.
        fn set_enrollment_token_for(
            &self,
            user_id: i64,
            token_hash: &[u8; 32],
            expires_at: i64,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Changes uploader <-> viewer (admin session, re-authenticated by the caller); a demotion to viewer revokes its API keys.
        fn set_role(
            &self,
            actor: &AccountActor,
            target_id: i64,
            role: GrantableRole,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator role change, the only way to grant or take away `admin` (D26 b).
        fn set_role_operator(&self, target_id: i64, role: Role, now: i64) -> Result<(), StoreError>;
        /// Stores the caller's own preferences (T120); `pref_change keys=...` audit row when anything changed.
        fn set_user_prefs(
            &self,
            actor_id: i64,
            prefs: UserPrefs,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Applies the `Some` fields of `patch` to the caller's own preferences as stored inside the write transaction
        /// (T133 review 48 L1); audited like `set_user_prefs`.
        fn patch_user_prefs(
            &self,
            actor_id: i64,
            patch: PrefsPatch,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn patch_user_prefs_as(
            &self,
            actor: &AccountActor,
            patch: PrefsPatch,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Stores one page size of the caller's own preferences, writing only that column (T133).
        fn set_page_size(
            &self,
            actor_id: i64,
            size: PageSize,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Session-bound write: active, unexpired, owner-matching session rechecked inside the transaction.
        fn set_page_size_as(
            &self,
            actor: &AccountActor,
            size: PageSize,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Parks the sealed pending TOTP secret in the staged swap unless one is already there (a
        /// reload shows the SAME secret) and returns the blob now stored.
        fn stage_totp_secret(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            sealed: &[u8],
            now: i64,
        ) -> Result<Option<Vec<u8>>, StoreError>;
        /// The staged swap of `(user_id, session_hash)`, if it exists and has not expired.
        fn staged_swap(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            now: i64,
        ) -> Result<Option<StagedSwap>, StoreError>;
        /// Stores a freshly sealed pending TOTP secret unless one already exists (or `replace` is set)
        /// and returns the blob now stored, so two concurrent enrollment page loads agree.
        fn store_pending_totp(
            &self,
            user_id: i64,
            sealed: &[u8],
            replace: bool,
        ) -> Result<Option<Vec<u8>>, StoreError>;
        /// Reads or creates a secret only for a live pending session with its current token or enrollment proof.
        fn store_pending_totp_for_session(
            &self,
            user_id: i64,
            session_hash: &[u8; 32],
            sealed: &[u8],
            replace: bool,
            token_hash: Option<[u8; 32]>,
            now: i64,
        ) -> Result<Option<Vec<u8>>, StoreError>;

        /// The throttle state of `(user_id, ip_key)` as of `now` (read-only; for UI decisions and
        /// health).
        fn throttle_state(
            &self,
            user_id: i64,
            ip_key: &str,
            now: i64,
        ) -> Result<ThrottleState, StoreError>;
        /// Records a use, but only if the stored `last_used_at` is older than `min_interval_secs` (so a
        /// busy client does not turn every request into a write).
        fn touch_api_key(&self, id: i64, now: i64, min_interval_secs: i64) -> Result<bool, StoreError>;
        /// Slides the idle deadline of an `active` session.
        fn touch_session(
            &self,
            id_hash: &[u8; 32],
            now: i64,
            expires_at: i64,
        ) -> Result<(), StoreError>;
        /// Clears every lock row and the persisted throttle counters of a uploader/viewer (admin
        /// session).
        fn unlock_account(
            &self,
            actor: &AccountActor,
            target_id: i64,
            ip: Option<&str>,
            now: i64,
        ) -> Result<(), StoreError>;
        /// Operator `user unlock`.
        fn unlock_account_operator(&self, target_id: i64, now: i64) -> Result<(), StoreError>;
        /// The stored preferences of an account (defaults without a row; T120).
        fn user_prefs(&self, account_id: i64) -> Result<UserPrefs, StoreError>;
    }
}

repo! {
    /// Releases, files, attribution, edits, bulk edits, trash, ingest log, library totals.
    pub trait LibraryRepo {
        // --- Search index source (ARCHITECTURE v3 3.1-3.5; adapted to `nzb_search::IndexSource`, `Hydrator` and
        // `DegradedSource` on `Store` by `nzb-search`).
        /// The oldest `limit` outbox rows, ascending sequence.
        fn search_outbox_read(&self, limit: usize) -> Result<Vec<OutboxEntry>, StoreError>;
        /// Outbox depth and index lag (metrics, health, the scanner's lag pause; T114).
        fn search_outbox_lag(&self) -> Result<OutboxLag, StoreError>;
        /// The current documents of `ids` in one snapshot; file names cut to `max_file_bytes` bytes (in SQL and while
        /// streaming, review 32 M2).
        fn search_index_load(
            &self,
            ids: &[i64],
            max_file_bytes: usize,
        ) -> Result<Vec<IndexRow>, StoreError>;
        /// Documents above `after_id`, ascending, at most `limit`, stopping once their text reaches `max_bytes`.
        fn search_index_scan(
            &self,
            after_id: i64,
            limit: usize,
            max_bytes: usize,
            max_file_bytes: usize,
        ) -> Result<Vec<IndexRow>, StoreError>;
        /// One transaction: delete exactly `seqs` from the outbox and, while a rebuild replays (flag read inside the
        /// transaction, review 30 L6 a), record `ids` in `search_replay`.
        fn search_outbox_consume(&self, seqs: &[i64], ids: &[i64]) -> Result<(), StoreError>;
        /// Records a release the indexer could not index (fixed error code).
        fn search_quarantine(&self, release_id: i64, code: &str) -> Result<(), StoreError>;
        /// Epoch, outbox position, replay and rebuild flags.
        fn search_source_state(&self) -> Result<SearchSourceState, StoreError>;
        /// Sets the replay flag and commits before a rebuild scan.
        fn search_begin_rebuild(&self) -> Result<(), StoreError>;
        /// Replay ids above `after_id`, ascending, at most `limit`.
        fn search_replay_ids(&self, after_id: i64, limit: usize) -> Result<Vec<i64>, StoreError>;
        /// Ends a rebuild: flags cleared, `generation` recorded, replay set emptied (one transaction).
        fn search_finish_rebuild(&self, generation: u64) -> Result<(), StoreError>;
        /// Asks the running indexer for a rebuild (`nzbd search rebuild`).
        fn search_request_rebuild(&self, now: i64) -> Result<(), StoreError>;
        /// One outbox row per id without changing the releases.
        fn enqueue_reindex(&self, ids: &[i64]) -> Result<(), StoreError>;
        /// The index epoch (`search_state.epoch`).
        fn search_epoch(&self) -> Result<Vec<u8>, StoreError>;
        /// Current rows of `ids` in the given order, minus vanished ids and rows whose current category is excluded.
        fn hydrate(&self, ids: &[i64], exclude: &[u32]) -> Result<Vec<ReleaseRow>, StoreError>;
        /// Bounded newest-first listing while the index is unavailable (review L5).
        fn degraded_browse(
            &self,
            before: Option<i64>,
            categories: &[u32],
            exclude: &[u32],
            limit: u32,
        ) -> Result<DegradedPage, StoreError>;
        /// `(category id, releases)` of every non-empty category, exact.
        fn category_totals(&self) -> Result<Vec<(u32, u64)>, StoreError>;
        /// Quarantined release ids (at most `limit`).
        fn search_quarantined(&self, limit: u32) -> Result<BTreeSet<i64>, StoreError>;
        /// The selection as [`BulkItem`]s in id order, de-duplicated.
        fn bulk_items(&self, ids: &[i64], hidden: &[u16]) -> Result<Vec<BulkItem>, StoreError>;
        /// Sets the category of every release of the selection (marks it manual, like
        /// [`Self::set_category_as`]) in one transaction.
        fn bulk_set_category_as(
            &self,
            actor: &AccountActor,
            ids: &[i64],
            category_id: u32,
            hidden: &[u16],
            ip: Option<&str>,
            now: i64,
        ) -> Result<usize, StoreError>;
        /// Sets (or, blank, clears) the source label of every release of the selection in one
        /// transaction.
        fn bulk_set_source_label_as(
            &self,
            actor: &AccountActor,
            ids: &[i64],
            label: &str,
            hidden: &[u16],
            ip: Option<&str>,
            now: i64,
        ) -> Result<(usize, Option<String>), StoreError>;
        /// Number of `failed` log rows recorded for `sha` (the retry count of a quarantined file).
        fn count_failed_for_sha(&self, sha: &Sha256) -> Result<u32, StoreError>;
        /// Removes the trash record with this id.
        fn forget_trash(&self, id: i64) -> Result<bool, StoreError>;
        /// Removes the trash record with this id and its NFO (the trash purge; T140).
        fn purge_trash_record(&self, id: i64, now: i64) -> Result<bool, StoreError>;
        /// Which of these release ids have a live NFO (T144; one query per index page, at most 1000 ids).
        fn releases_with_nfo(&self, ids: &[i64]) -> Result<HashSet<i64>, StoreError>;
        /// The NFO of a release, if it has one (T140).
        fn release_nfo(&self, release_id: i64) -> Result<Option<ReleaseNfo>, StoreError>;
        /// Attaches an NFO: an admin or the release's own uploader, only while it has none (D41 b).
        fn attach_nfo_as(
            &self,
            uploader: &Uploader,
            release_id: i64,
            expected: &Sha256,
            bytes: &[u8],
            now: i64,
            ip: Option<&str>,
        ) -> Result<NfoAttach, StoreError>;
        /// Attaches a watch-folder sidecar NFO (T141): the process (`system` actor), only while the release has none.
        fn attach_watch_nfo(
            &self,
            release_id: i64,
            expected: &Sha256,
            bytes: &[u8],
            now: i64,
        ) -> Result<NfoAttach, StoreError>;
        /// Removes the NFO of a release (admin).
        fn remove_nfo_as(
            &self,
            actor: &AccountActor,
            release_id: i64,
            now: i64,
            ip: Option<&str>,
        ) -> Result<bool, StoreError>;
        /// One file of a release by its index.
        fn get_file(&self, release_id: i64, idx: u32) -> Result<Option<ReleaseFile>, StoreError>;
        /// Fetch a release by id.
        fn get_release(&self, id: i64) -> Result<Option<ReleaseRow>, StoreError>;
        /// Fetch a release by hex SHA-256.
        fn get_release_by_sha(&self, hex: &str) -> Result<Option<ReleaseRow>, StoreError>;
        /// One deleted release by trash id.
        fn get_trash(&self, id: i64) -> Result<Option<TrashRow>, StoreError>;
        /// Newest-first `ingest_log` rows, `limit` (capped at 500) rows after skipping `offset`.
        fn ingest_log_page(&self, limit: u32, offset: u32) -> Result<Vec<IngestLogRow>, StoreError>;
        /// Inserts a release with its files and FTS row (and the `ingest_log` row when `log` is given)
        /// in one transaction, recording the uploader (`release.added_by`, `ingest_log.user_id`) after
        /// re-validating it in that transaction.
        fn insert_release_as(
            &self,
            new: &NewRelease<'_>,
            log: Option<&IngestLogEntry<'_>>,
            uploader: &Uploader,
        ) -> Result<i64, StoreError>;
        /// One ingest commit group (T114): every job in one transaction, per-job outcomes in item order; on SQLite
        /// the writer is held at most `hold` (the rest is [`GroupOutcome::Deferred`]).
        fn insert_release_group(
            &self,
            items: &[GroupItem<'_>],
            hold: Duration,
        ) -> Result<Vec<GroupOutcome>, StoreError>;
        /// Time of the newest `ok` ingest log row, if any.
        fn last_ok_ingest_ts(&self) -> Result<Option<i64>, StoreError>;
        /// Files of a release in NZB order (all of them; prefer [`Self::list_files_page`] in the UI).
        fn list_files(&self, release_id: i64) -> Result<Vec<ReleaseFile>, StoreError>;
        /// `limit` files of a release starting at row `offset`, in NZB order (SQL `LIMIT/OFFSET`).
        fn list_files_page(
            &self,
            release_id: i64,
            offset: u32,
            limit: u32,
        ) -> Result<Vec<ReleaseFile>, StoreError>;
        /// Newest-first `ingest_log` rows (at most `limit`, capped at 500).
        fn list_ingest_log(&self, limit: u32) -> Result<Vec<IngestLogRow>, StoreError>;
        /// Newest-first `ingest_log` rows (at most `limit`, capped at 500) that do not belong to a
        /// release whose category id is in `exclude`.
        fn list_ingest_log_excluding(
            &self,
            limit: u32,
            exclude: &[u32],
        ) -> Result<Vec<IngestLogRow>, StoreError>;
        /// Up to `limit` distinct newsgroups across all files of a release, sorted.
        fn list_release_groups(&self, release_id: i64, limit: u32) -> Result<Vec<String>, StoreError>;
        /// SHA-256 of every release row.
        fn list_shas(&self) -> Result<HashSet<Sha256>, StoreError>;
        /// Newest-first listing of deleted releases, at most `limit` (capped at 10 000).
        fn list_trash(&self, limit: u32) -> Result<Vec<TrashRow>, StoreError>;
        /// Appends an `ingest_log` row (duplicate/failed outcome) attributed to `uploader`.
        fn log_ingest_as(
            &self,
            e: &IngestLogEntry<'_>,
            release_id: Option<i64>,
            uploader: &Uploader,
        ) -> Result<(), StoreError>;
        /// `ingested_at` of the newest release row (`None` for an empty database).
        fn newest_ingested_at(&self) -> Result<Option<i64>, StoreError>;
        /// The uploader of a release as the detail page shows it; `None` when the release does not
        /// exist.
        fn release_attribution(
            &self,
            release_id: i64,
        ) -> Result<Option<ReleaseAttribution>, StoreError>;
        /// Which of `ids` are releases whose category id is in `exclude` (at most 500 ids are
        /// considered).
        fn release_ids_in_categories(
            &self,
            ids: &[i64],
            exclude: &[u32],
        ) -> Result<HashSet<i64>, StoreError>;
        /// At most `limit` release digests (lowest ids first) and whether more exist.
        fn release_shas_limited(&self, limit: u32) -> Result<(HashSet<Sha256>, bool), StoreError>;
        /// Release, file and byte totals for the admin page.
        fn release_totals(&self) -> Result<ReleaseTotals, StoreError>;
        /// Like [`Self::release_totals`] but ignoring releases whose category id is in `exclude` (display
        /// rule `ui.show_xxx = false`).
        fn release_totals_excluding(&self, exclude: &[u32]) -> Result<ReleaseTotals, StoreError>;
        /// Releases and bytes of every non-empty category, exact (`category_stats`; the Statistics page, T132).
        fn category_stats_list(&self) -> Result<Vec<CategoryTotals>, StoreError>;
        /// Manual category override by an admin (D26 c, D40).
        fn set_category_as(
            &self,
            actor: &AccountActor,
            release_id: i64,
            category_id: u32,
            ip: Option<&str>,
            now: i64,
        ) -> Result<u32, StoreError>;
        /// Sets or clears the source label of any release (admin, D40).
        fn set_source_label_as(
            &self,
            actor: &AccountActor,
            release_id: i64,
            label: Option<&str>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<Option<String>, StoreError>;
        /// Like [`Self::trash_release_as`], but only while the release still has the digest the admin
        /// confirmed (ids are reusable rowids).
        fn trash_release_checked_as(
            &self,
            actor: &AccountActor,
            id: i64,
            expected: &Sha256,
            now: i64,
            ip: Option<&str>,
        ) -> Result<TrashRow, StoreError>;
        /// Whether a deleted release with this digest is in the trash (review 38 L1).
        fn release_is_trashed(&self, sha: &Sha256) -> Result<bool, StoreError>;
        /// Digests of every deleted release (the set of trash blobs that have a record).
        fn trash_shas(&self) -> Result<HashSet<Sha256>, StoreError>;
        /// Re-validates `uploader` without writing anything (T101b).
        fn validate_uploader(&self, uploader: &Uploader, now: i64) -> Result<(), StoreError>;
    }
}

repo! {
    /// Audit append, chain walk, anchor and the recent-events view.
    pub trait AuditRepo {
        /// Applies the retention policy in force: cutoffs from the policy and the database clock, chain prefixes
        /// only (SEC-081), floors enforced by the database (SEC-093 / SEC-103).
        fn purge_logs(&self) -> Result<PurgeReport, StoreError>;
        /// The retention policy in force.
        fn retention_policy(&self) -> Result<RetentionPolicy, StoreError>;
        /// The recorded head hash of each chain class and the stored row count.
        fn audit_anchor(&self) -> Result<AuditAnchor, StoreError>;
        /// Row counts and head hashes against the stored state, without walking the chain.
        fn audit_chain_quick(&self) -> Result<ChainQuick, StoreError>;
        /// Appends an audit row with the full actor identity (inside the account-domain rules).
        fn audit_entry(&self, entry: &AuditEntry<'_>, now: i64) -> Result<(), StoreError>;
        /// Appends an audit row at most once per `window_secs` per account (the actor's, else the
        /// target's id).
        fn audit_entry_throttled(
            &self,
            entry: &AuditEntry<'_>,
            window_secs: i64,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Appends an audit event (SEC-033).
        fn audit_event(
            &self,
            now: i64,
            actor: Option<&str>,
            event: &str,
            detail: Option<&str>,
            ip: Option<&str>,
        ) -> Result<(), StoreError>;
        /// Walks every audit row in id order in one read snapshot, verifies the chain and calls
        /// `on_row` for rows with `ts >= since`.
        fn audit_walk(
            &self,
            since: Option<i64>,
            on_row: &mut (dyn FnMut(&AuditExportRow) + Send),
        ) -> Result<ChainReport, StoreError>;
        /// The newest audit events, newest first (`limit` is clamped to 500).
        fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>, StoreError>;
        /// One page of the audit log, newest first, keyset-paged by id (T138; `limit` clamped to 1..=200).
        /// A pure read.
        fn audit_page(&self, filter: &AuditFilter) -> Result<Vec<AuditRow>, StoreError>;
    }
}

repo! {
    /// Health facts, checks, schema state and restore-finish.
    pub trait OpsRepo {
        /// A restored database that `serve` refuses until `nzbd db restore-finish` (SEC-094).
        fn restore_pending(&self) -> Result<bool, StoreError>;
        /// The current restore-detection anchor values with the library identity (one read snapshot).
        fn capture_anchor(&self) -> Result<DbAnchor, StoreError>;
        /// Compares the database with an anchor taken earlier: `LIBRARY_MISMATCH` for another library,
        /// `RESTORE_DETECTED` for a database behind it (SEC-094, SEC-101).
        fn check_anchor(&self, anchored: &DbAnchor) -> Result<AnchorVerdict, StoreError>;
        /// True when the library holds no account and no release.
        fn library_is_empty(&self) -> Result<bool, StoreError>;
        /// `PRAGMA quick_check` and `foreign_key_check` on a **reader** connection (read-only file
        /// handle).
        fn deep_db_check(&self) -> Result<DeepDbReport, StoreError>;
        /// Row counts of the two log tables and the ingest time span.
        fn log_counts(&self) -> Result<LogCounts, StoreError>;
        /// Cheap reader round trip for the admin health row.
        fn ping(&self) -> Result<(), StoreError>;
        /// `SELECT 1` on the writer connection.
        fn ping_writer(&self) -> Result<(), StoreError>;
        /// Destroys sessions, open invitations, recovery codes, staging and throttle state and revokes
        /// every API key, in one transaction with one audit row.
        fn restore_finish(&self, now: i64, dry_run: bool) -> Result<RestoreFinishReport, StoreError>;
        /// Every account (tombstones included) with role and state, oldest first.
        fn restore_finish_accounts(&self) -> Result<Vec<RestoredAccount>, StoreError>;
        /// Applied versus embedded migrations.
        fn schema_info(&self) -> Result<SchemaInfo, StoreError>;
        /// Account, session and key facts at `now`; failed logins are counted from `since`.
        fn security_facts(&self, now: i64, since: i64) -> Result<SecurityFacts, StoreError>;
    }
}

/// The 1.x/2.x un-actored writers and steps that production no longer calls (review 35 I3): every one has an actored,
/// re-checking successor on the seam above (`*_as`, `*_v2`, `insert_release_attributed`, ...). They stay only as
/// test fixtures (seeding rows, driving a step directly) and are compiled into the seam only for tests
/// (`cfg(test)` or the `pg-test-support` feature), so production code cannot reach them through [`Store`].
#[cfg(any(test, feature = "pg-test-support"))]
mod fixtures {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    repo! {
        /// Test fixtures over both backends (see the module docs).
        pub trait FixtureRepo {
        /// Moves release `id` (row, files, FTS entry) into `release_trash` and writes the audit row,
        /// all in one transaction.
        fn trash_release(
            &self,
            id: i64,
            now: i64,
            actor: &str,
            ip: Option<&str>,
        ) -> Result<TrashRow, StoreError>;
        /// Moves a release to the trash on an ADMIN's authority (SEC-050 v2).
        fn trash_release_as(
            &self,
            actor: &AccountActor,
            id: i64,
            now: i64,
            ip: Option<&str>,
        ) -> Result<TrashRow, StoreError>;
        /// Manually set the category (marks `category_overridden` and source `manual`).
        fn set_category(&self, id: i64, category_id: u32) -> Result<(), StoreError>;
        /// Insert a release,its files and its FTS row in one transaction.
        fn insert_release(&self, new: &NewRelease<'_>) -> Result<i64, StoreError>;
        /// Like [`Self::insert_release`], and writes the `ingest_log` row (outcome `ok`, linked to the
        /// new release) in the **same transaction** (`INGEST_SPEC` step 6).
        fn insert_release_logged(
            &self,
            new: &NewRelease<'_>,
            log: &IngestLogEntry<'_>,
        ) -> Result<i64, StoreError>;
        /// Deletes a release with its files in one transaction (search index updated through the backend).
        fn delete_release(&self, id: i64) -> Result<(), StoreError>;
        /// Creates the first and only account (1.x provisioning, kept for the single-user CLI path).
        fn create_user(&self, username: &str, password_hash: &str, now: i64) -> Result<i64, StoreError>;
        /// Clears TOTP of the only live account (1.x `user reset-mfa`); see [`Self::reset_mfa_for`].
        fn reset_mfa(&self, now: i64) -> Result<(), StoreError>;
        /// Replaces the password hash of the only live account (1.x `user reset-password`); see
        /// [`Self::reset_password_for`].
        fn reset_password(&self, password_hash: &str, now: i64) -> Result<(), StoreError>;
        /// Decides the password step in ONE writer transaction, after verification (SEC-026).
        fn login_password_step(
            &self,
            user_id: Option<i64>,
            verified: bool,
            fail_reason: &str,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Decides one second-factor attempt (see the module docs).
        fn second_factor_step(&self, a: FactorAttempt<'_>) -> Result<bool, StoreError>;
        /// Checks the enrollment token in one writer transaction (lock re-read, failure counted in the
        /// shared lockout counter, audit row in every branch).
        fn check_enrollment_token(
            &self,
            user_id: i64,
            token_hash: Option<[u8; 32]>,
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Confirms first-time enrollment in one transaction (pending secret becomes active, replay
        /// floor, recovery codes).
        fn confirm_totp_enrollment(
            &self,
            user_id: i64,
            sealed: &[u8],
            token_hash: Option<[u8; 32]>,
            step: Option<i64>,
            recovery_hashes: &[[u8; 32]],
            ip: Option<&str>,
            now: i64,
        ) -> Result<bool, StoreError>;
        /// Counts one failed attempt (password or second factor) and applies the progressive lock.
        fn record_login_failure(&self, user_id: i64, now: i64) -> Result<Option<i64>, StoreError>;
        /// Clears the failure counter and any lock after a *fully completed* authentication.
        fn record_login_success(&self, user_id: i64) -> Result<(), StoreError>;
        /// Append one `ingest_log` row (duplicate / failed outcomes; `ok` rows are written together
        /// with the release by [`Self::insert_release_logged`]).
        fn log_ingest(&self, e: &IngestLogEntry<'_>, release_id: Option<i64>) -> Result<(), StoreError>;
        /// Arms enrollment.
        fn set_enrollment_token(
            &self,
            token_hash: &[u8; 32],
            expires_at: i64,
            now: i64,
        ) -> Result<bool, StoreError>;
        }
    }
}
#[cfg(any(test, feature = "pg-test-support"))]
pub use fixtures::FixtureRepo;
