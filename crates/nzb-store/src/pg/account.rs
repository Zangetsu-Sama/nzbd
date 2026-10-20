//! Accounts, roles, display names and audit attribution on Postgres (T112; 2.x `account.rs`, SEC-060..SEC-068).
//!
//! Same rules and the same public API as the 2.x module; the 2.x single writer (`BEGIN IMMEDIATE`) becomes the
//! account-domain advisory lock taken first in every mutating transaction ([`PgDb::begin_account`], ARCHITECTURE v3
//! section 6), and the last-admin trigger takes the same lock itself. Audit rows are appended last
//! ([`crate::pg::audit::append`]), so the audit class lock is the last lock of every transaction.

use sqlx::{PgConnection, Row};

use crate::account::{
    AccountActor, AccountError, AccountPolicy, AccountRow, AuditActor, AuditEntry, ChosenProfile,
    FAILURE_EVENTS, GrantableRole, ID_EVENTS, NAME_EVENTS, NewAccount, ReservedKind,
    ReservedLoginAccount, Role, Subject, TOMBSTONE_PASSWORD_HASH, ThrottleKey, check_login_name,
    default_handle, display_name_is_valid, foreign_handle_form, is_reserved_actor_name,
    is_reserved_handle_form, role_from,
};
use crate::pg::PgDb;
use crate::{SessionStage, StoreError};

/// The Users-page column list (a macro so complete statements stay compile-time literals, SEC-088).
macro_rules! account_select {
    () => {
        "SELECT u.id, u.username, u.display_name, u.role, u.disabled_at, \
    u.deleted_at, u.created_at, u.created_by, u.last_login_at, u.totp_enabled, \
    u.credentials_replaced_at, u.credentials_replaced_by, \
    (SELECT s.created_at FROM credential_staging s WHERE s.account_id = u.id) AS staged_at, u.email \
    FROM account u"
    };
}

/// Loads a LIVE account (tombstones are "not found").
pub(crate) async fn load_live(
    conn: &mut PgConnection,
    id: i64,
) -> Result<Option<Subject>, StoreError> {
    let row = sqlx::query(
        "SELECT id, username, role, disabled_at FROM account \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|r| {
        Ok(Subject {
            id: r.try_get("id")?,
            role: role_from(&r.try_get::<String, _>("role")?)?,
            username: r.try_get("username")?,
            disabled: r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
        })
    })
    .transpose()
}

/// Re-validates an acting account inside the transaction: live and enabled, and at least `min` by the
/// role stored in the database (not the one the struct claims).
pub(crate) async fn require_actor(
    conn: &mut PgConnection,
    actor_id: i64,
    min: Role,
) -> Result<Subject, StoreError> {
    match load_live(conn, actor_id).await? {
        Some(s) if !s.disabled && s.role >= min => Ok(s),
        _ => Err(AccountError::Forbidden.into()),
    }
}

/// [`require_actor`] for an actor built from a session: that session must also still exist (a recovery, reset,
/// revocation or role change deletes it), so a re-authenticated write never outlives the session that proved it.
pub(crate) async fn require_session_actor(
    conn: &mut PgConnection,
    actor: &AccountActor,
    min: Role,
    now: i64,
) -> Result<Subject, StoreError> {
    let s = require_actor(conn, actor.user_id, min).await?;
    if let Some(h) = &actor.session
        && !crate::pg::auth::session_is_live(conn, h, actor.user_id, now).await?
    {
        return Err(AccountError::Forbidden.into());
    }
    Ok(s)
}

/// Appends an audit row on `conn` (same transaction as the change it describes).
pub(crate) async fn write_audit(
    conn: &mut PgConnection,
    who: &AuditActor,
    now: i64,
    event: &str,
    detail: Option<&str>,
    ip: Option<&str>,
    target_id: Option<i64>,
) -> Result<(), StoreError> {
    crate::pg::audit::append(
        conn,
        &crate::audit_chain::AuditContent {
            ts: now,
            actor: who.actor.as_deref(),
            event,
            detail,
            ip,
            actor_id: who.actor_id,
            actor_kind: Some(who.kind),
            actor_role: who.role,
            target_id,
        },
    )
    .await
}

/// `(id, role)` of the account with this login name (tombstones never match: their name is
/// `~deleted~<id>`, outside the login charset).
async fn account_by_name(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<(i64, Role)>, StoreError> {
    let row = sqlx::query("SELECT id, role FROM account WHERE lower(username) = lower($1)")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    row.map(|r| {
        Ok((
            r.try_get("id")?,
            role_from(&r.try_get::<String, _>("role")?)?,
        ))
    })
    .transpose()
}

/// Writes an audit row for a caller that still passes the 1.x actor TEXT (`audit_event`, the 1.x
/// verdict functions, key and trash helpers): the identity columns are derived from the event class and
/// the actor text exactly like the migration backfill does, so rows written by 1.x-shaped callers are
/// attributed correctly without the caller changing. A failure row keeps the actor text (a display
/// snapshot, as in 1.x) but is `anonymous` with the targeted account in `target_id`.
pub(crate) async fn write_audit_legacy(
    conn: &mut PgConnection,
    now: i64,
    actor: Option<&str>,
    event: &str,
    detail: Option<&str>,
    ip: Option<&str>,
) -> Result<(), StoreError> {
    let mut who = AuditActor {
        actor: actor.map(str::to_owned),
        actor_id: None,
        kind: "",
        role: None,
    };
    let mut target: Option<i64> = None;
    let mut kind: Option<&'static str> = None;
    if NAME_EVENTS.contains(&event) {
        if let Some(name) = actor
            && let Some((id, role)) = account_by_name(conn, name).await?
        {
            who.actor_id = Some(id);
            who.role = Some(role.as_str());
            kind = Some("user");
        }
    } else if FAILURE_EVENTS.contains(&event) {
        kind = Some("anonymous");
        if event != "apikey.use_failure"
            && let Some(name) = actor
            && let Some((id, _)) = account_by_name(conn, name).await?
        {
            target = Some(id);
        }
    } else if actor == Some("cli") {
        kind = Some("cli");
    } else if ID_EVENTS.contains(&event)
        && let Some(id) = actor
            .and_then(|a| a.strip_prefix("user:"))
            .and_then(|n| n.parse::<i64>().ok())
        && let Some(s) = load_live(conn, id).await?
    {
        who.actor_id = Some(s.id);
        who.role = Some(s.role.as_str());
        kind = Some("user");
    }
    if let Some(k) = kind {
        who.kind = k;
        return write_audit(conn, &who, now, event, detail, ip, target).await;
    }
    // Unknown shape: keep the 1.x row as it was (kind NULL = "unknown").
    crate::pg::audit::append(
        conn,
        &crate::audit_chain::AuditContent {
            ts: now,
            actor,
            event,
            detail,
            ip,
            actor_id: None,
            actor_kind: None,
            actor_role: None,
            target_id: None,
        },
    )
    .await
}

/// Appends an audit row unless a row of the same `event` already exists for the same `key` (the account
/// id for account events, an address for pre-authentication events) within `window_secs`. Returns
/// whether a row was written. Used for the high-volume events (`authz_denied` 1/min per account,
/// `account_throttled` 1/h, `invite_redeem_failure` 1/min per address).
pub(crate) async fn write_audit_throttled(
    conn: &mut PgConnection,
    entry: &AuditEntry<'_>,
    key: ThrottleKey<'_>,
    window_secs: i64,
    now: i64,
) -> Result<bool, StoreError> {
    let since = now.saturating_sub(window_secs);
    let recent: i64 = match key {
        ThrottleKey::Account(id) => {
            sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE event = $1 AND ts > $2 \
                 AND (actor_id = $3 OR target_id = $3)",
            )
            .bind(entry.event)
            .bind(since)
            .bind(id)
            .fetch_one(&mut *conn)
            .await?
        }
        ThrottleKey::Address(ip) => {
            sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE event = $1 AND ts > $2 AND ip IS NOT DISTINCT FROM $3",
            )
            .bind(entry.event)
            .bind(since)
            .bind(ip)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    if recent > 0 {
        return Ok(false);
    }
    write_audit(
        conn,
        &entry.who,
        now,
        entry.event,
        entry.detail,
        entry.ip,
        entry.target_id,
    )
    .await?;
    Ok(true)
}

/// Maps the trigger aborts of `v3/0002_core.sql` and the NOCASE unique index onto stable errors; anything else stays a
/// database error (SEC-097: the server's message is matched, never forwarded).
pub(crate) fn map_trigger(e: sqlx::Error) -> StoreError {
    let (msg, constraint) = match &e {
        sqlx::Error::Database(d) => (d.message().to_owned(), d.constraint().map(str::to_owned)),
        _ => (String::new(), None),
    };
    if msg.contains("LAST_ADMIN") {
        AccountError::LastAdmin.into()
    } else if msg.contains("RESERVED_LOGIN_NAME") {
        AccountError::ReservedName.into()
    } else if msg.contains("ACCOUNT_ROWS_ARE_NEVER_REPLACED")
        || constraint.as_deref() == Some("account_username")
    {
        AccountError::UsernameUnavailable.into()
    } else {
        StoreError::Db(e)
    }
}

/// Number of live accounts.
pub(crate) async fn count_live(conn: &mut PgConnection) -> Result<i64, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM account WHERE deleted_at IS NULL")
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// True if `name` equals (NOCASE) a live display name.
pub(crate) async fn display_name_in_use(
    conn: &mut PgConnection,
    name: &str,
    except_id: Option<i64>,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account WHERE lower(display_name) = lower($1) \
         AND deleted_at IS NULL AND id IS DISTINCT FROM $2",
    )
    .bind(name)
    .bind(except_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// True if `name` has the same confusable skeleton ([`crate::display_name_skeleton`]) as a live display name other
/// than `except_id`'s (`SECURITY_REVIEW` 26 L2). Computed in Rust over the live display names inside the caller's
/// transaction: no stored skeleton column and no migration, because the live accounts are capped
/// (`security.max_accounts`, at most a few hundred rows); a stored, indexed skeleton is the path if that cap is lifted.
pub(crate) async fn confusable_display_name_in_use(
    conn: &mut PgConnection,
    name: &str,
    except_id: Option<i64>,
) -> Result<bool, StoreError> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT display_name FROM account WHERE display_name IS NOT NULL AND deleted_at IS NULL \
         AND id IS DISTINCT FROM $1",
    )
    .bind(except_id)
    .fetch_all(&mut *conn)
    .await?;
    let wanted = crate::display_name_skeleton(name);
    Ok(names
        .iter()
        .any(|n| crate::display_name_skeleton(n) == wanted))
}

/// True if `name` equals (NOCASE) any live login name.
pub(crate) async fn login_name_in_use(
    conn: &mut PgConnection,
    name: &str,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account WHERE lower(username) = lower($1) AND deleted_at IS NULL",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Picks the default handle for `id` (N5): `user-<id>`, else `acct-<id>`, `acct-<id>-1`, ... until it
/// equals no live login name and no live display name.
async fn pick_handle(conn: &mut PgConnection, id: i64) -> Result<String, StoreError> {
    let mut candidates = vec![default_handle(id), format!("acct-{id}")];
    for n in 1..=8 {
        candidates.push(format!("acct-{id}-{n}"));
    }
    for c in candidates {
        if !login_name_in_use(conn, &c).await? && !display_name_in_use(conn, &c, Some(id)).await? {
            return Ok(c);
        }
    }
    // Unreachable in practice (ids are unique); NULL renders as `user-<id>`.
    Err(StoreError::OutOfRange("display handle"))
}

/// Inserts an account row with its default handle. The caller has done the policy checks.
pub(crate) async fn insert_account(
    conn: &mut PgConnection,
    username: &str,
    password_hash: &str,
    role: Role,
    created_by: Option<i64>,
    now: i64,
) -> Result<i64, StoreError> {
    insert_account_with(conn, username, password_hash, role, created_by, None, now).await
}

/// [`insert_account`] with an optional chosen profile: without one the account gets its default handle and no
/// email (every creation path except invite redemption).
pub(crate) async fn insert_account_with(
    conn: &mut PgConnection,
    username: &str,
    password_hash: &str,
    role: Role,
    created_by: Option<i64>,
    profile: Option<ChosenProfile<'_>>,
    now: i64,
) -> Result<i64, StoreError> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO account (username, password_hash, role, created_by, created_at, password_changed_at, \
         display_name, email) VALUES ($1, $2, $3, $4, $5, $5, $6, $7) RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role.as_str())
    .bind(created_by)
    .bind(now)
    .bind(profile.map(|p| p.display_name))
    .bind(profile.map(|p| p.email))
    .fetch_one(&mut *conn)
    .await
    .map_err(map_trigger)?;
    if profile.is_some() {
        return Ok(id);
    }
    let handle = pick_handle(conn, id).await?;
    sqlx::query("UPDATE account SET display_name = $2 WHERE id = $1")
        .bind(id)
        .bind(handle)
        .execute(&mut *conn)
        .await?;
    Ok(id)
}

/// Another live, enabled admin must remain, and one of them must have MFA enrolled.
async fn ensure_other_usable_admin(
    conn: &mut PgConnection,
    except_id: i64,
) -> Result<(), StoreError> {
    let (others, usable): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE totp_enabled) FROM account \
         WHERE id <> $1 AND role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL",
    )
    .bind(except_id)
    .fetch_one(&mut *conn)
    .await?;
    if others == 0 {
        Err(AccountError::LastAdmin.into())
    } else if usable == 0 {
        Err(AccountError::LastUsableAdmin.into())
    } else {
        Ok(())
    }
}

/// Revokes every open recovery code issued FOR `user_id` and every open token issued BY it, and drops a
/// staged swap of `user_id`. Returns the number of revoked codes.
async fn revoke_tokens_around(
    conn: &mut PgConnection,
    user_id: i64,
    revoke_issued_by: bool,
    now: i64,
) -> Result<u64, StoreError> {
    let mut n = sqlx::query(
        "UPDATE invite SET revoked_at = $2 WHERE purpose = 'recover' AND account_id = $1 \
         AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if revoke_issued_by {
        n = n.saturating_add(
            sqlx::query(
                "UPDATE invite SET revoked_at = $2 WHERE created_by = $1 \
                 AND used_at IS NULL AND revoked_at IS NULL",
            )
            .bind(user_id)
            .bind(now)
            .execute(&mut *conn)
            .await?
            .rows_affected(),
        );
    }
    sqlx::query("DELETE FROM credential_staging WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    Ok(n)
}

async fn delete_sessions(conn: &mut PgConnection, user_id: i64) -> Result<u64, StoreError> {
    Ok(sqlx::query("DELETE FROM session WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?
        .rows_affected())
}

/// Who performs a lifecycle action: a re-validated admin session or the operator.
#[derive(Clone, Copy)]
enum Initiator<'a> {
    Account(&'a AccountActor),
    Operator,
}

/// A lifecycle action on an account.
#[derive(Clone, Copy)]
enum Action {
    SetRole(Role),
    Disable,
    Enable,
    Tombstone,
    Unlock,
    RevokeSessions,
}

/// Resolved initiator inside a transaction.
struct Resolved {
    who: AuditActor,
    actor_id: Option<i64>,
}

async fn resolve(
    conn: &mut PgConnection,
    init: Initiator<'_>,
    now: i64,
) -> Result<Resolved, StoreError> {
    match init {
        Initiator::Operator => Ok(Resolved {
            who: AuditActor::cli(),
            actor_id: None,
        }),
        Initiator::Account(a) => {
            let s = require_session_actor(conn, a, Role::Admin, now).await?;
            Ok(Resolved {
                who: AuditActor::account(s.id, s.role, &s.username),
                actor_id: Some(s.id),
            })
        }
    }
}

/// Target rules of `AUTH_SPEC` "Target rules": web actors never touch themselves or admins, except
/// `revoke-sessions` on another admin (the caller re-authenticated).
fn check_target_rules(res: &Resolved, target: &Subject, action: Action) -> Result<(), StoreError> {
    let Some(actor_id) = res.actor_id else {
        return Ok(()); // operator
    };
    if target.id == actor_id {
        return Err(AccountError::SelfTarget.into());
    }
    let admin_ok = matches!(action, Action::RevokeSessions);
    if target.role == Role::Admin && !admin_ok {
        return Err(AccountError::AdminIsCliOnly.into());
    }
    Ok(())
}

impl PgDb {
    /// The caller behind a session: one join, rejecting expired sessions and disabled or deleted
    /// accounts (they are "no session"). The role is read from the database on every call (SEC-060).
    ///
    /// # Errors
    /// Database failure.
    pub async fn session_actor(
        &self,
        id_hash: &[u8; 32],
        now: i64,
    ) -> Result<Option<AccountActor>, StoreError> {
        let row = sqlx::query(
            "SELECT u.id, u.username, u.role, u.display_name, s.stage, p.hide_xxx, p.theme, \
             p.page_size_releases, p.page_size_files \
             FROM session s JOIN account u ON u.id = s.account_id \
             LEFT JOIN user_pref p ON p.account_id = u.id \
             WHERE s.id_hash = $1 AND s.expires_at > $2 \
               AND u.disabled_at IS NULL AND u.deleted_at IS NULL",
        )
        .bind(id_hash.as_slice())
        .bind(now)
        .fetch_optional(self.web())
        .await?;
        row.map(|r| {
            let id: i64 = r.try_get("id")?;
            let stage = match r.try_get::<String, _>("stage")?.as_str() {
                "pending_mfa" => SessionStage::PendingMfa,
                "active" => SessionStage::Active,
                _ => return Err(StoreError::OutOfRange("session stage")),
            };
            Ok(AccountActor {
                session: Some(*id_hash),
                user_id: id,
                role: role_from(&r.try_get::<String, _>("role")?)?,
                username: r.try_get("username")?,
                display_name: r
                    .try_get::<Option<String>, _>("display_name")?
                    .unwrap_or_else(|| default_handle(id)),
                stage,
                prefs: crate::UserPrefs::from_columns(crate::pref::PrefColumns {
                    hide_xxx: r.try_get::<Option<bool>, _>("hide_xxx")?,
                    theme: r.try_get::<Option<String>, _>("theme")?.as_deref(),
                    page_size_releases: r.try_get("page_size_releases")?,
                    page_size_files: r.try_get("page_size_files")?,
                })?,
            })
        })
        .transpose()
    }

    /// Creates an account on the operator's authority (`nzbd user create`). `role = None` is accepted
    /// only for the first account, which becomes the admin (SEC-069). A second live account needs
    /// `policy.multi_user`; the live cap is `policy.max_accounts`. Writes `user_create` (actor `cli`).
    ///
    /// # Errors
    /// [`StoreError::InvalidUsername`], [`AccountError::ReservedName`],
    /// [`AccountError::UsernameUnavailable`], [`AccountError::MultiUserDisabled`],
    /// [`AccountError::AccountLimit`], [`AccountError::RoleRequired`].
    pub async fn create_account_operator(
        &self,
        new: &NewAccount<'_>,
        policy: AccountPolicy,
        now: i64,
    ) -> Result<i64, StoreError> {
        check_login_name(new.username)?;
        let mut tx = self.begin_account().await?;
        let live = count_live(&mut tx).await?;
        let role = match (new.role, live) {
            (Some(r), _) => r,
            (None, 0) => Role::Admin,
            (None, _) => return Err(AccountError::RoleRequired.into()),
        };
        if live > 0 && !policy.multi_user {
            return Err(AccountError::MultiUserDisabled.into());
        }
        if live >= i64::from(policy.max_accounts) {
            return Err(AccountError::AccountLimit.into());
        }
        if live == 0 && role != Role::Admin {
            // A database without a live admin must get one first (the operator can always create one).
            return Err(AccountError::RoleRequired.into());
        }
        if login_name_in_use(&mut tx, new.username).await?
            || display_name_in_use(&mut tx, new.username, None).await?
            || open_invite_for_name(&mut tx, new.username, now).await?
        {
            return Err(AccountError::UsernameUnavailable.into());
        }
        let id = insert_account(&mut tx, new.username, new.password_hash, role, None, now).await?;
        let detail = format!("role={}", role.as_str());
        write_audit(
            &mut tx,
            &AuditActor::cli(),
            now,
            "user_create",
            Some(&detail),
            None,
            Some(id),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// One account (live or tombstoned) by id.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_account(&self, id: i64) -> Result<Option<AccountRow>, StoreError> {
        let row = sqlx::query(concat!(account_select!(), " WHERE u.id = $1"))
            .bind(id)
            .fetch_optional(self.web())
            .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// A LIVE account by login name (NOCASE).
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_account_by_username(
        &self,
        username: &str,
    ) -> Result<Option<AccountRow>, StoreError> {
        let row = sqlx::query(concat!(
            account_select!(),
            " WHERE lower(u.username) = lower($1) AND u.deleted_at IS NULL"
        ))
        .bind(username)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// All accounts, oldest first; tombstones only when `include_deleted`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_accounts(
        &self,
        include_deleted: bool,
    ) -> Result<Vec<AccountRow>, StoreError> {
        let rows = sqlx::query(concat!(
            account_select!(),
            " WHERE ($1 OR u.deleted_at IS NULL) ORDER BY u.id"
        ))
        .bind(include_deleted)
        .fetch_all(self.web())
        .await?;
        rows.iter().map(account_from_row).collect()
    }

    /// Number of live accounts (the CLI's "is this the first account" question, I-5).
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_live_accounts(&self) -> Result<u64, StoreError> {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE deleted_at IS NULL")
            .fetch_one(self.web())
            .await?;
        u64::try_from(n).map_err(|_| StoreError::OutOfRange("account count"))
    }

    /// Live 1.x accounts whose login name is reserved (flagged for the startup WARN and the health
    /// WARN; never renamed).
    ///
    /// # Errors
    /// Database failure.
    pub async fn reserved_login_accounts(&self) -> Result<Vec<ReservedLoginAccount>, StoreError> {
        let rows =
            sqlx::query("SELECT id, username FROM account WHERE deleted_at IS NULL ORDER BY id")
                .fetch_all(self.web())
                .await?;
        let mut out = Vec::new();
        for r in &rows {
            let name: String = r.try_get("username")?;
            let kind = if is_reserved_actor_name(&name) {
                Some(ReservedKind::ActorName)
            } else if is_reserved_handle_form(&name) {
                Some(ReservedKind::HandleForm)
            } else {
                None
            };
            if let Some(kind) = kind {
                out.push(ReservedLoginAccount {
                    id: r.try_get("id")?,
                    kind,
                });
            }
        }
        Ok(out)
    }

    /// Changes uploader <-> viewer (admin session, re-authenticated by the caller). Revokes the target's
    /// sessions, its open recovery codes and its staged swap, and on a demotion to viewer its API keys; audit
    /// `role_change` with old and new role and the revoked counts.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`], [`AccountError::SelfTarget`],
    /// [`AccountError::AdminIsCliOnly`], [`AccountError::InvalidState`] (already that role).
    pub async fn set_role(
        &self,
        actor: &AccountActor,
        target_id: i64,
        role: GrantableRole,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::SetRole(role.into()),
            ip,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Operator role change, the only way to grant or take away `admin` (D26 b). Last-usable-admin rule
    /// applies; audit actor `cli`.
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`], [`AccountError::InvalidState`], [`AccountError::LastAdmin`],
    /// [`AccountError::LastUsableAdmin`].
    pub async fn set_role_operator(
        &self,
        target_id: i64,
        role: Role,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Operator,
            target_id,
            Action::SetRole(role),
            None,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Disables a uploader/viewer (admin session): sessions revoked, staged swap and codes revoked,
    /// invitations it issued revoked; its API keys stop working because use checks the owner.
    ///
    /// # Errors
    /// As [`SqliteDb::set_role`]; [`AccountError::InvalidState`] when already disabled.
    pub async fn disable_account(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::Disable,
            ip,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Operator disable of any account (last-usable-admin rule applies).
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`], [`AccountError::InvalidState`], [`AccountError::LastAdmin`],
    /// [`AccountError::LastUsableAdmin`].
    pub async fn disable_account_operator(
        &self,
        target_id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(Initiator::Operator, target_id, Action::Disable, None, now)
            .await
            .map(|_| ())
    }

    /// Re-enables a disabled uploader/viewer (admin session, re-authenticated by the caller).
    ///
    /// # Errors
    /// As [`SqliteDb::set_role`]; [`AccountError::InvalidState`] when not disabled.
    pub async fn enable_account(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::Enable,
            ip,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Operator enable of any account.
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`], [`AccountError::InvalidState`].
    pub async fn enable_account_operator(
        &self,
        target_id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(Initiator::Operator, target_id, Action::Enable, None, now)
            .await
            .map(|_| ())
    }

    /// Tombstones a DISABLED uploader/viewer (admin session, re-authenticated by the caller): credentials,
    /// sessions, recovery codes and staged swap removed, owned keys revoked, issued invitations and
    /// recovery codes revoked, `username` freed (`~deleted~<id>`). The row stays.
    ///
    /// # Errors
    /// As [`SqliteDb::set_role`]; [`AccountError::NotDisabled`].
    pub async fn delete_account(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::Tombstone,
            ip,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Operator tombstone of a disabled account (last-usable-admin rule applies to admins).
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`], [`AccountError::NotDisabled`], [`AccountError::LastAdmin`],
    /// [`AccountError::LastUsableAdmin`].
    pub async fn delete_account_operator(
        &self,
        target_id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(Initiator::Operator, target_id, Action::Tombstone, None, now)
            .await
            .map(|_| ())
    }

    /// Clears every lock row and the persisted throttle counters of a uploader/viewer (admin session).
    ///
    /// # Errors
    /// As [`SqliteDb::set_role`].
    pub async fn unlock_account(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::Unlock,
            ip,
            now,
        )
        .await
        .map(|_| ())
    }

    /// Operator `user unlock`: also clears the persisted aggregate (SEC-070).
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`].
    pub async fn unlock_account_operator(
        &self,
        target_id: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lifecycle(Initiator::Operator, target_id, Action::Unlock, None, now)
            .await
            .map(|_| ())
    }

    /// Revokes every session of another account (admin session; the web layer re-authenticates when the
    /// target is an admin, the only HTTP action on an admin). Returns the number revoked.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`], [`AccountError::SelfTarget`].
    pub async fn revoke_account_sessions(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<u64, StoreError> {
        self.lifecycle(
            Initiator::Account(actor),
            target_id,
            Action::RevokeSessions,
            ip,
            now,
        )
        .await
    }

    /// Operator `user revoke-sessions`. Returns the number revoked.
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`].
    pub async fn revoke_account_sessions_operator(
        &self,
        target_id: i64,
        now: i64,
    ) -> Result<u64, StoreError> {
        self.lifecycle(
            Initiator::Operator,
            target_id,
            Action::RevokeSessions,
            None,
            now,
        )
        .await
    }

    /// The single transaction behind the lifecycle writers.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    async fn lifecycle(
        &self,
        init: Initiator<'_>,
        target_id: i64,
        action: Action,
        ip: Option<&str>,
        now: i64,
    ) -> Result<u64, StoreError> {
        let mut tx = self.begin_account().await?;
        let res = resolve(&mut tx, init, now).await?;
        let target = load_live(&mut tx, target_id)
            .await?
            .ok_or(AccountError::TargetNotFound)?;
        check_target_rules(&res, &target, action)?;
        let removes_admin_power = target.role == Role::Admin && !target.disabled;
        let (event, detail, count) = match action {
            Action::SetRole(new) => {
                if new == target.role {
                    return Err(AccountError::InvalidState.into());
                }
                if removes_admin_power {
                    ensure_other_usable_admin(&mut tx, target.id).await?;
                }
                sqlx::query("UPDATE account SET role = $2 WHERE id = $1")
                    .bind(target.id)
                    .bind(new.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(map_trigger)?;
                let sessions = delete_sessions(&mut tx, target.id).await?;
                // Any code issued for the target, or by it (a demoted admin's invitations), dies.
                revoke_tokens_around(&mut tx, target.id, target.role == Role::Admin, now).await?;
                // A viewer cannot use a key (the owner's role is checked on use), so a demotion to viewer revokes its
                // keys in the same transaction: a later promotion must not silently revive them (T134 review I5).
                let keys = if new == Role::Viewer {
                    sqlx::query(
                        "UPDATE api_key SET revoked_at = $2 WHERE owner_id = $1 AND revoked_at IS NULL",
                    )
                    .bind(target.id)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                } else {
                    0
                };
                (
                    "role_change",
                    format!(
                        "old={} new={} sessions_revoked={sessions} keys_revoked={keys}",
                        target.role.as_str(),
                        new.as_str()
                    ),
                    sessions,
                )
            }
            Action::Disable => {
                if target.disabled {
                    return Err(AccountError::InvalidState.into());
                }
                if removes_admin_power {
                    ensure_other_usable_admin(&mut tx, target.id).await?;
                }
                sqlx::query("UPDATE account SET disabled_at = $2 WHERE id = $1")
                    .bind(target.id)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_trigger)?;
                let sessions = delete_sessions(&mut tx, target.id).await?;
                let codes = revoke_tokens_around(&mut tx, target.id, true, now).await?;
                (
                    "user_disable",
                    format!("sessions_revoked={sessions} codes_revoked={codes}"),
                    sessions,
                )
            }
            Action::Enable => {
                if !target.disabled {
                    return Err(AccountError::InvalidState.into());
                }
                sqlx::query("UPDATE account SET disabled_at = NULL WHERE id = $1")
                    .bind(target.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_trigger)?;
                ("user_enable", String::from("ok"), 0)
            }
            Action::Tombstone => {
                if !target.disabled {
                    return Err(AccountError::NotDisabled.into());
                }
                let (sessions, codes, keys) = tombstone(&mut tx, target.id, now).await?;
                (
                    "user_delete",
                    format!(
                        "sessions_revoked={sessions} codes_revoked={codes} keys_revoked={keys}"
                    ),
                    sessions,
                )
            }
            Action::Unlock => {
                clear_throttle_state(&mut tx, target.id).await?;
                ("user_unlock", String::from("ok"), 0)
            }
            Action::RevokeSessions => {
                let sessions = delete_sessions(&mut tx, target.id).await?;
                ("sessions_revoke", format!("count={sessions}"), sessions)
            }
        };
        write_audit(
            &mut tx,
            &res.who,
            now,
            event,
            Some(&detail),
            ip,
            Some(target.id),
        )
        .await?;
        tx.commit().await?;
        Ok(count)
    }

    /// Ids of the accounts that are throttled or locked right now (a hard lock at any address, the
    /// aggregate or the daily second-factor refusal): the Users page "Locked" status (T101b).
    ///
    /// # Errors
    /// Database failure.
    pub async fn locked_account_ids(&self, now: i64) -> Result<Vec<i64>, StoreError> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT account_id FROM login_lock WHERE coalesce(locked_until, 0) > $1 \
             UNION SELECT account_id FROM account_throttle WHERE coalesce(throttled_until, 0) > $1 \
             OR coalesce(mfa_refused_until, 0) > $1",
        )
        .bind(now)
        .fetch_all(self.web())
        .await?;
        Ok(ids)
    }

    /// Number of live (unexpired) sessions per account, for the Users page (T101b).
    ///
    /// # Errors
    /// Database failure.
    pub async fn active_session_counts(&self, now: i64) -> Result<Vec<(i64, i64)>, StoreError> {
        let rows = sqlx::query(
            "SELECT account_id, count(*) AS n FROM session WHERE expires_at > $1 GROUP BY account_id",
        )
        .bind(now)
        .fetch_all(self.web())
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("account_id")?, r.try_get("n")?)))
            .collect()
    }

    /// Ids of the accounts with an `active`, unexpired session whose last request was at or after `since`:
    /// "online now" for the Users page. `last_seen_at` is slid at most once a minute (`TOUCH_INTERVAL_SECS`).
    ///
    /// # Errors
    /// Database failure.
    pub async fn online_account_ids(&self, now: i64, since: i64) -> Result<Vec<i64>, StoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT account_id FROM session \
             WHERE stage = 'active' AND expires_at > $1 AND last_seen_at >= $2",
        )
        .bind(now)
        .bind(since)
        .fetch_all(self.web())
        .await?;
        rows.iter().map(|r| Ok(r.try_get("account_id")?)).collect()
    }

    /// Sets (or with `None` resets to the default handle) an account's display name. Admin session:
    /// target is a uploader/viewer or the admin itself. Rules: [`display_name_is_valid`], unique among live
    /// accounts, not confusable with another live display name ([`crate::display_name_skeleton`]), never a login name, never a reserved actor name, never `user-<n>`/`acct-<n>` of
    /// another id (N5). Audit `user_display_name` with old and new value.
    ///
    /// # Errors
    /// [`AccountError::InvalidDisplayName`], [`AccountError::DisplayNameTaken`],
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`], [`AccountError::AdminIsCliOnly`].
    pub async fn set_display_name(
        &self,
        actor: &AccountActor,
        target_id: i64,
        name: Option<&str>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.set_display_name_inner(Initiator::Account(actor), target_id, name, ip, now)
            .await
    }

    /// Operator `user set-display-name` (any account, admins included).
    ///
    /// # Errors
    /// As [`SqliteDb::set_display_name`] without the actor rules.
    pub async fn set_display_name_operator(
        &self,
        target_id: i64,
        name: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.set_display_name_inner(Initiator::Operator, target_id, name, None, now)
            .await
    }

    async fn set_display_name_inner(
        &self,
        init: Initiator<'_>,
        target_id: i64,
        name: Option<&str>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        if let Some(n) = name
            && !display_name_is_valid(n)
        {
            return Err(AccountError::InvalidDisplayName.into());
        }
        let mut tx = self.begin_account().await?;
        let res = resolve(&mut tx, init, now).await?;
        let target = load_live(&mut tx, target_id)
            .await?
            .ok_or(AccountError::TargetNotFound)?;
        if let Some(actor_id) = res.actor_id
            && target.role == Role::Admin
            && target.id != actor_id
        {
            return Err(AccountError::AdminIsCliOnly.into());
        }
        let new = match name {
            Some(n) => {
                if is_reserved_actor_name(n)
                    || login_name_in_use(&mut tx, n).await?
                    || display_name_in_use(&mut tx, n, Some(target.id)).await?
                    || confusable_display_name_in_use(&mut tx, n, Some(target.id)).await?
                    || foreign_handle_form(n, target.id)
                {
                    return Err(AccountError::DisplayNameTaken.into());
                }
                n.to_owned()
            }
            None => pick_handle(&mut tx, target.id).await?,
        };
        let old: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM account WHERE id = $1")
                .bind(target.id)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("UPDATE account SET display_name = $2 WHERE id = $1")
            .bind(target.id)
            .bind(&new)
            .execute(&mut *tx)
            .await?;
        let detail = format!("old={} new={new}", old.as_deref().unwrap_or("-"));
        write_audit(
            &mut tx,
            &res.who,
            now,
            "user_display_name",
            Some(&detail),
            ip,
            Some(target.id),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Appends an audit row (callers: web handlers for events with no store-side mutation, e.g.
    /// `download`, `invite_redeem_failure`). Never pass secrets.
    ///
    /// # Errors
    /// Database failure.
    pub async fn audit_entry(&self, entry: &AuditEntry<'_>, now: i64) -> Result<(), StoreError> {
        let mut conn = self.web().acquire().await?;
        write_audit(
            &mut conn,
            &entry.who,
            now,
            entry.event,
            entry.detail,
            entry.ip,
            entry.target_id,
        )
        .await
    }

    /// Appends an audit row at most once per `window_secs` per account (the actor's, else the target's
    /// id): the `authz_denied` rate limit (1/min per account). Returns whether a row was written.
    ///
    /// # Errors
    /// Database failure.
    pub async fn audit_entry_throttled(
        &self,
        entry: &AuditEntry<'_>,
        window_secs: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let key = match entry.who.actor_id.or(entry.target_id) {
            Some(id) => ThrottleKey::Account(id),
            None => ThrottleKey::Address(entry.ip),
        };
        let mut tx = self.begin_account().await?;
        let wrote = write_audit_throttled(&mut tx, entry, key, window_secs, now).await?;
        tx.commit().await?;
        Ok(wrote)
    }
}

/// Tombstones `id` (already verified disabled). Returns (sessions, codes, keys) revoked.
async fn tombstone(
    conn: &mut PgConnection,
    id: i64,
    now: i64,
) -> Result<(u64, u64, u64), StoreError> {
    let sessions = delete_sessions(conn, id).await?;
    let codes = revoke_tokens_around(conn, id, true, now).await?;
    sqlx::query("DELETE FROM recovery_code WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let keys = sqlx::query(
        "UPDATE api_key SET revoked_at = $2 WHERE owner_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    clear_throttle_state(conn, id).await?;
    sqlx::query("DELETE FROM user_known_ip WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    // Saved searches are private to the account (T127): they go with it.
    sqlx::query("DELETE FROM saved_search WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    // `~` is outside the login charset, so the freed name can never collide with a live one. The email is PII the
    // tombstone has no use for (D32): it goes with the credentials.
    sqlx::query(
        "UPDATE account SET password_hash = $2, totp_secret_enc = NULL, totp_enabled = false, \
         totp_last_step = NULL, enroll_token_hash = NULL, enroll_token_expires = NULL, \
         username = '~deleted~' || id::text, deleted_at = $3, failed_logins = 0, locked_until = NULL, \
         last_failed_at = NULL, email = NULL WHERE id = $1",
    )
    .bind(id)
    .bind(TOMBSTONE_PASSWORD_HASH)
    .bind(now)
    .execute(&mut *conn)
    .await
    .map_err(map_trigger)?;
    Ok((sessions, codes, keys))
}

/// Deletes the lock rows and the persisted aggregate of an account, and the legacy counters.
pub(crate) async fn clear_throttle_state(
    conn: &mut PgConnection,
    user_id: i64,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM login_lock WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM account_throttle WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE account SET failed_logins = 0, locked_until = NULL, last_failed_at = NULL WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// True when an open (unused, unrevoked, unexpired) invitation reserves `name`.
pub(crate) async fn open_invite_for_name(
    conn: &mut PgConnection,
    name: &str,
    now: i64,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM invite WHERE purpose = 'invite' AND lower(username) = lower($1) \
         AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(name)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

pub(crate) fn account_from_row(r: &sqlx::postgres::PgRow) -> Result<AccountRow, StoreError> {
    Ok(AccountRow {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        display_name: r.try_get("display_name")?,
        role: role_from(&r.try_get::<String, _>("role")?)?,
        disabled_at: r.try_get("disabled_at")?,
        deleted_at: r.try_get("deleted_at")?,
        created_at: r.try_get("created_at")?,
        created_by: r.try_get("created_by")?,
        last_login_at: r.try_get("last_login_at")?,
        totp_enabled: r.try_get("totp_enabled")?,
        credentials_replaced_at: r.try_get("credentials_replaced_at")?,
        credentials_replaced_by: r.try_get("credentials_replaced_by")?,
        recovery_staged_at: r.try_get("staged_at")?,
        email: r.try_get("email")?,
    })
}
