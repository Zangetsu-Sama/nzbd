//! Session and login-throttle repositories (SEC-024, SEC-026) plus audit writes (SEC-033).
//!
//! Only `SHA-256(session_id)` ever reaches this module: raw session ids stay in `nzb-web`.
//! Everything is parameterized SQL; timestamps are unix seconds supplied by the caller so tests
//! stay deterministic.

use sqlx::Row;

use crate::account::Role;
use crate::{SqliteDb, StoreError};

/// Consecutive failures before the first lockout.
pub const LOCKOUT_THRESHOLD: i64 = 5;
/// First lockout duration in seconds; doubles with every further failure.
pub const LOCKOUT_BASE_SECS: i64 = 60;
/// Longest lockout (one hour).
pub const LOCKOUT_CAP_SECS: i64 = 3600;
/// The failure counter stops growing here (the lock is capped long before).
const FAILED_LOGINS_CEILING: i64 = 1000;
/// A failure counter older than this (no failure for 24 h) is forgotten. Choice: long enough that
/// a slow guesser still pays the progressive lock, short enough that a single stray attempt
/// cannot leave the owner on the one-hour lock for days. The CLI `reset-password` remains the
/// recovery for a sustained attack (`AUTH_SPEC` §Throttling).
pub const LOCKOUT_DECAY_SECS: i64 = 24 * 3600;

/// Authentication stage of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStage {
    /// Password verified, second factor (or enrollment) still outstanding.
    PendingMfa,
    /// Fully authenticated.
    Active,
}

impl SessionStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PendingMfa => "pending_mfa",
            Self::Active => "active",
        }
    }
}

/// A session to insert. `id_hash` is `SHA-256(session id)`.
#[derive(Clone, Debug)]
pub struct NewSession {
    /// SHA-256 of the session id.
    pub id_hash: [u8; 32],
    /// Owning user.
    pub user_id: i64,
    /// Starting stage.
    pub stage: SessionStage,
    /// Per-session CSRF synchronizer token (32 random bytes).
    pub csrf_token: [u8; 32],
    /// Creation time (unix seconds).
    pub now: i64,
    /// Idle/pending deadline (unix seconds).
    pub expires_at: i64,
    /// Client address for display/audit only.
    pub ip: Option<String>,
    /// Truncated user agent for display only.
    pub user_agent: Option<String>,
}

/// A stored session (the CSRF token is redacted from `Debug`).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// Owning user.
    pub user_id: i64,
    /// Current stage.
    pub stage: SessionStage,
    /// CSRF synchronizer token bytes.
    pub csrf_token: Vec<u8>,
    /// Creation time (unix seconds); the absolute lifetime counts from here.
    pub created_at: i64,
    /// Last time the session was refreshed.
    pub last_seen_at: i64,
    /// Idle/pending deadline.
    pub expires_at: i64,
    /// The pending session was created by an invitation or recovery redemption: the out-of-band code
    /// already played the role of the enrollment token (the TOTP confirmation is still required).
    pub enroll_proven: bool,
    /// Failed second-factor attempts so far (the 5th destroys a pending session).
    pub mfa_failures: i64,
}

impl std::fmt::Debug for SessionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRow")
            .field("account_id", &self.user_id)
            .field("stage", &self.stage)
            .field("csrf_token", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("expires_at", &self.expires_at)
            .field("enroll_proven", &self.enroll_proven)
            .field("mfa_failures", &self.mfa_failures)
            .finish()
    }
}

/// Login-relevant view of the user row (hash redacted from `Debug`).
#[derive(Clone, PartialEq, Eq)]
pub struct LoginUser {
    /// Row id.
    pub id: i64,
    /// Username as created.
    pub username: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// Whether TOTP enrollment is complete.
    pub totp_enabled: bool,
    /// Consecutive failed attempts.
    pub failed_logins: i64,
    /// Locked until this unix time, if locked (legacy per-account lock; 2.0 uses `login_lock`).
    pub locked_until: Option<i64>,
    /// Role (2.0).
    pub role: Role,
    /// The account is disabled: a login attempt behaves like a wrong password.
    pub disabled: bool,
}

impl std::fmt::Debug for LoginUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginUser")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("totp_enabled", &self.totp_enabled)
            .field("failed_logins", &self.failed_logins)
            .field("locked_until", &self.locked_until)
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .finish()
    }
}

/// Filter and cursor of the paged audit query (`audit_page`, T138). All fields are optional; the filters are combined with AND.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Only rows whose `actor_id` is this account.
    pub actor_id: Option<i64>,
    /// Only rows of this exact event name.
    pub event: Option<String>,
    /// Only rows with `ts >= from` (unix seconds).
    pub from: Option<i64>,
    /// Only rows with `ts <= to` (unix seconds).
    pub to: Option<i64>,
    /// Keyset cursor: only rows with `id < before_id` (the smallest id of the previous page).
    pub before_id: Option<i64>,
    /// Page size, clamped to `1..=200`.
    pub limit: u32,
}

/// One audit log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// Row id (the keyset cursor of `audit_page`).
    pub id: i64,
    /// Unix seconds.
    pub ts: i64,
    /// Who acted (username, `cli`) if known.
    pub actor: Option<String>,
    /// Stable event name, e.g. `login.fail`.
    pub event: String,
    /// Short non-secret detail.
    pub detail: Option<String>,
    /// Client address.
    pub ip: Option<String>,
    /// `user|cli|system|api_key|anonymous` (T101b: rendered next to the name so a login name equal
    /// to a reserved actor name cannot pass as that actor); `None` for rows written before 0011.
    pub actor_kind: Option<String>,
    /// Account id of the actor, when the row carries one.
    pub actor_id: Option<i64>,
    /// Role of the actor at that time (`admin|uploader|viewer`), when recorded.
    pub actor_role: Option<String>,
    /// The account the event is about, when it is one (T101b).
    pub target_id: Option<i64>,
}

/// Lock duration after `failures` consecutive failures: none below the threshold, then 60 s
/// doubling per extra failure, capped at one hour.
#[must_use]
pub fn lock_secs_for(failures: i64) -> i64 {
    if failures < LOCKOUT_THRESHOLD {
        return 0;
    }
    let doublings = u32::try_from(failures.saturating_sub(LOCKOUT_THRESHOLD).min(16)).unwrap_or(16);
    LOCKOUT_BASE_SECS
        .saturating_mul(1_i64 << doublings)
        .min(LOCKOUT_CAP_SECS)
}

fn stage_from(s: &str) -> Result<SessionStage, StoreError> {
    match s {
        "pending_mfa" => Ok(SessionStage::PendingMfa),
        "active" => Ok(SessionStage::Active),
        _ => Err(StoreError::OutOfRange("session stage")),
    }
}

fn row_to_login(r: &sqlx::sqlite::SqliteRow) -> Result<LoginUser, StoreError> {
    Ok(LoginUser {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        password_hash: r.try_get("password_hash")?,
        totp_enabled: r.try_get::<i64, _>("totp_enabled")? != 0,
        failed_logins: r.try_get("failed_logins")?,
        locked_until: r.try_get("locked_until")?,
        role: Role::parse(&r.try_get::<String, _>("role")?)
            .ok_or(StoreError::OutOfRange("account.role"))?,
        disabled: r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
    })
}

/// Whether `id_hash` is still an unexpired `active` session of `account_id`. Every revocation (recovery, reset, role change,
/// disable, explicit revoke) deletes the row, so this is how a writer learns that the session which re-authenticated
/// the request died meanwhile.
pub(crate) async fn session_is_live(
    conn: &mut sqlx::SqliteConnection,
    id_hash: &[u8; 32],
    account_id: i64,
    now: i64,
) -> Result<bool, StoreError> {
    let live: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM session WHERE id_hash = ?1 AND account_id = ?2 \
         AND stage = 'active' AND expires_at > ?3",
    )
    .bind(id_hash.as_slice())
    .bind(account_id)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(live.is_some())
}

/// Inserts `s` and applies the per-user, per-stage cap. `enroll_proven` marks a pending session that
/// already proved possession of an out-of-band invite/recovery code (0011).
pub(crate) async fn insert_in_tx(
    tx: &mut sqlx::SqliteConnection,
    s: &NewSession,
    max_per_stage: u32,
    enroll_proven: bool,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, \
         expires_at, ip, user_agent, enroll_proven) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(s.id_hash.as_slice())
    .bind(s.user_id)
    .bind(s.stage.as_str())
    .bind(s.csrf_token.as_slice())
    .bind(s.now)
    .bind(s.expires_at)
    .bind(s.ip.as_deref())
    .bind(s.user_agent.as_deref())
    .bind(i64::from(enroll_proven))
    .execute(&mut *tx)
    .await?;
    // Cap per stage so pending logins (password only) can never evict an active session. A pending
    // session that owns an unexpired staged recovery is never an eviction candidate (N4 d): somebody
    // holding only the password cannot kill the owner's recovery by logging in repeatedly.
    sqlx::query(
        "DELETE FROM session WHERE account_id = ?1 AND stage = ?2 AND id_hash NOT IN \
         (SELECT id_hash FROM session WHERE account_id = ?1 AND stage = ?2 \
          ORDER BY created_at DESC, rowid DESC LIMIT ?3) \
         AND id_hash NOT IN (SELECT session_hash FROM credential_staging WHERE expires_at > ?4)",
    )
    .bind(s.user_id)
    .bind(s.stage.as_str())
    .bind(i64::from(max_per_stage))
    .bind(s.now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

impl SqliteDb {
    /// Issues a pending login only while the account still matches the password-verdict
    /// observation. Rechecking and replacing/inserting the session share the writer lock,
    /// so a password change either revokes this row or prevents its creation.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for changed or unusable credentials;
    /// [`StoreError::OutOfRange`] for a mismatched account or non-pending session; database failure.
    pub async fn insert_login_session(
        &self,
        seen: &LoginUser,
        s: &NewSession,
        replacing: Option<&[u8; 32]>,
        max_per_stage: u32,
    ) -> Result<(), StoreError> {
        if s.user_id != seen.id || s.stage != SessionStage::PendingMfa {
            return Err(StoreError::OutOfRange("login session"));
        }
        let mut tx = self.begin_immediate().await?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM account WHERE id = ?1 AND password_hash = ?2 AND role = ?3 \
             AND totp_enabled = ?4 AND disabled_at IS NULL AND deleted_at IS NULL",
        )
        .bind(seen.id)
        .bind(&seen.password_hash)
        .bind(seen.role.as_str())
        .bind(i64::from(seen.totp_enabled))
        .fetch_optional(&mut *tx)
        .await?;
        if seen.disabled || current.is_none() {
            return Err(StoreError::NotFound);
        }
        if let Some(old) = replacing {
            sqlx::query("DELETE FROM session WHERE id_hash = ?1")
                .bind(old.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        insert_in_tx(&mut tx, s, max_per_stage, false).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Inserts a session and revokes the oldest of the same stage beyond `max_per_stage`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn insert_session(
        &self,
        s: &NewSession,
        max_per_stage: u32,
    ) -> Result<(), StoreError> {
        let mut tx = self.writer().begin().await?;
        insert_in_tx(&mut tx, s, max_per_stage, false).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replaces `old_hash` with a brand-new session (id rotation: login, MFA completion).
    /// Atomic, so there is never a window where both ids are valid.
    ///
    /// # Errors
    /// Database failure.
    pub async fn rotate_session(
        &self,
        old_hash: &[u8; 32],
        s: &NewSession,
        max_per_stage: u32,
    ) -> Result<(), StoreError> {
        self.rotate_session_inner(old_hash, s, max_per_stage, false)
            .await
    }

    /// Like [`SqliteDb::rotate_session`] but refuses (and rolls back) when the old session no longer
    /// exists: a pending session that was revoked or already consumed by a concurrent request
    /// must never be promoted (MFA completion).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if `old_hash` was not present; database failure.
    pub async fn rotate_session_strict(
        &self,
        old_hash: &[u8; 32],
        s: &NewSession,
        max_per_stage: u32,
    ) -> Result<(), StoreError> {
        self.rotate_session_inner(old_hash, s, max_per_stage, true)
            .await
    }

    async fn rotate_session_inner(
        &self,
        old_hash: &[u8; 32],
        s: &NewSession,
        max_per_stage: u32,
        strict: bool,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_immediate().await?;
        let removed = sqlx::query("DELETE FROM session WHERE id_hash = ?1")
            .bind(old_hash.as_slice())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if strict && removed == 0 {
            return Err(StoreError::NotFound);
        }
        insert_in_tx(&mut tx, s, max_per_stage, false).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Looks a session up by `SHA-256(id)`. Expiry is the caller's decision.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_session(&self, id_hash: &[u8; 32]) -> Result<Option<SessionRow>, StoreError> {
        // A miss on a reader is final (rows are only ever deleted; a session committed before
        // this request is visible to a fresh read), so unauthenticated probes with well-formed
        // junk cookies do not queue on the writer. A hit is re-read on the writer, so a
        // revoked session is never served from a stale reader snapshot.
        let probe: Option<i64> = sqlx::query_scalar("SELECT 1 FROM session WHERE id_hash = ?1")
            .bind(id_hash.as_slice())
            .fetch_optional(self.readers())
            .await?;
        if probe.is_none() {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT account_id, stage, csrf_token, created_at, last_seen_at, expires_at, \
             enroll_proven, mfa_failures FROM session WHERE id_hash = ?1",
        )
        .bind(id_hash.as_slice())
        .fetch_optional(self.writer())
        .await?;
        row.map(|r| {
            Ok(SessionRow {
                user_id: r.try_get("account_id")?,
                stage: stage_from(&r.try_get::<String, _>("stage")?)?,
                csrf_token: r.try_get("csrf_token")?,
                created_at: r.try_get("created_at")?,
                last_seen_at: r.try_get("last_seen_at")?,
                expires_at: r.try_get("expires_at")?,
                enroll_proven: r.try_get::<i64, _>("enroll_proven")? != 0,
                mfa_failures: r.try_get("mfa_failures")?,
            })
        })
        .transpose()
    }

    /// Slides the idle deadline of an unexpired `active` session. A late touch never revives it.
    ///
    /// # Errors
    /// Database failure.
    pub async fn touch_session(
        &self,
        id_hash: &[u8; 32],
        now: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE session SET last_seen_at = ?2, expires_at = ?3 \
             WHERE id_hash = ?1 AND stage = 'active' AND expires_at > ?2",
        )
        .bind(id_hash.as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// Revokes one session. Returns whether a row was removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn delete_session(&self, id_hash: &[u8; 32]) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM session WHERE id_hash = ?1")
            .bind(id_hash.as_slice())
            .execute(self.writer())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Purges sessions past their idle/pending deadline or created before `created_before`
    /// (the absolute lifetime cutoff). Returns the number removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn purge_sessions(&self, now: i64, created_before: i64) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM session WHERE expires_at <= ?1 OR created_at <= ?2")
            .bind(now)
            .bind(created_before)
            .execute(self.writer())
            .await?;
        Ok(res.rows_affected())
    }

    /// Case-insensitive lookup of the login-relevant user fields of a LIVE account (a tombstone is
    /// "unknown", L7). A disabled account IS returned (`disabled`), so the caller can run the same
    /// verification and answer like a wrong password.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_login_user(&self, username: &str) -> Result<Option<LoginUser>, StoreError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, totp_enabled, failed_logins, locked_until, \
             role, disabled_at FROM account WHERE username = ?1 AND deleted_at IS NULL",
        )
        .bind(username)
        .fetch_optional(self.writer())
        .await?;
        row.as_ref().map(row_to_login).transpose()
    }

    /// Login-relevant fields by user id (used to re-check the account behind a session). Tombstones are
    /// not returned.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_login_user_by_id(&self, id: i64) -> Result<Option<LoginUser>, StoreError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, totp_enabled, failed_logins, locked_until, \
             role, disabled_at FROM account WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(self.writer())
        .await?;
        row.as_ref().map(row_to_login).transpose()
    }

    /// Counts one failed attempt (password or second factor) and applies the progressive lock.
    /// Returns the resulting `locked_until`. The counter lives in the database so restarts do not
    /// reset it (SEC-026). T044 calls this for wrong TOTP/recovery codes.
    ///
    /// # Errors
    /// Database failure.
    pub async fn record_login_failure(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Option<i64>, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let r = bump_failure(&mut tx, user_id, now).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// Decides the password step in ONE writer transaction, after verification (SEC-026).
    ///
    /// The lock is re-read with the writer held, so a correct password presented during or after
    /// a concurrent burst that engaged the lock never yields a session. Every branch (unknown
    /// user, locked, wrong password, accepted) performs exactly one transaction with one audit
    /// insert, so the bookkeeping cost does not distinguish them. Returns `true` only when the
    /// password step is accepted. The failure counter is NOT cleared here: only a completed
    /// second factor does that ([`SqliteDb::record_login_success`]).
    ///
    /// `user_id` is `None` for unknown names/unusable input; `verified` must be `false` then.
    /// `fail_reason` is a fixed non-secret label for the audit row.
    ///
    /// # Errors
    /// Database failure.
    pub async fn login_password_step(
        &self,
        user_id: Option<i64>,
        verified: bool,
        fail_reason: &str,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let row = match user_id {
            Some(id) => {
                sqlx::query(
                    "SELECT username, locked_until, disabled_at FROM account \
                     WHERE id = ?1 AND deleted_at IS NULL",
                )
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
            }
            None => None,
        };
        let (actor, locked) = match &row {
            Some(r) => (
                Some(r.try_get::<String, _>("username")?),
                r.try_get::<Option<i64>, _>("locked_until")?
                    .is_some_and(|l| l > now),
            ),
            None => (None, false),
        };
        // A disabled account behaves exactly like a wrong password (2.0); the reason is audit-only.
        let disabled = match &row {
            Some(r) => r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
            None => false,
        };
        let accepted = verified && row.is_some() && !locked && !disabled;
        let (event, detail) = if accepted {
            ("login.password_ok", None)
        } else if row.is_none() {
            ("login.fail", Some("unknown_user"))
        } else if disabled {
            ("login.fail", Some("disabled"))
        } else if locked {
            ("login.fail", Some("locked"))
        } else {
            ("login.fail", Some(fail_reason))
        };
        if let Some(id) = user_id
            && row.is_some()
            && !accepted
            && !locked
        {
            bump_failure(&mut tx, id, now).await?;
        }
        crate::account::write_audit_legacy(&mut tx, now, actor.as_deref(), event, detail, ip)
            .await?;
        tx.commit().await?;
        Ok(accepted)
    }

    /// Clears the failure counter and any lock after a *fully completed* authentication.
    ///
    /// Seam for T044: call this exactly once, when the second factor (TOTP/recovery code) or the
    /// first-time enrollment has been verified and the `active` session is about to be issued.
    /// The password step never calls it.
    ///
    /// # Errors
    /// Database failure.
    pub async fn record_login_success(&self, user_id: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE account SET failed_logins = 0, locked_until = NULL, last_failed_at = NULL \
             WHERE id = ?1",
        )
        .bind(user_id)
        .execute(self.writer())
        .await?;
        Ok(())
    }

    /// The newest audit events, newest first (`limit` is clamped to 500).
    ///
    /// # Errors
    /// Database failure.
    pub async fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, event, detail, ip, actor_kind, actor_id, actor_role, target_id \
             FROM audit_log \
             ORDER BY id DESC LIMIT ?1",
        )
        .bind(i64::from(limit.min(500)))
        .fetch_all(self.readers())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(AuditRow {
                    id: r.try_get("id")?,
                    ts: r.try_get("ts")?,
                    actor: r.try_get("actor")?,
                    event: r.try_get("event")?,
                    detail: r.try_get("detail")?,
                    ip: r.try_get("ip")?,
                    actor_kind: r.try_get("actor_kind")?,
                    actor_id: r.try_get("actor_id")?,
                    actor_role: r.try_get("actor_role")?,
                    target_id: r.try_get("target_id")?,
                })
            })
            .collect()
    }

    /// One page of the audit log, newest first, keyset-paged by id (T138). A pure read; the filters are
    /// bound parameters (a NULL parameter disables its filter) and `limit` is clamped to `1..=200`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn audit_page(&self, f: &AuditFilter) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, event, detail, ip, actor_kind, actor_id, actor_role, target_id \
             FROM audit_log \
             WHERE (?1 IS NULL OR actor_id = ?1) \
               AND (?2 IS NULL OR event = ?2) \
               AND (?3 IS NULL OR ts >= ?3) \
               AND (?4 IS NULL OR ts <= ?4) \
               AND (?5 IS NULL OR id < ?5) \
             ORDER BY id DESC LIMIT ?6",
        )
        .bind(f.actor_id)
        .bind(f.event.as_deref())
        .bind(f.from)
        .bind(f.to)
        .bind(f.before_id)
        .bind(i64::from(f.limit.clamp(1, 200)))
        .fetch_all(self.readers())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(AuditRow {
                    id: r.try_get("id")?,
                    ts: r.try_get("ts")?,
                    actor: r.try_get("actor")?,
                    event: r.try_get("event")?,
                    detail: r.try_get("detail")?,
                    ip: r.try_get("ip")?,
                    actor_kind: r.try_get("actor_kind")?,
                    actor_id: r.try_get("actor_id")?,
                    actor_role: r.try_get("actor_role")?,
                    target_id: r.try_get("target_id")?,
                })
            })
            .collect()
    }

    /// Appends an audit event (SEC-033). Callers must never pass secrets in any field.
    ///
    /// # Errors
    /// Database failure.
    pub async fn audit_event(
        &self,
        now: i64,
        actor: Option<&str>,
        event: &str,
        detail: Option<&str>,
        ip: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut conn = self.writer().acquire().await?;
        crate::account::write_audit_legacy(&mut conn, now, actor, event, detail, ip).await
    }
}

/// Increments the failure counter (after quiet-period decay) and sets the progressive lock.
pub(crate) async fn bump_failure(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    let row = sqlx::query("SELECT failed_logins, last_failed_at FROM account WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut current: i64 = row.try_get("failed_logins")?;
    let last: Option<i64> = row.try_get("last_failed_at")?;
    if last.is_some_and(|l| now.saturating_sub(l) > LOCKOUT_DECAY_SECS) {
        current = 0;
    }
    let failures = current.saturating_add(1).min(FAILED_LOGINS_CEILING);
    let lock = lock_secs_for(failures);
    let locked_until = (lock > 0).then(|| now.saturating_add(lock));
    sqlx::query(
        "UPDATE account SET failed_logins = ?2, locked_until = ?3, last_failed_at = ?4 WHERE id = ?1",
    )
    .bind(user_id)
    .bind(failures)
    .bind(locked_until)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    Ok(locked_until)
}
