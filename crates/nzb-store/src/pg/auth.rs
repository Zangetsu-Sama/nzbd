//! Sessions, the 1.x login step and audit reads on Postgres (T112; 2.x `auth.rs`, SEC-024, SEC-026, SEC-033).
//!
//! Session creation and rotation apply the per-user cap under the account-domain lock (SEC-024 on Postgres); the
//! failure counter and the password verdict run under the same lock, the 2.x `BEGIN IMMEDIATE` equivalent.

use sqlx::Row;

use crate::StoreError;
use crate::account::Role;
use crate::auth::{
    AuditFilter, AuditRow, LOCKOUT_DECAY_SECS, LoginUser, NewSession, SessionRow, SessionStage,
    lock_secs_for,
};
use crate::pg::PgDb;

/// The failure counter stops growing here (2.x `FAILED_LOGINS_CEILING`).
const FAILED_LOGINS_CEILING: i64 = 1000;

pub(crate) fn stage_from(s: &str) -> Result<SessionStage, StoreError> {
    match s {
        "pending_mfa" => Ok(SessionStage::PendingMfa),
        "active" => Ok(SessionStage::Active),
        _ => Err(StoreError::OutOfRange("session stage")),
    }
}

fn row_to_login(r: &sqlx::postgres::PgRow) -> Result<LoginUser, StoreError> {
    Ok(LoginUser {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        password_hash: r.try_get("password_hash")?,
        totp_enabled: r.try_get("totp_enabled")?,
        failed_logins: r.try_get("failed_logins")?,
        locked_until: r.try_get("locked_until")?,
        role: Role::parse(&r.try_get::<String, _>("role")?)
            .ok_or(StoreError::OutOfRange("user.role"))?,
        disabled: r.try_get::<Option<i64>, _>("disabled_at")?.is_some(),
    })
}

/// Whether `id_hash` is still an unexpired `active` session of `account_id` (see the SQLite twin). The row is locked
/// (`FOR SHARE`) so it cannot be deleted before the calling transaction ends.
pub(crate) async fn session_is_live(
    conn: &mut sqlx::PgConnection,
    id_hash: &[u8; 32],
    account_id: i64,
    now: i64,
) -> Result<bool, StoreError> {
    let live: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM session WHERE id_hash = $1 AND account_id = $2 \
         AND stage = 'active' AND expires_at > $3 FOR SHARE",
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
    tx: &mut sqlx::PgConnection,
    s: &NewSession,
    max_per_stage: u32,
    enroll_proven: bool,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, \
         expires_at, ip, user_agent, enroll_proven) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9)",
    )
    .bind(s.id_hash.as_slice())
    .bind(s.user_id)
    .bind(s.stage.as_str())
    .bind(s.csrf_token.as_slice())
    .bind(s.now)
    .bind(s.expires_at)
    .bind(s.ip.as_deref())
    .bind(s.user_agent.as_deref())
    .bind(enroll_proven)
    .execute(&mut *tx)
    .await?;
    // Cap per stage so pending logins (password only) can never evict an active session. A pending
    // session that owns an unexpired staged recovery is never an eviction candidate (N4 d): somebody
    // holding only the password cannot kill the owner's recovery by logging in repeatedly.
    sqlx::query(
        "DELETE FROM session WHERE account_id = $1 AND stage = $2 AND id_hash NOT IN \
         (SELECT id_hash FROM session WHERE account_id = $1 AND stage = $2 \
          ORDER BY created_at DESC, seq DESC LIMIT $3) \
         AND id_hash NOT IN (SELECT session_hash FROM credential_staging WHERE expires_at > $4)",
    )
    .bind(s.user_id)
    .bind(s.stage.as_str())
    .bind(i64::from(max_per_stage))
    .bind(s.now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

impl PgDb {
    /// Issues a pending login only while the account still matches the password-verdict
    /// observation. Rechecking and replacing/inserting the session share the account-domain
    /// lock, so a password change either revokes this row or prevents its creation.
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
        let mut tx = self.begin_account().await?;
        let current: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM account WHERE id = $1 AND password_hash = $2 AND role = $3 \
             AND totp_enabled = $4 AND disabled_at IS NULL AND deleted_at IS NULL",
        )
        .bind(seen.id)
        .bind(&seen.password_hash)
        .bind(seen.role.as_str())
        .bind(seen.totp_enabled)
        .fetch_optional(&mut *tx)
        .await?;
        if seen.disabled || current.is_none() {
            return Err(StoreError::NotFound);
        }
        if let Some(old) = replacing {
            sqlx::query("DELETE FROM session WHERE id_hash = $1")
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
        // The per-user cap is an account-domain rule (ARCHITECTURE v3 section 6, SEC-024).
        let mut tx = self.begin_account().await?;
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

    /// Like [`PgDb::rotate_session`] but refuses (and rolls back) when the old session no longer
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
        let mut tx = self.begin_account().await?;
        let removed = sqlx::query("DELETE FROM session WHERE id_hash = $1")
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
        // One read: Postgres has no stale reader snapshot to guard against (READ COMMITTED, 2.x needed a re-read on
        // the writer).
        let row = sqlx::query(
            "SELECT account_id, stage, csrf_token, created_at, last_seen_at, expires_at, \
             enroll_proven, mfa_failures FROM session WHERE id_hash = $1",
        )
        .bind(id_hash.as_slice())
        .fetch_optional(self.web())
        .await?;
        row.map(|r| {
            Ok(SessionRow {
                user_id: r.try_get("account_id")?,
                stage: stage_from(&r.try_get::<String, _>("stage")?)?,
                csrf_token: r.try_get("csrf_token")?,
                created_at: r.try_get("created_at")?,
                last_seen_at: r.try_get("last_seen_at")?,
                expires_at: r.try_get("expires_at")?,
                enroll_proven: r.try_get("enroll_proven")?,
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
            "UPDATE session SET last_seen_at = $2, expires_at = $3 \
             WHERE id_hash = $1 AND stage = 'active' AND expires_at > $2",
        )
        .bind(id_hash.as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(self.web())
        .await?;
        Ok(())
    }

    /// Revokes one session. Returns whether a row was removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn delete_session(&self, id_hash: &[u8; 32]) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM session WHERE id_hash = $1")
            .bind(id_hash.as_slice())
            .execute(self.web())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Purges sessions past their idle/pending deadline or created before `created_before`
    /// (the absolute lifetime cutoff). Returns the number removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn purge_sessions(&self, now: i64, created_before: i64) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM session WHERE expires_at <= $1 OR created_at <= $2")
            .bind(now)
            .bind(created_before)
            .execute(self.web())
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
             role, disabled_at FROM account WHERE lower(username) = lower($1) AND deleted_at IS NULL",
        )
        .bind(username)
        .fetch_optional(self.web())
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
             role, disabled_at FROM account WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(self.web())
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
        let mut tx = self.begin_account().await?;
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
    /// second factor does that ([`PgDb::record_login_success`]).
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
        let mut tx = self.begin_account().await?;
        let row = match user_id {
            Some(id) => {
                sqlx::query(
                    "SELECT username, locked_until, disabled_at FROM account \
                     WHERE id = $1 AND deleted_at IS NULL",
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
        crate::pg::account::write_audit_legacy(&mut tx, now, actor.as_deref(), event, detail, ip)
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
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(self.web())
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
             ORDER BY id DESC LIMIT $1",
        )
        .bind(i64::from(limit.min(500)))
        .fetch_all(self.web())
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
             WHERE ($1::bigint IS NULL OR actor_id = $1) \
               AND ($2::text IS NULL OR event = $2) \
               AND ($3::bigint IS NULL OR ts >= $3) \
               AND ($4::bigint IS NULL OR ts <= $4) \
               AND ($5::bigint IS NULL OR id < $5) \
             ORDER BY id DESC LIMIT $6",
        )
        .bind(f.actor_id)
        .bind(f.event.as_deref())
        .bind(f.from)
        .bind(f.to)
        .bind(f.before_id)
        .bind(i64::from(f.limit.clamp(1, 200)))
        .fetch_all(self.web())
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
        let mut conn = self.web().acquire().await?;
        crate::pg::account::write_audit_legacy(&mut conn, now, actor, event, detail, ip).await
    }
}

/// Increments the failure counter (after quiet-period decay) and sets the progressive lock.
pub(crate) async fn bump_failure(
    tx: &mut sqlx::PgConnection,
    user_id: i64,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    let row = sqlx::query("SELECT failed_logins, last_failed_at FROM account WHERE id = $1")
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
        "UPDATE account SET failed_logins = $2, locked_until = $3, last_failed_at = $4 WHERE id = $1",
    )
    .bind(user_id)
    .bind(failures)
    .bind(locked_until)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    Ok(locked_until)
}
