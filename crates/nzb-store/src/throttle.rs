//! Persisted login throttling for several accounts (T101a; `AUTH_SPEC` "Throttling and rate-limit keys",
//! SEC-026, SEC-066, SEC-064).
//!
//! State lives in the database so a restart forgets nothing and the `nzbd` CLI can clear it:
//!
//! * `login_lock` - the HARD lock, keyed `(account, client address key)`; 5 failures lock for 60 s,
//!   doubling, capped at 1 h (5 min for admins); an address that is not the owner's cannot lock the owner
//!   out from another address (M1).
//! * `account_throttle` - the per-account AGGREGATE (20 failures per hour from any address, password step
//!   and every second-factor, enrollment and re-authentication post) and the DAILY second-factor cap
//!   (50 per 24 h, then unknown addresses are refused for an hour and the counter is set back to 45).
//!   Both only ever affect addresses outside `user_known_ip` (N1/N2).
//! * `user_known_ip` - the 5 most recent addresses of COMPLETED logins (N8): written only by
//!   [`SqliteDb::record_login_success_v2`] and the staged-recovery commit, never by a password step.
//! * `session.mfa_failures` - the pending session dies at the 5th failed second-factor attempt from any
//!   address (N1).
//!
//! The verdict functions take the decision in one `BEGIN IMMEDIATE` transaction after the caller did the
//! expensive verification, and every branch (unknown, disabled, locked, throttled, wrong, right) has the
//! same shape: one transaction, one audit row. Failures are audited as `actor_kind='anonymous'` with the
//! targeted account in `target_id`, never as that account (M5).

use sqlx::{Row, SqliteConnection};

use crate::account::{
    AuditActor, AuditEntry, Role, ThrottleKey, write_audit, write_audit_throttled,
};
use crate::auth::{LOCKOUT_DECAY_SECS, LoginUser, lock_secs_for};
use crate::invite::note_known_ip;
use crate::mfa::{FactorAttempt, SecondFactor};
use crate::{SqliteDb, StoreError};

/// Aggregate failures per window before unknown addresses are throttled.
pub const AGGREGATE_LIMIT: i64 = 20;
/// Aggregate window in seconds (one hour).
pub const AGGREGATE_WINDOW_SECS: i64 = 3600;
/// How long unknown-address throttling stays in force after a trip (extended by new failures).
pub const AGGREGATE_THROTTLE_SECS: i64 = 3600;
/// Second-factor failures per 24 h before unknown addresses are refused.
pub const DAILY_MFA_LIMIT: i64 = 50;
/// The counter after a trip (five more failures trip it again).
pub const DAILY_MFA_RESET_TO: i64 = 45;
/// Daily window in seconds.
pub const DAILY_WINDOW_SECS: i64 = 86_400;
/// Refusal of unknown addresses per daily-cap trip.
pub const MFA_REFUSE_SECS: i64 = 3600;
/// Admin hard locks never exceed this (SEC-066).
pub const ADMIN_LOCK_CAP_SECS: i64 = 300;
/// Failed second-factor attempts a pending session survives.
pub const PENDING_SESSION_MAX_FAILURES: i64 = 5;
/// Rows kept per account in `login_lock`.
pub const LOGIN_LOCK_MAX_ROWS: i64 = 64;
/// Longest accepted address key (an IPv6 text form is at most 45 characters).
pub(crate) const MAX_IP_KEY: usize = 64;

/// What a failed attempt was (all count in the aggregate; all but the password step in the daily cap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Wrong password at `/login`.
    Password,
    /// Wrong code at `/login/mfa`.
    SecondFactor,
    /// Wrong enrollment token or confirmation code.
    Enrollment,
    /// Wrong password or code at a re-authentication prompt.
    Reauth,
}

/// Request context of one authentication attempt.
#[derive(Clone, Copy)]
pub struct AttemptContext<'a> {
    /// Client address key: IPv4 text or the IPv6 /64 prefix, as the rate limiter keys it.
    pub ip_key: &'a str,
    /// The pending session the attempt belongs to (second factor / enrollment), for the 5-failure cap.
    pub session: Option<&'a [u8; 32]>,
    /// The caller's unknown-address bucket (1 attempt/min while the aggregate is tripped) denied this
    /// attempt: the store still sees the work done, then refuses.
    pub bucket_refused: bool,
}

impl std::fmt::Debug for AttemptContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptContext")
            .field("ip_key", &self.ip_key)
            .field("session", &self.session.map(|_| "[REDACTED]"))
            .field("bucket_refused", &self.bucket_refused)
            .finish()
    }
}

/// Effect of recording one failure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FailureEffect {
    /// Hard lock for this address after the failure, if any.
    pub hard_locked_until: Option<i64>,
    /// The aggregate tripped on this failure.
    pub aggregate_tripped: bool,
    /// The daily second-factor cap tripped on this failure.
    pub daily_tripped: bool,
    /// The pending session was destroyed (5th failure).
    pub session_killed: bool,
}

/// Read-only view of an account's throttle state for one address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThrottleState {
    /// Hard lock for `(account, address)`.
    pub hard_locked_until: Option<i64>,
    /// The address is one of the account's completed-login addresses.
    pub ip_known: bool,
    /// Unknown-address throttling in force until.
    pub aggregate_until: Option<i64>,
    /// Second-factor refusal of unknown addresses in force until.
    pub second_factor_refused_until: Option<i64>,
    /// Aggregate failures in the current window.
    pub hour_failures: i64,
    /// Second-factor failures in the current 24 h window.
    pub day_mfa_failures: i64,
}

impl ThrottleState {
    /// The hard lock refuses this address now.
    #[must_use]
    pub fn hard_locked(&self, now: i64) -> bool {
        self.hard_locked_until.is_some_and(|u| u > now)
    }

    /// Unknown-address throttling applies to this address now (known addresses never are).
    #[must_use]
    pub fn unknown_ip_throttled(&self, now: i64) -> bool {
        !self.ip_known && self.aggregate_until.is_some_and(|u| u > now)
    }

    /// Second factors from this address are refused now (daily cap).
    #[must_use]
    pub fn second_factor_refused(&self, now: i64) -> bool {
        !self.ip_known && self.second_factor_refused_until.is_some_and(|u| u > now)
    }
}

/// Verdict of [`SqliteDb::second_factor_step_v2`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactorVerdict {
    /// The factor was accepted.
    pub accepted: bool,
    /// The failed attempt destroyed the pending session.
    pub session_killed: bool,
}

/// Input of [`SqliteDb::confirm_totp_enrollment_v2`].
#[derive(Clone, Copy)]
pub struct EnrollConfirm<'a> {
    /// The account enrolling.
    pub user_id: i64,
    /// The sealed secret that was displayed.
    pub sealed: &'a [u8],
    /// The enrollment token hash (ignored for an invite-proven session).
    pub token_hash: Option<[u8; 32]>,
    /// The verified step of the confirmation code.
    pub step: Option<i64>,
    /// Hashes of the 10 recovery codes.
    pub recovery_hashes: &'a [[u8; 32]],
}

fn check_ip_key(k: &str) -> Result<(), StoreError> {
    if k.is_empty() || k.len() > MAX_IP_KEY {
        return Err(StoreError::OutOfRange("ip key"));
    }
    Ok(())
}

/// Gate decisions read under the writer lock.
struct Gate {
    locked: bool,
    aggregate_refused: bool,
    daily_refused: bool,
}

async fn gate(
    conn: &mut SqliteConnection,
    user_id: i64,
    ctx: &AttemptContext<'_>,
    now: i64,
) -> Result<Gate, StoreError> {
    let locked: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT locked_until FROM login_lock WHERE account_id = ?1 AND ip_key = ?2",
    )
    .bind(user_id)
    .bind(ctx.ip_key)
    .fetch_optional(&mut *conn)
    .await?;
    let known: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_known_ip WHERE account_id = ?1 AND ip_key = ?2",
    )
    .bind(user_id)
    .bind(ctx.ip_key)
    .fetch_one(&mut *conn)
    .await?;
    let agg = sqlx::query(
        "SELECT throttled_until, mfa_refused_until FROM account_throttle WHERE account_id = ?1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (until, refused) = match &agg {
        Some(r) => (
            r.try_get::<Option<i64>, _>("throttled_until")?,
            r.try_get::<Option<i64>, _>("mfa_refused_until")?,
        ),
        None => (None, None),
    };
    let known = known > 0;
    Ok(Gate {
        locked: locked.flatten().is_some_and(|u| u > now),
        aggregate_refused: ctx.bucket_refused && !known && until.is_some_and(|u| u > now),
        daily_refused: !known && refused.is_some_and(|u| u > now),
    })
}

/// Records one failed attempt: hard-lock row, aggregate and daily counters, and the throttled audit row
/// when a cap trips. Callers do not call it for an attempt that was refused by an already engaged lock
/// (a locked address's attempts are not counted again).
#[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
pub(crate) async fn record_failure_in(
    conn: &mut SqliteConnection,
    user_id: i64,
    ip_key: &str,
    kind: FailureKind,
    now: i64,
) -> Result<FailureEffect, StoreError> {
    let mut effect = FailureEffect::default();
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM account WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(role) = role else {
        return Ok(effect);
    };
    let is_admin = Role::parse(&role) == Some(Role::Admin);

    // Hard lock for (account, address).
    let row = sqlx::query(
        "SELECT failures, last_failure FROM login_lock WHERE account_id = ?1 AND ip_key = ?2",
    )
    .bind(user_id)
    .bind(ip_key)
    .fetch_optional(&mut *conn)
    .await?;
    let (mut failures, last): (i64, Option<i64>) = match &row {
        Some(r) => (r.try_get("failures")?, Some(r.try_get("last_failure")?)),
        None => (0, None),
    };
    if last.is_some_and(|l| now.saturating_sub(l) > LOCKOUT_DECAY_SECS) {
        failures = 0;
    }
    failures = failures.saturating_add(1).min(1000);
    let mut lock = lock_secs_for(failures);
    if is_admin {
        lock = lock.min(ADMIN_LOCK_CAP_SECS);
    }
    let locked_until = (lock > 0).then(|| now.saturating_add(lock));
    sqlx::query(
        "INSERT INTO login_lock (account_id, ip_key, failures, locked_until, last_failure) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(account_id, ip_key) DO UPDATE SET failures = excluded.failures, \
           locked_until = excluded.locked_until, last_failure = excluded.last_failure",
    )
    .bind(user_id)
    .bind(ip_key)
    .bind(failures)
    .bind(locked_until)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM login_lock WHERE account_id = ?1 AND ip_key NOT IN \
         (SELECT ip_key FROM login_lock WHERE account_id = ?1 \
          ORDER BY last_failure DESC, ip_key LIMIT ?2)",
    )
    .bind(user_id)
    .bind(LOGIN_LOCK_MAX_ROWS)
    .execute(&mut *conn)
    .await?;
    effect.hard_locked_until = locked_until;

    // Aggregate (tumbling one-hour window) and daily second-factor cap.
    let agg = sqlx::query(
        "SELECT hour_start, hour_failures, throttled_until, day_start, day_mfa_failures, \
         mfa_refused_until FROM account_throttle WHERE account_id = ?1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (
        mut hour_start,
        mut hour_failures,
        mut throttled_until,
        mut day_start,
        mut day_mfa,
        mut refused,
    ) = match &agg {
        Some(r) => (
            r.try_get::<i64, _>("hour_start")?,
            r.try_get::<i64, _>("hour_failures")?,
            r.try_get::<Option<i64>, _>("throttled_until")?,
            r.try_get::<i64, _>("day_start")?,
            r.try_get::<i64, _>("day_mfa_failures")?,
            r.try_get::<Option<i64>, _>("mfa_refused_until")?,
        ),
        None => (now, 0, None, now, 0, None),
    };
    if now.saturating_sub(hour_start) >= AGGREGATE_WINDOW_SECS {
        hour_start = now;
        hour_failures = 0;
    }
    if now.saturating_sub(day_start) >= DAILY_WINDOW_SECS {
        day_start = now;
        day_mfa = 0;
    }
    hour_failures = hour_failures.saturating_add(1);
    if hour_failures >= AGGREGATE_LIMIT {
        effect.aggregate_tripped = throttled_until.is_none_or(|u| u <= now);
        throttled_until = Some(now.saturating_add(AGGREGATE_THROTTLE_SECS));
    }
    if kind != FailureKind::Password {
        day_mfa = day_mfa.saturating_add(1);
        if day_mfa >= DAILY_MFA_LIMIT {
            effect.daily_tripped = refused.is_none_or(|u| u <= now);
            refused = Some(now.saturating_add(MFA_REFUSE_SECS));
            day_mfa = DAILY_MFA_RESET_TO;
        }
    }
    sqlx::query(
        "INSERT INTO account_throttle (account_id, hour_start, hour_failures, throttled_until, \
         day_start, day_mfa_failures, mfa_refused_until) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(account_id) DO UPDATE SET hour_start = excluded.hour_start, \
           hour_failures = excluded.hour_failures, throttled_until = excluded.throttled_until, \
           day_start = excluded.day_start, day_mfa_failures = excluded.day_mfa_failures, \
           mfa_refused_until = excluded.mfa_refused_until",
    )
    .bind(user_id)
    .bind(hour_start)
    .bind(hour_failures)
    .bind(throttled_until)
    .bind(day_start)
    .bind(day_mfa)
    .bind(refused)
    .execute(&mut *conn)
    .await?;
    for (tripped, reason) in [
        (effect.aggregate_tripped, "aggregate"),
        (effect.daily_tripped, "second_factor_daily"),
    ] {
        if tripped {
            let detail = format!("reason={reason}");
            write_audit_throttled(
                conn,
                &AuditEntry {
                    who: AuditActor::anonymous(),
                    event: "account_throttled",
                    detail: Some(&detail),
                    ip: None,
                    target_id: Some(user_id),
                },
                ThrottleKey::Account(user_id),
                3600,
                now,
            )
            .await?;
        }
    }
    Ok(effect)
}

/// Counts a failed second-factor attempt on the pending session; the 5th destroys it (with its staged
/// swap, through the trigger). Returns whether it was destroyed.
pub(crate) async fn session_failure_in(
    conn: &mut SqliteConnection,
    session: &[u8; 32],
    user_id: i64,
    now: i64,
) -> Result<bool, StoreError> {
    let touched = sqlx::query(
        "UPDATE session SET mfa_failures = mfa_failures + 1 \
         WHERE id_hash = ?1 AND account_id = ?2 AND stage = 'pending_mfa'",
    )
    .bind(session.as_slice())
    .bind(user_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if touched == 0 {
        return Ok(false);
    }
    let n: i64 = sqlx::query_scalar("SELECT mfa_failures FROM session WHERE id_hash = ?1")
        .bind(session.as_slice())
        .fetch_one(&mut *conn)
        .await?;
    if n < PENDING_SESSION_MAX_FAILURES {
        return Ok(false);
    }
    sqlx::query("DELETE FROM session WHERE id_hash = ?1")
        .bind(session.as_slice())
        .execute(&mut *conn)
        .await?;
    write_audit_throttled(
        conn,
        &AuditEntry {
            who: AuditActor::anonymous(),
            event: "session_pending_killed",
            detail: Some("failures=5"),
            ip: None,
            target_id: Some(user_id),
        },
        ThrottleKey::Account(user_id),
        60,
        now,
    )
    .await?;
    Ok(true)
}

async fn audit_failure(
    conn: &mut SqliteConnection,
    now: i64,
    event: &str,
    user_id: Option<i64>,
    detail: &str,
    ip: Option<&str>,
) -> Result<(), StoreError> {
    write_audit(
        conn,
        &AuditActor::anonymous(),
        now,
        event,
        Some(detail),
        ip,
        user_id,
    )
    .await
}

impl SqliteDb {
    /// The throttle state of `(user_id, ip_key)` as of `now` (read-only; for UI decisions and health).
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for an empty or overlong key; database failure.
    pub async fn throttle_state(
        &self,
        user_id: i64,
        ip_key: &str,
        now: i64,
    ) -> Result<ThrottleState, StoreError> {
        check_ip_key(ip_key)?;
        let mut conn = self.writer().acquire().await?;
        let lock: Option<Option<i64>> = sqlx::query_scalar(
            "SELECT locked_until FROM login_lock WHERE account_id = ?1 AND ip_key = ?2",
        )
        .bind(user_id)
        .bind(ip_key)
        .fetch_optional(&mut *conn)
        .await?;
        let known: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_known_ip WHERE account_id = ?1 AND ip_key = ?2",
        )
        .bind(user_id)
        .bind(ip_key)
        .fetch_one(&mut *conn)
        .await?;
        let agg = sqlx::query(
            "SELECT hour_start, hour_failures, throttled_until, day_start, day_mfa_failures, \
             mfa_refused_until FROM account_throttle WHERE account_id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        let mut st = ThrottleState {
            hard_locked_until: lock.flatten().filter(|u| *u > now),
            ip_known: known > 0,
            ..ThrottleState::default()
        };
        if let Some(r) = agg {
            st.aggregate_until = r.try_get("throttled_until")?;
            st.second_factor_refused_until = r.try_get("mfa_refused_until")?;
            let hour_start: i64 = r.try_get("hour_start")?;
            let day_start: i64 = r.try_get("day_start")?;
            if now.saturating_sub(hour_start) < AGGREGATE_WINDOW_SECS {
                st.hour_failures = r.try_get("hour_failures")?;
            }
            if now.saturating_sub(day_start) < DAILY_WINDOW_SECS {
                st.day_mfa_failures = r.try_get("day_mfa_failures")?;
            }
        }
        Ok(st)
    }

    /// Number of accounts whose aggregate or daily cap is in force (health WARN input).
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_throttled_accounts(&self, now: i64) -> Result<u64, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_throttle WHERE COALESCE(throttled_until, 0) > ?1 \
             OR COALESCE(mfa_refused_until, 0) > ?1",
        )
        .bind(now)
        .fetch_one(self.writer())
        .await?;
        u64::try_from(n).map_err(|_| StoreError::OutOfRange("count"))
    }

    /// Records one failed attempt that the store did not see decided (for example an enrollment-token
    /// check done elsewhere): hard lock, aggregate, daily cap and, with `session`, the 5-failure cap.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    pub async fn record_failure(
        &self,
        user_id: i64,
        ip_key: &str,
        kind: FailureKind,
        session: Option<&[u8; 32]>,
        now: i64,
    ) -> Result<FailureEffect, StoreError> {
        check_ip_key(ip_key)?;
        let mut tx = self.begin_immediate().await?;
        let mut effect = record_failure_in(&mut tx, user_id, ip_key, kind, now).await?;
        if let Some(s) = session {
            effect.session_killed = session_failure_in(&mut tx, s, user_id, now).await?;
        }
        tx.commit().await?;
        Ok(effect)
    }

    /// The completed-login bookkeeping (call exactly once when the second factor, or the enrollment
    /// commit, succeeded and the `active` session is about to be issued): sets `last_login_at`, clears
    /// the legacy counters and the lock row of THIS address, clears the HOURLY aggregate (not the daily second-factor cap) when the address was
    /// already known, and records the address (at most 5 per account, oldest evicted) in the same
    /// transaction (N8).
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    pub async fn record_login_success_v2(
        &self,
        user_id: i64,
        ip_key: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        if let Some(k) = ip_key {
            check_ip_key(k)?;
        }
        let mut tx = self.begin_immediate().await?;
        sqlx::query(
            "UPDATE account SET failed_logins = 0, locked_until = NULL, last_failed_at = NULL, \
             last_login_at = ?2 WHERE id = ?1",
        )
        .bind(user_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if let Some(k) = ip_key {
            let known: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM user_known_ip WHERE account_id = ?1 AND ip_key = ?2",
            )
            .bind(user_id)
            .bind(k)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM login_lock WHERE account_id = ?1 AND ip_key = ?2")
                .bind(user_id)
                .bind(k)
                .execute(&mut *tx)
                .await?;
            if known > 0 {
                // Only the hourly aggregate is cleared; the daily second-factor counter and its
                // refusal age out with their window (or `unlock`), so an owner's logins cannot
                // refresh an attacker's guess budget (review R1).
                sqlx::query(
                    "UPDATE account_throttle SET hour_failures = 0, throttled_until = NULL \
                     WHERE account_id = ?1",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            }
            note_known_ip(&mut tx, user_id, k, now).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Decides the password step with per-address locks (the 2.0 counterpart of
    /// [`SqliteDb::login_password_step`]). `seen` is the account the caller verified the password
    /// against, `None` for an unknown name, `~`-prefixed input or a tombstone (`verified` must then be
    /// `false`). A disabled account behaves exactly like a wrong password (reason `disabled` is
    /// audit-only). Returns `true` only when the step is accepted.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    pub async fn login_password_step_v2(
        &self,
        seen: Option<&LoginUser>,
        verified: bool,
        fail_reason: &str,
        ctx: &AttemptContext<'_>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        check_ip_key(ctx.ip_key)?;
        let user_id = seen.map(|u| u.id);
        let mut tx = self.begin_immediate().await?;
        // Review 30.3 (a), same rule as the Postgres backend: the Argon2 verification ran outside the
        // writer against `seen`; the credential state is re-read here, inside the writer transaction, and
        // an attempt verified against a password hash, role or enabled state that has changed since is a
        // failure (no TOCTOU with a concurrent password change, disable or delete). It is not a guess.
        let row = match user_id {
            Some(id) => sqlx::query(
                "SELECT password_hash, role, disabled_at, deleted_at FROM account WHERE id = ?1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?,
            None => None,
        };
        let (exists, disabled, changed) = match (&row, seen) {
            (Some(r), Some(u)) => {
                let hash: String = r.try_get("password_hash")?;
                let role = Role::parse(&r.try_get::<String, _>("role")?);
                let disabled = r.try_get::<Option<i64>, _>("disabled_at")?.is_some();
                (
                    r.try_get::<Option<i64>, _>("deleted_at")?.is_none(),
                    disabled,
                    hash != u.password_hash || role != Some(u.role) || disabled != u.disabled,
                )
            }
            _ => (false, false, false),
        };
        let uid = user_id.filter(|_| exists);
        let g = match uid {
            Some(id) => Some(gate(&mut tx, id, ctx, now).await?),
            None => None,
        };
        let locked = g.as_ref().is_some_and(|g| g.locked);
        let throttled = g.as_ref().is_some_and(|g| g.aggregate_refused);
        let accepted = verified && exists && !disabled && !locked && !throttled && !changed;
        let reason = if !exists {
            "unknown_user"
        } else if disabled {
            "disabled"
        } else if locked {
            "locked"
        } else if throttled {
            "throttled"
        } else if changed {
            "credentials_changed"
        } else {
            fail_reason
        };
        if accepted {
            audit_failure(&mut tx, now, "login.password_ok", uid, "ok", ip).await?;
        } else {
            // A correct password refused by a lock or throttle is not a guess: it is not counted.
            if let Some(id) = uid
                && !disabled
                && !locked
                && !verified
            {
                record_failure_in(&mut tx, id, ctx.ip_key, FailureKind::Password, now).await?;
            }
            audit_failure(&mut tx, now, "login.fail", uid, reason, ip).await?;
        }
        tx.commit().await?;
        Ok(accepted)
    }

    /// Decides one second-factor attempt with per-address locks, the persisted aggregate and the
    /// 5-failure cap of the pending session (the 2.0 counterpart of [`SqliteDb::second_factor_step`]). Same
    /// work in every branch; a refused (locked, throttled, capped) attempt still consumed the caller's
    /// verification and is answered like a wrong code.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    pub async fn second_factor_step_v2(
        &self,
        a: FactorAttempt<'_>,
        ctx: &AttemptContext<'_>,
    ) -> Result<FactorVerdict, StoreError> {
        check_ip_key(ctx.ip_key)?;
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT username, role, totp_enabled, totp_last_step, disabled_at FROM account \
             WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(a.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let g = gate(&mut tx, a.user_id, ctx, a.now).await?;
        let mut enabled = false;
        let mut disabled = false;
        let mut last_step: Option<i64> = None;
        let mut who: Option<AuditActor> = None;
        if let Some(r) = &row {
            enabled = r.try_get::<i64, _>("totp_enabled")? != 0;
            disabled = r.try_get::<Option<i64>, _>("disabled_at")?.is_some();
            last_step = r.try_get("totp_last_step")?;
            let role = Role::parse(&r.try_get::<String, _>("role")?)
                .ok_or(StoreError::OutOfRange("account.role"))?;
            who = Some(AuditActor::account(
                a.user_id,
                role,
                &r.try_get::<String, _>("username")?,
            ));
        }
        let exists = row.is_some();
        let refused = g.aggregate_refused || g.daily_refused;
        let usable = exists && enabled && !disabled && !g.locked && !refused && a.precondition_ok;
        let mut accepted = false;
        let mut recovery_used = false;
        if usable {
            match a.factor {
                SecondFactor::Totp(Some(step)) if last_step.is_none_or(|l| step > l) => {
                    let res = sqlx::query(
                        "UPDATE account SET totp_last_step = ?2 \
                         WHERE id = ?1 AND (totp_last_step IS NULL OR totp_last_step < ?2)",
                    )
                    .bind(a.user_id)
                    .bind(step)
                    .execute(&mut *tx)
                    .await?;
                    accepted = res.rows_affected() == 1;
                }
                SecondFactor::Recovery(Some(hash)) => {
                    let res = sqlx::query(
                        "UPDATE recovery_code SET used_at = ?3 \
                         WHERE account_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
                    )
                    .bind(a.user_id)
                    .bind(hash.as_slice())
                    .bind(a.now)
                    .execute(&mut *tx)
                    .await?;
                    accepted = res.rows_affected() == 1;
                    recovery_used = accepted;
                }
                _ => {}
            }
        }
        let login = a.purpose == "login";
        // Re-using an already consumed step on re-authentication is the owner's own replay: refused,
        // not counted (as in 1.x).
        let own_replay = !accepted
            && usable
            && !login
            && matches!(a.factor, SecondFactor::Totp(Some(s)) if last_step.is_some_and(|l| s <= l));
        let reason = if !exists {
            "no_user"
        } else if disabled {
            "disabled"
        } else if g.locked {
            "locked"
        } else if refused {
            "throttled"
        } else if !enabled {
            "not_enrolled"
        } else if !a.precondition_ok {
            "reauth_failed"
        } else if own_replay {
            "replay"
        } else {
            "bad_code"
        };
        let mut killed = false;
        if !accepted {
            if exists && !disabled && !g.locked && !refused && !own_replay {
                let kind = if login {
                    FailureKind::SecondFactor
                } else {
                    FailureKind::Reauth
                };
                record_failure_in(&mut tx, a.user_id, ctx.ip_key, kind, a.now).await?;
            }
            if exists
                && !own_replay
                && let Some(s) = ctx.session
            {
                killed = session_failure_in(&mut tx, s, a.user_id, a.now).await?;
            }
        }
        if let (Some(w), true) = (&who, accepted) {
            let event = if recovery_used {
                "mfa.recovery_used"
            } else {
                "mfa.ok"
            };
            let detail = format!("purpose={}", a.purpose);
            write_audit(
                &mut tx,
                w,
                a.now,
                event,
                Some(&detail),
                a.ip,
                Some(a.user_id),
            )
            .await?;
        } else {
            let detail = format!("purpose={} reason={reason}", a.purpose);
            audit_failure(
                &mut tx,
                a.now,
                "mfa.fail",
                exists.then_some(a.user_id),
                &detail,
                a.ip,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(FactorVerdict {
            accepted,
            session_killed: killed,
        })
    }

    /// Per-address counterpart of [`SqliteDb::check_enrollment_token`]: the token is NOT consumed. Wrong
    /// attempts feed the hard lock, the aggregate, the daily cap and the pending session's 5-failure cap.
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    pub async fn check_enrollment_token_v2(
        &self,
        user_id: i64,
        token_hash: Option<[u8; 32]>,
        ctx: &AttemptContext<'_>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        check_ip_key(ctx.ip_key)?;
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT totp_enabled, enroll_token_hash, enroll_token_expires, disabled_at FROM account \
             WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let g = gate(&mut tx, user_id, ctx, now).await?;
        let refused = g.aggregate_refused || g.daily_refused;
        let mut ok = false;
        let exists = row.is_some();
        let mut disabled = false;
        if let Some(r) = &row {
            disabled = r.try_get::<Option<i64>, _>("disabled_at")?.is_some();
            let stored: Option<Vec<u8>> = r.try_get("enroll_token_hash")?;
            let expires: Option<i64> = r.try_get("enroll_token_expires")?;
            let matches = match (&stored, &token_hash) {
                (Some(s), Some(t)) => crate::mfa::ct_eq32(s, t),
                _ => false,
            };
            ok = r.try_get::<i64, _>("totp_enabled")? == 0
                && !disabled
                && !g.locked
                && !refused
                && expires.is_some_and(|e| e > now)
                && matches;
        }
        if !ok {
            if exists && !disabled && !g.locked && !refused {
                record_failure_in(&mut tx, user_id, ctx.ip_key, FailureKind::Enrollment, now)
                    .await?;
            }
            if exists && let Some(s) = ctx.session {
                session_failure_in(&mut tx, s, user_id, now).await?;
            }
        }
        let (event, detail) = if ok {
            ("mfa.enroll_token_ok", "ok")
        } else if g.locked {
            ("mfa.fail", "purpose=enroll_token reason=locked")
        } else if refused {
            ("mfa.fail", "purpose=enroll_token reason=throttled")
        } else {
            ("mfa.fail", "purpose=enroll_token reason=bad_token")
        };
        audit_failure(&mut tx, now, event, exists.then_some(user_id), detail, ip).await?;
        tx.commit().await?;
        Ok(ok)
    }

    /// Per-address counterpart of [`SqliteDb::confirm_totp_enrollment`]. The enrollment token is waived for a
    /// pending session that was created by an invitation redemption (`enroll_proven`); the TOTP
    /// confirmation never is. A recovery session cannot use this (its account has TOTP enabled): the
    /// swap commits through [`SqliteDb::commit_staged_recovery`].
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the pending session of `ctx` is gone (revoked, expired);
    /// [`StoreError::OutOfRange`] for a bad key; database failure.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    pub async fn confirm_totp_enrollment_v2(
        &self,
        c: &EnrollConfirm<'_>,
        ctx: &AttemptContext<'_>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        check_ip_key(ctx.ip_key)?;
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT username, role, totp_enabled, totp_secret_enc, enroll_token_hash, \
             enroll_token_expires, disabled_at FROM account WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(c.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let proven = if let Some(hash) = ctx.session {
            let live: Option<i64> = sqlx::query_scalar(
                "SELECT enroll_proven FROM session WHERE id_hash = ?1 AND account_id = ?2 \
                     AND stage = 'pending_mfa' AND expires_at > ?3",
            )
            .bind(hash.as_slice())
            .bind(c.user_id)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            // A revoked or expired pending session is not a wrong code: the caller must not
            // answer it with the secret page again.
            let Some(proven) = live else {
                return Err(StoreError::NotFound);
            };
            proven != 0
        } else {
            false
        };
        let g = gate(&mut tx, c.user_id, ctx, now).await?;
        let refused = g.aggregate_refused || g.daily_refused;
        let exists = row.is_some();
        let mut pending = false;
        let mut who: Option<AuditActor> = None;
        let mut disabled = false;
        if let Some(r) = &row {
            disabled = r.try_get::<Option<i64>, _>("disabled_at")?.is_some();
            let stored_blob: Option<Vec<u8>> = r.try_get("totp_secret_enc")?;
            let stored_tok: Option<Vec<u8>> = r.try_get("enroll_token_hash")?;
            let expires: Option<i64> = r.try_get("enroll_token_expires")?;
            let token_ok = match (&stored_tok, &c.token_hash) {
                (Some(s), Some(t)) => crate::mfa::ct_eq32(s, t),
                _ => false,
            } && expires.is_some_and(|e| e > now);
            pending = r.try_get::<i64, _>("totp_enabled")? == 0
                && stored_blob.as_deref() == Some(c.sealed)
                && (token_ok || proven);
            let role = Role::parse(&r.try_get::<String, _>("role")?)
                .ok_or(StoreError::OutOfRange("account.role"))?;
            who = Some(AuditActor::account(
                c.user_id,
                role,
                &r.try_get::<String, _>("username")?,
            ));
        }
        let accepted = exists && pending && !disabled && !g.locked && !refused && c.step.is_some();
        if accepted {
            let res = sqlx::query(
                "UPDATE account SET totp_enabled = 1, totp_last_step = ?2, enroll_token_hash = NULL, \
                 enroll_token_expires = NULL WHERE id = ?1 AND totp_enabled = 0 AND totp_secret_enc = ?3",
            )
            .bind(c.user_id)
            .bind(c.step)
            .bind(c.sealed)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Err(StoreError::NotFound);
            }
            sqlx::query("DELETE FROM recovery_code WHERE account_id = ?1")
                .bind(c.user_id)
                .execute(&mut *tx)
                .await?;
            for h in c.recovery_hashes {
                sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, ?2)")
                    .bind(c.user_id)
                    .bind(h.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
        } else {
            if exists && !disabled && !g.locked && !refused {
                record_failure_in(&mut tx, c.user_id, ctx.ip_key, FailureKind::Enrollment, now)
                    .await?;
            }
            if exists && let Some(s) = ctx.session {
                session_failure_in(&mut tx, s, c.user_id, now).await?;
            }
        }
        if let (Some(w), true) = (&who, accepted) {
            write_audit(
                &mut tx,
                w,
                now,
                "mfa.enrolled",
                Some("ok"),
                ip,
                Some(c.user_id),
            )
            .await?;
        } else {
            let reason = if g.locked {
                "locked"
            } else if refused {
                "throttled"
            } else {
                "bad_code"
            };
            let detail = format!("purpose=enroll reason={reason}");
            audit_failure(
                &mut tx,
                now,
                "mfa.fail",
                exists.then_some(c.user_id),
                &detail,
                ip,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(accepted)
    }
}
