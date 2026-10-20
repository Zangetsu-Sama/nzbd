//! MFA repository: encrypted TOTP secret, replay step, recovery codes, second-factor verdicts
//! and the account page's session list (SEC-023, SEC-026, SEC-033).
//!
//! This crate never sees plaintext secrets or recovery codes: the caller passes the sealed
//! (encrypted) TOTP blob and the SHA-256 of recovery codes. Verdicts are taken in ONE writer
//! transaction with the lock re-read under the writer, mirroring `SqliteDb::login_password_step`, so
//! a concurrent burst cannot slip a correct code past a lock engaged by its own failures and a
//! TOTP step can be accepted only once (compare-and-set on `totp_last_step`).

use sqlx::Row;

use crate::auth::bump_failure;
use crate::{NewSession, SessionStage, SqliteDb, StoreError};

/// Session and proof re-read together before an enrollment secret is accessed.
pub(crate) struct PendingEnrollment<'a> {
    pub(crate) session_hash: &'a [u8; 32],
    pub(crate) token_hash: Option<[u8; 32]>,
    pub(crate) now: i64,
}

/// Stored MFA state of a user (the sealed secret is opaque here).
#[derive(Clone, PartialEq, Eq)]
pub struct MfaState {
    /// Login name (for the `otpauth` label and audit).
    pub username: String,
    /// Whether enrollment was confirmed.
    pub totp_enabled: bool,
    /// `nonce || ciphertext || tag` of the TOTP secret, if one was generated.
    pub totp_secret_enc: Option<Vec<u8>>,
    /// Last accepted 30 s step (replay guard).
    pub totp_last_step: Option<i64>,
}

impl std::fmt::Debug for MfaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaState")
            .field("username", &self.username)
            .field("totp_enabled", &self.totp_enabled)
            .field("totp_secret_enc", &"[REDACTED]")
            .field("totp_last_step", &self.totp_last_step)
            .finish()
    }
}

/// The second factor a caller wants verified. `None` payloads mean "the input was malformed":
/// the attempt is still counted and takes the same code path (uniform shape, SEC-026).
#[derive(Clone, Copy, Debug)]
pub enum SecondFactor {
    /// A TOTP code that matched this step in constant time, if any did.
    Totp(Option<i64>),
    /// SHA-256 of a well-formed recovery code, if the input was one.
    Recovery(Option<[u8; 32]>),
}

/// One verification attempt (login step 2, or re-authentication on the account page).
#[derive(Clone, Copy, Debug)]
pub struct FactorAttempt<'a> {
    /// The user being authenticated.
    pub user_id: i64,
    /// Extra precondition computed by the caller (account page: current password verified);
    /// `true` for the login step. A `false` here counts as a failure like a wrong code.
    pub precondition_ok: bool,
    /// The factor.
    pub factor: SecondFactor,
    /// Fixed non-secret label for the audit row, e.g. `login`, `password_change`.
    pub purpose: &'static str,
    /// Client address for the audit row.
    pub ip: Option<&'a str>,
    /// Unix seconds.
    pub now: i64,
}

/// A session as shown on the account page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// `SHA-256(session id)`; doubles as the opaque revoke handle (it cannot be turned back into
    /// the cookie value).
    pub id_hash: [u8; 32],
    /// Creation time.
    pub created_at: i64,
    /// Last refresh.
    pub last_seen_at: i64,
    /// Client address recorded at login (display only).
    pub ip: Option<String>,
    /// Truncated user agent recorded at login (display only; hostile text, escape on output).
    pub user_agent: Option<String>,
}

async fn audit_tx(
    tx: &mut sqlx::SqliteConnection,
    now: i64,
    actor: Option<&str>,
    event: &str,
    detail: Option<&str>,
    ip: Option<&str>,
) -> Result<(), StoreError> {
    crate::account::write_audit_legacy(tx, now, actor, event, detail, ip).await
}

/// Constant-time equality of two 32-byte hashes.
pub(crate) fn ct_eq32(a: &[u8], b: &[u8; 32]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Arms the enrollment token of one account (only while MFA is not enabled). The pending secret
/// is dropped, so a new token always starts with a new secret.
async fn arm_enrollment_token(
    conn: &mut sqlx::SqliteConnection,
    id: i64,
    token_hash: &[u8; 32],
    expires_at: i64,
    now: i64,
) -> Result<bool, StoreError> {
    let res = sqlx::query(
        "UPDATE account SET enroll_token_hash = ?2, enroll_token_expires = ?3, \
         totp_secret_enc = NULL WHERE id = ?1 AND totp_enabled = 0",
    )
    .bind(id)
    .bind(token_hash.as_slice())
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;
    let armed = res.rows_affected() > 0;
    if armed {
        crate::user::revoke_recovery_state(conn, id, now).await?;
        crate::account::write_audit(
            conn,
            &crate::AuditActor::cli(),
            now,
            "user.enroll_token_issued",
            None,
            None,
            Some(id),
        )
        .await?;
    }
    Ok(armed)
}

async fn username_of(
    tx: &mut sqlx::SqliteConnection,
    user_id: i64,
) -> Result<Option<String>, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT username FROM account WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?,
    )
}

/// A delayed request cannot revoke sessions after its own authentication was revoked or expired.
async fn require_revoking_session(
    conn: &mut sqlx::SqliteConnection,
    user_id: i64,
    session_hash: &[u8; 32],
    now: i64,
) -> Result<(), StoreError> {
    let live: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM session s JOIN account a ON a.id = s.account_id \
         WHERE s.id_hash = ?1 AND s.account_id = ?2 AND s.stage = 'active' \
         AND s.expires_at > ?3 AND a.disabled_at IS NULL AND a.deleted_at IS NULL",
    )
    .bind(session_hash.as_slice())
    .bind(user_id)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    live.map(|_| ()).ok_or(StoreError::NotFound)
}

/// Revalidates the pending session before an enrollment secret or staged recovery write.
pub(crate) async fn pending_session_is_live(
    conn: &mut sqlx::SqliteConnection,
    user_id: i64,
    hash: &[u8; 32],
    now: i64,
) -> Result<bool, StoreError> {
    let live: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM session s JOIN account a ON a.id = s.account_id \
         WHERE s.id_hash = ?1 AND s.account_id = ?2 AND s.stage = 'pending_mfa' \
         AND s.expires_at > ?3 AND a.disabled_at IS NULL AND a.deleted_at IS NULL",
    )
    .bind(hash.as_slice())
    .bind(user_id)
    .bind(now)
    .fetch_optional(conn)
    .await?;
    Ok(live.is_some())
}

/// The session and the out-of-band enrollment proof authorize one secret read/write together.
/// Both rows stay fixed until commit (SQLite writer / Postgres account and session locks).
async fn pending_secret_authorized(
    conn: &mut sqlx::SqliteConnection,
    user_id: i64,
    session_hash: &[u8; 32],
    token_hash: Option<&[u8; 32]>,
    now: i64,
) -> Result<bool, StoreError> {
    if !pending_session_is_live(conn, user_id, session_hash, now).await? {
        return Ok(false);
    }
    let row = sqlx::query(
        "SELECT s.enroll_proven, a.enroll_token_hash, a.enroll_token_expires \
         FROM session s JOIN account a ON a.id = s.account_id \
         WHERE s.id_hash = ?1 AND s.account_id = ?2",
    )
    .bind(session_hash.as_slice())
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    let Some(r) = row else { return Ok(false) };
    if r.try_get::<i64, _>("enroll_proven")? != 0 {
        return Ok(true);
    }
    let stored: Option<Vec<u8>> = r.try_get("enroll_token_hash")?;
    let expires: Option<i64> = r.try_get("enroll_token_expires")?;
    Ok(expires.is_some_and(|e| e > now)
        && match (stored.as_deref(), token_hash) {
            (Some(stored), Some(supplied)) => ct_eq32(stored, supplied),
            _ => false,
        })
}

impl SqliteDb {
    /// Arms enrollment: stores `SHA-256(token)` and its expiry for the only user, replacing any
    /// earlier token. Returns `false` when TOTP is already enabled (nothing to enroll) and
    /// `NotFound` when there is no user. Called by the CLI (`user create|reset-mfa|enroll-token`).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] without a user; database failure.
    pub async fn set_enrollment_token(
        &self,
        token_hash: &[u8; 32],
        expires_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let id = crate::user::only_live_user(&mut tx).await?;
        let armed = arm_enrollment_token(&mut tx, id, token_hash, expires_at, now).await?;
        tx.commit().await?;
        Ok(armed)
    }

    /// Operator `user enroll-token <name>`: arms enrollment for one account (see
    /// [`SqliteDb::set_enrollment_token`]). Also revokes the account's open recovery codes and drops its
    /// staged swap (N4).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] without such a live account; database failure.
    pub async fn set_enrollment_token_for(
        &self,
        user_id: i64,
        token_hash: &[u8; 32],
        expires_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let live: Option<i64> =
            sqlx::query_scalar("SELECT id FROM account WHERE id = ?1 AND deleted_at IS NULL")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        if live.is_none() {
            return Err(StoreError::NotFound);
        }
        let armed = arm_enrollment_token(&mut tx, user_id, token_hash, expires_at, now).await?;
        tx.commit().await?;
        Ok(armed)
    }

    /// Checks the enrollment token in one writer transaction (lock re-read, failure counted in the
    /// shared lockout counter, audit row in every branch). The token is NOT consumed here.
    ///
    /// # Errors
    /// Database failure.
    pub async fn check_enrollment_token(
        &self,
        user_id: i64,
        token_hash: Option<[u8; 32]>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT username, totp_enabled, locked_until, enroll_token_hash, enroll_token_expires \
             FROM account WHERE id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let mut exists = false;
        let mut actor: Option<String> = None;
        let mut locked = false;
        let mut ok = false;
        if let Some(r) = &row {
            exists = true;
            actor = Some(r.try_get("username")?);
            locked = r
                .try_get::<Option<i64>, _>("locked_until")?
                .is_some_and(|l| l > now);
            let stored: Option<Vec<u8>> = r.try_get("enroll_token_hash")?;
            let expires: Option<i64> = r.try_get("enroll_token_expires")?;
            let fresh = expires.is_some_and(|e| e > now);
            let matches = match (&stored, &token_hash) {
                (Some(s), Some(t)) => ct_eq32(s, t),
                _ => false,
            };
            ok = r.try_get::<i64, _>("totp_enabled")? == 0 && !locked && fresh && matches;
        }
        if !ok && exists && !locked {
            bump_failure(&mut tx, user_id, now).await?;
        }
        let (event, detail) = if ok {
            ("mfa.enroll_token_ok", "ok")
        } else if locked {
            ("mfa.fail", "purpose=enroll_token reason=locked")
        } else {
            ("mfa.fail", "purpose=enroll_token reason=bad_token")
        };
        audit_tx(&mut tx, now, actor.as_deref(), event, Some(detail), ip).await?;
        tx.commit().await?;
        Ok(ok)
    }

    /// MFA columns of a user.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_mfa_state(&self, user_id: i64) -> Result<Option<MfaState>, StoreError> {
        let row = sqlx::query(
            "SELECT username, totp_enabled, totp_secret_enc, totp_last_step FROM account WHERE id = ?1",
        )
        .bind(user_id)
        .fetch_optional(self.writer())
        .await?;
        row.map(|r| {
            Ok(MfaState {
                username: r.try_get("username")?,
                totp_enabled: r.try_get::<i64, _>("totp_enabled")? != 0,
                totp_secret_enc: r.try_get("totp_secret_enc")?,
                totp_last_step: r.try_get("totp_last_step")?,
            })
        })
        .transpose()
    }

    /// Stores a freshly sealed pending TOTP secret unless one already exists (or `replace` is
    /// set) and returns the blob now stored, so two concurrent enrollment page loads agree.
    /// Returns `None` when TOTP is already enabled (enrollment is closed) or the user is gone.
    ///
    /// # Errors
    /// Database failure.
    pub async fn store_pending_totp(
        &self,
        user_id: i64,
        sealed: &[u8],
        replace: bool,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.store_pending_totp_inner(user_id, sealed, replace, None)
            .await
    }

    /// Stores or reads an enrollment secret only for its live pending browser session.
    /// The current unexpired enrollment token must match, or the stored session must be `enroll_proven`.
    /// Revocation, expiry, an active session, a disabled/deleted owner or a missing proof returns `None`.
    /// The same checks apply to reading an existing secret, so rotating a token invalidates an earlier proof.
    ///
    /// # Errors
    /// Database failure.
    pub async fn store_pending_totp_for_session(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        sealed: &[u8],
        replace: bool,
        token_hash: Option<[u8; 32]>,
        now: i64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.store_pending_totp_inner(
            user_id,
            sealed,
            replace,
            Some(PendingEnrollment {
                session_hash,
                token_hash,
                now,
            }),
        )
        .await
    }

    async fn store_pending_totp_inner(
        &self,
        user_id: i64,
        sealed: &[u8],
        replace: bool,
        session: Option<PendingEnrollment<'_>>,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut tx = self.begin_immediate().await?;
        if let Some(access) = session
            && !pending_secret_authorized(
                &mut tx,
                user_id,
                access.session_hash,
                access.token_hash.as_ref(),
                access.now,
            )
            .await?
        {
            return Ok(None);
        }
        sqlx::query(
            "UPDATE account SET totp_secret_enc = ?2 \
             WHERE id = ?1 AND totp_enabled = 0 AND (totp_secret_enc IS NULL OR ?3 = 1)",
        )
        .bind(user_id)
        .bind(sealed)
        .bind(i64::from(replace))
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query("SELECT totp_enabled, totp_secret_enc FROM account WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        let Some(row) = row else { return Ok(None) };
        if row.try_get::<i64, _>("totp_enabled")? != 0 {
            return Ok(None);
        }
        Ok(row.try_get("totp_secret_enc")?)
    }

    /// Decides one second-factor attempt (see the module docs). Returns `true` only when the
    /// factor is accepted. A TOTP step is accepted only if it is greater than the stored last
    /// step (replay), and is recorded in the same transaction; a recovery code is consumed
    /// (`used_at`) atomically. The failure counter is NOT cleared here: the caller invokes
    /// [`SqliteDb::record_login_success`] once the whole login is complete.
    ///
    /// # Errors
    /// Database failure.
    pub async fn second_factor_step(&self, a: FactorAttempt<'_>) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT username, totp_enabled, totp_last_step, locked_until FROM account \
             WHERE id = ?1 AND deleted_at IS NULL AND disabled_at IS NULL",
        )
        .bind(a.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let mut exists = false;
        let mut actor: Option<String> = None;
        let mut enabled = false;
        let mut last_step: Option<i64> = None;
        let mut locked = false;
        if let Some(r) = &row {
            exists = true;
            actor = Some(r.try_get("username")?);
            enabled = r.try_get::<i64, _>("totp_enabled")? != 0;
            last_step = r.try_get("totp_last_step")?;
            locked = r
                .try_get::<Option<i64>, _>("locked_until")?
                .is_some_and(|l| l > a.now);
        }
        let usable = exists && enabled && !locked && a.precondition_ok;
        let mut accepted = false;
        let mut recovery_used = false;
        if usable {
            match a.factor {
                SecondFactor::Totp(Some(step)) if last_step.is_none_or(|l| step > l) => {
                    // Compare-and-set: only one concurrent request can move the step forward.
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
        let reason = if !exists {
            "no_user"
        } else if locked {
            "locked"
        } else if !enabled {
            "not_enrolled"
        } else if !a.precondition_ok {
            "reauth_failed"
        } else {
            "bad_code"
        };
        // Re-auth with a code from a step that was already used is the owner re-using their own
        // code (e.g. right after a password change), not a guess: refuse it without counting it.
        let own_replay = !accepted
            && usable
            && a.purpose != "login"
            && matches!(a.factor, SecondFactor::Totp(Some(step)) if last_step.is_some_and(|l| step <= l));
        if !accepted && exists && !locked && !own_replay {
            bump_failure(&mut tx, a.user_id, a.now).await?;
        }
        let reason = if own_replay { "replay" } else { reason };
        let (event, detail) = if recovery_used {
            ("mfa.recovery_used", format!("purpose={}", a.purpose))
        } else if accepted {
            ("mfa.ok", format!("purpose={}", a.purpose))
        } else {
            ("mfa.fail", format!("purpose={} reason={reason}", a.purpose))
        };
        audit_tx(&mut tx, a.now, actor.as_deref(), event, Some(&detail), a.ip).await?;
        tx.commit().await?;
        Ok(accepted)
    }

    /// Confirms first-time enrollment in one transaction: the pending secret becomes active,
    /// the matched step becomes the replay floor and `recovery_hashes` replace any old codes.
    /// Returns `false` (counted as a failure) for a wrong code, a locked account, or when there
    /// is no pending secret.
    ///
    /// # Errors
    /// Database failure.
    // Every argument is a distinct, required input of the one atomic verdict.
    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_totp_enrollment(
        &self,
        user_id: i64,
        sealed: &[u8],
        token_hash: Option<[u8; 32]>,
        step: Option<i64>,
        recovery_hashes: &[[u8; 32]],
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        let row = sqlx::query(
            "SELECT username, totp_enabled, totp_secret_enc, locked_until, enroll_token_hash, \
             enroll_token_expires FROM account WHERE id = ?1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let mut exists = false;
        let mut actor: Option<String> = None;
        let mut pending = false;
        let mut locked = false;
        if let Some(r) = &row {
            exists = true;
            actor = Some(r.try_get("username")?);
            // The confirmation must be for the very secret the user saw (`sealed`), and the
            // one-time enrollment token must still be valid and match.
            let stored_blob: Option<Vec<u8>> = r.try_get("totp_secret_enc")?;
            let stored_tok: Option<Vec<u8>> = r.try_get("enroll_token_hash")?;
            let expires: Option<i64> = r.try_get("enroll_token_expires")?;
            let token_ok = match (&stored_tok, &token_hash) {
                (Some(s), Some(t)) => ct_eq32(s, t),
                _ => false,
            } && expires.is_some_and(|e| e > now);
            pending = r.try_get::<i64, _>("totp_enabled")? == 0
                && stored_blob.as_deref() == Some(sealed)
                && token_ok;
            locked = r
                .try_get::<Option<i64>, _>("locked_until")?
                .is_some_and(|l| l > now);
        }
        let accepted = exists && pending && !locked && step.is_some();
        if accepted {
            let res = sqlx::query(
                "UPDATE account SET totp_enabled = 1, totp_last_step = ?2, enroll_token_hash = NULL, \
                 enroll_token_expires = NULL WHERE id = ?1 AND totp_enabled = 0 AND totp_secret_enc = ?3",
            )
            .bind(user_id)
            .bind(step)
            .bind(sealed)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Err(StoreError::NotFound);
            }
            sqlx::query("DELETE FROM recovery_code WHERE account_id = ?1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            for h in recovery_hashes {
                sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, ?2)")
                    .bind(user_id)
                    .bind(h.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
        } else if exists && !locked {
            bump_failure(&mut tx, user_id, now).await?;
        }
        let (event, detail) = if accepted {
            ("mfa.enrolled", "ok")
        } else if locked {
            ("mfa.fail", "purpose=enroll reason=locked")
        } else {
            ("mfa.fail", "purpose=enroll reason=bad_code")
        };
        audit_tx(&mut tx, now, actor.as_deref(), event, Some(detail), ip).await?;
        tx.commit().await?;
        Ok(accepted)
    }

    /// Replaces all recovery codes (old ones, used or not, stop working). Audit-logged. Bound to
    /// the session that re-authenticated, like [`SqliteDb::change_password`].
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the session is gone; database failure.
    pub async fn replace_recovery_codes(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        hashes: &[[u8; 32]],
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_immediate().await?;
        if !crate::auth::session_is_live(&mut tx, session_hash, user_id, now).await? {
            return Err(StoreError::NotFound);
        }
        sqlx::query("DELETE FROM recovery_code WHERE account_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for h in hashes {
            sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, ?2)")
                .bind(user_id)
                .bind(h.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        let actor = username_of(&mut tx, user_id).await?;
        audit_tx(
            &mut tx,
            now,
            actor.as_deref(),
            "mfa.recovery_regenerated",
            None,
            ip,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Number of recovery codes that can still be used.
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_unused_recovery_codes(&self, user_id: i64) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM recovery_code WHERE account_id = ?1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(self.writer())
        .await?)
    }

    /// Replaces the password hash after an authenticated, re-verified change, revokes EVERY
    /// session of the user and inserts `new_session` in its place (rotation at password change).
    /// API keys are kept (the owner is present and authenticated). Audit-logged.
    ///
    /// The change is bound to the session that re-authenticated: if `session_hash` is gone (a
    /// recovery, reset or revocation committed meanwhile), nothing is written, so a concurrent
    /// change cannot undo it.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the user or the session vanished.
    pub async fn change_password(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        password_hash: &str,
        new_session: &NewSession,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_immediate().await?;
        let own = sqlx::query(
            "DELETE FROM session WHERE id_hash = ?1 AND account_id = ?2 \
             AND stage = 'active' AND expires_at > ?3",
        )
        .bind(session_hash.as_slice())
        .bind(user_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if own.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        let res = sqlx::query(
            "UPDATE account SET password_hash = ?2, password_changed_at = ?3 WHERE id = ?1",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        let others = sqlx::query("DELETE FROM session WHERE account_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let revoked = others.saturating_add(1);
        let mut s = new_session.clone();
        s.user_id = user_id;
        s.stage = SessionStage::Active;
        crate::auth::insert_in_tx(&mut tx, &s, 5, false).await?;
        let detail = format!("sessions_revoked={revoked}");
        let actor = username_of(&mut tx, user_id).await?;
        audit_tx(
            &mut tx,
            now,
            actor.as_deref(),
            "user.password_changed",
            Some(&detail),
            ip,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Unexpired `active` sessions of the user, newest first.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_active_sessions(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Vec<SessionInfo>, StoreError> {
        let rows = sqlx::query(
            "SELECT id_hash, created_at, last_seen_at, ip, user_agent FROM session \
             WHERE account_id = ?1 AND stage = 'active' AND expires_at > ?2 \
             ORDER BY created_at DESC, rowid DESC",
        )
        .bind(user_id)
        .bind(now)
        .fetch_all(self.writer())
        .await?;
        rows.iter()
            .map(|r| {
                let raw: Vec<u8> = r.try_get("id_hash")?;
                Ok(SessionInfo {
                    id_hash: <[u8; 32]>::try_from(raw.as_slice())
                        .map_err(|_| StoreError::OutOfRange("session id hash"))?,
                    created_at: r.try_get("created_at")?,
                    last_seen_at: r.try_get("last_seen_at")?,
                    ip: r.try_get("ip")?,
                    user_agent: r.try_get("user_agent")?,
                })
            })
            .collect()
    }

    /// Revokes one session owned by `user_id`, while the calling session is still active.
    /// Audit-logged when removed.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the calling session is no longer usable; database failure.
    pub async fn revoke_user_session(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        id_hash: &[u8; 32],
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_immediate().await?;
        require_revoking_session(&mut tx, user_id, session_hash, now).await?;
        let n = sqlx::query("DELETE FROM session WHERE account_id = ?1 AND id_hash = ?2")
            .bind(user_id)
            .bind(id_hash.as_slice())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n > 0 {
            let actor = username_of(&mut tx, user_id).await?;
            audit_tx(&mut tx, now, actor.as_deref(), "session.revoked", None, ip).await?;
        }
        tx.commit().await?;
        Ok(n > 0)
    }

    /// Revokes every session of the user except the still-active calling session `keep`.
    /// Returns how many were removed.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the calling session is no longer usable; database failure.
    pub async fn revoke_other_sessions(
        &self,
        user_id: i64,
        keep: &[u8; 32],
        ip: Option<&str>,
        now: i64,
    ) -> Result<u64, StoreError> {
        let mut tx = self.begin_immediate().await?;
        require_revoking_session(&mut tx, user_id, keep, now).await?;
        let n = sqlx::query("DELETE FROM session WHERE account_id = ?1 AND id_hash <> ?2")
            .bind(user_id)
            .bind(keep.as_slice())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let detail = format!("count={n}");
        let actor = username_of(&mut tx, user_id).await?;
        audit_tx(
            &mut tx,
            now,
            actor.as_deref(),
            "session.revoked_others",
            Some(&detail),
            ip,
        )
        .await?;
        tx.commit().await?;
        Ok(n)
    }
}
