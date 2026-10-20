//! Invitations, recovery codes and staged credential swaps on Postgres (T112; 2.x `invite.rs`, SEC-063, SEC-064,
//! SEC-085). Every mutation runs under the account-domain lock; the D32 refusal counter, its check and the revocation
//! at the 3rd refusal are one locked transaction (review 30.3 b).

use sqlx::{PgConnection, Row};

use crate::account::{
    AccountActor, AccountError, AccountPolicy, AuditActor, AuditEntry, ChosenProfile, Role,
    ThrottleKey, check_login_name,
};
use crate::invite::{
    AccountPurgeReport, CommitRecovery, INVITE_TTL_RANGE, InvitePurpose, InviteRow,
    MAX_NAME_REFUSALS, MAX_OPEN_INVITES, NewInvite, NewRecovery, RECOVER_TTL_RANGE, Redeemed,
    Redemption, STAGING_TTL_SECS, StagedSwap,
};
use crate::pg::PgDb;
use crate::pg::account::{
    confusable_display_name_in_use, count_live, display_name_in_use, insert_account_with,
    load_live, login_name_in_use, open_invite_for_name, require_session_actor, write_audit,
    write_audit_throttled,
};
use crate::pg::auth::insert_in_tx;
use crate::profile::{RegistrationProfile, normalize_email, self_display_name_is_valid};
use crate::{SessionStage, StoreError};

fn invite_from_row(r: &sqlx::postgres::PgRow) -> Result<InviteRow, StoreError> {
    Ok(InviteRow {
        id: r.try_get("id")?,
        purpose: InvitePurpose::parse(&r.try_get::<String, _>("purpose")?)?,
        username: r.try_get("username")?,
        role: r
            .try_get::<Option<String>, _>("role")?
            .map(|s| Role::parse(&s).ok_or(StoreError::OutOfRange("invite.role")))
            .transpose()?,
        user_id: r.try_get("account_id")?,
        created_by: r.try_get("created_by")?,
        created_via: r.try_get("created_via")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        used_at: r.try_get("used_at")?,
        used_by: r.try_get("used_by")?,
        revoked_at: r.try_get("revoked_at")?,
    })
}

/// Invite columns (a macro so complete statements stay compile-time literals, SEC-088).
macro_rules! invite_cols {
    () => {
        "id, purpose, username, role, account_id, created_by, created_via, \
         created_at, expires_at, used_at, used_by, revoked_at"
    };
}

/// Constant-time equality of two 32-byte hashes.
fn ct_eq(a: &[u8], b: &[u8; 32]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The issuer must still be valid: the operator (`NULL`), or an enabled live admin.
async fn issuer_valid(
    conn: &mut PgConnection,
    created_by: Option<i64>,
) -> Result<bool, StoreError> {
    match created_by {
        None => Ok(true),
        Some(id) => Ok(matches!(
            load_live(conn, id).await?,
            Some(s) if s.role == Role::Admin && !s.disabled
        )),
    }
}

/// Deletes the staged swap of `user_id` together with the pending session bound to it.
pub(crate) async fn drop_staged_swap(
    conn: &mut PgConnection,
    user_id: i64,
) -> Result<u64, StoreError> {
    let staged: i64 =
        sqlx::query_scalar("SELECT count(*) FROM credential_staging WHERE account_id = $1")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
    // The session goes first (the trigger removes the staged row with it); the explicit delete below is
    // the belt to that suspender.
    sqlx::query(
        "DELETE FROM session WHERE id_hash IN \
         (SELECT session_hash FROM credential_staging WHERE account_id = $1)",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM credential_staging WHERE account_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    u64::try_from(staged).map_err(|_| StoreError::OutOfRange("staged count"))
}

/// Records `ip_key` as a completed-login address (cap 5 per user, newest kept).
pub(crate) async fn note_known_ip(
    conn: &mut PgConnection,
    user_id: i64,
    ip_key: &str,
    now: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO user_known_ip (account_id, ip_key, last_seen) VALUES ($1, $2, $3) \
         ON CONFLICT (account_id, ip_key) DO UPDATE SET last_seen = excluded.last_seen",
    )
    .bind(user_id)
    .bind(ip_key)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM user_known_ip WHERE account_id = $1 AND ip_key NOT IN \
         (SELECT ip_key FROM user_known_ip WHERE account_id = $1 \
          ORDER BY last_seen DESC, ip_key LIMIT 5)",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

impl PgDb {
    /// Issues an invitation (admin session; the caller re-authenticated). Needs `policy.multi_user`.
    /// Rules: login-name rules for new accounts (reserved names and the `user-<digits>` form refused),
    /// the name is free (live accounts, display names, open invitations), at most 20 open invitations.
    /// Returns the invite id; the code itself is never stored.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::MultiUserDisabled`], [`AccountError::BadTtl`],
    /// [`StoreError::InvalidUsername`], [`AccountError::ReservedName`],
    /// [`AccountError::UsernameUnavailable`], [`AccountError::TooManyOpenInvites`].
    pub async fn create_invite(
        &self,
        actor: &AccountActor,
        new: &NewInvite<'_>,
        policy: AccountPolicy,
        ip: Option<&str>,
        now: i64,
    ) -> Result<i64, StoreError> {
        let mut tx = self.begin_account().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let id = create_invite_in(
            &mut tx,
            Some(a.id),
            "ui",
            &AuditActor::account(a.id, a.role, &a.username),
            new,
            policy,
            ip,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Operator `nzbd user invite` (uploader/viewer only; there is no admin invite, D27).
    ///
    /// # Errors
    /// As [`PgDb::create_invite`] without the actor rule.
    pub async fn create_invite_operator(
        &self,
        new: &NewInvite<'_>,
        policy: AccountPolicy,
        now: i64,
    ) -> Result<i64, StoreError> {
        let mut tx = self.begin_account().await?;
        let id = create_invite_in(
            &mut tx,
            None,
            "cli",
            &AuditActor::cli(),
            new,
            policy,
            None,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Revokes an open invitation or recovery code (admin session).
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`] (unknown id),
    /// [`AccountError::InvalidState`] (already used or revoked).
    pub async fn revoke_invite(
        &self,
        actor: &AccountActor,
        invite_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        revoke_invite_in(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            invite_id,
            ip,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Open (unused, unrevoked, unexpired) codes, newest first, with their issuers.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_open_invites(&self, now: i64) -> Result<Vec<InviteRow>, StoreError> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            invite_cols!(),
            " FROM invite WHERE used_at IS NULL AND revoked_at IS NULL \
             AND expires_at > $1 ORDER BY id DESC"
        ))
        .bind(now)
        .fetch_all(self.web())
        .await?;
        rows.iter().map(invite_from_row).collect()
    }

    /// One code by id.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_invite(&self, id: i64) -> Result<Option<InviteRow>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            invite_cols!(),
            " FROM invite WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(invite_from_row).transpose()
    }

    /// The login name an OPEN code would apply to (the reserved name of an invitation, the target's
    /// login name of a recovery code), or `None` for any other code. Read-only; the web layer uses
    /// it solely to apply the "password is not the username" rule of the one password policy
    /// (SEC-022) before the password is hashed. Its only caller is the holder of the code.
    ///
    /// # Errors
    /// Database failure.
    pub async fn open_code_login_name(
        &self,
        code_hash: &[u8; 32],
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        let name: Option<Option<String>> = sqlx::query_scalar(
            "SELECT CASE i.purpose WHEN 'invite' THEN i.username ELSE u.username END \
             FROM invite i LEFT JOIN account u ON u.id = i.account_id \
             WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.revoked_at IS NULL \
             AND i.expires_at > $2",
        )
        .bind(code_hash.as_slice())
        .bind(now)
        .fetch_optional(self.web())
        .await?;
        Ok(name.flatten())
    }

    /// Issues a single-use recovery code for a uploader/viewer (admin session, re-authenticated by the
    /// caller). Any earlier open code for the target and any staged swap are removed first (a re-issue
    /// kills the previous attempt, N4). Audit `recover_issue` with the issuing admin and the target.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`], [`AccountError::SelfTarget`],
    /// [`AccountError::AdminIsCliOnly`], [`AccountError::InvalidState`] (disabled target),
    /// [`AccountError::BadTtl`].
    pub async fn issue_recovery(
        &self,
        actor: &AccountActor,
        new: &NewRecovery<'_>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<i64, StoreError> {
        let mut tx = self.begin_account().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        if a.id == new.target_id {
            return Err(AccountError::SelfTarget.into());
        }
        let id = issue_recovery_in(
            &mut tx,
            Some(a.id),
            "ui",
            &AuditActor::account(a.id, a.role, &a.username),
            new,
            ip,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Operator-issued recovery code for a uploader/viewer (admins are recovered with
    /// `reset-password`/`enroll-token`, never with a code).
    ///
    /// # Errors
    /// As [`PgDb::issue_recovery`] without the actor rules.
    pub async fn issue_recovery_operator(
        &self,
        new: &NewRecovery<'_>,
        now: i64,
    ) -> Result<i64, StoreError> {
        let mut tx = self.begin_account().await?;
        let id =
            issue_recovery_in(&mut tx, None, "cli", &AuditActor::cli(), new, None, now).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Redeems a code at `/invite` (anonymous, token-gated) with the registration profile of D32 (T109): the email
    /// and the self-chosen display name typed at `/invite`, passed RAW for every code (the form cannot know which kind
    /// of code it holds). One writer transaction decides: hash lookup, constant-time compare, unused, unrevoked,
    /// unexpired, issuer still valid and, per purpose, the username is still free / the target is still live, enabled
    /// and not an admin. Every such refusal (also registration off, a taken username or the account cap) is
    /// [`AccountError::InvalidCode`] with the same work and one throttled `invite_redeem_failure` row per address,
    /// and the profile is never looked at (SEC-064).
    ///
    /// * invitation: only now, in the same writer transaction:
    ///   1. display name shape ([`crate::self_display_name_is_valid`]) else [`AccountError::InvalidDisplayName`],
    ///      then the email ([`crate::normalize_email`]) else [`AccountError::InvalidEmail`]; both roll back and
    ///      consume nothing (they reveal nothing about other accounts);
    ///   2. availability: the name must not equal (NOCASE) the invitation's own login name, any live login name, any
    ///      live display name or the name reserved by any open invitation. If it does, `invite.name_refusals` is
    ///      incremented, the 3rd refusal also revokes the invitation ([`MAX_NAME_REFUSALS`]), an
    ///      `invite_name_unavailable` audit row (`invite=<id> refusals=<n>`, never the name) and on revocation an
    ///      `invite_revoke` row (`reason=name_refusals`) are written, and that is COMMITTED before
    ///      [`AccountError::DisplayNameUnavailable`] is returned;
    ///   3. otherwise inserts the account (role from the invite row only) with the chosen display name and the
    ///      normalised email, marks the code used, creates a `pending_mfa` session with `enroll_proven = 1`, audit
    ///      `invite_redeem` (anonymous actor, `target_id` = new account). The audit rows carry neither value.
    /// * recovery: the profile is ignored entirely; marks the code used, parks the new password hash in
    ///   `credential_staging` bound to the new pending session and changes nothing about the account; audit
    ///   `recover_redeem` naming the issuer in the detail (`issued_by=<id>`).
    ///
    /// On either success, the presented session (`Redemption::replacing`) is revoked before
    /// committing. A revoke failure rolls back the redemption; refusals never revoke it.
    ///
    /// # Errors
    /// [`AccountError::InvalidCode`], [`AccountError::InvalidDisplayName`], [`AccountError::InvalidEmail`],
    /// [`AccountError::DisplayNameUnavailable`]; database failure.
    pub async fn redeem_code_with_profile(
        &self,
        r: &Redemption<'_>,
        profile: &RegistrationProfile<'_>,
        policy: AccountPolicy,
        ip: Option<&str>,
        now: i64,
    ) -> Result<Redeemed, StoreError> {
        self.redeem_with(r, profile, policy, ip, now).await
    }

    async fn redeem_with(
        &self,
        r: &Redemption<'_>,
        profile: &RegistrationProfile<'_>,
        policy: AccountPolicy,
        ip: Option<&str>,
        now: i64,
    ) -> Result<Redeemed, StoreError> {
        let mut tx = self.begin_account().await?;
        // An `Err` here drops `tx` uncommitted: a shape refusal of the profile changes nothing.
        match redeem_in(&mut tx, r, profile, policy, ip, now).await? {
            Outcome::Done(done) => {
                if let Some(old) = r.replacing {
                    sqlx::query("DELETE FROM session WHERE id_hash = $1")
                        .bind(old.as_slice())
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                return Ok(done);
            }
            Outcome::NameRefused { invite_revoked } => {
                // The refusal counter (and the revocation at the 3rd) must survive the failed redemption.
                tx.commit().await?;
                return Err(AccountError::DisplayNameUnavailable { invite_revoked }.into());
            }
            Outcome::Invalid => {}
        }
        // The failure row is part of the same transaction shape as a success: one write, one commit,
        // no early return that is cheaper than the real path.
        write_audit_throttled(
            &mut tx,
            &AuditEntry {
                who: AuditActor::anonymous(),
                event: "invite_redeem_failure",
                detail: Some("invalid"),
                ip,
                target_id: None,
            },
            ThrottleKey::Address(ip),
            60,
            now,
        )
        .await?;
        tx.commit().await?;
        Err(AccountError::InvalidCode.into())
    }

    /// The staged swap of `(user_id, session_hash)`, if it exists and has not expired.
    ///
    /// # Errors
    /// Database failure.
    pub async fn staged_swap(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        now: i64,
    ) -> Result<Option<StagedSwap>, StoreError> {
        let row = sqlx::query(
            "SELECT totp_secret_enc, expires_at FROM credential_staging \
             WHERE account_id = $1 AND session_hash = $2 AND expires_at > $3",
        )
        .bind(user_id)
        .bind(session_hash.as_slice())
        .bind(now)
        .fetch_optional(self.web())
        .await?;
        row.map(|r| {
            Ok(StagedSwap {
                totp_secret_enc: r.try_get("totp_secret_enc")?,
                expires_at: r.try_get("expires_at")?,
            })
        })
        .transpose()
    }

    /// Parks the sealed pending TOTP secret in the staged swap unless one is already there (a reload
    /// shows the SAME secret) and returns the blob now stored. `None` when no unexpired staged swap
    /// matches the session.
    ///
    /// # Errors
    /// Database failure.
    pub async fn stage_totp_secret(
        &self,
        user_id: i64,
        session_hash: &[u8; 32],
        sealed: &[u8],
        now: i64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut tx = self.begin_account().await?;
        if !crate::pg::mfa::pending_session_is_live(&mut tx, user_id, session_hash, now).await? {
            return Ok(None);
        }
        sqlx::query(
            "UPDATE credential_staging SET totp_secret_enc = $3 \
             WHERE account_id = $1 AND session_hash = $2 AND expires_at > $4 AND totp_secret_enc IS NULL",
        )
        .bind(user_id)
        .bind(session_hash.as_slice())
        .bind(sealed)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let blob: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM credential_staging \
             WHERE account_id = $1 AND session_hash = $2 AND expires_at > $3",
        )
        .bind(user_id)
        .bind(session_hash.as_slice())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(blob.flatten())
    }

    /// The commit point of a staged recovery (M3, N4): in ONE transaction re-checks the staged row
    /// (matches `(user_id, confirming session)`, unexpired, the sealed secret that was displayed, the
    /// invite it came from), the target (live, enabled, not an admin) and the issuer, then replaces the
    /// password hash and the sealed TOTP secret, resets the replay floor to `step`, replaces the recovery
    /// codes, revokes every session of the account and every API key it owns, clears its lock and
    /// throttle state, records `credentials_replaced_at/by` and the known address, issues the new
    /// `active` session and writes `recover_apply`. Anything else changes nothing.
    ///
    /// # Errors
    /// [`AccountError::StagingInvalid`] (the one answer for every mismatch); database failure.
    #[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
    pub async fn commit_staged_recovery(
        &self,
        c: &CommitRecovery<'_>,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        if !crate::pg::mfa::pending_session_is_live(&mut tx, c.user_id, c.session_hash, now).await?
        {
            return Err(AccountError::StagingInvalid.into());
        }
        let staged = sqlx::query(
            "SELECT invite_id, issued_by, password_hash, totp_secret_enc FROM credential_staging \
             WHERE account_id = $1 AND session_hash = $2 AND expires_at > $3",
        )
        .bind(c.user_id)
        .bind(c.session_hash.as_slice())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(staged) = staged else {
            return Err(AccountError::StagingInvalid.into());
        };
        let invite_id: i64 = staged.try_get("invite_id")?;
        let issued_by: Option<i64> = staged.try_get("issued_by")?;
        let password_hash: String = staged.try_get("password_hash")?;
        let staged_blob: Option<Vec<u8>> = staged.try_get("totp_secret_enc")?;
        if staged_blob.as_deref() != Some(c.sealed) {
            return Err(AccountError::StagingInvalid.into());
        }
        let redeemed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invite WHERE id = $1 AND purpose = 'recover' AND account_id = $2 \
             AND used_at IS NOT NULL",
        )
        .bind(invite_id)
        .bind(c.user_id)
        .fetch_one(&mut *tx)
        .await?;
        let target_ok = matches!(
            load_live(&mut tx, c.user_id).await?,
            Some(s) if !s.disabled && s.role != Role::Admin
        );
        if redeemed == 0 || !target_ok || !issuer_valid(&mut tx, issued_by).await? {
            return Err(AccountError::StagingInvalid.into());
        }

        sqlx::query(
            "UPDATE account SET password_hash = $2, password_changed_at = $3, totp_secret_enc = $4, \
             totp_enabled = true, totp_last_step = $5, enroll_token_hash = NULL, \
             enroll_token_expires = NULL, credentials_replaced_at = $3, credentials_replaced_by = $6, \
             last_login_at = $3, failed_logins = 0, locked_until = NULL, last_failed_at = NULL \
             WHERE id = $1",
        )
        .bind(c.user_id)
        .bind(&password_hash)
        .bind(now)
        .bind(c.sealed)
        .bind(c.step)
        .bind(issued_by)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM recovery_code WHERE account_id = $1")
            .bind(c.user_id)
            .execute(&mut *tx)
            .await?;
        for h in c.recovery_hashes {
            sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES ($1, $2)")
                .bind(c.user_id)
                .bind(h.as_slice())
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM session WHERE account_id = $1")
            .bind(c.user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM credential_staging WHERE account_id = $1")
            .bind(c.user_id)
            .execute(&mut *tx)
            .await?;
        let keys = sqlx::query(
            "UPDATE api_key SET revoked_at = $2 WHERE owner_id = $1 AND revoked_at IS NULL",
        )
        .bind(c.user_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        crate::pg::account::clear_throttle_state(&mut tx, c.user_id).await?;
        let mut s = c.new_session.clone();
        s.user_id = c.user_id;
        s.stage = SessionStage::Active;
        insert_in_tx(&mut tx, &s, 5, false).await?;
        if let Some(ip_key) = c.ip_key {
            note_known_ip(&mut tx, c.user_id, ip_key, now).await?;
        }
        let detail = match issued_by {
            Some(a) => format!("issued_by={a} keys_revoked={keys}"),
            None => format!("issued_by=operator keys_revoked={keys}"),
        };
        write_audit(
            &mut tx,
            &AuditActor::anonymous(),
            now,
            "recover_apply",
            Some(&detail),
            ip,
            Some(c.user_id),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Cancels a redeemed-but-uncommitted recovery (admin session, CSRF only: it only removes a pending
    /// change, N4): deletes the staged swap and the pending session bound to it. Audit `recover_cancel`.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`], [`AccountError::TargetNotFound`], [`AccountError::SelfTarget`],
    /// [`AccountError::AdminIsCliOnly`], [`AccountError::InvalidState`] (nothing staged).
    pub async fn cancel_recovery(
        &self,
        actor: &AccountActor,
        target_id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        let a = require_session_actor(&mut tx, actor, Role::Admin, now).await?;
        let target = load_live(&mut tx, target_id)
            .await?
            .ok_or(AccountError::TargetNotFound)?;
        if target.id == a.id {
            return Err(AccountError::SelfTarget.into());
        }
        if target.role == Role::Admin {
            return Err(AccountError::AdminIsCliOnly.into());
        }
        if drop_staged_swap(&mut tx, target.id).await? == 0 {
            return Err(AccountError::InvalidState.into());
        }
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "recover_cancel",
            None,
            ip,
            Some(target.id),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revokes every open code (startup while `security.multi_user` is off, I-5): audit
    /// `invite_revoke` with actor `system`. Returns the number revoked.
    ///
    /// # Errors
    /// Database failure.
    pub async fn revoke_open_invites_system(&self, now: i64) -> Result<u64, StoreError> {
        self.revoke_open_invites_system_for(now, "multi_user_off")
            .await
    }

    /// [`PgDb::revoke_open_invites_system`] with the audit reason (`multi_user_off`,
    /// `registration_disabled`). Recovery codes are not touched.
    ///
    /// # Errors
    /// Database failure.
    pub async fn revoke_open_invites_system_for(
        &self,
        now: i64,
        reason: &'static str,
    ) -> Result<u64, StoreError> {
        let detail = format!("reason={reason}");
        let mut tx = self.begin_account().await?;
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM invite WHERE purpose = 'invite' AND used_at IS NULL AND revoked_at IS NULL",
        )
        .fetch_all(&mut *tx)
        .await?;
        for id in &ids {
            sqlx::query("UPDATE invite SET revoked_at = $2 WHERE id = $1")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            write_audit(
                &mut tx,
                &AuditActor::system(),
                now,
                "invite_revoke",
                Some(&detail),
                None,
                None,
            )
            .await?;
        }
        tx.commit().await?;
        u64::try_from(ids.len()).map_err(|_| StoreError::OutOfRange("invite count"))
    }

    /// Daily maintenance of the account tables: used/revoked/expired codes older than 7 days, staged
    /// swaps past `expires_at`, aggregate rows idle 48 h, lock rows idle 24 h, known addresses idle 90 d.
    /// (The audit rows survive; they follow the log retention.)
    ///
    /// # Errors
    /// Database failure.
    pub async fn purge_account_state(&self, now: i64) -> Result<AccountPurgeReport, StoreError> {
        const DAY: i64 = 86_400;
        let mut tx = self.begin_account().await?;
        let invites = sqlx::query(
            "DELETE FROM invite WHERE id NOT IN (SELECT invite_id FROM credential_staging) AND \
             coalesce(used_at, revoked_at, expires_at) < $1 AND \
             (used_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at < $1)",
        )
        .bind(now.saturating_sub(7 * DAY))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // A staged swap whose pending session survives is deleted with it: drop the session first so the
        // user sees a clean "start again" instead of a dangling pending session.
        let staged: i64 =
            sqlx::query_scalar("SELECT count(*) FROM credential_staging WHERE expires_at <= $1")
                .bind(now)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query(
            "DELETE FROM session WHERE id_hash IN \
             (SELECT session_hash FROM credential_staging WHERE expires_at <= $1)",
        )
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM credential_staging WHERE expires_at <= $1")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let staging = u64::try_from(staged).map_err(|_| StoreError::OutOfRange("staged count"))?;
        let throttle = sqlx::query(
            "DELETE FROM account_throttle WHERE hour_start < $1 AND day_start < $1 \
             AND coalesce(throttled_until, 0) < $2 AND coalesce(mfa_refused_until, 0) < $2",
        )
        .bind(now.saturating_sub(2 * DAY))
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let locks = sqlx::query(
            "DELETE FROM login_lock WHERE last_failure < $1 AND coalesce(locked_until, 0) < $2",
        )
        .bind(now.saturating_sub(DAY))
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let known_ips = sqlx::query("DELETE FROM user_known_ip WHERE last_seen < $1")
            .bind(now.saturating_sub(90 * DAY))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(AccountPurgeReport {
            invites,
            staging,
            throttle,
            locks,
            known_ips,
        })
    }
}

#[allow(clippy::too_many_arguments)] // one transaction body shared by the admin and operator entry points
async fn create_invite_in(
    conn: &mut PgConnection,
    created_by: Option<i64>,
    via: &str,
    who: &AuditActor,
    new: &NewInvite<'_>,
    policy: AccountPolicy,
    ip: Option<&str>,
    now: i64,
) -> Result<i64, StoreError> {
    if !policy.multi_user {
        return Err(AccountError::MultiUserDisabled.into());
    }
    if !policy.registration_enabled {
        return Err(AccountError::InvitesDisabled.into());
    }
    if !INVITE_TTL_RANGE.contains(&new.ttl_secs) {
        return Err(AccountError::BadTtl.into());
    }
    check_login_name(new.username)?;
    // Expired open invitations hold the username through the unique index: close them first.
    sqlx::query(
        "UPDATE invite SET revoked_at = $1 WHERE purpose = 'invite' AND used_at IS NULL \
         AND revoked_at IS NULL AND expires_at <= $1",
    )
    .bind(now)
    .execute(&mut *conn)
    .await?;
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM invite WHERE purpose = 'invite' AND used_at IS NULL \
         AND revoked_at IS NULL",
    )
    .fetch_one(&mut *conn)
    .await?;
    if open >= MAX_OPEN_INVITES {
        return Err(AccountError::TooManyOpenInvites.into());
    }
    let display_taken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account WHERE lower(display_name) = lower($1) AND deleted_at IS NULL",
    )
    .bind(new.username)
    .fetch_one(&mut *conn)
    .await?;
    if login_name_in_use(conn, new.username).await? || display_taken > 0 {
        return Err(AccountError::UsernameUnavailable.into());
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO invite (purpose, token_hash, username, role, created_by, created_via, \
         created_at, expires_at) VALUES ('invite', $1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(new.code_hash.as_slice())
    .bind(new.username)
    .bind(Role::from(new.role).as_str())
    .bind(created_by)
    .bind(via)
    .bind(now)
    .bind(now.saturating_add(new.ttl_secs))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        let unique = matches!(&e, sqlx::Error::Database(d) if d.is_unique_violation());
        if unique {
            StoreError::from(AccountError::UsernameUnavailable)
        } else {
            StoreError::Db(e)
        }
    })?;
    let detail = format!("invite={id} role={}", Role::from(new.role).as_str());
    write_audit(conn, who, now, "invite_create", Some(&detail), ip, None).await?;
    Ok(id)
}

async fn revoke_invite_in(
    conn: &mut PgConnection,
    who: &AuditActor,
    invite_id: i64,
    ip: Option<&str>,
    now: i64,
) -> Result<(), StoreError> {
    let row =
        sqlx::query("SELECT purpose, account_id, used_at, revoked_at FROM invite WHERE id = $1")
            .bind(invite_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(AccountError::TargetNotFound)?;
    if row.try_get::<Option<i64>, _>("used_at")?.is_some()
        || row.try_get::<Option<i64>, _>("revoked_at")?.is_some()
    {
        return Err(AccountError::InvalidState.into());
    }
    sqlx::query("UPDATE invite SET revoked_at = $2 WHERE id = $1")
        .bind(invite_id)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    let target: Option<i64> = row.try_get("account_id")?;
    let event = "invite_revoke";
    let detail = format!("invite={invite_id}");
    write_audit(conn, who, now, event, Some(&detail), ip, target).await?;
    Ok(())
}

async fn issue_recovery_in(
    conn: &mut PgConnection,
    created_by: Option<i64>,
    via: &str,
    who: &AuditActor,
    new: &NewRecovery<'_>,
    ip: Option<&str>,
    now: i64,
) -> Result<i64, StoreError> {
    if !RECOVER_TTL_RANGE.contains(&new.ttl_secs) {
        return Err(AccountError::BadTtl.into());
    }
    let target = load_live(conn, new.target_id)
        .await?
        .ok_or(AccountError::TargetNotFound)?;
    if target.role == Role::Admin {
        return Err(AccountError::AdminIsCliOnly.into());
    }
    if target.disabled {
        return Err(AccountError::InvalidState.into());
    }
    // One open code per target: a re-issue revokes the previous one and kills its staged swap (N4).
    sqlx::query(
        "UPDATE invite SET revoked_at = $2 WHERE purpose = 'recover' AND account_id = $1 \
         AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(target.id)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    drop_staged_swap(conn, target.id).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO invite (purpose, token_hash, account_id, created_by, created_via, created_at, \
         expires_at) VALUES ('recover', $1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(new.code_hash.as_slice())
    .bind(target.id)
    .bind(created_by)
    .bind(via)
    .bind(now)
    .bind(now.saturating_add(new.ttl_secs))
    .fetch_one(&mut *conn)
    .await?;
    let detail = format!("invite={id}");
    write_audit(
        conn,
        who,
        now,
        "recover_issue",
        Some(&detail),
        ip,
        Some(target.id),
    )
    .await?;
    Ok(id)
}

/// What [`redeem_in`] decided.
enum Outcome {
    /// Redeemed; the mutations are applied on the connection.
    Done(Redeemed),
    /// The uniform invalid-code refusal (the caller writes the failure row).
    Invalid,
    /// A valid invitation, but the chosen display name is not available; the counter (and the revocation at the
    /// 3rd) is applied on the connection and must be committed.
    NameRefused { invite_revoked: bool },
}

/// True if a self-chosen display name is not available: it equals (NOCASE) the invitation's own login name, a live
/// login name, a live display name or the name reserved by an open invitation, or it has the same confusable skeleton
/// as a live display name (`SECURITY_REVIEW` 26 L2; login names and open invitations keep the exact NOCASE rule).
async fn chosen_name_unavailable(
    conn: &mut PgConnection,
    name: &str,
    own_login: &str,
    now: i64,
) -> Result<bool, StoreError> {
    Ok(name.eq_ignore_ascii_case(own_login)
        || login_name_in_use(conn, name).await?
        || display_name_in_use(conn, name, None).await?
        || confusable_display_name_in_use(conn, name, None).await?
        || open_invite_for_name(conn, name, now).await?)
}

/// Counts one "not available" answer on invitation `id` and revokes it at the [`MAX_NAME_REFUSALS`]th. Returns
/// whether it is now revoked. Audit rows carry the invite id and the count, never the name.
async fn count_name_refusal(
    conn: &mut PgConnection,
    id: i64,
    ip: Option<&str>,
    now: i64,
) -> Result<bool, StoreError> {
    // SET expressions read the OLD row, so `name_refusals + 1` is the new count in both places.
    let refusals: i64 = sqlx::query_scalar(
        "UPDATE invite SET name_refusals = name_refusals + 1, \
         revoked_at = CASE WHEN name_refusals + 1 >= $3 THEN $2 ELSE revoked_at END \
         WHERE id = $1 RETURNING name_refusals",
    )
    .bind(id)
    .bind(now)
    .bind(MAX_NAME_REFUSALS)
    .fetch_one(&mut *conn)
    .await?;
    let detail = format!("invite={id} refusals={refusals}");
    write_audit(
        conn,
        &AuditActor::anonymous(),
        now,
        "invite_name_unavailable",
        Some(&detail),
        ip,
        None,
    )
    .await?;
    let revoked = refusals >= MAX_NAME_REFUSALS;
    if revoked {
        let detail = format!("invite={id} reason=name_refusals");
        write_audit(
            conn,
            &AuditActor::system(),
            now,
            "invite_revoke",
            Some(&detail),
            None,
            None,
        )
        .await?;
    }
    Ok(revoked)
}

/// The redemption decision. On [`Outcome::Done`] and [`Outcome::NameRefused`] the mutations are already applied on
/// `conn`; an `Err` must roll the transaction back.
#[allow(clippy::too_many_lines)] // one transaction: the order of its steps is the contract
async fn redeem_in(
    conn: &mut PgConnection,
    r: &Redemption<'_>,
    profile: &RegistrationProfile<'_>,
    policy: AccountPolicy,
    ip: Option<&str>,
    now: i64,
) -> Result<Outcome, StoreError> {
    let row = sqlx::query(
        "SELECT id, purpose, token_hash, username, role, account_id, created_by, expires_at, used_at, \
         revoked_at FROM invite WHERE token_hash = $1",
    )
    .bind(r.code_hash.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    // Defence in depth: with `security.multi_user` off the routes are not mounted, and a code that
    // somehow reaches the store is the same uniform failure.
    let Some(row) = row.filter(|_| policy.multi_user) else {
        return Ok(Outcome::Invalid);
    };
    let stored: Vec<u8> = row.try_get("token_hash")?;
    let open = ct_eq(&stored, r.code_hash)
        && row.try_get::<Option<i64>, _>("used_at")?.is_none()
        && row.try_get::<Option<i64>, _>("revoked_at")?.is_none()
        && row.try_get::<i64, _>("expires_at")? > now;
    if !open {
        return Ok(Outcome::Invalid);
    }
    let id: i64 = row.try_get("id")?;
    let created_by: Option<i64> = row.try_get("created_by")?;
    if !issuer_valid(conn, created_by).await? {
        return Ok(Outcome::Invalid);
    }
    match InvitePurpose::parse(&row.try_get::<String, _>("purpose")?)? {
        InvitePurpose::Invite => {
            // D28: with registration switched off an invitation code is the generic failure (same
            // transaction shape and work as any other refusal); recovery codes are unaffected.
            if !policy.registration_enabled {
                return Ok(Outcome::Invalid);
            }
            let username: String = row.try_get("username")?;
            let role = Role::parse(&row.try_get::<String, _>("role")?)
                .filter(|r| *r != Role::Admin)
                .ok_or(StoreError::OutOfRange("invite.role"))?;
            let display_taken: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM account WHERE lower(display_name) = lower($1) \
                 AND deleted_at IS NULL",
            )
            .bind(&username)
            .fetch_one(&mut *conn)
            .await?;
            if login_name_in_use(conn, &username).await?
                || display_taken > 0
                || count_live(conn).await? >= i64::from(policy.max_accounts)
                || check_login_name(&username).is_err()
            {
                return Ok(Outcome::Invalid);
            }
            // D32: the profile is looked at only now, with the code proven valid (SEC-064).
            if !self_display_name_is_valid(profile.display_name) {
                return Err(AccountError::InvalidDisplayName.into());
            }
            let email = normalize_email(profile.email).ok_or(AccountError::InvalidEmail)?;
            if chosen_name_unavailable(conn, profile.display_name, &username, now).await? {
                let invite_revoked = count_name_refusal(conn, id, ip, now).await?;
                return Ok(Outcome::NameRefused { invite_revoked });
            }
            let user_id = insert_account_with(
                conn,
                &username,
                r.password_hash,
                role,
                created_by,
                Some(ChosenProfile {
                    display_name: profile.display_name,
                    email: email.as_str(),
                }),
                now,
            )
            .await?;
            mark_used(conn, id, user_id, now).await?;
            let mut s = r.session.clone();
            s.user_id = user_id;
            s.stage = SessionStage::PendingMfa;
            insert_in_tx(conn, &s, 5, true).await?;
            let detail = format!("invite={id} role={}", role.as_str());
            write_audit(
                conn,
                &AuditActor::anonymous(),
                now,
                "invite_redeem",
                Some(&detail),
                ip,
                Some(user_id),
            )
            .await?;
            Ok(Outcome::Done(Redeemed::Account {
                user_id,
                username,
                role,
            }))
        }
        InvitePurpose::Recover => {
            let Some(user_id) = row.try_get::<Option<i64>, _>("account_id")? else {
                return Ok(Outcome::Invalid);
            };
            // H2: the target is re-read in this transaction.
            let ok = matches!(
                load_live(conn, user_id).await?,
                Some(s) if !s.disabled && s.role != Role::Admin
            );
            if !ok {
                return Ok(Outcome::Invalid);
            }
            mark_used(conn, id, user_id, now).await?;
            drop_staged_swap(conn, user_id).await?;
            let mut s = r.session.clone();
            s.user_id = user_id;
            s.stage = SessionStage::PendingMfa;
            // Not `enroll_proven`: the staged row, never the flag, decides recovery mode (review R5).
            insert_in_tx(conn, &s, 5, false).await?;
            sqlx::query(
                "INSERT INTO credential_staging (account_id, session_hash, invite_id, issued_by, \
                 password_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(user_id)
            .bind(s.id_hash.as_slice())
            .bind(id)
            .bind(created_by)
            .bind(r.password_hash)
            .bind(now)
            .bind(now.saturating_add(STAGING_TTL_SECS))
            .execute(&mut *conn)
            .await?;
            let detail = match created_by {
                Some(a) => format!("invite={id} issued_by={a}"),
                None => format!("invite={id} issued_by=operator"),
            };
            write_audit(
                conn,
                &AuditActor::anonymous(),
                now,
                "recover_redeem",
                Some(&detail),
                ip,
                Some(user_id),
            )
            .await?;
            Ok(Outcome::Done(Redeemed::Recovery {
                user_id,
                issued_by: created_by,
            }))
        }
    }
}

async fn mark_used(
    conn: &mut PgConnection,
    invite_id: i64,
    used_by: i64,
    now: i64,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE invite SET used_at = $2, used_by = $3 WHERE id = $1")
        .bind(invite_id)
        .bind(now)
        .bind(used_by)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
