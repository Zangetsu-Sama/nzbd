//! Upload API keys on Postgres (T112; 2.x `apikey.rs`, SEC-036). Creation (caps) and revocation are account-domain
//! mutations under the advisory lock; lookups are plain reads.

use sqlx::Row;

use crate::account::{AccountActor, AuditActor, Role};
use crate::apikey::{
    Actor, ApiKeyAuth, ApiKeyRow, CreateKey, MAX_ACTIVE_KEYS_INSTANCE, MAX_RATE_PER_MIN, NewApiKey,
    sanitize_label,
};
use crate::pg::PgDb;
use crate::pg::account::{require_actor, require_session_actor, write_audit};
use crate::{AccountError, StoreError};

/// Validates an optional per-key budget.
fn checked_rate(rate: Option<u32>) -> Result<Option<i64>, StoreError> {
    match rate {
        None => Ok(None),
        Some(n) if (1..=MAX_RATE_PER_MIN).contains(&n) => Ok(Some(i64::from(n))),
        Some(_) => Err(StoreError::OutOfRange("api_key.rate_per_min")),
    }
}

/// Inserts a key unless the owner or the instance is at its cap. Returns the new id.
async fn insert_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: NewApiKey<'_>,
    label: &str,
    owner: Option<i64>,
    max_per_owner: u32,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    let rate = checked_rate(key.rate_per_min)?;
    // The caps are checked by the insert itself; the caller holds the account-domain lock, so two creations cannot
    // both pass the count (the 2.x single writer).
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO api_key (name, prefix, key_hash, created_at, owner_id, scope, rate_per_min) \
         SELECT $1, $2, $3, $4, $6, 'upload', $7 \
         WHERE (SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL AND owner_id IS NOT DISTINCT FROM $6) < $5 \
           AND (SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL) < $8 \
         RETURNING id",
    )
    .bind(label)
    .bind(key.prefix)
    .bind(key.key_hash.as_slice())
    .bind(now)
    .bind(i64::from(max_per_owner))
    .bind(owner)
    .bind(rate)
    .bind(i64::from(MAX_ACTIVE_KEYS_INSTANCE))
    .fetch_optional(&mut **tx)
    .await?;
    Ok(id)
}

/// Whether the instance-wide cap (not the owner's) is what refused an insert.
async fn instance_cap_hit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL")
        .fetch_one(&mut **tx)
        .await?;
    Ok(n >= i64::from(MAX_ACTIVE_KEYS_INSTANCE))
}

/// Key list columns (a macro so complete statements stay compile-time literals, SEC-088).
macro_rules! key_select {
    () => {
        "SELECT k.id, k.name, k.prefix, k.created_at, k.last_used_at, k.revoked_at, \
     k.scope, k.owner_id, k.rate_per_min, k.revoked_by, u.username AS owner_username, \
     u.display_name AS owner_display, (u.deleted_at IS NOT NULL) AS owner_deleted \
     FROM api_key k LEFT JOIN account u ON u.id = k.owner_id"
    };
}

fn key_row(r: &sqlx::postgres::PgRow) -> Result<ApiKeyRow, StoreError> {
    let owner_id: Option<i64> = r.try_get("owner_id")?;
    let display: Option<String> = r.try_get("owner_display")?;
    let rate: Option<i64> = r.try_get("rate_per_min")?;
    Ok(ApiKeyRow {
        id: r.try_get("id")?,
        label: r.try_get("name")?,
        prefix: r.try_get("prefix")?,
        created_at: r.try_get("created_at")?,
        last_used_at: r.try_get("last_used_at")?,
        revoked_at: r.try_get("revoked_at")?,
        scope: r.try_get("scope")?,
        owner_id,
        owner_username: r.try_get("owner_username")?,
        owner_handle: owner_id.map(|id| display.unwrap_or_else(|| format!("user-{id}"))),
        owner_deleted: r
            .try_get::<Option<bool>, _>("owner_deleted")?
            .unwrap_or(false),
        rate_per_min: rate.and_then(|n| u32::try_from(n).ok()),
        revoked_by: r.try_get("revoked_by")?,
    })
}

impl PgDb {
    /// Stores a new key hash unless `max_active` unrevoked keys exist already (check and insert
    /// are one transaction on the single writer connection). Audit-logged without secrets.
    ///
    /// # Errors
    /// [`StoreError::InvalidLabel`] for a label that fails [`sanitize_label`]; database failure.
    pub async fn create_api_key(
        &self,
        key: NewApiKey<'_>,
        max_active: u32,
        now: i64,
        actor: Actor<'_>,
    ) -> Result<CreateKey, StoreError> {
        let label = sanitize_label(key.label).ok_or(StoreError::InvalidLabel)?;
        let mut tx = self.begin_account().await?;
        // Operator-created keys belong to the oldest enabled admin (NULL in a database without users).
        let owner: Option<i64> = sqlx::query_scalar(
            "SELECT min(id) FROM account WHERE role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL",
        )
        .fetch_one(&mut *tx)
        .await?;
        let Some(id) = insert_key(&mut tx, key, &label, owner, max_active, now).await? else {
            if instance_cap_hit(&mut tx).await? {
                let detail = format!("cap={MAX_ACTIVE_KEYS_INSTANCE}");
                audit(&mut tx, now, actor, "apikey_instance_cap", &detail).await?;
                tx.commit().await?;
                return Ok(CreateKey::InstanceLimitReached);
            }
            return Ok(CreateKey::LimitReached);
        };
        let detail = format!("id={id} prefix={}", key.prefix);
        audit(&mut tx, now, actor, "apikey.create", &detail).await?;
        tx.commit().await?;
        Ok(CreateKey::Created(id))
    }

    /// Like [`PgDb::create_api_key`] with an explicit OWNER (`nzbd apikey create --user`, and the
    /// per-user key management of T103). The owner must be a live, enabled uploader or admin: a viewer
    /// cannot upload, so it cannot own a key. `owner_id` comes from the session or the CLI, never from
    /// a form. Audit row names the acting identity.
    ///
    /// # Errors
    /// [`StoreError::InvalidLabel`]; [`AccountError::Forbidden`] for an unusable owner.
    pub async fn create_api_key_for(
        &self,
        key: NewApiKey<'_>,
        owner_id: i64,
        max_active: u32,
        now: i64,
        who: &AuditActor,
        ip: Option<&str>,
    ) -> Result<CreateKey, StoreError> {
        self.create_key_owned(key, owner_id, None, max_active, now, who, ip)
            .await
    }

    /// Like [`Self::create_api_key_for`] from a web session that re-authenticated: the key is only
    /// created while `session_hash` is still a live `active` session of the owner, so a key cannot
    /// outlive a recovery, reset or revocation that committed after the re-authentication.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the session is gone; otherwise as [`Self::create_api_key_for`].
    #[allow(clippy::too_many_arguments)] // `create_api_key_for` plus the session
    pub async fn create_api_key_for_session(
        &self,
        key: NewApiKey<'_>,
        owner_id: i64,
        session_hash: &[u8; 32],
        max_active: u32,
        now: i64,
        who: &AuditActor,
        ip: Option<&str>,
    ) -> Result<CreateKey, StoreError> {
        self.create_key_owned(key, owner_id, Some(session_hash), max_active, now, who, ip)
            .await
    }

    #[allow(clippy::too_many_arguments)] // the two public entry points above, plus the session
    async fn create_key_owned(
        &self,
        key: NewApiKey<'_>,
        owner_id: i64,
        session_hash: Option<&[u8; 32]>,
        max_active: u32,
        now: i64,
        who: &AuditActor,
        ip: Option<&str>,
    ) -> Result<CreateKey, StoreError> {
        let label = sanitize_label(key.label).ok_or(StoreError::InvalidLabel)?;
        let mut tx = self.begin_account().await?;
        require_actor(&mut tx, owner_id, Role::Uploader)
            .await
            .map_err(|_| StoreError::from(AccountError::Forbidden))?;
        if let Some(h) = session_hash
            && !crate::pg::auth::session_is_live(&mut tx, h, owner_id, now).await?
        {
            return Err(StoreError::NotFound);
        }
        let Some(id) = insert_key(&mut tx, key, &label, Some(owner_id), max_active, now).await?
        else {
            if instance_cap_hit(&mut tx).await? {
                // Distinct, secret-free signal for the operator: the instance table is full.
                let detail = format!("cap={MAX_ACTIVE_KEYS_INSTANCE} owner={owner_id}");
                write_audit(
                    &mut tx,
                    who,
                    now,
                    "apikey_instance_cap",
                    Some(&detail),
                    ip,
                    Some(owner_id),
                )
                .await?;
                tx.commit().await?;
                return Ok(CreateKey::InstanceLimitReached);
            }
            return Ok(CreateKey::LimitReached);
        };
        let detail = format!("id={id} prefix={} owner={owner_id}", key.prefix);
        write_audit(
            &mut tx,
            who,
            now,
            "apikey.create",
            Some(&detail),
            ip,
            Some(owner_id),
        )
        .await?;
        tx.commit().await?;
        Ok(CreateKey::Created(id))
    }

    /// Revokes every active key owned by `owner_id` (an owner's own revocation, or an admin acting on
    /// owned keys only). Returns the number revoked.
    ///
    /// # Errors
    /// Database failure.
    pub async fn revoke_keys_of_owner(
        &self,
        owner_id: i64,
        now: i64,
        who: &AuditActor,
        ip: Option<&str>,
    ) -> Result<u64, StoreError> {
        let mut tx = self.begin_account().await?;
        let n = sqlx::query(
            "UPDATE api_key SET revoked_at = $2 WHERE owner_id = $1 AND revoked_at IS NULL",
        )
        .bind(owner_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let detail = format!("count={n} owner={owner_id}");
        write_audit(
            &mut tx,
            who,
            now,
            "apikey.revoke",
            Some(&detail),
            ip,
            Some(owner_id),
        )
        .await?;
        tx.commit().await?;
        Ok(n)
    }

    /// All keys, newest first (operator CLI).
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRow>, StoreError> {
        let rows = sqlx::query(concat!(key_select!(), " ORDER BY k.id DESC"))
            .fetch_all(self.web())
            .await?;
        rows.iter().map(key_row).collect()
    }

    /// Number of unrevoked keys (for the cap check that precedes re-authentication).
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_active_api_keys(&self) -> Result<i64, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL")
                .fetch_one(self.web())
                .await?,
        )
    }

    /// Number of unrevoked keys owned by `owner_id` (the per-owner cap).
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_active_api_keys_of(&self, owner_id: i64) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL AND owner_id = $1",
        )
        .bind(owner_id)
        .fetch_one(self.web())
        .await?)
    }

    /// Every unrevoked key plus only the `max_revoked` most recently created revoked ones, newest
    /// first, optionally restricted to one `owner`. Bounds the account page however many
    /// create/revoke cycles happened.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_api_keys_recent(
        &self,
        owner: Option<i64>,
        max_revoked: u32,
    ) -> Result<Vec<ApiKeyRow>, StoreError> {
        let rows = sqlx::query(concat!(
            key_select!(),
            " WHERE ($2::bigint IS NULL OR k.owner_id = $2) AND (k.revoked_at IS NULL OR k.id IN \
               (SELECT id FROM api_key WHERE revoked_at IS NOT NULL AND ($2::bigint IS NULL OR owner_id = $2) \
                ORDER BY id DESC LIMIT $1)) \
             ORDER BY k.id DESC"
        ))
        .bind(i64::from(max_revoked))
        .bind(owner)
        .fetch_all(self.web())
        .await?;
        rows.iter().map(key_row).collect()
    }

    /// Deletes keys revoked more than `days` days before `now` (maintenance purge; the audit rows
    /// stay, `ingest_log.api_key_id` becomes NULL). `days == 0` keeps everything. Returns rows
    /// removed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn purge_revoked_api_keys(&self, now: i64, days: u32) -> Result<u64, StoreError> {
        if days == 0 {
            return Ok(0);
        }
        let cutoff = now.saturating_sub(i64::from(days).saturating_mul(86_400));
        let r = sqlx::query("DELETE FROM api_key WHERE revoked_at IS NOT NULL AND revoked_at < $1")
            .bind(cutoff)
            .execute(self.web())
            .await?;
        Ok(r.rows_affected())
    }

    /// Revokes an active key. Returns `false` if it does not exist or was revoked already.
    ///
    /// # Errors
    /// Database failure.
    pub async fn revoke_api_key(
        &self,
        id: i64,
        now: i64,
        actor: Actor<'_>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_account().await?;
        let res =
            sqlx::query("UPDATE api_key SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
                .bind(now)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        audit(&mut tx, now, actor, "apikey.revoke", &format!("id={id}")).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Revokes one active key on behalf of a signed-in account (T103): the OWNER may revoke its own
    /// keys, an ADMIN any key. The actor is re-validated inside the transaction (live, enabled, at least
    /// uploader, with its calling session still active) and the key's owner is read in the same transaction.
    /// Returns `false` when the key does not
    /// exist, was revoked already, or belongs to someone else and the actor is not an admin: the three
    /// cases are indistinguishable to the caller. An admin acting on another account's key is attributed
    /// with the owner as `target_id`.
    ///
    /// # Errors
    /// [`AccountError::Forbidden`] when the actor or its calling session is no longer usable.
    pub async fn revoke_api_key_by(
        &self,
        actor: &AccountActor,
        id: i64,
        ip: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_account().await?;
        let a = require_session_actor(&mut tx, actor, Role::Uploader, now).await?;
        let owner: Option<Option<i64>> =
            sqlx::query_scalar("SELECT owner_id FROM api_key WHERE id = $1 AND revoked_at IS NULL")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(owner) = owner else { return Ok(false) };
        let own = owner == Some(a.id);
        if !own && a.role < Role::Admin {
            return Ok(false);
        }
        let res = sqlx::query(
            "UPDATE api_key SET revoked_at = $1, revoked_by = $3 WHERE id = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(id)
        .bind(a.id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        let detail = match owner {
            Some(o) => format!("id={id} owner={o}"),
            None => format!("id={id}"),
        };
        write_audit(
            &mut tx,
            &AuditActor::account(a.id, a.role, &a.username),
            now,
            "apikey.revoke",
            Some(&detail),
            ip,
            if own { None } else { owner },
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Looks a key up by the hash of the presented secret (read pool; no write).
    ///
    /// # Errors
    /// Database failure, or a stored hash of the wrong length.
    pub async fn find_api_key(&self, hash: &[u8; 32]) -> Result<Option<ApiKeyAuth>, StoreError> {
        let row = sqlx::query(
            "SELECT k.id, k.key_hash, k.revoked_at, k.last_used_at, k.owner_id, k.scope, k.rate_per_min, \
             u.role AS owner_role, \
             (u.id IS NOT NULL AND u.disabled_at IS NULL AND u.deleted_at IS NULL) AS owner_usable \
             FROM api_key k LEFT JOIN account u ON u.id = k.owner_id WHERE k.key_hash = $1",
        )
        .bind(hash.as_slice())
        .fetch_optional(self.web())
        .await?;
        let Some(r) = row else { return Ok(None) };
        let stored: Vec<u8> = r.try_get("key_hash")?;
        let key_hash = <[u8; 32]>::try_from(stored.as_slice())
            .map_err(|_| StoreError::OutOfRange("api_key.key_hash"))?;
        Ok(Some(ApiKeyAuth {
            id: r.try_get("id")?,
            key_hash,
            revoked: r.try_get::<Option<i64>, _>("revoked_at")?.is_some(),
            last_used_at: r.try_get("last_used_at")?,
            owner_id: r.try_get("owner_id")?,
            owner_role: r
                .try_get::<Option<String>, _>("owner_role")?
                .as_deref()
                .and_then(Role::parse),
            owner_usable: r.try_get::<bool, _>("owner_usable")?,
            scope: r.try_get("scope")?,
            rate_per_min: r
                .try_get::<Option<i64>, _>("rate_per_min")?
                .and_then(|n| u32::try_from(n).ok()),
        }))
    }

    /// Records a use, but only if the stored `last_used_at` is older than `min_interval_secs`
    /// (so a busy client does not turn every request into a write). Revoked keys are never touched.
    ///
    /// # Errors
    /// Database failure.
    pub async fn touch_api_key(
        &self,
        id: i64,
        now: i64,
        min_interval_secs: i64,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            "UPDATE api_key SET last_used_at = $1 WHERE id = $2 AND revoked_at IS NULL \
             AND (last_used_at IS NULL OR last_used_at <= $1 - $3)",
        )
        .bind(now)
        .bind(id)
        .bind(min_interval_secs)
        .execute(self.web())
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    now: i64,
    actor: Actor<'_>,
    event: &str,
    detail: &str,
) -> Result<(), StoreError> {
    crate::pg::account::write_audit_legacy(tx, now, Some(actor.name), event, Some(detail), actor.ip)
        .await
}
