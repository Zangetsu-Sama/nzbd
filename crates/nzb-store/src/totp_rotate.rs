//! Atomic re-seal of every stored TOTP secret under a new key (T104, `nzbd keys rotate-totp`).
//!
//! The crypto stays in the caller (this crate knows no TOTP key): [`SqliteDb::reseal_totp_secrets`] feeds
//! each sealed blob to a closure and writes back what it returns, all inside ONE writer
//! transaction together with an audit row. Either every secret is re-sealed or none is: a failure
//! on any user, a crash, or `dry_run` rolls back. Each update is a compare-and-set on the blob it
//! read, so a concurrently running server that rewrote a row cannot be overwritten silently.

use crate::db::SqliteDb;
use crate::error::StoreError;
use sqlx::Row as _;

/// What the re-seal closure decided for one stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reseal {
    /// Replace the blob with this one (sealed under the new key).
    Sealed(Vec<u8>),
    /// The blob already opens under the new key (a re-run after a completed rotation).
    AlreadyCurrent,
    /// The blob opens under neither key.
    Undecryptable,
}

/// Counts of one rotation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResealReport {
    /// Secrets re-sealed (or that would be, in a dry run).
    pub resealed: u64,
    /// Secrets that were already under the new key.
    pub already_current: u64,
    /// Users without a stored secret (never enrolled, or reset).
    pub without_secret: u64,
    /// Sealed secrets parked in `credential_staging` (a staged recovery) that were re-sealed.
    pub staging_resealed: u64,
}

impl SqliteDb {
    /// Re-seals every user's `totp_secret_enc` through `f(user_id, blob)` in one transaction and
    /// records an audit row `totp_key_rotated` (counts only). With `dry_run` nothing is written.
    ///
    /// # Errors
    /// Any `Undecryptable` verdict aborts the whole run (nothing changes) with an
    /// [`StoreError::Integrity`] naming the affected user ids; database errors likewise.
    #[allow(clippy::too_many_lines)] // one linear transaction: read, decide, write, audit
    pub async fn reseal_totp_secrets<F>(
        &self,
        now: i64,
        dry_run: bool,
        mut f: F,
    ) -> Result<ResealReport, StoreError>
    where
        F: FnMut(i64, &[u8]) -> Reseal,
    {
        let mut tx = self.begin_immediate().await?;
        let rows = sqlx::query("SELECT id, totp_secret_enc FROM account ORDER BY id")
            .fetch_all(&mut *tx)
            .await?;
        let mut rep = ResealReport {
            resealed: 0,
            already_current: 0,
            without_secret: 0,
            staging_resealed: 0,
        };
        let mut bad: Vec<i64> = Vec::new();
        let mut updates: Vec<(i64, Vec<u8>, Vec<u8>)> = Vec::new();
        for r in &rows {
            let id: i64 = r.try_get("id")?;
            let blob: Option<Vec<u8>> = r.try_get("totp_secret_enc")?;
            let Some(blob) = blob else {
                rep.without_secret = rep.without_secret.saturating_add(1);
                continue;
            };
            match f(id, &blob) {
                Reseal::Sealed(new) => {
                    rep.resealed = rep.resealed.saturating_add(1);
                    updates.push((id, blob, new));
                }
                Reseal::AlreadyCurrent => {
                    rep.already_current = rep.already_current.saturating_add(1);
                }
                Reseal::Undecryptable => bad.push(id),
            }
        }
        // A staged recovery parks a sealed secret (AAD = user id) until the enrollment confirms:
        // it must move with the user rows or its enrollment page could not open it (SEC-053).
        let staged = sqlx::query(
            "SELECT account_id, totp_secret_enc FROM credential_staging \
             WHERE totp_secret_enc IS NOT NULL ORDER BY account_id",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut staging_updates: Vec<(i64, Vec<u8>, Vec<u8>)> = Vec::new();
        for r in &staged {
            let id: i64 = r.try_get("account_id")?;
            let blob: Vec<u8> = r.try_get("totp_secret_enc")?;
            match f(id, &blob) {
                Reseal::Sealed(new) => {
                    rep.staging_resealed = rep.staging_resealed.saturating_add(1);
                    staging_updates.push((id, blob, new));
                }
                Reseal::AlreadyCurrent => {}
                Reseal::Undecryptable => bad.push(id),
            }
        }
        if !bad.is_empty() {
            let ids: Vec<String> = bad.iter().map(i64::to_string).collect();
            return Err(StoreError::Integrity(format!(
                "TOTP secret of user id(s) {} opens under neither key; nothing was changed \
                 (check the keys, or run `nzbd user reset-mfa` for them)",
                ids.join(", ")
            )));
        }
        if dry_run {
            return Ok(rep);
        }
        for (id, old, new) in &updates {
            let done = sqlx::query(
                "UPDATE account SET totp_secret_enc = ?2 WHERE id = ?1 AND totp_secret_enc = ?3",
            )
            .bind(id)
            .bind(new)
            .bind(old)
            .execute(&mut *tx)
            .await?;
            if done.rows_affected() != 1 {
                // Changed under us (a running server): abort, the transaction rolls back.
                return Err(StoreError::Integrity(
                    "a TOTP secret changed during rotation; stop the server and retry".into(),
                ));
            }
        }
        for (id, old, new) in &staging_updates {
            let done = sqlx::query(
                "UPDATE credential_staging SET totp_secret_enc = ?2 \
                 WHERE account_id = ?1 AND totp_secret_enc = ?3",
            )
            .bind(id)
            .bind(new)
            .bind(old)
            .execute(&mut *tx)
            .await?;
            if done.rows_affected() != 1 {
                return Err(StoreError::Integrity(
                    "a staged TOTP secret changed during rotation; stop the server and retry"
                        .into(),
                ));
            }
        }
        let detail = format!(
            "resealed={} already_current={} staging={}",
            rep.resealed, rep.already_current, rep.staging_resealed
        );
        crate::account::write_audit_legacy(
            &mut tx,
            now,
            Some("cli"),
            "totp_key_rotated",
            Some(&detail),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(rep)
    }
}
