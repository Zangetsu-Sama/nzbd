//! `nzbd apikey create|list|revoke` (`AUTH_SPEC` §API keys, SEC-036).
//!
//! `create` prints the secret once on stdout and never anywhere else; `list` shows id, display
//! prefix, label, owner, scope, rate, dates and status only (the database holds just a hash).
//! `--user` sets the owner (default: the oldest enabled admin), `--rate` a per-key budget.

use nzb_store::prelude::*;
use std::fmt::Write as _;

use nzb_store::Actor;
use nzb_web::apikey::{self, IssueError};

use crate::users::now_secs;

const ACTOR: Actor<'static> = Actor {
    name: "cli",
    ip: None,
};

/// A user-facing CLI failure (safe to print).
#[derive(Debug, thiserror::Error)]
pub enum KeyCmdError {
    /// Creation was refused or failed.
    #[error("{0}")]
    Issue(#[from] IssueError),
    /// `--user` names no live account.
    #[error("no such account")]
    UnknownOwner,
    /// No active key with that id.
    #[error("no active API key with that id")]
    NotFound,
    /// Storage failure.
    #[error("{0}")]
    Store(#[from] nzb_store::StoreError),
    /// The key could not be printed; it was revoked again.
    #[error("could not print the key ({0}); the new key was revoked, run the command again")]
    Print(std::io::ErrorKind),
}

/// Creates a key and writes the one-time text to `out`. If the secret could not be written
/// (closed pipe, full disk) the freshly created key is revoked again, so no key exists that
/// nobody has seen (`SECURITY_REVIEW` T050 L3).
pub async fn create<W: std::io::Write>(
    db: &nzb_store::Store,
    label: &str,
    owner: Option<&str>,
    rate: Option<u32>,
    out: &mut W,
) -> Result<(), KeyCmdError> {
    let (id, key) = match owner {
        None => apikey::issue_with_rate(db, label, rate, now_secs(), ACTOR).await?,
        Some(name) => {
            let acct = db
                .get_account_by_username(name)
                .await?
                .ok_or(KeyCmdError::UnknownOwner)?;
            apikey::issue_for_rate(
                db,
                label,
                acct.id,
                rate,
                None,
                &nzb_store::AuditActor::cli(),
                None,
                now_secs(),
            )
            .await?
        }
    };
    let shown = writeln!(
        out,
        "API key {id} created. Copy it now; it cannot be shown again:\n{}",
        key.secret.as_str()
    )
    .and_then(|()| out.flush());
    if let Err(e) = shown {
        db.revoke_api_key(id, now_secs(), ACTOR).await?;
        return Err(KeyCmdError::Print(e.kind()));
    }
    Ok(())
}

fn date(ts: i64) -> String {
    // `YYYY-MM-DD HH:MM` UTC via the same civil-date arithmetic the web layer uses.
    nzb_web::fmt_utc(ts)
}

/// Renders the key table.
pub async fn list(db: &nzb_store::Store) -> Result<String, KeyCmdError> {
    let keys = db.list_api_keys().await?;
    let mut out = format!(
        "{:<5}{:<14}{:<22}{:<18}{:<8}{:<8}{:<24}{:<24}STATUS\n",
        "ID", "KEY", "LABEL", "OWNER", "SCOPE", "RATE", "CREATED", "LAST USED"
    );
    for k in keys {
        let owner = match (&k.owner_username, k.owner_deleted) {
            (Some(_), true) => "(deleted)".to_owned(),
            (Some(u), false) => u.clone(),
            (None, _) => "-".to_owned(),
        };
        let _ = writeln!(
            out,
            "{:<5}{:<14}{:<22}{:<18}{:<8}{:<8}{:<24}{:<24}{}",
            k.id,
            format!("nzbd_{}...", k.prefix),
            k.label,
            owner,
            k.scope,
            k.rate_per_min
                .map_or_else(|| "-".to_owned(), |n| format!("{n}/min")),
            date(k.created_at),
            k.last_used_at.map_or_else(|| "never".to_owned(), date),
            k.revoked_at
                .map_or_else(|| "active".to_owned(), |t| format!("revoked {}", date(t)))
        );
    }
    Ok(out)
}

/// Revokes key `id`.
pub async fn revoke(db: &nzb_store::Store, id: i64) -> Result<(), KeyCmdError> {
    if db.revoke_api_key(id, now_secs(), ACTOR).await? {
        Ok(())
    } else {
        Err(KeyCmdError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn sec_036_cli_create_prints_key_once_list_never_does() {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = ts.store.clone();
        let mut buf: Vec<u8> = Vec::new();
        create(&db, "backup script", None, None, &mut buf)
            .await
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let secret = out.lines().last().unwrap().to_owned();
        assert!(apikey::is_well_formed(secret.as_bytes()));
        let listing = list(&db).await.unwrap();
        assert!(listing.contains("backup script") && listing.contains("active"));
        assert!(!listing.contains(&secret));
        assert!(listing.contains(&secret[..11]), "prefix is shown");
        assert!(matches!(
            create(&db, "bad\nlabel", None, None, &mut Vec::new()).await,
            Err(KeyCmdError::Issue(IssueError::InvalidLabel))
        ));
        assert!(matches!(revoke(&db, 99).await, Err(KeyCmdError::NotFound)));
        revoke(&db, 1).await.unwrap();
        assert!(list(&db).await.unwrap().contains("revoked"));
        assert!(matches!(revoke(&db, 1).await, Err(KeyCmdError::NotFound)));
        let audit = format!("{:?}", db.recent_audit(10).await.unwrap());
        assert!(audit.contains("apikey.create") && audit.contains("apikey.revoke"));
        assert!(!audit.contains(&secret));
    }

    #[tokio::test]
    async fn sec_036_cli_create_for_a_user_with_a_rate_lists_owner_scope_and_rate() {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = ts.store.clone();
        let policy = nzb_store::AccountPolicy {
            multi_user: true,
            max_accounts: 100,
            registration_enabled: true,
        };
        for (name, role) in [
            ("root", nzb_store::Role::Admin),
            ("alice", nzb_store::Role::Uploader),
            ("vera", nzb_store::Role::Viewer),
        ] {
            db.create_account_operator(
                &nzb_store::NewAccount {
                    username: name,
                    password_hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
                    role: Some(role),
                },
                policy,
                1,
            )
            .await
            .unwrap();
        }
        let mut buf = Vec::new();
        create(&db, "alice script", Some("alice"), Some(5), &mut buf)
            .await
            .unwrap();
        create(&db, "default owner", None, None, &mut Vec::new())
            .await
            .unwrap();
        // A viewer cannot own a key; an unknown name and a bad rate are refused.
        assert!(
            create(&db, "v", Some("vera"), None, &mut Vec::new())
                .await
                .is_err()
        );
        assert!(matches!(
            create(&db, "x", Some("nobody"), None, &mut Vec::new()).await,
            Err(KeyCmdError::UnknownOwner)
        ));
        assert!(matches!(
            create(&db, "x", Some("alice"), Some(31), &mut Vec::new()).await,
            Err(KeyCmdError::Issue(IssueError::InvalidRate))
        ));
        let listing = list(&db).await.unwrap();
        let alice = listing
            .lines()
            .find(|l| l.contains("alice script"))
            .unwrap();
        assert!(alice.contains("alice") && alice.contains("upload") && alice.contains("5/min"));
        let dflt = listing
            .lines()
            .find(|l| l.contains("default owner"))
            .unwrap();
        assert!(dflt.contains("root") && dflt.contains("upload"));
    }

    /// A stdout that is a closed pipe.
    struct BrokenPipe;
    impl std::io::Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[tokio::test]
    async fn sec_036_cli_create_revokes_the_key_when_the_secret_cannot_be_printed() {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = ts.store.clone();
        let err = create(&db, "lost", None, None, &mut BrokenPipe)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KeyCmdError::Print(std::io::ErrorKind::BrokenPipe)
        ));
        assert!(!err.to_string().contains("nzbd_"));
        // No panic, no live key nobody has seen, and the slot is free again.
        assert_eq!(db.count_active_api_keys().await.unwrap(), 0);
        let listing = list(&db).await.unwrap();
        assert!(listing.contains("lost") && listing.contains("revoked"));
    }
}
