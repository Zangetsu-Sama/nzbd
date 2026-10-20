//! Shared fixtures of the multi-user storage tests (T101a). Test-only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use nzb_core::{Analysis, ReleaseFlags, Sha256};
use sqlx::Row;

use crate::{
    AccountActor, AccountPolicy, AuditActor, CategorySource, DbConfig, InviteCode, NewAccount,
    NewApiKey, NewRelease, NewSession, Role, SceneColumns, SessionStage, SqliteDb, StoreError,
    Uploader,
};

/// `security.multi_user = true`, default cap.
pub(crate) const POLICY: AccountPolicy = AccountPolicy {
    multi_user: true,
    max_accounts: 100,
    registration_enabled: true,
};
/// Fixed "now" of most tests.
pub(crate) const T0: i64 = 1_000_000;
/// A stand-in for an Argon2id PHC string (the store never verifies passwords).
pub(crate) const PHC: &str = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA";

/// A database in a temp dir.
pub(crate) struct Env {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) db: SqliteDb,
}

pub(crate) async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    Env { dir, db }
}

/// An audit row with every identity column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Aud {
    pub(crate) actor: Option<String>,
    pub(crate) actor_id: Option<i64>,
    pub(crate) kind: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) target_id: Option<i64>,
    pub(crate) event: String,
    pub(crate) detail: Option<String>,
}

impl Env {
    /// Creates an account through the operator path.
    pub(crate) async fn account(&self, name: &str, role: Option<Role>) -> i64 {
        self.db
            .create_account_operator(
                &NewAccount {
                    username: name,
                    password_hash: PHC,
                    role,
                },
                POLICY,
                T0,
            )
            .await
            .unwrap()
    }

    pub(crate) async fn admin(&self, name: &str) -> i64 {
        self.account(name, Some(Role::Admin)).await
    }

    pub(crate) async fn uploader(&self, name: &str) -> i64 {
        self.account(name, Some(Role::Uploader)).await
    }

    pub(crate) async fn viewer(&self, name: &str) -> i64 {
        self.account(name, Some(Role::Viewer)).await
    }

    /// Marks MFA as enrolled (raw; the enrollment flow is tested elsewhere).
    pub(crate) async fn mfa(&self, id: i64) {
        sqlx::query("UPDATE account SET totp_enabled = 1 WHERE id = ?1")
            .bind(id)
            .execute(self.db.writer())
            .await
            .unwrap();
    }

    /// The actor struct a session loader would hand to a handler.
    pub(crate) async fn actor(&self, id: i64) -> AccountActor {
        let a = self.db.get_account(id).await.unwrap().unwrap();
        AccountActor {
            user_id: id,
            role: a.role,
            username: a.username.clone(),
            display_name: a.handle(),
            stage: SessionStage::Active,
            prefs: crate::UserPrefs::default(),
            session: None,
        }
    }

    /// A release added through `uploader`.
    pub(crate) async fn release(&self, n: u8, uploader: &Uploader) -> Result<i64, StoreError> {
        let a = analysis(n);
        let new = NewRelease {
            analysis: &a,
            nzb_size_bytes: 1,
            source_name: None,
            source_label: Some("orig"),
            category_id: 8010,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: SceneColumns::default(),
            ingested_at: T0,
        };
        self.db.insert_release_as(&new, None, uploader).await
    }

    /// An API key (hash derived from `n`) owned by `owner`; returns `(key id, hash)`.
    pub(crate) async fn key(&self, owner: i64, n: u8) -> (i64, [u8; 32]) {
        let hash = [n; 32];
        let r = self
            .db
            .create_api_key_for(
                NewApiKey {
                    label: "k",
                    prefix: "abcdef",
                    key_hash: &hash,
                    rate_per_min: None,
                },
                owner,
                10,
                T0,
                &AuditActor::cli(),
                None,
            )
            .await
            .unwrap();
        match r {
            crate::CreateKey::Created(id) => (id, hash),
            crate::CreateKey::LimitReached | crate::CreateKey::InstanceLimitReached => {
                panic!("key limit")
            }
        }
    }

    /// All audit rows of `event`, oldest first.
    pub(crate) async fn audit(&self, event: &str) -> Vec<Aud> {
        sqlx::query(
            "SELECT actor, actor_id, actor_kind, actor_role, target_id, event, detail \
             FROM audit_log WHERE event = ?1 ORDER BY id",
        )
        .bind(event)
        .fetch_all(self.db.writer())
        .await
        .unwrap()
        .iter()
        .map(aud_row)
        .collect()
    }

    pub(crate) async fn count(&self, table: &str, filter: &str) -> i64 {
        // Test-only: `table` and `filter` are literals in the callers.
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE {filter}"
        )))
        .fetch_one(self.db.writer())
        .await
        .unwrap()
    }
}

fn aud_row(r: &sqlx::sqlite::SqliteRow) -> Aud {
    Aud {
        actor: r.get("actor"),
        actor_id: r.get("actor_id"),
        kind: r.get("actor_kind"),
        role: r.get("actor_role"),
        target_id: r.get("target_id"),
        event: r.get("event"),
        detail: r.get("detail"),
    }
}

pub(crate) fn analysis(n: u8) -> Analysis {
    Analysis {
        sha256: Sha256([n; 32]),
        name_candidates: vec![],
        meta_name_candidates: 0,
        title: format!("release {n}"),
        poster: None,
        posted_at: None,
        total_bytes: 1,
        file_count: 0,
        segment_count: 0,
        duplicate_segments: 0,
        par2_blocks: 0,
        flags: ReleaseFlags::EMPTY,
        meta_category: None,
        repairable_estimate: None,
        files: vec![],
    }
}

/// A session row for `user` (id hash derived from `n`).
pub(crate) fn sess(user: i64, n: u8, stage: SessionStage, now: i64) -> NewSession {
    NewSession {
        id_hash: [n; 32],
        user_id: user,
        stage,
        csrf_token: [9; 32],
        now,
        expires_at: now + 3600,
        ip: None,
        user_agent: None,
    }
}

/// A valid registration email for redemptions in tests (D32).
pub(crate) const TEST_EMAIL: &str = "invitee@example.org";

/// A valid, unique self-chosen display name for the redemption of code `n` (D32).
pub(crate) fn chosen_name(n: u8) -> String {
    format!("Invitee_{n}")
}

/// A code from fixed entropy.
pub(crate) fn code(n: u8) -> InviteCode {
    InviteCode::from_entropy(&[n; 20])
}
