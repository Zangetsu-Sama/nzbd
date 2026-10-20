//! Shared fixtures of the v3 (Postgres) store tests: the 2.x `acct_testkit` on a private test database. Test-only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use sqlx::Row;

pub(crate) use crate::acct_testkit::{
    PHC, POLICY, T0, TEST_EMAIL, analysis, chosen_name, code, sess,
};
use crate::pg::PgDb;
use crate::pg::testing::TestDb;
use crate::{
    AccountActor, AuditActor, CategorySource, NewAccount, NewApiKey, NewRelease, Role,
    SceneColumns, SessionStage, StoreError, Uploader,
};

/// A private database with its app-role handle.
pub(crate) struct Env {
    pub(crate) t: TestDb,
    pub(crate) db: PgDb,
}

pub(crate) async fn env() -> Env {
    let t = TestDb::new().await;
    let db = t.db.clone();
    Env { t, db }
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
    /// A second, independent handle on the same database (another "process": its own pools).
    pub(crate) async fn second(&self) -> PgDb {
        PgDb::connect(&self.t.settings(), crate::pg::testing::TEST_APP_PASSWORD)
            .await
            .unwrap()
    }

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
        sqlx::query("UPDATE account SET totp_enabled = true WHERE id = $1")
            .bind(id)
            .execute(self.db.web())
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
             FROM audit_log WHERE event = $1 ORDER BY id",
        )
        .bind(event)
        .fetch_all(self.db.web())
        .await
        .unwrap()
        .iter()
        .map(aud_row)
        .collect()
    }

    /// `count(*)` of `table` under `filter` (test-only: both are literals in the callers).
    pub(crate) async fn count(&self, table: &str, filter: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE {filter}"
        )))
        .fetch_one(self.db.web())
        .await
        .unwrap()
    }

    /// Runs one statement as the superuser of the private database (tests that must bypass the app role, e.g. to
    /// stage a hostile row the application would never write).
    pub(crate) async fn superuser_exec(&self, sql: &str) {
        let mut c = self.t.superuser_conn().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "SET search_path = nzbd, pg_temp; {sql}"
        )))
        .execute(&mut c)
        .await
        .unwrap();
    }
}

fn aud_row(r: &sqlx::postgres::PgRow) -> Aud {
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
