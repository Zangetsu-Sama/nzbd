//! Accounts, roles, last-admin protection, tombstones and display names (T101a).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::used_underscore_binding
)]

use crate::acct_testkit::{PHC, POLICY, T0, env, sess};
use crate::{
    AccountPolicy, AttemptContext, DbConfig, GrantableRole, NewAccount, NewRecovery, Role,
    SessionStage, SqliteDb, StoreError, Uploader,
};

/// Error code of a refused account rule (`"OK"` for success); anything else fails the test.
fn code<T>(r: Result<T, StoreError>) -> &'static str {
    match r {
        Ok(_) => "OK",
        Err(StoreError::Account(e)) => e.code(),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

async fn open_second(env: &crate::acct_testkit::Env) -> SqliteDb {
    SqliteDb::open(&DbConfig {
        path: env.dir.path().join("t.sqlite"),
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn sec_069_empty_database_first_user_is_admin() {
    let e = env().await;
    let id =
        e.db.create_account_operator(
            &NewAccount {
                username: "owner",
                password_hash: PHC,
                role: None,
            },
            AccountPolicy::default(),
            T0,
        )
        .await
        .unwrap();
    let a = e.db.get_account(id).await.unwrap().unwrap();
    assert_eq!(a.role, Role::Admin);
    assert_eq!(a.display_name, Some(format!("user-{id}")));
    assert!(a.disabled_at.is_none() && a.deleted_at.is_none());
    // A second account needs an explicit role, and multi_user.
    let second = |role, policy| {
        let db = e.db.clone();
        async move {
            db.create_account_operator(
                &NewAccount {
                    username: "second",
                    password_hash: PHC,
                    role,
                },
                policy,
                T0,
            )
            .await
        }
    };
    assert_eq!(code(second(None, POLICY).await), "ROLE_REQUIRED");
    assert_eq!(
        code(second(Some(Role::Uploader), AccountPolicy::default()).await),
        "MULTI_USER_OFF"
    );
    assert_eq!(code(second(Some(Role::Uploader), POLICY).await), "OK");
    // The 1.x provisioning path also yields an admin on an empty database.
    let e2 = env().await;
    let id = e2.db.create_user("alice", PHC, T0).await.unwrap();
    assert_eq!(
        e2.db.get_account(id).await.unwrap().unwrap().role,
        Role::Admin
    );
}

#[tokio::test]
async fn account_cap_and_name_rules() {
    let e = env().await;
    let low = AccountPolicy {
        multi_user: true,
        max_accounts: 2,
        registration_enabled: true,
    };
    let mk = |n: &'static str, p: AccountPolicy| {
        let db = e.db.clone();
        async move {
            db.create_account_operator(
                &NewAccount {
                    username: n,
                    password_hash: PHC,
                    role: Some(Role::Admin),
                },
                p,
                T0,
            )
            .await
        }
    };
    assert_eq!(code(mk("a", low).await), "OK");
    assert_eq!(code(mk("A", low).await), "USERNAME_UNAVAILABLE");
    assert_eq!(code(mk("b", low).await), "OK");
    assert_eq!(code(mk("c", low).await), "ACCOUNT_LIMIT");
    assert!(matches!(
        mk("bad name", low).await,
        Err(StoreError::InvalidUsername)
    ));
}

#[tokio::test]
async fn sec_062_last_admin_cannot_be_demoted_disabled_or_deleted() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mallory").await;
    assert_eq!(
        code(e.db.set_role_operator(a, Role::Uploader, T0).await),
        "LAST_ADMIN"
    );
    assert_eq!(
        code(e.db.disable_account_operator(a, T0).await),
        "LAST_ADMIN"
    );
    // Delete needs a disabled account, and the admin can never become disabled.
    assert_eq!(
        code(e.db.delete_account_operator(a, T0).await),
        "NOT_DISABLED"
    );
    // The admin is untouched.
    let row = e.db.get_account(a).await.unwrap().unwrap();
    assert_eq!(row.role, Role::Admin);
    assert!(row.disabled_at.is_none() && row.deleted_at.is_none());
    // Other roles are unconstrained.
    assert_eq!(code(e.db.disable_account_operator(m, T0).await), "OK");
}

#[tokio::test]
async fn sec_062_last_usable_admin_rule() {
    let e = env().await;
    let a = e.admin("alpha").await;
    let b = e.admin("beta").await;
    // Neither has MFA enrolled: demoting one would leave a "phantom" admin.
    assert_eq!(
        code(e.db.set_role_operator(a, Role::Uploader, T0).await),
        "LAST_USABLE_ADMIN"
    );
    assert_eq!(
        code(e.db.disable_account_operator(a, T0).await),
        "LAST_USABLE_ADMIN"
    );
    e.mfa(b).await;
    assert_eq!(
        code(e.db.set_role_operator(a, Role::Uploader, T0).await),
        "OK"
    );
    assert_eq!(
        code(e.db.set_role_operator(b, Role::Uploader, T0).await),
        "LAST_ADMIN"
    );
}

#[tokio::test]
async fn sec_062_cli_obeys_last_admin_rule() {
    let e = env().await;
    let a = e.admin("alpha").await;
    let b = e.admin("beta").await;
    e.mfa(a).await;
    e.mfa(b).await;
    // The operator path may demote one of two usable admins, audited as `cli`...
    e.db.set_role_operator(b, Role::Viewer, T0 + 1)
        .await
        .unwrap();
    let row = e.audit("role_change").await;
    assert_eq!(row.len(), 1);
    assert_eq!(row[0].kind.as_deref(), Some("cli"));
    assert_eq!(row[0].actor_id, None);
    assert_eq!(row[0].target_id, Some(b));
    assert!(
        row[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("old=admin new=viewer")
    );
    // ...but never remove the last one, and the refusal leaves no audit row.
    assert_eq!(
        code(e.db.set_role_operator(a, Role::Viewer, T0 + 2).await),
        "LAST_ADMIN"
    );
    assert_eq!(
        code(e.db.disable_account_operator(a, T0 + 2).await),
        "LAST_ADMIN"
    );
    assert_eq!(e.audit("role_change").await.len(), 1);
    // The operator can always create an admin and promote.
    e.db.set_role_operator(b, Role::Admin, T0 + 3)
        .await
        .unwrap();
}

#[tokio::test]
async fn sec_062_trigger_refuses_raw_sql_removal_of_last_admin() {
    let e = env().await;
    let a = e.admin("root").await;
    let w = e.db.writer();
    for stmt in [
        "UPDATE account SET role = 'viewer' WHERE id = ?1",
        "UPDATE account SET disabled_at = 5 WHERE id = ?1",
        "UPDATE account SET deleted_at = 5 WHERE id = ?1",
    ] {
        let err = sqlx::query(stmt).bind(a).execute(w).await.unwrap_err();
        assert!(err.to_string().contains("LAST_ADMIN"), "{stmt}: {err}");
    }
    let err = sqlx::query("DELETE FROM account WHERE id = ?1")
        .bind(a)
        .execute(w)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ACCOUNT_ROWS_ARE_TOMBSTONED"));
    // With a second enabled admin the same statement is allowed (the trigger guards the LAST one).
    let b = e.admin("second").await;
    sqlx::query("UPDATE account SET role = 'viewer' WHERE id = ?1")
        .bind(b)
        .execute(w)
        .await
        .unwrap();
    // A disabled admin is not counted: demoting the other one is refused again.
    let err = sqlx::query("UPDATE account SET role = 'uploader' WHERE id = ?1")
        .bind(a)
        .execute(w)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("LAST_ADMIN"));
}

#[tokio::test]
async fn sec_062_insert_or_replace_cannot_remove_an_admin() {
    let e = env().await;
    let a = e.admin("root").await;
    let w = e.db.writer();
    // Collides on the primary key.
    let r = sqlx::query(
        "INSERT OR REPLACE INTO account (id, username, password_hash, created_at, password_changed_at) \
         VALUES (?1, 'intruder', 'x', 0, 0)",
    )
    .bind(a)
    .execute(w)
    .await;
    assert!(r.is_err(), "REPLACE on the id must be refused");
    // Collides on the (NOCASE) unique username.
    let r = sqlx::query(
        "INSERT OR REPLACE INTO account (username, password_hash, created_at, password_changed_at) \
         VALUES ('ROOT', 'x', 0, 0)",
    )
    .execute(w)
    .await;
    assert!(r.is_err(), "REPLACE on the username must be refused");
    // ON CONFLICT ... REPLACE is the same statement class.
    let r = sqlx::query(
        "INSERT INTO account (username, password_hash, created_at, password_changed_at) \
         VALUES ('root', 'x', 0, 0) ON CONFLICT(username) DO UPDATE SET role = 'viewer'",
    )
    .execute(w)
    .await;
    assert!(r.is_err());
    let row = e.db.get_account(a).await.unwrap().unwrap();
    assert_eq!(row.role, Role::Admin);
    assert_eq!(row.username, "root");
    assert_eq!(e.count("account", "1=1").await, 1);
}

#[tokio::test]
async fn sec_062_concurrent_mutual_demotion_leaves_one_admin() {
    let e = env().await;
    let a = e.admin("alpha").await;
    let b = e.admin("beta").await;
    e.mfa(a).await;
    e.mfa(b).await;
    // Two operator processes (two connections to the same file) demote each other at once.
    let other = open_second(&e).await;
    let db = e.db.clone();
    let (r1, r2) = tokio::join!(
        async move { db.set_role_operator(a, Role::Uploader, T0 + 1).await },
        async move { other.set_role_operator(b, Role::Uploader, T0 + 1).await },
    );
    let codes = [code(r1), code(r2)];
    assert_eq!(
        codes.iter().filter(|c| **c == "OK").count(),
        1,
        "exactly one wins: {codes:?}"
    );
    assert!(
        codes
            .iter()
            .any(|c| matches!(*c, "LAST_ADMIN" | "LAST_USABLE_ADMIN")),
        "{codes:?}"
    );
    assert_eq!(
        e.count(
            "account",
            "role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn sec_061_uploader_cannot_change_own_role() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let v = e.viewer("view").await;
    let am = e.actor(m).await;
    // Not an admin: refused whoever the target is (and `GrantableRole` has no `Admin`).
    for target in [m, v] {
        assert_eq!(
            code(
                e.db.set_role(&am, target, GrantableRole::Viewer, None, T0)
                    .await
            ),
            "FORBIDDEN"
        );
    }
    // A forged actor struct claiming admin is re-validated against the database.
    let mut forged = am.clone();
    forged.role = Role::Admin;
    assert_eq!(
        code(
            e.db.set_role(&forged, m, GrantableRole::Viewer, None, T0)
                .await
        ),
        "FORBIDDEN"
    );
    assert_eq!(
        e.db.get_account(m).await.unwrap().unwrap().role,
        Role::Uploader
    );
}

#[tokio::test]
async fn sec_061_admin_cannot_demote_or_disable_self() {
    let e = env().await;
    let a = e.admin("root").await;
    let _b = e.admin("second").await;
    let act = e.actor(a).await;
    assert_eq!(
        code(
            e.db.set_role(&act, a, GrantableRole::Uploader, None, T0)
                .await
        ),
        "SELF_TARGET"
    );
    assert_eq!(
        code(e.db.disable_account(&act, a, None, T0).await),
        "SELF_TARGET"
    );
    assert_eq!(
        code(e.db.delete_account(&act, a, None, T0).await),
        "SELF_TARGET"
    );
    assert_eq!(
        code(e.db.revoke_account_sessions(&act, a, None, T0).await),
        "SELF_TARGET"
    );
}

#[tokio::test]
async fn sec_061_admin_target_actions_are_cli_only_except_revoke_sessions() {
    let e = env().await;
    let a = e.admin("alpha").await;
    let b = e.admin("beta").await;
    e.mfa(a).await;
    e.mfa(b).await;
    let act = e.actor(a).await;
    e.db.insert_session(&sess(b, 1, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let h = [7_u8; 32];
    let refused = [
        code(
            e.db.set_role(&act, b, GrantableRole::Uploader, None, T0)
                .await,
        ),
        code(e.db.disable_account(&act, b, None, T0).await),
        code(e.db.enable_account(&act, b, None, T0).await),
        code(e.db.delete_account(&act, b, None, T0).await),
        code(e.db.unlock_account(&act, b, None, T0).await),
        code(e.db.set_display_name(&act, b, Some("bee"), None, T0).await),
        code(
            e.db.issue_recovery(
                &act,
                &NewRecovery {
                    target_id: b,
                    code_hash: &h,
                    ttl_secs: 7200,
                },
                None,
                T0,
            )
            .await,
        ),
        code(e.db.cancel_recovery(&act, b, None, T0).await),
    ];
    assert!(
        refused.iter().all(|c| *c == "ADMIN_IS_CLI_ONLY"),
        "{refused:?}"
    );
    let row = e.db.get_account(b).await.unwrap().unwrap();
    assert_eq!(row.role, Role::Admin);
    assert!(row.disabled_at.is_none());
    // The one HTTP action allowed on an admin (the web layer re-authenticated first).
    assert_eq!(
        e.db.revoke_account_sessions(&act, b, None, T0 + 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(e.audit("sessions_revoke").await.len(), 1);
}

#[tokio::test]
async fn sec_024_disable_and_role_change_revoke_sessions() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    for n in 1..=3_u8 {
        e.db.insert_session(&sess(m, n, SessionStage::Active, T0), 5)
            .await
            .unwrap();
    }
    e.db.insert_session(&sess(m, 9, SessionStage::PendingMfa, T0), 5)
        .await
        .unwrap();
    e.db.set_role(&act, m, GrantableRole::Viewer, None, T0 + 1)
        .await
        .unwrap();
    assert_eq!(e.count("session", &format!("account_id = {m}")).await, 0);
    e.db.insert_session(&sess(m, 4, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    e.db.disable_account(&act, m, None, T0 + 2).await.unwrap();
    assert_eq!(e.count("session", &format!("account_id = {m}")).await, 0);
    // A disabled account's session id is "no session" even if one existed.
    e.db.insert_session(&sess(m, 5, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    assert!(
        e.db.session_actor(&[5; 32], T0 + 3)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sec_060_role_change_applies_on_next_request() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    e.db.insert_session(&sess(m, 1, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let before = e.db.session_actor(&[1; 32], T0 + 1).await.unwrap().unwrap();
    assert_eq!((before.user_id, before.role), (m, Role::Uploader));
    assert_eq!(before.display_name, format!("user-{m}"));
    // The role is a database column read per call: no cached copy survives the change. (set_role also
    // revokes sessions; re-create the session to observe the new role on a surviving cookie.)
    sqlx::query("UPDATE account SET role = 'viewer' WHERE id = ?1")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap();
    let after = e.db.session_actor(&[1; 32], T0 + 2).await.unwrap().unwrap();
    assert_eq!(after.role, Role::Viewer);
    // Expired sessions are "no session".
    assert!(
        e.db.session_actor(&[1; 32], T0 + 7200)
            .await
            .unwrap()
            .is_none()
    );
    let _ = a;
}

#[tokio::test]
async fn sec_024_sessions_are_capped_per_user() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    for n in 1..=7_u8 {
        e.db.insert_session(&sess(a, n, SessionStage::Active, T0 + i64::from(n)), 5)
            .await
            .unwrap();
    }
    for n in 20..=22_u8 {
        e.db.insert_session(&sess(m, n, SessionStage::Active, T0 + i64::from(n)), 5)
            .await
            .unwrap();
    }
    assert_eq!(
        e.count("session", &format!("account_id = {a} AND stage = 'active'"))
            .await,
        5
    );
    assert_eq!(
        e.count("session", &format!("account_id = {m} AND stage = 'active'"))
            .await,
        3
    );
    // Pending sessions never evict an active one (per user AND per stage).
    for n in 30..=40_u8 {
        e.db.insert_session(
            &sess(a, n, SessionStage::PendingMfa, T0 + 100 + i64::from(n)),
            5,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        e.count("session", &format!("account_id = {a} AND stage = 'active'"))
            .await,
        5
    );
    assert_eq!(
        e.count(
            "session",
            &format!("account_id = {a} AND stage = 'pending_mfa'")
        )
        .await,
        5
    );
}

#[tokio::test]
async fn sec_068_delete_tombstones_and_keeps_library() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mallory").await;
    let act = e.actor(a).await;
    let rel = e.release(1, &Uploader::Account(m)).await.unwrap();
    e.db.log_ingest_as(
        &crate::IngestLogEntry {
            ts: T0,
            source: crate::LogSource::UploadUi,
            api_key_id: None,
            source_name: Some("x.nzb"),
            sha256: None,
            outcome: crate::LogOutcome::Failed,
            error_code: Some("NZB_EMPTY"),
            detail: None,
        },
        None,
        &Uploader::Account(m),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, randomblob(32))")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap();
    e.mfa(m).await;
    e.db.insert_session(&sess(m, 3, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let (key, hash) = e.key(m, 5).await;
    let before = e.audit("user_create").await.len();

    // A live account cannot be deleted; it must be disabled first.
    assert_eq!(
        code(e.db.delete_account(&act, m, None, T0 + 1).await),
        "NOT_DISABLED"
    );
    e.db.disable_account(&act, m, None, T0 + 1).await.unwrap();
    e.db.delete_account(&act, m, None, T0 + 2).await.unwrap();

    let row = e.db.get_account(m).await.unwrap().unwrap();
    assert_eq!(row.deleted_at, Some(T0 + 2));
    assert_eq!(row.username, format!("~deleted~{m}"));
    assert!(!row.totp_enabled);
    assert_eq!(
        e.count("recovery_code", &format!("account_id = {m}")).await,
        0
    );
    assert_eq!(e.count("session", &format!("account_id = {m}")).await, 0);
    let hashed: String = sqlx::query_scalar("SELECT password_hash FROM account WHERE id = ?1")
        .bind(m)
        .fetch_one(e.db.writer())
        .await
        .unwrap();
    assert_eq!(hashed, crate::TOMBSTONE_PASSWORD_HASH);
    // Library, ingest log and audit survive and still point at the account id.
    let att = e.db.release_attribution(rel).await.unwrap().unwrap();
    assert_eq!(att.added_by, Some(m));
    assert!(att.deleted);
    assert_eq!(att.handle, Some(format!("user-{m}")));
    assert_eq!(e.count("ingest_log", &format!("account_id = {m}")).await, 1);
    assert_eq!(e.count("release", "1=1").await, 1);
    assert_eq!(e.audit("user_create").await.len(), before);
    // The owned key was revoked and does not work any more.
    let k = e.db.find_api_key(&hash).await.unwrap().unwrap();
    assert!(k.revoked && !k.may_upload());
    let _ = key;
    // The name is free again.
    e.uploader("mallory").await;
}

#[tokio::test]
async fn sec_068_deleted_account_has_no_working_credentials() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mallory").await;
    let act = e.actor(a).await;
    e.db.insert_session(&sess(m, 3, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    e.db.disable_account(&act, m, None, T0 + 1).await.unwrap();
    e.db.delete_account(&act, m, None, T0 + 2).await.unwrap();
    assert!(e.db.get_login_user("mallory").await.unwrap().is_none());
    assert!(
        e.db.get_login_user(&format!("~deleted~{m}"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(e.db.get_login_user_by_id(m).await.unwrap().is_none());
    assert!(
        e.db.session_actor(&[3; 32], T0 + 3)
            .await
            .unwrap()
            .is_none()
    );
    // The password step can never accept it, even with `verified = true`.
    let ctx = AttemptContext {
        ip_key: "192.0.2.1",
        session: None,
        bucket_refused: false,
    };
    let ok =
        e.db.login_password_step_v2(
            e.db.get_login_user_by_id(m).await.unwrap().as_ref(),
            true,
            "bad_password",
            &ctx,
            None,
            T0 + 4,
        )
        .await
        .unwrap();
    assert!(!ok);
    // Legacy path too.
    assert!(
        !e.db
            .login_password_step(Some(m), true, "bad_password", None, T0 + 4)
            .await
            .unwrap()
    );
    // And a password reset cannot resurrect it.
    assert_eq!(
        code(e.db.reset_password_for(m, PHC, T0 + 5).await),
        "TARGET_NOT_FOUND"
    );
}

#[tokio::test]
async fn sec_068_ids_are_never_reused() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    e.db.disable_account(&act, m, None, T0 + 1).await.unwrap();
    e.db.delete_account(&act, m, None, T0 + 2).await.unwrap();
    let n = e.uploader("newcomer").await;
    assert!(n > m, "new id {n} must be above the tombstoned {m}");
    // A tombstone cannot be removed by SQL either.
    let err = sqlx::query("DELETE FROM account WHERE id = ?1")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ACCOUNT_ROWS_ARE_TOMBSTONED"));
    // Live count ignores tombstones (I-5).
    assert_eq!(e.db.count_live_accounts().await.unwrap(), 3 - 1);
}

#[tokio::test]
async fn sec_068_disable_stops_sessions_keys_and_invites() {
    let e = env().await;
    let a = e.admin("alpha").await;
    let b = e.admin("beta").await;
    e.mfa(a).await;
    e.mfa(b).await;
    let m = e.uploader("mem").await;
    let (_k, hash) = e.key(m, 8).await;
    e.db.insert_session(&sess(m, 3, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    assert!(
        e.db.find_api_key(&hash)
            .await
            .unwrap()
            .unwrap()
            .may_upload()
    );
    // An invitation issued by admin B.
    let bh = crate::acct_testkit::code(4).hash();
    let actor_b = e.actor(b).await;
    let inv =
        e.db.create_invite(
            &actor_b,
            &crate::NewInvite {
                username: "guest",
                role: GrantableRole::Viewer,
                code_hash: &bh,
                ttl_secs: 3600,
            },
            POLICY,
            None,
            T0,
        )
        .await
        .unwrap();
    // Disable the uploader: session gone, key stops working at once (owner checked on use).
    let act = e.actor(a).await;
    e.db.disable_account(&act, m, None, T0 + 1).await.unwrap();
    assert_eq!(e.count("session", &format!("account_id = {m}")).await, 0);
    let k = e.db.find_api_key(&hash).await.unwrap().unwrap();
    assert!(!k.revoked, "suspended, not revoked");
    assert!(!k.owner_usable && !k.may_upload());
    // Enabling restores the key (it was suspended, never destroyed).
    e.db.enable_account(&act, m, None, T0 + 2).await.unwrap();
    assert!(
        e.db.find_api_key(&hash)
            .await
            .unwrap()
            .unwrap()
            .may_upload()
    );
    // Disabling the ISSUING admin revokes the invitations it issued.
    e.db.disable_account_operator(b, T0 + 3).await.unwrap();
    let row = e.db.get_invite(inv).await.unwrap().unwrap();
    assert_eq!(row.revoked_at, Some(T0 + 3));
    // A viewer-owned key cannot upload either.
    let v = e.viewer("view").await;
    sqlx::query("UPDATE api_key SET owner_id = ?1")
        .bind(v)
        .execute(e.db.writer())
        .await
        .unwrap();
    assert!(
        !e.db
            .find_api_key(&hash)
            .await
            .unwrap()
            .unwrap()
            .may_upload()
    );
}

#[tokio::test]
async fn sec_064_display_name_never_equals_a_login_name() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mallory").await;
    let v = e.viewer("victor").await;
    let act = e.actor(a).await;
    let set = |target: i64, n: &str| {
        let db = e.db.clone();
        let act = act.clone();
        let n = n.to_owned();
        async move { db.set_display_name(&act, target, Some(&n), None, T0).await }
    };
    // Another account's login name, the target's own login name (any case), reserved actor names.
    assert_eq!(code(set(m, "victor").await), "DISPLAY_NAME_TAKEN");
    assert_eq!(code(set(m, "MALLORY").await), "DISPLAY_NAME_TAKEN");
    assert_eq!(code(set(m, "system").await), "DISPLAY_NAME_TAKEN");
    assert_eq!(code(set(m, "CLI").await), "DISPLAY_NAME_TAKEN");
    // The `user-<n>` / `acct-<n>` forms belong to the account with that id: a FUTURE id included.
    assert_eq!(code(set(m, "user-99").await), "DISPLAY_NAME_TAKEN");
    assert_eq!(
        code(set(m, &format!("user-{v}")).await),
        "DISPLAY_NAME_TAKEN"
    );
    assert_eq!(code(set(m, "acct-7").await), "DISPLAY_NAME_TAKEN");
    assert_eq!(code(set(m, &format!("user-{m}")).await), "OK");
    // Shape.
    for bad in [
        "",
        " lead",
        "trail ",
        "a/b",
        "é",
        "012345678901234567890123456789012",
    ] {
        assert_eq!(code(set(m, bad).await), "INVALID_DISPLAY_NAME", "{bad:?}");
    }
    // Unique among live accounts (NOCASE).
    assert_eq!(code(set(m, "Mal Lory").await), "OK");
    assert_eq!(code(set(v, "mal lory").await), "DISPLAY_NAME_TAKEN");
    // Resetting gives the default handle again; a NULL stored name renders as `user-<id>`.
    e.db.set_display_name(&act, m, None, None, T0)
        .await
        .unwrap();
    let row = e.db.get_account(m).await.unwrap().unwrap();
    assert_eq!(row.handle(), format!("user-{m}"));
    sqlx::query("UPDATE account SET display_name = NULL WHERE id = ?1")
        .bind(v)
        .execute(e.db.writer())
        .await
        .unwrap();
    assert_eq!(
        e.db.get_account(v).await.unwrap().unwrap().handle(),
        format!("user-{v}")
    );
    // An uploader cannot set one (admin or operator only).
    let am = e.actor(m).await;
    assert_eq!(
        code(e.db.set_display_name(&am, m, Some("mine"), None, T0).await),
        "FORBIDDEN"
    );
    // The audit row keeps old and new value.
    let rows = e.audit("user_display_name").await;
    assert!(
        rows.iter()
            .any(|r| r.detail.as_deref() == Some(&format!("old=user-{m} new=Mal Lory")))
    );
}

#[tokio::test]
async fn sec_064_reserved_handle_pattern_is_refused_for_login_names() {
    let e = env().await;
    let root = e.admin("root").await;
    for bad in ["user-1", "USER-42", "User-0007", "user-999999999999"] {
        assert!(crate::is_reserved_handle_form(bad), "{bad}");
        assert_eq!(
            code(
                e.db.create_account_operator(
                    &NewAccount {
                        username: bad,
                        password_hash: PHC,
                        role: Some(Role::Uploader)
                    },
                    POLICY,
                    T0
                )
                .await
            ),
            "RESERVED_LOGIN_NAME",
            "{bad}"
        );
        // The trigger is the backstop for any other insert path.
        let err = sqlx::query(
            "INSERT INTO account (username, password_hash, created_at, password_changed_at) \
             VALUES (?1, 'h', 0, 0)",
        )
        .bind(bad)
        .execute(e.db.writer())
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("RESERVED_LOGIN_NAME"),
            "{bad}: {err}"
        );
    }
    // Reserved actor names are refused as login names too.
    for bad in ["system", "CLI", "Api", "anonymous"] {
        assert_eq!(
            code(
                e.db.create_account_operator(
                    &NewAccount {
                        username: bad,
                        password_hash: PHC,
                        role: Some(Role::Uploader)
                    },
                    POLICY,
                    T0
                )
                .await
            ),
            "RESERVED_LOGIN_NAME"
        );
    }
    // Lookalikes are fine.
    for ok in ["user-", "user-1a", "users-1", "user_1", "acct-1", "xuser-1"] {
        assert!(!crate::is_reserved_handle_form(ok), "{ok}");
    }
    e.uploader("user-1a").await;
    // The invite path applies the same rule.
    let admin = e.actor(root).await;
    let h = crate::acct_testkit::code(1).hash();
    assert_eq!(
        code(
            e.db.create_invite(
                &admin,
                &crate::NewInvite {
                    username: "user-5",
                    role: GrantableRole::Uploader,
                    code_hash: &h,
                    ttl_secs: 3600
                },
                POLICY,
                None,
                T0
            )
            .await
        ),
        "RESERVED_LOGIN_NAME"
    );
}

#[tokio::test]
async fn reserved_login_accounts_are_flagged_not_renamed() {
    let e = env().await;
    // Legacy rows can carry a reserved name (inserted before the trigger existed): simulate by
    // renaming with an UPDATE (the trigger only covers INSERT).
    let a = e.admin("root").await;
    let m = e.uploader("plain").await;
    let v = e.uploader("other").await;
    sqlx::query("UPDATE account SET username = 'cli' WHERE id = ?1")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap();
    sqlx::query("UPDATE account SET username = 'user-3' WHERE id = ?1")
        .bind(v)
        .execute(e.db.writer())
        .await
        .unwrap();
    let flagged = e.db.reserved_login_accounts().await.unwrap();
    assert_eq!(flagged.len(), 2);
    assert!(
        flagged
            .iter()
            .any(|f| f.id == m && f.kind == crate::ReservedKind::ActorName)
    );
    assert!(
        flagged
            .iter()
            .any(|f| f.id == v && f.kind == crate::ReservedKind::HandleForm)
    );
    assert_eq!(e.db.get_account(a).await.unwrap().unwrap().username, "root");
}

#[tokio::test]
async fn unlock_clears_lock_rows_and_legacy_counters() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    for _ in 0..6 {
        e.db.record_failure(m, "192.0.2.5", crate::FailureKind::Password, None, T0)
            .await
            .unwrap();
    }
    assert!(
        e.db.throttle_state(m, "192.0.2.5", T0)
            .await
            .unwrap()
            .hard_locked(T0)
    );
    e.db.unlock_account(&act, m, None, T0 + 1).await.unwrap();
    let st = e.db.throttle_state(m, "192.0.2.5", T0 + 1).await.unwrap();
    assert!(!st.hard_locked(T0 + 1));
    assert_eq!(e.count("login_lock", &format!("account_id = {m}")).await, 0);
    assert_eq!(e.audit("user_unlock").await.len(), 1);
}

#[tokio::test]
async fn account_listing_exposes_no_secrets_and_marks_staged_recovery() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let rows = e.db.list_accounts(false).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.recovery_staged_at.is_none()));
    let dbg = format!("{rows:?}");
    assert!(!dbg.contains("argon2"), "no hash in the listing");
    let _ = m;
}

#[tokio::test]
async fn sec_065_cannot_revoke_foreign_session_handle() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    e.db.insert_session(&sess(a, 1, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    e.db.insert_session(&sess(m, 2, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    // The uploader presents the admin's session handle (`SHA-256(session id)`): it behaves like an
    // unknown one, and the admin's session is untouched.
    assert!(
        !e.db
            .revoke_user_session(m, &[2; 32], &[1; 32], None, T0 + 1)
            .await
            .unwrap()
    );
    assert!(e.db.get_session(&[1; 32]).await.unwrap().is_some());
    // "Revoke others" only ever touches the caller's own sessions.
    e.db.revoke_other_sessions(m, &[2; 32], None, T0 + 2)
        .await
        .unwrap();
    assert!(e.db.get_session(&[1; 32]).await.unwrap().is_some());
    // The listing behind the account page is scoped to the user as well.
    let mine = e.db.list_active_sessions(m, T0 + 3).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id_hash, [2; 32]);
    // The owner can revoke their own.
    assert!(
        e.db.revoke_user_session(a, &[1; 32], &[1; 32], None, T0 + 4)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_065_session_revocation_cannot_outlive_its_calling_session() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.viewer("mem").await;
    e.db.insert_session(&sess(m, 10, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    // A revocation request has authenticated as session 10 but is still reading its body.
    // The owner changes the password and continues in session 11 before that body completes.
    e.db.change_password(
        m,
        &[10; 32],
        "new-password-hash",
        &sess(m, 11, SessionStage::Active, T0 + 1),
        None,
        T0 + 1,
    )
    .await
    .unwrap();
    assert!(e.db.get_session(&[10; 32]).await.unwrap().is_none());
    let revoke_all = e.db.revoke_other_sessions(m, &[10; 32], None, T0 + 2).await;
    assert!(matches!(revoke_all, Err(StoreError::NotFound)));
    let revoke_one =
        e.db.revoke_user_session(m, &[10; 32], &[11; 32], None, T0 + 2)
            .await;
    assert!(matches!(revoke_one, Err(StoreError::NotFound)));
    assert!(e.db.get_session(&[11; 32]).await.unwrap().is_some());
    assert_eq!(e.audit("session.revoked").await.len(), 0);
    assert_eq!(e.audit("session.revoked_others").await.len(), 0);

    // The replacement session can still revoke another of its own sessions.
    e.db.insert_session(&sess(m, 12, SessionStage::Active, T0 + 3), 5)
        .await
        .unwrap();
    assert_eq!(
        e.db.revoke_other_sessions(m, &[11; 32], None, T0 + 4)
            .await
            .unwrap(),
        1
    );
    assert!(e.db.get_session(&[11; 32]).await.unwrap().is_some());
    assert!(e.db.get_session(&[12; 32]).await.unwrap().is_none());
}

#[tokio::test]
async fn sec_065_session_revocation_requires_active_owned_unexpired_session() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.viewer("mem").await;
    for s in [
        sess(m, 20, SessionStage::Active, T0),
        sess(a, 21, SessionStage::Active, T0),
        sess(m, 22, SessionStage::PendingMfa, T0),
        sess(m, 23, SessionStage::Active, T0 - 4000),
    ] {
        e.db.insert_session(&s, 5).await.unwrap();
    }
    // A foreign account, pending MFA, expiry, or a missing cookie cannot authorize revocation.
    for n in [21, 22, 23, 24] {
        let all = e.db.revoke_other_sessions(m, &[n; 32], None, T0 + 1).await;
        assert!(matches!(all, Err(StoreError::NotFound)), "cookie {n}");
        let one =
            e.db.revoke_user_session(m, &[n; 32], &[20; 32], None, T0 + 1)
                .await;
        assert!(matches!(one, Err(StoreError::NotFound)), "cookie {n}");
        assert!(e.db.get_session(&[20; 32]).await.unwrap().is_some());
    }
    assert_eq!(e.audit("session.revoked").await.len(), 0);
    assert_eq!(e.audit("session.revoked_others").await.len(), 0);
}
