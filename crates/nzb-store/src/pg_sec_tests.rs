//! New v3 security tests of the Postgres store (T112; `docs/v3/SECURITY_DELTA.md` sections 3 and 4).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::many_single_char_names
)]

use std::path::Path;

use crate::pg_testkit::{PHC, POLICY, T0, env, sess};
use crate::{
    AuditActor, CreateKey, NewAccount, NewApiKey, Role, SessionStage, StoreError, Uploader,
};

/// SEC-097: a unique violation's `DETAIL` names the conflicting value; nothing of it reaches the error text a client
/// or a log could see, in `Display` nor in `Debug`.
#[tokio::test]
async fn sec_097_unique_violation_detail_never_reaches_the_client() {
    let e = env().await;
    let a = e.admin("root").await;
    let hash = [0xab_u8; 32];
    let key = |label| NewApiKey {
        label,
        prefix: "abcdef",
        key_hash: &hash,
        rate_per_min: None,
    };
    let first =
        e.db.create_api_key_for(key("one"), a, 10, T0, &AuditActor::cli(), None)
            .await
            .unwrap();
    assert!(matches!(first, CreateKey::Created(_)));
    let err =
        e.db.create_api_key_for(key("two"), a, 10, T0, &AuditActor::cli(), None)
            .await
            .unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(shown.contains("23505"), "{shown}");
    assert!(shown.contains("api_key_key_hash_key"), "{shown}");
    for leak in ["abab", "already exists", "Key (", "detail", "duplicate key"] {
        assert!(!shown.contains(leak), "{leak} in {shown}");
    }
}

/// SEC-097: an error on an authentication table logs the SQLSTATE and the constraint name only, never the failing
/// row (a CHECK violation's `DETAIL` prints every column, password hash included).
#[tokio::test]
async fn sec_097_auth_table_errors_log_sqlstate_only() {
    let e = env().await;
    let secret_hash = format!("$argon2id$v=19$SECRETHASH{}", "x".repeat(300));
    let err =
        e.db.create_account_operator(
            &NewAccount {
                username: "root",
                password_hash: &secret_hash,
                role: Some(Role::Admin),
            },
            POLICY,
            T0,
        )
        .await
        .unwrap_err();
    let shown = format!("{err} / {err:?}");
    assert!(shown.contains("23514"), "{shown}");
    assert!(shown.contains("account_password_hash_check"), "{shown}");
    for leak in ["SECRETHASH", "Failing row", "root", "argon2"] {
        assert!(!shown.contains(leak), "{leak} in {shown}");
    }
    // Non-database errors keep their plain text.
    assert_eq!(format!("{:?}", StoreError::NotFound), "NotFound");
}

/// SEC-087: `nzbd db check` self-tests the privileges of the app role and fails when it can do more than designed.
#[tokio::test]
async fn sec_087_db_check_fails_on_excess_privileges() {
    let e = env().await;
    assert_eq!(
        e.db.privilege_self_test().await.unwrap(),
        Vec::<String>::new()
    );
    let report = e.db.deep_db_check().await.unwrap();
    assert!(report.quick_check_ok, "{report:?}");
    // An operator mistake (or an attacker with the owner role) widens the app role: the check says so.
    e.superuser_exec("GRANT UPDATE, DELETE ON nzbd.audit_log TO nzbd_app; GRANT DELETE ON nzbd.account TO nzbd_app")
        .await;
    let excess = e.db.privilege_self_test().await.unwrap();
    assert_eq!(
        excess,
        ["update audit_log", "delete audit_log", "delete account"]
    );
    let report = e.db.deep_db_check().await.unwrap();
    assert!(!report.quick_check_ok);
    assert_eq!(report.fk_violations, 3);
}

/// SEC-099: the bulk statements bind the selection as ONE array parameter (no list of placeholders, no JSON
/// expansion), and a 100-id selection is one statement per step.
#[tokio::test]
async fn sec_099_bulk_ids_are_bound_as_one_array() {
    let src: String =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg/bulk.rs"))
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    assert!(src.contains("WHERE id = ANY($1) ORDER BY id FOR UPDATE"));
    assert!(src.contains("WHERE id = ANY($2)"));
    for banned in [
        "json_each",
        "push_bind",
        "separated(",
        "format!(\"SELECT",
        "format!(\"UPDATE",
    ] {
        assert!(!src.contains(banned), "{banned}");
    }
    let e = env().await;
    let a = e.admin("root").await;
    let act = e.actor(a).await;
    let mut ids = Vec::new();
    for n in 1..=100_u8 {
        ids.push(e.release(n, &Uploader::Unattributed).await.unwrap());
    }
    assert_eq!(
        e.db.bulk_set_category_as(&act, &ids, 5040, &[], None, T0 + 1)
            .await
            .unwrap(),
        100
    );
    assert_eq!(e.count("release", "category_id = 5040").await, 100);
    // 101 distinct ids are refused before anything is read.
    ids.push(e.release(101, &Uploader::Unattributed).await.unwrap());
    assert!(matches!(
        e.db.bulk_set_category_as(&act, &ids, 2040, &[], None, T0 + 2)
            .await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(e.count("release", "category_id = 2040").await, 0);
}

/// SEC-099: two bulk edits racing on overlapping selections are serialized by the row locks (taken in id order, so
/// they cannot deadlock): every release ends with ONE of the two values, each edit applied all-or-nothing, the
/// totals exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_099_bulk_edit_is_atomic_under_concurrent_edits() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.admin("root2").await; // edits are admin-only (D40)
    let (act_a, act_m) = (e.actor(a).await, e.actor(m).await);
    let mut ids = Vec::new();
    for n in 1..=40_u8 {
        ids.push(e.release(n, &Uploader::Unattributed).await.unwrap());
    }
    for round in 0..5_i64 {
        let left: Vec<i64> = ids[..30].to_vec();
        let mut right: Vec<i64> = ids[10..].to_vec();
        right.reverse(); // a different input order: the store must still lock in id order
        let (db1, db2) = (e.db.clone(), e.second().await);
        let (x, y) = (act_a.clone(), act_m.clone());
        let t1 = tokio::spawn(async move {
            db1.bulk_set_category_as(&x, &left, 5040, &[], None, T0 + round)
                .await
        });
        let t2 = tokio::spawn(async move {
            db2.bulk_set_category_as(&y, &right, 2040, &[], None, T0 + round)
                .await
        });
        assert_eq!(t1.await.unwrap().unwrap(), 30);
        assert_eq!(t2.await.unwrap().unwrap(), 30);
        let overlap: Vec<i64> = sqlx::query_scalar(
            "SELECT category_id::int8 FROM release WHERE id = ANY($1) GROUP BY category_id",
        )
        .bind(&ids[10..30])
        .fetch_all(e.db.web())
        .await
        .unwrap();
        assert_eq!(
            overlap.len(),
            1,
            "the overlap carries one edit's value, never a mix: {overlap:?}"
        );
        let totals = e.db.release_totals().await.unwrap();
        assert_eq!(totals.releases, 40);
        let in_stats: i64 =
            sqlx::query_scalar("SELECT releases FROM category_stats WHERE category_id = $1")
                .bind(i32::try_from(overlap[0]).unwrap())
                .fetch_one(e.db.web())
                .await
                .unwrap();
        assert_eq!(
            in_stats, 30,
            "the winner of the overlap holds 20 + its own 10"
        );
    }
}

/// SEC-024 on Postgres: the per-user, per-stage session cap holds when logins of one account race on different
/// connections (the account-domain lock replaces the 2.x single writer).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_024_session_cap_holds_under_concurrent_logins_on_postgres() {
    let e = env().await;
    let a =
        e.db.create_account_operator(
            &NewAccount {
                username: "root",
                password_hash: PHC,
                role: None,
            },
            POLICY,
            T0,
        )
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for n in 0..24_u8 {
        let db = if n % 2 == 0 {
            e.db.clone()
        } else {
            e.second().await
        };
        tasks.push(tokio::spawn(async move {
            db.insert_session(
                &sess(
                    a,
                    n.wrapping_add(1),
                    SessionStage::Active,
                    T0 + i64::from(n),
                ),
                5,
            )
            .await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(
        e.count("session", &format!("account_id = {a} AND stage = 'active'"))
            .await,
        5
    );
}
