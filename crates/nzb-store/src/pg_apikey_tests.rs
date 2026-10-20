//! Per-user scoped API keys (T103; SEC-036 v2): ownership, per-owner caps, revocation authority,
//! scope, per-key budget and the N9 re-check inside the ingest transaction.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines
)]

#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::pg_testkit::{T0, env, sess};
use crate::{
    AccountError, AuditActor, CreateKey, GrantableRole, NewApiKey, SessionStage, StoreError,
    Uploader,
};

fn new_key(hash: &[u8; 32], rate: Option<u32>) -> NewApiKey<'_> {
    NewApiKey {
        label: "script",
        prefix: "abcdef",
        key_hash: hash,
        rate_per_min: rate,
    }
}

#[tokio::test]
async fn sec_036_keys_belong_to_their_owner_and_lists_are_scoped() {
    let e = env().await;
    let a = e.admin("root").await;
    let m1 = e.uploader("mem1").await;
    let m2 = e.uploader("mem2").await;
    let (k1, _) = e.key(m1, 1).await;
    let (k2, _) = e.key(m2, 2).await;
    let (ka, _) = e.key(a, 3).await;
    let ids = |rows: Vec<crate::ApiKeyRow>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
    // An uploader's listing is exactly their own keys; the admin's (no owner filter) is all of them.
    assert_eq!(
        ids(e.db.list_api_keys_recent(Some(m1), 20).await.unwrap()),
        [k1]
    );
    assert_eq!(
        ids(e.db.list_api_keys_recent(Some(m2), 20).await.unwrap()),
        [k2]
    );
    assert_eq!(
        ids(e.db.list_api_keys_recent(None, 20).await.unwrap()),
        [ka, k2, k1]
    );
    let rows = e.db.list_api_keys_recent(None, 20).await.unwrap();
    let row = rows.iter().find(|r| r.id == k1).unwrap();
    assert_eq!(row.scope, "upload");
    assert_eq!(row.owner_id, Some(m1));
    assert_eq!(row.owner_username.as_deref(), Some("mem1"));
    assert_eq!(
        row.owner_handle.as_deref(),
        Some(format!("user-{m1}").as_str())
    );
    // The create audit row names the owner as the target.
    let created = e.audit("apikey.create").await;
    assert_eq!(created.len(), 3);
    assert!(created.iter().any(|r| r.target_id == Some(m1)));
}

#[tokio::test]
async fn sec_036_cap_is_per_owner_not_per_instance() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m1 = e.uploader("mem1").await;
    let m2 = e.uploader("mem2").await;
    for n in 0..10_u8 {
        e.key(m1, n + 1).await;
    }
    let over =
        e.db.create_api_key_for(
            new_key(&[200; 32], None),
            m1,
            10,
            T0,
            &AuditActor::cli(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(over, CreateKey::LimitReached);
    // Another account is unaffected by m1 being at its cap.
    let ok =
        e.db.create_api_key_for(
            new_key(&[201; 32], None),
            m2,
            10,
            T0,
            &AuditActor::cli(),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(ok, CreateKey::Created(_)));
    assert_eq!(e.db.count_active_api_keys_of(m1).await.unwrap(), 10);
    assert_eq!(e.db.count_active_api_keys_of(m2).await.unwrap(), 1);
}

#[tokio::test]
async fn sec_036_instance_cap_bounds_the_key_table() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    // Fill the instance up to one below the ceiling with raw rows owned by other (revoked-free) keys.
    for i in 0..(crate::MAX_ACTIVE_KEYS_INSTANCE - 1) {
        sqlx::query(
            "INSERT INTO api_key (name, prefix, key_hash, created_at, owner_id) VALUES ('x', 'p', $1, 1, NULL)",
        )
        .bind(i.to_be_bytes().repeat(8))
        .execute(e.db.web())
        .await
        .unwrap();
    }
    let ok =
        e.db.create_api_key_for(new_key(&[7; 32], None), m, 10, T0, &AuditActor::cli(), None)
            .await
            .unwrap();
    assert!(matches!(ok, CreateKey::Created(_)));
    let full =
        e.db.create_api_key_for(new_key(&[8; 32], None), m, 10, T0, &AuditActor::cli(), None)
            .await
            .unwrap();
    assert_eq!(full, CreateKey::InstanceLimitReached);
    // A distinct, secret-free audit row names the cap and the account that hit it.
    let rows = e.audit("apikey_instance_cap").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, Some(m));
    let detail = rows[0].detail.clone().unwrap();
    assert!(detail.contains("cap=500") && !detail.contains("prefix"));
    // The per-owner cap is a different answer and writes no such row.
    assert_eq!(e.audit("apikey.create").await.len(), 1);
}

#[tokio::test]
async fn sec_036_owner_revokes_own_key_and_nobody_else_s() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m1 = e.uploader("mem1").await;
    let m2 = e.uploader("mem2").await;
    let (k1, h1) = e.key(m1, 1).await;
    // Another uploader cannot revoke it, and the answer is the same as for a key that does not exist.
    assert!(
        !e.db
            .revoke_api_key_by(&e.actor(m2).await, k1, None, T0 + 1)
            .await
            .unwrap()
    );
    assert!(
        !e.db
            .revoke_api_key_by(&e.actor(m2).await, 9999, None, T0 + 1)
            .await
            .unwrap()
    );
    assert!(e.db.find_api_key(&h1).await.unwrap().unwrap().may_upload());
    assert!(
        e.audit("apikey.revoke").await.is_empty(),
        "a refusal writes nothing"
    );
    // The owner can, and it is audited with the owner as actor.
    assert!(
        e.db.revoke_api_key_by(&e.actor(m1).await, k1, Some("10.0.0.1"), T0 + 2)
            .await
            .unwrap()
    );
    assert!(!e.db.find_api_key(&h1).await.unwrap().unwrap().may_upload());
    let rows = e.audit("apikey.revoke").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, Some(m1));
    assert_eq!(rows[0].kind.as_deref(), Some("user"));
    assert_eq!(rows[0].role.as_deref(), Some("uploader"));
    assert_eq!(rows[0].target_id, None, "own key: no foreign target");
    // Revoking twice is "not found", not an error.
    assert!(
        !e.db
            .revoke_api_key_by(&e.actor(m1).await, k1, None, T0 + 3)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sec_036_key_revocation_requires_current_actor_session() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    for (actor_id, n) in [(a, 70_u8), (m, 71_u8)] {
        let (key, hash) = e.key(m, n).await;
        e.db.insert_session(&sess(actor_id, n, SessionStage::Active, T0), 5)
            .await
            .unwrap();
        let mut actor = e.actor(actor_id).await;
        actor.session = Some([n; 32]);
        // A password reset or explicit revocation invalidated the request's calling cookie.
        assert!(e.db.delete_session(&[n; 32]).await.unwrap());
        let r = e.db.revoke_api_key_by(&actor, key, None, T0 + 1).await;
        assert!(matches!(
            r,
            Err(StoreError::Account(AccountError::Forbidden))
        ));
        assert!(!e.db.find_api_key(&hash).await.unwrap().unwrap().revoked);
        assert_eq!(e.audit("apikey.revoke").await.len(), usize::from(n - 70));

        // Both an administrator and the key owner can still revoke with a current session.
        e.db.insert_session(&sess(actor_id, n + 10, SessionStage::Active, T0 + 2), 5)
            .await
            .unwrap();
        actor.session = Some([n + 10; 32]);
        assert!(
            e.db.revoke_api_key_by(&actor, key, None, T0 + 3)
                .await
                .unwrap()
        );
        assert!(e.db.find_api_key(&hash).await.unwrap().unwrap().revoked);
    }
    assert_eq!(e.audit("apikey.revoke").await.len(), 2);
}

#[tokio::test]
async fn sec_036_admin_revokes_any_key_and_is_named_in_the_audit() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (k, h) = e.key(m, 1).await;
    assert!(
        e.db.revoke_api_key_by(&e.actor(a).await, k, Some("10.0.0.9"), T0 + 5)
            .await
            .unwrap()
    );
    assert!(e.db.find_api_key(&h).await.unwrap().unwrap().revoked);
    let rows = e.audit("apikey.revoke").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, Some(a));
    assert_eq!(rows[0].role.as_deref(), Some("admin"));
    assert_eq!(rows[0].target_id, Some(m), "the key's owner is the target");
    assert_eq!(
        rows[0].detail.as_deref(),
        Some(format!("id={k} owner={m}").as_str())
    );
    // The listing tells the owner that someone else revoked it.
    let row = &e.db.list_api_keys_recent(Some(m), 5).await.unwrap()[0];
    assert_eq!(row.revoked_by, Some(a));
    assert_eq!(row.revoked_at, Some(T0 + 5));
}

#[tokio::test]
async fn sec_036_viewer_and_disabled_actors_cannot_revoke_or_own() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let v = e.viewer("view").await;
    let (k, _) = e.key(m, 1).await;
    let err =
        e.db.revoke_api_key_by(&e.actor(v).await, k, None, T0 + 1)
            .await
            .unwrap_err();
    assert!(matches!(err, StoreError::Account(AccountError::Forbidden)));
    // A viewer cannot own a key.
    let err =
        e.db.create_api_key_for(new_key(&[9; 32], None), v, 10, T0, &AuditActor::cli(), None)
            .await
            .unwrap_err();
    assert!(matches!(err, StoreError::Account(AccountError::Forbidden)));
    // An uploader demoted to viewer loses the authority over their own key at once.
    e.db.set_role(&e.actor(a).await, m, GrantableRole::Viewer, None, T0 + 2)
        .await
        .unwrap();
    let err =
        e.db.revoke_api_key_by(&e.actor(m).await, k, None, T0 + 3)
            .await
            .unwrap_err();
    assert!(matches!(err, StoreError::Account(AccountError::Forbidden)));
}

#[tokio::test]
async fn sec_036_per_key_rate_is_stored_and_bounded() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let r =
        e.db.create_api_key_for(
            new_key(&[1; 32], Some(5)),
            m,
            10,
            T0,
            &AuditActor::cli(),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, CreateKey::Created(_)));
    assert_eq!(
        e.db.find_api_key(&[1; 32])
            .await
            .unwrap()
            .unwrap()
            .rate_per_min,
        Some(5)
    );
    for bad in [0_u32, 31, 1000] {
        let err =
            e.db.create_api_key_for(
                new_key(&[2; 32], Some(bad)),
                m,
                10,
                T0,
                &AuditActor::cli(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::OutOfRange(_)), "rate {bad}");
    }
    // The database refuses it as well (hand-written SQL).
    let raw = sqlx::query("UPDATE api_key SET rate_per_min = 31")
        .execute(e.db.web())
        .await;
    assert!(raw.is_err());
    // A key created without a rate has none stored.
    let (_, h) = e.key(m, 3).await;
    assert_eq!(
        e.db.find_api_key(&h).await.unwrap().unwrap().rate_per_min,
        None
    );
}

#[tokio::test]
async fn sec_036_scope_is_explicit_and_only_upload_exists() {
    let e = env().await;
    let a = e.admin("root").await;
    let (id, h) = e.key(a, 1).await;
    let k = e.db.find_api_key(&h).await.unwrap().unwrap();
    assert_eq!(k.scope, crate::SCOPE_UPLOAD);
    assert!(k.may_upload());
    // No other scope can be stored, so no key can silently gain a wider one.
    let raw = sqlx::query("UPDATE api_key SET scope = 'admin' WHERE id = $1")
        .bind(id)
        .execute(e.db.web())
        .await;
    assert!(raw.is_err());
    let raw = sqlx::query("UPDATE api_key SET scope = 'read' WHERE id = $1")
        .bind(id)
        .execute(e.db.web())
        .await;
    assert!(raw.is_err());
}

#[tokio::test]
async fn sec_036_key_revoked_by_its_owner_during_body_is_refused() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (key, h) = e.key(m, 1).await;
    // The gate accepted the key at the start of the request...
    assert!(e.db.find_api_key(&h).await.unwrap().unwrap().may_upload());
    // ...the owner revoked it through the account page while the body streamed...
    assert!(
        e.db.revoke_api_key_by(&e.actor(m).await, key, None, T0 + 1)
            .await
            .unwrap()
    );
    // ...and the ingest transaction refuses and writes nothing.
    let r = e.release(1, &Uploader::ApiKey(key)).await;
    assert!(matches!(
        r,
        Err(StoreError::Account(AccountError::KeyRefused))
    ));
    assert_eq!(e.count("release", "1=1").await, 0);
}

#[tokio::test]
async fn sec_036_uploader_demoted_to_viewer_loses_key_during_body() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (key, _) = e.key(m, 1).await;
    e.db.set_role(&e.actor(a).await, m, GrantableRole::Viewer, None, T0 + 1)
        .await
        .unwrap();
    let r = e.release(1, &Uploader::ApiKey(key)).await;
    assert!(matches!(
        r,
        Err(StoreError::Account(AccountError::KeyRefused))
    ));
}

#[tokio::test]
async fn sec_036_concurrent_creates_cannot_exceed_the_owner_cap() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let mut tasks = Vec::new();
    for i in 0..40_u8 {
        let db = e.db.clone();
        tasks.push(tokio::spawn(async move {
            let hash = [i.wrapping_add(1); 32];
            db.create_api_key_for(
                NewApiKey {
                    label: "race",
                    prefix: "abcdef",
                    key_hash: &hash,
                    rate_per_min: None,
                },
                m,
                10,
                T0,
                &AuditActor::cli(),
                None,
            )
            .await
            .unwrap()
        }));
    }
    let mut created = 0;
    for t in tasks {
        if matches!(t.await.unwrap(), CreateKey::Created(_)) {
            created += 1;
        }
    }
    assert_eq!(created, 10);
    assert_eq!(e.db.count_active_api_keys_of(m).await.unwrap(), 10);
}

/// T134 review I5: a demotion to viewer (web and operator path) revokes the account's unrevoked API keys in the role
/// transaction and counts them in the `role_change` detail; a promotion back does not revive them; a change that
/// keeps upload rights (viewer -> uploader) revokes nothing.
#[tokio::test]
async fn sec_036_demotion_to_viewer_revokes_the_owners_keys() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    let (k1, h1) = e.key(m, 1).await;
    let (_k2, _h2) = e.key(m, 2).await;
    assert!(e.db.find_api_key(&h1).await.unwrap().unwrap().may_upload());
    let live = format!("owner_id = {m} AND revoked_at IS NULL");
    assert_eq!(e.count("api_key", &live).await, 2);
    e.db.set_role(&act, m, GrantableRole::Viewer, None, T0 + 1)
        .await
        .unwrap();
    assert_eq!(e.count("api_key", &live).await, 0);
    let rows = e.audit("role_change").await;
    assert_eq!(
        rows.last().unwrap().detail.as_deref(),
        Some("old=uploader new=viewer sessions_revoked=0 keys_revoked=2")
    );
    // Back to uploader: the keys stay revoked; nothing else is revoked on the way up.
    e.db.set_role(&act, m, GrantableRole::Uploader, None, T0 + 2)
        .await
        .unwrap();
    assert!(!e.db.find_api_key(&h1).await.unwrap().unwrap().may_upload());
    assert!(
        e.audit("role_change")
            .await
            .last()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .ends_with("keys_revoked=0")
    );
    // The operator path does the same.
    let (_k3, h3) = e.key(m, 3).await;
    assert!(e.db.find_api_key(&h3).await.unwrap().unwrap().may_upload());
    e.db.set_role_operator(m, crate::Role::Viewer, T0 + 3)
        .await
        .unwrap();
    assert_eq!(e.count("api_key", &live).await, 0);
    assert!(
        e.audit("role_change")
            .await
            .last()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .ends_with("keys_revoked=1")
    );
    let _ = k1;
}

#[tokio::test]
async fn web_key_creation_is_bound_to_the_reauthenticated_session() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem1").await;
    // The session that re-authenticated is gone (a recovery, reset or revocation committed
    // meanwhile): no key is created.
    let r =
        e.db.create_api_key_for_session(
            new_key(&[210; 32], None),
            m,
            &[90; 32],
            10,
            T0,
            &AuditActor::cli(),
            None,
        )
        .await;
    assert!(matches!(r, Err(StoreError::NotFound)));
    assert_eq!(e.db.count_active_api_keys_of(m).await.unwrap(), 0);
    e.db.insert_session(&sess(m, 90, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let ok =
        e.db.create_api_key_for_session(
            new_key(&[211; 32], None),
            m,
            &[90; 32],
            10,
            T0 + 1,
            &AuditActor::cli(),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(ok, CreateKey::Created(_)));
}
