//! Attribution of uploads, edits, deletions and audit rows; log retention (T101a; SEC-033, SEC-036,
//! SEC-060, SEC-067).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::used_underscore_binding
)]

use crate::acct_testkit::{Env, T0, analysis, env, sess};
use crate::{
    AccountError, AuditActor, AuditEntry, CategorySource, GrantableRole, IngestLogEntry,
    LogOutcome, LogSource, NewRelease, SceneColumns, SessionStage, StoreError, Uploader,
};

#[tokio::test]
async fn sec_060_single_release_mutations_require_current_session() {
    let e = env().await;
    let admin = e.admin("root").await;
    let other = e.admin("other").await;
    let mut actor = e.actor(admin).await;
    // Capture the actor before logout, as a request admitted before reading its body would.
    for (owner, hash, stage) in [
        (admin, 10, SessionStage::Active),
        (admin, 11, SessionStage::Active),
        (admin, 12, SessionStage::PendingMfa),
        (other, 13, SessionStage::Active),
    ] {
        let mut session = sess(owner, hash, stage, T0);
        if hash == 11 {
            session.expires_at = T0 + 1;
        }
        e.db.insert_session(&session, 10).await.unwrap();
    }
    e.db.delete_session(&[10; 32]).await.unwrap();
    let id = e.release(1, &Uploader::Unattributed).await.unwrap();
    let before = e.db.get_release(id).await.unwrap().unwrap();
    let outbox = e.count("search_outbox", "1 = 1").await;
    let audit = e.count("audit_log", "1 = 1").await;
    for hash in [10, 11, 12, 13] {
        actor.session = Some([hash; 32]);
        let results = [
            e.db.set_category_as(&actor, id, 5040, None, T0 + 1)
                .await
                .map(|_| ()),
            e.db.set_source_label_as(&actor, id, Some("changed"), None, T0 + 1)
                .await
                .map(|_| ()),
            e.db.trash_release_as(&actor, id, T0 + 1, None)
                .await
                .map(|_| ()),
            e.db.trash_release_checked_as(&actor, id, &before.sha256, T0 + 1, None)
                .await
                .map(|_| ()),
        ];
        for result in results {
            assert!(
                matches!(result, Err(StoreError::Account(AccountError::Forbidden))),
                "session {hash}: {result:?}"
            );
        }
        assert_eq!(e.db.get_release(id).await.unwrap().unwrap(), before);
        assert_eq!(e.db.list_trash(10).await.unwrap().len(), 0);
        assert_eq!(e.count("search_outbox", "1 = 1").await, outbox);
        assert_eq!(e.count("audit_log", "1 = 1").await, audit);
    }
    // The same expiring session remains usable one second before its boundary.
    actor.session = Some([11; 32]);
    e.db.set_category_as(&actor, id, 5040, None, T0)
        .await
        .unwrap();
    e.db.set_source_label_as(&actor, id, Some("allowed"), None, T0)
        .await
        .unwrap();
    e.db.trash_release_checked_as(&actor, id, &before.sha256, T0, None)
        .await
        .unwrap();
    // CLI/internal actors intentionally have no browser session.
    actor.session = None;
    let legacy = e.release(2, &Uploader::Unattributed).await.unwrap();
    e.db.trash_release_as(&actor, legacy, T0 + 1, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn sec_060_upload_revalidates_browser_session_at_commit() {
    let e = env().await;
    let admin = e.admin("root").await;
    let other = e.admin("other").await;
    for (owner, hash, stage) in [
        (admin, 10, SessionStage::Active),
        (admin, 11, SessionStage::Active),
        (admin, 12, SessionStage::PendingMfa),
        (other, 13, SessionStage::Active),
    ] {
        let mut session = sess(owner, hash, stage, T0);
        if hash == 11 {
            session.expires_at = T0 + 1;
        }
        e.db.insert_session(&session, 10).await.unwrap();
    }
    let admitted = Uploader::Session {
        user_id: admin,
        id_hash: [10; 32],
    };
    e.db.validate_uploader(&admitted, T0).await.unwrap();
    e.db.delete_session(&[10; 32]).await.unwrap();
    for hash in [10, 11, 12, 13] {
        let uploader = Uploader::Session {
            user_id: admin,
            id_hash: [hash; 32],
        };
        let a = analysis(hash);
        let new = NewRelease {
            analysis: &a,
            nzb_size_bytes: 1,
            source_name: None,
            source_label: None,
            category_id: 8010,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: SceneColumns::default(),
            ingested_at: T0 + 1,
        };
        let log = entry(&a, LogSource::UploadUi);
        assert!(
            matches!(
                e.db.validate_uploader(&uploader, T0 + 1).await,
                Err(StoreError::Account(AccountError::Forbidden))
            ),
            "duplicate disclosure must be refused for session {hash}"
        );
        assert_eq!(
            refused(&e.db.insert_release_as(&new, Some(&log), &uploader).await),
            Some(AccountError::Forbidden),
            "session {hash}"
        );
        let outcomes =
            e.db.insert_release_group(
                &[crate::GroupItem { new, log, uploader }],
                std::time::Duration::MAX,
            )
            .await
            .unwrap();
        assert!(
            matches!(
                outcomes.as_slice(),
                [crate::GroupOutcome::Failed(StoreError::Account(
                    AccountError::Forbidden
                ))]
            ),
            "session {hash}: {outcomes:?}"
        );
    }
    for table in ["release", "nzb_file", "search_outbox", "ingest_log"] {
        assert_eq!(e.count(table, "1 = 1").await, 0, "{table}");
    }
    let live = Uploader::Session {
        user_id: admin,
        id_hash: [11; 32],
    };
    let id = e.release(20, &live).await.unwrap();
    assert_eq!(
        e.db.release_attribution(id)
            .await
            .unwrap()
            .unwrap()
            .added_by,
        Some(admin)
    );
    e.release(21, &Uploader::Account(admin)).await.unwrap();
    assert_eq!(
        format!("{live:?}"),
        format!("Session {{ user_id: {admin}, .. }}")
    );
}

#[tokio::test]
async fn sec_060_upload_group_does_not_cache_session_past_expiry() {
    let e = env().await;
    let admin = e.admin("root").await;
    let mut session = sess(admin, 10, SessionStage::Active, T0);
    session.expires_at = T0 + 1;
    e.db.insert_session(&session, 10).await.unwrap();
    let uploader = Uploader::Session {
        user_id: admin,
        id_hash: [10; 32],
    };
    let analyses = [analysis(1), analysis(2), analysis(3)];
    let items: Vec<_> = analyses
        .iter()
        .zip([T0, T0 + 1, T0])
        .map(|(a, now)| crate::GroupItem {
            new: NewRelease {
                analysis: a,
                nzb_size_bytes: 1,
                source_name: None,
                source_label: None,
                category_id: 8010,
                category_source: CategorySource::Fallback,
                meta_json: None,
                scene: SceneColumns::default(),
                ingested_at: now,
            },
            log: entry(a, LogSource::UploadUi),
            uploader,
        })
        .collect();
    let outcomes =
        e.db.insert_release_group(&items, std::time::Duration::MAX)
            .await
            .unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [
                crate::GroupOutcome::Inserted(_),
                crate::GroupOutcome::Failed(StoreError::Account(AccountError::Forbidden)),
                crate::GroupOutcome::Inserted(_),
            ]
        ),
        "{outcomes:?}"
    );
    assert_eq!(e.count("release", "1 = 1").await, 2);
    assert_eq!(e.count("search_outbox", "1 = 1").await, 2);
    assert_eq!(e.count("ingest_log", "1 = 1").await, 2);
    assert!(
        e.db.get_release_by_sha(&analyses[1].sha256.to_hex())
            .await
            .unwrap()
            .is_none()
    );
}

fn refused(r: &Result<i64, StoreError>) -> Option<AccountError> {
    match r {
        Err(StoreError::Account(e)) => Some(*e),
        _ => None,
    }
}

fn entry(a: &nzb_core::Analysis, source: LogSource) -> IngestLogEntry<'static> {
    IngestLogEntry {
        ts: T0,
        source,
        api_key_id: None,
        source_name: Some("x.nzb"),
        sha256: Some(a.sha256),
        outcome: LogOutcome::Ok,
        error_code: None,
        detail: None,
    }
}

#[tokio::test]
async fn sec_067_added_by_comes_from_session_not_request() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (key, _) = e.key(m, 3).await;
    // Account upload (UI): attribution is the validated actor id.
    let r1 = e.release(1, &Uploader::Account(m)).await.unwrap();
    // Key upload (API): attribution is the key's owner, not the (absent) session.
    let r2 = e.release(2, &Uploader::ApiKey(key)).await.unwrap();
    // Watch folder / CLI / 1.x callers: unattributed.
    let r3 = e.release(3, &Uploader::Unattributed).await.unwrap();
    for (id, want) in [(r1, Some(m)), (r2, Some(m)), (r3, None)] {
        let att = e.db.release_attribution(id).await.unwrap().unwrap();
        assert_eq!(att.added_by, want, "release {id}");
        assert_eq!(att.handle, want.map(|u| format!("user-{u}")));
        assert!(!att.deleted);
    }
    // The 1.x insert signature records nothing.
    let an = analysis(4);
    let new = NewRelease {
        analysis: &an,
        nzb_size_bytes: 1,
        source_name: None,
        source_label: None,
        category_id: 8010,
        category_source: CategorySource::Fallback,
        meta_json: None,
        scene: SceneColumns::default(),
        ingested_at: T0,
    };
    let r4 = e.db.insert_release(&new).await.unwrap();
    assert_eq!(
        e.db.release_attribution(r4)
            .await
            .unwrap()
            .unwrap()
            .added_by,
        None
    );
    // The ingest log row of a logged insert carries the same attribution (same transaction).
    let an5 = analysis(5);
    let new5 = NewRelease {
        analysis: &an5,
        ..new.clone()
    };
    let log = entry(&an5, LogSource::UploadUi);
    let r5 =
        e.db.insert_release_as(&new5, Some(&log), &Uploader::Account(a))
            .await
            .unwrap();
    let uid: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM ingest_log WHERE release_id = ?1")
            .bind(r5)
            .fetch_one(e.db.writer())
            .await
            .unwrap();
    assert_eq!(uid, Some(a));
    // A duplicate or failed submission is logged with its uploader too.
    e.db.log_ingest_as(
        &entry(&an5, LogSource::UploadApi),
        None,
        &Uploader::ApiKey(key),
    )
    .await
    .unwrap();
    assert_eq!(e.count("ingest_log", &format!("account_id = {m}")).await, 1);
}

#[tokio::test]
async fn sec_060_role_is_rechecked_before_each_upload_part() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let v = e.viewer("view").await;
    // A viewer can never upload.
    assert_eq!(
        refused(&e.release(1, &Uploader::Account(v)).await),
        Some(AccountError::Forbidden)
    );
    // The uploader's first part is committed...
    e.release(2, &Uploader::Account(m)).await.unwrap();
    // ...then the role changes mid-request: the next part is refused and nothing is written.
    sqlx::query("UPDATE account SET role = 'viewer' WHERE id = ?1")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap();
    assert_eq!(
        refused(&e.release(3, &Uploader::Account(m)).await),
        Some(AccountError::Forbidden)
    );
    assert_eq!(e.count("release", "1=1").await, 1);
    // Disabled and tombstoned accounts are refused as well.
    sqlx::query("UPDATE account SET role = 'uploader', disabled_at = 5 WHERE id = ?1")
        .bind(m)
        .execute(e.db.writer())
        .await
        .unwrap();
    assert_eq!(
        refused(&e.release(4, &Uploader::Account(m)).await),
        Some(AccountError::Forbidden)
    );
    assert_eq!(e.count("release", "1=1").await, 1);
    assert_eq!(e.count("ingest_log", "1=1").await, 0);
}

#[tokio::test]
async fn sec_036_key_of_disabled_owner_is_refused() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (_k, h) = e.key(m, 3).await;
    let (_ka, ha) = e.key(a, 4).await;
    assert!(e.db.find_api_key(&h).await.unwrap().unwrap().may_upload());
    assert!(e.db.find_api_key(&ha).await.unwrap().unwrap().may_upload());
    let act = e.actor(a).await;
    e.db.disable_account(&act, m, None, T0).await.unwrap();
    let k = e.db.find_api_key(&h).await.unwrap().unwrap();
    assert!(!k.may_upload(), "disabled owner");
    // A viewer-owned key and an ownerless key are not usable either.
    e.db.enable_account(&act, m, None, T0 + 1).await.unwrap();
    e.db.set_role(&act, m, GrantableRole::Viewer, None, T0 + 2)
        .await
        .unwrap();
    assert!(!e.db.find_api_key(&h).await.unwrap().unwrap().may_upload());
    sqlx::query("UPDATE api_key SET owner_id = NULL WHERE key_hash = ?1")
        .bind(ha.as_slice())
        .execute(e.db.writer())
        .await
        .unwrap();
    assert!(!e.db.find_api_key(&ha).await.unwrap().unwrap().may_upload());
    // Creating a key for a viewer is refused in the first place.
    let err =
        e.db.create_api_key_for(
            crate::NewApiKey {
                label: "v",
                prefix: "abcdef",
                key_hash: &[9; 32],
                rate_per_min: None,
            },
            m,
            10,
            T0,
            &AuditActor::cli(),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Account(AccountError::Forbidden)));
}

#[tokio::test]
async fn sec_036_key_owner_disabled_during_body_is_refused() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let (key, h) = e.key(m, 3).await;
    // The API handler looked the key up at the start of the request (accepted)...
    assert!(e.db.find_api_key(&h).await.unwrap().unwrap().may_upload());
    // ...and while the body streamed the owner was disabled: the ingest transaction re-checks.
    e.db.disable_account(&e.actor(a).await, m, None, T0)
        .await
        .unwrap();
    let r = e.release(1, &Uploader::ApiKey(key)).await;
    assert_eq!(refused(&r), Some(AccountError::KeyRefused));
    assert_eq!(e.count("release", "1=1").await, 0);
    // Same for a key revoked mid-body, and for a key that does not exist.
    e.db.enable_account(&e.actor(a).await, m, None, T0 + 1)
        .await
        .unwrap();
    e.release(2, &Uploader::ApiKey(key)).await.unwrap();
    let rev =
        e.db.revoke_api_key(
            key,
            T0 + 2,
            crate::Actor {
                name: "cli",
                ip: None,
            },
        )
        .await
        .unwrap();
    assert!(rev);
    assert_eq!(
        refused(&e.release(3, &Uploader::ApiKey(key)).await),
        Some(AccountError::KeyRefused)
    );
    assert_eq!(
        refused(&e.release(4, &Uploader::ApiKey(9999)).await),
        Some(AccountError::KeyRefused)
    );
    assert_eq!(e.count("release", "1=1").await, 1);
}

#[tokio::test]
async fn sec_067_category_and_source_edits_name_the_actor() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let v = e.viewer("view").await;
    // The release was added by the UPLOADER; only the admin edits it (D26 c: any release; D40: admin only).
    let rel = e.release(1, &Uploader::Account(m)).await.unwrap();
    let aa = e.actor(a).await;
    let old =
        e.db.set_category_as(&aa, rel, 2040, Some("192.0.2.9"), T0 + 1)
            .await
            .unwrap();
    assert_eq!(old, 8010);
    let stored =
        e.db.set_source_label_as(&aa, rel, Some("  torrent "), None, T0 + 2)
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some("torrent"));
    for (event, n) in [("category_override", 0), ("source_label_edit", 1)] {
        let rows = e.audit(event).await;
        assert_eq!(rows.len(), 1, "{event}");
        assert_eq!(rows[0].kind.as_deref(), Some("user"), "{n}");
        assert_eq!(rows[0].actor_id, Some(a));
        assert_eq!(rows[0].role.as_deref(), Some("admin"));
        assert_eq!(rows[0].actor.as_deref(), Some("root"));
    }
    // Neither the uploader (not even on their own upload, D40) nor a viewer can edit, and nothing changes.
    for who in [m, v] {
        let actor = e.actor(who).await;
        assert!(matches!(
            e.db.set_category_as(&actor, rel, 5040, None, T0 + 3).await,
            Err(StoreError::Account(AccountError::Forbidden))
        ));
        assert!(matches!(
            e.db.set_source_label_as(&actor, rel, None, None, T0 + 3)
                .await,
            Err(StoreError::Account(AccountError::Forbidden))
        ));
    }
    assert_eq!(e.audit("category_override").await.len(), 1);
    assert_eq!(e.audit("source_label_edit").await.len(), 1);
    // Unknown release / category.
    assert!(matches!(
        e.db.set_category_as(&aa, 99_999, 2040, None, T0 + 4).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        e.db.set_category_as(&aa, rel, 1, None, T0 + 4).await,
        Err(StoreError::UnknownCategory)
    ));
}

#[tokio::test]
async fn sec_067_shared_edit_detail_holds_old_and_new_value() {
    let e = env().await;
    let a = e.admin("root").await;
    let rel = e.release(1, &Uploader::Account(a)).await.unwrap();
    let act = e.actor(a).await;
    e.db.set_category_as(&act, rel, 2040, None, T0 + 1)
        .await
        .unwrap();
    e.db.set_category_as(&act, rel, 5040, None, T0 + 2)
        .await
        .unwrap();
    let rows = e.audit("category_override").await;
    let d: Vec<_> = rows.iter().map(|r| r.detail.clone().unwrap()).collect();
    assert_eq!(d[0], format!("release={rel} old=8010 new=2040"));
    assert_eq!(d[1], format!("release={rel} old=2040 new=5040"));
    // The source label's old value ("orig" was given at upload) and new value; hostile text is data:
    // it is JSON-serialized, never concatenated.
    e.db.set_source_label_as(&act, rel, Some("a \"quoted\" label"), None, T0 + 3)
        .await
        .unwrap();
    e.db.set_source_label_as(&act, rel, None, None, T0 + 4)
        .await
        .unwrap();
    let rows = e.audit("source_label_edit").await;
    let v0: serde_json::Value = serde_json::from_str(rows[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(v0["old"], "orig");
    assert_eq!(v0["new"], "a \"quoted\" label");
    let v1: serde_json::Value = serde_json::from_str(rows[1].detail.as_deref().unwrap()).unwrap();
    assert_eq!(v1["old"], "a \"quoted\" label");
    assert!(v1["new"].is_null());
    assert_eq!(v1["release"], rel);
}

#[tokio::test]
async fn trash_release_as_requires_an_admin_and_records_deleted_by() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let rel = e.release(1, &Uploader::Account(m)).await.unwrap();
    // An uploader (or a forged admin struct) is refused before anything is read or moved.
    let mut forged = e.actor(m).await;
    forged.role = crate::Role::Admin;
    assert!(matches!(
        e.db.trash_release_as(&forged, rel, T0 + 1, None).await,
        Err(StoreError::Account(AccountError::Forbidden))
    ));
    assert_eq!(e.count("release", "1=1").await, 1);
    let act = e.actor(a).await;
    let t =
        e.db.trash_release_as(&act, rel, T0 + 2, Some("192.0.2.1"))
            .await
            .unwrap();
    assert_eq!(t.original_id, rel);
    let (added, deleted): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT added_by, deleted_by FROM release_trash WHERE id = ?1")
            .bind(t.id)
            .fetch_one(e.db.writer())
            .await
            .unwrap();
    assert_eq!((added, deleted), (Some(m), Some(a)));
    let rows = e.audit("release_delete").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].kind.as_deref(),
            rows[0].actor_id,
            rows[0].role.as_deref()
        ),
        (Some("user"), Some(a), Some("admin"))
    );
    // The 1.x entry point still works and is attributed from its actor text.
    let rel2 = e.release(2, &Uploader::Unattributed).await.unwrap();
    e.db.trash_release(rel2, T0 + 3, &format!("user:{a}"), None)
        .await
        .unwrap();
    let rows = e.audit("release_delete").await;
    assert_eq!(rows[1].actor_id, Some(a));
}

#[tokio::test]
async fn sec_033_account_events_are_attributed() {
    let e = env().await;
    let a = e.admin("root").await;
    let b = e.admin("second").await;
    e.mfa(a).await;
    e.mfa(b).await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    let h = crate::acct_testkit::code(1).hash();
    e.db.create_invite(
        &act,
        &crate::NewInvite {
            username: "guest",
            role: GrantableRole::Viewer,
            code_hash: &h,
            ttl_secs: 3600,
        },
        crate::acct_testkit::POLICY,
        Some("192.0.2.1"),
        T0 + 1,
    )
    .await
    .unwrap();
    e.db.set_role(&act, m, GrantableRole::Viewer, Some("192.0.2.1"), T0 + 2)
        .await
        .unwrap();
    e.db.disable_account(&act, m, Some("192.0.2.1"), T0 + 3)
        .await
        .unwrap();
    e.db.enable_account(&act, m, None, T0 + 4).await.unwrap();
    e.db.unlock_account(&act, m, None, T0 + 5).await.unwrap();
    e.db.set_display_name(&act, m, Some("Emm"), None, T0 + 6)
        .await
        .unwrap();
    e.db.revoke_account_sessions(&act, m, None, T0 + 7)
        .await
        .unwrap();
    e.db.disable_account(&act, m, None, T0 + 8).await.unwrap();
    e.db.delete_account(&act, m, None, T0 + 9).await.unwrap();
    for (event, target) in [
        ("role_change", Some(m)),
        ("user_disable", Some(m)),
        ("user_enable", Some(m)),
        ("user_unlock", Some(m)),
        ("user_display_name", Some(m)),
        ("sessions_revoke", Some(m)),
        ("user_delete", Some(m)),
        ("invite_create", None),
    ] {
        let rows = e.audit(event).await;
        assert!(!rows.is_empty(), "{event}");
        for r in rows {
            assert_eq!(r.kind.as_deref(), Some("user"), "{event}");
            assert_eq!(r.actor_id, Some(a), "{event}");
            assert_eq!(r.role.as_deref(), Some("admin"), "{event}");
            assert_eq!(r.actor.as_deref(), Some("root"), "{event}");
            assert_eq!(r.target_id, target, "{event}");
        }
    }
}

#[tokio::test]
async fn sec_067_every_mutation_names_its_actor() {
    let e = env().await;
    let a = e.admin("root").await;
    let b = e.admin("second").await;
    e.mfa(a).await;
    e.mfa(b).await;
    let m = e.uploader("mem").await;
    let act = e.actor(a).await;
    let (key, _h) = e.key(m, 7).await;
    e.release(1, &Uploader::Account(m)).await.unwrap();
    e.db.set_category_as(&act, 1, 2040, None, T0).await.unwrap();
    e.db.set_role(&act, m, GrantableRole::Viewer, None, T0)
        .await
        .unwrap();
    e.db.set_role_operator(m, crate::Role::Uploader, T0)
        .await
        .unwrap();
    e.db.disable_account_operator(m, T0).await.unwrap();
    e.db.enable_account_operator(m, T0).await.unwrap();
    e.db.reset_password_for(m, "h2", T0).await.unwrap();
    e.db.reset_mfa_for(m, T0).await.unwrap();
    e.db.set_enrollment_token_for(m, &[1; 32], T0 + 100, T0)
        .await
        .unwrap();
    e.db.set_display_name_operator(m, Some("Emm"), T0)
        .await
        .unwrap();
    e.db.revoke_keys_of_owner(
        m,
        T0,
        &AuditActor::account(a, crate::Role::Admin, "root"),
        None,
    )
    .await
    .unwrap();
    let _ = key;
    e.db.audit_entry(
        &AuditEntry {
            who: AuditActor::system(),
            event: "maintenance",
            detail: None,
            ip: None,
            target_id: None,
        },
        T0,
    )
    .await
    .unwrap();
    // No row written by the 2.0 code has an unknown kind; a `user` row always carries id and role;
    // `cli`/`system`/`anonymous` rows never do.
    assert_eq!(e.count("audit_log", "actor_kind IS NULL").await, 0);
    assert_eq!(
        e.count(
            "audit_log",
            "actor_kind = 'user' AND (actor_id IS NULL OR actor_role IS NULL)"
        )
        .await,
        0
    );
    assert_eq!(
        e.count(
            "audit_log",
            "actor_kind IN ('cli','system','anonymous') AND actor_id IS NOT NULL"
        )
        .await,
        0
    );
    // CLI rows say so and name the target.
    for event in [
        "user.reset_password",
        "user.reset_mfa",
        "user.enroll_token_issued",
    ] {
        let rows = e.audit(event).await;
        assert_eq!(rows.len(), 1, "{event}");
        assert_eq!(rows[0].kind.as_deref(), Some("cli"));
        assert_eq!(rows[0].target_id, Some(m));
    }
    let _ = b;
}

#[tokio::test]
async fn sec_033_authz_denied_is_audited_and_throttled() {
    let e = env().await;
    let _a = e.admin("root").await;
    let m = e.uploader("mem").await;
    let v = e.viewer("view").await;
    let mk = |who: i64, now: i64| {
        let db = e.db.clone();
        async move {
            db.audit_entry_throttled(
                &AuditEntry {
                    who: AuditActor::account(who, crate::Role::Viewer, "x"),
                    event: "authz_denied",
                    detail: Some("class=admin role=viewer"),
                    ip: Some("192.0.2.4"),
                    target_id: None,
                },
                60,
                now,
            )
            .await
            .unwrap()
        }
    };
    assert!(mk(v, T0).await);
    assert!(!mk(v, T0 + 10).await, "same account within a minute");
    assert!(!mk(v, T0 + 59).await);
    assert!(mk(m, T0 + 10).await, "another account is independent");
    assert!(mk(v, T0 + 61).await);
    let rows = e.audit("authz_denied").await;
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|r| r.detail.as_deref() == Some("class=admin role=viewer"))
    );
}

#[tokio::test]
async fn sec_067_audit_survives_account_deletion_unchanged() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mallory").await;
    let act = e.actor(a).await;
    // Rows that name the uploader as actor, as target and as snapshot.
    e.release(1, &Uploader::Account(m)).await.unwrap();
    // The uploader acts on its own key (an uploader edits no metadata since D40).
    let (key, _h) = e.key(m, 7).await;
    assert!(
        e.db.revoke_api_key_by(&e.actor(m).await, key, Some("192.0.2.1"), T0)
            .await
            .unwrap()
    );
    e.db.set_display_name(&act, m, Some("Mal"), None, T0 + 1)
        .await
        .unwrap();
    let all = |db: &crate::SqliteDb| {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (i64, Option<String>, Option<i64>, Option<String>, Option<i64>, String, Option<String>)>(
                "SELECT id, actor, actor_id, actor_kind, target_id, event, detail FROM audit_log ORDER BY id",
            )
            .fetch_all(db.writer())
            .await
            .unwrap()
        }
    };
    let before = all(&e.db).await;
    e.db.disable_account(&act, m, None, T0 + 2).await.unwrap();
    e.db.delete_account(&act, m, None, T0 + 3).await.unwrap();
    let after = all(&e.db).await;
    // Every earlier row is identical (snapshot text, id, kind, target), none rewritten or removed.
    assert_eq!(&after[..before.len()], &before[..]);
    assert!(
        after
            .iter()
            .any(|r| r.1.as_deref() == Some("mallory") && r.2 == Some(m))
    );
    assert!(after.len() > before.len());
}

#[tokio::test]
async fn sec_067_account_events_survive_log_purge() {
    let e = env().await;
    let day = 86_400;
    let now = T0 + 1000 * day;
    let w = e.db.writer();
    // One old row of every account-lifecycle event, and of the high-volume ones.
    for ev in crate::ACCOUNT_AUDIT_EVENTS {
        sqlx::query("INSERT INTO audit_log (ts, event, actor_kind) VALUES (?1, ?2, 'user')")
            .bind(now - 200 * day)
            .bind(ev)
            .execute(w)
            .await
            .unwrap();
    }
    for ev in [
        "authz_denied",
        "login.fail",
        "mfa.fail",
        "invite_redeem_failure",
        "account_throttled",
        "download",
    ] {
        // A failure row carries target_id too: retention is by event NAME, never by target_id (I-6).
        sqlx::query("INSERT INTO audit_log (ts, event, target_id) VALUES (?1, ?2, 1)")
            .bind(now - 200 * day)
            .bind(ev)
            .execute(w)
            .await
            .unwrap();
    }
    let n_account = i64::try_from(crate::ACCOUNT_AUDIT_EVENTS.len()).unwrap();
    // 90-day log retention, 365-day account retention: the 200-day-old lifecycle rows stay.
    let r = e.db.purge_logs_at(now, 90, 365).await.unwrap();
    assert_eq!(r.audit, 6);
    assert_eq!(e.count("audit_log", "1=1").await, n_account);
    // The convenience entry point has the same default.
    let r = e.db.purge_old_logs(now, 90).await.unwrap();
    assert_eq!(r.audit, 0);
    // Past the account retention they go too; 0 keeps them forever.
    assert_eq!(e.db.purge_logs_at(now, 90, 0).await.unwrap().audit, 0);
    assert_eq!(
        e.db.purge_logs_at(now + 200 * day, 90, 365)
            .await
            .unwrap()
            .audit,
        u64::try_from(n_account).unwrap()
    );
}

#[tokio::test]
async fn legacy_actor_text_is_attributed_by_event_class() {
    let e = env().await;
    // A 1.x account that happens to be called `cli` (legal before 2.0; renamed by raw SQL here because
    // new accounts cannot take reserved names).
    let a = e.admin("root").await;
    sqlx::query("UPDATE account SET username = 'cli' WHERE id = ?1")
        .bind(a)
        .execute(e.db.writer())
        .await
        .unwrap();
    // Completed-authentication events carry the username snapshot: a user, never the CLI.
    e.db.audit_event(T0, Some("cli"), "mfa.ok", Some("purpose=login"), None)
        .await
        .unwrap();
    // Failure rows: anonymous with the target.
    e.db.audit_event(T0, Some("cli"), "mfa.fail", None, None)
        .await
        .unwrap();
    // Web events carry `user:<id>`.
    e.db.audit_event(
        T0,
        Some(&format!("user:{a}")),
        "download",
        Some("release=1"),
        None,
    )
    .await
    .unwrap();
    // The CLI's own events carry the literal `cli`.
    e.db.audit_event(T0, Some("cli"), "cleanup_purge", Some("bucket=x"), None)
        .await
        .unwrap();
    // The API key failure actor is not an account.
    e.db.audit_event(T0, Some("api"), "apikey.use_failure", Some("unknown"), None)
        .await
        .unwrap();
    // Unknown shape: stays unattributed.
    e.db.audit_event(T0, Some("whoever"), "something_else", None, None)
        .await
        .unwrap();
    let k = |ev: &str| {
        let ev = ev.to_owned();
        let db = e.db.clone();
        async move {
            let r: (Option<String>, Option<i64>, Option<i64>) = sqlx::query_as(
                "SELECT actor_kind, actor_id, target_id FROM audit_log WHERE event = ?1",
            )
            .bind(ev)
            .fetch_one(db.writer())
            .await
            .unwrap();
            r
        }
    };
    assert_eq!(k("mfa.ok").await, (Some("user".into()), Some(a), None));
    assert_eq!(
        k("mfa.fail").await,
        (Some("anonymous".into()), None, Some(a))
    );
    assert_eq!(k("download").await, (Some("user".into()), Some(a), None));
    assert_eq!(k("cleanup_purge").await, (Some("cli".into()), None, None));
    assert_eq!(
        k("apikey.use_failure").await,
        (Some("anonymous".into()), None, None)
    );
    assert_eq!(k("something_else").await, (None, None, None));
}

#[tokio::test]
async fn legacy_create_api_key_is_owned_by_the_oldest_enabled_admin() {
    let e = env().await;
    let a = e.admin("root").await;
    let _m = e.uploader("mem").await;
    let r =
        e.db.create_api_key(
            crate::NewApiKey {
                label: "ci",
                prefix: "abcdef",
                key_hash: &[5; 32],
                rate_per_min: None,
            },
            10,
            T0,
            crate::Actor {
                name: "cli",
                ip: None,
            },
        )
        .await
        .unwrap();
    assert!(matches!(r, crate::CreateKey::Created(_)));
    let k = e.db.find_api_key(&[5; 32]).await.unwrap().unwrap();
    assert_eq!(k.owner_id, Some(a));
    assert!(k.may_upload());
    let rows = e.audit("apikey.create").await;
    assert_eq!(rows[0].kind.as_deref(), Some("cli"));
    // sessions of the owner are untouched by key operations.
    e.db.insert_session(&sess(a, 1, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let _: &Env = &e;
}
