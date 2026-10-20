//! T119 store tests: bulk edits are all-or-nothing, de-duplicated, capped, uniform for hidden and
//! unknown ids, re-validate the actor and audit every release like the single edit.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::assert_is_empty
)]

use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::pg_testkit::{T0, env, sess};
use crate::{AccountError, CategorySource, MAX_BULK_IDS, SessionStage, StoreError, Uploader};

#[tokio::test]
async fn sec_060_bulk_metadata_requires_current_session() {
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
    let first = e.release(1, &Uploader::Unattributed).await.unwrap();
    let second = e.release(2, &Uploader::Unattributed).await.unwrap();
    let before = [
        e.db.get_release(first).await.unwrap().unwrap(),
        e.db.get_release(second).await.unwrap().unwrap(),
    ];
    let outbox = e.count("search_outbox", "1 = 1").await;
    let audit = e.count("audit_log", "1 = 1").await;
    for hash in [10, 11, 12, 13] {
        actor.session = Some([hash; 32]);
        let results = [
            e.db.bulk_set_category_as(&actor, &[first, second], 5040, &[], None, T0 + 1)
                .await
                .map(|_| ()),
            e.db.bulk_set_source_label_as(&actor, &[first, second], "changed", &[], None, T0 + 1)
                .await
                .map(|_| ()),
        ];
        for result in results {
            assert!(
                matches!(result, Err(StoreError::Account(AccountError::Forbidden))),
                "session {hash}: {result:?}"
            );
        }
        assert_eq!(e.db.get_release(first).await.unwrap().unwrap(), before[0]);
        assert_eq!(e.db.get_release(second).await.unwrap().unwrap(), before[1]);
        assert_eq!(e.count("search_outbox", "1 = 1").await, outbox);
        assert_eq!(e.count("audit_log", "1 = 1").await, audit);
    }
    actor.session = Some([11; 32]);
    assert_eq!(
        e.db.bulk_set_category_as(&actor, &[first, second], 5040, &[], None, T0)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        e.db.bulk_set_source_label_as(&actor, &[first, second], "allowed", &[], None, T0)
            .await
            .unwrap()
            .0,
        2
    );
    actor.session = None;
    assert_eq!(
        e.db.bulk_set_category_as(&actor, &[first, second], 8010, &[], None, T0 + 1)
            .await
            .unwrap(),
        2
    );
}

const HIDDEN: [u16; 1] = [6000];

async fn cat_of(db: &PgDb, id: i64) -> (u32, CategorySource, Option<String>) {
    let r = db.get_release(id).await.unwrap().unwrap();
    (r.category_id, r.category_source, r.source_label)
}

/// Moves a release through the store (v3: a raw `UPDATE` would bypass `category_stats` and the outbox).
async fn move_to(db: &PgDb, id: i64, category: i64) {
    db.set_category(id, u32::try_from(category).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn sec_067_bulk_edits_name_the_actor_with_old_and_new_values() {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    // Releases added by the UPLOADER; only the admin edits them (D26 c: any release; D40).
    let r1 = e.release(1, &Uploader::Account(m)).await.unwrap();
    let r2 = e.release(2, &Uploader::Account(m)).await.unwrap();
    move_to(&e.db, r2, 2040).await;
    let am = e.actor(a).await;
    let n =
        e.db.bulk_set_category_as(&am, &[r2, r1, r2, r1], 5040, &[], Some("192.0.2.9"), T0)
            .await
            .unwrap();
    assert_eq!(n, 2);
    for id in [r1, r2] {
        let (c, s, _) = cat_of(&e.db, id).await;
        assert_eq!((c, s), (5040, CategorySource::Manual));
    }
    // One row per release in the single-edit format, plus one summary row; all name the admin.
    let rows = e.audit("category_override").await;
    let d: Vec<_> = rows.iter().map(|r| r.detail.clone().unwrap()).collect();
    assert_eq!(
        d,
        vec![
            format!("release={r1} old=8010 new=5040"),
            format!("release={r2} old=2040 new=5040"),
        ]
    );
    let sum = e.audit("bulk_edit_category").await;
    assert_eq!(sum.len(), 1);
    assert_eq!(sum[0].detail.as_deref(), Some("count=2 new=5040"));
    for r in rows.iter().chain(sum.iter()) {
        assert_eq!(
            (r.kind.as_deref(), r.actor_id, r.role.as_deref()),
            (Some("user"), Some(a), Some("admin"))
        );
    }
    // Source label: JSON old/new per release (hostile text serialized), summary without text.
    let (n, stored) =
        e.db.bulk_set_source_label_as(&am, &[r1, r2], "  a \"quoted\" <b>x</b> ", &[], None, T0)
            .await
            .unwrap();
    assert_eq!(n, 2);
    let stored = stored.unwrap();
    let rows = e.audit("source_label_edit").await;
    assert_eq!(rows.len(), 2);
    for (row, id) in rows.iter().zip([r1, r2]) {
        let v: serde_json::Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
        assert_eq!(v["release"], id);
        assert_eq!(v["old"], "orig");
        assert_eq!(v["new"], stored.as_str());
        assert_eq!(row.actor_id, Some(a));
    }
    let sum = e.audit("bulk_edit_source").await;
    assert_eq!(sum.len(), 1);
    assert_eq!(sum[0].detail.as_deref(), Some("count=2"));
    // Clearing: the new value is null and the stored label is gone.
    let (_, none) =
        e.db.bulk_set_source_label_as(&am, &[r1, r2], "   ", &[], None, T0 + 1)
            .await
            .unwrap();
    assert_eq!(none, None);
    assert_eq!(cat_of(&e.db, r1).await.2, None);
    let rows = e.audit("source_label_edit").await;
    let v: serde_json::Value = serde_json::from_str(rows[3].detail.as_deref().unwrap()).unwrap();
    assert!(v["new"].is_null());
}

#[tokio::test]
async fn sec_060_bulk_edit_refuses_a_viewer_before_reading_anything() {
    let e = env().await;
    let a = e.admin("root").await;
    let v = e.viewer("view").await;
    let up = e.uploader("up").await;
    let r1 = e.release(1, &Uploader::Account(a)).await.unwrap();
    // A viewer and, since D40, an uploader (even on its own upload) are refused.
    let own = e.release(2, &Uploader::Account(up)).await.unwrap();
    for (who, ids) in [
        (v, vec![r1]),
        (v, vec![r1, 99_999]),
        (up, vec![own]),
        (up, vec![own, 99_999]),
    ] {
        let mut av = e.actor(who).await;
        // The role claimed by the struct is irrelevant: the database role decides.
        av.role = crate::Role::Admin;
        // Even an unknown id is answered with the refusal (the actor check comes first).
        assert!(matches!(
            e.db.bulk_set_category_as(&av, &ids, 5040, &[], None, T0)
                .await,
            Err(StoreError::Account(AccountError::Forbidden))
        ));
        assert!(matches!(
            e.db.bulk_set_source_label_as(&av, &ids, "x", &[], None, T0)
                .await,
            Err(StoreError::Account(AccountError::Forbidden))
        ));
    }
    assert_eq!(cat_of(&e.db, r1).await.0, 8010);
    assert_eq!(e.count("audit_log", "event LIKE 'bulk_%'").await, 0);
    assert_eq!(e.count("audit_log", "event = 'category_override'").await, 0);
}

#[tokio::test]
async fn sec_034_bulk_edit_is_all_or_nothing_for_unknown_and_hidden_ids() {
    let e = env().await;
    let root = e.admin("root").await;
    let am = e.actor(root).await;
    let a = e.release(1, &Uploader::Unattributed).await.unwrap();
    let hidden = e.release(2, &Uploader::Unattributed).await.unwrap();
    move_to(&e.db, hidden, 6000).await;
    for ids in [vec![a, a + 1000], vec![a, hidden]] {
        let r =
            e.db.bulk_set_category_as(&am, &ids, 5040, &HIDDEN, None, T0)
                .await;
        assert!(matches!(r, Err(StoreError::NotFound)), "{r:?}");
        let r =
            e.db.bulk_set_source_label_as(&am, &ids, "x", &HIDDEN, None, T0)
                .await;
        assert!(matches!(r, Err(StoreError::NotFound)), "{r:?}");
        let r = e.db.bulk_items(&ids, &HIDDEN).await;
        assert!(matches!(r, Err(StoreError::NotFound)), "{r:?}");
    }
    // Nothing changed, nothing audited.
    assert_eq!(
        cat_of(&e.db, a).await,
        (8010, CategorySource::Fallback, Some("orig".to_owned()))
    );
    assert_eq!(cat_of(&e.db, hidden).await.0, 6000);
    assert_eq!(e.count("audit_log", "event LIKE 'bulk_%'").await, 0);
    assert_eq!(e.count("audit_log", "event = 'category_override'").await, 0);
    assert_eq!(e.count("audit_log", "event = 'source_label_edit'").await, 0);
    // Without the hiding rule the same selection works.
    assert_eq!(
        e.db.bulk_set_category_as(&am, &[a, hidden], 5040, &[], None, T0)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn bulk_category_refuses_unknown_and_hidden_targets_without_effect() {
    let e = env().await;
    let root = e.admin("root").await;
    let am = e.actor(root).await;
    let a = e.release(1, &Uploader::Unattributed).await.unwrap();
    for (target, hidden) in [(999_999_u32, vec![]), (6000, vec![6000_u16])] {
        let r =
            e.db.bulk_set_category_as(&am, &[a], target, &hidden, None, T0)
                .await;
        assert!(matches!(r, Err(StoreError::UnknownCategory)), "{r:?}");
    }
    assert_eq!(cat_of(&e.db, a).await.0, 8010);
    assert_eq!(e.count("audit_log", "event LIKE 'bulk_%'").await, 0);
}

#[tokio::test]
async fn bulk_selection_is_capped_and_ids_must_be_positive() {
    let e = env().await;
    let root = e.admin("root").await;
    let am = e.actor(root).await;
    let a = e.release(1, &Uploader::Unattributed).await.unwrap();
    let cap = i64::try_from(MAX_BULK_IDS).unwrap();
    let many: Vec<i64> = (1..=cap + 1).collect();
    assert!(matches!(
        e.db.bulk_set_category_as(&am, &many, 5040, &[], None, T0)
            .await,
        Err(StoreError::NotFound)
    ));
    // A full selection is allowed even when most ids do not exist: still not found, uniformly.
    let full: Vec<i64> = (1..=cap).collect();
    assert!(matches!(
        e.db.bulk_items(&full, &[]).await,
        Err(StoreError::NotFound)
    ));
    for bad in [vec![], vec![0], vec![a, -1]] {
        assert!(matches!(
            e.db.bulk_items(&bad, &[]).await,
            Err(StoreError::NotFound)
        ));
    }
    // Duplicates count once towards the cap.
    let dup = vec![a; MAX_BULK_IDS * 3];
    let items = e.db.bulk_items(&dup, &[]).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, a);
    assert_eq!(items[0].source_label.as_deref(), Some("orig"));
}

#[tokio::test]
async fn sec_050_trash_release_checked_as_refuses_a_reused_rowid() {
    let e = env().await;
    let adm = e.admin("root").await;
    let act = e.actor(adm).await;
    let id = e.release(1, &Uploader::Unattributed).await.unwrap();
    let old = e.db.get_release(id).await.unwrap().unwrap().sha256;
    // The old release is deleted elsewhere and a different NZB comes back under the same id. v3 never reuses ids
    // from its sequence; restoring an older backup can (DATA_MODEL v3 section 1), so the restore is simulated by the
    // superuser inserting the other NZB with that id.
    e.db.delete_release(id).await.unwrap();
    e.superuser_exec(&format!(
        "INSERT INTO release (id, sha256, title, category_id, ingested_at, total_bytes, file_count, segment_count, \
         nzb_size_bytes) VALUES ({id}, decode(repeat('02', 32), 'hex'), 'other', 8010, 1, 0, 0, 0, 0); \
         UPDATE category_stats SET releases = releases + 1 WHERE category_id = 8010"
    ))
    .await;
    let new = e.db.get_release(id).await.unwrap().unwrap().sha256;
    let r =
        e.db.trash_release_checked_as(&act, id, &old, T0, None)
            .await;
    assert!(matches!(r, Err(StoreError::NotFound)), "{r:?}");
    assert!(e.db.get_release(id).await.unwrap().is_some());
    assert!(e.db.list_trash(10).await.unwrap().is_empty());
    assert_eq!(e.count("audit_log", "event = 'release_delete'").await, 0);
    // An uploader is refused before the digest is even compared.
    let m = e.uploader("mem").await;
    let am = e.actor(m).await;
    assert!(matches!(
        e.db.trash_release_checked_as(&am, id, &new, T0, None).await,
        Err(StoreError::Account(AccountError::Forbidden))
    ));
    // The matching digest moves it, attributed to the admin.
    let t =
        e.db.trash_release_checked_as(&act, id, &new, T0, None)
            .await
            .unwrap();
    assert_eq!(t.sha256, new);
    assert!(e.db.get_release(id).await.unwrap().is_none());
    let rows = e.audit("release_delete").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, Some(adm));
}
