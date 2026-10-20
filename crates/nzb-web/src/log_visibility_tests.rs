//! Category privacy across ingest-log deletion and purge.
#![allow(clippy::unwrap_used, clippy::too_many_lines, clippy::indexing_slicing)]
use std::sync::Arc;

use crate::{
    AuthConfig, AuthState, WebConfig,
    auth::{ClientMeta, ManualWallClock},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, header},
};
use nzb_core::{Analysis, ReleaseFlags, Sha256, Taxonomy};
use nzb_store::{
    CategorySource, IngestLogEntry, LogOutcome, LogSource, NewAccount, NewRelease, Role,
    SceneColumns, SessionStage, prelude::*, test_backend::TestStore,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: i64 = 1_700_000_000;
const HIDDEN: &str = "audit-hidden-dummy.nzb";
const VISIBLE: &str = "audit-visible-dummy.nzb";

fn analysis(n: u8, title: &str) -> Analysis {
    Analysis {
        sha256: Sha256([n; 32]),
        name_candidates: vec![],
        meta_name_candidates: 0,
        title: title.to_owned(),
        poster: None,
        posted_at: None,
        total_bytes: 0,
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

fn release<'a>(a: &'a Analysis, category_id: u32, name: &'a str) -> NewRelease<'a> {
    NewRelease {
        analysis: a,
        nzb_size_bytes: 1,
        source_name: Some(name),
        source_label: None,
        category_id,
        category_source: CategorySource::Fallback,
        meta_json: None,
        scene: SceneColumns::default(),
        ingested_at: NOW - 10,
    }
}

fn entry(ts: i64, n: u8, name: &str, outcome: LogOutcome) -> IngestLogEntry<'_> {
    IngestLogEntry {
        ts,
        source: LogSource::Watch,
        api_key_id: None,
        source_name: Some(name),
        sha256: Some(Sha256([n; 32])),
        outcome,
        error_code: None,
        detail: None,
    }
}

async fn cookie(auth: &AuthState, uid: i64) -> String {
    auth.start_session(uid, SessionStage::Active, &ClientMeta::default(), None)
        .await
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn observation(test: &TestStore, app: &Router, cookie: &str) -> Value {
    let names: Vec<String> = test
        .store
        .list_ingest_log_excluding(6, &[6000])
        .await
        .unwrap()
        .iter()
        .filter_map(|r| r.source_name.clone())
        .collect();
    let response = app
        .clone()
        .oneshot(
            Request::get("/")
                .header(header::HOST, "localhost")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        !html.contains("Full ingest log"),
        "viewer must not get operator link"
    );
    assert!(
        html.contains(VISIBLE),
        "visible control stays in ordinary viewer response"
    );
    json!({"returned_names": names, "http_status": status,
        "html_contains_hidden_dummy": html.contains(HIDDEN),
        "html_contains_visible_dummy": html.contains(VISIBLE),
        "viewer_has_operator_log_link": html.contains("Full ingest log"),
        "live_release_rows": test.i64("SELECT count(*) FROM release").await,
        "trash_rows": test.i64("SELECT count(*) FROM release_trash").await})
}

#[tokio::test]
async fn hidden_ingest_names_stay_hidden_after_trash_and_purge() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let test = TestStore::open(dir).await;
    let cfg = AuthConfig {
        insecure_cookies: true,
        multi_user: true,
        ..AuthConfig::default()
    };
    let admin_id = test
        .store
        .create_account_operator(
            &NewAccount {
                username: "audit-admin",
                password_hash: "unused-test-hash",
                role: Some(Role::Admin),
            },
            cfg.account_policy(),
            NOW,
        )
        .await
        .unwrap();
    let viewer_id = test
        .store
        .create_account_operator(
            &NewAccount {
                username: "audit-viewer",
                password_hash: "unused-test-hash",
                role: Some(Role::Viewer),
            },
            cfg.account_policy(),
            NOW,
        )
        .await
        .unwrap();
    let admin_auth = AuthState::new(
        test.store.clone(),
        cfg.clone(),
        Arc::new(ManualWallClock::new(NOW)),
    )
    .await
    .unwrap();
    let admin_cookie = cookie(&admin_auth, admin_id).await;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, admin_cookie.parse().unwrap());
    let admin = admin_auth.peek_session(&headers).await.unwrap().unwrap();
    assert_eq!(admin.role, Role::Admin);

    let hidden = analysis(11, "Audit hidden dummy");
    let hidden_id = test
        .store
        .insert_release_logged(
            &release(&hidden, 6000, HIDDEN),
            &entry(NOW - 4, 11, HIDDEN, LogOutcome::Ok),
        )
        .await
        .unwrap();
    test.store
        .log_ingest(&entry(NOW - 3, 11, HIDDEN, LogOutcome::Duplicate), None)
        .await
        .unwrap();
    let visible = analysis(22, "Audit visible dummy");
    test.store
        .insert_release_logged(
            &release(&visible, 8010, VISIBLE),
            &entry(NOW - 2, 22, VISIBLE, LogOutcome::Ok),
        )
        .await
        .unwrap();

    // Only the viewer configuration excludes 6000. The admin still has a legal
    // deletion path; no ability to delete a hidden item is attributed to viewer.
    let viewer_auth = AuthState::new(
        test.store.clone(),
        AuthConfig {
            hidden_categories: Arc::from([6000u16]),
            ..cfg
        },
        Arc::new(ManualWallClock::new(NOW)),
    )
    .await
    .unwrap();
    let viewer_cookie = cookie(&viewer_auth, viewer_id).await;
    let mut viewer_headers = HeaderMap::new();
    viewer_headers.insert(header::COOKIE, viewer_cookie.parse().unwrap());
    let viewer = viewer_auth
        .peek_session(&viewer_headers)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(viewer.role, Role::Viewer);
    assert!(viewer.hides_category(6000));
    let search = nzb_search::testing::SettlingIndex::open(&test.store, &dir.join("index")).await;
    let routes = crate::index::routes_with_clock(
        test.store.clone(),
        search,
        Arc::new(Taxonomy::builtin().unwrap()),
        Arc::new(ManualWallClock::new(NOW)),
    );
    let app = crate::router_with_auth(
        &WebConfig {
            insecure_cookies: true,
            ..WebConfig::default()
        },
        &viewer_auth,
        routes,
    );

    let live = observation(&test, &app, &viewer_cookie).await;
    assert_eq!(live["returned_names"], json!([VISIBLE]));
    assert_eq!(live["html_contains_hidden_dummy"], false);

    let trash = test
        .store
        .trash_release_checked_as(&admin.actor(), hidden_id, &hidden.sha256, NOW, None)
        .await
        .unwrap();
    assert_eq!(trash.category_id, 6000);
    let trashed = observation(&test, &app, &viewer_cookie).await;

    // Purge only this dummy trash metadata via the repository's public operation.
    // There are no production blobs or files in this fixture.
    assert!(test.store.forget_trash(trash.id).await.unwrap());
    let purged = observation(&test, &app, &viewer_cookie).await;
    assert_eq!(trashed["html_contains_hidden_dummy"], false);
    assert_eq!(purged["html_contains_hidden_dummy"], false);
    assert_eq!(trashed["returned_names"], json!([VISIBLE]));
    assert_eq!(purged["returned_names"], json!([VISIBLE]));
    // The operator's retained history remains intact after the privacy-filtered view drops it.
    assert_eq!(
        test.store
            .list_ingest_log_excluding(10, &[])
            .await
            .unwrap()
            .len(),
        3
    );

    // A still-classified visible trash entry may be shown, but after purge its old
    // category is unknowable. Filtering must not guess that orphaned metadata is public.
    let visible_id = test
        .store
        .get_release_by_sha(&visible.sha256.to_hex())
        .await
        .unwrap()
        .unwrap()
        .id;
    let visible_trash = test
        .store
        .trash_release_checked_as(&admin.actor(), visible_id, &visible.sha256, NOW, None)
        .await
        .unwrap();
    assert_eq!(
        test.store
            .list_ingest_log_excluding(10, &[6000])
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(test.store.forget_trash(visible_trash.id).await.unwrap());
    assert_eq!(
        test.store
            .list_ingest_log_excluding(10, &[6000])
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        test.store
            .list_ingest_log_excluding(10, &[])
            .await
            .unwrap()
            .len(),
        3
    );
    test.store.close().await;
}
