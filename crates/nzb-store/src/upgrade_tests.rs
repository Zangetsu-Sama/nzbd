//! A populated 3.1 library keeps its data through the saved-search/page-size migrations, then the current startup
//! path refuses the roles migration with `FRESH_DATA_REQUIRED` (D40). Each migration commits independently: a refusal
//! must preserve both the original library and the earlier successful migrations, including on a retry. These tests
//! exercise that contract, not an unsupported populated-library upgrade across the roles boundary.
//!
//! Fixtures use admin/viewer accounts for current store API checks and a raw historical `member` account for legacy
//! data preservation. The current role parser deliberately does not accept `member`; no production bypass is used.
//! SQLite inspection after refusal is read-only, before its test-only historical opener exercises saved searches.
//! Postgres app pools permit inspection, but readiness must continue refusing the database. Empty-library roles
//! migration is covered by the T134 backend tests.
//!
//! The 3.1 schema is the compiled-in migrator filtered to the versions present at tag `v3.1.0` (not SQL files copied
//! into fixtures): one source of truth for the migration text. What the filter alone could not catch, an edit of a
//! released migration file (a real 3.1 database would then fail the sqlx checksum check), is pinned by
//! [`released_3_1_migrations_are_unchanged`] with the SHA-384 checksums of the files at `v3.1.0`.
//!
//! A 3.1 binary refusing the 3.2 schema is covered elsewhere: `startup_tests::
//! t090_an_unknown_ledger_entry_is_rejected_before_any_check_or_migration` (SQLite `VersionMissing`) and
//! `pg_tests::readiness_refuses_pending_migrations_newer_schema_and_pending_restore` (Postgres `SCHEMA_NEWER`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::{Arc, Mutex};

use crate::acct_testkit::{PHC, POLICY, T0, analysis, sess};
use crate::pg::testing::TestDb;
use crate::pg::{MIGRATOR, Readiness};
use crate::repo::{AccountRepo as _, AuditRepo as _, LibraryRepo as _, OpsRepo as _};
use crate::{
    AnchorVerdict, AuditAnchor, CategorySource, DbAnchor, DbConfig, NewAccount, NewRelease,
    OpenEvent, Role, SceneColumns, SessionStage, SqliteDb, StartupCheck, Store, Theme, Uploader,
    UserPrefs, read_anchor, write_anchor,
};

/// Last SQLite migration of 3.1 (`v3-sqlite/0001_v3_baseline`).
const SQLITE_3_1_LAST: i64 = 1;
/// Last Postgres migration of 3.1 (`v3/0007_library_identity`).
const PG_3_1_LAST: i64 = 7;
/// The migration 3.2 adds on SQLite.
const SQLITE_3_2_SAVED_SEARCH: i64 = 2;
/// The migration 3.2 adds on Postgres.
const PG_3_2_SAVED_SEARCH: i64 = 8;
/// Last SQLite migration before the fresh-data roles boundary.
const SQLITE_PAGE_SIZE: i64 = 3;
/// Last Postgres migration before the fresh-data roles boundary.
const PG_PAGE_SIZE: i64 = 9;
const SQLITE_ROLES: i64 = 4;
const PG_ROLES: i64 = 10;
/// The 0.6 NFO migration on Postgres (`v3/0011_release_nfo`), pending after the roles boundary.
const PG_RELEASE_NFO: i64 = 11;

/// SHA-384 (the sqlx checksum) of each migration file at tag `v3.1.0`.
const SQLITE_3_1_CHECKSUMS: [(i64, &str); 1] = [(
    1,
    "8780b893d4fec42d2a15f561f38199640aa2cb802b1825c4e7a375ad04cfe9aa996bcb0e9bf12709e8de593bb6b2dc2c",
)];
const PG_3_1_CHECKSUMS: [(i64, &str); 6] = [
    (
        2,
        "7155bb1a3d8c329a46d68833e02699c7c3d149cc5711b7e54d65b556c8bc509065050625b2561d1facb6cb65d8db1c18",
    ),
    (
        3,
        "95d3b0595a84502c09b04e3dbfe407c9dff851c72f8ce689f9820e0af83cb96e14f0f505b7eff60efd56cdf519199242",
    ),
    (
        4,
        "be242fbc674e7a1359f7e93625b60114d089e2cc0928ce44e1965dee9b93deea5eab027d6589833c30be4a28096ca29a",
    ),
    (
        5,
        "647b887867b37f34a4b660230d2830894bcb3385e0b2499efce8ab6c09cc19a0514e008beeeb1ec3d4bcccbf56274bdc",
    ),
    (
        6,
        "b27d32fd960fe7157e487dfc7373e1c58c1a52c2b78e3befbe2843ec791e3fa44f67da3da1c3c619f95164cd1265ecee",
    ),
    (
        7,
        "41bbe9ff0de3296aa8318607494dc24ee75ab61191f79f7c700c1b9a225ef25327a7b980b29a2afb3b7a60b7d035f0e0",
    ),
];

/// Releases of the fixture: `(n, category)`.
const RELEASES: [(u8, u32); 3] = [(1, 2040), (2, 5040), (3, 8010)];
/// Session id hash byte of the viewer's session.
const SESSION: u8 = 7;
const LATER: i64 = T0 + 3_000;

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// A released migration file is never edited: a 3.1 database records these checksums, and sqlx refuses to run
/// against a ledger whose checksums differ from the compiled-in files (the filtered 3.1 migrator of the upgrade tests
/// shares the compiled text, so it could not notice such an edit by itself).
#[test]
fn released_3_1_migrations_are_unchanged() {
    let sqlite = sqlx::migrate!("../../migrations/v3-sqlite");
    for (set, pinned, last) in [
        (&sqlite, &SQLITE_3_1_CHECKSUMS[..], SQLITE_3_1_LAST),
        (&MIGRATOR, &PG_3_1_CHECKSUMS[..], PG_3_1_LAST),
    ] {
        let released: Vec<(i64, String)> = set
            .iter()
            .filter(|m| m.version <= last)
            .map(|m| (m.version, hex(&m.checksum)))
            .collect();
        let expected: Vec<(i64, String)> =
            pinned.iter().map(|(v, h)| (*v, (*h).to_owned())).collect();
        assert_eq!(released, expected);
    }
}

/// What the 3.1 library held before the upgrade.
#[derive(Debug)]
struct Before {
    admin: i64,
    viewer: i64,
    legacy_member: LegacyMember,
    role_schema: Vec<(String, String)>,
    categories: Vec<(i64, Option<i64>, String)>,
    releases: Vec<i64>,
    audit: AuditAnchor,
    anchor: DbAnchor,
    counts: Vec<(&'static str, i64)>,
}

/// The current Role type cannot represent the historical value; preserve its stored fields without decoding it.
type LegacyMember = (i64, String, String, String, i64, i64);

async fn legacy_member(store: &Store) -> LegacyMember {
    let sql = "SELECT id, username, password_hash, role, created_at, password_changed_at \
               FROM account WHERE username = 'carol'";
    match store {
        Store::Sqlite(db) => sqlx::query_as(sql).fetch_one(db.readers()).await.unwrap(),
        Store::Postgres(db) => sqlx::query_as(sql).fetch_one(db.web()).await.unwrap(),
    }
}

/// Tables/constraints that the rejected roles migration would rebuild or replace.
async fn role_schema(store: &Store) -> Vec<(String, String)> {
    let rows: Vec<(String, String)> = match store {
        Store::Sqlite(db) => sqlx::query_as(
            "SELECT name, sql FROM sqlite_master \
             WHERE type = 'table' AND name IN ('account', 'invite', 'audit_log') ORDER BY name",
        )
        .fetch_all(db.readers())
        .await
        .unwrap(),
        Store::Postgres(db) => sqlx::query_as(
            "SELECT c.relname::text || '.' || k.conname::text, pg_get_constraintdef(k.oid) \
             FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'nzbd' AND k.conname IN \
             ('account_role_check', 'invite_role_check', 'audit_log_actor_role_check') \
             ORDER BY c.relname, k.conname",
        )
        .fetch_all(db.web())
        .await
        .unwrap(),
    };
    assert_eq!(rows.len(), 3);
    rows
}

/// Preserve taxonomy fields too: the SQLite opener's seed upsert could otherwise hide changes to them.
async fn categories(store: &Store) -> Vec<(i64, Option<i64>, String)> {
    let sql =
        "SELECT CAST(id AS BIGINT), CAST(parent_id AS BIGINT), name FROM category ORDER BY id";
    match store {
        Store::Sqlite(db) => sqlx::query_as(sql).fetch_all(db.readers()).await.unwrap(),
        Store::Postgres(db) => sqlx::query_as(sql).fetch_all(db.web()).await.unwrap(),
    }
}

/// Tables whose row counts must survive the upgrade unchanged.
const TABLES: [&str; 7] = [
    "account",
    "user_pref",
    "release",
    "session",
    "audit_log",
    "category",
    "search_outbox",
];

async fn count(store: &Store, table: &str) -> i64 {
    // Test-only: `table` is one of the literals above.
    let sql = format!("SELECT count(*) FROM {table}");
    match store {
        Store::Sqlite(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(db.readers())
            .await
            .unwrap(),
        Store::Postgres(db) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(db.web())
            .await
            .unwrap(),
    }
}

async fn counts(store: &Store) -> Vec<(&'static str, i64)> {
    let mut v = Vec::new();
    for t in TABLES {
        v.push((t, count(store, t).await));
    }
    v
}

/// Populate the historical schema with three accounts, three releases, preferences, both audit classes and a session.
/// The raw legacy member models stored 3.1 data; admin/viewer roles also exist in 3.1 and remain usable by today's API.
async fn fill_3_1(store: &Store) -> Before {
    let admin = store
        .create_account_operator(
            &NewAccount {
                username: "alice",
                password_hash: PHC,
                role: Some(Role::Admin),
            },
            POLICY,
            T0,
        )
        .await
        .unwrap();
    let viewer = store
        .create_account_operator(
            &NewAccount {
                username: "bob",
                password_hash: PHC,
                role: Some(Role::Viewer),
            },
            POLICY,
            T0 + 1,
        )
        .await
        .unwrap();
    match store {
        Store::Sqlite(db) => {
            sqlx::query(
                "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
                 VALUES ('carol', ?1, 'member', ?2, ?2)",
            )
            .bind(PHC)
            .bind(T0 + 2)
            .execute(db.writer())
            .await
            .unwrap();
        }
        Store::Postgres(db) => {
            sqlx::query(
                "INSERT INTO account (username, password_hash, role, created_at, password_changed_at) \
                 VALUES ('carol', $1, 'member', $2, $2)",
            )
            .bind(PHC)
            .bind(T0 + 2)
            .execute(db.web())
            .await
            .unwrap();
        }
    }
    let legacy_member = legacy_member(store).await;
    assert_eq!(
        (
            &*legacy_member.1,
            &*legacy_member.2,
            &*legacy_member.3,
            legacy_member.4,
            legacy_member.5
        ),
        ("carol", PHC, "member", T0 + 2, T0 + 2)
    );
    // The 3.1-shaped preference row, written as 3.1 stored it: this binary's `set_user_prefs` also writes the T133 page
    // size columns (T133), which a 3.1 schema does not have yet.
    let sql = format!(
        "INSERT INTO user_pref (account_id, hide_xxx, theme, updated_at) VALUES ({viewer}, true, 'dark', {})",
        T0 + 2
    );
    match store {
        Store::Sqlite(db) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(db.writer())
                .await
                .unwrap();
        }
        Store::Postgres(db) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(db.web())
                .await
                .unwrap();
        }
    }
    let mut releases = Vec::new();
    for (n, category) in RELEASES {
        let a = analysis(n);
        let uploader = if n == 1 {
            Uploader::Account(admin)
        } else {
            Uploader::Unattributed
        };
        let id = store
            .insert_release_as(
                &NewRelease {
                    analysis: &a,
                    nzb_size_bytes: 1,
                    source_name: None,
                    source_label: Some("orig"),
                    category_id: category,
                    category_source: CategorySource::Fallback,
                    meta_json: None,
                    scene: SceneColumns::default(),
                    ingested_at: T0 + i64::from(n),
                },
                None,
                &uploader,
            )
            .await
            .unwrap();
        releases.push(id);
    }
    store
        .audit_event(
            T0 + 10,
            Some("user:2"),
            "download",
            Some("release=1"),
            Some("192.0.2.1"),
        )
        .await
        .unwrap();
    store
        .insert_session(&sess(viewer, SESSION, SessionStage::Active, T0 + 20), 5)
        .await
        .unwrap();

    // The 3.1 chain is whole before anything changes.
    let report = store.audit_walk(None, &mut |_| {}).await.unwrap();
    assert!(report.is_ok(), "{report:?}");
    let audit = store.audit_anchor().await.unwrap();
    // API account creation and the library event cover both audit classes. Raw historical rows write no audit entry.
    assert!(audit.rows >= 3, "{audit:?}");
    Before {
        admin,
        viewer,
        legacy_member,
        role_schema: role_schema(store).await,
        categories: categories(store).await,
        releases,
        audit,
        // What a 3.1 `serve` wrote to paths.state/db-anchor.json.
        anchor: store.capture_anchor().await.unwrap(),
        counts: counts(store).await,
    }
}

/// Historical migration/refusal preserves all original data, the identity and restore checks.
async fn verify_preserved(store: &Store, before: &Before, state_dir: &std::path::Path) {
    // Row counts and field values.
    assert_eq!(counts(store).await, before.counts);
    assert_eq!(legacy_member(store).await, before.legacy_member);
    assert_eq!(role_schema(store).await, before.role_schema);
    assert_eq!(categories(store).await, before.categories);
    let admin = store.get_account(before.admin).await.unwrap().unwrap();
    assert_eq!(
        (admin.username.as_str(), admin.role),
        ("alice", Role::Admin)
    );
    let viewer = store.get_account(before.viewer).await.unwrap().unwrap();
    assert_eq!(
        (viewer.username.as_str(), viewer.role, viewer.created_at),
        ("bob", Role::Viewer, T0 + 1)
    );
    for (id, (n, category)) in before.releases.iter().zip(RELEASES) {
        let r = store.get_release(*id).await.unwrap().unwrap();
        assert_eq!(r.title, format!("release {n}"));
        assert_eq!(r.category_id, category);
        assert_eq!(r.sha256, analysis(n).sha256);
    }
    let first = store
        .release_attribution(before.releases[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.added_by, Some(before.admin));
    // The stored session/preferences still decode; this inspection does not bypass the production readiness gate.
    let actor = store
        .session_actor(&[SESSION; 32], T0 + 30)
        .await
        .unwrap()
        .expect("the 3.1 session survives migration refusal");
    assert_eq!(actor.user_id, before.viewer);
    assert_eq!(actor.role, Role::Viewer);
    assert_eq!(
        actor.prefs,
        UserPrefs {
            hide_xxx: true,
            theme: Theme::Dark,
            ..UserPrefs::default()
        }
    );

    // The audit chain verifies and is the same chain (the migration writes no audit row).
    let report = store.audit_walk(None, &mut |_| {}).await.unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(store.audit_anchor().await.unwrap(), before.audit);
    assert!(store.audit_chain_quick().await.unwrap().consistent);

    // Library identity and restore detection: the anchor 3.1 wrote (also through the file) still matches, nothing
    // asks for a restore-finish, and a restore-finish would find exactly the 3.1 state.
    let file = state_dir.join("db-anchor.json");
    write_anchor(&file, &before.anchor).unwrap();
    let anchored = read_anchor(&file).unwrap().unwrap();
    assert_eq!(
        store.check_anchor(&anchored).await.unwrap(),
        AnchorVerdict::Consistent
    );
    let now = store.capture_anchor().await.unwrap();
    assert_eq!(
        (&now.backend, &now.instance_id, &now.system_identifier),
        (
            &before.anchor.backend,
            &before.anchor.instance_id,
            &before.anchor.system_identifier
        )
    );
    assert!(!store.restore_pending().await.unwrap());
    assert!(!store.library_is_empty().await.unwrap());
    let dry = store.restore_finish(LATER, true).await.unwrap();
    assert_eq!(dry.sessions, 1);
}

async fn exercise_saved_search(store: &Store, before: &Before) -> i64 {
    // Saved searches on the upgraded library: create, list, open; private to the account.
    let filters = r#"{"q":"release","cat":"2040"}"#;
    let id = store
        .create_saved_search(before.viewer, "Movies", filters, LATER)
        .await
        .unwrap();
    let listed = store.saved_searches(before.viewer).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].id,
            listed[0].name.as_str(),
            listed[0].filters.as_str()
        ),
        (id, "Movies", filters)
    );
    let opened = store
        .open_saved_search(before.viewer, id, LATER + 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((opened.id, opened.last_seen_at), (id, LATER));
    assert_eq!(
        store.saved_searches(before.viewer).await.unwrap()[0].last_seen_at,
        LATER + 60
    );
    assert_eq!(store.saved_searches(before.admin).await.unwrap(), []);
    assert!(
        store
            .open_saved_search(before.admin, id, LATER)
            .await
            .unwrap()
            .is_none()
    );
    // Not audited (private display state): the chain is unchanged and still consistent.
    assert_eq!(store.audit_anchor().await.unwrap(), before.audit);
    assert_eq!(
        store.check_anchor(&before.anchor).await.unwrap(),
        AnchorVerdict::Consistent
    );
    id
}

/// A retry must not recreate or lose the table populated after the first refusal.
async fn verify_saved_search(store: &Store, before: &Before, id: i64) {
    let listed = store.saved_searches(before.viewer).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].id,
            listed[0].name.as_str(),
            listed[0].filters.as_str(),
            listed[0].last_seen_at
        ),
        (id, "Movies", r#"{"q":"release","cat":"2040"}"#, LATER + 60)
    );
    assert_eq!(store.saved_searches(before.admin).await.unwrap(), []);
    assert!(
        store
            .open_saved_search(before.admin, id, LATER)
            .await
            .unwrap()
            .is_none()
    );
}

async fn sqlite_ledger(db: &SqliteDb, version: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version = ?1 AND success")
        .bind(version)
        .fetch_one(db.readers())
        .await
        .unwrap()
}

async fn sqlite_has_table(db: &SqliteDb, name: &str) -> bool {
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(name)
            .fetch_one(db.readers())
            .await
            .unwrap();
    n > 0
}

/// A failed fresh-data guard must not rewrite a successful ledger entry or leave a dirty roles entry.
type Ledger = Vec<(i64, bool, Vec<u8>, String, i64)>;

async fn sqlite_ledger_snapshot(db: &SqliteDb) -> Ledger {
    sqlx::query_as(
        "SELECT version, success, checksum, CAST(installed_on AS TEXT), execution_time \
         FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(db.readers())
    .await
    .unwrap()
}

/// The normal opener applies saved-search/page-size once, refuses roles, and preserves the populated library.
#[tokio::test]
async fn sqlite_3_1_data_survives_historical_migrations_and_roles_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    };
    let old = SqliteDb::open_at_version(&cfg, SQLITE_3_1_LAST)
        .await
        .unwrap();
    assert_eq!(sqlite_ledger(&old, SQLITE_3_1_LAST).await, 1);
    assert_eq!(sqlite_ledger(&old, SQLITE_3_2_SAVED_SEARCH).await, 0);
    assert!(!sqlite_has_table(&old, "saved_search").await);
    let store = Store::Sqlite(old);
    let before = fill_3_1(&store).await;
    store.close().await;

    let mut first_ledger = None;
    let mut saved_search = None;
    for attempt in 0..2 {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let error = SqliteDb::open_with(&cfg, StartupCheck::Fast, &move |e| {
            sink.lock().unwrap().push(e);
        })
        .await
        .expect_err("a populated historical library must not cross the roles boundary");
        assert!(error.to_string().contains("FRESH_DATA_REQUIRED"), "{error}");
        {
            let events = events.lock().unwrap();
            assert!(
                matches!(
                    events.first(),
                    Some(OpenEvent::CheckStarted {
                        mode: StartupCheck::Full,
                        escalated: true
                    })
                ),
                "{events:?}"
            );
            let pending: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    OpenEvent::MigrationsPending { total, first, last } => {
                        Some((*total, *first, *last))
                    }
                    _ => None,
                })
                .collect();
            let started: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    OpenEvent::MigrationStarted { version, .. } => Some(*version),
                    _ => None,
                })
                .collect();
            let finished: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    OpenEvent::MigrationFinished { version, .. } => Some(*version),
                    _ => None,
                })
                .collect();
            if attempt == 0 {
                // Versions 5 (release NFO) and 6 (failed-ingest SHA index) are also pending, but refusal at
                // roles must stop before them.
                assert_eq!(pending, [(5, SQLITE_3_2_SAVED_SEARCH, 6)]);
                assert_eq!(
                    started,
                    [SQLITE_3_2_SAVED_SEARCH, SQLITE_PAGE_SIZE, SQLITE_ROLES]
                );
                assert_eq!(finished, [SQLITE_3_2_SAVED_SEARCH, SQLITE_PAGE_SIZE]);
            } else {
                assert_eq!(pending, [(3, SQLITE_ROLES, 6)]);
                assert_eq!(started, [SQLITE_ROLES]);
                assert!(
                    finished.is_empty(),
                    "successful migrations must not run again"
                );
            }
        }

        // Inspect before any opener can migrate or reseed the database and conceal damage from the refusal.
        // Repeat this neutral inspection on retry, before validating checksums through the historical opener.
        let db = SqliteDb::open_read_only(&cfg.path).await.unwrap();
        let ledger = sqlite_ledger_snapshot(&db).await;
        assert_eq!(
            ledger
                .iter()
                .map(|(v, ok, ..)| (*v, *ok))
                .collect::<Vec<_>>(),
            [
                (SQLITE_3_1_LAST, true),
                (SQLITE_3_2_SAVED_SEARCH, true),
                (SQLITE_PAGE_SIZE, true)
            ]
        );
        if let Some(first) = &first_ledger {
            assert_eq!(&ledger, first, "retry must preserve the committed ledger");
        } else {
            first_ledger = Some(ledger);
        }
        assert!(sqlite_has_table(&db, "saved_search").await);
        for name in ["account_t134", "invite_t134", "audit_log_t134"] {
            assert!(
                !sqlite_has_table(&db, name).await,
                "failed rebuild left {name}"
            );
        }
        let store = Store::Sqlite(db);
        let schema = store.schema_info().await.unwrap();
        assert_eq!(
            (schema.latest_applied, schema.applied),
            (SQLITE_PAGE_SIZE, 3)
        );
        verify_preserved(&store, &before, dir.path()).await;
        store.close().await;

        // The historical opener validates applied checksums and permits the saved-search write exercise;
        // production still refuses this populated library above.
        let store = Store::Sqlite(
            SqliteDb::open_at_version(&cfg, SQLITE_PAGE_SIZE)
                .await
                .unwrap(),
        );
        if let Some(id) = saved_search {
            verify_saved_search(&store, &before, id).await;
        } else {
            saved_search = Some(exercise_saved_search(&store, &before).await);
        }
        store.close().await;
    }
}

async fn pg_ledger(t: &TestDb, version: i64) -> i64 {
    let mut su = t.superuser_conn().await;
    let n = sqlx::query_scalar(
        "SELECT count(*) FROM nzbd._sqlx_migrations WHERE version = $1 AND success",
    )
    .bind(version)
    .fetch_one(&mut su)
    .await
    .unwrap();
    sqlx::Connection::close(su).await.unwrap();
    n
}

async fn pg_ledger_snapshot(t: &TestDb) -> Ledger {
    let mut su = t.superuser_conn().await;
    let rows = sqlx::query_as(
        "SELECT version, success, checksum, CAST(installed_on AS TEXT), execution_time \
         FROM nzbd._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut su)
    .await
    .unwrap();
    sqlx::Connection::close(su).await.unwrap();
    rows
}

/// Owner migration commits the historical changes, refuses roles, and leaves readiness closed even after a retry.
#[tokio::test]
async fn pg_3_1_data_survives_historical_migrations_and_roles_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let t = TestDb::new_upto(PG_3_1_LAST).await;
    assert_eq!(pg_ledger(&t, PG_3_1_LAST).await, 1);
    assert_eq!(pg_ledger(&t, PG_3_2_SAVED_SEARCH).await, 0);
    let store = Store::Postgres(t.db.clone());
    let before = fill_3_1(&store).await;
    drop(store);
    assert_eq!(
        t.db.readiness().await.unwrap(),
        Readiness::MigrationsPending(vec![
            PG_3_2_SAVED_SEARCH,
            PG_PAGE_SIZE,
            PG_ROLES,
            PG_RELEASE_NFO
        ])
    );

    let mut first_ledger = None;
    let mut saved_search = None;
    for _ in 0..2 {
        let error = crate::pg::migrate_as_owner(t.owner_options())
            .await
            .expect_err("a populated historical library must not cross the roles boundary");
        assert!(error.to_string().contains("FRESH_DATA_REQUIRED"), "{error}");
        assert_eq!(
            t.db.readiness().await.unwrap(),
            Readiness::MigrationsPending(vec![PG_ROLES, PG_RELEASE_NFO])
        );
        let ledger = pg_ledger_snapshot(&t).await;
        assert_eq!(
            ledger
                .iter()
                .map(|(v, ok, ..)| (*v, *ok))
                .collect::<Vec<_>>(),
            (2..=PG_PAGE_SIZE).map(|v| (v, true)).collect::<Vec<_>>()
        );
        if let Some(first) = &first_ledger {
            assert_eq!(&ledger, first, "retry must preserve the committed ledger");
        } else {
            first_ledger = Some(ledger);
        }

        // New app-role pools see the preserved rows and grants, but their readiness gate still refuses serving.
        let db = crate::pg::PgDb::connect(&t.settings(), crate::pg::testing::TEST_APP_PASSWORD)
            .await
            .unwrap();
        assert_eq!(
            db.readiness().await.unwrap(),
            Readiness::MigrationsPending(vec![PG_ROLES, PG_RELEASE_NFO])
        );
        let store = Store::Postgres(db);
        let schema = store.schema_info().await.unwrap();
        assert_eq!((schema.latest_applied, schema.applied), (PG_PAGE_SIZE, 8));
        verify_preserved(&store, &before, dir.path()).await;
        if let Some(id) = saved_search {
            verify_saved_search(&store, &before, id).await;
        } else {
            saved_search = Some(exercise_saved_search(&store, &before).await);
        }
        store.close().await;
    }
    t.db.close().await;
}
