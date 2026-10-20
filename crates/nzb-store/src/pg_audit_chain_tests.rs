//! Tamper-evident audit chain on the v3 Postgres store (T105 tests ported by T112; SEC-080, SEC-081, SEC-093):
//! detection of edit, deletion and insertion, and retention that keeps the chain verifiable. Tampering needs the
//! superuser or the owner in v3 (the app role cannot write audit rows), so the attacker of these tests is the
//! superuser of the private test database. The 2.x bootstrap of pre-0013 rows does not exist in v3 (rows arrive
//! chained; the 2.x chain is verified by `migrate`, SEC-096), so those tests are not ported.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use crate::audit_chain::{AuditContent, GENESIS, chain_hash};
use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::pg_testkit::{Env, T0, env};
use crate::{ChainBreak, ChainBreakKind, ChainReport};

const DAY: i64 = 86_400;

fn hex_of(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

async fn walk(db: &PgDb) -> ChainReport {
    db.audit_walk(None, &mut |_| {}).await.unwrap()
}

/// `n` rows: mostly class 0 (`download`), every fourth an account-lifecycle row (class 1, `user.create`).
async fn seed(e: &Env, n: i64) {
    for i in 0..n {
        let (actor, event) = if i % 4 == 3 {
            (Some("cli"), "user.create")
        } else {
            (Some("user:1"), "download")
        };
        e.db.audit_event(
            T0 + i,
            actor,
            event,
            Some(&format!("release={i}")),
            Some("192.0.2.1"),
        )
        .await
        .unwrap();
    }
}

/// Ids of the rows of one class, oldest first.
async fn ids(e: &Env, class: i64) -> Vec<i64> {
    sqlx::query_scalar("SELECT id FROM audit_log WHERE chain_class = $1 ORDER BY id")
        .bind(class)
        .fetch_all(e.db.web())
        .await
        .unwrap()
}

/// Raw SQL as an attacker with database write access would run it: the superuser, with the immutability trigger
/// disabled first (a plain `UPDATE` is refused, see `sec_080_audit_content_is_immutable_at_the_sql_level`).
async fn tamper(e: &Env, sql: &str) {
    e.superuser_exec(&format!(
        "ALTER TABLE nzbd.audit_log DISABLE TRIGGER audit_log_immutable; {sql}; \
         ALTER TABLE nzbd.audit_log ENABLE TRIGGER audit_log_immutable;"
    ))
    .await;
}

/// The v3 purge: the DATABASE clock is `now`, the owner policy says `days` / `account_days` (0 = keep forever), then
/// the app role runs the bounded purge.
async fn purge(e: &Env, now: i64, days: u32, account_days: u32) -> crate::PurgeReport {
    e.t.set_db_clock(now).await;
    crate::pg::set_retention_policy(
        e.t.owner_options(),
        crate::pg::RetentionPolicy {
            log_days: days,
            account_days: account_days.max(365),
            ingest_days: days,
            keep_all: false,
            account_keep_all: account_days == 0,
        },
    )
    .await
    .unwrap();
    e.db.purge_logs().await.unwrap()
}

#[tokio::test]
async fn sec_080_fresh_chain_verifies_and_links_rows() {
    let e = env().await;
    // Empty log: nothing to report, genesis heads.
    let r = walk(&e.db).await;
    assert!(r.is_ok());
    assert_eq!((r.rows, r.heads), (0, [GENESIS, GENESIS]));
    seed(&e, 12).await;
    let r = walk(&e.db).await;
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(r.rows, 12);
    assert_ne!(r.heads[0], GENESIS);
    assert_ne!(r.heads[1], GENESIS);
    let q = e.db.audit_chain_quick().await.unwrap();
    assert!(q.consistent && q.bootstrapped, "{q:?}");
    assert_eq!((q.rows, q.unchained), (12, 0));
    // A write that is rolled back leaves no trace in the chain or its state.
    {
        let mut tx = e.db.web().begin().await.unwrap();
        crate::pg::audit_append_for_tests(
            &mut tx,
            &AuditContent {
                ts: T0,
                actor: None,
                event: "download",
                detail: None,
                ip: None,
                actor_id: None,
                actor_kind: None,
                actor_role: None,
                target_id: None,
            },
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
    }
    let again = walk(&e.db).await;
    assert!(again.is_ok());
    assert_eq!(again.heads, r.heads);
}

#[tokio::test]
async fn sec_080_chain_detects_an_edited_row() {
    let e = env().await;
    seed(&e, 12).await;
    let victim = ids(&e, 0).await[3];
    tamper(
        &e,
        &format!("UPDATE audit_log SET detail = 'release=999' WHERE id = {victim}"),
    )
    .await;
    let r = walk(&e.db).await;
    assert_eq!(
        r.first_break,
        Some(ChainBreak {
            id: victim,
            kind: ChainBreakKind::Edited
        })
    );
    // Editing the actor column (attribution) is caught the same way.
    let e = env().await;
    seed(&e, 6).await;
    let v = ids(&e, 1).await[0];
    tamper(
        &e,
        &format!("UPDATE audit_log SET actor_id = 77, actor_kind = 'user' WHERE id = {v}"),
    )
    .await;
    assert_eq!(walk(&e.db).await.first_break.map(|b| b.id), Some(v));
}

#[tokio::test]
async fn sec_080_edit_with_recomputed_row_hash_breaks_the_next_link() {
    let e = env().await;
    seed(&e, 12).await;
    let class0 = ids(&e, 0).await;
    let (victim, next) = (class0[2], class0[3]);
    // The attacker rewrites the row AND recomputes its own hash from the recorded predecessor.
    let (prev, _): (Vec<u8>, i64) =
        sqlx::query_as("SELECT chain_prev, id FROM audit_log WHERE id = $1")
            .bind(victim)
            .fetch_one(e.db.web())
            .await
            .unwrap();
    let prev: [u8; 32] = prev.try_into().unwrap();
    let forged = chain_hash(
        0,
        &prev,
        &AuditContent {
            ts: T0 + 2,
            actor: Some("user:1"),
            event: "download",
            detail: Some("release=forged"),
            ip: Some("192.0.2.1"),
            actor_id: Some(1),
            actor_kind: Some("user"),
            actor_role: Some("admin"),
            target_id: None,
        },
    );
    let sql = format!(
        "UPDATE audit_log SET detail = 'release=forged', actor_id = 1, actor_kind = 'user', actor_role = 'admin', \
         chain_hash = '\\x{}'::bytea WHERE id = {victim}",
        hex_of(&forged)
    );
    tamper(&e, &sql).await;
    let r = walk(&e.db).await;
    // The forged row itself is self-consistent; the row after it no longer links to it.
    assert_eq!(
        r.first_break,
        Some(ChainBreak {
            id: next,
            kind: ChainBreakKind::Gap
        })
    );
}

#[tokio::test]
async fn sec_080_chain_detects_deletion_in_the_middle_and_at_the_end() {
    let e = env().await;
    seed(&e, 12).await;
    let class0 = ids(&e, 0).await;
    tamper(
        &e,
        &format!("DELETE FROM audit_log WHERE id = {}", class0[2]),
    )
    .await;
    assert_eq!(
        walk(&e.db).await.first_break,
        Some(ChainBreak {
            id: class0[3],
            kind: ChainBreakKind::Gap
        })
    );
    assert!(!e.db.audit_chain_quick().await.unwrap().consistent);

    // Deleting the newest rows leaves a perfectly linked chain: the recorded head and row count expose it.
    let e = env().await;
    seed(&e, 12).await;
    let class0 = ids(&e, 0).await;
    let last = *class0.last().unwrap();
    let before_last = class0[class0.len() - 2];
    tamper(&e, &format!("DELETE FROM audit_log WHERE id = {last}")).await;
    assert_eq!(
        walk(&e.db).await.first_break,
        Some(ChainBreak {
            id: before_last,
            kind: ChainBreakKind::TailRemoved
        })
    );
    assert!(!e.db.audit_chain_quick().await.unwrap().consistent);

    // Deleting the OLDEST row (a prefix) without a purge is caught by the floor anchor.
    let e = env().await;
    seed(&e, 12).await;
    let class0 = ids(&e, 0).await;
    tamper(
        &e,
        &format!("DELETE FROM audit_log WHERE id = {}", class0[0]),
    )
    .await;
    assert_eq!(
        walk(&e.db).await.first_break,
        Some(ChainBreak {
            id: class0[1],
            kind: ChainBreakKind::Gap
        })
    );
}

#[tokio::test]
async fn sec_080_chain_detects_insertion() {
    // A row that bypasses the application has no chain columns. v3: the app role cannot insert at all; only the
    // owner, the superuser or the data files can, and the walk reports it.
    let e = env().await;
    seed(&e, 8).await;
    let refused = sqlx::query(
        "INSERT INTO audit_log (ts, actor, event, detail) VALUES (1, 'cli', 'user.create', 'x')",
    )
    .execute(e.db.web())
    .await
    .unwrap_err();
    assert!(
        refused.to_string().contains("permission denied"),
        "{refused}"
    );
    e.superuser_exec(
        "INSERT INTO audit_log (ts, actor, event, detail) VALUES (1, 'cli', 'user.create', 'backdoor')",
    )
    .await;
    let injected: i64 = sqlx::query_scalar("SELECT max(id) FROM audit_log")
        .fetch_one(e.db.web())
        .await
        .unwrap();
    let r = walk(&e.db).await;
    assert_eq!(
        r.first_break,
        Some(ChainBreak {
            id: injected,
            kind: ChainBreakKind::Unchained
        })
    );
    let q = e.db.audit_chain_quick().await.unwrap();
    assert_eq!(q.unchained, 1);
    // Nothing ever seals it silently.
    assert_eq!(walk(&e.db).await.first_break.map(|b| b.id), Some(injected));

    // A forged row with a valid hash placed in the middle (the row it replaces is removed): the row after it breaks.
    let e = env().await;
    seed(&e, 12).await;
    let class0 = ids(&e, 0).await;
    let (victim, next) = (class0[2], class0[3]);
    let prev: Vec<u8> = sqlx::query_scalar("SELECT chain_prev FROM audit_log WHERE id = $1")
        .bind(victim)
        .fetch_one(e.db.web())
        .await
        .unwrap();
    let prev: [u8; 32] = prev.try_into().unwrap();
    let fake = chain_hash(
        0,
        &prev,
        &AuditContent {
            ts: 5,
            actor: Some("cli"),
            event: "download",
            detail: Some("fabricated"),
            ip: None,
            actor_id: None,
            actor_kind: None,
            actor_role: None,
            target_id: None,
        },
    );
    let hex = hex_of;
    tamper(
        &e,
        &format!(
            "DELETE FROM audit_log WHERE id = {victim}; \
             INSERT INTO audit_log (id, ts, actor, event, detail, chain_class, chain_prev, chain_hash) \
             VALUES ({victim}, 5, 'cli', 'download', 'fabricated', 0, '\\x{}'::bytea, '\\x{}'::bytea)",
            hex(&prev),
            hex(&fake)
        ),
    )
    .await;
    assert_eq!(
        walk(&e.db).await.first_break,
        Some(ChainBreak {
            id: next,
            kind: ChainBreakKind::Gap
        })
    );
}

#[tokio::test]
async fn sec_080_audit_content_is_immutable_at_the_sql_level() {
    let e = env().await;
    seed(&e, 3).await;
    for col in [
        "ts = 1",
        "actor = 'x'",
        "event = 'x'",
        "detail = 'x'",
        "ip = 'x'",
        "actor_id = 5",
        "actor_kind = 'cli'",
        "actor_role = 'admin'",
        "target_id = 3",
    ] {
        let r = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE audit_log SET {col}")))
            .execute(e.db.web())
            .await;
        assert!(r.is_err(), "{col} must be refused");
    }
    assert!(walk(&e.db).await.is_ok());
}

#[tokio::test]
async fn sec_081_purge_keeps_the_chain_verifiable() {
    let e = env().await;
    let now = T0 + 1000 * DAY;
    // Old log rows, old account rows (older than 90, younger than 365 days), fresh rows of both classes.
    for (age, actor, event) in [
        (400, "user:1", "download"),
        (400, "cli", "user.create"),
        (200, "user:1", "download"),
        (200, "cli", "user.create"),
        (100, "user:1", "download"),
        (5, "user:1", "download"),
        (5, "cli", "user.create"),
    ] {
        e.db.audit_event(now - age * DAY, Some(actor), event, Some("d"), None)
            .await
            .unwrap();
    }
    assert!(walk(&e.db).await.is_ok());
    let r = purge(&e, now, 90, 365).await;
    // log class: 400, 200, 100 days old removed (3); account class: only the 400-day row (1).
    assert_eq!(r.audit, 4);
    let after = walk(&e.db).await;
    assert!(after.is_ok(), "{after:?}");
    assert_eq!(after.rows, 3);
    let q = e.db.audit_chain_quick().await.unwrap();
    assert!(q.consistent, "{q:?}");
    // New rows keep chaining onto the head.
    seed(&e, 4).await;
    assert!(walk(&e.db).await.is_ok());
    // A second purge, much later, removes everything and the chain still verifies (floor == head).
    let r = purge(&e, now + 2000 * DAY, 90, 365).await;
    assert_eq!(r.audit, 7);
    let empty = walk(&e.db).await;
    assert!(empty.is_ok(), "{empty:?}");
    assert_eq!(empty.rows, 0);
    assert!(e.db.audit_chain_quick().await.unwrap().consistent);
    e.db.audit_event(now + 2000 * DAY, Some("cli"), "user.create", None, None)
        .await
        .unwrap();
    let again = walk(&e.db).await;
    assert!(again.is_ok(), "{again:?}");
    assert_eq!(again.rows, 1);
}

#[tokio::test]
async fn sec_081_purge_removes_only_a_prefix_and_survivors_stay_protected() {
    let e = env().await;
    let now = T0 + 1000 * DAY;
    // A young row (clock stepped back) sits before two old ones: a purge must not punch a hole in the chain.
    for (age, d) in [(120, "old-a"), (1, "young"), (120, "old-b"), (120, "old-c")] {
        e.db.audit_event(now - age * DAY, Some("user:1"), "download", Some(d), None)
            .await
            .unwrap();
    }
    assert_eq!(purge(&e, now, 90, 365).await.audit, 1);
    assert!(walk(&e.db).await.is_ok());
    assert_eq!(ids(&e, 0).await.len(), 3);
    // Survivors are still protected: editing or removing the first survivor is caught against the floor anchor.
    let first = ids(&e, 0).await[0];
    tamper(&e, &format!("DELETE FROM audit_log WHERE id = {first}")).await;
    let r = walk(&e.db).await;
    assert!(!r.is_ok());
}

#[tokio::test]
async fn sec_081_purge_of_a_tampered_floor_is_detected() {
    let e = env().await;
    let now = T0 + 1000 * DAY;
    for age in [200, 150, 1] {
        e.db.audit_event(now - age * DAY, Some("user:1"), "download", None, None)
            .await
            .unwrap();
    }
    purge(&e, now, 90, 365).await;
    assert!(walk(&e.db).await.is_ok());
    // Resetting the recorded floor (to hide that rows were removed) breaks the link of the first survivor.
    tamper(
        &e,
        "UPDATE audit_chain_state SET floor_hash = decode(repeat('00', 32), 'hex') WHERE class = 0",
    )
    .await;
    assert!(!walk(&e.db).await.is_ok());
}

#[tokio::test]
async fn sec_080_state_row_rewrite_is_the_documented_undetected_case() {
    // The limit of an unkeyed chain (SECURITY.md SEC-080): anyone who can write the database file can remove the
    // newest rows of a class and make `audit_chain_state` agree. Verification then reports OK; only a head recorded
    // elsewhere (the startup/backup/purge log line, `nzbd audit export`) exposes it.
    let e = env().await;
    seed(&e, 12).await;
    let before = e.db.audit_anchor().await.unwrap();
    let class0 = ids(&e, 0).await;
    let (keep, drop_ids) = class0.split_at(class0.len() - 2);
    let new_head: Vec<u8> = sqlx::query_scalar("SELECT chain_hash FROM audit_log WHERE id = $1")
        .bind(*keep.last().unwrap())
        .fetch_one(e.db.web())
        .await
        .unwrap();
    for id in drop_ids {
        tamper(&e, &format!("DELETE FROM audit_log WHERE id = {id}")).await;
    }
    // v3: the app role cannot write the state row (SEC-093); this residual now needs the owner role.
    let e_app = sqlx::query("UPDATE audit_chain_state SET rows = 0 WHERE class = 0")
        .execute(e.db.web())
        .await
        .unwrap_err();
    assert!(e_app.to_string().contains("permission denied"), "{e_app}");
    let mut owner = e.t.owner_conn().await;
    sqlx::query("UPDATE audit_chain_state SET head_hash = $1, rows = rows - 2 WHERE class = 0")
        .bind(new_head)
        .execute(&mut owner)
        .await
        .unwrap();
    let r = walk(&e.db).await;
    assert!(r.is_ok(), "documented limit: {r:?}");
    // ... but the off-host anchor taken before shows it.
    let after = e.db.audit_anchor().await.unwrap();
    assert_ne!(before.head_log, after.head_log);
    assert!(after.rows < before.rows);
    assert!(after.line().starts_with("head_log="));
}

#[tokio::test]
async fn sec_081_a_far_future_row_does_not_pin_the_purge() {
    let e = env().await;
    let day = 86_400;
    let now = T0 + 1000 * day;
    // old, FUTURE (a year ahead: clock step), old, young.
    for (ts, d) in [
        (now - 200 * day, "old-1"),
        (now + 365 * day, "future"),
        (now - 190 * day, "old-2"),
        (now - 1, "young"),
    ] {
        e.db.audit_event(ts, Some("user:1"), "download", Some(d), None)
            .await
            .unwrap();
    }
    let r = purge(&e, now, 90, 365).await;
    // old-1, future and old-2 go (the prefix before the first sane young row); `young` stays.
    assert_eq!((r.audit, r.future_rows), (3, 1));
    let rows: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_log ORDER BY id")
        .fetch_all(e.db.web())
        .await
        .unwrap();
    assert_eq!(rows, ["young"]);
    assert!(walk(&e.db).await.is_ok());
    // `account_audit_days = 0` still keeps every account-lifecycle row, future-stamped or not.
    e.db.audit_event(now + 400 * day, Some("cli"), "user.create", None, None)
        .await
        .unwrap();
    e.db.audit_event(now - 900 * day, Some("cli"), "user.create", None, None)
        .await
        .unwrap();
    purge(&e, now, 90, 0).await;
    assert_eq!(ids(&e, 1).await.len(), 2);
}

#[tokio::test]
async fn sec_080_anchor_line_carries_heads_and_row_count_only() {
    let e = env().await;
    let empty = e.db.audit_anchor().await.unwrap();
    assert_eq!(
        (empty.rows, empty.head_log, empty.head_account),
        (0, GENESIS, GENESIS)
    );
    seed(&e, 8).await;
    let a = e.db.audit_anchor().await.unwrap();
    let w = walk(&e.db).await;
    assert_eq!(
        (a.head_log, a.head_account, a.rows),
        (w.heads[0], w.heads[1], w.rows)
    );
    let line = a.line();
    let parts: Vec<&str> = line.split(' ').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[0].len() == "head_log=".len() + 64 && parts[1].starts_with("head_account="));
    assert_eq!(parts[2], "rows=8");
}
