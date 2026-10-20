//! Schema parity (ARCHITECTURE v3 13.4, review 35 L1): both schemas carry the same tables, columns and `CHECK`-ed
//! columns, except the intended differences listed here with their reason.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;

use crate::pg::testing::TestDb;
use crate::{DbConfig, SqliteDb};

/// `table.column` of every column, and `table.column` of every column a CHECK constraint covers.
struct Shape {
    columns: BTreeSet<String>,
    checked: BTreeSet<String>,
    tables: BTreeSet<String>,
}

async fn sqlite_shape() -> Shape {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("p.sqlite"),
    })
    .await
    .unwrap();
    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name <> '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(db.readers())
    .await
    .unwrap();
    let mut s = Shape {
        columns: BTreeSet::new(),
        checked: BTreeSet::new(),
        tables: BTreeSet::new(),
    };
    for (t, sql) in &tables {
        s.tables.insert(t.clone());
        let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?1)")
            .bind(t)
            .fetch_all(db.readers())
            .await
            .unwrap();
        for c in &cols {
            s.columns.insert(format!("{t}.{c}"));
            // Any CHECK expression (column or table constraint) that names the column.
            let named = check_exprs(sql).iter().any(|x| has_word(x, c));
            if named {
                s.checked.insert(format!("{t}.{c}"));
            }
        }
    }
    db.close().await;
    s
}

/// The text of every `CHECK (...)` in a `CREATE TABLE` statement (balanced parentheses).
fn check_exprs(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = sql;
    while let Some(i) = rest.find("CHECK") {
        rest = &rest[i + 5..];
        let Some(open) = rest.find('(') else { break };
        let mut depth = 0_i32;
        let mut end = None;
        for (j, ch) in rest[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        out.push(rest[open..=end].to_owned());
        rest = &rest[end..];
    }
    out
}

fn has_word(hay: &str, w: &str) -> bool {
    hay.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|x| x == w)
}

async fn postgres_shape() -> Shape {
    let t = TestDb::new().await;
    let mut c = t.superuser_conn().await;
    let cols: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'nzbd' AND c.relkind IN ('r', 'p') \
         AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped AND c.relname <> '_sqlx_migrations'",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let checked: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute a ON a.attrelid = c.oid \
         AND a.attnum = ANY (k.conkey) WHERE n.nspname = 'nzbd' AND k.contype = 'c' AND NOT c.relispartition",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let mut s = Shape {
        columns: BTreeSet::new(),
        checked: BTreeSet::new(),
        tables: BTreeSet::new(),
    };
    for (t, col) in cols {
        s.tables.insert(t.clone());
        s.columns.insert(format!("{t}.{col}"));
    }
    for (t, col) in checked {
        s.checked.insert(format!("{t}.{col}"));
    }
    s
}

/// Intended differences: `(object, reason)`. An object is `table` or `table.column`; for CHECKs `check:table.column`.
const INTENDED: [(&str, &str); 23] = [
    (
        "migrate_progress",
        "Postgres-only: progress of the withdrawn 2.x import (T115 re-scoped by D37); unused",
    ),
    (
        "migrate_source",
        "Postgres-only: source record of the withdrawn 2.x import (D37); unused",
    ),
    ("migrate_progress.digest", "see migrate_progress"),
    ("migrate_progress.done", "see migrate_progress"),
    ("migrate_progress.last_key", "see migrate_progress"),
    ("migrate_progress.rows", "see migrate_progress"),
    ("migrate_progress.table_name", "see migrate_progress"),
    ("migrate_progress.updated_at", "see migrate_progress"),
    ("migrate_source.fingerprint", "see migrate_source"),
    ("migrate_source.finished_at", "see migrate_source"),
    ("migrate_source.id", "see migrate_source"),
    ("migrate_source.sqlite_schema_version", "see migrate_source"),
    ("migrate_source.started_at", "see migrate_source"),
    (
        "nzb_file.id",
        "SQLite rowid key; Postgres keys nzb_file by (release_id, idx) for its partitions",
    ),
    (
        "release.scene_title",
        "Postgres-only, never written by either store (always NULL); kept out of the SQLite baseline",
    ),
    (
        "session.seq",
        "Postgres tie-break for sessions created in the same second; SQLite orders by rowid",
    ),
    (
        "check:db_state.restore_pending",
        "boolean on Postgres (the type is the check); SQLite needs IN (0, 1)",
    ),
    ("check:release.category_overridden", "boolean on Postgres"),
    (
        "check:retention_policy.account_keep_all",
        "boolean on Postgres",
    ),
    ("check:retention_policy.keep_all", "boolean on Postgres"),
    ("check:search_state.replay", "boolean on Postgres"),
    ("check:session.enroll_proven", "boolean on Postgres"),
    ("check:user_pref.hide_xxx", "boolean on Postgres"),
];

/// Tables, columns and `CHECK`-ed columns of the two schemas must match, except [`INTENDED`]; a stale entry fails too.
/// (Triggers differ in mechanism, not in rules: their behaviour is compared by the seam and store suites.)
#[tokio::test]
async fn schema_parity_between_sqlite_and_postgres() {
    let (a, b) = (sqlite_shape().await, postgres_shape().await);
    let mut diff: BTreeSet<String> = BTreeSet::new();
    diff.extend(a.tables.symmetric_difference(&b.tables).cloned());
    diff.extend(a.columns.symmetric_difference(&b.columns).cloned());
    // CHECKs are compared on the columns both schemas have.
    let common: BTreeSet<String> = a.columns.intersection(&b.columns).cloned().collect();
    let ca: BTreeSet<String> = a.checked.intersection(&common).cloned().collect();
    let cb: BTreeSet<String> = b.checked.intersection(&common).cloned().collect();
    diff.extend(ca.symmetric_difference(&cb).map(|c| format!("check:{c}")));
    let intended: BTreeSet<String> = INTENDED.iter().map(|(o, _)| (*o).to_owned()).collect();
    let unexplained: Vec<&String> = diff.difference(&intended).collect();
    let stale: Vec<&String> = intended.difference(&diff).collect();
    assert!(
        unexplained.is_empty(),
        "schema difference without a reason (fix the schema or add it to INTENDED): {unexplained:?}"
    );
    assert!(stale.is_empty(), "stale INTENDED entries: {stale:?}");
}
