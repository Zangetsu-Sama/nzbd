//! `GET /admin/activity` (T138, `docs/UI_SPEC.md` Activity page): the audit log, filtered and paged.
//!
//! Admin only (the access gate answers the uniform 404 to every other role, D26); a GET with no
//! state change, so no CSRF form. Every query parameter is parsed strictly and an invalid value is
//! *ignored* (never echoed, never an error): `user` (digits), `event` (one of [`KNOWN_EVENTS`]),
//! `from`/`to` (`YYYY-MM-DD`), `before` (the keyset cursor, digits). The store query is
//! parameterized; the page text is askama-escaped, and `detail` goes through the same whitelist as
//! the Admin page's audit tail (`(hidden)` when it does not match the fixed grammar).

use std::collections::HashMap;

use askama::Template;
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::routing::get;
use nzb_core::sanitize_text;
use nzb_store::prelude::*;
use nzb_store::{AccountRow, AuditFilter, AuditRow, Store};

use crate::account::fmt_utc;
use crate::admin::{actor_text, audit_detail};
use crate::assets::Layout;
use crate::auth::SessionCtx;
use crate::csrf;
use crate::index::parse_date;
use crate::login::{html, internal};

/// Rows per page.
pub const PAGE_ROWS: u32 = 50;

/// Events offered in the filter (and the only ones accepted as a filter value).
pub const KNOWN_EVENTS: &[&str] = &[
    "nzb_upload",
    "nzb_upload_dup",
    "nzb_upload_reject",
    "release_delete",
    "download",
    "download_selected",
    "download_bulk",
    "category_override",
    "source_label_edit",
    // T140 (review 49 I4).
    "nfo_attach",
    "nfo_remove",
    "bulk_edit_category",
    "bulk_edit_source",
    "bulk_delete",
    "cleanup_purge",
    "apikey.create",
    "apikey.revoke",
    "login.ok",
    "login.fail",
    "authz_denied",
    "user_display_name",
    "pref_change",
];

#[derive(Clone)]
struct St {
    db: Store,
}

struct Opt {
    value: String,
    label: String,
    selected: bool,
}

struct Row {
    time: String,
    actor: String,
    event: String,
    detail: String,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct Page {
    layout: Layout,
    users: Vec<Opt>,
    events: Vec<Opt>,
    from: String,
    to: String,
    rows: Vec<Row>,
    filtered: bool,
    /// Link to the next older page, when there is one.
    older: Option<String>,
}

/// The validated query.
#[derive(Default)]
struct Query {
    user: Option<i64>,
    event: Option<&'static str>,
    from: Option<(String, i64)>,
    to: Option<(String, i64)>,
    before: Option<i64>,
}

fn id_param(v: Option<&str>) -> Option<i64> {
    let v = v?;
    if v.is_empty() || v.len() > 15 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse::<i64>().ok().filter(|n| *n > 0)
}

fn date_param(v: Option<&str>) -> Option<(String, i64)> {
    let v = v?;
    let ts = parse_date(v).ok()?;
    Some((v.to_owned(), ts))
}

fn parse_query(raw: Option<&str>) -> Query {
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    let get = |k: &str| csrf::form_get(&form, k);
    Query {
        user: id_param(get("user")),
        event: get("event").and_then(|e| KNOWN_EVENTS.iter().copied().find(|k| *k == e)),
        from: date_param(get("from")),
        to: date_param(get("to")),
        before: id_param(get("before")),
    }
}

fn actor_cell(r: &AuditRow, accounts: &HashMap<i64, AccountRow>) -> String {
    match r.actor_id {
        Some(id) => match accounts.get(&id) {
            Some(a) if a.is_live() => {
                let handle = sanitize_text(&a.handle(), 64);
                match r.actor_role.as_deref() {
                    Some(role @ ("admin" | "uploader" | "viewer")) => format!("{handle} ({role})"),
                    _ => handle,
                }
            }
            Some(_) => format!("Deleted account #{id}"),
            None => format!("Account #{id}"),
        },
        None => actor_text(r),
    }
}

async fn activity(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    uri: Uri,
) -> Response {
    let q = parse_query(uri.query());
    let filter = AuditFilter {
        actor_id: q.user,
        event: q.event.map(str::to_owned),
        from: q.from.as_ref().map(|f| f.1),
        // The whole "to" day.
        to: q.to.as_ref().map(|t| t.1.saturating_add(86_399)),
        before_id: q.before,
        limit: PAGE_ROWS + 1,
    };
    let (rows, accounts) = tokio::join!(st.db.audit_page(&filter), st.db.list_accounts(true));
    let Ok(mut rows) = rows else {
        tracing::error!("activity page query failed");
        return internal();
    };
    let accounts = accounts.unwrap_or_default();
    let has_more = rows.len() > PAGE_ROWS as usize;
    rows.truncate(PAGE_ROWS as usize);
    let by_id: HashMap<i64, AccountRow> = accounts.iter().map(|a| (a.id, a.clone())).collect();

    // Filter part of the link (all values validated above: digits, a known event, ISO dates).
    let mut parts: Vec<String> = Vec::new();
    if let Some(u) = q.user {
        parts.push(format!("user={u}"));
    }
    if let Some(e) = q.event {
        parts.push(format!("event={e}"));
    }
    if let Some((s, _)) = &q.from {
        parts.push(format!("from={s}"));
    }
    if let Some((s, _)) = &q.to {
        parts.push(format!("to={s}"));
    }
    let older = if has_more {
        rows.last().map(|r| {
            parts.push(format!("before={}", r.id));
            format!("/admin/activity?{}", parts.join("&"))
        })
    } else {
        None
    };
    let users = accounts
        .iter()
        .filter(|a| a.is_live())
        .map(|a| Opt {
            value: a.id.to_string(),
            label: sanitize_text(&a.handle(), 64),
            selected: q.user == Some(a.id),
        })
        .collect();
    let events = KNOWN_EVENTS
        .iter()
        .map(|e| Opt {
            value: (*e).to_owned(),
            label: (*e).to_owned(),
            selected: q.event == Some(*e),
        })
        .collect();
    let page = Page {
        layout: Layout::for_session("Activity", &sess),
        users,
        events,
        from: q.from.as_ref().map(|f| f.0.clone()).unwrap_or_default(),
        to: q.to.as_ref().map(|f| f.0.clone()).unwrap_or_default(),
        filtered: q.user.is_some() || q.event.is_some() || q.from.is_some() || q.to.is_some(),
        rows: rows
            .iter()
            .map(|r| Row {
                time: fmt_utc(r.ts),
                actor: actor_cell(r, &by_id),
                event: sanitize_text(&r.event, 64),
                detail: audit_detail(r),
            })
            .collect(),
        older,
    };
    match page.render() {
        Ok(body) => html(StatusCode::OK, body),
        Err(e) => {
            tracing::error!(error = %e, "activity page render failed");
            internal()
        }
    }
}

/// The Activity route; mounted by [`crate::admin::routes`].
pub fn routes(db: Store) -> Router {
    Router::new()
        .route("/admin/activity", get(activity))
        .with_state(St { db })
}
