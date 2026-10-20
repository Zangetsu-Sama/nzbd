//! `POST /page-size` (T133): the "Per page" control under the release list and under a release's files table.
//!
//! Why a POST and not a GET form: the choice is remembered per account (`user_pref.page_size_releases` /
//! `page_size_files`), so submitting it changes stored state and writes a `pref_change` audit row. Every state change
//! sits behind the CSRF layer (SEC-025) and a per-account budget (the audit log cannot be flooded through it), which a
//! GET could not have. The form is still a plain HTML form (select + "Show"), it works without JavaScript and needs no
//! CSP change.
//!
//! Fields (strict form, at most [`MAX_FIELDS`], no repeated field, else `400 BAD_REQUEST`):
//! * `list` = `releases` | `files` (else `400 BAD_REQUEST`);
//! * `per_page`: one value of the allowlist ([`ReleasePageSize`] 25/50/100, [`FilePageSize`] 50/100/250/500). Anything
//!   else is **ignored**: nothing is stored and the current choice (the default until one is made) stays; it is never
//!   an error page and never a raw number that reaches a query;
//! * `releases`: the index filters and sort as the page's hidden fields (the names of [`crate::saved::SAVED_KEYS`]),
//!   re-validated by the index parser (`400 BAD_QUERY` like the index itself, also for a category hidden for the
//!   caller, so the answer never tells a hidden category from a typo);
//! * `files`: `release` = the release id (strict decimal, else `400 BAD_REQUEST`).
//!
//! The answer is `303 See Other` to page 1 of the same listing, built from validated values only (the canonical index
//! href without page or cursor, or `/release/<id>`): no open redirect, and the keyset cursors are reset. Whether the
//! release exists is decided by the release page it lands on (its uniform 404), so this route reveals nothing.
//!
//! Writes (review 48): only an allowlisted value that differs from the stored one is written, and only such a request
//! costs the per-account budget ([`SAVES_PER_MIN`], then `429 RATE_LIMITED`). The write touches the one column
//! (`set_page_size`), so it never reverts a preference saved at the same time on the Account page.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use nzb_search::SearchIndexV3;
use nzb_store::prelude::*;
use nzb_store::{FilePageSize, PageSize, ReleasePageSize};

use crate::auth::SessionCtx;
use crate::bulk::WallMs;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::index::{IndexState, parse_params};
use crate::ratelimit::{Decision, KeyedLimiter};
use crate::release::parse_id;

/// Fields the form may carry at most (token, `list`, `per_page`, `release`, the filter names, slack).
pub const MAX_FIELDS: usize = 24;
/// Page-size saves per account and minute (the same budget as `POST /account/preferences`): each stored change is
/// one audit row, so this bounds what one account can write.
pub const SAVES_PER_MIN: u32 = crate::auth::PREF_SAVES_PER_MIN;
/// Upper bound of tracked accounts (the account cap is far below it).
const MAX_TRACKED_ACCOUNTS: usize = 4096;

/// The per-account budget of this route, built on the index state's wall clock.
pub(crate) fn limiter(clock: &Arc<dyn crate::auth::WallClock>) -> Arc<KeyedLimiter<i64>> {
    Arc::new(KeyedLimiter::new(
        SAVES_PER_MIN,
        MAX_TRACKED_ACCOUNTS,
        Arc::new(WallMs(Arc::clone(clock))),
    ))
}

/// The page sizes offered for `current` as select choices (value = label = the number).
pub(crate) fn choices(list: &[u32], current: u32) -> Vec<crate::index::Choice> {
    list.iter()
        .map(|n| crate::index::Choice {
            value: n.to_string(),
            label: n.to_string(),
            selected: *n == current,
        })
        .collect()
}

fn fail(status: StatusCode, code: &'static str) -> Response {
    ApiError::new(status, code).into_response()
}

/// `POST /page-size`: see the module documentation.
pub(crate) async fn post<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let bad_request = || fail(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    let bad_query = || fail(StatusCode::BAD_REQUEST, "BAD_QUERY");
    let Some(form) = csrf::parse_form_strict(&body, MAX_FIELDS) else {
        return bad_request();
    };
    let singles: Vec<&str> = ["csrf_token", "list", "per_page", "release"]
        .iter()
        .chain(crate::saved::SAVED_KEYS.iter())
        .copied()
        .collect();
    if !csrf::singletons_ok(&form, &singles) {
        return bad_request();
    }
    let per_page = csrf::form_get(&form, "per_page").unwrap_or_default();
    // What to store (only an allowlisted value) and where to go back to.
    let (size, target): (Option<PageSize>, String) = match csrf::form_get(&form, "list") {
        Some("releases") => {
            let tax = st.taxonomy.as_ref();
            let query =
                crate::saved::saved_query(form.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            let Ok(p) = parse_params(Some(&query), tax) else {
                return bad_query();
            };
            if p.category
                .is_some_and(|c| sess.hidden_categories.contains(&c))
            {
                return bad_query();
            }
            // The same second validation as the index (review 48 I2): a filter set the index would refuse is refused
            // here too, so the redirect never lands on a 400.
            if p.to_search(ReleasePageSize::DEFAULT.get()).is_err() {
                return bad_query();
            }
            (
                ReleasePageSize::parse(per_page).map(PageSize::Releases),
                p.href(tax, p.sort, 1, true),
            )
        }
        Some("files") => {
            let Some(id) = csrf::form_get(&form, "release").and_then(parse_id) else {
                return bad_request();
            };
            (
                FilePageSize::parse(per_page).map(PageSize::Files),
                format!("/release/{id}"),
            )
        }
        _ => return bad_request(),
    };
    // Only a real change costs budget and writes (review 48 I1): an ignored or unchanged value is a plain redirect.
    if let Some(size) = size.filter(|s| s.applied_to(sess.prefs) != sess.prefs) {
        if let Decision::Deny { retry_after_secs } = st.page_size_saves.check(sess.user_id) {
            return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
                .retry_after(retry_after_secs)
                .into_response();
        }
        // One column only (review 48 L1): a preference saved at the same time elsewhere is never reverted.
        if let Err(e) = st
            .db
            .set_page_size_as(
                &sess.actor(),
                size,
                Some(&ip.to_string()),
                st.clock.now_secs(),
            )
            .await
        {
            if matches!(
                e,
                nzb_store::StoreError::Account(nzb_store::AccountError::Forbidden)
            ) {
                return fail(StatusCode::NOT_FOUND, "NOT_FOUND");
            }
            tracing::error!(error = %e, "page size change failed");
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL");
        }
    }
    crate::saved::see_other(&target)
}
