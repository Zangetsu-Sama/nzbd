//! The NFO viewer (T140, D41): the full view of a release's NFO, its raw download and the admin's remove.
//!
//! The stored bytes are decoded by [`nzb_core::decode_nfo`] (CP437 unless the file is UTF-8) into text that holds no
//! control character but LF and TAB; askama escapes it into a `<pre>`, so an NFO can never become markup. The raw
//! download is an attachment (`application/octet-stream`, `nosniff`, `no-store`) named after the release, never after
//! anything in the NFO. A release in a hidden category, or without an NFO, is the uniform 404.

use askama::Template;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use nzb_core::{NfoEncoding, NfoText, decode_nfo};
use nzb_store::prelude::*;
use nzb_store::{ReleaseNfo, ReleaseRow, StoreError};

use crate::assets::Layout;
use crate::auth::SessionCtx;
use crate::ctx::ClientIp;
use crate::release::{St, fail, internal, not_found, parse_id};

/// What the release page and the full view show of an NFO.
pub(crate) struct NfoView {
    /// Decoded text (escaped by the template).
    pub(crate) text: String,
    /// `CP437` or `UTF-8`.
    pub(crate) encoding: &'static str,
    pub(crate) lines: usize,
    pub(crate) columns: usize,
}

impl NfoView {
    pub(crate) fn decode(bytes: &[u8], force: Option<NfoEncoding>) -> (Self, NfoEncoding) {
        let NfoText {
            text,
            encoding,
            lines,
            columns,
        } = decode_nfo(bytes, force);
        (
            Self {
                text,
                encoding: encoding.label(),
                lines,
                columns,
            },
            encoding,
        )
    }
}

/// The release (visible to this session) and its NFO, or the response to send instead.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
async fn load(st: &St, sess: &SessionCtx, id: &str) -> Result<(ReleaseRow, ReleaseNfo), Response> {
    let Some(id) = parse_id(id) else {
        return Err(not_found());
    };
    let db = &st.deps.db;
    let row = match db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => r,
        Ok(_) => return Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return Err(internal());
        }
    };
    match db.release_nfo(id).await {
        Ok(Some(n)) => Ok((row, n)),
        Ok(None) => Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "nfo lookup failed");
            Err(internal())
        }
    }
}

/// `enc` of the full view: absent (auto), `cp437` or `utf8`; anything else is refused.
fn parse_enc(query: Option<&str>) -> Result<Option<NfoEncoding>, ()> {
    match query {
        None | Some("") => Ok(None),
        Some(q) => match q.strip_prefix("enc=") {
            Some(v) => NfoEncoding::from_param(v).map(Some).ok_or(()),
            None => Err(()),
        },
    }
}

#[derive(Template)]
#[template(path = "nfo.html")]
struct NfoPage {
    layout: Layout,
    id: i64,
    title: String,
    nfo: NfoView,
    /// The other encoding's `enc` value and label, for the switch link.
    other_enc: &'static str,
    other_label: &'static str,
    can_delete: bool,
}

/// `GET /release/{id}/nfo[?enc=cp437|utf8]`.
pub(crate) async fn page(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path(id): Path<String>,
    uri: Uri,
) -> Response {
    let Ok(force) = parse_enc(uri.query()) else {
        return fail(StatusCode::BAD_REQUEST, "BAD_QUERY");
    };
    let (row, nfo) = match load(&st, &sess, &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (view, used) = NfoView::decode(&nfo.bytes, force);
    let other = match used {
        NfoEncoding::Cp437 => NfoEncoding::Utf8,
        NfoEncoding::Utf8 => NfoEncoding::Cp437,
    };
    let page = NfoPage {
        layout: Layout::for_session("NFO", &sess),
        id: row.id,
        title: sanitize(&row.title),
        nfo: view,
        other_enc: other.as_str(),
        other_label: other.label(),
        can_delete: sess.role >= nzb_store::Role::Admin,
    };
    match page.render() {
        Ok(body) => axum::response::Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "nfo render failed");
            internal()
        }
    }
}

fn sanitize(s: &str) -> String {
    nzb_core::sanitize_text(s, 512)
}

/// `GET /release/{id}/nfo/download`: the stored bytes as they were uploaded.
pub(crate) async fn download(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Path(id): Path<String>,
) -> Response {
    let (row, nfo) = match load(&st, &sess, &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let full = crate::download::safe_filename(&row.title, row.id);
    let name = format!("{}.nfo", full.strip_suffix(".nzb").unwrap_or(&full));
    let (Ok(cd), Ok(len)) = (
        HeaderValue::from_str(&crate::download::content_disposition(&name)),
        HeaderValue::from_str(&nfo.bytes.len().to_string()),
    ) else {
        return internal();
    };
    let mut resp = Response::new(axum::body::Body::from(nfo.bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_DISPOSITION, cd);
    h.insert(header::CONTENT_LENGTH, len);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// `POST /release/{id}/nfo/delete` (admin; CSRF checked by the session gate). The store re-validates the actor and
/// writes `nfo_remove` in the same transaction.
pub(crate) async fn delete(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    match st.deps.db.get_release(id).await {
        Ok(Some(r)) if !sess.hides_category(r.category_id) => {}
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "release lookup failed");
            return internal();
        }
    }
    match st
        .deps
        .db
        .remove_nfo_as(
            &sess.actor(),
            id,
            st.deps.clock.now_secs(),
            Some(&ip.to_string()),
        )
        .await
    {
        Ok(_) => {}
        Err(StoreError::NotFound | StoreError::Account(_)) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "nfo remove failed");
            return internal();
        }
    }
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(&format!("/release/{id}")) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::parse_enc;
    use nzb_core::NfoEncoding;

    #[test]
    fn enc_query_is_strict() {
        assert_eq!(parse_enc(None), Ok(None));
        assert_eq!(parse_enc(Some("")), Ok(None));
        assert_eq!(parse_enc(Some("enc=cp437")), Ok(Some(NfoEncoding::Cp437)));
        assert_eq!(parse_enc(Some("enc=utf8")), Ok(Some(NfoEncoding::Utf8)));
        for bad in ["enc=UTF8", "enc=latin1", "x=1", "enc=utf8&x=1", "enc="] {
            assert_eq!(parse_enc(Some(bad)), Err(()), "{bad}");
        }
    }
}
