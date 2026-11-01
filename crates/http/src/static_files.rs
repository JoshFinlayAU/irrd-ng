//! `/static/`: Starlette's `StaticFiles` for the files the GraphiQL
//! explorer loads (`irrd/webui/static/js/graphiql/`). The rest of v4's
//! static files belong to the web UI, a later phase.
//!
//! `last-modified` and `etag` come from the file's modification time in
//! v4, which differs on every installation; irrd-ng uses the date of the
//! pinned v4 release.

use bytes::Bytes;
use hyper::{Method, StatusCode};
use md5::{Digest, Md5};

use crate::Reply;

/// The release date of v4.5.4, as a Unix time.
const MTIME: i64 = 1_792_368_000;

macro_rules! asset {
    ($name:literal) => {
        (
            concat!("/static/js/graphiql/", $name),
            include_bytes!(concat!(
                "../../../vendor/irrd-v4/irrd/webui/static/js/graphiql/",
                $name
            ))
            .as_slice(),
        )
    };
}

const ASSETS: &[(&str, &[u8])] = &[
    asset!("graphiql.min.css"),
    asset!("graphiql.min.js"),
    asset!("mount.js"),
    asset!("page.css"),
    asset!("plugin-explorer.style.css"),
    asset!("plugin-explorer.umd.js"),
    asset!("react-dom.production.min.js"),
    asset!("react.production.min.js"),
];

fn content_type(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// `StaticFiles.get_response()`
pub(crate) fn serve(method: &Method, path: &str) -> Reply {
    if *method != Method::GET && *method != Method::HEAD {
        return Reply::text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    }
    let Some((_, data)) = ASSETS.iter().find(|(p, _)| *p == path) else {
        return Reply::text(StatusCode::NOT_FOUND, "Not Found");
    };
    let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(MTIME as u64);
    let etag_base = format!("{MTIME}.0-{}", data.len());
    let etag: String = Md5::digest(etag_base.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut r = Reply::empty(StatusCode::OK);
    r.headers = vec![
        ("content-type", content_type(path).to_owned()),
        ("accept-ranges", "bytes".to_owned()),
        ("content-length", data.len().to_string()),
        ("last-modified", httpdate::fmt_http_date(mtime)),
        ("etag", format!("\"{etag}\"")),
    ];
    r.body = Bytes::from_static(data);
    r
}
