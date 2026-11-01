//! `/static/`: Starlette's `StaticFiles` for the files the GraphiQL
//! explorer loads (`irrd/webui/static/js/graphiql/`). The rest of v4's
//! static files belong to the web UI, a later phase.
//!
//! The files are byte-identical copies of v4's in `assets/graphiql/`, with
//! their origins and licences, so that a source tarball builds without the
//! `vendor/irrd-v4` submodule. A test checks the copies against the
//! submodule when it is present.
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
            include_bytes!(concat!("../assets/graphiql/", $name)).as_slice(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The copies in `assets/graphiql/` and `src/graphiql.html` must stay
    /// byte-identical to v4's files at the pinned tag. Skipped when the
    /// submodule is not checked out (a source tarball).
    #[test]
    fn graphiql_assets_match_vendor() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let v4 = crate_dir.join("../../vendor/irrd-v4/irrd");
        let v4_assets = v4.join("webui/static/js/graphiql");
        if !v4_assets.is_dir() {
            eprintln!("vendor/irrd-v4 is not checked out; skipping the comparison");
            return;
        }
        let mut names: Vec<String> = std::fs::read_dir(&v4_assets)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut served: Vec<String> = ASSETS
            .iter()
            .map(|(p, _)| p.trim_start_matches("/static/js/graphiql/").to_owned())
            .collect();
        served.sort();
        assert_eq!(served, names, "v4's GraphiQL file list changed");
        for (path, data) in ASSETS {
            let name = path.trim_start_matches("/static/js/graphiql/");
            let theirs = std::fs::read(v4_assets.join(name)).unwrap();
            assert!(
                *data == theirs.as_slice(),
                "assets/graphiql/{name} differs from v4's copy"
            );
        }
        let html = std::fs::read(v4.join("server/graphql/graphiql.html")).unwrap();
        assert!(
            crate::gql::GRAPHIQL_HTML.as_bytes() == html.as_slice(),
            "src/graphiql.html differs from v4's irrd/server/graphql/graphiql.html"
        );
    }
}
