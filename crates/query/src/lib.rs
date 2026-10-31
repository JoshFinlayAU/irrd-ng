//! Whois query engine, IRRd and RIPE styles, and set expansion.
//!
//! A port of IRRd 4.5.4's `irrd/server/whois/query_parser.py`,
//! `query_response.py` and `irrd/server/query_resolver.py`, with the SQL
//! and Redis preload lookups answered from the store's indexes. Network
//! independent: the whois server and `/v1/whois/` drive a
//! [`WhoisSession`] per connection or request.
//!
//! ```no_run
//! # fn demo(store: &store::Store, settings: std::sync::Arc<query::QuerySettings>) {
//! use query::{NrtmServer, WhoisSession};
//! let mut session = WhoisSession::new(settings, std::sync::Arc::new(NrtmServer), "192.0.2.1", "192.0.2.1:4321");
//! let mut out = Vec::new();
//! session.query_whois(store, "!gAS65537", &mut out);
//! # }
//! ```

#![deny(unsafe_code)]

mod json;
pub mod messages;
pub mod nrtm;
pub mod order;
pub mod parser;
pub mod resolver;
pub mod response;
pub mod settings;
mod status;

pub use nrtm::{NrtmRequest, NrtmServer, NrtmV3};
pub use parser::{SOCKET_DEFAULT_TIMEOUT, WhoisSession};
pub use resolver::{QueryError, QueryResolver, RouteLookupType};
pub use response::{Response, ResponseMode, ResponseType};
pub use settings::{ConfigValue, QuerySettings, SourceQuerySettings};

/// `lookup_field_names()`. v4 builds it as a Python set, so the order in
/// its "not supported" message changes from one start to the next;
/// irrd-ng lists the names sorted.
pub fn lookup_field_names() -> Vec<&'static str> {
    rpsl::lookup_field_names()
}

impl WhoisSession {
    /// Run a whois query and append the bytes v4 would send for it
    /// (`generate_response()`) to `out`.
    ///
    /// A panic while answering is contained here: it is logged with the
    /// query, and the client gets v4's answer to an unexpected exception
    /// in a query (`handle_query()`'s internal error), as if the engine had
    /// raised one.
    pub fn query_whois(
        &mut self,
        store: &store::Store,
        query: &str,
        out: &mut Vec<u8>,
    ) -> Response {
        let start = out.len();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let r = self.handle_query(store, query);
            r.clean(self.result_mut());
            r.render(self.result(), out);
            r
        }));
        match caught {
            Ok(r) => r,
            Err(payload) => {
                out.truncate(start);
                let r = self.panicked(query, payload.as_ref());
                r.render(self.result(), out);
                r
            }
        }
    }

    /// Run a query for `/v1/whois/`: the response after `clean_response()`,
    /// with the text in [`WhoisSession::result`]. Panics are contained as
    /// in [`WhoisSession::query_whois`].
    pub fn query_http(&mut self, store: &store::Store, query: &str) -> Response {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let r = self.handle_query(store, query);
            r.clean(self.result_mut());
            r
        }));
        match caught {
            Ok(r) => r,
            Err(payload) => self.panicked(query, payload.as_ref()),
        }
    }

    fn panicked(&mut self, query: &str, payload: &(dyn std::any::Any + Send)) -> Response {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".to_owned());
        let shown: String = query.chars().take(500).collect();
        tracing::error!(
            target: "irrd.server.whois.query_parser",
            "{}",
            messages::log_exception(&shown, &format!("panic: {msg}"))
        );
        let mode = if query.starts_with('!') {
            ResponseMode::Irrd
        } else {
            ResponseMode::Ripe
        };
        let result = self.result_mut();
        result.clear();
        result.push_str(messages::INTERNAL_ERROR);
        Response {
            response_type: ResponseType::ErrorInternal,
            mode,
            remove_auth_hashes: true,
        }
    }
}
