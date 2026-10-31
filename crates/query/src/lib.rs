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
//! use query::{NrtmNotServed, WhoisSession};
//! let mut session = WhoisSession::new(settings, std::sync::Arc::new(NrtmNotServed), "192.0.2.1", "192.0.2.1:4321");
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

pub use nrtm::{NrtmNotServed, NrtmRequest, NrtmV3};
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
    pub fn query_whois(
        &mut self,
        store: &store::Store,
        query: &str,
        out: &mut Vec<u8>,
    ) -> Response {
        let r = self.handle_query(store, query);
        r.clean(self.result_mut());
        r.render(self.result(), out);
        r
    }

    /// Run a query for `/v1/whois/`: the response after `clean_response()`,
    /// with the text in [`WhoisSession::result`].
    pub fn query_http(&mut self, store: &store::Store, query: &str) -> Response {
        let r = self.handle_query(store, query);
        r.clean(self.result_mut());
        r
    }
}
