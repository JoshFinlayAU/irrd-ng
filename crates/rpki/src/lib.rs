//! ROA import, route validation, scope filter and route preference.
//!
//! Phase 2 carries what the file loaders need: [`BulkRouteRoaValidator`]
//! (v4's `BulkRouteROAValidator.validate_route`) over the store's ROA table
//! and [`ScopeFilterValidator`]. ROA import, the RPKI pseudo-IRR source and
//! route preference evaluation come in Phase 5.

#![deny(unsafe_code)]

pub mod messages;
mod roa;
mod scopefilter;

pub use roa::BulkRouteRoaValidator;
pub use scopefilter::{ScopeFilterConfig, ScopeFilterValidator};
