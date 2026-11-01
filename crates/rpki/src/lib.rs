//! ROA import, route validation, scope filter, route preference and the
//! RPKI invalid notifications.
//!
//! - [`importer`]: v4's `ROADataImporter` (ROA JSON, SLURM, the RPKI
//!   pseudo-IRR objects).
//! - [`BulkRouteRoaValidator`] and [`validate_route_single`]: route origin
//!   validation, for imports and for the full re-validation after a ROA
//!   import.
//! - [`ScopeFilterValidator`]: the scope filter.
//! - [`routepref`]: route object preference, including the store hook run
//!   before each commit that touched route objects.
//! - [`notifications`]: mail to contacts of newly invalid objects.
//!
//! The periodic jobs that drive these (`ROAImportRunner`,
//! `ScopeFilterUpdateRunner`, `RoutePreferenceUpdateRunner`) live with the
//! mirroring scheduler in the `nrtm` crate, as they do in v4.

#![deny(unsafe_code)]

pub mod importer;
pub mod messages;
pub mod notifications;
mod roa;
pub mod routepref;
mod scopefilter;

pub use roa::{BulkRouteRoaValidator, RpkiChanges, validate_route_single};
pub use routepref::route_preference_hook;
pub use scopefilter::{ScopeFilterChanges, ScopeFilterConfig, ScopeFilterValidator};
