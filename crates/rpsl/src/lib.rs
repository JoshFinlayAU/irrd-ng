//! RPSL parser, object model and validation. No I/O.
//!
//! A port of IRRd 4.5.4's `irrd/rpsl` package and the text helpers it relies
//! on. For any paragraph, [`rpsl_object_from_text`] produces what v4
//! produces: the object class, primary key, source, `parsed_data`, every
//! INFO/ERROR message in order with identical text, the rendered object
//! text, address and AS number metadata, and strong references, in strict
//! and non-strict mode.
//!
//! ```
//! use rpsl::{Keyring, ParseOptions, RpslSettings, rpsl_object_from_text};
//!
//! let settings = RpslSettings::default();
//! let keyring = Keyring::new();
//! let options = ParseOptions { strict: false, default_source: None, settings: &settings, keyring: &keyring };
//! let obj = rpsl_object_from_text(
//!     "route: 192.0.2.0/24\norigin: as65537\nsource: test",
//!     &options,
//! ).unwrap();
//! assert_eq!(obj.pk(), "192.0.2.0/24AS65537");
//! assert_eq!(obj.messages().all().len(), 1); // INFO: AS number reformatted
//! assert_eq!(obj.render_rpsl_text(), "route:          192.0.2.0/24\norigin:         AS65537\nsource:         test\n");
//! ```

#![deny(unsafe_code)]

pub mod classes;
pub mod fields;
pub mod ipy;
pub mod messages;
pub mod parser;
pub mod parser_state;
pub mod pgp;
mod py;
pub mod settings;
mod template;
pub mod text;
pub mod validators;

pub use classes::{ClassDef, OBJECT_CLASSES, class_by_name, lookup_field_names};
pub use fields::{FieldDef, FieldKind, bcrypt_hash_error};
pub use ipy::Ip;
pub use parser::{
    ObjectAttr, ParseError, ParseOptions, RpslObject, Value, format_fingerprint,
    rpsl_object_from_text,
};
pub use parser_state::{Level, Messages};
pub use pgp::Keyring;
pub use settings::{HasherAvailability, PasswordHasher, RpslSettings, SourceRenderSettings};
pub use text::{decode_rpsl_file, split_paragraphs_rpsl, split_rpsl_file, splitline_unicodesafe};
pub use validators::parse_as_number;
