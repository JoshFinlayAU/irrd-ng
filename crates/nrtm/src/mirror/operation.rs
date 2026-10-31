//! `NRTMOperation` (`irrd/mirroring/nrtm_operation.py`): one ADD/DEL from
//! an NRTMv3 stream or an NRTMv4 delta.
//!
//! The object text is parsed and checked outside the write transaction
//! ([`prepare`]); [`apply`] then does what `save()` does to the database,
//! inside it, logging as v4 logs while it saves.

use rpki::ScopeFilterValidator;
use rpsl::{Keyring, ParseError, ParseOptions, RpslSettings};
use store::{IpPrefix, JournalEntryOrigin, NewRpslObject, RpkiStatus, Timestamp, WriteTx};

use crate::file_import::{self, ParseEnv};
use crate::messages;
use crate::mirror::nrtm3::Operation;
use crate::mirror::pyerr::PyErr;

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.nrtm_operation";

/// What `NRTMOperation(...)` is constructed with.
#[derive(Debug, Clone)]
pub struct NrtmOperation {
    /// `source`
    pub source: String,
    /// `operation`
    pub operation: Operation,
    /// `serial`: the NRTMv3 serial, `None` for NRTMv4.
    pub serial: Option<i64>,
    /// `origin_identifier`, defaulting to the serial.
    pub origin_identifier: String,
    /// `object_text`
    pub object_text: Option<String>,
    /// `rpsl_pk`, for NRTMv4 deletions.
    pub rpsl_pk: Option<String>,
    /// `object_class`, for NRTMv4 deletions.
    pub object_class: Option<String>,
    /// `strict_validation_key_cert`
    pub strict_validation_key_cert: bool,
    /// `rpki_aware`
    pub rpki_aware: bool,
    /// `object_class_filter`
    pub object_class_filter: Option<Vec<String>>,
}

impl NrtmOperation {
    /// `str(self)`: `source/origin_identifier/ADD`.
    pub fn repr(&self) -> String {
        messages::nrtm_operation_repr(
            &self.source,
            &self.origin_identifier,
            self.operation.value(),
        )
    }
}

/// What the parsers need.
#[derive(Debug, Clone, Copy)]
pub struct OperationEnv<'a> {
    /// Parser settings.
    pub rpsl: &'a RpslSettings,
    /// The key-cert keyring.
    pub keyring: &'a Keyring,
    /// `ScopeFilterValidator`
    pub scopefilter: &'a ScopeFilterValidator,
    /// `get_setting(f"sources.{source}.rpki_excluded")`
    pub rpki_excluded: bool,
}

/// What `save()` will do, decided before the transaction.
#[derive(Debug, Clone)]
pub enum Prepared {
    /// `save()` returns False; an info line may be logged.
    Ignored(Option<String>),
    /// Parser errors or a wrong source: a critical log line and a mirror
    /// error.
    Rejected {
        /// The critical log line.
        log: String,
        /// The mirror error recorded.
        mirror_error: String,
    },
    /// `upsert_rpsl_object(obj, mirror, source_serial=serial)`.
    Upsert {
        /// The row, with the scope filter status set; the RPKI status is
        /// set in [`apply`].
        object: Box<NewRpslObject>,
        /// The route to validate against ROAs, if v4 would.
        rpki_route: Option<(IpPrefix, u32)>,
        /// "Completed NRTM operation ..." without the RPKI part.
        completed: String,
        /// Whether the RPKI part is logged.
        log_rpki: bool,
    },
    /// `delete_rpsl_object(source, rpsl_pk, object_class, mirror, serial)`.
    Delete {
        /// `rpsl_pk`
        rpsl_pk: String,
        /// `object_class`
        object_class: String,
        /// "Completed NRTM operation ..." with the RPKI part, if any.
        completed: String,
    },
}

/// One prepared operation.
#[derive(Debug, Clone)]
pub struct PreparedOperation {
    /// The source.
    pub source: String,
    /// The serial passed as `source_serial`.
    pub serial: Option<i64>,
    /// The outcome.
    pub prepared: Prepared,
}

fn ip_prefix(obj: &rpsl::RpslObject) -> Option<IpPrefix> {
    let p = obj.prefix?;
    let addr = if p.version() == 4 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(p.int() as u32))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(p.int()))
    };
    IpPrefix::new(addr, p.prefixlen() as u8)
}

/// The parsing half of `save()`.
pub fn prepare(op: &NrtmOperation, env: &OperationEnv<'_>) -> Result<PreparedOperation, PyErr> {
    let done = |prepared| {
        Ok(PreparedOperation {
            source: op.source.clone(),
            serial: op.serial,
            prepared,
        })
    };
    let default_source = (op.operation == Operation::Del).then_some(op.source.as_str());
    let mut obj = None;
    let mut rpsl_pk = op.rpsl_pk.clone().unwrap_or_default();
    let mut object_class = op.object_class.clone().unwrap_or_default();
    if let Some(text) = op.object_text.as_deref().filter(|t| !t.is_empty()) {
        let text = rpsl::text::py_strip(text);
        let parse = |strict: bool| {
            rpsl::rpsl_object_from_text(
                text,
                &ParseOptions {
                    strict,
                    default_source,
                    settings: env.rpsl,
                    keyring: env.keyring,
                },
            )
        };
        let parsed = match parse(false) {
            Ok(o) if op.strict_validation_key_cert && o.rpsl_object_class() == "key-cert" => {
                parse(true)
            }
            other => other,
        };
        match parsed {
            Ok(o) => {
                rpsl_pk = o.pk();
                object_class = o.rpsl_object_class().to_lowercase();
                obj = Some(o);
            }
            Err(ParseError::UnknownClass { class }) => {
                let lower = class.to_lowercase();
                let log = match &op.object_class_filter {
                    Some(f) if !f.iter().any(|c| *c == lower) => None,
                    _ => Some(messages::ignoring_nrtm_operation(
                        &op.repr(),
                        &ParseError::UnknownClass {
                            class: class.clone(),
                        }
                        .to_string(),
                    )),
                };
                return done(Prepared::Ignored(log));
            }
            Err(ParseError::Uncaught(m)) => return Err(PyErr::Other(m)),
        }
    }
    if let Some(filter) = &op.object_class_filter
        && !filter.iter().any(|c| *c == object_class.to_lowercase())
    {
        return done(Prepared::Ignored(None));
    }
    if let Some(o) = &obj {
        let errors: Vec<String> = o.messages().errors().map(str::to_owned).collect();
        if !errors.is_empty() {
            let original = op.object_text.clone().unwrap_or_default();
            return done(Prepared::Rejected {
                log: messages::nrtm_operation_parsing_errors(
                    &op.repr(),
                    &errors.join("; "),
                    &original,
                ),
                mirror_error: messages::parsing_errors(&config::str_list_repr(&errors), &original),
            });
        }
        if let Some(rpsl::Value::Str(s)) = o.parsed_value("source")
            && s.to_uppercase() != op.source
        {
            let msg = messages::nrtm_incorrect_source(
                &op.source,
                o.source().unwrap_or_default(),
                &op.origin_identifier,
                op.operation.value(),
                &o.pk(),
            );
            return done(Prepared::Rejected {
                log: msg.clone(),
                mirror_error: msg,
            });
        }
    }
    let completed = messages::completed_nrtm_operation(&op.repr(), &object_class, &rpsl_pk);
    let route_logged = |o: &rpsl::RpslObject| op.rpki_aware && o.is_route();
    match (op.operation, obj) {
        (Operation::Add, Some(o)) => {
            let parse_env = ParseEnv {
                rpsl: env.rpsl,
                keyring: env.keyring,
                roa_validator: None,
                scopefilter: env.scopefilter,
            };
            let object = file_import::new_rpsl_object(&o, &parse_env, Timestamp::now())
                .map_err(PyErr::Other)?;
            let rpki_route = if op.rpki_aware && o.is_route() {
                match (ip_prefix(&o), o.asn_first) {
                    (Some(p), Some(asn)) if asn != 0 => Some((p, asn)),
                    _ => None,
                }
            } else {
                None
            };
            done(Prepared::Upsert {
                object: Box::new(object),
                rpki_route,
                completed,
                log_rpki: route_logged(&o),
            })
        }
        (Operation::Del, o) => {
            let mut completed = completed;
            if let Some(o) = &o
                && route_logged(o)
            {
                completed.push_str(&messages::completed_rpki_status(
                    RpkiStatus::NotFound.py_value(),
                ));
            }
            done(Prepared::Delete {
                rpsl_pk,
                object_class,
                completed,
            })
        }
        // An ADD always carries object text.
        (Operation::Add, None) => done(Prepared::Ignored(None)),
    }
}

/// The database half of `save()`, inside the transaction. Returns whether
/// the operation was saved.
pub fn apply(
    tx: &mut WriteTx<'_, '_>,
    op: &PreparedOperation,
    rpki_excluded: bool,
) -> store::Result<bool> {
    match &op.prepared {
        Prepared::Ignored(log) => {
            if let Some(l) = log {
                tracing::info!(target: LOG_TARGET, "{l}");
            }
            Ok(false)
        }
        Prepared::Rejected { log, mirror_error } => {
            // v4 records the error before or after logging; both land.
            tracing::error!(target: LOG_TARGET, critical = true, "{log}");
            tx.record_mirror_error(&op.source, mirror_error)?;
            Ok(false)
        }
        Prepared::Upsert {
            object,
            rpki_route,
            completed,
            log_rpki,
        } => {
            let mut object = (**object).clone();
            if let Some((prefix, asn)) = rpki_route {
                object.rpki_status =
                    rpki::validate_route_single(&tx.read_unflushed(), prefix, *asn, rpki_excluded)?;
            }
            tx.upsert_rpsl_object(&object, JournalEntryOrigin::Mirror, op.serial, None)?;
            let mut line = completed.clone();
            if *log_rpki {
                line.push_str(&messages::completed_rpki_status(
                    object.rpki_status.py_value(),
                ));
            }
            tracing::info!(target: LOG_TARGET, "{line}");
            Ok(true)
        }
        Prepared::Delete {
            rpsl_pk,
            object_class,
            completed,
        } => {
            tx.delete_rpsl_object(
                &op.source,
                rpsl_pk,
                object_class,
                JournalEntryOrigin::Mirror,
                op.serial,
                false,
            )?;
            tracing::info!(target: LOG_TARGET, "{completed}");
            Ok(true)
        }
    }
}
