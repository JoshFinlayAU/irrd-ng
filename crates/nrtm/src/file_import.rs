//! File imports: v4's `MirrorFileImportParser` and
//! `MirrorUpdateFileImportParser` (`irrd/mirroring/parsers.py`).
//!
//! Parsing runs on all cores; everything that depends on order (counters,
//! the first error, strict key-cert re-parsing into the keyring, the order
//! of writes) runs afterwards in file order, so the outcome is v4's.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rpki::{BulkRouteRoaValidator, ScopeFilterValidator};
use rpsl::{Keyring, ParseError, ParseOptions, RpslObject, RpslSettings, Value};
use store::{
    IpPrefix, JournalEntryOrigin, Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus,
    Timestamp, WriteTx,
};

use crate::messages;

/// v4's logger name for these messages.
pub const LOG_TARGET: &str = "irrd.mirroring.parsers";

/// Per-source import settings.
#[derive(Debug, Clone, Default)]
pub struct ImportSettings {
    /// The source being imported.
    pub source: String,
    /// `get_object_class_filter_for_source()`: lower-cased, stripped.
    pub object_class_filter: Option<Vec<String>>,
    /// `sources.X.strict_import_keycert_objects`
    pub strict_import_keycert_objects: bool,
    /// Return on the first error instead of logging and skipping.
    pub direct_error_return: bool,
    /// Keep each object's plain rendering, which the update import compares
    /// against the stored text.
    pub keep_plain_text: bool,
}

/// What the parsers need besides the settings.
#[derive(Debug, Clone, Copy)]
pub struct ParseEnv<'a> {
    /// Parser settings from `irrd.yaml`.
    pub rpsl: &'a RpslSettings,
    /// The keyring key-certs are imported into in strict mode.
    pub keyring: &'a Keyring,
    /// `BulkRouteROAValidator`, if any.
    pub roa_validator: Option<&'a BulkRouteRoaValidator>,
    /// `ScopeFilterValidator`.
    pub scopefilter: &'a ScopeFilterValidator,
}

/// One parsed object, ready to upsert.
#[derive(Debug, Clone)]
pub struct ImportedObject {
    /// The row to upsert.
    pub object: NewRpslObject,
    /// `render_rpsl_text()` without `last_modified`, for update comparisons
    /// (empty unless [`ImportSettings::keep_plain_text`]).
    pub plain_text: String,
}

/// A side effect of parsing, in order.
#[derive(Debug, Clone)]
pub enum ImportAction {
    /// `upsert_rpsl_object(obj, origin=mirror)`
    Upsert(Box<ImportedObject>),
    /// `record_mirror_error(source, error)`
    MirrorError(String),
}

/// v4's import counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// `obj_parsed`
    pub obj_parsed: i64,
    /// `obj_errors`
    pub obj_errors: i64,
    /// `obj_ignored_class`
    pub obj_ignored_class: i64,
    /// `obj_unknown`
    pub obj_unknown: i64,
    /// `unknown_object_classes` (v4 keeps a set, so its log order varies;
    /// this is first-seen order).
    pub unknown_object_classes: Vec<String>,
}

impl Counters {
    /// `obj_parsed - obj_unknown - obj_errors - obj_ignored_class`
    pub fn successful(&self) -> i64 {
        self.obj_parsed - self.obj_unknown - self.obj_errors - self.obj_ignored_class
    }

    /// `log_unknown_object_classes()`
    pub fn log_unknown_object_classes(&self, source: &str) {
        if self.obj_unknown != 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "{}",
                messages::unknown_classes_report(
                    self.obj_unknown,
                    source,
                    &self.unknown_object_classes.join(", ")
                )
            );
        }
    }
}

/// The result of parsing a file.
#[derive(Debug, Clone, Default)]
pub struct ParsedFile {
    /// Upserts and mirror errors, in file order.
    pub actions: Vec<ImportAction>,
    /// Counters.
    pub counters: Counters,
}

/// Why parsing stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// `RPSLImportError` with `direct_error_return`: the message v4 returns.
    Rpsl(String),
    /// An exception v4 does not catch; its message.
    Uncaught(String),
}

enum Prepared {
    Ok(Box<ImportedObject>, bool),
    ParseErrors(String),
    BadSource(String),
    Filtered,
    Unknown(String),
    Legacy,
    Uncaught(String),
}

fn ip_addr(ip: &rpsl::Ip) -> IpAddr {
    if ip.version() == 4 {
        IpAddr::V4(Ipv4Addr::from(ip.int() as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip.int()))
    }
}

/// `parsed_data` as canonical JSON.
pub fn parsed_data_json(obj: &RpslObject) -> Json {
    let mut map = serde_json::Map::new();
    for (k, v) in obj.parsed_data() {
        let jv = match v {
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::List(l) => serde_json::Value::Array(
                l.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        };
        map.insert((*k).to_owned(), jv);
    }
    Json::from_value(&serde_json::Value::Object(map))
}

/// The row v4 upserts for an object, with statuses from the validators.
pub fn new_rpsl_object(
    obj: &RpslObject,
    env: &ParseEnv<'_>,
    last_modified: Timestamp,
) -> Result<NewRpslObject, String> {
    let source = obj.source().map_err(|e| e.to_string())?.to_owned();
    let prefix = obj
        .prefix
        .and_then(|p| IpPrefix::new(ip_addr(&p), p.prefixlen() as u8));
    let mut rpki_status = RpkiStatus::NotFound;
    if let Some(v) = env.roa_validator
        && obj.is_route()
        && let (Some(len), Some(asn), Some(first)) =
            (obj.prefix_length, obj.asn_first, obj.ip_first)
        && len != 0
        && asn != 0
    {
        rpki_status = v.validate_route(ip_addr(&first), len, asn, &source);
    }
    let scopefilter_status = env.scopefilter.validate_rpsl_object(
        &source,
        obj.rpsl_object_class(),
        prefix.as_ref(),
        obj.asn_first,
    );
    Ok(NewRpslObject {
        rpsl_pk: obj.pk(),
        object_class: obj.rpsl_object_class().to_owned(),
        parsed_data: parsed_data_json(obj),
        object_text: obj
            .render_rpsl_text_with_last_modified(last_modified.unix_seconds(), env.rpsl),
        ip_first: obj.ip_first.as_ref().map(ip_addr),
        ip_last: obj.ip_last.as_ref().map(ip_addr),
        prefix,
        prefix_length: obj.prefix_length,
        asn_first: obj.asn_first,
        asn_last: obj.asn_last,
        rpki_status,
        scopefilter_status,
        route_preference_status: RoutePreferenceStatus::Visible,
        source,
    })
}

fn prepare(
    paragraph: &str,
    settings: &ImportSettings,
    env: &ParseEnv<'_>,
    strict: bool,
) -> Prepared {
    let text = rpsl::text::py_strip(paragraph);
    let options = ParseOptions {
        strict,
        default_source: None,
        settings: env.rpsl,
        keyring: env.keyring,
    };
    let obj = match rpsl::rpsl_object_from_text(text, &options) {
        Ok(o) => o,
        Err(ParseError::UnknownClass { class }) => {
            // Legacy IRRd artifacts are not objects at all (irrd4 #232).
            if class.starts_with("*xx") {
                return Prepared::Legacy;
            }
            return Prepared::Unknown(class);
        }
        Err(ParseError::Uncaught(m)) => return Prepared::Uncaught(m),
    };
    let is_keycert = obj.rpsl_object_class() == "key-cert";
    let errors: Vec<String> = obj.messages().errors().map(str::to_owned).collect();
    if !errors.is_empty() {
        return Prepared::ParseErrors(config::str_list_repr(&errors));
    }
    let source = match obj.source() {
        Ok(s) => s,
        Err(e) => return Prepared::Uncaught(e.to_string()),
    };
    if source != settings.source {
        return Prepared::BadSource(messages::invalid_source(
            source,
            &obj.pk(),
            &settings.source,
        ));
    }
    if let Some(filter) = &settings.object_class_filter
        && !filter.iter().any(|c| c == obj.rpsl_object_class())
    {
        return Prepared::Filtered;
    }
    match new_rpsl_object(&obj, env, Timestamp::now()) {
        Ok(object) => Prepared::Ok(
            Box::new(ImportedObject {
                object,
                plain_text: if settings.keep_plain_text {
                    obj.render_rpsl_text()
                } else {
                    String::new()
                },
            }),
            is_keycert,
        ),
        Err(m) => Prepared::Uncaught(m),
    }
}

/// Paragraphs parsed in parallel at a time; bounds memory on large files.
const CHUNK: usize = 1 << 16;

/// Why streaming stopped.
#[derive(Debug)]
pub enum StreamError {
    /// The import itself failed (v4's return value or exception).
    Import(ImportError),
    /// Writing to the store failed.
    Store(store::StoreError),
}

fn parse_parallel(
    paragraphs: &[String],
    settings: &ImportSettings,
    env: &ParseEnv<'_>,
) -> Vec<Prepared> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 32);
    let chunk = paragraphs.len().div_ceil(threads).max(1);
    let mut prepared: Vec<Prepared> = Vec::with_capacity(paragraphs.len());
    std::thread::scope(|scope| {
        let handles: Vec<_> = paragraphs
            .chunks(chunk)
            .map(|c| {
                scope.spawn(move || {
                    c.iter()
                        .map(|p| prepare(p, settings, env, false))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for h in handles {
            match h.join() {
                Ok(v) => prepared.extend(v),
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    });
    prepared
}

/// Parse every paragraph as `MirrorFileImportParserBase.parse_object`
/// does, logging what v4 logs, and hand each resulting action to `sink`
/// in file order. Parsing runs a chunk at a time, so memory stays bounded
/// by the chunk, not the file.
pub fn parse_streaming(
    paragraphs: &[String],
    settings: &ImportSettings,
    env: &ParseEnv<'_>,
    sink: &mut dyn FnMut(ImportAction) -> store::Result<()>,
) -> Result<Counters, StreamError> {
    let mut c = Counters::default();
    let mut unknown_seen = HashSet::new();
    for block in paragraphs.chunks(CHUNK) {
        let prepared = parse_parallel(block, settings, env);
        for (paragraph, mut p) in block.iter().zip(prepared) {
            c.obj_parsed += 1;
            // A key-cert is parsed again strictly, in order, to load it into
            // the keyring.
            if settings.strict_import_keycert_objects && matches!(p, Prepared::Ok(_, true)) {
                p = prepare(paragraph, settings, env, true);
            }
            let fail = |e: ImportError| Err(StreamError::Import(e));
            match p {
                Prepared::Ok(obj, _) => {
                    sink(ImportAction::Upsert(obj)).map_err(StreamError::Store)?
                }
                Prepared::Legacy => c.obj_parsed -= 1,
                Prepared::Unknown(class) => {
                    if settings.direct_error_return {
                        return fail(ImportError::Rpsl(messages::unknown_object_class(&class)));
                    }
                    c.obj_unknown += 1;
                    if unknown_seen.insert(class.clone()) {
                        c.unknown_object_classes.push(class);
                    }
                }
                Prepared::ParseErrors(repr) => {
                    let msg = messages::parsing_errors(&repr, paragraph);
                    if settings.direct_error_return {
                        return fail(ImportError::Rpsl(msg));
                    }
                    sink(ImportAction::MirrorError(msg)).map_err(StreamError::Store)?;
                    tracing::error!(
                        target: LOG_TARGET,
                        critical = true,
                        "{}",
                        messages::parsing_errors_log(&settings.source, &repr, paragraph)
                    );
                    c.obj_errors += 1;
                }
                Prepared::BadSource(msg) => {
                    if settings.direct_error_return {
                        return fail(ImportError::Rpsl(msg));
                    }
                    tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::invalid_source_log(&msg));
                    sink(ImportAction::MirrorError(msg)).map_err(StreamError::Store)?;
                    c.obj_errors += 1;
                }
                Prepared::Filtered => c.obj_ignored_class += 1,
                Prepared::Uncaught(m) => return fail(ImportError::Uncaught(m)),
            }
        }
    }
    Ok(c)
}

/// [`parse_streaming`] into memory.
pub fn parse_paragraphs(
    paragraphs: &[String],
    settings: &ImportSettings,
    env: &ParseEnv<'_>,
) -> Result<ParsedFile, ImportError> {
    let mut actions = Vec::new();
    let counters = parse_streaming(paragraphs, settings, env, &mut |a| {
        actions.push(a);
        Ok(())
    })
    .map_err(|e| match e {
        StreamError::Import(i) => i,
        StreamError::Store(s) => ImportError::Uncaught(s.to_string()),
    })?;
    Ok(ParsedFile { actions, counters })
}

/// `MirrorFileImportParser.run_import()` against a write transaction:
/// parse and upsert as it goes (origin `mirror`), then record the serial
/// if one was given and is not 0.
pub fn run_file_import(
    tx: &mut WriteTx<'_, '_>,
    paragraphs: &[String],
    settings: &ImportSettings,
    env: &ParseEnv<'_>,
    serial: Option<i64>,
) -> Result<Counters, StreamError> {
    let source = settings.source.clone();
    let counters = parse_streaming(paragraphs, settings, env, &mut |a| match a {
        ImportAction::Upsert(o) => {
            tx.upsert_rpsl_object(&o.object, JournalEntryOrigin::Mirror, None, None)
        }
        ImportAction::MirrorError(e) => tx.record_mirror_error(&source, &e),
    })?;
    if let Some(s) = serial
        && s != 0
    {
        tx.record_serial_seen(&source, s)
            .map_err(StreamError::Store)?;
    }
    Ok(counters)
}

/// `MirrorFileImportParser.run_import()`'s database writes: upsert every
/// object with origin `mirror`, record errors, and record the serial if
/// one was given (and is not 0).
pub fn apply_file_import(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    actions: &[ImportAction],
    serial: Option<i64>,
) -> store::Result<()> {
    for a in actions {
        match a {
            ImportAction::Upsert(o) => {
                tx.upsert_rpsl_object(&o.object, JournalEntryOrigin::Mirror, None, None)?
            }
            ImportAction::MirrorError(e) => tx.record_mirror_error(source, e)?,
        }
    }
    if let Some(s) = serial
        && s != 0
    {
        tx.record_serial_seen(source, s)?;
    }
    Ok(())
}

/// `log_report()` of `MirrorFileImportParser`.
pub fn log_file_import_report(source: &str, c: &Counters) {
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::file_import_report(source, c.obj_parsed, c.successful(), c.obj_errors, c.obj_ignored_class)
    );
    c.log_unknown_object_classes(source);
}

/// The counts `MirrorUpdateFileImportParser` adds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpdateCounts {
    /// `obj_new`
    pub obj_new: i64,
    /// `obj_modified`
    pub obj_modified: i64,
    /// `obj_retained`
    pub obj_retained: i64,
    /// `obj_deleted`
    pub obj_deleted: i64,
}

/// `MirrorUpdateFileImportParser.run_import()`'s database work: treat the
/// file as the complete new state of the source, with origin
/// `synthetic_nrtm`.
pub fn apply_update_import(
    tx: &mut WriteTx<'_, '_>,
    source: &str,
    actions: &[ImportAction],
) -> store::Result<UpdateCounts> {
    let mut counts = UpdateCounts::default();
    for a in actions {
        if let ImportAction::MirrorError(e) = a {
            tx.record_mirror_error(source, e)?;
        }
    }
    // A dict keyed on (pk, class): first position, last value.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut by_pk: HashMap<(String, String), &ImportedObject> = HashMap::new();
    for a in actions {
        if let ImportAction::Upsert(o) = a {
            let k = (o.object.rpsl_pk.clone(), o.object.object_class.clone());
            if by_pk.insert(k.clone(), o).is_none() {
                order.push(k);
            }
        }
    }

    let current: BTreeMap<(String, String), ()> = {
        let view = tx.read()?;
        let mut m = BTreeMap::new();
        for item in view.objects(Some(source), None)? {
            let (_, o) = item?;
            m.insert((o.rpsl_pk.to_owned(), o.object_class.to_owned()), ());
        }
        m
    };
    let new: Vec<&(String, String)> = order.iter().filter(|k| !current.contains_key(*k)).collect();
    let deleted: Vec<&(String, String)> =
        current.keys().filter(|k| !by_pk.contains_key(*k)).collect();
    counts.obj_new = new.len() as i64;
    counts.obj_deleted = deleted.len() as i64;
    counts.obj_retained = order.iter().filter(|k| current.contains_key(*k)).count() as i64;

    for k in &new {
        tx.upsert_rpsl_object(
            &by_pk[*k].object,
            JournalEntryOrigin::SyntheticNrtm,
            None,
            None,
        )?;
    }
    for (pk, class) in deleted {
        tx.delete_rpsl_object(
            source,
            pk,
            class,
            JournalEntryOrigin::SyntheticNrtm,
            None,
            false,
        )?;
    }

    // Every row of the source is compared, including the ones just
    // inserted, as v4's query runs after the inserts.
    let rows: Vec<((String, String), String)> = {
        let view = tx.read()?;
        let mut v = Vec::new();
        for item in view.objects(Some(source), None)? {
            let (_, o) = item?;
            v.push((
                (o.rpsl_pk.to_owned(), o.object_class.to_owned()),
                o.object_text.to_owned(),
            ));
        }
        v
    };
    for (k, text) in rows {
        let Some(file_obj) = by_pk.get(&k) else {
            continue;
        };
        if file_obj.plain_text != remove_last_modified(&text) {
            tx.upsert_rpsl_object(
                &file_obj.object,
                JournalEntryOrigin::SyntheticNrtm,
                None,
                None,
            )?;
            counts.obj_modified += 1;
        }
    }
    Ok(counts)
}

/// `log_report()` of `MirrorUpdateFileImportParser`.
pub fn log_update_report(source: &str, filename: &str, c: &Counters, u: &UpdateCounts) {
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::file_update_report(
            source,
            c.obj_parsed,
            c.successful(),
            u.obj_new,
            u.obj_deleted,
            u.obj_retained,
            u.obj_modified,
            c.obj_errors,
            c.obj_ignored_class,
            filename
        )
    );
    c.log_unknown_object_classes(source);
}

/// `remove_last_modified()`: drop every line matching
/// `^last-modified: [^\n]+\n`.
pub fn remove_last_modified(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let drop = line.ends_with('\n')
            && line
                .strip_prefix("last-modified: ")
                .is_some_and(|rest| rest.len() > 1);
        if !drop {
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_last_modified_matches_v4_regex() {
        let t = "route:          192.0.2.0/24\nlast-modified:  2020-01-01T00:00:00Z\nsource: X\nlast-modified: \nlast-modified: x";
        assert_eq!(
            remove_last_modified(t),
            "route:          192.0.2.0/24\nsource: X\nlast-modified: \nlast-modified: x"
        );
    }
}
