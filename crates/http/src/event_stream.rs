//! The event stream (`irrd/server/http/event_stream.py`): the
//! WebSocket at `/v1/event-stream/` and `/v1/event-stream/initial/`.
//!
//! v4 signals new journal entries and full reloads through a Redis stream
//! (`irrd-eventstream-rpsl-stream`, at most 1000 entries). irrd-ng keeps
//! the same stream in process: the store publishes a `journal_extended`
//! event per source after each commit that added journal entries, and the
//! mirror runner a `full_reload` event, with Redis-style ids
//! (`<milliseconds>-<sequence>`).
//!
//! Followers hold no long read transaction: each poll of the journal opens
//! its own, as v4 runs a fresh query each time, so LMDB can reuse pages.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use hyper::StatusCode;
use store::Timestamp;
use tokio::sync::{Notify, mpsc};

use crate::{HttpSettings, HttpState, Reply, messages, query_param};

/// `REDIS_STREAM_MAX_LEN`
const STREAM_MAX_LEN: usize = 1000;
/// `EVENT_STREAM_MAX_WAIT_MS`
const MAX_WAIT: std::time::Duration = std::time::Duration::from_millis(60_000);

/// One stream entry: (id, source, operation).
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub id: (u64, u64),
    pub source: String,
    pub operation: String,
}

#[derive(Debug, Default)]
struct Inner {
    log: Mutex<VecDeque<Entry>>,
    notify: Notify,
}

/// The in-process event stream.
#[derive(Debug, Clone, Default)]
pub struct Events {
    inner: Arc<Inner>,
}

impl Events {
    /// An empty stream.
    pub fn new() -> Self {
        Events::default()
    }

    /// `XADD`: append an event with the next id.
    pub fn publish(&self, source: &str, operation: &str) {
        let ms = u64::try_from(Timestamp::now().micros() / 1000).unwrap_or(0);
        if let Ok(mut log) = self.inner.log.lock() {
            let id = match log.back() {
                Some(last) if last.id.0 >= ms => (last.id.0, last.id.1 + 1),
                _ => (ms, 0),
            };
            log.push_back(Entry {
                id,
                source: source.to_owned(),
                operation: operation.to_owned(),
            });
            while log.len() > STREAM_MAX_LEN {
                log.pop_front();
            }
        }
        self.inner.notify.notify_waiters();
    }

    /// A store listener publishing `journal_extended` for each source.
    pub fn store_listener(&self) -> store::EventListener {
        let me = self.clone();
        Arc::new(move |source: &str, operation: &str| me.publish(source, operation))
    }

    /// The id of the newest entry (`$`).
    fn last_id(&self) -> (u64, u64) {
        self.inner
            .log
            .lock()
            .ok()
            .and_then(|l| l.back().map(|e| e.id))
            .unwrap_or((0, 0))
    }

    /// Entries after `after`, at most 1000.
    fn after(&self, after: (u64, u64)) -> Vec<Entry> {
        self.inner
            .log
            .lock()
            .map(|l| {
                l.iter()
                    .filter(|e| e.id > after)
                    .take(1000)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `XREAD BLOCK 60000`: entries after `after`, waiting for one.
    async fn read(&self, after: (u64, u64)) -> Vec<Entry> {
        let notified = self.inner.notify.notified();
        let now = self.after(after);
        if !now.is_empty() {
            return now;
        }
        let _ = tokio::time::timeout(MAX_WAIT, notified).await;
        self.after(after)
    }
}

// ---- ujson ----

/// `ujson.encode()`: compact, ASCII only, `/` escaped.
pub(crate) fn ujson(v: &graphql::Value) -> String {
    let mut out = String::new();
    ujson_into(v, &mut out);
    out
}

fn ujson_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) >= 0x80 => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ujson_into(v: &graphql::Value, out: &mut String) {
    use graphql::Value as V;
    match v {
        V::Null => out.push_str("null"),
        V::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        V::Int(i) => {
            let _ = write!(out, "{i}");
        }
        V::BigInt(s) => out.push_str(s),
        V::Float(f) => out.push_str(&graphql::value::float_repr(*f)),
        V::Str(s) => ujson_str(s, out),
        V::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ujson_into(x, out);
            }
            out.push(']');
        }
        V::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ujson_str(k, out);
                out.push(':');
                ujson_into(x, out);
            }
            out.push('}');
        }
    }
}

/// `datetime.isoformat()` of a UTC timestamp.
fn isoformat(t: Timestamp) -> String {
    query::status::isoformat(t)
}

/// PostgreSQL's text output of a `timestamptz` in UTC, as `COPY ... CSV`
/// writes it: fractional seconds without trailing zeros, offset `+00`.
fn pg_timestamptz(t: Timestamp) -> String {
    let s = t.to_string();
    let (date_time, _) = s.split_at(26);
    let (base, frac) = date_time.split_at(19);
    let frac = frac.trim_start_matches('.').trim_end_matches('0');
    let mut out = base.replacen('T', " ", 1);
    if !frac.is_empty() {
        out.push('.');
        out.push_str(frac);
    }
    out.push_str("+00");
    out
}

/// `datetime.utcnow().isoformat()`: naive, microseconds only when not 0.
fn utcnow_isoformat() -> String {
    let s = isoformat(Timestamp::now());
    s.trim_end_matches("+00:00").to_owned()
}

// ---- /v1/event-stream/initial/ ----

/// `EventStreamInitialDownloadEndpoint.get()`
pub(crate) fn initial_download(
    state: Arc<HttpState>,
    settings: &HttpSettings,
    _host: &str,
    raw_query: Option<&str>,
) -> Reply {
    let sources = query_param(raw_query, "sources");
    let object_classes = query_param(raw_query, "object_classes");
    // set(request.query_params.keys()) - {"sources", "object_classes"}
    let mut unknown: Vec<String> = Vec::new();
    if let Some(raw) = raw_query {
        for pair in raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let k = pair.split_once('=').map_or(pair, |(k, _)| k);
            let k = crate::unquote_plus(k);
            if k != "sources" && k != "object_classes" && !unknown.contains(&k) {
                unknown.push(k);
            }
        }
    }
    if !unknown.is_empty() {
        return Reply::text(
            StatusCode::BAD_REQUEST,
            messages::unknown_get_parameters(&unknown.join(", ")),
        );
    }
    let split = |v: Option<String>| -> Vec<String> {
        match v {
            Some(s) if !s.is_empty() => s.split(',').map(str::to_owned).collect(),
            _ => Vec::new(),
        }
    };
    let sources = split(sources);
    let object_classes = split(object_classes);
    let hostname = settings.hostname.clone();
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    tokio::task::spawn_blocking(move || {
        let _ = stream_initial(&state, &sources, &object_classes, &hostname, &tx);
    });
    let mut r = Reply::empty(StatusCode::OK);
    r.headers = vec![("content-type", "application/jsonl+json".to_owned())];
    r.stream = Some(rx);
    r
}

fn stream_initial(
    state: &HttpState,
    sources: &[String],
    object_classes: &[String],
    hostname: &str,
    tx: &mpsc::Sender<Bytes>,
) -> store::Result<()> {
    use graphql::Value as V;
    // One read transaction for the header and every row, as v4 runs them
    // in one database transaction.
    let rtx = state.store.read()?;
    let view = rtx.view();
    let max_serial = view.max_serial_global()?;
    let max_ts = view.max_journal_timestamp()?;
    let header = V::Object(vec![
        (
            "data_type".into(),
            V::str("irrd_event_stream_initial_download"),
        ),
        (
            "sources_filter".into(),
            V::List(sources.iter().map(|s| V::Str(s.clone())).collect()),
        ),
        (
            "object_classes_filter".into(),
            V::List(object_classes.iter().map(|s| V::Str(s.clone())).collect()),
        ),
        (
            "max_serial_global".into(),
            max_serial.map_or(V::Null, |s| V::Int(i128::from(s))),
        ),
        (
            "last_change_timestamp".into(),
            max_ts.map_or(V::Null, |t| V::Str(isoformat(t))),
        ),
        ("generated_at".into(), V::Str(utcnow_isoformat())),
        ("generated_on".into(), V::str(hostname)),
    ]);
    if tx
        .blocking_send(Bytes::from(ujson(&header) + "\n"))
        .is_err()
    {
        return Ok(());
    }
    let upper_sources: Vec<String> = sources
        .iter()
        .map(|s| rpsl::python::strip(&rpsl::python::upper(s)).to_owned())
        .collect();
    let mut q = query::objects::ObjectQuery {
        rpki: Some(vec![store::RpkiStatus::NotFound, store::RpkiStatus::Valid]),
        scope: Some(vec![store::ScopeFilterStatus::InScope]),
        routepref: Some(vec![store::RoutePreferenceStatus::Visible]),
        ..Default::default()
    };
    if !sources.is_empty() {
        q.sources = Some(upper_sources);
    }
    if !object_classes.is_empty() {
        q.object_classes(object_classes.to_vec());
    }
    let settings = state.query.read().map(|s| s.clone()).unwrap_or_default();
    let found = q
        .execute(&view, &settings)
        .map_err(|e| store::StoreError::Aborted(format!("{e:?}")))?;
    let mut chunk = String::new();
    for (_, o) in found {
        let mut parsed = graphql::value::json_loads_str(o.parsed_data).unwrap_or(V::Null);
        if let V::Object(fields) = &mut parsed {
            for (k, v) in fields.iter_mut() {
                if k == "auth"
                    && let V::List(items) = v
                {
                    for i in items.iter_mut() {
                        if let V::Str(s) = i {
                            *s = rpsl::text::remove_auth_hashes(s).into_owned();
                        }
                    }
                }
            }
        }
        let row = V::Object(vec![
            // `pk` is the first selected column, `rpsl_pk`.
            ("pk".into(), V::str(o.rpsl_pk)),
            ("object_class".into(), V::str(o.object_class)),
            (
                "object_text".into(),
                V::Str(rpsl::text::remove_auth_hashes(o.object_text).into_owned()),
            ),
            ("source".into(), V::str(o.source)),
            ("updated".into(), V::Str(pg_timestamptz(o.updated))),
            ("parsed_data".into(), parsed),
        ]);
        chunk.push_str(&ujson(&row));
        chunk.push('\n');
        if chunk.len() >= 64 * 1024
            && tx
                .blocking_send(Bytes::from(std::mem::take(&mut chunk)))
                .is_err()
        {
            return Ok(());
        }
    }
    if !chunk.is_empty() {
        let _ = tx.blocking_send(Bytes::from(chunk));
    }
    Ok(())
}

// ---- the WebSocket session ----

/// A message to send: text, sent as is.
pub(crate) type Outbox = mpsc::Sender<String>;

/// `EventStreamEndpoint.send_header()`: the `stream_status` message.
pub(crate) fn stream_status(state: &HttpState, settings: &HttpSettings) -> store::Result<String> {
    use graphql::Value as V;
    let journaled = &settings.journaled_sources;
    let rtx = state.store.read()?;
    let view = rtx.view();
    let rows = query::QueryResolver::status_rows(&view, journaled)
        .map_err(|e| store::StoreError::Aborted(format!("{e:?}")))?;
    let mut times: Vec<(String, V)> = Vec::new();
    for r in rows {
        let iso = isoformat(r.created);
        match times.iter_mut().find(|(k, _)| *k == r.source) {
            Some(e) => e.1 = V::Str(iso),
            None => times.push((r.source.clone(), V::Str(iso))),
        }
    }
    Ok(ujson(&V::Object(vec![
        ("message_type".into(), V::str("stream_status")),
        (
            "streamed_sources".into(),
            V::List(journaled.iter().map(|s| V::Str(s.clone())).collect()),
        ),
        ("last_reload_times".into(), V::Object(times)),
    ])))
}

/// The answer to a subscription request: a follower to start, or an
/// error message to send (and whether to close with 1003).
pub(crate) enum Subscribe {
    /// Start following after this global serial (`None`: v4's task fails
    /// on `None + 1` and sends nothing).
    Follow(Option<i64>),
    /// Send this (with `json.dumps`) and close with 1003.
    Invalid(String),
    /// Send this with `ujson.encode` and do not start.
    TooHigh(String),
}

/// `EventStreamSubscriptionRequest.model_validate_json()` and the checks
/// in `AsyncEventStreamFollower.create()`.
pub(crate) fn subscribe(state: &HttpState, data: &str) -> Subscribe {
    use graphql::Value as V;
    let invalid = |errors: V| -> Subscribe {
        let msg = V::Object(vec![
            ("message_type".into(), V::str("invalid_request")),
            ("errors".into(), errors),
        ]);
        Subscribe::Invalid(graphql::value::json_dumps(&msg))
    };
    let err = |ty: &str, loc: Vec<V>, msg: &str, input: V, ctx: Option<V>| -> V {
        let mut o = vec![
            ("type".into(), V::str(ty)),
            ("loc".into(), V::List(loc)),
            ("msg".into(), V::str(msg)),
            ("input".into(), input),
        ];
        if let Some(c) = ctx {
            o.push(("ctx".into(), c));
        }
        o.push((
            "url".into(),
            V::Str(format!("https://errors.pydantic.dev/2.12/v/{ty}")),
        ));
        V::Object(o)
    };
    let Some(parsed) = graphql::value::json_loads_str(data) else {
        let e = crate::pydantic::json_error(data);
        return invalid(V::List(vec![err(
            "json_invalid",
            vec![],
            &format!("Invalid JSON: {e}"),
            V::str(data),
            Some(V::Object(vec![("error".into(), V::Str(e))])),
        )]));
    };
    let V::Object(_) = &parsed else {
        return invalid(V::List(vec![err(
            "model_type",
            vec![],
            "Input should be an object",
            parsed,
            Some(V::Object(vec![(
                "class_name".into(),
                V::str("EventStreamSubscriptionRequest"),
            )])),
        )]));
    };
    let mut errors = Vec::new();
    match parsed.get("message_type") {
        None => errors.push(err(
            "missing",
            vec![V::str("message_type")],
            "Field required",
            parsed.clone(),
            None,
        )),
        Some(V::Str(s)) if s == "subscribe" => {}
        Some(other) => errors.push(err(
            "literal_error",
            vec![V::str("message_type")],
            "Input should be 'subscribe'",
            other.clone(),
            Some(V::Object(vec![("expected".into(), V::str("'subscribe'"))])),
        )),
    }
    let mut after: Option<i64> = None;
    match parsed.get("after_global_serial") {
        None | Some(V::Null) => {}
        Some(V::Int(i)) => after = i64::try_from(*i).ok(),
        Some(V::Float(f)) if f.fract() == 0.0 && f.is_finite() => after = Some(*f as i64),
        Some(V::Float(f)) => errors.push(err(
            "int_from_float",
            vec![V::str("after_global_serial")],
            "Input should be a valid integer, got a number with a fractional part",
            V::Float(*f),
            None,
        )),
        Some(V::Str(s)) => match s.trim().parse::<i64>() {
            Ok(i) => after = Some(i),
            Err(_) => errors.push(err(
                "int_parsing",
                vec![V::str("after_global_serial")],
                "Input should be a valid integer, unable to parse string as an integer",
                V::Str(s.clone()),
                None,
            )),
        },
        Some(other) => errors.push(err(
            "int_type",
            vec![V::str("after_global_serial")],
            "Input should be a valid integer",
            other.clone(),
            None,
        )),
    }
    if !errors.is_empty() {
        return invalid(V::List(errors));
    }
    let max = state
        .store
        .read()
        .and_then(|t| t.view().max_serial_global())
        .unwrap_or(None);
    match (after, max) {
        (Some(a), Some(m)) if a > m => Subscribe::TooHigh(ujson(&V::Object(vec![
            ("message_type".into(), V::str("invalid_request")),
            (
                "errors".into(),
                V::List(vec![V::Object(vec![(
                    "msg".into(),
                    V::Str(messages::max_known_serial(&m.to_string())),
                )])]),
            ),
        ]))),
        (Some(a), _) => Subscribe::Follow(Some(a)),
        (None, m) => Subscribe::Follow(m),
    }
}

/// `AsyncEventStreamFollower._run_monitor()`: send journal entries after
/// `after`, then follow the stream until the receiver goes away.
pub(crate) async fn follow(state: Arc<HttpState>, mut after: i64, out: Outbox, host: String) {
    let mut after_event = state.events.last_id();
    tracing::info!(
        target: "irrd.server.http.event_stream",
        "event stream {host}: sending entries from global serial {after}"
    );
    if send_journal(&state, &mut after, &out).await.is_err() {
        return;
    }
    loop {
        let entries = state.events.read(after_event).await;
        for e in entries {
            let msg = graphql::Value::Object(vec![
                ("message_type".into(), graphql::Value::str("event")),
                (
                    "event_id".into(),
                    graphql::Value::Str(format!("{}-{}", e.id.0, e.id.1)),
                ),
                (
                    "event_data".into(),
                    graphql::Value::Object(vec![
                        ("source".into(), graphql::Value::Str(e.source.clone())),
                        ("operation".into(), graphql::Value::Str(e.operation.clone())),
                    ]),
                ),
            ]);
            if out.send(ujson(&msg)).await.is_err() {
                return;
            }
            after_event = e.id;
        }
        if send_journal(&state, &mut after, &out).await.is_err() {
            return;
        }
    }
}

/// `_send_new_journal_entries()`: a fresh read transaction each time.
async fn send_journal(state: &Arc<HttpState>, after: &mut i64, out: &Outbox) -> Result<(), ()> {
    let st = state.clone();
    let from = *after + 1;
    let msgs = tokio::task::spawn_blocking(move || -> store::Result<Vec<(i64, String)>> {
        let rtx = st.store.read()?;
        let view = rtx.view();
        let settings = rpsl::RpslSettings::default();
        let keyring = rpsl::Keyring::new();
        // RPSLDatabaseJournalQuery orders by source, serial_nrtm and
        // rpsl_pk, not by serial_global.
        let mut entries = Vec::new();
        for e in view.journal_by_serial_global(from)? {
            entries.push(e?);
        }
        entries.sort_by(|a, b| {
            (a.source, a.serial_nrtm, a.rpsl_pk).cmp(&(b.source, b.serial_nrtm, b.rpsl_pk))
        });
        Ok(entries
            .iter()
            .map(|e| (e.serial_global, journal_message(e, &settings, &keyring)))
            .collect())
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    for (serial, m) in msgs {
        out.send(m).await.map_err(|_| ())?;
        *after = (*after).max(serial);
    }
    Ok(())
}

fn journal_message(
    e: &store::JournalEntryRef<'_>,
    settings: &rpsl::RpslSettings,
    keyring: &rpsl::Keyring,
) -> String {
    use graphql::Value as V;
    let text = rpsl::text::remove_auth_hashes(e.object_text).into_owned();
    let parsed = match rpsl::rpsl_object_from_text(
        rpsl::text::py_strip(&text),
        &rpsl::ParseOptions {
            strict: false,
            default_source: None,
            settings,
            keyring,
        },
    ) {
        Ok(o) => V::Object(
            o.parsed_data()
                .iter()
                .map(|(k, v)| {
                    (
                        (*k).to_owned(),
                        match v {
                            rpsl::Value::Str(s) => V::Str(s.clone()),
                            rpsl::Value::List(l) => {
                                V::List(l.iter().map(|x| V::Str(x.clone())).collect())
                            }
                        },
                    )
                })
                .collect(),
        ),
        Err(_) => V::Object(Vec::new()),
    };
    ujson(&V::Object(vec![
        ("message_type".into(), V::str("rpsl_journal")),
        (
            "event_data".into(),
            V::Object(vec![
                ("pk".into(), V::str(e.rpsl_pk)),
                ("source".into(), V::str(e.source)),
                ("operation".into(), V::str(e.operation.pg_label())),
                ("object_class".into(), V::str(e.object_class)),
                ("serial_global".into(), V::Int(i128::from(e.serial_global))),
                ("serial_nrtm".into(), V::Int(i128::from(e.serial_nrtm))),
                ("origin".into(), V::str(e.origin.pg_label())),
                ("timestamp".into(), V::Str(isoformat(e.timestamp))),
                ("object_text".into(), V::Str(text)),
                ("parsed_data".into(), parsed),
            ]),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_timestamps() {
        let t = Timestamp::parse("2026-11-01T01:58:16.450000+00:00").expect("ts");
        assert_eq!(pg_timestamptz(t), "2026-11-01 01:58:16.45+00");
        let t = Timestamp::parse("2026-11-01T01:58:16+00:00").expect("ts");
        assert_eq!(pg_timestamptz(t), "2026-11-01 01:58:16+00");
    }

    #[test]
    fn ujson_escapes() {
        let v = graphql::Value::Object(vec![("a/b".into(), graphql::Value::str("é\n"))]);
        assert_eq!(ujson(&v), "{\"a\\/b\":\"\\u00e9\\n\"}");
    }
}
