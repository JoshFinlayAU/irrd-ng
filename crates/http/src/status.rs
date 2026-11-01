//! `/v1/status/` (`StatusGenerator`) and `/metrics/`
//! (`MetricsGenerator`), with v4's text layout.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use query::QuerySettings;
use store::{DatabaseStatus, ReadView, Timestamp};

use crate::{HttpSettings, StatusSourceSettings};

/// `RPSLDatabaseObjectStatisticsQuery`: object counts per source and
/// class.
pub(crate) fn statistics(view: &ReadView<'_>) -> store::Result<BTreeMap<(String, String), u64>> {
    let mut out: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (s, c, n) in view.object_class_counts()? {
        *out.entry((s, c)).or_insert(0) += n;
    }
    Ok(out)
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "None".to_owned(), |x| x.to_string())
}

/// `str(datetime)` of a UTC timestamp.
fn dt(t: Timestamp) -> String {
    query::status::isoformat(t).replacen('T', " ", 1)
}

fn yes_no(b: bool) -> &'static str {
    if b { "Yes" } else { "No" }
}

/// One row of the statistics table.
struct Row([String; 6]);

/// The statistics table as `BeautifulTable` 0.8 prints it with IRRd's
/// settings: no side borders, two-space column separators, a dashed line
/// above and below the header, the source column left aligned and the
/// rest right aligned.
fn table(rows: &[Row]) -> String {
    let headers = [
        "source",
        "total obj",
        "rt obj",
        "aut-num obj",
        "serial",
        "last export",
    ];
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.0.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let widths: Vec<usize> = widths.iter().map(|w| w + 2).collect();
    let total: usize = widths.iter().sum::<usize>() + 2 * (widths.len() - 1);
    let line = |cells: &[String]| -> String {
        let mut out = Vec::new();
        for (i, c) in cells.iter().enumerate() {
            let inner = widths[i] - 2;
            let n = c.chars().count();
            let pad = " ".repeat(inner.saturating_sub(n));
            out.push(if i == 0 {
                format!(" {c}{pad} ")
            } else {
                format!(" {pad}{c} ")
            });
        }
        out.join("  ")
    };
    let dashes = "-".repeat(total);
    let mut lines = vec![dashes.clone()];
    lines.push(line(&headers.map(str::to_owned)));
    lines.push(dashes);
    for r in rows {
        lines.push(line(&r.0));
    }
    lines.join("\n")
}

/// `whois_query_source_status()`: the remote `!j` answer, or the text v4
/// reports when it fails.
fn remote_status(
    host: &str,
    port: i64,
    source: &str,
) -> Result<(Option<bool>, i64, i64, Option<i64>), bool> {
    // Err(true): an OSError (unreachable); Err(false): a ValueError.
    let addr = (host, u16::try_from(port).map_err(|_| true)?)
        .to_socket_addrs()
        .map_err(|_| true)?
        .next()
        .ok_or(true)?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|_| true)?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    s.write_all(format!("!j{source}\n").as_bytes())
        .map_err(|_| true)?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut expected: Option<usize> = None;
    let mut offset = 0usize;
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if expected.is_none() {
            let text = String::from_utf8_lossy(&buf);
            if let Some(first) = text.split('\n').next().filter(|_| text.contains('\n')) {
                if let Some(len) = first.strip_prefix('A') {
                    expected = len.trim().parse().ok();
                    offset = first.len() + 1;
                } else if first == "C" || first == "D" || first.starts_with('F') {
                    return Err(false);
                }
            }
        }
        if let Some(e) = expected
            && buf.len() > e + offset
        {
            break;
        }
    }
    let Some(e) = expected else { return Err(false) };
    if buf.len() < e + offset {
        return Err(false);
    }
    let body = String::from_utf8_lossy(&buf[offset..offset + e - 1]).into_owned();
    let fields: Vec<&str> = body.split(':').collect();
    if fields.len() < 3 || fields[0].to_uppercase() != source.to_uppercase() {
        return Err(false);
    }
    let mirrorable = match fields[1].to_uppercase().as_str() {
        "Y" => Some(true),
        "N" => Some(false),
        _ => None,
    };
    let (a, b) = fields[2].split_once('-').ok_or(false)?;
    let oldest: i64 = a.trim().parse().map_err(|_| false)?;
    let newest: i64 = b.trim().parse().map_err(|_| false)?;
    let export = match fields.get(3) {
        None => None,
        Some(x) => Some(x.trim().parse::<i64>().map_err(|_| false)?),
    };
    Ok((mirrorable, oldest, newest, export))
}

fn remote_information(s: Option<&StatusSourceSettings>, source: &str) -> Vec<String> {
    let s = s.cloned().unwrap_or_default();
    if let Some(url) = s.nrtm4_client_notification_file_url {
        return vec![format!("NRTMv4 client Update Notification File URL: {url}")];
    }
    let Some(host) = s.nrtm_host else {
        return vec!["No NRTM configured.".to_owned()];
    };
    let port = s.nrtm_port;
    match remote_status(&host, port, source) {
        Ok((m, oldest, newest, export)) => vec![
            format!("NRTM host: {host} port {port}"),
            format!("Mirrorable: {}", yes_no(m == Some(true))),
            format!("Oldest journal serial number: {oldest}"),
            format!("Newest journal serial number: {newest}"),
            format!("Last export at serial number: {}", opt(export)),
        ],
        Err(false) => vec![
            format!("NRTM host: {host} port {port}"),
            "Remote status query unsupported or query failed".to_owned(),
        ],
        Err(true) => vec![
            format!("NRTM host: {host} port {port}"),
            "Unable to reach remote server for status query".to_owned(),
        ],
    }
}

/// `StatusGenerator.generate()`
pub(crate) fn status_text(
    view: &ReadView<'_>,
    q: &QuerySettings,
    h: &HttpSettings,
) -> store::Result<String> {
    let stats = statistics(view)?;
    let rows: Vec<DatabaseStatus> = view.database_statuses()?;
    let counts = |source: Option<&str>| -> (u64, u64, u64) {
        let mut t = (0, 0, 0);
        for ((s, c), n) in &stats {
            if source.is_some_and(|x| x != s) {
                continue;
            }
            t.0 += n;
            if c == "route" {
                t.1 += n;
            }
            if c == "aut-num" {
                t.2 += n;
            }
        }
        t
    };
    let mut out = format!(
        "IRRD version {}\nListening on {} port {}\n",
        q.version, h.whois_interface, h.whois_port
    );
    out.push_str("\n\n");
    let mut trows = Vec::new();
    for r in &rows {
        let source = rpsl::python::upper(&r.source).into_owned();
        let (t, rt, an) = counts(Some(&source));
        let last_export = match r.serial_last_export {
            Some(x) if x != 0 => x.to_string(),
            _ => String::new(),
        };
        trows.push(Row([
            source,
            t.to_string(),
            rt.to_string(),
            an.to_string(),
            opt(r.serial_newest_seen),
            last_export,
        ]));
    }
    let (t, rt, an) = counts(None);
    trows.push(Row([
        "TOTAL".into(),
        t.to_string(),
        rt.to_string(),
        an.to_string(),
        String::new(),
        String::new(),
    ]));
    out.push_str(&table(&trows));
    out.push_str("\n\n");
    for r in &rows {
        let source = rpsl::python::upper(&r.source).into_owned();
        let s = q.source(&source);
        let ocf = match &s.object_class_filter {
            Some(l) if !l.is_empty() => l.join(","),
            _ => "None".to_owned(),
        };
        let deltas = match &r.nrtm4_server_previous_deltas {
            Some(store::Json(text)) => match graphql::value::json_loads_str(text) {
                Some(graphql::Value::List(a)) => a.len(),
                Some(graphql::Value::Object(o)) => o.len(),
                Some(graphql::Value::Str(s)) => s.chars().count(),
                _ => 0,
            },
            None => 0,
        };
        let route_pref = match &s.route_object_preference {
            query::ConfigValue::Null => "None".to_owned(),
            query::ConfigValue::Int(i) => i.to_string(),
            query::ConfigValue::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
            query::ConfigValue::Str(x) => x.clone(),
            other => format!("{other:?}"),
        };
        let mut block = String::new();
        let _ = write!(
            block,
            "\nStatus for {source}\n-------------------\nLocal information:\n\
             \x20   Authoritative: {}\n\
             \x20   Object class filter: {ocf}\n\
             \x20   Oldest serial seen: {}\n\
             \x20   Newest serial seen: {}\n\
             \x20   Oldest local journal serial number: {}\n\
             \x20   Newest local journal serial number: {}\n\
             \x20   Last export at serial number: {}\n\
             \x20   Newest serial number mirrored: {}\n\
             \x20   NRTMv4 client: current session: {}\n\
             \x20   NRTMv4 client: current version: {}\n\
             \x20   NRTMv4 server: current session: {}\n\
             \x20   NRTMv4 server: current version: {}\n\
             \x20   NRTMv4 server: last Update Notification File update: {}\n\
             \x20   NRTMv4 server: last snapshot version: {}\n\
             \x20   NRTMv4 server: number of deltas: {deltas}\n\
             \x20   Synchronised NRTM serials: {}\n\
             \x20   Last change to RPSL data: {}\n\
             \x20   Last internal status update: {}\n\
             \x20   Local journal kept: {}\n\
             \x20   Last import error occurred at: {}\n\
             \x20   RPKI validation enabled: {}\n\
             \x20   Scope filter enabled: {}\n\
             \x20   Route object preference: {route_pref}\n\
             \nRemote information:\n",
            yes_no(s.authoritative.truthy()),
            opt(r.serial_oldest_seen),
            opt(r.serial_newest_seen),
            opt(r.serial_oldest_journal),
            opt(r.serial_newest_journal),
            opt(r.serial_last_export),
            opt(r.serial_newest_mirror),
            opt(r.nrtm4_client_session_id),
            opt(r.nrtm4_client_version),
            opt(r.nrtm4_server_session_id),
            opt(r.nrtm4_server_version),
            opt(r.nrtm4_server_last_update_notification_file_update.map(dt)),
            opt(r.nrtm4_server_last_snapshot_version),
            yes_no(query::status::is_serial_synchronised(q, r)),
            dt(r.rpsl_data_updated),
            dt(r.updated),
            yes_no(s.keep_journal.truthy()),
            opt(r.last_error_timestamp.map(dt)),
            yes_no(q.rpki_enabled && !s.rpki_excluded),
            yes_no(q.scopefilter_enabled && !s.scopefilter_excluded),
        );
        for l in remote_information(h.status_sources.get(&source), &source) {
            let _ = writeln!(block, "    {l}");
        }
        block.push('\n');
        out.push_str(&block);
    }
    Ok(out)
}

/// `MetricsGenerator.generate()`
pub(crate) fn metrics_text(
    view: &ReadView<'_>,
    q: &QuerySettings,
    startup: i64,
) -> store::Result<String> {
    let now = Timestamp::now();
    let stats = statistics(view)?;
    let mut rows = view.database_statuses()?;
    rows.sort_by(|a, b| a.source.cmp(&b.source));
    let mut sections: Vec<String> = Vec::new();
    sections.push(format!(
        "# HELP irrd_info Info from IRRd, value is always 1\n\
         # TYPE irrd_info gauge\n\
         irrd_info{{version=\"{}\"}} 1\n\n\
         # HELP irrd_uptime_seconds Uptime of IRRd in seconds\n\
         # TYPE irrd_uptime_seconds gauge\n\
         irrd_uptime_seconds {}\n\n\
         # HELP irrd_startup_timestamp Startup time of IRRd in seconds since UNIX epoch\n\
         # TYPE irrd_startup_timestamp gauge\n\
         irrd_startup_timestamp {startup}\n",
        q.version,
        now.unix_seconds() - startup
    ));
    // Sorted by f"{source}-{object_class}".
    let mut st: Vec<(String, &(String, String), &u64)> = stats
        .iter()
        .map(|(k, v)| (format!("{}-{}", k.0, k.1), k, v))
        .collect();
    st.sort_by(|a, b| a.0.cmp(&b.0));
    let lines: Vec<String> = st
        .iter()
        .map(|(_, (s, c), n)| {
            format!("irrd_object_class_total{{source=\"{s}\", object_class=\"{c}\"}} {n}")
        })
        .collect();
    sections.push(format!(
        "# HELP irrd_object_class_total Number of objects per class per source\n# TYPE irrd_object_class_total gauge\n{}\n",
        lines.join("\n")
    ));
    let secs = |t: Timestamp| (now.micros() - t.micros()) / 1_000_000;
    let pair = |name: &str,
                help_s: &str,
                help_t: &str,
                get: &dyn Fn(&DatabaseStatus) -> Option<Timestamp>|
     -> String {
        let mut l = vec![
            format!("# HELP {name}_seconds {help_s}"),
            format!("# TYPE {name}_seconds gauge"),
        ];
        for r in &rows {
            if let Some(t) = get(r) {
                l.push(format!(
                    "{name}_seconds{{source=\"{}\"}} {}",
                    r.source,
                    secs(t)
                ));
            }
        }
        l.push(String::new());
        l.push(format!("# HELP {name}_timestamp {help_t}"));
        l.push(format!("# TYPE {name}_timestamp gauge"));
        for r in &rows {
            if let Some(t) = get(r) {
                l.push(format!(
                    "{name}_timestamp{{source=\"{}\"}} {}",
                    r.source,
                    t.unix_seconds()
                ));
            }
        }
        l.join("\n") + "\n"
    };
    sections.push(pair(
        "irrd_last_rpsl_data_update",
        "Seconds since the last update to RPSL data",
        "Timestamp of the last update to RPSL data in seconds since UNIX epoch",
        &|r| Some(r.rpsl_data_updated),
    ));
    sections.push(pair(
        "irrd_last_update",
        "Seconds since the last internal status change",
        "Timestamp of the last internal status change in seconds since UNIX epoch",
        &|r| Some(r.updated),
    ));
    sections.push(pair(
        "irrd_last_error",
        "Seconds since the last mirroring error",
        "Timestamp of the last mirroring error in seconds since UNIX epoch",
        &|r| r.last_error_timestamp,
    ));
    let field =
        |metric: &str, help: &str, get: &dyn Fn(&DatabaseStatus) -> Option<i64>| -> String {
            let lines: Vec<String> = rows
                .iter()
                .filter_map(|r| {
                    get(r)
                        .filter(|v| *v != 0)
                        .map(|v| format!("{metric}{{source=\"{}\"}} {v}", r.source))
                })
                .collect();
            format!(
                "# HELP {metric} {help}\n# TYPE {metric} gauge\n{}\n",
                lines.join("\n")
            )
        };
    sections.push(field(
        "irrd_nrtm4_client_version",
        "Newest NRTMv4 version mirrored from upstream",
        &|r| r.nrtm4_client_version,
    ));
    sections.push(field(
        "irrd_mirrored_serial",
        "Newest serial NRTMv3 number mirrored from upstream",
        &|r| r.serial_newest_mirror,
    ));
    sections.push(field(
        "irrd_last_export_serial",
        "Last serial number for full export",
        &|r| r.serial_last_export,
    ));
    sections.push(field(
        "irrd_oldest_journal_serial",
        "Oldest serial in the journal",
        &|r| r.serial_oldest_journal,
    ));
    sections.push(field(
        "irrd_newest_journal_serial",
        "Newest serial in the journal",
        &|r| r.serial_newest_journal,
    ));
    Ok(sections.join("\n") + "\n")
}
