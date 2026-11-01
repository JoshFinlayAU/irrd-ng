//! `!J`: `QueryResolver.database_status()` rendered with
//! `ujson.dumps(results, indent=4)`.

use store::{DatabaseStatus, ReadView, Timestamp};

use crate::json::{Object, write_list, write_str};
use crate::messages;
use crate::resolver::{QResult, QueryResolver};
use crate::settings::{ConfigValue, QuerySettings};

/// `datetime.astimezone(UTC).isoformat()`: microseconds only when non-zero.
pub fn isoformat(t: Timestamp) -> String {
    let s = t.to_string();
    if t.micros().rem_euclid(1_000_000) == 0 {
        // 2026-10-31T01:02:03.000000+00:00 -> 2026-10-31T01:02:03+00:00
        format!("{}{}", &s[..19], &s[26..])
    } else {
        s
    }
}

fn opt_int(o: &mut Object<'_>, key: &str, v: Option<i64>) {
    let out = o.key(key);
    match v {
        Some(i) => out.push_str(&i.to_string()),
        None => out.push_str("null"),
    }
}

fn opt_str(o: &mut Object<'_>, key: &str, v: Option<String>) {
    let out = o.key(key);
    match v {
        Some(s) => write_str(out, &s),
        None => out.push_str("null"),
    }
}

fn bool_val(o: &mut Object<'_>, key: &str, v: bool) {
    o.key(key).push_str(if v { "true" } else { "false" });
}

fn config(o: &mut Object<'_>, key: &str, v: &ConfigValue) {
    let d = o.depth();
    v.write_ujson(o.key(key), d);
}

/// `is_serial_synchronised()`
pub fn is_serial_synchronised(settings: &QuerySettings, row: &DatabaseStatus) -> bool {
    let s = settings.source(&row.source);
    row.synchronised_serials
        && (!settings.scopefilter_enabled || s.scopefilter_excluded)
        && (!settings.rpki_enabled || s.rpki_excluded)
        && !s.route_object_preference.truthy()
        && s.nrtm_host
}

fn regular(settings: &QuerySettings, row: &DatabaseStatus, out: &mut String, depth: usize) {
    let source = rpsl::python::upper(&row.source);
    let s = settings.source(&source);
    let mut o = Object::new(out, depth);
    write_str(o.key("source_type"), "regular");
    config(&mut o, "authoritative", &s.authoritative);
    {
        let d = o.depth();
        let out = o.key("object_class_filter");
        match &s.object_class_filter {
            Some(list) => write_list(out, d, list.iter(), |o, v, _| write_str(o, v)),
            None => out.push_str("null"),
        }
    }
    bool_val(
        &mut o,
        "rpki_rov_filter",
        settings.rpki_enabled && !s.rpki_excluded,
    );
    bool_val(
        &mut o,
        "scopefilter_enabled",
        settings.scopefilter_enabled && !s.scopefilter_excluded,
    );
    config(&mut o, "route_preference", &s.route_object_preference);
    config(&mut o, "local_journal_kept", &s.keep_journal);
    opt_int(&mut o, "serial_oldest_journal", row.serial_oldest_journal);
    opt_int(&mut o, "serial_newest_journal", row.serial_newest_journal);
    opt_int(&mut o, "serial_last_export", row.serial_last_export);
    opt_int(&mut o, "serial_newest_mirror", row.serial_newest_mirror);
    opt_str(
        &mut o,
        "nrtm4_client_session_id",
        row.nrtm4_client_session_id.map(|u| u.to_string()),
    );
    opt_int(&mut o, "nrtm4_client_version", row.nrtm4_client_version);
    opt_str(
        &mut o,
        "nrtm4_server_session_id",
        row.nrtm4_server_session_id.map(|u| u.to_string()),
    );
    opt_int(&mut o, "nrtm4_server_version", row.nrtm4_server_version);
    opt_str(
        &mut o,
        "nrtm4_server_last_update_notification_file_update",
        row.nrtm4_server_last_update_notification_file_update
            .map(isoformat),
    );
    opt_int(
        &mut o,
        "nrtm4_server_last_snapshot_version",
        row.nrtm4_server_last_snapshot_version,
    );
    opt_str(
        &mut o,
        "rpsl_data_updated",
        Some(isoformat(row.rpsl_data_updated)),
    );
    opt_str(&mut o, "last_update", Some(isoformat(row.updated)));
    bool_val(
        &mut o,
        "synchronised_serials",
        is_serial_synchronised(settings, row),
    );
    o.finish();
}

enum Entry<'a> {
    Regular(Box<DatabaseStatus>),
    Alias(&'a [String]),
    Unknown,
}

/// The `!J` JSON text.
pub(crate) fn database_status_json(
    resolver: &QueryResolver,
    view: &ReadView<'_>,
    sources: Option<Vec<String>>,
) -> QResult<String> {
    let settings = resolver.settings();
    let sources = sources.unwrap_or_else(|| settings.all_valid_sources());
    let invalid: Vec<&String> = sources
        .iter()
        .filter(|s| !settings.is_valid_source(s))
        .collect();
    let rows = QueryResolver::status_rows(view, &sources)?;

    // An OrderedDict: assigning an existing key keeps its position.
    let mut entries: Vec<(String, Entry<'_>)> = Vec::new();
    fn set<'a>(entries: &mut Vec<(String, Entry<'a>)>, k: String, v: Entry<'a>) {
        match entries.iter_mut().find(|(key, _)| *key == k) {
            Some(e) => e.1 = v,
            None => entries.push((k, v)),
        }
    }
    for row in rows {
        let k = rpsl::python::upper(&row.source).into_owned();
        set(&mut entries, k, Entry::Regular(Box::new(row)));
    }
    for s in &sources {
        if let Some(aliased) = settings.alias(s) {
            set(&mut entries, s.clone(), Entry::Alias(aliased));
        }
    }
    for s in invalid {
        set(
            &mut entries,
            rpsl::python::upper(s).into_owned(),
            Entry::Unknown,
        );
    }

    let mut out = String::new();
    let mut top = Object::new(&mut out, 0);
    for (k, v) in &entries {
        let d = top.depth();
        let o = top.key(k);
        match v {
            Entry::Regular(row) => regular(settings, row, o, d),
            Entry::Alias(list) => {
                let mut a = Object::new(o, d);
                write_str(a.key("source_type"), "alias");
                let dd = a.depth();
                let w = a.key("aliased_sources");
                write_list(w, dd, list.iter(), |o, v, _| write_str(o, v));
                a.finish();
            }
            Entry::Unknown => {
                let mut a = Object::new(o, d);
                write_str(a.key("error"), messages::UNKNOWN_SOURCE_JSON);
                a.finish();
            }
        }
    }
    top.finish();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isoformat_like_python() {
        assert_eq!(
            isoformat(Timestamp(1_793_408_028_927_123)),
            "2026-10-31T00:53:48.927123+00:00"
        );
        assert_eq!(
            isoformat(Timestamp(1_793_408_028_000_000)),
            "2026-10-31T00:53:48+00:00"
        );
    }
}
