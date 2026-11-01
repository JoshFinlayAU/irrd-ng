//! `irrd/rpki/notifications.py`: mail the contacts of route objects in
//! authoritative sources that just became RPKI invalid.

use std::collections::{BTreeSet, HashMap, HashSet};

use rpsl::{Keyring, ParseOptions, RpslObject, RpslSettings, Value};
use store::{ReadView, Result, RpkiStatus, StatusChange};

use crate::messages;

/// v4's logger.
pub const LOG_TARGET: &str = "irrd.rpki.notifications";

/// The settings `notify_rpki_invalid_owners` reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifySettings {
    /// `rpki.notify_invalid_enabled`
    pub enabled: bool,
    /// Sources with `authoritative` set.
    pub authoritative_sources: HashSet<String>,
    /// `rpki.notify_invalid_subject`
    pub subject: String,
    /// `rpki.notify_invalid_header`
    pub header: String,
}

/// One notification: (recipient, subject, body).
pub type Notification = (String, String, String);

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::List(l)) => l.clone(),
        Some(Value::Str(s)) => vec![s.clone()],
        None => Vec::new(),
    }
}

/// `parsed_data[key]` of a stored row, as a list of strings.
fn json_list(parsed: &str, key: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(parsed) else {
        return Vec::new();
    };
    match v.get(key) {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// `str.format(sources_str=..., object_count=...)` on the subject and
/// header settings.
fn format_template(template: &str, sources_str: &str, object_count: usize) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut field = String::new();
                for f in chars.by_ref() {
                    if f == '}' {
                        break;
                    }
                    field.push(f);
                }
                match field.as_str() {
                    "sources_str" => out.push_str(sources_str),
                    "object_count" => out.push_str(&object_count.to_string()),
                    other => {
                        out.push('{');
                        out.push_str(other);
                        out.push('}');
                    }
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The mails `notify_rpki_invalid_owners(dh, rpsl_dicts_now_invalid)`
/// sends, in v4's order. v4 collects each recipient's objects in a set,
/// so the order of objects within a mail (and of sources in the subject)
/// varies from run to run there; here it is the order they were found.
pub fn invalid_owner_notifications(
    view: &ReadView<'_>,
    settings: &NotifySettings,
    rpsl: &RpslSettings,
    now_invalid: &[StatusChange<RpkiStatus>],
) -> Result<Vec<Notification>> {
    if !settings.enabled {
        return Ok(Vec::new());
    }
    let keyring = Keyring::new();
    let options = ParseOptions {
        strict: true,
        default_source: None,
        settings: rpsl,
        keyring: &keyring,
    };
    let mut objs: Vec<RpslObject> = Vec::new();
    for c in now_invalid {
        if settings.authoritative_sources.contains(&c.source)
            && c.rpki_status == RpkiStatus::Invalid
            && let Ok(o) = rpsl::rpsl_object_from_text(&c.object_text, &options)
        {
            objs.push(o);
        }
    }
    if objs.is_empty() {
        return Ok(Vec::new());
    }
    let source_of = |o: &RpslObject| o.source().map(str::to_owned).unwrap_or_default();

    let sources: BTreeSet<String> = objs.iter().map(source_of).collect();
    let mut emails_by_source: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for source in &sources {
        let mut mntner_emails: HashMap<String, Vec<String>> = HashMap::new();
        let add = |m: &str, e: &str, map: &mut HashMap<String, Vec<String>>| {
            let list = map.entry(m.to_owned()).or_default();
            if !list.iter().any(|x| x == e) {
                list.push(e.to_owned());
            }
        };
        // Step 1: the maintainers of these objects.
        let mut mntner_pks: Vec<String> = Vec::new();
        for o in objs.iter().filter(|o| source_of(o) == *source) {
            for m in list(o.parsed_value("mnt-by")) {
                let m = rpsl::python::upper(rpsl::python::strip(&m)).into_owned();
                if !mntner_pks.contains(&m) {
                    mntner_pks.push(m);
                }
            }
        }
        let mut mntner_contacts: Vec<(String, Vec<String>)> = Vec::new();
        for pk in &mntner_pks {
            let Some(m) = view.object(source, "mntner", pk)? else {
                continue;
            };
            // Step 2: mnt-nfy.
            for e in json_list(m.parsed_data, "mnt-nfy") {
                add(m.rpsl_pk, &e, &mut mntner_emails);
            }
            // Step 3: tech-c and admin-c.
            let mut contacts = json_list(m.parsed_data, "tech-c");
            contacts.extend(json_list(m.parsed_data, "admin-c"));
            mntner_contacts.push((m.rpsl_pk.to_owned(), contacts));
        }
        // Step 4: their e-mail addresses.
        let mut contact_emails: HashMap<String, Vec<String>> = HashMap::new();
        for (_, contacts) in &mntner_contacts {
            for c in contacts {
                let key = rpsl::python::upper(rpsl::python::strip(c)).into_owned();
                if contact_emails.contains_key(&key) {
                    continue;
                }
                for class in ["person", "role"] {
                    if let Some(r) = view.object(source, class, &key)? {
                        contact_emails
                            .insert(r.rpsl_pk.to_owned(), json_list(r.parsed_data, "e-mail"));
                    }
                }
            }
        }
        // Step 5: per maintainer.
        for (mntner, contacts) in &mntner_contacts {
            for c in contacts {
                if let Some(emails) = contact_emails.get(c.as_str()) {
                    for e in emails {
                        add(mntner, e, &mut mntner_emails);
                    }
                }
            }
        }
        emails_by_source.insert(source.clone(), mntner_emails);
    }

    // Objects per recipient, in first-seen order, each object once.
    let mut per_email: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        let source = source_of(o);
        let Some(by_mntner) = emails_by_source.get(&source) else {
            continue;
        };
        for m in list(o.parsed_value("mnt-by")) {
            let Some(emails) = by_mntner.get(m.as_str()) else {
                continue;
            };
            for e in emails {
                match per_email.iter_mut().find(|(x, _)| x == e) {
                    Some((_, idx)) => {
                        if !idx.contains(&i) {
                            idx.push(i);
                        }
                    }
                    None => per_email.push((e.clone(), vec![i])),
                }
            }
        }
    }

    let mut out = Vec::with_capacity(per_email.len());
    for (email, idx) in per_email {
        let srcs: BTreeSet<String> = idx.iter().map(|&i| source_of(&objs[i])).collect();
        let sources_str = srcs.into_iter().collect::<Vec<_>>().join(", ");
        let subject = format_template(&settings.subject, &sources_str, idx.len());
        let mut body = format_template(&settings.header, &sources_str, idx.len());
        body.push_str(messages::NOTIFY_AFFECTED);
        body.push_str(messages::NOTIFY_RULE);
        body.push_str("\n\n");
        for &i in &idx {
            body.push_str(&objs[i].render_rpsl_text());
            body.push('\n');
        }
        body.push_str(messages::NOTIFY_RULE);
        out.push((email, subject, body));
    }
    Ok(out)
}

/// Send the notifications; failures are logged as v4 logs them. Returns
/// the number of recipients, which v4 reports as "emails sent" whether or
/// not delivery worked.
pub fn send_notifications(mail: &mail::MailSettings, notifications: &[Notification]) -> usize {
    for (email, subject, body) in notifications {
        match mail::send_email(mail, email, subject, body) {
            Ok(()) | Err(mail::MailError::BadRecipient) => {}
            Err(e) => {
                tracing::warn!(target: LOG_TARGET, "{}", messages::notify_send_failed(email, &e.to_string()))
            }
        }
    }
    notifications.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates() {
        assert_eq!(
            format_template(
                "route(6) objects in {sources_str} marked RPKI invalid",
                "TEST",
                2
            ),
            "route(6) objects in TEST marked RPKI invalid"
        );
        assert_eq!(format_template("{object_count} {{x}}", "S", 3), "3 {x}");
    }
}
