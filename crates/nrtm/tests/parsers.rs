//! Ported from `irrd/mirroring/tests/test_parsers.py` (v4.5.4):
//! `TestMirrorFileImportParser` and `TestMirrorUpdateFileImportParser`.

use std::collections::HashSet;
use std::path::Path;

use nrtm::file_import::{
    self, ImportAction, ImportError, ImportSettings, ParseEnv, apply_file_import,
    apply_update_import,
};
use nrtm::messages;
use rpki::{BulkRouteRoaValidator, ScopeFilterConfig, ScopeFilterValidator};
use rpsl::{Keyring, RpslSettings};
use store::{
    DatabaseOperation, IpPrefix, JournalEntryOrigin, RpkiStatus, ScopeFilterStatus, SourceSettings,
    Store, StoreOptions, StoreSettings,
};

fn sample(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../parity/corpus/rpsl/expected.samples.jsonl");
    for line in std::fs::read_to_string(p).expect("samples").lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("json");
        if v["name"] == name {
            return v["text"].as_str().expect("text").to_owned();
        }
    }
    panic!("no sample {name}");
}

struct Tmp(std::path::PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store(tag: &str, keep_journal: bool) -> (Tmp, Store) {
    let p = std::env::temp_dir().join(format!("irrd-ng-nrtm-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 32 << 20;
    let mut s = StoreSettings::default();
    s.sources.insert(
        "TEST".into(),
        SourceSettings {
            keep_journal,
            ..Default::default()
        },
    );
    let st = Store::open(&o, s).expect("store");
    (Tmp(p), st)
}

fn paragraphs(parts: &[String]) -> Vec<String> {
    rpsl::split_rpsl_file(parts.join("\n\n").as_bytes())
}

#[test]
fn file_import_parse() {
    let (_t, st) = store("fileparse", false);
    // A ROA for 0/0 and ::/0 with AS0 makes every route invalid, as the
    // mocked validator in v4's test does.
    st.write(|tx| {
        tx.insert_roa_object(4, IpPrefix::parse("0.0.0.0/0").expect("p"), 0, 32, "TA")?;
        tx.insert_roa_object(6, IpPrefix::parse("::/0").expect("p"), 0, 128, "TA")
    })
    .expect("roa");
    let roa = BulkRouteRoaValidator::from_store(&st.read().expect("r").view(), HashSet::new())
        .expect("roa");
    let rpsl_settings = RpslSettings::default();
    let keyring = Keyring::new();
    let scope = ScopeFilterValidator::new(ScopeFilterConfig::default());
    let env = ParseEnv {
        rpsl: &rpsl_settings,
        keyring: &keyring,
        roa_validator: Some(&roa),
        scopefilter: &scope,
    };
    let settings = ImportSettings {
        source: "TEST".into(),
        object_class_filter: Some(vec!["route".into(), "key-cert".into()]),
        strict_import_keycert_objects: true,
        direct_error_return: false,
    };
    let input = paragraphs(&[
        sample("SAMPLE_UNKNOWN_ATTRIBUTE"),
        sample("SAMPLE_ROUTE6"),
        sample("SAMPLE_KEY_CERT"),
        sample("SAMPLE_ROUTE").replace("TEST", "BADSOURCE"),
        sample("SAMPLE_UNKNOWN_CLASS"),
        sample("SAMPLE_MALFORMED_PK"),
        sample("SAMPLE_LEGACY_IRRD_ARTIFACT"),
    ]);
    let parsed = file_import::parse_paragraphs(&input, &settings, &env).expect("parse");
    let kinds: Vec<String> = parsed
        .actions
        .iter()
        .map(|a| match a {
            ImportAction::Upsert(o) => format!("upsert {}", o.object.rpsl_pk),
            ImportAction::MirrorError(e) => format!("error {}", e.lines().next().unwrap_or("")),
        })
        .collect();
    assert_eq!(kinds.len(), 4);
    assert_eq!(kinds[0], "upsert 192.0.2.0/24AS65537");
    assert_eq!(kinds[1], "upsert PGPKEY-80F238C6");
    assert!(kinds[2].starts_with("error Invalid source BADSOURCE for object"));
    assert!(kinds[3].contains("Invalid address prefix"));
    if let ImportAction::Upsert(o) = &parsed.actions[0] {
        assert_eq!(o.object.rpki_status, RpkiStatus::Invalid);
        assert_eq!(o.object.scopefilter_status, ScopeFilterStatus::InScope);
    }
    let c = &parsed.counters;
    assert_eq!(
        messages::file_import_report(
            "TEST",
            c.obj_parsed,
            c.successful(),
            c.obj_errors,
            c.obj_ignored_class
        ),
        "File import for TEST: 6 objects read, 2 objects inserted, ignored 2 due to errors, ignored 1 due to object_class_filter"
    );
    assert_eq!(c.obj_unknown, 1);
    assert!(
        messages::unknown_classes_report(
            c.obj_unknown,
            "TEST",
            &c.unknown_object_classes.join(", ")
        )
        .starts_with("Ignored 1 objects found in import for TEST due to unknown object classes")
    );
    // The strict re-parse loaded the key into the keyring.
    assert_eq!(keyring.fingerprints().len(), 1);

    let actions = parsed.actions.clone();
    st.write(move |tx| apply_file_import(tx, "TEST", &actions, Some(424242)))
        .expect("apply");
    let r = st.read().expect("r");
    let s = r.view().database_status("TEST").expect("s").expect("row");
    assert_eq!(s.serial_oldest_seen, Some(424242));
    assert!(
        s.last_error
            .expect("err")
            .contains("Invalid address prefix")
    );
}

fn direct(input: &[String]) -> Result<file_import::ParsedFile, ImportError> {
    let rpsl_settings = RpslSettings::default();
    let keyring = Keyring::new();
    let scope = ScopeFilterValidator::new(ScopeFilterConfig::default());
    let env = ParseEnv {
        rpsl: &rpsl_settings,
        keyring: &keyring,
        roa_validator: None,
        scopefilter: &scope,
    };
    let settings = ImportSettings {
        source: "TEST".into(),
        direct_error_return: true,
        ..Default::default()
    };
    file_import::parse_paragraphs(&paragraphs(input), &settings, &env)
}

#[test]
fn direct_error_return_invalid_source() {
    let r = direct(&[
        sample("SAMPLE_UNKNOWN_ATTRIBUTE"),
        sample("SAMPLE_ROUTE").replace("TEST", "BADSOURCE"),
    ]);
    assert_eq!(
        r.expect_err("error"),
        ImportError::Rpsl(
            "Invalid source BADSOURCE for object 192.0.2.0/24AS65537, expected TEST".into()
        )
    );
}

#[test]
fn direct_error_return_malformed_pk() {
    match direct(&[sample("SAMPLE_MALFORMED_PK")]).expect_err("error") {
        ImportError::Rpsl(m) => assert!(m.contains("Invalid address prefix: not-a-prefix")),
        e => panic!("{e:?}"),
    }
}

#[test]
fn direct_error_return_unknown_class() {
    assert_eq!(
        direct(&[sample("SAMPLE_UNKNOWN_CLASS")]).expect_err("error"),
        ImportError::Rpsl("Unknown object class: foo-block".into())
    );
    // TestMirrorUpdateFileImportParser.test_direct_error_return: the first
    // error wins.
    assert_eq!(
        direct(&[
            sample("SAMPLE_UNKNOWN_CLASS"),
            sample("SAMPLE_MALFORMED_PK")
        ])
        .expect_err("error"),
        ImportError::Rpsl("Unknown object class: foo-block".into())
    );
}

#[test]
fn update_import_parse() {
    let (_t, st) = store("update", true);
    let rpsl_settings = RpslSettings::default();
    let keyring = Keyring::new();
    let scope = ScopeFilterValidator::new(ScopeFilterConfig::default());
    let env = ParseEnv {
        rpsl: &rpsl_settings,
        keyring: &keyring,
        roa_validator: None,
        scopefilter: &scope,
    };

    // What is in the database before: the route (with a last-modified,
    // ignored in the comparison), a modified route6 and an rtr-set that
    // the file no longer has.
    let existing = paragraphs(&[
        format!(
            "{}last-modified:  2020-01-01T00:00:00Z\n",
            sample("SAMPLE_ROUTE")
        ),
        sample("SAMPLE_ROUTE6").replace("test-MNT", "existing-mnt"),
        sample("SAMPLE_RTR_SET"),
    ]);
    let settings = ImportSettings {
        source: "TEST".into(),
        ..Default::default()
    };
    let pre = file_import::parse_paragraphs(&existing, &settings, &env).expect("existing");
    st.write(move |tx| {
        tx.disable_journaling();
        apply_file_import(tx, "TEST", &pre.actions, None)
    })
    .expect("seed");

    let settings = ImportSettings {
        source: "TEST".into(),
        object_class_filter: Some(vec![
            "route".into(),
            "route6".into(),
            "key-cert".into(),
            "role".into(),
        ]),
        ..Default::default()
    };
    let input = paragraphs(&[
        sample("SAMPLE_ROUTE"),
        sample("SAMPLE_ROUTE6"),
        sample("SAMPLE_ROLE"),
        sample("SAMPLE_ROUTE").replace("TEST", "BADSOURCE"),
        sample("SAMPLE_UNKNOWN_CLASS"),
        sample("SAMPLE_MALFORMED_PK"),
    ]);
    let parsed = file_import::parse_paragraphs(&input, &settings, &env).expect("parse");
    let actions = parsed.actions.clone();
    let counts = st
        .write(move |tx| apply_update_import(tx, "TEST", &actions))
        .expect("apply");
    let c = &parsed.counters;
    assert_eq!(
        messages::file_update_report(
            "TEST",
            c.obj_parsed,
            c.successful(),
            counts.obj_new,
            counts.obj_deleted,
            counts.obj_retained,
            counts.obj_modified,
            c.obj_errors,
            c.obj_ignored_class,
            "f"
        ),
        "File update for TEST: 6 objects read, 3 objects processed, 1 objects newly inserted, 1 objects newly deleted, 2 objects retained, of which 1 modified, ignored 2 due to errors, ignored 0 due to object_class_filter, source f"
    );
    assert_eq!(c.obj_unknown, 1);

    let r = st.read().expect("r");
    let ops: Vec<(String, DatabaseOperation, JournalEntryOrigin)> = r
        .view()
        .journal(Some("TEST"), None, None)
        .expect("j")
        .map(|e| {
            let e = e.expect("e");
            (e.rpsl_pk.to_owned(), e.operation, e.origin)
        })
        .collect();
    use DatabaseOperation::*;
    use JournalEntryOrigin::SyntheticNrtm as S;
    assert_eq!(
        ops,
        vec![
            ("ROLE-TEST".into(), AddOrUpdate, S),
            ("RTRS-SETTEST".into(), Delete, S),
            ("2001:DB8::/48AS65537".into(), AddOrUpdate, S),
        ]
    );
    let st_row = r.view().database_status("TEST").expect("s").expect("row");
    assert_eq!(
        st_row
            .last_error
            .as_deref()
            .map(|e| e.starts_with("Parsing errors")),
        Some(true)
    );
}
