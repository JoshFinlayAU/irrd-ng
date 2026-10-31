//! Ported from `irrd/mirroring/tests/test_nrtm_operation.py` (v4.5.4),
//! with the database calls checked against a real store.

use std::path::Path;

use nrtm::mirror::nrtm3::Operation;
use nrtm::mirror::operation::{self, NrtmOperation, OperationEnv, Prepared};
use rpki::{ScopeFilterConfig, ScopeFilterValidator};
use rpsl::{Keyring, RpslSettings};
use store::{IpPrefix, RoaRow, RpkiStatus, ScopeFilterStatus, Store, StoreOptions, StoreSettings};

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

fn op(source: &str, operation: Operation, text: &str) -> NrtmOperation {
    NrtmOperation {
        source: source.into(),
        operation,
        serial: Some(42424242),
        origin_identifier: "42424242".into(),
        object_text: Some(text.into()),
        rpsl_pk: None,
        object_class: None,
        strict_validation_key_cert: false,
        rpki_aware: false,
        object_class_filter: None,
    }
}

fn prepare(o: &NrtmOperation, scope: ScopeFilterConfig) -> Prepared {
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    let sf = ScopeFilterValidator::new(scope);
    let env = OperationEnv {
        rpsl: &settings,
        keyring: &keyring,
        scopefilter: &sf,
        rpki_excluded: false,
    };
    operation::prepare(o, &env).expect("prepare").prepared
}

#[test]
fn add_valid_key_cert_with_and_without_strict_import() {
    for strict in [false, true] {
        let mut o = op("TEST", Operation::Add, &sample("SAMPLE_KEY_CERT"));
        o.strict_validation_key_cert = strict;
        o.object_class_filter = Some(vec![
            "route".into(),
            "route6".into(),
            "mntner".into(),
            "key-cert".into(),
        ]);
        match prepare(&o, ScopeFilterConfig::default()) {
            Prepared::Upsert { object, .. } => assert_eq!(object.rpsl_pk, "PGPKEY-80F238C6"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn add_valid_rpki_and_scopefilter_aware() {
    let dir = tempfile::tempdir().expect("dir");
    let st = Store::open(&StoreOptions::new(dir.path()), StoreSettings::default()).expect("store");
    // A ROA for another origin covering the route: invalid.
    st.write(|tx| {
        tx.put_roa(&RoaRow {
            pk: store::Uuid::new_v4(),
            prefix: IpPrefix::new("192.0.2.0".parse().expect("ip"), 24).expect("prefix"),
            asn: 65530,
            max_length: 24,
            trust_anchor: Some("TA".into()),
            ip_version: 4,
            created: store::Timestamp::now(),
        })
    })
    .expect("roa");
    let mut o = op("TEST", Operation::Add, &sample("SAMPLE_ROUTE"));
    o.rpki_aware = true;
    let scope = ScopeFilterConfig {
        prefixes: vec![IpPrefix::new("192.0.2.0".parse().expect("ip"), 24).expect("p")],
        ..Default::default()
    };
    let p = prepare(&o, scope);
    let Prepared::Upsert { object, .. } = &p else {
        panic!("{p:?}");
    };
    assert_eq!(object.rpsl_pk, "192.0.2.0/24AS65537");
    assert_eq!(object.scopefilter_status, ScopeFilterStatus::OutScopePrefix);
    let prepared = operation::PreparedOperation {
        source: "TEST".into(),
        serial: Some(42424242),
        prepared: p,
    };
    st.write(move |tx| operation::apply(tx, &prepared, false).map(|_| ()))
        .expect("apply");
    let r = st.read().expect("read");
    let v = r.view();
    let stored = v
        .objects(Some("TEST"), None)
        .expect("objects")
        .next()
        .expect("one")
        .expect("ok")
        .1;
    assert_eq!(stored.rpki_status, RpkiStatus::Invalid);
}

#[test]
fn add_ignored_object_class() {
    let mut o = op("TEST", Operation::Add, &sample("SAMPLE_MNTNER"));
    o.object_class_filter = Some(vec!["route".into(), "route6".into()]);
    assert!(matches!(
        prepare(&o, ScopeFilterConfig::default()),
        Prepared::Ignored(None)
    ));
}

#[test]
fn delete_valid() {
    let o = op("TEST", Operation::Del, &sample("SAMPLE_MNTNER"));
    match prepare(&o, ScopeFilterConfig::default()) {
        Prepared::Delete {
            rpsl_pk,
            object_class,
            ..
        } => {
            assert_eq!(rpsl_pk, "TEST-MNT");
            assert_eq!(object_class, "mntner");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn add_unknown_object_class() {
    let o = op("TEST", Operation::Add, &sample("SAMPLE_UNKNOWN_CLASS"));
    match prepare(&o, ScopeFilterConfig::default()) {
        Prepared::Ignored(Some(log)) => assert_eq!(
            log,
            "Ignoring NRTM operation TEST/42424242/ADD: unknown object class: foo-block"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn add_inconsistent_source() {
    let o = op("NOT-TEST", Operation::Add, &sample("SAMPLE_MNTNER"));
    match prepare(&o, ScopeFilterConfig::default()) {
        Prepared::Rejected { mirror_error, .. } => assert_eq!(
            mirror_error,
            "Incorrect source in NRTM object: stream has source NOT-TEST, found object with source TEST in operation 42424242/ADD/TEST-MNT. This operation is ignored, causing potential data inconsistencies."
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn add_rpsl_errors() {
    let o = op(
        "TEST",
        Operation::Add,
        &sample("SAMPLE_MALFORMED_EMPTY_LINE"),
    );
    match prepare(&o, ScopeFilterConfig::default()) {
        Prepared::Rejected { log, mirror_error } => {
            assert!(log.starts_with(
                "Parsing errors occurred while processing NRTM operation TEST/42424242/ADD."
            ));
            assert!(mirror_error.starts_with("Parsing errors: ["));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn incomplete_objects_delete_but_do_not_add() {
    // NRTM deletions sometimes arrive without a source: the stream's is
    // used. Additions without one are refused.
    let text = "route: 192.0.02.0/24\norigin: AS65537";
    match prepare(
        &op("TEST", Operation::Del, text),
        ScopeFilterConfig::default(),
    ) {
        Prepared::Delete {
            rpsl_pk,
            object_class,
            ..
        } => {
            assert_eq!(rpsl_pk, "192.0.2.0/24AS65537");
            assert_eq!(object_class, "route");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        prepare(
            &op("TEST", Operation::Add, text),
            ScopeFilterConfig::default()
        ),
        Prepared::Rejected { .. }
    ));
}
