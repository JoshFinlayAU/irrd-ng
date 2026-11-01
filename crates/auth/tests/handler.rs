//! End to end runs of the submission handler on a temporary store, with
//! expectations taken from v4 (the submission differential, and v4's own
//! integration test in `irrd/integration_tests/run.py`).

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use auth::{RequestMeta, SourceSubmitSettings, Submission, SubmitSettings, SuspensionType};
use store::{SourceSettings, Store, StoreOptions, StoreSettings};

// passlib md5_crypt of "override-password" and of "seed-password".
const OVERRIDE_HASH: &str = "$1$harness1$0DM.kwoE/9kYUSx27OhPP.";
const SEED_HASH: &str = "$1$harness2$kGMJtGz/2zIPH/.XwCpTf0";

fn setup() -> (tempfile::TempDir, Store, Arc<SubmitSettings>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &StoreOptions::new(dir.path()),
        StoreSettings {
            sources: HashMap::from([(
                "TEST".to_owned(),
                SourceSettings {
                    keep_journal: true,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        },
    )
    .unwrap();
    let mut rpsl = rpsl::RpslSettings::default();
    rpsl.md5_pw = rpsl::HasherAvailability::Enabled;
    let settings = SubmitSettings {
        rpsl,
        override_password: Some(OVERRIDE_HASH.to_owned()),
        sources: HashMap::from([(
            "TEST".to_owned(),
            SourceSubmitSettings {
                authoritative: true,
                suspension_enabled: true,
                ..Default::default()
            },
        )]),
        ..Default::default()
    };
    (dir, store, Arc::new(settings))
}

fn submit(store: &Store, settings: &Arc<SubmitSettings>, text: &str) -> auth::Handler {
    auth::process(
        store,
        settings.clone(),
        Submission::TextBlob {
            text: text.to_owned(),
            origin: auth::Origin::Email,
            pgp_fingerprint: None,
        },
        RequestMeta::default(),
    )
    .unwrap()
}

const SEED: &str = "mntner: SEED-MNT\nadmin-c: PERSON-SEED\nupd-to: upd@example.com\nmnt-nfy: nfy@example.com\nauth: MD5-PW {hash}\nmnt-by: SEED-MNT\nsource: TEST\n\nperson: Seed Person\naddress: street\nphone: +31 20 000 0000\ne-mail: seed@example.com\nnic-hdl: PERSON-SEED\nmnt-by: SEED-MNT\nnotify: notify@example.com\nsource: TEST\n";

fn seeded() -> (tempfile::TempDir, Store, Arc<SubmitSettings>) {
    let (d, store, settings) = setup();
    let h = submit(
        &store,
        &settings,
        &(SEED.replace("{hash}", SEED_HASH) + "\noverride: override-password\n"),
    );
    let mut h = h;
    assert_eq!(h.status(), "SUCCESS", "{}", h.submitter_report_human());
    (d, store, settings)
}

#[test]
fn new_mntner_needs_override() {
    let (_d, store, settings) = setup();
    let mut h = submit(
        &store,
        &settings,
        &(SEED.replace("{hash}", SEED_HASH) + "\npassword: seed-password\n"),
    );
    assert_eq!(h.status(), "FAILED");
    let report = h.submitter_report_human();
    assert!(report.contains("ERROR: New mntner objects must be added by an administrator.\n"));
    assert!(report.contains("Number of objects processed with errors:    2\n"));
}

#[test]
fn modify_with_password_notifies() {
    let (_d, store, settings) = seeded();
    let h = submit(
        &store,
        &settings,
        "person: Seed Person\naddress: new street\nphone: +31 20 000 0000\ne-mail: seed@example.com\nnic-hdl: PERSON-SEED\nmnt-by: SEED-MNT\nsource: TEST\n\npassword: seed-password\n",
    );
    assert_eq!(h.status(), "SUCCESS");
    let mails = h.notification_reports().unwrap();
    let to: Vec<&str> = mails.iter().map(|(t, _, _)| t.as_str()).collect();
    assert_eq!(to, vec!["nfy@example.com", "notify@example.com"]);
    assert_eq!(mails[0].1, "Notification of TEST database changes");
    assert!(
        mails[0]
            .2
            .contains("\nModify succeeded for object below: [person] PERSON-SEED:\n\n@@ -1,")
    );
}

#[test]
fn auth_failure_notifies_upd_to() {
    let (_d, store, settings) = seeded();
    let mut h = submit(
        &store,
        &settings,
        "person: Seed Person\naddress: other\nphone: +31 20 000 0000\ne-mail: seed@example.com\nnic-hdl: PERSON-SEED\nmnt-by: SEED-MNT\nsource: TEST\n\npassword: wrong\n",
    );
    assert!(h.submitter_report_human().contains(
        "ERROR: Authorisation for person PERSON-SEED failed: must be authenticated by one of: SEED-MNT\n"
    ));
    let mails = h.notification_reports().unwrap();
    // upd-to of the mntner, and notify of the current object.
    assert_eq!(mails.len(), 2);
    assert_eq!(mails[0].0, "upd@example.com");
    assert_eq!(mails[1].0, "notify@example.com");
    assert!(mails[0].2.contains("*failed* the \nproper authorisation"));
}

#[test]
fn delete_with_references_fails() {
    let (_d, store, settings) = seeded();
    let mut h = submit(
        &store,
        &settings,
        "person: Seed Person\nnic-hdl: PERSON-SEED\nmnt-by: SEED-MNT\nsource: TEST\ndelete: gone\npassword: seed-password\n",
    );
    assert!(h.submitter_report_human().contains(
        "ERROR: Object PERSON-SEED to be deleted, but still referenced by mntner SEED-MNT\n"
    ));
}

#[test]
fn suspension_restores_in_suspension_order() {
    let (_d, store, settings) = seeded();
    let h = submit(
        &store,
        &settings,
        "route: 192.0.2.0/24\norigin: AS65530\nmnt-by: SEED-MNT\nsource: TEST\n\npassword: seed-password\n",
    );
    assert_eq!(h.status(), "SUCCESS");
    let run = |t: SuspensionType| {
        let mut h = auth::process(
            &store,
            settings.clone(),
            Submission::Suspension {
                objects: vec![("SEED-MNT".into(), "TEST".into(), t)],
                override_: Some("override-password".into()),
            },
            RequestMeta::default(),
        )
        .unwrap();
        h.submitter_report_json()
    };
    let s = run(SuspensionType::Suspend);
    assert!(s.contains(r#""info_messages":["Suspended route/192.0.2.0/24AS65530/TEST","Suspended person/PERSON-SEED/TEST","Suspended mntner/SEED-MNT/TEST"]"#), "{s}");
    let r = run(SuspensionType::Reactivate);
    // The mntner first, then the others in the order they were suspended.
    assert!(r.contains(r#""info_messages":["Restored mntner/SEED-MNT/TEST","Restored route/192.0.2.0/24AS65530/TEST","Restored person/PERSON-SEED/TEST"]"#), "{r}");
}

#[test]
fn bad_override_on_suspension_repeats_like_v4() {
    let (_d, store, settings) = seeded();
    let mut h = auth::process(
        &store,
        settings.clone(),
        Submission::Suspension {
            objects: vec![("SEED-MNT".into(), "TEST".into(), SuspensionType::Suspend)],
            override_: Some("wrong".into()),
        },
        RequestMeta::default(),
    )
    .unwrap();
    // v4 re-validates on every is_valid() call, so the error is listed
    // three times in the JSON report.
    let j = h.submitter_report_json();
    assert_eq!(
        j.matches("override password invalid or missing").count(),
        3,
        "{j}"
    );
}
