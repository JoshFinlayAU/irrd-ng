//! Every schema version keeps a small committed environment under
//! `tests/fixtures/schema-v<N>/`. This test opens a copy of each with the
//! current build, which migrates it, and checks the data survived. When
//! [`store::SCHEMA_VERSION`] is bumped, a fixture of the new version is
//! added (run with `STORE_WRITE_FIXTURE=1`) and the old ones stay, so the
//! migration from each is exercised.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use store::{
    AuthApiTokenRow, AuthMntnerRow, AuthPermissionRow, AuthUserRow, AuthWebAuthnRow, ChangeLogRow,
    IpPrefix, JournalEntryOrigin, ProtectedNameRow, SettingRow, SourceSettings, Store,
    StoreOptions, SuspendedObjectRow, Timestamp, UpdateRequestType, Uuid,
};

fn fixture_dir(version: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("schema-v{version}"))
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn ts() -> Timestamp {
    Timestamp::parse("2026-10-31T00:00:00.123456+00:00").unwrap_or(Timestamp(0))
}

/// Populate one row of every table.
fn populate(store: &Store) {
    store
        .write(|tx| {
            tx.upsert_rpsl_object(
                &route(
                    "192.0.2.0/24AS65537",
                    "TEST",
                    "192.0.2.0/24",
                    65537,
                    "MNT-TEST",
                ),
                JournalEntryOrigin::AuthChange,
                None,
                None,
            )?;
            tx.upsert_rpsl_object(
                &simple("MNT-TEST", "mntner", "TEST"),
                JournalEntryOrigin::AuthChange,
                None,
                None,
            )?;
            tx.record_serial_seen("TEST", 1)?;
            tx.insert_roa_object(
                4,
                IpPrefix::parse("192.0.2.0/24").unwrap_or_else(|| unreachable!()),
                65537,
                24,
                "TA",
            )?;
            tx.put_suspended_object(&SuspendedObjectRow {
                pk: uuid(1),
                rpsl_pk: "AS-SUSP".into(),
                source: "TEST".into(),
                object_class: "as-set".into(),
                object_text: "as-set: AS-SUSP\n".into(),
                mntners: vec!["MNT-TEST".into()],
                timestamp: ts(),
                original_created: ts(),
                original_updated: ts(),
            })?;
            tx.put_protected_name(&ProtectedNameRow {
                pk: uuid(2),
                rpsl_pk: "PERSON-TEST".into(),
                source: "TEST".into(),
                object_class: "person".into(),
                protected_name: "PERSON-TEST".into(),
                created: ts(),
            })?;
            tx.put_setting(&SettingRow {
                name: "nrtm4_server_key".into(),
                value: Some("v".into()),
                created: ts(),
            })?;
            tx.put_auth_user(&AuthUserRow {
                pk: uuid(3),
                email: "user@example.com".into(),
                name: "User".into(),
                password: "hash".into(),
                totp_secret: None,
                totp_last_used: None,
                active: true,
                override_: false,
                created: ts(),
                updated: ts(),
            })?;
            tx.put_auth_mntner(&AuthMntnerRow {
                pk: uuid(4),
                rpsl_mntner_pk: "MNT-TEST".into(),
                rpsl_mntner_obj_id: uuid(5),
                rpsl_mntner_source: "TEST".into(),
                migration_token: None,
                created: ts(),
                updated: ts(),
            })?;
            tx.put_auth_permission(&AuthPermissionRow {
                pk: uuid(6),
                user_id: Some(uuid(3)),
                mntner_id: Some(uuid(4)),
                user_management: true,
                created: ts(),
                updated: ts(),
            })?;
            tx.put_auth_api_token(&AuthApiTokenRow {
                pk: uuid(7),
                token: Some(uuid(8)),
                name: "token".into(),
                creator_id: Some(uuid(3)),
                mntner_id: Some(uuid(4)),
                ip_restriction: Some("192.0.2.0/24".into()),
                enabled_webapi: true,
                enabled_email: false,
                created: ts(),
                updated: ts(),
            })?;
            tx.put_auth_webauthn(&AuthWebAuthnRow {
                pk: uuid(9),
                user_id: Some(uuid(3)),
                name: "key".into(),
                credential_id: vec![1, 2, 3],
                credential_public_key: vec![4, 5],
                credential_sign_count: 7,
                created: ts(),
                last_used: ts(),
            })?;
            tx.put_pgp_key("0123456789ABCDEF0123456789ABCDEF01234567", b"test key")?;
            tx.put_change_log(&ChangeLogRow {
                pk: uuid(10),
                auth_by_user_id: Some(uuid(3)),
                auth_by_user_email: Some("user@example.com".into()),
                auth_by_api_key_id: None,
                auth_by_api_key_id_fixed: None,
                auth_through_mntner_id: Some(uuid(4)),
                auth_through_rpsl_mntner_pk: Some("MNT-TEST".into()),
                auth_by_rpsl_mntner_password: false,
                auth_by_rpsl_mntner_pgp_key: false,
                auth_by_override: Some(false),
                from_email: None,
                from_ip: Some("192.0.2.1".into()),
                auth_change_descr: None,
                auth_affected_user_id: None,
                auth_affected_mntner_id: None,
                rpsl_target_request_type: Some(UpdateRequestType::Create),
                rpsl_target_pk: Some("MNT-TEST".into()),
                rpsl_target_source: Some("TEST".into()),
                rpsl_target_object_class: Some("mntner".into()),
                rpsl_target_object_text_old: None,
                rpsl_target_object_text_new: Some("mntner: MNT-TEST\n".into()),
                timestamp: ts(),
            })
        })
        .expect("populate");
}

fn journal_settings() -> store::StoreSettings {
    settings(&[(
        "TEST",
        SourceSettings {
            keep_journal: true,
            ..Default::default()
        },
    )])
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for e in std::fs::read_dir(from).expect("read fixture") {
        let e = e.expect("entry");
        std::fs::copy(e.path(), to.join(e.file_name())).expect("copy");
    }
}

#[test]
fn every_committed_schema_version_opens() {
    if std::env::var_os("STORE_WRITE_FIXTURE").is_some() {
        let dir = fixture_dir(store::SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
        let mut o = StoreOptions::new(&dir);
        o.initial_map_size = 4 << 20;
        let store = Store::open(&o, journal_settings()).expect("create fixture");
        populate(&store);
        drop(store);
        let _ = std::fs::remove_file(dir.join("lock.mdb"));
    }
    for version in 1..=store::SCHEMA_VERSION {
        let src = fixture_dir(version);
        assert!(
            src.join("data.mdb").exists(),
            "no committed fixture for schema version {version}: run with STORE_WRITE_FIXTURE=1"
        );
        let tmp = TempDir::new("fixture");
        let path = tmp.0.join("store");
        copy_dir(&src, &path);
        let store =
            Store::open(&StoreOptions::new(&path), journal_settings()).expect("open fixture");
        assert_eq!(
            store.info().expect("info").schema_version,
            store::SCHEMA_VERSION
        );
        let r = store.read().expect("read");
        let v = r.view();
        assert_eq!(v.object_count().expect("count"), 2);
        assert!(
            v.object("TEST", "route", "192.0.2.0/24AS65537")
                .expect("q")
                .is_some()
        );
        assert_eq!(
            v.ids_by_lookup("mnt-by", Some("MNT-TEST"))
                .expect("q")
                .len(),
            2
        );
        assert_eq!(
            v.routes_for_origin("TEST", 65537, Some(4))
                .expect("q")
                .len(),
            1
        );
        assert_eq!(v.journal(Some("TEST"), None, None).expect("j").count(), 2);
        let st = v.database_status("TEST").expect("st").expect("row");
        assert_eq!(st.serial_oldest_seen, Some(1));
        assert_eq!(st.serial_newest_journal, Some(3));
        assert_eq!(v.roas().expect("roas").len(), 1);
        assert_eq!(v.suspended_by_mntner("MNT-TEST").expect("s").len(), 1);
        assert_eq!(v.protected_name("TEST", "PERSON-TEST").expect("p").len(), 1);
        assert_eq!(v.settings().expect("s").len(), 1);
        assert_eq!(v.auth_users().expect("u")[0].email, "user@example.com");
        assert_eq!(v.auth_permissions().expect("p").len(), 1);
        assert_eq!(v.auth_mntners().expect("m").len(), 1);
        assert_eq!(
            v.auth_api_token_by_token(&uuid(8))
                .expect("t")
                .expect("row")
                .name,
            "token"
        );
        assert_eq!(
            v.auth_webauthns().expect("w")[0].credential_id,
            vec![1, 2, 3]
        );
        assert_eq!(
            v.change_logs().expect("c")[0].rpsl_target_request_type,
            Some(UpdateRequestType::Create)
        );
        // The keyring arrived in version 4; older stores start empty.
        let keys = v.pgp_keyring().expect("keyring");
        if version >= 4 {
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].1, b"test key");
        } else {
            assert!(keys.is_empty());
        }
    }
}

#[test]
fn newer_schema_is_refused() {
    let tmp = TempDir::new("newer");
    let store = open(&tmp, journal_settings());
    drop(store);
    // Bump the version on disk past what this build knows.
    store::env::set_schema_version_for_tests(&tmp.0, store::SCHEMA_VERSION + 1).expect("set");
    let e = Store::open(&StoreOptions::new(&tmp.0), journal_settings()).expect_err("too new");
    assert!(e.to_string().contains("supports up to version"));
}
