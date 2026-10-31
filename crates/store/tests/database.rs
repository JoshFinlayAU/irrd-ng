//! Ported from `irrd/storage/tests/test_database.py` (v4.5.4): what those
//! tests assert about journal serials, `database_status`, readonly
//! handling, suspension, protected names, ROAs and RPKI status storage.

mod common;

use common::*;
use store::{
    DatabaseOperation, IpPrefix, JournalEntryOrigin, Json, Nrtm4ClientStatus, Nrtm4ServerStatus,
    RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus, SourceSettings, StatusChange, StoreError,
    Timestamp, Uuid,
};

fn keep_journal() -> SourceSettings {
    SourceSettings {
        keep_journal: true,
        ..Default::default()
    }
}

fn synchronised() -> SourceSettings {
    SourceSettings {
        keep_journal: true,
        nrtm_host: true,
        rpki_excluded: true,
        ..Default::default()
    }
}

/// (rpsl_pk, source, serial_nrtm, operation, origin, serial_global)
type J = (
    String,
    String,
    i64,
    DatabaseOperation,
    JournalEntryOrigin,
    i64,
);

fn journal(store: &store::Store) -> Vec<J> {
    let r = store.read().expect("read");
    r.view()
        .journal(None, None, None)
        .expect("journal")
        .map(|e| {
            let e = e.expect("entry");
            (
                e.rpsl_pk.to_owned(),
                e.source.to_owned(),
                e.serial_nrtm,
                e.operation,
                e.origin,
                e.serial_global,
            )
        })
        .collect()
}

#[test]
fn readonly_standby_refuses_writes() {
    let dir = TempDir::new("readonly");
    let mut s = settings(&[]);
    s.readonly_standby = true;
    let store = open(&dir, s);
    let r = store.write(|tx| {
        tx.upsert_rpsl_object(
            &route(
                "192.0.2.0/24,AS65537",
                "TEST",
                "192.0.2.0/24",
                65537,
                "MNT-WRONG",
            ),
            JournalEntryOrigin::AuthChange,
            None,
            None,
        )
    });
    let e = r.expect_err("readonly");
    assert!(e.to_string().contains("readonly"));
}

#[test]
fn duplicate_key_different_class() {
    // #560: the same primary key in two classes is two objects.
    let dir = TempDir::new("dupclass");
    let store = open(&dir, settings(&[]));
    store
        .write(|tx| {
            tx.upsert_rpsl_object(
                &simple("AS-TEST", "mntner", "TEST"),
                JournalEntryOrigin::AuthChange,
                None,
                None,
            )?;
            tx.upsert_rpsl_object(
                &simple("AS-TEST", "as-set", "TEST"),
                JournalEntryOrigin::AuthChange,
                None,
                None,
            )
        })
        .expect("write");
    let r = store.read().expect("read");
    assert_eq!(r.view().object_count().expect("count"), 2);
}

#[test]
fn object_writing_and_status_checking() {
    let dir = TempDir::new("writing");
    let store = open(
        &dir,
        settings(&[("TEST", keep_journal()), ("TEST2", synchronised())]),
    );
    let mut v4 = route(
        "192.0.2.0/24,AS65537",
        "TEST",
        "192.0.2.0/24",
        65537,
        "MNT-WRONG",
    );
    let v6 = route(
        "2001:db8::/64,AS65537",
        "TEST2",
        "2001:db8::/32",
        65537,
        "MNT-CORRECT",
    );

    let (v4a, v6a) = (v4.clone(), v6.clone());
    v4.parsed_data =
        Json::canonical(r#"{"mnt-by": ["MNT-CORRECT"], "source": "TEST"}"#).expect("json");
    let v4b = v4;
    store
        .write(move |tx| {
            tx.upsert_rpsl_object(
                &v4a,
                JournalEntryOrigin::AuthChange,
                None,
                Some(Timestamp::parse("2021-01-01").unwrap_or(Timestamp(0))),
            )?;
            // A duplicate key flushes the buffer: two journal entries.
            tx.upsert_rpsl_object(&v4b, JournalEntryOrigin::AuthChange, None, None)?;
            tx.upsert_rpsl_object(&v6a, JournalEntryOrigin::AuthChange, Some(42), None)?;
            tx.upsert_rpsl_object(&v6a, JournalEntryOrigin::AuthChange, Some(43), None)
        })
        .expect("first commit");

    {
        let r = store.read().expect("read");
        let v = r.view();
        assert_eq!(v.object_count().expect("count"), 2);
        assert_eq!(
            v.ids_by_lookup("mnt-by", Some("MNT-CORRECT"))
                .expect("lookup")
                .len(),
            2
        );
    }

    // Rolled back: nothing of this survives.
    let r = store.write(|tx| {
        let aut = simple("AS2914", "aut-num", "TEST");
        tx.upsert_rpsl_object(&aut, JournalEntryOrigin::AuthChange, None, None)?;
        tx.upsert_rpsl_object(&aut, JournalEntryOrigin::AuthChange, None, None)?;
        tx.flush_rpsl_object_writing_buffer()?;
        Err::<(), _>(StoreError::Aborted("rollback".into()))
    });
    assert!(r.is_err());
    assert_eq!(
        store
            .read()
            .expect("read")
            .view()
            .object_count()
            .expect("count"),
        2
    );

    let v6c = v6.clone();
    store
        .write(move |tx| {
            assert!(tx.delete_rpsl_object(
                &v6c.source,
                &v6c.rpsl_pk,
                "route",
                JournalEntryOrigin::AuthChange,
                Some(44),
                false
            )?);
            // Already gone: no row, no journal entry.
            assert!(!tx.delete_rpsl_object(
                &v6c.source,
                &v6c.rpsl_pk,
                "route",
                JournalEntryOrigin::AuthChange,
                Some(45),
                false
            )?);
            tx.record_mirror_error("TEST2", "error")?;
            tx.record_nrtm4_client_status(
                "TEST2",
                Nrtm4ClientStatus {
                    session_id: Some(Uuid::new_v4()),
                    version: Some(20),
                    current_key: Some("current key".into()),
                    next_key: Some("next key".into()),
                    previous_file_hashes: Some(
                        Json::canonical(r#"{"file": "hash"}"#).expect("json"),
                    ),
                },
            )?;
            tx.record_nrtm4_server_status(
                "TEST2",
                Nrtm4ServerStatus {
                    session_id: Some(Uuid::new_v4()),
                    version: Some(20),
                    last_snapshot_version: Some(10),
                    last_snapshot_global_serial: Some(11),
                    last_snapshot_filename: Some("filename".into()),
                    last_snapshot_hash: Some("hash".into()),
                    previous_deltas: Some(Json::canonical(r#"["delta"]"#).expect("json")),
                    ..Default::default()
                },
            )?;
            tx.record_serial_exported("TEST2", Some(424242))
        })
        .expect("second commit");
    assert_eq!(
        store
            .read()
            .expect("read")
            .view()
            .object_count()
            .expect("count"),
        1
    );

    // TEST is not synchronised: its own serials 1, 2. TEST2 is: the
    // mirror's serials. v4's serial_global for the delete is 7 because two
    // sequence values were burnt by the rolled-back transaction; LMDB rolls
    // the sequence back too, so it is 5 here (P-15).
    let pk4 = "192.0.2.0/24,AS65537".to_owned();
    let pk6 = "2001:db8::/64,AS65537".to_owned();
    use DatabaseOperation::*;
    use JournalEntryOrigin::AuthChange as A;
    assert_eq!(
        journal(&store),
        vec![
            (pk4.clone(), "TEST".into(), 1, AddOrUpdate, A, 1),
            (pk4, "TEST".into(), 2, AddOrUpdate, A, 2),
            (pk6.clone(), "TEST2".into(), 42, AddOrUpdate, A, 3),
            (pk6.clone(), "TEST2".into(), 43, AddOrUpdate, A, 4),
            (pk6, "TEST2".into(), 44, Delete, A, 5),
        ]
    );
    {
        let r = store.read().expect("read");
        let partial: Vec<i64> = r
            .view()
            .journal(Some("TEST"), Some(1), Some(1))
            .expect("j")
            .map(|e| e.expect("e").serial_nrtm)
            .collect();
        assert_eq!(partial, vec![1]);
        let partial: Vec<i64> = r
            .view()
            .journal(Some("TEST"), Some(1), None)
            .expect("j")
            .map(|e| e.expect("e").serial_nrtm)
            .collect();
        assert_eq!(partial, vec![1, 2]);
    }

    // Now TEST is configured for synchronised serials as well.
    store.set_settings(settings(&[
        ("TEST", synchronised()),
        ("TEST2", synchronised()),
    ]));
    store
        .write(|tx| tx.set_force_reload("TEST"))
        .expect("force reload");
    {
        let r = store.read().expect("read");
        let st = r
            .view()
            .database_status("TEST")
            .expect("status")
            .expect("row");
        assert_eq!(st.serial_oldest_journal, Some(1));
        assert_eq!(st.serial_newest_journal, Some(2));
        assert_eq!(st.serial_oldest_seen, None);
        assert_eq!(st.serial_newest_seen, None);
        assert_eq!(st.serial_last_export, None);
        assert_eq!(st.serial_newest_mirror, None);
        assert_eq!(st.nrtm4_client_session_id, None);
        assert_eq!(st.nrtm4_server_previous_deltas, None);
        assert_eq!(st.last_error, None);
        assert!(st.force_reload);
        assert!(st.synchronised_serials);
        assert_eq!(st.last_error_timestamp, None);
    }

    store
        .write(|tx| {
            tx.record_serial_newest_mirror("TEST2", 99999999)?;
            tx.record_serial_seen("TEST2", 44)
        })
        .expect("third commit");
    {
        let r = store.read().expect("read");
        let st = r
            .view()
            .database_status("TEST2")
            .expect("status")
            .expect("row");
        assert_eq!(st.serial_oldest_journal, Some(42));
        assert_eq!(st.serial_newest_journal, Some(44));
        assert_eq!(st.serial_oldest_seen, Some(42));
        assert_eq!(st.serial_newest_seen, Some(44));
        assert_eq!(st.serial_last_export, Some(424242));
        assert_eq!(st.serial_newest_mirror, Some(99999999));
        assert_eq!(st.nrtm4_client_version, Some(20));
        assert_eq!(st.nrtm4_client_current_key.as_deref(), Some("current key"));
        assert_eq!(st.nrtm4_client_next_key.as_deref(), Some("next key"));
        assert_eq!(
            st.nrtm4_server_last_snapshot_filename.as_deref(),
            Some("filename")
        );
        assert_eq!(st.nrtm4_server_last_snapshot_global_serial, Some(11));
        assert_eq!(st.nrtm4_server_last_snapshot_hash.as_deref(), Some("hash"));
        assert_eq!(st.nrtm4_server_last_snapshot_version, Some(10));
        assert_eq!(st.nrtm4_server_version, Some(20));
        assert_eq!(st.last_error.as_deref(), Some("error"));
        assert!(!st.force_reload);
        assert!(st.synchronised_serials);
        assert!(st.last_error_timestamp.is_some());
    }

    let v6d = v6;
    store
        .write(move |tx| {
            tx.upsert_rpsl_object(&v6d, JournalEntryOrigin::AuthChange, Some(45), None)?;
            assert_eq!(tx.read()?.objects(Some("TEST"), None)?.count(), 1);
            assert!(tx.read()?.database_status("TEST")?.is_some());
            assert_eq!(tx.read()?.objects(Some("TEST2"), None)?.count(), 1);
            tx.delete_all_rpsl_objects_with_journal("TEST", false)?;
            assert_eq!(tx.read()?.objects(Some("TEST"), None)?.count(), 0);
            assert!(tx.read()?.database_status("TEST")?.is_none());
            assert_eq!(tx.read()?.objects(Some("TEST2"), None)?.count(), 1);
            Ok(())
        })
        .expect("fourth commit");
}

#[test]
fn disable_journaling() {
    let dir = TempDir::new("nojournal");
    let store = open(&dir, settings(&[("TEST", keep_journal())]));
    let obj = route("192.0.2.0/24,AS65537", "TEST", "192.0.2.0/24", 65537, "MNT");
    let o = obj.clone();
    store
        .write(move |tx| {
            tx.disable_journaling();
            tx.upsert_rpsl_object(&o, JournalEntryOrigin::AuthChange, None, None)
        })
        .expect("write");
    assert!(journal(&store).is_empty());
    {
        let r = store.read().expect("read");
        let st = r
            .view()
            .database_status("TEST")
            .expect("status")
            .expect("row");
        assert_eq!(st.serial_oldest_journal, None);
        assert_eq!(st.serial_newest_journal, None);
        assert_eq!(st.serial_oldest_seen, None);
        assert_eq!(st.serial_newest_seen, None);
        assert!(!st.force_reload);
        assert!(!st.synchronised_serials);
    }
    store
        .write(move |tx| tx.upsert_rpsl_object(&obj, JournalEntryOrigin::AuthChange, None, None))
        .expect("write");
    assert_eq!(journal(&store).len(), 1);
}

#[test]
fn keep_initial_serial() {
    let dir = TempDir::new("initialserial");
    let store = open(&dir, settings(&[("TEST", keep_journal())]));
    assert!(journal(&store).is_empty());
    // The initial serial given to irrd_load_database.
    store
        .write(|tx| tx.record_serial_seen("TEST", 10))
        .expect("write");
    {
        let r = store.read().expect("read");
        let st = r
            .view()
            .database_status("TEST")
            .expect("status")
            .expect("row");
        assert_eq!(
            (st.serial_oldest_journal, st.serial_newest_journal),
            (None, None)
        );
        assert_eq!(
            (st.serial_oldest_seen, st.serial_newest_seen),
            (Some(10), Some(10))
        );
        assert!(!st.force_reload);
        assert!(!st.synchronised_serials);
    }
    let a = route("192.0.2.0/24,AS65537", "TEST", "192.0.2.0/24", 65537, "MNT");
    let b = route(
        "2001:db8::/64,AS65537",
        "TEST",
        "2001:db8::/32",
        65537,
        "MNT-CORRECT",
    );
    store
        .write(move |tx| {
            tx.upsert_rpsl_object(&a, JournalEntryOrigin::AuthChange, None, None)?;
            tx.upsert_rpsl_object(&b, JournalEntryOrigin::AuthChange, None, None)
        })
        .expect("write");
    let r = store.read().expect("read");
    let st = r
        .view()
        .database_status("TEST")
        .expect("status")
        .expect("row");
    assert_eq!(
        (st.serial_oldest_journal, st.serial_newest_journal),
        (Some(11), Some(12))
    );
    assert_eq!(
        (st.serial_oldest_seen, st.serial_newest_seen),
        (Some(10), Some(12))
    );
}

#[test]
fn synchronised_source_without_serial_violates_not_null() {
    let dir = TempDir::new("syncnull");
    let store = open(&dir, settings(&[("TEST", synchronised())]));
    let a = route("192.0.2.0/24,AS65537", "TEST", "192.0.2.0/24", 65537, "MNT");
    let e = store
        .write(move |tx| tx.upsert_rpsl_object(&a, JournalEntryOrigin::Mirror, None, None))
        .expect_err("null serial");
    assert!(e.to_string().contains("serial_nrtm"));
    assert_eq!(
        store
            .read()
            .expect("read")
            .view()
            .object_count()
            .expect("count"),
        0
    );
}

#[test]
fn suppressed_objects_get_no_journal_entry() {
    let dir = TempDir::new("suppressed");
    let store = open(&dir, settings(&[("TEST", keep_journal())]));
    let mut a = route("192.0.2.0/24,AS65537", "TEST", "192.0.2.0/24", 65537, "MNT");
    a.rpki_status = RpkiStatus::Invalid;
    store
        .write(move |tx| tx.upsert_rpsl_object(&a, JournalEntryOrigin::Mirror, None, None))
        .expect("write");
    assert!(journal(&store).is_empty());
    assert_eq!(
        store
            .read()
            .expect("read")
            .view()
            .object_count()
            .expect("count"),
        1
    );
}

#[test]
fn roa_handling_and_query() {
    let dir = TempDir::new("roa");
    let store = open(&dir, settings(&[]));
    store
        .write(|tx| {
            tx.insert_roa_object(
                4,
                IpPrefix::parse("192.0.2.0/24").expect("p"),
                64496,
                28,
                "TEST TA",
            )?;
            tx.insert_roa_object(
                6,
                IpPrefix::parse("2001:db8::/32").expect("p"),
                64497,
                64,
                "TEST TA",
            )
        })
        .expect("write");
    {
        let r = store.read().expect("read");
        let roas: Vec<(String, i64, i64, Option<String>, u8)> = r
            .view()
            .roas()
            .expect("roas")
            .into_iter()
            .map(|r| {
                (
                    r.prefix.to_string(),
                    r.asn,
                    r.max_length,
                    r.trust_anchor,
                    r.ip_version,
                )
            })
            .collect();
        assert_eq!(
            roas,
            vec![
                ("192.0.2.0/24".into(), 64496, 28, Some("TEST TA".into()), 4),
                ("2001:db8::/32".into(), 64497, 64, Some("TEST TA".into()), 6),
            ]
        );
        let v = r.view();
        let cov = |p: &str| {
            v.roas_covering(&IpPrefix::parse(p).expect("p"))
                .expect("covering")
                .len()
        };
        assert_eq!(cov("192.0.2.0/23"), 0);
        assert_eq!(cov("192.0.2.0/24"), 1);
        assert_eq!(cov("192.0.2.0/25"), 1);
    }
    // Inserting the same ROA twice violates the unique constraint.
    let e = store.write(|tx| {
        tx.insert_roa_object(
            4,
            IpPrefix::parse("192.0.2.0/24").expect("p"),
            64496,
            28,
            "TEST TA",
        )
    });
    assert!(e.is_err());
    store
        .write(|tx| tx.delete_all_roa_objects())
        .expect("delete");
    assert!(
        store
            .read()
            .expect("read")
            .view()
            .roas()
            .expect("roas")
            .is_empty()
    );
}

fn rpki_change(
    pk: Uuid,
    old: RpkiStatus,
    new: RpkiStatus,
    sf: ScopeFilterStatus,
) -> StatusChange<RpkiStatus> {
    StatusChange {
        pk,
        rpsl_pk: "192.0.2.0/24,AS65537".into(),
        source: "TEST".into(),
        object_class: "route".into(),
        object_text: "object-text".into(),
        prefix: IpPrefix::parse("192.0.2.0/24"),
        old_status: old,
        rpki_status: new,
        scopefilter_status: sf,
        route_preference_status: RoutePreferenceStatus::Visible,
    }
}

#[test]
fn rpki_status_storage() {
    let dir = TempDir::new("rpkistatus");
    let store = open(&dir, settings(&[("TEST", keep_journal())]));
    let mut first = route(
        "192.0.2.0/24,AS65537",
        "TEST",
        "192.0.2.0/24",
        65537,
        "MNT-TEST",
    );
    first.rpki_status = RpkiStatus::Invalid;
    // Same rpsl_pk, different source: its status must never change (#461).
    let second = route(
        "192.0.2.0/24,AS65537",
        "RPKI-EXCLUDED",
        "192.0.2.0/24",
        65537,
        "MNT-TEST",
    );
    store
        .write(move |tx| {
            tx.upsert_rpsl_object(&first, JournalEntryOrigin::AuthChange, None, None)?;
            tx.upsert_rpsl_object(&second, JournalEntryOrigin::AuthChange, None, None)
        })
        .expect("write");
    let pk = {
        let r = store.read().expect("read");
        r.view()
            .object("TEST", "route", "192.0.2.0/24,AS65537")
            .expect("get")
            .expect("row")
            .pk
    };
    let count = |s: RpkiStatus| {
        let r = store.read().expect("read");
        r.view()
            .objects(None, None)
            .expect("objects")
            .filter(|o| o.as_ref().expect("o").1.rpki_status == s)
            .count()
    };
    let serial = |n: i64| {
        let r = store.read().expect("read");
        r.view()
            .journal_entry("TEST", n)
            .expect("j")
            .map(|e| e.operation)
    };
    assert_eq!(count(RpkiStatus::Invalid), 1);
    assert_eq!(count(RpkiStatus::NotFound), 1);
    use RpkiStatus::*;
    use ScopeFilterStatus::*;
    let w = |valid: Vec<StatusChange<RpkiStatus>>,
             invalid: Vec<StatusChange<RpkiStatus>>,
             nf: Vec<StatusChange<RpkiStatus>>| {
        store
            .write(move |tx| tx.update_rpki_status(&valid, &invalid, &nf))
            .expect("update");
    };

    w(
        vec![],
        vec![],
        vec![rpki_change(pk, Invalid, NotFound, InScope)],
    );
    assert_eq!(count(NotFound), 2);
    assert_eq!(serial(1), Some(DatabaseOperation::AddOrUpdate));

    w(vec![], vec![], vec![]);
    assert_eq!(count(NotFound), 2);
    assert_eq!(journal(&store).len(), 1);

    w(
        vec![],
        vec![rpki_change(pk, Valid, Invalid, InScope)],
        vec![],
    );
    assert_eq!(count(Invalid), 1);
    assert_eq!(serial(2), Some(DatabaseOperation::Delete));

    w(
        vec![],
        vec![rpki_change(pk, Valid, Invalid, InScope)],
        vec![],
    );
    assert_eq!(count(Invalid), 1);
    assert_eq!(serial(3), Some(DatabaseOperation::Delete));

    w(
        vec![],
        vec![],
        vec![rpki_change(pk, Invalid, NotFound, InScope)],
    );
    assert_eq!(count(NotFound), 2);
    assert_eq!(serial(4), Some(DatabaseOperation::AddOrUpdate));

    w(
        vec![rpki_change(pk, Invalid, Valid, InScope)],
        vec![],
        vec![],
    );
    assert_eq!(count(Valid), 1);
    assert_eq!(serial(5), Some(DatabaseOperation::AddOrUpdate));

    // valid to not_found: no journal entry.
    w(
        vec![],
        vec![],
        vec![rpki_change(pk, Valid, NotFound, InScope)],
    );
    assert_eq!(serial(6), None);

    // invalid to valid while out of scope: no journal entry.
    w(
        vec![rpki_change(pk, Invalid, Valid, OutScopeAs)],
        vec![],
        vec![],
    );
    assert_eq!(count(Valid), 1);
    assert_eq!(serial(6), None);

    store
        .write(|tx| tx.delete_journal_entries_before_date(Timestamp::now(), "TEST"))
        .expect("expire");
    assert!(journal(&store).is_empty());
}

#[test]
fn suspension() {
    let dir = TempDir::new("suspension");
    let store = open(&dir, settings(&[("TEST", keep_journal())]));
    let mut obj = route(
        "192.0.2.0/24,AS65537",
        "TEST",
        "192.0.2.0/24",
        65537,
        "MNT-TEST",
    );
    obj.parsed_data = Json::canonical(r#"{"mnt-by": ["MNT-TEST", "MNT-TEST2"], "source": "TEST"}"#)
        .expect("json");
    store
        .write(move |tx| {
            tx.disable_journaling();
            tx.upsert_rpsl_object(&obj, JournalEntryOrigin::AuthChange, None, None)
        })
        .expect("write");
    let pk = {
        let r = store.read().expect("read");
        r.view()
            .objects(None, None)
            .expect("o")
            .next()
            .expect("one")
            .expect("row")
            .1
            .pk
    };
    let e = store.write(|tx| tx.suspend_rpsl_object(Uuid::new_v4()));
    assert!(matches!(e, Err(StoreError::ValueError(_))));
    store
        .write(move |tx| tx.suspend_rpsl_object(pk))
        .expect("suspend");

    let r = store.read().expect("read");
    let v = r.view();
    assert_eq!(v.object_count().expect("count"), 0);
    let suspended = v.suspended_objects().expect("suspended");
    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0].rpsl_pk, "192.0.2.0/24,AS65537");
    let mut m = suspended[0].mntners.clone();
    m.sort();
    assert_eq!(m, vec!["MNT-TEST", "MNT-TEST2"]);
    let j: Vec<_> = v
        .journal(None, None, None)
        .expect("j")
        .map(|e| e.expect("e").to_entry())
        .collect();
    assert_eq!(j.len(), 1);
    assert_eq!(j[0].rpsl_pk, "192.0.2.0/24,AS65537");
    assert_eq!(j[0].operation, DatabaseOperation::Delete);
    assert_eq!(v.suspended_by_mntner("MNT-TEST").expect("m").len(), 1);
    assert_eq!(v.suspended_by_mntner("MNT-TEST2").expect("m").len(), 1);
    assert_eq!(v.suspended_by_mntner("MNT-NO").expect("m").len(), 0);
    let spk = suspended[0].pk;
    drop(r);
    store
        .write(move |tx| tx.delete_suspended_rpsl_objects(&[spk]))
        .expect("delete");
    assert!(
        store
            .read()
            .expect("read")
            .view()
            .suspended_objects()
            .expect("s")
            .is_empty()
    );
}

#[test]
fn protect_rpsl_name() {
    let dir = TempDir::new("protect");
    let store = open(&dir, settings(&[]));
    store
        .write(|tx| {
            tx.upsert_rpsl_object(
                &simple("PERSON", "person", "TEST"),
                JournalEntryOrigin::AuthChange,
                None,
                None,
            )?;
            tx.delete_rpsl_object(
                "TEST",
                "PERSON",
                "person",
                JournalEntryOrigin::AuthChange,
                None,
                true,
            )?;
            Ok(())
        })
        .expect("write");
    let r = store.read().expect("read");
    assert_eq!(
        r.view().protected_name("TEST", "PERSON").expect("q").len(),
        1
    );
}
