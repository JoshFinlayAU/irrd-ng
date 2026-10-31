//! The secondary indexes answer what v4's SQL filters answer
//! (`irrd/storage/queries.py`): checked against a brute-force evaluation of
//! the same predicates over pseudo-random ranges.

mod common;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::*;
use store::{JournalEntryOrigin, Json, NewRpslObject, Space};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn obj(
    n: usize,
    class: &str,
    first: IpAddr,
    last: IpAddr,
    asn: Option<(u32, u32)>,
) -> NewRpslObject {
    let mut o = simple(&format!("OBJ{n}"), class, "TEST");
    o.ip_first = Some(first);
    o.ip_last = Some(last);
    if let Some((a, b)) = asn {
        o.asn_first = Some(a);
        o.asn_last = Some(b);
    }
    o
}

fn v4(v: u128) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(v as u32))
}

#[test]
fn range_queries_match_v4_predicates() {
    let dir = TempDir::new("ranges");
    let store = open(&dir, settings(&[]));
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut ranges: Vec<(u128, u128)> = Vec::new();
    // Mix of aligned prefixes (route-like) and arbitrary ranges
    // (inetnum-like), clustered in a small space so they overlap.
    for i in 0..600 {
        let (f, l) = if i % 2 == 0 {
            let len = 8 + (rng.next() % 25) as u32;
            let base = (rng.next() as u128 & 0x00FF_FFFF) | 0x0A00_0000;
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) } as u128;
            let f = base & mask;
            (f, f | (!mask & 0xFFFF_FFFF))
        } else {
            let a = (rng.next() as u128 & 0x00FF_FFFF) | 0x0A00_0000;
            let b = a + (rng.next() as u128 % 70000);
            (a, b.min(0xFFFF_FFFF))
        };
        ranges.push((f, l));
    }
    ranges.push((0, 0xFFFF_FFFF));
    let objects: Vec<NewRpslObject> = ranges
        .iter()
        .enumerate()
        .map(|(i, (f, l))| {
            obj(
                i,
                "inetnum",
                v4(*f),
                v4(*l),
                Some((*f as u32 >> 8, (*l as u32 >> 8))),
            )
        })
        .collect();
    let objs = objects.clone();
    store
        .write(move |tx| {
            for o in &objs {
                tx.upsert_rpsl_object(o, JournalEntryOrigin::Mirror, None, None)?;
            }
            Ok(())
        })
        .expect("write");

    let r = store.read().expect("read");
    let v = r.view();
    let names = |ids: Vec<(u64, u128, u128)>| -> BTreeSet<String> {
        ids.into_iter()
            .map(|(id, _, _)| {
                v.object_by_id(id)
                    .expect("get")
                    .expect("row")
                    .rpsl_pk
                    .to_owned()
            })
            .collect()
    };
    for q in 0..200 {
        let (a, b) = if q < ranges.len() && q % 3 == 0 {
            ranges[q]
        } else {
            let a = (rng.next() as u128 & 0x00FF_FFFF) | 0x0A00_0000;
            (a, a + (rng.next() as u128 % 5000))
        };
        let exact: BTreeSet<String> = ranges
            .iter()
            .enumerate()
            .filter(|(_, (f, l))| *f == a && *l == b)
            .map(|(i, _)| format!("OBJ{i}"))
            .collect();
        // ip_first <= net AND ip_last >= broadcast
        let less: BTreeSet<String> = ranges
            .iter()
            .enumerate()
            .filter(|(_, (f, l))| *f <= a && *l >= b)
            .map(|(i, _)| format!("OBJ{i}"))
            .collect();
        // first in [a, b], last in [a, b], not exact
        let more: BTreeSet<String> = ranges
            .iter()
            .enumerate()
            .filter(|(_, (f, l))| *f >= a && *f <= b && *l <= b && *l >= a && !(*f == a && *l == b))
            .map(|(i, _)| format!("OBJ{i}"))
            .collect();
        assert_eq!(names(v.range_exact(Space::Ipv4, a, b).expect("q")), exact);
        assert_eq!(
            names(v.range_less_specific(Space::Ipv4, a, b).expect("q")),
            less
        );
        assert_eq!(
            names(v.range_more_specific(Space::Ipv4, a, b).expect("q")),
            more
        );

        // asn_first <= x AND asn_last >= x
        let x = (a as u32) >> 8;
        let asn_less: BTreeSet<String> = ranges
            .iter()
            .enumerate()
            .filter(|(_, (f, l))| (*f as u32 >> 8) <= x && (*l as u32 >> 8) >= x)
            .map(|(i, _)| format!("OBJ{i}"))
            .collect();
        assert_eq!(
            names(
                v.range_less_specific(Space::Asn, u128::from(x), u128::from(x))
                    .expect("q")
            ),
            asn_less
        );
    }
}

#[test]
fn ipv6_and_origin_and_lookup() {
    let dir = TempDir::new("v6");
    let store = open(&dir, settings(&[]));
    let a = route(
        "2001:DB8::/32AS65537",
        "TEST",
        "2001:db8::/32",
        65537,
        "MNT-A",
    );
    let b = route(
        "2001:DB8:1::/48AS65537",
        "TEST",
        "2001:db8:1::/48",
        65537,
        "MNT-B",
    );
    let c = route(
        "192.0.2.0/24AS65538",
        "TEST",
        "192.0.2.0/24",
        65538,
        "MNT-A",
    );
    let mut set = simple("AS-SET1", "as-set", "TEST");
    set.parsed_data = Json::canonical(
        r#"{"as-set": "AS-SET1", "members": ["AS1", "AS-OTHER"], "mp-members": ["AS2"], "mbrs-by-ref": ["MNT-A"], "mnt-by": ["MNT-A"], "source": "TEST"}"#,
    )
    .expect("json");
    store
        .write(move |tx| {
            for o in [&a, &b, &c, &set] {
                tx.upsert_rpsl_object(o, JournalEntryOrigin::Mirror, None, None)?;
            }
            Ok(())
        })
        .expect("write");
    let r = store.read().expect("read");
    let v = r.view();
    let p32 = u128::from("2001:db8::".parse::<Ipv6Addr>().expect("ip"));
    let p32_last = p32 | ((1u128 << 96) - 1);
    assert_eq!(
        v.range_exact(Space::Ipv6, p32, p32_last).expect("q").len(),
        1
    );
    assert_eq!(
        v.range_more_specific(Space::Ipv6, p32, p32_last)
            .expect("q")
            .len(),
        1
    );
    let p48 = u128::from("2001:db8:1::".parse::<Ipv6Addr>().expect("ip"));
    assert_eq!(
        v.range_less_specific(Space::Ipv6, p48, p48 | ((1u128 << 80) - 1))
            .expect("q")
            .len(),
        2
    );

    let routes = v.routes_for_origin("TEST", 65537, None).expect("q");
    assert_eq!(routes.len(), 2);
    assert_eq!(
        v.routes_for_origin("TEST", 65537, Some(4))
            .expect("q")
            .len(),
        0
    );
    assert_eq!(
        v.routes_for_origin("TEST", 65538, Some(4))
            .expect("q")
            .len(),
        1
    );
    assert_eq!(
        v.routes_for_origin("OTHER", 65537, None).expect("q").len(),
        0
    );

    assert_eq!(
        v.ids_by_lookup("mnt-by", Some("MNT-A")).expect("q").len(),
        3
    );
    assert_eq!(
        v.ids_by_lookup("mnt-by", Some("mnt-a")).expect("q").len(),
        0
    );
    assert_eq!(v.ids_by_lookup("members", Some("AS1")).expect("q").len(), 1);
    assert_eq!(v.ids_by_lookup("mbrs-by-ref", None).expect("q").len(), 1);
    assert_eq!(
        v.ids_by_lookup("origin", Some("AS65537")).expect("q").len(),
        2
    );
    assert_eq!(v.ids_by_rpsl_pk("AS-SET1").expect("q").len(), 1);

    let sm = v.set_members("AS-SET1").expect("q");
    assert_eq!(sm.len(), 1);
    assert_eq!(sm[0].2.members, vec!["AS1", "AS-OTHER", "AS2"]);
    assert_eq!(sm[0].2.mbrs_by_ref, vec!["MNT-A"]);
}

#[test]
fn deleting_removes_every_index_entry() {
    let dir = TempDir::new("unindex");
    let store = open(&dir, settings(&[]));
    let a = route(
        "192.0.2.0/24AS65537",
        "TEST",
        "192.0.2.0/24",
        65537,
        "MNT-A",
    );
    let a2 = a.clone();
    store
        .write(move |tx| tx.upsert_rpsl_object(&a2, JournalEntryOrigin::Mirror, None, None))
        .expect("write");
    store
        .write(|tx| {
            tx.delete_rpsl_object(
                "TEST",
                "192.0.2.0/24AS65537",
                "route",
                JournalEntryOrigin::Mirror,
                None,
                false,
            )
            .map(|_| ())
        })
        .expect("delete");
    let r = store.read().expect("read");
    let v = r.view();
    assert_eq!(v.object_count().expect("c"), 0);
    assert!(
        v.ids_by_lookup("mnt-by", Some("MNT-A"))
            .expect("q")
            .is_empty()
    );
    assert!(
        v.ids_by_rpsl_pk("192.0.2.0/24AS65537")
            .expect("q")
            .is_empty()
    );
    assert!(
        v.routes_for_origin("TEST", 65537, None)
            .expect("q")
            .is_empty()
    );
    assert!(
        v.range_less_specific(Space::Ipv4, 0xC0000200, 0xC00002FF)
            .expect("q")
            .is_empty()
    );
    assert!(v.ids_by_asn_first(65537).expect("q").is_empty());
    drop(a);
}
