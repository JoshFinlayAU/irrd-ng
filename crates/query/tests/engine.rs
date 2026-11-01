//! The engine end to end over a real store: behaviour ported from v4's
//! `irrd/server/whois/tests/test_query_parser.py`,
//! `irrd/server/tests/test_query_resolver.py` and
//! `irrd/server/whois/tests/test_query_response.py`, plus regression cases
//! from the differential runs against v4 4.5.4.

use std::sync::Arc;

use nrtm::file_import::{self, ImportSettings, ParseEnv, apply_file_import};
use query::{NrtmServer, QuerySettings, ResponseType, SourceQuerySettings, WhoisSession};
use rpki::{ScopeFilterConfig, ScopeFilterValidator};
use rpsl::{Keyring, RpslSettings};
use store::{Store, StoreOptions, StoreSettings};

struct Tmp(std::path::PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const TEST1: &str = "\
route:          192.0.2.0/24
origin:         AS65537
mnt-by:         MNT-A
member-of:      RS-REF
source:         TEST1

route:          192.0.2.0/25
origin:         AS65537
mnt-by:         MNT-A
source:         TEST1

route:          192.0.2.0/24
origin:         AS65538
mnt-by:         MNT-B
source:         TEST1

route:          198.51.100.0/24
origin:         AS65538
mnt-by:         MNT-B
source:         TEST1

route6:         2001:db8::/32
origin:         AS65537
mnt-by:         MNT-A
source:         TEST1

aut-num:        AS65537
as-name:        A
member-of:      AS-REF
mnt-by:         MNT-A
source:         TEST1

aut-num:        AS65538
as-name:        B
member-of:      AS-REF
mnt-by:         MNT-OTHER
source:         TEST1

as-set:         AS-TOP
members:        AS65537, AS-MID, AS-LOOP
mnt-by:         MNT-A
source:         TEST1

as-set:         AS-MID
members:        AS65538, AS-TOP, AS-MISSING
mnt-by:         MNT-A
source:         TEST1

as-set:         AS-LOOP
members:        AS-LOOP
mnt-by:         MNT-A
source:         TEST1

as-set:         AS-REF
mbrs-by-ref:    MNT-A
mnt-by:         MNT-A
source:         TEST1

as-set:         AS-EMPTY
mnt-by:         MNT-A
source:         TEST1

route-set:      RS-TOP
members:        198.51.100.0/24^+, AS65537, RS-REF
mnt-by:         MNT-A
source:         TEST1

route-set:      RS-REF
mbrs-by-ref:    ANY
mnt-by:         MNT-A
source:         TEST1

mntner:         MNT-A
auth:           CRYPT-PW LEuuhsBJNFV0Q
upd-to:         a@example.net
mnt-by:         MNT-A
source:         TEST1

person:         Alice Example
address:        Street
phone:          +1 555 0100
nic-hdl:        AE1-TEST
mnt-by:         MNT-A
source:         TEST1
";

const TEST2: &str = "\
route:          192.0.2.0/24
origin:         AS65537
mnt-by:         MNT-A
source:         TEST2

as-set:         AS-TOP
members:        AS65539
mnt-by:         MNT-A
source:         TEST2
";

fn load(st: &Store, source: &str, text: &str) {
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
        source: source.into(),
        object_class_filter: None,
        strict_import_keycert_objects: false,
        direct_error_return: true,
        keep_plain_text: false,
    };
    let paragraphs = rpsl::split_rpsl_file(text.as_bytes());
    let parsed = file_import::parse_paragraphs(&paragraphs, &settings, &env).expect("parse");
    let source = source.to_owned();
    st.write(move |tx| apply_file_import(tx, &source, &parsed.actions, None))
        .expect("apply");
}

fn setup(tag: &str) -> (Tmp, Store, Arc<QuerySettings>) {
    let p = std::env::temp_dir().join(format!("irrd-ng-query-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 32 << 20;
    let st = Store::open(&o, StoreSettings::default()).expect("store");
    load(&st, "TEST1", TEST1);
    load(&st, "TEST2", TEST2);
    let mut s = QuerySettings {
        version: "4.5.4".into(),
        sources: vec!["TEST1".into(), "TEST2".into()],
        ..QuerySettings::default()
    };
    s.per_source
        .insert("TEST1".into(), SourceQuerySettings::default());
    s.source_aliases
        .push(("ALIAS".into(), vec!["TEST2".into()]));
    (Tmp(p), st, Arc::new(s))
}

fn session(settings: &Arc<QuerySettings>) -> WhoisSession {
    WhoisSession::new(
        settings.clone(),
        Arc::new(NrtmServer),
        "192.0.2.1",
        "192.0.2.1:65000",
    )
}

fn whois(s: &mut WhoisSession, st: &Store, q: &str) -> String {
    let mut out = Vec::new();
    s.query_whois(st, q, &mut out);
    String::from_utf8(out).expect("utf8")
}

fn one(st: &Store, settings: &Arc<QuerySettings>, q: &str) -> String {
    whois(&mut session(settings), st, q)
}

fn irrd_body(resp: &str) -> &str {
    let rest = resp.split_once('\n').map(|x| x.1).unwrap_or_default();
    rest.strip_suffix("\nC\n").unwrap_or(rest)
}

#[test]
fn version_and_framing() {
    let (_t, st, s) = setup("version");
    assert_eq!(one(&st, &s, "!v"), "A22\nIRRd -- version 4.5.4\nC\n");
    assert_eq!(one(&st, &s, "!x"), "F Unrecognised command: x\n");
    assert_eq!(one(&st, &s, "!"), "F Missing IRRD command\n");
    assert_eq!(one(&st, &s, "!g"), "F Missing parameter for g query\n");
    assert_eq!(
        one(&st, &s, "a\0b"),
        "F Queries may not contain null bytes\n"
    );
    assert_eq!(one(&st, &s, "!t0"), "F Invalid value for timeout: 0\n");
    assert_eq!(
        one(&st, &s, "!t1001"),
        "F Invalid value for timeout: 1001\n"
    );
    assert_eq!(
        one(&st, &s, "!a"),
        "F Missing required set name for A query\n"
    );
    assert_eq!(
        one(&st, &s, "!a4"),
        "F Missing required set name for A query\n"
    );
    assert_eq!(
        one(&st, &s, "!mfoo"),
        "F Invalid argument for object lookup: foo\n"
    );
    assert_eq!(
        one(&st, &s, "!rfoo"),
        "F Invalid input for route search: foo\n"
    );
    assert_eq!(
        one(&st, &s, "!r192.0.2.0/24,x"),
        "F Invalid route search option: x\n"
    );
    // v4 raises a ValueError on unpacking, an internal error.
    assert_eq!(
        one(&st, &s, "!r192.0.2.0/24,o,x"),
        "F An internal error occurred while processing this query.\n"
    );
    assert_eq!(
        one(&st, &s, "-z"),
        "%% ERROR: Unrecognised flag/search: z\n\n\n"
    );
    assert_eq!(
        one(&st, &s, "-x"),
        "%% ERROR: Missing argument for flag/search: x\n\n\n"
    );
    assert_eq!(
        one(&st, &s, "-k"),
        "%  No entries found for the selected source(s).\n\n\n"
    );
}

#[test]
fn routes_for_origin() {
    let (_t, st, s) = setup("origin");
    assert_eq!(
        one(&st, &s, "!gAS65537"),
        "A26\n192.0.2.0/24 192.0.2.0/25\nC\n"
    );
    assert_eq!(one(&st, &s, "!6as65537"), "A14\n2001:db8::/32\nC\n");
    assert_eq!(one(&st, &s, "!gAS1"), "D\n");
    assert!(one(&st, &s, "!gfoo").starts_with("F Invalid AS number"));
}

#[test]
fn set_members() {
    let (_t, st, s) = setup("sets");
    // TEST1 comes first; its AS-TOP wins over TEST2's.
    assert_eq!(
        irrd_body(&one(&st, &s, "!iAS-TOP")),
        "AS-LOOP AS-MID AS65537"
    );
    // Recursive: loops are cut, unresolvable names dropped, sorted.
    assert_eq!(irrd_body(&one(&st, &s, "!iAS-TOP,1")), "AS65537 AS65538");
    // mbrs-by-ref: only aut-nums whose mnt-by is listed.
    assert_eq!(irrd_body(&one(&st, &s, "!iAS-REF")), "AS65537");
    assert_eq!(one(&st, &s, "!iAS-EMPTY"), "D\n");
    assert_eq!(one(&st, &s, "!iAS-NONE"), "D\n");
    assert_eq!(
        irrd_body(&one(&st, &s, "!iRS-TOP,1")),
        "192.0.2.0/24 192.0.2.0/25 198.51.100.0/24^+ 2001:db8::/32"
    );
    assert_eq!(irrd_body(&one(&st, &s, "!iRS-REF")), "192.0.2.0/24");
    assert_eq!(
        irrd_body(&one(&st, &s, "!aAS-TOP")),
        "192.0.2.0/24 192.0.2.0/25 198.51.100.0/24 2001:db8::/32"
    );
    assert_eq!(irrd_body(&one(&st, &s, "!a6AS-TOP")), "2001:db8::/32");
    let mut ses = session(&s);
    assert_eq!(whois(&mut ses, &st, "!!"), "");
    assert_eq!(whois(&mut ses, &st, "!eas-mid"), "C\n");
    assert_eq!(whois(&mut ses, &st, "!e-lc"), "A7\nAS-MID\nC\n");
    assert_eq!(irrd_body(&whois(&mut ses, &st, "!iAS-TOP,1")), "AS65537");
    assert_eq!(whois(&mut ses, &st, "!sTEST2"), "C\n");
    assert_eq!(whois(&mut ses, &st, "!s-lc"), "A6\nTEST2\nC\n");
    assert_eq!(irrd_body(&whois(&mut ses, &st, "!iAS-TOP")), "AS65539");
    assert_eq!(
        whois(&mut ses, &st, "!sFOO"),
        "F One or more selected sources are unavailable.\n"
    );
}

#[test]
fn object_queries_follow_v4_order() {
    let (_t, st, s) = setup("objects");
    let r = one(&st, &s, "!r192.0.2.0/24,o");
    // ip_first, asn_first, rpsl_pk; the TEST2 copy ties with TEST1's and
    // follows insertion order.
    assert_eq!(irrd_body(&r), "AS65537 AS65537 AS65538");
    let l = one(&st, &s, "!r192.0.2.0/25,l");
    assert_eq!(l.matches("route:").count(), 3);
    assert_eq!(
        one(&st, &s, "!r192.0.2.0/24,M").matches("route:").count(),
        1
    );
    assert_eq!(
        one(&st, &s, "!r192.0.2.0/25,L").matches("route:").count(),
        4
    );
    let m = one(&st, &s, "!mroute,192.0.2.0/24 as-65537");
    assert!(m.contains("source:         TEST1"));
    assert_eq!(one(&st, &s, "!mAUT-NUM,AS65537"), "D\n");
    let o = one(&st, &s, "!oMNT-B");
    assert!(o.starts_with("A") && o.matches("route:").count() == 2);
    // Password hashes are filtered from every answer.
    let mntner = one(&st, &s, "-s TEST1 MNT-A");
    assert!(mntner.contains("auth:           CRYPT-PW DummyValue  # Filtered for security"));
    // Free text: person names, case-insensitively.
    assert!(one(&st, &s, "alice").contains("nic-hdl:        AE1-TEST"));
    assert!(one(&st, &s, "-i mnt-by mnt-b").contains("AS65538"));
    assert!(
        one(&st, &s, "-i MNT-BY x")
            .starts_with("%% ERROR: Inverse attribute search not supported for MNT-BY,only")
    );
}

/// Regression: `-K` output is stripped like every other result (v4's
/// `_flatten_query_output` strips both branches), so RIPE answers end in
/// exactly three newlines, for one, several or no results, over whois and
/// HTTP.
#[test]
fn key_fields_only() {
    let (_t, st, s) = setup("keyfields");
    assert_eq!(one(&st, &s, "-K AS65537"), "aut-num: AS65537\n\n\n");
    assert_eq!(
        one(&st, &s, "-K -s TEST1 -T as-set AS-TOP"),
        "as-set: AS-TOP\nmembers: AS65537\nmembers: AS-MID\nmembers: AS-LOOP\n\n\n"
    );
    assert_eq!(
        one(&st, &s, "-K -x 192.0.2.0/24"),
        "route: 192.0.2.0/24\norigin: AS65537\n\nroute: 192.0.2.0/24\norigin: AS65538\n\n\n"
    );
    assert_eq!(
        one(&st, &s, "-K -x 203.0.113.0/24"),
        "%  No entries found for the selected source(s).\n\n\n"
    );
    let mut h = session(&s);
    let r = h.query_http(&st, "-K -i mnt-by MNT-B");
    assert_eq!(r.response_type, ResponseType::Success);
    assert_eq!(
        h.result(),
        "route: 192.0.2.0/24\norigin: AS65538\n\nroute: 198.51.100.0/24\norigin: AS65538"
    );
    let mut h = session(&s);
    h.query_http(&st, "-K -x 203.0.113.0/24");
    assert_eq!(h.result(), "");
}

#[test]
fn templates_match_reference() {
    let (_t, st, s) = setup("templates");
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/reference/templates");
    for c in ["route", "aut-num", "as-set", "mntner", "person"] {
        let expected = std::fs::read_to_string(dir.join(format!("{c}.txt"))).expect("template");
        let got = one(&st, &s, &format!("-t {c}"));
        assert_eq!(got.trim_end(), expected.trim_end(), "{c}");
    }
    assert_eq!(
        one(&st, &s, "-t foo"),
        "%% ERROR: Unknown object class: foo\n\n\n"
    );
}

const EDGES: &str = "\
route:          0.0.0.0/0
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3

route:          192.0.2.1/32
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3

route:          255.255.255.255/32
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3

route6:         ::/0
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3

route6:         2001:db8::1/128
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3

route6:         ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
origin:         AS65599
mnt-by:         MNT-A
source:         TEST3
";

/// Regression: prefix masks at /0 and at full length (/32, /128) once
/// overflowed. Every route search variant at the edges of both address
/// families, with the counts v4's SQL predicates give.
#[test]
fn route_searches_at_prefix_length_edges() {
    let p = std::env::temp_dir().join(format!("irrd-ng-query-edges-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let _t = Tmp(p.clone());
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 32 << 20;
    let st = Store::open(&o, StoreSettings::default()).expect("store");
    load(&st, "TEST3", EDGES);
    let s = Arc::new(QuerySettings {
        version: "4.5.4".into(),
        sources: vec!["TEST3".into()],
        ..QuerySettings::default()
    });
    let count = |q: &str| {
        let r = one(&st, &s, q);
        assert!(!r.contains("internal error"), "{q}: {r}");
        r.matches("origin:").count()
    };
    // (query, !r count, -x/-l/-L/-M count): exact, one level less, less
    // with exact, more specific.
    let cases: &[(&str, [usize; 4])] = &[
        ("0.0.0.0/0", [1, 0, 1, 2]),
        ("192.0.2.1/32", [1, 1, 2, 0]),
        ("192.0.2.1", [1, 1, 2, 0]),
        ("255.255.255.255/32", [1, 1, 2, 0]),
        ("192.0.2.0/24", [0, 1, 1, 1]),
        ("::/0", [1, 0, 1, 2]),
        ("2001:db8::1/128", [1, 1, 2, 0]),
        ("2001:db8::1", [1, 1, 2, 0]),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", [1, 1, 2, 0]),
        ("2001:db8::/32", [0, 1, 1, 1]),
    ];
    for (prefix, [exact, one_less, less, more]) in cases {
        assert_eq!(count(&format!("!r{prefix}")), *exact, "!r{prefix}");
        assert_eq!(count(&format!("!r{prefix},l")), *one_less, "!r{prefix},l");
        assert_eq!(count(&format!("!r{prefix},L")), *less, "!r{prefix},L");
        assert_eq!(count(&format!("!r{prefix},M")), *more, "!r{prefix},M");
        assert_eq!(count(&format!("-x {prefix}")), *exact, "-x {prefix}");
        assert_eq!(count(&format!("-l {prefix}")), *one_less, "-l {prefix}");
        assert_eq!(count(&format!("-L {prefix}")), *less, "-L {prefix}");
        assert_eq!(count(&format!("-M {prefix}")), *more, "-M {prefix}");
        let o = one(&st, &s, &format!("!r{prefix},o"));
        assert!(!o.contains("internal error"));
        // Free text takes the less-specific path.
        assert_eq!(count(prefix), *less, "{prefix}");
    }
    assert_eq!(
        irrd_body(&one(&st, &s, "!gAS65599")),
        "0.0.0.0/0 192.0.2.1/32 255.255.255.255/32"
    );
    assert_eq!(
        irrd_body(&one(&st, &s, "!6AS65599")),
        "::/0 2001:db8::1/128 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    );
}

/// Route6 objects in and around `::/96` (v4's run had `::/0` too, out of
/// scope there, so it is left out), where IPy guesses the broadcast
/// address as IPv4 and v4 stores and compares `ip_last` as IPv4 text.
const EDGE96: &str = "\
route6:         ::/8
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/64
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/96
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/104
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/120
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/128
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::1/128
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::102:300/120
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::ffff:0:0/96
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::ffff:c000:200/120
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::1:0:0/96
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::2:0:0/95
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         2001:db8::/32
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         ::/95
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96

route6:         0:0:0:1::/64
origin:         AS65599
mnt-by:         MNT-EDGE
source:         EDGE96
";

/// Regression: IPv6 searches in and around `::/96` give v4's results.
/// Counts measured on v4 4.5.4 with the same objects (`!r` with each
/// option, `-x/-l/-L/-M`, free text, free text with `-T route6`).
#[test]
fn ipv6_searches_inside_96() {
    let p = std::env::temp_dir().join(format!("irrd-ng-query-edge96-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    let _t = Tmp(p.clone());
    let mut o = StoreOptions::new(&p);
    o.initial_map_size = 32 << 20;
    let st = Store::open(&o, StoreSettings::default()).expect("store");
    load(&st, "EDGE96", EDGE96);
    let s = Arc::new(QuerySettings {
        version: "4.5.4".into(),
        sources: vec!["EDGE96".into()],
        ..QuerySettings::default()
    });
    let count = |q: &str| one(&st, &s, q).matches("origin:").count();
    let cases: &[(&str, [usize; 10])] = &[
        ("::/0", [0, 0, 0, 15, 0, 0, 0, 15, 0, 0]),
        ("::/8", [1, 0, 1, 13, 1, 0, 1, 13, 1, 1]),
        ("::/95", [1, 1, 3, 7, 1, 1, 3, 7, 3, 3]),
        ("::/96", [1, 1, 4, 5, 1, 1, 4, 5, 4, 4]),
        ("::/97", [0, 1, 4, 5, 0, 1, 4, 5, 4, 4]),
        ("::/104", [1, 1, 5, 3, 1, 1, 5, 3, 5, 5]),
        ("::/120", [1, 1, 6, 2, 1, 1, 6, 2, 6, 6]),
        ("::/128", [1, 1, 7, 0, 1, 1, 7, 0, 7, 7]),
        ("::1", [1, 1, 7, 0, 1, 1, 7, 0, 7, 7]),
        ("::102:304", [0, 1, 5, 0, 0, 1, 5, 0, 5, 5]),
        ("::ffff:0:0/96", [1, 1, 3, 1, 1, 1, 3, 1, 3, 3]),
        ("::1:0:0/96", [1, 1, 4, 0, 1, 1, 4, 0, 4, 4]),
        ("::/64", [1, 1, 2, 11, 1, 1, 2, 11, 2, 2]),
    ];
    for (prefix, expected) in cases {
        let got = [
            count(&format!("!r{prefix}")),
            count(&format!("!r{prefix},l")),
            count(&format!("!r{prefix},L")),
            count(&format!("!r{prefix},M")),
            count(&format!("-x {prefix}")),
            count(&format!("-l {prefix}")),
            count(&format!("-L {prefix}")),
            count(&format!("-M {prefix}")),
            count(prefix),
            count(&format!("-T route6 {prefix}")),
        ];
        assert_eq!(&got, expected, "{prefix}");
    }
}

/// v4 prints `rpki_status.name` (lower case), with the comment only for
/// `not_found`, on route and route6 objects outside the RPKI source.
#[test]
fn rpki_ov_state_uses_v4_member_names() {
    let (_tmp, st, settings) = setup("rpki-ov-state");
    let mut s = (*settings).clone();
    s.rpki_enabled = true;
    let settings = Arc::new(s);
    let cases = [
        (
            store::RpkiStatus::NotFound,
            "rpki-ov-state:  not_found # No ROAs found, or RPKI validation not enabled for source\n",
        ),
        (store::RpkiStatus::Valid, "rpki-ov-state:  valid\n"),
    ];
    for (status, line) in cases {
        let row = {
            let rtx = st.read().expect("read");
            let view = rtx.view();
            let found = view
                .objects(Some("TEST2"), Some("route"))
                .expect("objects")
                .next()
                .expect("route")
                .expect("row");
            let mut row = found.1.to_row();
            row.rpki_status = status;
            row
        };
        st.write(move |tx| tx.put_rpsl_object(&row)).expect("write");
        let out = one(&st, &settings, "!r192.0.2.0/24");
        assert!(out.contains(line), "{status:?}: {out:?}");
        assert!(
            !out.contains("VALID") && !out.contains("NOT_FOUND"),
            "{out:?}"
        );
    }
}
