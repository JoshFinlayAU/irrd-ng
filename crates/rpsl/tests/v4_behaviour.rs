//! v4 behaviour the file oracle cannot record: inputs on which v4 itself
//! raises, and API options the importers do not use. Expected values were
//! taken from the pinned v4 4.5.4 container.

#![allow(clippy::unwrap_used, clippy::panic)]

use rpsl::{
    Keyring, ParseError, ParseOptions, RpslObject, RpslSettings, Value, rpsl_object_from_text,
};

fn parse(text: &str, strict: bool, default_source: Option<&str>) -> Result<RpslObject, ParseError> {
    let settings = RpslSettings::default();
    let keyring = Keyring::new();
    rpsl_object_from_text(
        text,
        &ParseOptions {
            strict,
            default_source,
            settings: &settings,
            keyring: &keyring,
        },
    )
}

fn uncaught(text: &str, strict: bool) -> String {
    match parse(text, strict, None) {
        Err(ParseError::Uncaught(e)) => e,
        other => panic!("expected an uncaught v4 exception, got {other:?}"),
    }
}

fn messages(obj: &RpslObject) -> Vec<(String, String)> {
    obj.messages()
        .all()
        .iter()
        .map(|(l, m)| (l.as_str().to_owned(), m.clone()))
        .collect()
}

#[test]
fn duplicate_key_metadata_raises_in_non_strict_mode() {
    assert_eq!(
        uncaught(
            "route: 192.0.2.0/24\nroute: 192.0.2.0/25\norigin: AS1\nsource: TEST",
            false
        ),
        "Parsing of 192.0.2.0/25 reads 192.0.2.0 for ip_first,but value 192.0.2.0 is already set."
    );
    assert_eq!(
        uncaught(
            "route: 192.0.2.0/24\norigin: AS1\norigin: AS2\nsource: TEST",
            false
        ),
        "Parsing of AS2 reads 2 for asn_first,but value 1 is already set."
    );
}

#[test]
fn duplicate_as0_origin_does_not_raise() {
    // AS0 is falsy in Python, so v4 does not notice the conflict.
    let obj = parse(
        "route: 192.0.2.0/24\norigin: AS0\norigin: AS2\nsource: TEST",
        false,
        None,
    )
    .unwrap();
    assert!(obj.messages().all().is_empty());
    assert_eq!(
        obj.parsed_value("origin"),
        Some(&Value::Str("\nAS2".to_owned()))
    );
    assert_eq!(
        obj.render_rpsl_text(),
        "route:          192.0.2.0/24\norigin:         AS0\norigin:         AS2\nsource:         TEST\n"
    );
}

#[test]
fn duplicate_key_in_strict_mode_is_an_error() {
    let obj = parse(
        "route: 192.0.2.0/24\nroute: 192.0.2.0/25\norigin: AS1\nmnt-by: M\nsource: TEST",
        true,
        None,
    )
    .unwrap();
    assert_eq!(
        messages(&obj),
        vec![
            (
                "ERROR".to_owned(),
                "Attribute \"route\" on object route occurs multiple times, but is only allowed once".to_owned()
            ),
            (
                "ERROR".to_owned(),
                "Invalid name: M: contains invalid characters, does not start with a letter, or does not end in a letter/digit".to_owned()
            ),
        ]
    );
    assert_eq!(
        obj.parsed_value("route"),
        Some(&Value::Str("\n192.0.2.0/25".to_owned()))
    );
}

#[test]
fn unbalanced_url_bracket_raises() {
    assert_eq!(
        uncaught(
            "inet6num: 2001:db8::/48\nnetname: N\ncountry: NL\nadmin-c: P\ntech-c: P\nstatus: x\ngeofeed: https://[::1/x\nmnt-by: M\nsource: TEST",
            true
        ),
        "Invalid IPv6 URL"
    );
}

#[test]
fn key_cert_text_outside_latin1_raises() {
    assert_eq!(
        uncaught(
            "key-cert: PGPKEY-12345678\ncertif: a\u{20ac}b\nmnt-by: TEST-MNT\nsource: TEST",
            true
        ),
        "'latin-1' codec can't encode character '\\u20ac' in position 1: ordinal not in range(256)"
    );
    assert_eq!(
        uncaught(
            "key-cert: PGPKEY-12345678\ncertif: x\ncertif: \u{20ac}\u{20ac}b\nmnt-by: TEST-MNT\nsource: TEST",
            true
        ),
        "'latin-1' codec can't encode characters in position 2-3: ordinal not in range(256)"
    );
}

#[test]
fn empty_line_inside_object() {
    let obj = parse(
        "route: 192.0.2.0/24\n\norigin: AS1\nsource: TEST",
        true,
        None,
    )
    .unwrap();
    assert_eq!(
        obj.messages().errors().next(),
        Some("Line 2: encountered empty line in the middle of object: []")
    );
    // As in v4, there is no source and render_rpsl_text would raise.
    assert!(obj.source().is_err());
}

#[test]
fn default_source() {
    let obj = parse("route: 192.0.2.0/24\norigin: AS1", false, Some(" test ")).unwrap();
    assert!(obj.messages().all().is_empty());
    assert_eq!(obj.source().unwrap(), "TEST");
    assert_eq!(
        obj.render_rpsl_text(),
        "route:          192.0.2.0/24\norigin:         AS1\n"
    );

    let obj = parse("route: 192.0.2.0/24\norigin: AS1", false, Some("  ")).unwrap();
    assert_eq!(
        obj.messages().errors().collect::<Vec<_>>(),
        vec!["Primary key attribute \"source\" on object route is missing"]
    );

    let obj = parse(
        "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M",
        true,
        Some("test"),
    )
    .unwrap();
    assert_eq!(
        obj.messages().errors().next(),
        Some("Mandatory attribute \"source\" on object route is missing")
    );
    assert_eq!(obj.source().unwrap(), "TEST");
}

#[test]
fn render_with_last_modified() {
    let settings = RpslSettings::default();
    let obj = parse(
        "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: TEST\nlast-modified: x",
        true,
        None,
    )
    .unwrap();
    // 2024-02-03T04:05:06Z
    assert_eq!(
        obj.render_rpsl_text_with_last_modified(1_706_933_106, &settings),
        "route:          192.0.2.0/24\norigin:         AS1\nmnt-by:         M\nsource:         TEST\nlast-modified:  2024-02-03T04:05:06Z\n"
    );
    let obj = parse(
        "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: OTHER\nlast-modified: x",
        true,
        None,
    )
    .unwrap();
    assert_eq!(
        obj.render_rpsl_text_with_last_modified(1_706_933_106, &settings),
        "route:          192.0.2.0/24\norigin:         AS1\nmnt-by:         M\nsource:         OTHER\nlast-modified:  x\n"
    );
}

#[test]
fn clean_for_create_set_names() {
    let mut settings = RpslSettings::default();
    let invalid_m = "Invalid name: M: contains invalid characters, does not start with a letter, or does not end in a letter/digit";

    let mut obj = parse("as-set: AS-FOO\nmnt-by: M\nsource: TEST", true, None).unwrap();
    assert!(!obj.clean_for_create(&settings));
    assert_eq!(
        obj.messages().errors().collect::<Vec<_>>(),
        vec![
            invalid_m,
            "as-set names must be hierarchical and the first component must be an AS number, e.g. \"AS65537:None\": Invalid AS number AS-FOO: number part is not numeric"
        ]
    );
    assert_eq!(obj.pk_asn_segment, None);

    let mut obj = parse(
        "as-set: AS65537:AS-FOO\nmnt-by: M\nsource: TEST",
        true,
        None,
    )
    .unwrap();
    assert!(obj.clean_for_create(&settings));
    assert_eq!(obj.pk_asn_segment.as_deref(), Some("AS65537"));

    let mut obj = parse(
        "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: TEST",
        true,
        None,
    )
    .unwrap();
    assert!(obj.clean_for_create(&settings));
    assert_eq!(obj.pk_asn_segment, None);

    let mut obj = parse("route-set: RS-FOO\nmnt-by: M\nsource: TEST", true, None).unwrap();
    assert!(!obj.clean_for_create(&settings));
    assert_eq!(
        obj.messages().errors().last(),
        Some(
            "route-set names must be hierarchical and the first component must be an AS number, e.g. \"AS65537:None\": Invalid AS number RS-FOO: must start with \"AS\""
        )
    );

    settings
        .set_creation_prefix_required
        .insert("route-set".to_owned(), false);
    let mut obj = parse("route-set: RS-FOO\nmnt-by: M\nsource: TEST", true, None).unwrap();
    assert!(obj.clean_for_create(&settings));
}

#[test]
fn repr_and_message_display() {
    let obj = parse(
        "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: TEST",
        true,
        None,
    )
    .unwrap();
    assert_eq!(obj.to_string(), "route/192.0.2.0/24AS1/TEST");
    let obj = parse("route: 192.0.2.1/24\norigin: as1\nsource: TEST", true, None).unwrap();
    assert_eq!(
        obj.messages().to_string(),
        "ERROR: Mandatory attribute \"mnt-by\" on object route is missing\nERROR: Invalid address prefix: 192.0.2.1/24: invalid prefix length (24)"
    );
}

#[test]
fn unknown_class_is_case_sensitive() {
    match parse("Route: 192.0.2.0/24\norigin: AS1\nsource: TEST", true, None) {
        Err(ParseError::UnknownClass { class }) => assert_eq!(class, "Route"),
        other => panic!("{other:?}"),
    }
    let err = parse("foo-block: x", true, None).unwrap_err();
    assert_eq!(err.to_string(), "unknown object class: foo-block");
}

#[test]
fn lookup_field_names_match_v4() {
    assert_eq!(
        rpsl::lookup_field_names(),
        vec![
            "admin-c",
            "mbrs-by-ref",
            "member-of",
            "members",
            "mnt-by",
            "mp-members",
            "origin",
            "person",
            "role",
            "tech-c",
            "zone-c"
        ]
    );
}
