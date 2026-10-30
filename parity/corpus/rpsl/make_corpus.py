"""Write the synthetic RPSL corpus files (*.db) in this directory.

Real IRR dumps rarely contain the cases below, so they are written by hand:
comment and whitespace lines inside objects, CRLF and lone CR line ends,
invalid UTF-8, every class with every attribute, odd continuation lines,
and each error path in irrd/rpsl/parser.py and fields.py. The v4 oracle's
output for each file is committed as expected.<name>.jsonl (regen.sh).

No case may make v4 itself raise, since the oracle would stop: those
(duplicate key attributes in non-strict mode, unbalanced URL brackets,
non Latin-1 key-cert text) are unit tests in crates/rpsl instead.

Usage: python3 -I make_corpus.py
"""

import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def write(name, paragraphs, sep=b"\n\n", prefix=b"", suffix=b"\n"):
    data = prefix + sep.join(p if isinstance(p, bytes) else p.encode("utf-8") for p in paragraphs) + suffix
    with open(os.path.join(HERE, name + ".db"), "wb") as f:
        f.write(data)


def obj(*lines):
    return "\n".join(lines)


ROUTE_TAIL = ("mnt-by:         TEST-MNT", "source:         TEST")

# ---------------------------------------------------------------------------
# text: file decoding and paragraph splitting
# ---------------------------------------------------------------------------
text = [
    # A BOM at the start of the file is kept by Python's utf-8 codec.
    "﻿person: BOM Person\naddress: x\nphone: +1\ne-mail: a@example.net\nnic-hdl: BOM1-TEST\nmnt-by: TEST-MNT\nsource: TEST",
    # Comment lines inside an object: '%' and '#' lines are dropped.
    obj("route:          192.0.2.0/24", "% a percent comment", "descr:          d", "# a hash comment",
        "origin:         AS65537", *ROUTE_TAIL),
    # A whitespace-only line is a continuation, not a paragraph break.
    obj("route:          192.0.2.0/24", "descr:          first", "   ", "\t", "origin:         AS65537", *ROUTE_TAIL),
    # '#' inside a value starts an inline comment.
    obj("route:          192.0.2.0/24 # inline comment", "origin:         AS65537 #c", "descr: # only comment",
        *ROUTE_TAIL),
    # Comment lines between objects.
    "% comment between objects\n# another",
    obj("route6:         2001:db8::/32", "origin:         AS65537", *ROUTE_TAIL),
]
crlf = obj("route:          198.51.100.0/24", "descr:          crlf object", "origin:         AS65537",
           *ROUTE_TAIL).replace("\n", "\r\n").encode()
lone_cr = b"route:          198.51.100.0/24\rdescr:          lone cr splits lines\norigin: AS65537\nmnt-by: TEST-MNT\nsource: TEST"
invalid_utf8 = (b"route:          203.0.113.0/24\ndescr:          bad \xff\xfe bytes \xe2\x82 and \xc3\nremarks: \xed\xa0\x80 surrogate\n"
                b"origin:         AS65537\nmnt-by:         TEST-MNT\nsource:         TEST")
invalid_pk = b"person: Bad Bytes\naddress: x\nphone: 1\ne-mail: a@example.net\nnic-hdl: BAD\xff-TEST\nmnt-by: TEST-MNT\nsource: TEST"
trailing = b"route: 192.0.2.0/24  \t\norigin: AS65537\t\nmnt-by: TEST-MNT \nsource: TEST   "
write("text", text + [crlf, lone_cr, invalid_utf8, invalid_pk, trailing], sep=b"\n\n\n")
# A file without a final newline, and with blank lines that hold only '\r'.
with open(os.path.join(HERE, "text-noeol.db"), "wb") as f:
    f.write(b"\r\n\r\nperson: No EOL\r\naddress: x\r\nphone: 1\r\ne-mail: a@example.net\r\nnic-hdl: NOEOL-TEST\r\n"
            b"\r\n\r\n%START\r\nmnt-by: TEST-MNT\r\nsource: TEST")

# ---------------------------------------------------------------------------
# classes: every class with every attribute
# ---------------------------------------------------------------------------
COMMON = ("remarks:        a remark", "notify:         notify@example.net", "mnt-by:         TEST-MNT, OTHER-MNT",
          "changed:        changed@example.net 20240101", "source:         TEST", "last-modified:  2024-01-01T00:00:00Z")
CONTACTS = ("admin-c:        PERSON-TEST", "tech-c:         ROLE-TEST")
classes = [
    obj("as-block:       AS65536 - as065538", "descr:          block", *CONTACTS, *COMMON),
    obj("as-set:         AS65537:AS-SETTEST", "descr:          set", "members:        AS65538, as65539, AS-OTHER",
        "members:        AS65540:AS-NESTED", "mbrs-by-ref:    TEST-MNT", *CONTACTS, *COMMON),
    obj("as-set:         AS-ANYREF", "mbrs-by-ref:    ANY", "mnt-by: TEST-MNT", "source: TEST"),
    obj("aut-num:        as065537", "as-name:        AS-EXAMPLE", "descr:          aut-num",
        "member-of:      AS-SETTEST", "import:         from AS65538 accept ANY", "mp-import:      afi ipv6 from AS1 accept ANY",
        "import-via:     AS1 from AS2 accept ANY", "export:         to AS65538 announce AS65537",
        "mp-export:      afi ipv6 to AS1 announce AS2", "export-via:     AS1 to AS2 announce AS3",
        "default:        to AS65538", "mp-default:     to AS65538", *CONTACTS, *COMMON),
    obj("domain:         2.0.192.in-addr.arpa", "descr:          domain", *CONTACTS, "zone-c:         PERSON-TEST",
        "nserver:        ns1.example.net", "sub-dom:        x", "dom-net:        192.0.2.0", "refer:          SIMPLE",
        *COMMON),
    obj("filter-set:     fltr-settest", "descr:          filter", "filter:         { 192.0.2.0/24 }",
        "mp-filter:      { 2001:db8::/32 }", *CONTACTS, *COMMON),
    obj("inet-rtr:       rtr.example.com", "descr:          router", "alias:          alias.example.com",
        "local-as:       AS65537", "ifaddr:         192.0.2.1 masklen 24", "interface:      2001:db8::1 masklen 64",
        "peer:           BGP4 192.0.2.2 asno(AS65538)", "mp-peer:        BGP4 2001:db8::2 asno(AS65538)",
        "member-of:      rtrs-settest", "rs-in:          from AS1 accept ANY", "rs-out:         to AS1 announce ANY",
        *CONTACTS, *COMMON),
    obj("inet6num:       2001:db8::/48", "netname:        NET-TEST", "descr:          inet6num", "country:        NL",
        *CONTACTS, "rev-srv:        ns.example.net", "status:         ASSIGNED", "geofeed:        https://example.net/geo.csv",
        *COMMON),
    obj("inetnum:        192.0.2.0 - 192.0.02.255", "netname:        NET-TEST", "descr:          inetnum",
        "country:        NL", *CONTACTS, "rev-srv:        ns.example.net", "status:         ASSIGNED PA",
        "geofeed:        http://example.net/geo.csv", *COMMON),
    obj("irt:            IRT-TEST", "address:        street", "phone:          +31 20 000", "fax-no:         +31 20 001",
        "e-mail:         irt@example.net", "abuse-mailbox:  abuse@example.net", *CONTACTS, *COMMON),
    obj("mntner:         TEST-MNT", "descr:          maintainer", *CONTACTS, "upd-to:         upd@example.net",
        "mnt-nfy:        nfy@example.net", "auth:           PGPKEY-80F238C6", "auth:           IRRD-INTERNAL-AUTH",
        "auth:           BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa", *COMMON),
    obj("organisation:   ORG-TEST", "org-name:       Test Org", "country:        NL", "address:        street",
        "phone:          +31", "fax-no:         +32", "e-mail:         org@example.net", *CONTACTS, *COMMON),
    obj("peering-set:    prng-settest", "descr:          peering", "peering:        AS65537 at 192.0.2.1",
        "mp-peering:     AS65537 at 2001:db8::1", *CONTACTS, *COMMON),
    obj("person:         Test person", "address:        street", "phone:          +31", "fax-no:         +32",
        "e-mail:         person@example.net", "nic-hdl:        PERSON-TEST", *COMMON),
    obj("role:           Test role", "trouble:        call", "address:        street", "phone:          +31",
        "fax-no:         +32", "e-mail:         role@example.net", *CONTACTS, "nic-hdl:        ROLE-TEST", *COMMON),
    obj("route:          192.0.02.0/24", "descr:          route", "origin:         AS65537",
        "holes:          192.0.2.0/25, 192.0.2.128/26", "member-of:      RS-TEST", "inject:         at 192.0.2.1",
        "aggr-bndry:     AS65537", "aggr-mtd:       inbound", "export-comps:   { 192.0.2.0/24 }",
        "components:     protocol BGP4 { 192.0.2.0/25 }", *CONTACTS, "geoidx:         1", "roa-uri:        rsync://x",
        "rpki-ov-state:  valid", *COMMON),
    obj("route-set:      RS-TEST", "members:        192.0.2.0/24^+, 192.0.2.0/24^-, 192.0.2.0/24^25, 192.0.2.0/24^24-26",
        "members:        RS-OTHER^+, AS65537:RS-NESTED, AS65538, as01^-", "mp-members:     2001:db8::/32^48, 192.0.2.1",
        "mbrs-by-ref:    TEST-MNT", "descr:          route-set", *CONTACTS, *COMMON),
    obj("route6:         2001:DB8::/48", "descr:          route6", "origin:         AS65537",
        "holes:          2001:db8::/56, 2001:db8:0:100::/56", "member-of:      RS-TEST", "inject:         at x",
        "aggr-bndry:     AS1", "aggr-mtd:       inbound", "export-comps:   {}", "components:     x", *CONTACTS,
        "geoidx:         1", "roa-uri:        x", "rpki-ov-state:  invalid", *COMMON),
    obj("rtr-set:        rtrs-settest", "descr:          rtr-set", "members:        rtr.example.com, RTRS-OTHER",
        "mp-members:     rtr2.example.com", "mbrs-by-ref:    ANY", *CONTACTS, *COMMON),
]
write("classes", classes)

# ---------------------------------------------------------------------------
# continuation: continuation lines and normalisation
# ---------------------------------------------------------------------------
continuation = [
    obj("inetnum:        192.0.2.0 # comment1", "+- # comment 2", "+192.0.2.255 # comment 3", "+ # comment 4",
        "netname: N", "country: NL", "admin-c: P-TEST", "tech-c: P-TEST", "status: x", "mnt-by: TEST-MNT", "source: TEST"),
    obj("route:          192.0.2.0/24", "descr:          line one", "+", "                line three",
        "\tline four after a tab", "+               ", "origin:         AS65537", *ROUTE_TAIL),
    obj("route:", " 192.0.2.0/24", "origin:", "+AS65537", "mnt-by:", "\tTEST-MNT,", "+ OTHER-MNT ,", "source: TEST"),
    obj("as-set: AS-CONT", "members: AS1,", " AS2, ,", "+, AS3", " ", "mnt-by: TEST-MNT", "source: TEST"),
    obj("route:          192.0.2.0/24", "remarks:", "+", "+", "origin: AS65537", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "remarks:        x", "+   ##### #", "origin: AS65537", *ROUTE_TAIL),
    obj("person:         Long Value " + "x" * 5000, "address:        " + "street " * 800, "phone: 1",
        "e-mail: a@example.net", "nic-hdl: LONG-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("as-set:         AS-CONT2", "members:        AS1 # first", "+AS2 # second", "+# only comment",
        "+  AS3  ", "mnt-by: TEST-MNT", "source: TEST"),
    obj("Route:          192.0.2.0/24", "ORIGIN:         AS65537", "Mnt-By:         TEST-MNT", "SOURCE:         test"),
    obj("route: 192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT", "source: TEST",
        "remarks:value:with:colons", "x-custom_attr-1:  custom"),
]
write("continuation", continuation)

# ---------------------------------------------------------------------------
# parser: object level errors
# ---------------------------------------------------------------------------
parser = [
    obj("foo-block:      192.0.2.0/24", "source: TEST"),
    obj("*xxte:          192.0.2.0/24", "source: TEST"),
    "just some text without a colon",
    obj(" route: 192.0.2.0/24", "origin: AS65537", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "this line has no colon", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "bad attr name: x", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "bad@attr: x", "worse attr: y", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "source: TEST"),
    obj("route:          192.0.2.0/24", "origin: AS65537"),
    obj("route:          192.0.2.0/24", "origin: AS65537", "unknown-attr: x", "unknown-attr: y", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "aggr-mtd: a", "aggr-mtd: b", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT", "source: TEST", "source: OTHER"),
    obj("person:         Two Handles", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: ONE-TEST",
        "nic-hdl: TWO-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("route:          not-a-prefix", "origin: AS65537", *ROUTE_TAIL),
    obj("route:          192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT", "source: TEST-SOURCE!"),
    obj("route:          192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT", "source:"),
    obj("route:          192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT"),
    obj("route:          192.0.2.0/24", "origin: AS65537", "last-modified: a", "last-modified: b", *ROUTE_TAIL),
    obj("mntner:         DUMMY-MNT", "admin-c: P-TEST", "upd-to: a@example.net", "auth: MD5-PW DummyValue",
        "auth: BCRYPT-PW DummyValue", "mnt-by: DUMMY-MNT", "source: TEST"),
    obj("mntner:         MIXED-MNT", "admin-c: P-TEST", "upd-to: a@example.net", "auth: BCRYPT-PW DummyValue",
        "auth: BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa", "mnt-by: MIXED-MNT", "source: TEST"),
    obj("route6: 2001:db8::/32", "origin: AS65537", "mnt-by: TEST-MNT", "member-of: RS-A", "member-of: RS-B, rs-c",
        "admin-c: A-TEST", "admin-c: ANY", "source: TEST"),
    obj("aut-num: AS0", "as-name: ZERO", "admin-c: P-TEST", "tech-c: P-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("as-block: AS0 - AS0", "admin-c: P-TEST", "tech-c: P-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("route: 0.0.0.0/0", "origin: AS0", *ROUTE_TAIL),
    obj("route6: ::/0", "origin: AS4294967295", *ROUTE_TAIL),
    obj("key-cert: PGPKEY-ABCDEF01", "certif: x", "mnt-by: TEST-MNT"),
]
write("parser", parser)

# ---------------------------------------------------------------------------
# fields: every field validation path
# ---------------------------------------------------------------------------


def route(prefix, *extra):
    return obj("route:          " + prefix, "origin:         AS65537", *extra, *ROUTE_TAIL)


def route6(prefix, *extra):
    return obj("route6:         " + prefix, "origin:         AS65537", *extra, *ROUTE_TAIL)


def inetnum(rng):
    return obj("inetnum:        " + rng, "netname: N", "country: NL", "admin-c: P-TEST", "tech-c: P-TEST",
               "status: x", "mnt-by: TEST-MNT", "source: TEST")


def rset(*members):
    return obj("route-set:      RS-FIELDS", *members, "mnt-by: TEST-MNT", "source: TEST")


def autnum(asn, *extra):
    return obj("aut-num:        " + asn, "as-name: TEST", "admin-c: P-TEST", "tech-c: P-TEST", *extra,
               "mnt-by: TEST-MNT", "source: TEST")


fields = []
for p in ["192.0.2.0/24", "192.0.02.0/24", "192.0.2.1/32", "192.0.2.1/24", "192.0.2.0/33", "192.0.2.256/24",
          "192.0.2/24", "192.0.2.0", "192.0.2.0/", "192.0.2.0/24/24", "0192.0.2.0/24", "1.2.3.4/0", "0.0.0.0/0",
          "192.0.2.0/abc", "١٩٢.0.2.0/24", "192.0.2.0/٢٤", "192.0.2.0 /24", "192.0.2.0/24,192.0.3.0/24"]:
    fields.append(route(p))
for p in ["2001:db8::/32", "2001:DB8::/32", "2001:db8:0:0:0:0:0:0/32", "2001:db8::1/128", "2001:db8::1/64",
          "2001:db8::/129", "2001:db8:::/32", "2001:db8::1::/64", "2001:db8:1:2:3:4:5:6:7/64", "20010db8000000000000000000000000/32",
          "::/0", "::/96", "::ffff:0:0/96", "::1:2:3:4:5:6/96", "1:0:0:1:0:0:0:0/64", "fffff::/16", "::ffff:192.0.2.0/120",
          "ABCD/16", "2001:db8::/32 ", "::/1", "0::/0", "1::/16", "1:2:3:4:5:6:7::/112", "::1:0:0:0:0/32",
          "٢٠٠١:db8::/32", "2001:db8:g::/48", "2001:db8::1.2.3.4/128", "2001:db8::-1/64", "1:2:3:4:5:6:7:8::/128"]:
    fields.append(route6(p))
for r in ["192.0.2.0 - 192.0.2.255", "192.0.2.0-192.0.2.255", "192.0.2.0", "192.0.02.0 - 192.0.2.0255",
          "192.0.2.255 - 192.0.2.0", "192.0.2.0 - 2001:db8::1", "2001:db8::1 - 2001:db8::2", "192.0.2.0 - ",
          "192.0.2.0/24", "192.0.2.0/24 - 192.0.3.0/24", "192.0.2.0 - 192.0.2.1 - 192.0.2.3", "10", "300",
          "0x0A000000 - 0x0A0000FF", "192.0.2.0 -192.0.2.9", "a.b.c.d - 1.2.3.4", "1.2.3.4.5 - 1.2.3.5",
          "192.0.2.0/255.255.255.0", "192.0.2.0/255.0.255.0", "192.0.2.0/24 - 192.0.2.255/32", "1.2.3.4/1.2.3.4",
          "192.0.2.0 - 192.0.2.4-192.0.2.7", "192.0.2.4-192.0.2.6 - 192.0.2.9", "4294967295", "4294967296",
          "99999999999999999999999999999999999999999999"]:
    fields.append(inetnum(r))
for m in ["members: 192.0.2.0/24", "members: 192.0.2.0/24^", "members: 192.0.2.0/24^foo", "members: 192.0.2.0/24^23",
          "members: 192.0.2.0/24^23-25", "members: 192.0.2.0/24^25-24", "members: 192.0.2.0/24^1234",
          "members: 192.0.2.0/24^0-0", "members: 192.0.2.1", "members: 2001:db8::/32", "members: ::1.2.3.4",
          "members: rs-lower^+", "members: AS-SET^-", "members: as1", "members: AS1^24", "members: as01:rs-x",
          "members: foo", "members: 192.0.2.0/24^٢٥", "members: 192.0.2.0 - 192.0.2.255",
          "members: 192.0.2.0-192.0.2.255", "members: 192.0.2.5-192.0.2.6", "members: 192.0.2.0/33",
          "members: RS-A:RS-B:RS-C:RS-D:RS-E:RS-F", "members: AS1:AS2", "members: RS-ANY:ANY",
          "mp-members: 2001:db8::/32^48-56", "mp-members: 2001:db8::1", "mp-members: 2001:db8::/32^24",
          "mp-members: 192.0.2.0/24^+", "mp-members: fe80::/10^-", "mp-members: 2001:db8::/32^129",
          "members: 0x0A000000/8", "members: 167772160/8", "members: 192.0.2.0/24^+^-"]:
    fields.append(rset(m))
for a in ["AS65537", "as65537", "AS065537", "65537", "ASX", "AS", "AS-1", "AS+5", "AS 5", "AS1_000", "AS4294967295",
          "AS4294967296", "AS99999999999999999999999999", "AS1.5", "AS١٢", "ASN65537"]:
    fields.append(autnum(a))
for b in ["AS1 - AS2", "AS1-AS2", "as1 - as02", "AS2 - AS1", "AS1", "AS1 - ASX", "ASX - AS1", "AS1 - AS2 - AS3",
          "1 - 2"]:
    fields.append(obj("as-block: " + b, "admin-c: P-TEST", "tech-c: P-TEST", "mnt-by: TEST-MNT", "source: TEST"))
for s in ["AS-TEST", "as-test", "AS65537:AS-TEST", "AS065537:as-test:AS01", "AS1:AS2", "TEST", "AS-TEST:ANY",
          "AS1:AS2:AS3:AS4:AS5:AS-SIX", "AS-A:AS-B:AS-C:AS-D:AS-E", "AS-TEST:", ":AS-TEST", "AS-TEST:RS-TEST",
          "AS-TEST:FOO", "AS-TEST:1FOO", "AS-TEST_", "AS-T", "AS-", "as-te_st"]:
    fields.append(obj("as-set: " + s, "mnt-by: TEST-MNT", "source: TEST"))
for s in ["RS-TEST", "rs-test", "AS1:RS-X", "RS-TEST:AS-X", "FLTR-X"]:
    fields.append(obj("route-set: " + s, "mnt-by: TEST-MNT", "source: TEST"))
for s in ["FLTR-TEST", "fltr-a:fltr-b", "RTRS-X"]:
    fields.append(obj("filter-set: " + s, "filter: ANY", "mnt-by: TEST-MNT", "source: TEST"))
for s in ["PRNG-TEST", "RTRS-TEST"]:
    fields.append(obj("peering-set: " + s, "mnt-by: TEST-MNT", "source: TEST"))
    fields.append(obj("rtr-set: " + s, "mnt-by: TEST-MNT", "source: TEST"))
for e in ["a@example.net", "a.b+c@example.net", "a@[192.0.2.1]", "a@[2001:db8::1]", "a@[IPv6:2001:db8::1]",
          "a@b@c", "@example.net", "a@", "a b@example.net", "a@exa mple.net", "a@exämple.net", "äb@example.net",
          "a@[192.0.2.1", "a@[1.2.3]", "a@[٢.٢.٢.٢]", "$!#%&\"*+/=?^_`{|}~\\.-@x", "a@x\\y", "a@EXAMPLE.NET"]:
    fields.append(obj("person: P", "address: x", "phone: 1", "e-mail: " + e, "nic-hdl: P-TEST",
                      "notify: " + e, "mnt-by: TEST-MNT", "source: TEST"))
for c in ["a@example.net", "a@example.net 20240229", "a@example.net 20230229", "a@example.net 2024", "a@example.net 202401011",
          "a@example.net 20241301", "a@example.net 2024011", "a@example.net 20240100", "a@example.net 00000101",
          "a@example.net 2024 0101", "a@example.net  20240101", "bad 20240101", "a@example.net 202401 1",
          "a@example.net 2024-01-01", "a@example.net ٢٠٢٤0101", "a@example.net 20241231 extra"]:
    fields.append(obj("person: P", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: P-TEST",
                      "changed: " + c, "mnt-by: TEST-MNT", "source: TEST"))
for d in ["rtr.example.com", "RTR.EXAMPLE.COM", "rtr", "-rtr.example.com", "rtr-.example.com", "rtr..example.com",
          "rtr.example.com.", "rtr_x.example.com", "1.2.3.4", "r.e", "ſtr.example.com"]:
    fields.append(obj("inet-rtr: " + d, "local-as: AS1", "alias: " + d, "mnt-by: TEST-MNT", "source: TEST"))
for u in ["https://example.net/x", "HTTP://example.net", "ftp://example.net", "https://", "https:example.net",
          "example.net", "https:///path", "  https://example.net", "https://exa mple.net/?a#b", "1http://x",
          "h+t.tp://x", "https://[2001:db8::1]/x"]:
    fields.append(obj("inet6num: 2001:db8::/48", "netname: N", "country: NL", "admin-c: P-TEST", "tech-c: P-TEST",
                      "status: x", "geofeed: " + u, "mnt-by: TEST-MNT", "source: TEST"))
for n in ["TEST-MNT", "test-mnt", "T", "1TEST", "TEST-", "TEST_X", "AS-MNT", "RS-MNT", "ANY", "any", "PEERAS",
          "TE.ST", "TEST MNT", "FLTR-X", "PRNG-X", "RTRS-X", "AS_X"]:
    fields.append(obj("mntner: " + n, "admin-c: P-TEST", "upd-to: a@example.net", "auth: PGPKEY-12345678",
                      "mnt-by: " + n, "source: TEST"))
for n in ["AS-EXAMPLE", "RS-EXAMPLE", "AS65537"]:
    fields.append(autnum("AS1", "as-name: " + n))
for h in ["P-TEST", "p-test", "AUTO-1", "AS-TEST", "!!!", "ANY", "with space"]:
    fields.append(obj("person: P", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: " + h,
                      "mnt-by: TEST-MNT", "source: TEST"))
    fields.append(obj("role: R", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: " + h,
                      "admin-c: " + h, "tech-c: " + h, "mnt-by: TEST-MNT", "source: TEST"))
for r in ["admin-c: P-TEST", "admin-c: p-test", "admin-c: AS-TEST", "admin-c: bad value", "admin-c: ANY",
          "member-of: AS-SET1, as-set2", "member-of: ANY", "member-of: NOTASET", "member-of: AS1:AS-X",
          "member-of: AS1"]:
    fields.append(autnum("AS1", r))
for r in ["members: AS1, AS-X, as2:as-y", "members: NOTASET", "members: ANY", "mbrs-by-ref: ANY",
          "mbrs-by-ref: any", "mbrs-by-ref: TEST-MNT, ANY", "mbrs-by-ref: ", "members: AS1,,AS2", "members: ,"]:
    fields.append(obj("as-set: AS-REFS", r, "mnt-by: TEST-MNT", "source: TEST"))
for r in ["members: rtr.example.com, RTRS-X", "members: AS1", "mp-members: bad_name", "members: RTRS-A:RTRS-B"]:
    fields.append(obj("rtr-set: RTRS-REFS", r, "mnt-by: TEST-MNT", "source: TEST"))
for h in ["192.0.2.0/25", "192.0.2.0/25, 192.0.2.1/32", "192.0.2.1/24", "bad", "192.0.2.0/25,,"]:
    fields.append(route("192.0.2.0/24", "holes: " + h))
for h in ["2001:db8::/48", "2001:db8::1/32, ::/0", "bad"]:
    fields.append(route6("2001:db8::/32", "holes: " + h))
fields.append(obj("route: 192.0.2.0/24", "origin: as065537", "descr: control \x01\x02 chars\x7f and ‍ zwj ­ shy",
                  "remarks:  line sep and \u0085 nel", *ROUTE_TAIL))
fields.append(obj("inet-rtr: rtr.example.com", "local-as: 65537", "mnt-by: TEST-MNT", "source: TEST"))
write("fields", fields)

# ---------------------------------------------------------------------------
# auth: mntner auth attribute validation (password_hashers from irrd.yaml)
# ---------------------------------------------------------------------------
auth = []
for a in ["CRYPT-PW LEuuhsBJNFV0Q", "crypt-pw LEuuhsBJNFV0Q", "MD5-PW $1$fgW84Y9r$kKEn9MUq8PChNKpQhO6BM.",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "bcrypt-pw $2a$10$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2y$04$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2$16$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$17$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$31$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$32$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$03$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$4$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$012$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2x$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2c$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e", "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0S",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Saa",
          "BCRYPT-PW $2b$12$!TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0f6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sb",
          "BCRYPT-PW $2b$12$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa$",
          "BCRYPT-PW $2b$xx$.TF/gD0SXGhpJsqdmd9u0e6UVdb21ZzoSAAQSTSWD6cvyTm6Ta0Sa",
          "BCRYPT-PW not-a-hash", "BCRYPT-PW DummyValue", "BCRYPT-PW", "BCRYPT-PW  double", "BCRYPT-PW a,b",
          "PGPKEY-80F238C6", "pgpkey-80f238c6", "PGPKEY-80F238C", "PGPKEY-80F238C6A", "PGPKEY-GGGGGGGG",
          "IRRD-INTERNAL-AUTH", "irrd-internal-auth", "MAIL-FROM a@example.net", "NONE", "X509-1",
          "SSO a@example.net", "CRYPT-PW", "MD5-PW DummyValue"]:
    auth.append(obj("mntner: AUTH-MNT", "admin-c: P-TEST", "upd-to: a@example.net", "auth: " + a,
                    "mnt-by: AUTH-MNT", "source: TEST"))
write("auth", auth)

# ---------------------------------------------------------------------------
# unicode: CPython string semantics
# ---------------------------------------------------------------------------
unicode = [
    obj("person: Ünïcødé Persön", "address: Straße 1", "phone: 1", "e-mail: a@example.net", "nic-hdl: straße-TEST",
        "mnt-by: maß-mnt", "source: tést"),
    obj("person: Dotless", "address: x", "phone: 1", "e-mail: ı@example.net", "nic-hdl: ıSTANBUL-TEST",
        "mnt-by: TEST-MNT", "source: TEST"),
    obj("person: Kelvin", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: KELVIN",
        "mnt-by: K-MNT", "source: TEST"),
    obj("person: Ligature", "address: x", "phone: 1", "e-mail: a@example.net", "nic-hdl: ﬁx-TEST",
        "mnt-by: TEST-MNT", "source: TEST"),
    obj("K:  kelvin attribute", "route: 192.0.2.0/24", "origin: AS65537", *ROUTE_TAIL),
    obj("route: 192.0.2.0/24", "KEY: x", "ROUTEſ: y", "İ: z", "origin: AS65537", *ROUTE_TAIL),
    obj("route: 192.0.2.0/24", "ΑΣ: sigma", "origin: AS65537", *ROUTE_TAIL),
    obj("route: 192.0.2.0/24　", "origin: AS65537 ", "descr:\x1c x \x1f", *ROUTE_TAIL),
    obj("route: 192.0.2.0/24", "origin: AS65537", "descr: tab\tinside", "remarks:  ", *ROUTE_TAIL),
    obj("aut-num: AS١٢٣", "as-name: X", "admin-c: P-TEST", "tech-c: P-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("aut-num: AS𝟙𝟚", "as-name: X", "admin-c: P-TEST", "tech-c: P-TEST", "mnt-by: TEST-MNT", "source: TEST"),
    obj("route: 192.0.2.0/24", "origin: AS65537", "mnt-by: ǅ-mnt, ǆ-MNT", "source: TEST"),
    obj("route: 192.0.2.0/24", "origin: AS65537", "mnt-by: TEST-MNT", "source: ŉ-TEST"),
]
write("unicode", unicode)

# ---------------------------------------------------------------------------
# key-cert: GnuPG import emulation, with synthetic keys from keys/
# ---------------------------------------------------------------------------


def key(name):
    with open(os.path.join(HERE, "keys", name + ".asc"), encoding="ascii") as f:
        return f.read().strip().split("\n")


def keyid(lines):
    import subprocess  # noqa: PLC0415  (only used when writing the corpus)

    data = "\n".join(lines).encode()
    out = subprocess.run(["gpg", "--with-colons", "--import-options", "show-only", "--import"], input=data,
                         capture_output=True).stdout.decode()
    return [l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")][0]


def keycert(name, lines, style="plus", extra=()):
    if style == "plus":
        body = ["certif:         " + lines[0]] + [("+" if not l else " ") + "               " + l for l in lines[1:]]
    elif style == "attr":
        body = ["certif:         " + l if l else "certif:" for l in lines]
    else:
        body = ["certif:         " + lines[0]] + ["                " + l for l in lines[1:] if l]
    return obj("key-cert:       " + name, *body, *extra, "mnt-by:         TEST-MNT", "source:         TEST")


KEYS = ["ed25519", "multi", "revoked-uid", "expired", "unicode", "a-ring", "subkey", "dsa"]
keycerts = []
for k in KEYS:
    lines = key(k)
    fp = keyid(lines)
    keycerts.append(keycert("PGPKEY-" + fp[-8:], lines, "plus", ("method: X509", "owner: wrong", "fingerpr: wrong")))
    keycerts.append(keycert("pgpkey-" + fp[-8:].lower(), lines, "attr"))
ed = key("ed25519")
fp_ed = keyid(ed)
multi = key("multi")
fp_multi = keyid(multi)
blank_idx = ed.index("")
no_crc = [l for l in ed if not l.startswith("=")]
keycerts += [
    keycert("PGPKEY-" + fp_ed[:8], ed),
    keycert("PGPKEY-" + fp_ed[-8:], ed, "noblank"),
    keycert("PGPKEY-" + fp_ed[-8:], no_crc),
    keycert("PGPKEY-" + fp_ed[-8:], no_crc[:-1]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:-1]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:blank_idx] + ["Comment: an extra header", "Foo: unknown header"] + ed[blank_idx:]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:-2] + ["=AAAA", ed[-1]]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:3] + ["!!" + ed[3]] + ed[4:]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:3] + ed[3:5][::-1] + ed[5:]),
    keycert("PGPKEY-" + fp_ed[-8:], ed + multi),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:-2] + multi[blank_idx + 1:]),
    keycert("PGPKEY-" + fp_ed[-8:], ["not a key at all"]),
    keycert("PGPKEY-" + fp_ed[-8:], ["-----BEGIN PGP PUBLIC KEY BLOCK-----", "", "-----END PGP PUBLIC KEY BLOCK-----"]),
    keycert("PGPKEY-" + fp_ed[-8:], [l.replace("PUBLIC KEY BLOCK", "MESSAGE") for l in ed]),
    keycert("PGPKEY-" + fp_ed[-8:], ["junk before", *ed, "junk after"]),
    keycert("PGPKEY-" + fp_ed[-8:], [ed[0], ed[0], *ed[1:]]),
    keycert("PGPKEY-" + fp_ed[-8:], ed[:3] + [ed[3] + " # trailing comment"] + ed[4:]),
    keycert("PGPKEY-" + fp_ed[-8:], ed, "plus", ("certif: extra line",)),
    keycert("PGPKEY-" + fp_multi[-8:], key("multi-one-uid")),
    keycert("PGPKEY-" + fp_multi[-8:], multi),
    keycert("PGPKEY-" + fp_ed[-8:], ed),
    keycert("PGPKEY-" + fp_ed[-8:], [l + " " for l in ed]),
    keycert("PGPKEY-" + fp_ed[-8:], [ed[0], *[base64.b64encode(b"\x99\x00").decode()], ed[-1]]),
]
write("keycert", keycerts)
print("written")
