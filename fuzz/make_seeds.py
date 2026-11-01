#!/usr/bin/env python3
"""Write seed corpora for the fuzz targets into fuzz/corpus/<target>/.

Seeds come from the committed parity corpus (synthetic data only) and a
few hand-written inputs. Run from anywhere; existing seeds are kept.
"""

import hashlib
import json
import pathlib
import re
import struct
import zlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CORPUS = ROOT / "parity" / "corpus"


def put(target, data):
    if isinstance(data, str):
        data = data.encode()
    d = HERE / "corpus" / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha1(data).hexdigest()).write_bytes(data)


def rpsl():
    n = 0
    for db in sorted((CORPUS / "rpsl").glob("*.db")):
        text = db.read_text(errors="replace")
        for para in re.split(r"\n\s*\n", text):
            if para.strip() and n < 3000:
                put("rpsl_parse", para.strip() + "\n")
                n += 1


def whois():
    for q in sorted((CORPUS / "whois").glob("*.q")):
        for line in q.read_text(errors="replace").splitlines():
            if line and not line.startswith(("#", "@")):
                put("whois_query", line)
    put("whois_query", "!!\n!t100\n!iAS-TOP,1\n!aAS-TOP\n!gAS65537\n!q")
    put("whois_query", "-k\n-i mnt-by MNT-A\n-T route -r 192.0.2.0/24\n-g TEST:3:1-LAST")


def graphql():
    queries = []
    for f in sorted((CORPUS / "graphql").glob("*.gq")) + [CORPUS / "graphql" / "irrexplorer.graphql"]:
        for line in f.read_text(errors="replace").splitlines():
            s = line.strip()
            if s.startswith(("query", "{", "mutation", "subscription", "fragment")):
                queries.append(s)
    for q in queries[:2000]:
        put("graphql_document", q)
        put("graphql_request", json.dumps({"query": q}))
        put("multipart", 'boundary=b\n--b\r\nContent-Disposition: form-data; name="operations"\r\n\r\n'
            + json.dumps({"query": q, "variables": {"f": None}})
            + '\r\n--b\r\nContent-Disposition: form-data; name="map"\r\n\r\n{"0": ["variables.f"]}\r\n'
            + '--b\r\nContent-Disposition: form-data; name="0"; filename="a.txt"\r\n\r\nx\r\n--b--\r\n')


def config():
    for y in sorted((CORPUS / "config").glob("*.yaml")):
        if y.is_file():
            put("config_load", y.read_bytes())


def nrtm3():
    put("nrtm3_stream", "%START Version: 3 TEST 11012700-11012701\n\nADD 11012700\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL 11012701\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n")
    put("nrtm3_stream", "%START Version: 1 TEST 11012700-11012701\n\nADD\n\nperson: NRTM test\naddress: NowhereLand\nsource: TEST\n\nDEL\n\ninetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST\n\n%END TEST\n")


def email():
    put("email_parse", "From: a@example.net\nSubject: update\nMessage-ID: <1@example.net>\n\nperson: A\nnic-hdl: A-TEST\nsource: TEST\npassword: x\n")
    put("email_parse", 'From: a@example.net\nContent-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="b"\n\n--b\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nperson: A=3D\n--b\nContent-Type: application/pgp-signature\n\n-----BEGIN PGP SIGNATURE-----\n\niQ==\n-----END PGP SIGNATURE-----\n--b--\n')
    put("email_parse", "From: a@example.net\nContent-Type: text/plain; charset=koi8-r\nContent-Transfer-Encoding: base64\n\ncGVyc29uOiBB\n")


def submit():
    put("submit_json", json.dumps({"objects": [{"object_text": "person: A\nsource: TEST\n"}], "passwords": ["x"], "override": "y", "delete_reason": "z"}))
    put("submit_json", json.dumps({"objects": [{"attributes": [{"name": "person", "value": "A"}, {"name": "remarks", "value": ["x", "y"]}]}]}))
    put("submit_json", json.dumps({"objects": [{"mntner": "MNT-A", "source": "TEST", "request_type": "suspend"}], "override": "x"}))


def roa():
    roas = {"roas": [{"asn": "AS65537", "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "TA"},
                     {"asn": 65538, "prefix": "2001:db8::/32", "maxLength": 48, "ta": "TA"}]}
    slurm = {"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"prefix": "192.0.2.0/25", "asn": 65537}], "bgpsecFilters": []},
             "locallyAddedAssertions": {"prefixAssertions": [{"asn": 65539, "prefix": "198.51.100.0/24", "maxPrefixLength": 25}], "bgpsecAssertions": []}}
    put("roa_slurm", json.dumps(roas))
    put("roa_slurm", json.dumps(roas).encode() + b"\xff" + json.dumps(slurm).encode())


def nrtm4():
    unf = {"nrtm_version": 4, "type": "notification", "source": "TEST", "session_id": "ca128382-78d9-41d1-8927-1ecef15275be",
           "version": 4, "timestamp": "2026-10-31T00:00:00Z", "next_signing_key": None,
           "snapshot": {"version": 3, "url": "https://example.net/snapshot.json", "hash": "a" * 64},
           "deltas": [{"version": 4, "url": "https://example.net/delta.json", "hash": "b" * 64}]}
    put("nrtm4_files", b"\x02" + json.dumps(unf).encode())
    header = {"nrtm_version": 4, "type": "snapshot", "source": "TEST", "session_id": "00000000-0000-0000-0000-000000000000", "version": 3}
    seq = b"\x1e" + json.dumps(header).encode() + b"\n\x1e" + json.dumps({"object": "person: A\nsource: TEST\n"}).encode() + b"\n"
    put("nrtm4_files", b"\x03" + seq)
    put("nrtm4_files", b"\x00eyJhbGciOiJFUzI1NiJ9.eyJ4IjoxfQ.AAAA")
    put("nrtm4_files", b"\x01-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n")


def websocket():
    def frame(op, payload, fin=True, rsv1=False):
        mask = b"\x01\x02\x03\x04"
        head = bytes([(0x80 if fin else 0) | (0x40 if rsv1 else 0) | op])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        else:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    msg = b'{"type": "connection_init"}'
    put("websocket_frames", b"\x00" + frame(1, msg) + frame(9, b"ping") + frame(8, b"\x03\xe8bye"))
    put("websocket_frames", b"\x00" + frame(1, msg[:10], fin=False) + frame(0, msg[10:]))
    c = zlib.compressobj(wbits=-15)
    z = c.compress(msg) + c.flush(zlib.Z_SYNC_FLUSH)
    put("websocket_frames", b"\x01" + frame(1, z[:-4], rsv1=True))


def replication():
    # Mode 1: raw, a HELLO frame as a standby sends it.
    hello = b"IRRDNG-REPL" + struct.pack(">II", 1, 1) + b"\x00" * 32
    put("replication_frames", b"\x01" + struct.pack(">I", 1 + len(hello)) + b"\x01" + hello)
    # Mode 0: frames tagged by the harness.
    entries = struct.pack(">H", 3) + b"abc" + struct.pack(">I", 1) + struct.pack(">Q", 1) + struct.pack(">I", 2) + b"\x00\x00"
    rows = b"\x01" + struct.pack(">I", 1) + b"k" + struct.pack(">I", 1) + b"v"
    put("replication_frames", b"\x00" + bytes([7]) + struct.pack(">H", len(entries)) + entries
        + bytes([5]) + struct.pack(">H", len(rows)) + rows)


for f in (rpsl, whois, graphql, config, nrtm3, email, submit, roa, nrtm4, websocket, replication):
    f()
