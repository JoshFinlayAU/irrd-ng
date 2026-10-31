#!/usr/bin/env python3
"""Canonical JSONL export of an IRRd v4 PostgreSQL database.

Writes one file per table, <outdir>/<table>.jsonl, one JSON object per row,
keys named after v4's columns: the canonical export format defined in
crates/store/src/export.rs (the authority), so v4's database and an irrd-ng
store (`irrd-ng export-jsonl --table all`) compare with a plain byte diff.
It deliberately shares no code with irrd-ng.

Rendering, as that spec has it:
  - JSON: keys sorted bytewise at every level, compact, UTF-8 kept as is,
    one object per line.
  - uuid: lower-case hyphenated string.
  - timestamptz: UTC, "YYYY-MM-DDTHH:MM:SS.ffffff+00:00" (always 6 digits).
  - inet, cidr: PostgreSQL's text output (inet drops a full-length mask).
  - numeric (ip_size): decimal integer as a string (it reaches 2**128).
  - jsonb: the JSON value itself.
  - bytea: PostgreSQL's hex output, "\\x" and lower-case hex.
  - text[]: JSON array of strings.
  - enums: the stored label (e.g. "not_found", "add_or_update").
  - integer, bigint, boolean, null: native JSON.

Row order (strings bytewise, NULL first):
  - rpsl_objects: source, object_class, rpsl_pk.
  - rpsl_database_journal: source, serial_nrtm.
  - database_status: source.
  - roa_object: ip_version, network address, prefix length, asn,
    max_length, trust_anchor.
  - rpsl_objects_suspended: source, object_class, rpsl_pk, timestamp, pk.
  - protected_rpsl_name: source, protected_name, object_class, rpsl_pk,
    created, pk.
  - setting: name.
  - auth_* and change_log: pk.
The schema revision goes to stdout with the row counts, not to a file.

Read-only: runs in a READ ONLY, REPEATABLE READ transaction and streams
through a server-side cursor, so it is safe on a large database.

    export_v4.py <dsn> <outdir>
"""
import argparse
import datetime
import ipaddress
import json
import os
import sys

import psycopg2

C = 'COLLATE "C"'
TABLES = [
    ("rpsl_objects", f"source {C}, object_class {C}, rpsl_pk {C}"),
    ("rpsl_database_journal", f"source {C}, serial_nrtm"),
    ("database_status", f"source {C}"),
    # Sorted here, not in SQL: the order is by numeric network address.
    ("roa_object", None),
    ("rpsl_objects_suspended", f"source {C}, object_class {C}, rpsl_pk {C}, timestamp, pk"),
    ("protected_rpsl_name", f"source {C}, protected_name {C}, object_class {C}, rpsl_pk {C}, created, pk"),
    ("setting", 'name COLLATE "C"'),
    ("auth_user", "pk"),
    ("auth_mntner", "pk"),
    ("auth_permission", "pk"),
    ("auth_api_token", "pk"),
    ("auth_webauthn", "pk"),
    ("change_log", "pk"),
]

UTC = datetime.timezone.utc


def render(value, data_type):
    if value is None:
        return None
    if data_type == "timestamp with time zone":
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    if data_type == "numeric":
        return str(int(value))
    if data_type == "bytea":
        return "\\x" + bytes(value).hex()
    if data_type in ("uuid", "inet", "cidr"):
        return str(value)
    return value


def roa_key(names):
    i = {n: k for k, n in enumerate(names)}

    def key(row):
        net = ipaddress.ip_network(row[i["prefix"]])
        ta = row[i["trust_anchor"]]
        return (
            row[i["ip_version"]],
            int(net.network_address),
            net.prefixlen,
            row[i["asn"]],
            row[i["max_length"]],
            (0, b"") if ta is None else (1, ta.encode("utf-8")),
        )

    return key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dsn")
    ap.add_argument("outdir")
    ap.add_argument("--batch", type=int, default=10000)
    args = ap.parse_args()

    # psycopg2 would parse jsonb with the json module already; keep that,
    # and leave inet/cidr/uuid as their PostgreSQL text form.
    conn = psycopg2.connect(args.dsn)
    conn.set_session(readonly=True, isolation_level="REPEATABLE READ")
    os.makedirs(args.outdir, exist_ok=True)
    with conn:
        meta = conn.cursor()
        meta.execute("SET TIME ZONE 'UTC'")
        meta.execute("SELECT version_num FROM alembic_version")
        (revision,) = meta.fetchone()
        counts = {}
        for table, order in TABLES:
            meta.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position",
                (table,),
            )
            cols = meta.fetchall()
            if not cols:
                sys.exit(f"table {table} not found")
            names = [c for c, _ in cols]
            types = [t for _, t in cols]
            cur = conn.cursor(name=f"export_{table}")
            cur.itersize = args.batch
            select = "SELECT " + ", ".join(f'"{c}"' for c in names) + f" FROM {table}"
            cur.execute(select + (f" ORDER BY {order}" if order else ""))
            rows = cur if order else sorted(cur, key=roa_key(names))
            n = 0
            path = os.path.join(args.outdir, f"{table}.jsonl")
            with open(path + ".part", "w", encoding="utf-8", newline="\n") as f:
                for row in rows:
                    obj = {name: render(v, t) for name, t, v in zip(names, types, row)}
                    f.write(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
                    f.write("\n")
                    n += 1
            os.replace(path + ".part", path)
            cur.close()
            counts[table] = n
    conn.close()
    json.dump({"alembic_version": revision, "rows": counts}, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
