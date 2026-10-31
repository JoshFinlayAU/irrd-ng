#!/usr/bin/env python3
"""Canonical JSONL export of an IRRd v4 PostgreSQL database.

Writes one file per table, <outdir>/<table>.jsonl, one JSON object per row,
keys named after v4's columns. This is the v4 side of the three-way load
check; irrd-ng's store export emits the same shape, so the two are compared
with a plain byte diff. It deliberately shares no code with irrd-ng.

Rendering (the contract both exporters follow):
  - JSON: keys sorted, separators "," and ":", UTF-8 (no \\u escapes for
    non-ASCII), one object per line, "\\n" line ends.
  - uuid: lowercase hyphenated string.
  - timestamptz: UTC, "YYYY-MM-DDTHH:MM:SS.ffffffZ" (always 6 digits).
  - inet, cidr: PostgreSQL's text output (inet drops a full-length mask).
  - numeric: decimal integer as a string (ip_size exceeds 2**64 for IPv6).
  - jsonb: the JSON value itself, keys sorted.
  - bytea: lowercase hex string.
  - text[]: JSON array of strings.
  - enums: the stored label (e.g. "not_found", "add_or_update").
  - integer, bigint, boolean, null: native JSON.

Row order (stable, independent of the planner):
  - rpsl_objects: source, object_class, rpsl_pk, bytewise ("C" collation).
  - rpsl_database_journal: serial_global.
  - database_status: source, bytewise.
  - setting: name, bytewise.
  - every other table: pk, which v4 generates and the import preserves.

Read-only: runs in a READ ONLY, REPEATABLE READ transaction and streams
through a server-side cursor, so it is safe on a large database.

    export_v4.py <dsn> <outdir>
"""
import argparse
import datetime
import json
import os
import sys

import psycopg2

TABLES = [
    ("rpsl_objects", 'source COLLATE "C", object_class COLLATE "C", rpsl_pk COLLATE "C"'),
    ("rpsl_database_journal", "serial_global"),
    ("database_status", 'source COLLATE "C"'),
    ("roa_object", "pk"),
    ("rpsl_objects_suspended", "pk"),
    ("protected_rpsl_name", "pk"),
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
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if data_type == "numeric":
        return str(int(value))
    if data_type == "bytea":
        return bytes(value).hex()
    if data_type in ("uuid", "inet", "cidr"):
        return str(value)
    return value


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
        with open(os.path.join(args.outdir, "alembic_version.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"version_num": revision}, sort_keys=True, separators=(",", ":")) + "\n")
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
            cur.execute(
                "SELECT " + ", ".join(f'"{c}"' for c in names) + f" FROM {table} ORDER BY {order}"
            )
            n = 0
            path = os.path.join(args.outdir, f"{table}.jsonl")
            with open(path + ".part", "w", encoding="utf-8", newline="\n") as f:
                for row in cur:
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
