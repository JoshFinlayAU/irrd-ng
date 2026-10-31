#!/usr/bin/env python3
"""Compact status comparison for Tier 2 (parity/status/tier2.sh).

A full canonical export of the reference data is several GB per side, more
than the parity VM has to spare, so Tier 2 compares a compact form instead:
per object its key, the three statuses, md5 of the object text and the
address columns; per journal entry its serial, operation, origin, key and
md5 of the text; the ROAs; and the status columns of database_status.

    compact.py sql TABLE                  # v4: the COPY ... TO STDOUT query
    compact.py ng TABLE < export.jsonl    # irrd-ng: the same lines from export-jsonl
    compact.py compare V4_DIR NG_DIR      # objects/journal/roas/status .tsv

Lines are tab separated in PostgreSQL's COPY text format (\\N for NULL,
backslash escapes), so the v4 side is a plain COPY from psql. Objects come
in (source, class, key) byte order on both sides and are compared in one
streaming pass; the journal is compared as compare_status.py does (same
serials and origin/operation sequence per source, same entries as a
multiset), since v4 writes each batch of status changes in PostgreSQL's
unspecified scan order.
"""
import collections
import hashlib
import json
import sys

OBJECT_COLUMNS = [
    "source", "object_class", "rpsl_pk", "rpki_status", "scopefilter_status",
    "route_preference_status", "md5(object_text)", "ip_first", "ip_last", "prefix",
    "prefix_length", "asn_first", "asn_last",
]
JOURNAL_COLUMNS = ["source", "serial_nrtm", "operation", "origin", "rpsl_pk", "object_class", "md5(object_text)"]
ROA_COLUMNS = ["prefix", "asn", "max_length", "trust_anchor"]
STATUS_COLUMNS = [
    "source", "serial_oldest_seen", "serial_newest_seen", "serial_oldest_journal",
    "serial_newest_journal", "serial_last_export", "serial_newest_mirror", "force_reload",
    "synchronised_serials", "last_error",
]
C = 'COLLATE "C"'
SQL = {
    "objects": f"SELECT {', '.join(OBJECT_COLUMNS)} FROM rpsl_objects ORDER BY source {C}, object_class {C}, rpsl_pk {C}",
    "journal": f"SELECT {', '.join(JOURNAL_COLUMNS)} FROM rpsl_database_journal ORDER BY source {C}, serial_nrtm",
    "roas": f"SELECT {', '.join(ROA_COLUMNS)} FROM roa_object",
    "status": f"SELECT {', '.join(STATUS_COLUMNS)} FROM database_status ORDER BY source {C}",
}
NG_TABLE = {
    "objects": ("rpsl_objects", OBJECT_COLUMNS),
    "journal": ("rpsl_database_journal", JOURNAL_COLUMNS),
    "roas": ("roa_object", ROA_COLUMNS),
    "status": ("database_status", STATUS_COLUMNS),
}


def copy_text(v):
    """A value in COPY's text format."""
    if v is None:
        return "\\N"
    if isinstance(v, bool):
        return "t" if v else "f"
    s = str(v)
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def ng(kind):
    _, cols = NG_TABLE[kind]
    out = sys.stdout
    for line in sys.stdin:
        row = json.loads(line)
        vals = []
        for c in cols:
            if c == "md5(object_text)":
                vals.append(hashlib.md5(row["object_text"].encode()).hexdigest())
            else:
                vals.append(row.get(c))
        out.write("\t".join(copy_text(v) for v in vals) + "\n")


def roa_key(line):
    import ipaddress
    p, asn, ml, ta = line.rstrip("\n").split("\t")
    n = ipaddress.ip_network(p)
    return (n.version, int(n.network_address), n.prefixlen, int(asn), int(ml), ta)


def compare_objects(a, b, show=5):
    n = diff = 0
    per_col = collections.Counter()
    examples = []
    with open(a) as fa, open(b) as fb:
        for la, lb in __import__("itertools").zip_longest(fa, fb):
            n += 1
            if la == lb:
                continue
            diff += 1
            xa = (la or "").rstrip("\n").split("\t")
            xb = (lb or "").rstrip("\n").split("\t")
            if xa[:3] != xb[:3]:
                per_col["(row key)"] += 1
                if len(examples) < show:
                    examples.append(f"key v4 {xa[:3]} ng {xb[:3]}")
                continue
            for i, c in enumerate(OBJECT_COLUMNS):
                if i < len(xa) and i < len(xb) and xa[i] != xb[i]:
                    per_col[c] += 1
            if len(examples) < show:
                examples.append(f"{xa[:3]}: " + ", ".join(
                    f"{c} v4 {xa[i]} ng {xb[i]}" for i, c in enumerate(OBJECT_COLUMNS) if xa[i] != xb[i]))
    return n, diff, per_col, examples


def compare_journal(a, b, show=5):
    def read(path):
        d = collections.defaultdict(list)
        for line in open(path):
            x = line.rstrip("\n").split("\t")
            d[x[0]].append(x)
        return d
    da, db = read(a), read(b)
    problems, reordered, total = [], 0, 0
    for s in sorted(set(da) | set(db)):
        x, y = da.get(s, []), db.get(s, [])
        total += len(x)
        if [r[1] for r in x] != [r[1] for r in y]:
            problems.append(f"{s}: serials differ ({len(x)} vs {len(y)})")
            continue
        if [r[2:4] for r in x] != [r[2:4] for r in y]:
            problems.append(f"{s}: origin/operation sequence differs")
            continue
        cx = collections.Counter(tuple(r[2:]) for r in x)
        cy = collections.Counter(tuple(r[2:]) for r in y)
        if cx != cy:
            problems.append(f"{s}: entries differ: v4 only {list((cx - cy).elements())[:show]} ng only {list((cy - cx).elements())[:show]}")
            continue
        reordered += sum(1 for p, q in zip(x, y) if p != q)
    return total, problems, reordered


def compare(da, db):
    failed = False
    n, diff, per_col, ex = compare_objects(f"{da}/objects.tsv", f"{db}/objects.tsv")
    if diff:
        failed = True
        print(f"rpsl_objects: DIFFERS, {diff} of {n} rows; by column: {dict(per_col)}")
        for e in ex:
            print(f"  {e}")
    else:
        print(f"rpsl_objects: {n} rows identical (statuses, text md5, addresses)")
    total, problems, reordered = compare_journal(f"{da}/journal.tsv", f"{db}/journal.tsv")
    if problems:
        failed = True
        print(f"rpsl_database_journal: DIFFERS ({total} v4 rows)")
        for p in problems[:10]:
            print(f"  {p}")
    elif reordered:
        print(f"rpsl_database_journal: {total} rows equivalent ({reordered} positions ordered differently within status batches)")
    else:
        print(f"rpsl_database_journal: {total} rows identical")
    ra = sorted(open(f"{da}/roas.tsv"), key=roa_key)
    rb = sorted(open(f"{db}/roas.tsv"), key=roa_key)
    if ra != rb:
        failed = True
        print(f"roa_object: DIFFERS, {len(ra)} vs {len(rb)} rows, {len(set(ra) ^ set(rb))} differ")
    else:
        print(f"roa_object: {len(ra)} rows identical")
    sa, sb = open(f"{da}/status.tsv").read(), open(f"{db}/status.tsv").read()
    if sa != sb:
        failed = True
        print("database_status: DIFFERS")
        for x, y in zip(sa.splitlines(), sb.splitlines()):
            if x != y:
                print(f"  v4 {x}\n  ng {y}")
    else:
        print(f"database_status: {len(sa.splitlines())} rows identical (serial and error columns)")
    return 1 if failed else 0


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "sql":
        print(f"COPY ({SQL[sys.argv[2]]}) TO STDOUT")
    elif cmd == "ng":
        ng(sys.argv[2])
    elif cmd == "compare":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
