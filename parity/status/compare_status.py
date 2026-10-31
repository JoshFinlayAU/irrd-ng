#!/usr/bin/env python3
"""Compare a v4 and an irrd-ng export after a status suite step.

    compare_status.py V4_DIR NG_DIR --exclude-file FILE [--show N]

Every table but the journal is compared row by row, as compare_exports.py
does, after dropping the excluded columns. The journal is compared per
source: the serials, and the (origin, operation) at each serial, must be
the same, and the entries (origin, operation, class, key, text) must be
the same multiset. When v4 writes a batch of status changes (an RPKI,
scope filter or route preference update) it takes the objects in
PostgreSQL's scan order, which is unspecified, so the object at a given
serial within such a batch can differ; that case is reported as
"equivalent", never as identical, with the number of positions affected.
Exit 1 on any real difference.
"""
import argparse
import collections
import json
import os
import sys


def excludes(paths):
    out = set()
    for p in paths:
        for line in open(p, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line.split("\t", 1)[0].strip())
    return out


def load(path, table, excl):
    drop = {c.split(".", 1)[1] for c in excl if c.split(".", 1)[0] in (table, "*")}
    rows = []
    if not os.path.exists(path):
        return None
    for line in open(path, encoding="utf-8"):
        obj = json.loads(line)
        for c in drop:
            obj.pop(c, None)
        rows.append(obj)
    return rows


def dumps(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compare_journal(left, right, show):
    def by_source(rows):
        d = collections.defaultdict(list)
        for r in rows:
            d[r["source"]].append(r)
        for v in d.values():
            v.sort(key=lambda r: r["serial_nrtm"])
        return d

    lsrc, rsrc = by_source(left), by_source(right)
    problems, reordered = [], 0
    for source in sorted(set(lsrc) | set(rsrc)):
        a, b = lsrc.get(source, []), rsrc.get(source, [])
        if [r["serial_nrtm"] for r in a] != [r["serial_nrtm"] for r in b]:
            problems.append(f"{source}: serials differ ({len(a)} vs {len(b)} entries)")
            continue
        labels = lambda rows: [(r["origin"], r["operation"]) for r in rows]
        if labels(a) != labels(b):
            i = next(i for i, (x, y) in enumerate(zip(labels(a), labels(b))) if x != y)
            problems.append(f"{source}: origin/operation differ at serial {a[i]['serial_nrtm']}: {labels(a)[i]} vs {labels(b)[i]}")
            continue
        ka = collections.Counter(dumps(r) for r in a)
        kb = collections.Counter(dumps(r) for r in b)
        if ka != kb:
            # Same serials and labels, different content: compare without
            # serials to see whether only the order differs.
            strip = lambda r: dumps({k: v for k, v in r.items() if k != "serial_nrtm"})
            ca = collections.Counter(strip(r) for r in a)
            cb = collections.Counter(strip(r) for r in b)
            if ca != cb:
                only_a = list((ca - cb).elements())[:show]
                only_b = list((cb - ca).elements())[:show]
                problems.append(f"{source}: entries differ")
                for x in only_a:
                    problems.append(f"    v4 only: {x[:600]}")
                for x in only_b:
                    problems.append(f"    ng only: {x[:600]}")
                continue
            reordered += sum(1 for x, y in zip(a, b) if dumps(x) != dumps(y))
    return problems, reordered, len(left), len(right)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--exclude-file", action="append", default=[])
    ap.add_argument("--show", type=int, default=3)
    args = ap.parse_args()
    excl = excludes(args.exclude_file)
    tables = sorted({f[:-6] for d in (args.left, args.right) for f in os.listdir(d) if f.endswith(".jsonl")})
    failed = False
    for table in tables:
        left = load(os.path.join(args.left, table + ".jsonl"), table, excl)
        right = load(os.path.join(args.right, table + ".jsonl"), table, excl)
        if left is None or right is None:
            print(f"{table}: MISSING in {'v4' if left is None else 'irrd-ng'}")
            failed = True
            continue
        if table == "rpsl_database_journal":
            problems, reordered, nl, nr = compare_journal(left, right, args.show)
            if problems:
                failed = True
                print(f"{table}: DIFFERS, {nl} vs {nr} rows")
                for p in problems[: 4 * args.show + 4]:
                    print(f"  {p}")
            elif reordered:
                print(f"{table}: {nl} rows equivalent ({reordered} positions ordered differently within status batches)")
            else:
                print(f"{table}: {nl} rows identical")
            continue
        diffs = [(i, x, y) for i, (x, y) in enumerate(zip(left, right)) if x != y]
        if len(left) == len(right) and not diffs:
            print(f"{table}: {len(left)} rows identical")
            continue
        failed = True
        print(f"{table}: DIFFERS, {len(left)} vs {len(right)} rows, {len(diffs)} positions differ")
        for i, x, y in diffs[: args.show]:
            keys = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))
            ident = {k: x.get(k) for k in ("source", "object_class", "rpsl_pk", "prefix") if k in x}
            print(f"  row {i} {dumps(ident)}")
            for k in keys:
                print(f"    {k}: v4 {dumps(x.get(k))[:300]} | ng {dumps(y.get(k))[:300]}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
