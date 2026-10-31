#!/usr/bin/env python3
"""Compare two canonical exports (directories of <table>.jsonl).

    compare_exports.py <left> <right> [--exclude table.column ...]
                       [--exclude-file path] [--label-left L] [--label-right R]
                       [--table T ...] [--only-source S | --skip-source S ...]

Exact byte comparison of every table when nothing is excluded. Excluded
columns ("rpsl_objects.created", or "*.pk" for every table) are dropped from
both sides first, then rows are compared in order. Prints one line per
table and the first differing rows, and exits 1 on any difference.

An exclude file has one "table.column<TAB>reason" per line; # comments.

--table limits the comparison to the named tables. --skip-source drops rows
whose "source" is S from both sides; --only-source keeps only rows whose
"source" is S (rows without a source column are dropped).
"""
import argparse
import itertools
import json
import os
import sys


def load_excludes(args):
    excl = set(args.exclude or [])
    for path in args.exclude_file or []:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    excl.add(line.split("\t", 1)[0].strip())
    return excl


def keep(line, args):
    if not (args.only_source or args.skip_source):
        return True
    source = json.loads(line).get("source")
    if args.only_source:
        return source == args.only_source
    return source not in args.skip_source


def rows(f, args):
    for line in f:
        line = line.rstrip("\n")
        if keep(line, args):
            yield line


def project(line, table, excl):
    drop = {c.split(".", 1)[1] for c in excl if c.split(".", 1)[0] in (table, "*")}
    if not drop:
        return line
    obj = json.loads(line)
    for c in drop:
        obj.pop(c, None)
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--exclude", action="append")
    ap.add_argument("--exclude-file", action="append")
    ap.add_argument("--label-left", default="left")
    ap.add_argument("--label-right", default="right")
    ap.add_argument("--show", type=int, default=3)
    ap.add_argument("--table", action="append")
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--only-source")
    sel.add_argument("--skip-source", action="append")
    args = ap.parse_args()
    excl = load_excludes(args)

    tables = sorted(
        {f[:-6] for d in (args.left, args.right) for f in os.listdir(d) if f.endswith(".jsonl")}
    )
    if args.table:
        tables = [t for t in tables if t in args.table]
    failed = False
    for table in tables:
        paths = [os.path.join(d, table + ".jsonl") for d in (args.left, args.right)]
        if not all(os.path.exists(p) for p in paths):
            print(f"{table}: MISSING in {'left' if not os.path.exists(paths[0]) else 'right'}")
            failed = True
            continue
        n_left = n_right = 0
        diffs = []
        n_diff = 0
        # Streamed: full dumps do not fit comfortably in memory twice.
        with open(paths[0], encoding="utf-8") as lf, open(paths[1], encoding="utf-8") as rf:
            for i, (lline, rline) in enumerate(itertools.zip_longest(rows(lf, args), rows(rf, args))):
                if lline is not None:
                    n_left += 1
                if rline is not None:
                    n_right += 1
                lp = project(lline, table, excl) if lline is not None else None
                rp = project(rline, table, excl) if rline is not None else None
                if lp != rp:
                    n_diff += 1
                    if len(diffs) < args.show:
                        diffs.append((i, lp, rp))
        if not n_diff:
            print(f"{table}: {n_left} rows identical")
            continue
        failed = True
        print(f"{table}: DIFFERS, {n_left} vs {n_right} rows, {n_diff} positions differ")
        for i, lp, rp in diffs:
            print(f"  row {i}")
            print(f"    {args.label_left}:  {(lp or '<none>')[:600]}")
            print(f"    {args.label_right}: {(rp or '<none>')[:600]}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
