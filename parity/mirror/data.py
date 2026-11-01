#!/usr/bin/env python3
"""Upstream data for the mirroring differential.

    data.py initial <dump.gz> <outdir> SOURCE... [--per-source N]
    data.py change  <state.db> <pool.db> <round> [--seed S]

`initial` cuts N objects per source from a cached public dump (renaming
the source), writes <outdir>/<source>.db (the state loaded upstream) and
<outdir>/<source>.pool (objects held back for later additions).

`change` rewrites a state file for one round: about 4% of objects get a
new remarks line (--modify-rate), 2% are deleted (--delete-rate), and 2%
are added from the pool. The
change is deterministic for a given round and seed. The state file is then
applied upstream with irrd_update_database, which journals every change.

No real registry data is committed: the dump comes from parity/.cache.
"""
import argparse
import gzip
import random
import re

KEEP_CLASSES = ("route", "route6", "aut-num", "as-set", "route-set", "mntner", "person", "role")


def paragraphs(text):
    cur = []
    for line in text.splitlines():
        if line.startswith("#") or line.startswith("%"):
            continue
        if not line.strip():
            if cur:
                yield "\n".join(cur) + "\n"
            cur = []
        else:
            cur.append(line)
    if cur:
        yield "\n".join(cur) + "\n"


def write(path, objs):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(objs))


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return list(paragraphs(f.read()))
    except FileNotFoundError:
        return []


def initial(args):
    with gzip.open(args.dump, "rt", encoding="utf-8", errors="backslashreplace") as f:
        objs = [p for p in paragraphs(f.read()) if p.split(":", 1)[0] in KEEP_CLASSES]
    rnd = random.Random(4242)
    rnd.shuffle(objs)
    n = args.per_source
    for i, source in enumerate(args.sources):
        chunk = objs[i * 2 * n : (i + 1) * 2 * n]
        chunk = [re.sub(r"(?m)^source:\s*\S+", "source:         " + source, o) for o in chunk]
        write(f"{args.outdir}/{source}.db", chunk[:n])
        write(f"{args.outdir}/{source}.pool", chunk[n:])


def change(args):
    state = read(args.state)
    pool = read(args.pool)
    rnd = random.Random(f"{args.seed}-{args.round}-{args.state}")
    out = []
    for o in state:
        r = rnd.random()
        if r < args.delete_rate:
            continue
        if 0.02 <= r < 0.02 + args.modify_rate:
            o = o.rstrip("\n") + f"\nremarks:        parity change round {args.round}\n"
        out.append(o)
    add = max(1, len(state) // 50)
    out.extend(pool[:add])
    write(args.state, out)
    write(args.pool, pool[add:])
    print(f"{args.state}: {len(state)} -> {len(out)} objects")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("initial")
    a.add_argument("dump")
    a.add_argument("outdir")
    a.add_argument("sources", nargs="+")
    a.add_argument("--per-source", type=int, default=1000)
    b = sub.add_parser("change")
    b.add_argument("state")
    b.add_argument("pool")
    b.add_argument("round", type=int)
    b.add_argument("--seed", default="irrd-ng")
    b.add_argument("--delete-rate", type=float, default=0.02)
    b.add_argument("--modify-rate", type=float, default=0.04)
    args = ap.parse_args()
    {"initial": initial, "change": change}[args.cmd](args)


if __name__ == "__main__":
    main()
