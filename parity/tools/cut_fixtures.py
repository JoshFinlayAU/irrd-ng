"""Cut the Tier 1 fixture dumps from the cached public IRR dumps.

For each source this keeps, deterministically:
  - a sample of every object class (the PER_CLASS objects whose text hashes
    lowest, so the choice is stable while those objects exist upstream),
  - every object that exercises an RPSL formatting edge case (continuation
    lines with '+', tab or space, comments, mixed-case attribute names,
    non-ASCII bytes, very long lines), capped per kind,
  - the full recursive closure of the SETS deepest as-sets in the source,
    with the aut-num, route and route6 objects of every member ASN, so set
    expansion and !a/!g/!6 have real trees, loops and dangling members.

Object bytes are copied verbatim. Output goes to parity/.cache/fixtures/,
never into git.

Usage: python3 -I parity/tools/cut_fixtures.py parity/.cache
"""

import gzip
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

PER_CLASS = 40
EDGE_CAP = 25
SETS = 4
MAX_CLOSURE = 3000

MERGE = {"APNIC-": "APNIC"}


def source_of(name):
    for prefix, target in MERGE.items():
        if name.startswith(prefix):
            return target
    return name


def objects(raw):
    for chunk in re.split(rb"\n[ \t]*\n", raw):
        lines = [ln for ln in chunk.split(b"\n") if ln and not ln.startswith((b"#", b"%"))]
        if lines and b":" in lines[0]:
            yield b"\n".join(lines) + b"\n"


def attrs(obj):
    out = []
    for line in obj.split(b"\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t", b"+") and out:
            out[-1][1] += b" " + line[1:].strip()
        elif b":" in line:
            k, _, v = line.partition(b":")
            out.append([k.strip().lower(), v.split(b"#")[0].strip()])
    return out


def edge_kinds(obj):
    lines = obj.split(b"\n")
    kinds = set()
    for ln in lines[1:]:
        if ln.startswith(b"+"):
            kinds.add("cont-plus")
        elif ln.startswith(b"\t"):
            kinds.add("cont-tab")
        elif ln.startswith(b" "):
            kinds.add("cont-space")
    for ln in lines:
        k = ln.split(b":", 1)[0]
        if b"#" in ln:
            kinds.add("comment")
        if k != k.lower() and ln[:1] not in (b" ", b"\t", b"+"):
            kinds.add("attr-case")
        if len(ln) > 400:
            kinds.add("long-line")
    try:
        obj.decode("ascii")
    except UnicodeDecodeError:
        kinds.add("non-ascii")
    return kinds


def asn(value):
    m = re.fullmatch(rb"AS(\d+)", value.strip().upper())
    return int(m.group(1)) if m else None


def main(cache):
    cache = Path(cache)
    by_source = defaultdict(list)
    for dump in sorted(cache.glob("*.db.gz")):
        by_source[source_of(dump.name[: -len(".db.gz")])].append(dump)

    out_dir = cache / "fixtures"
    out_dir.mkdir(exist_ok=True)
    manifest = []
    for source, dumps in sorted(by_source.items()):
        objs = [o for d in dumps for o in objects(gzip.decompress(d.read_bytes()))]
        cls = defaultdict(list)
        sets, routes_by_asn, autnums = {}, defaultdict(list), {}
        for o in objs:
            a = attrs(o)
            klass, key = a[0][0], a[0][1].upper()
            cls[klass].append(o)
            if klass == b"as-set":
                members = []
                for k, v in a:
                    if k in (b"members", b"mp-members"):
                        members += [m.strip().upper() for m in v.split(b",") if m.strip()]
                sets[key] = (o, members)
            elif klass in (b"route", b"route6"):
                for k, v in a:
                    if k == b"origin" and asn(v) is not None:
                        routes_by_asn[asn(v)].append(o)
            elif klass == b"aut-num" and asn(key) is not None:
                autnums[asn(key)] = o

        keep = {}
        for klass, group in cls.items():
            for o in sorted(group, key=lambda o: hashlib.sha256(o).digest())[:PER_CLASS]:
                keep[o] = True
        edge_count = defaultdict(int)
        for o in sorted(objs, key=lambda o: hashlib.sha256(o).digest()):
            for kind in edge_kinds(o):
                if edge_count[kind] < EDGE_CAP:
                    edge_count[kind] += 1
                    keep[o] = True

        def closure(root):
            seen, order, stack = set(), [], [root]
            while stack and len(order) < MAX_CLOSURE:
                name = stack.pop()
                if name in seen:
                    continue
                seen.add(name)
                if name in sets:
                    order.append(sets[name][0])
                    stack.extend(reversed(sets[name][1]))
                elif asn(name) is not None:
                    n = asn(name)
                    if n in autnums:
                        order.append(autnums[n])
                    order.extend(routes_by_asn.get(n, [])[:20])
            return seen, order

        depth = {}
        for name in sorted(sets):
            seen, _ = closure(name)
            depth[name] = sum(1 for s in seen if s in sets)
        roots = sorted(depth, key=lambda n: (-depth[n], n))[:SETS]
        for r in roots:
            for o in closure(r)[1]:
                keep[o] = True

        path = out_dir / f"{source}.db"
        path.write_bytes(b"\n".join(keep))
        manifest.append(
            f"{source}\t{len(objs)}\t{len(keep)}\t{','.join(r.decode(errors='replace') for r in roots)}\t"
            + ",".join(f"{k}={v}" for k, v in sorted(edge_count.items()))
        )
    (out_dir / "MANIFEST.tsv").write_text(
        "source\tobjects_in_dump\tobjects_kept\tset_roots\tedge_cases\n" + "\n".join(manifest) + "\n"
    )
    print((out_dir / "MANIFEST.tsv").read_text(), end="")


if __name__ == "__main__":
    main(sys.argv[1])
