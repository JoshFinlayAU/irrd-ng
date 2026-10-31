#!/usr/bin/env python3
"""Pick the objects the whois corpus templates are expanded with.

    corpus_bindings.py [--per N] [--out bindings.json] DUMP [DUMP ...]

Reads RPSL dumps (plain or .gz, or '-' for stdin; on Tier 2 the stream is
`SELECT object_text ...` from the reference database) and writes one
JSON object: placeholder name -> list of values. corpus_expand.py substitutes
them into parity/corpus/whois/*.q. Everything is deterministic: samples are
the objects whose key hashes lowest, rankings break ties by name, so the
same data always gives the same bindings.

Only names, prefixes and numbers are written, never object text, and the
output is written under parity/.work (git-ignored), never committed.

Placeholders (see parity/corpus/whois/README.md for how they are used):
  as_set, as_set_deep, as_set_large, as_set_loop, as_set_dangling,
  as_set_hier, as_set_refd (has mbrs-by-ref), as_set_wide (most direct
  members), route_set, route_set_deep, route_set_hier, aut_num,
  origin4/origin6 (origins of route/route6 objects), origin_many4/6,
  aut_num_no_routes, route4/route6 (dicts: prefix, origin, net, len),
  route4_covering/route6_covering (have more-specifics), route4_nested/
  route6_nested (have less-specifics), route4_host (an address inside a
  route), mntner, mntner_busy (most objects), member_of_target,
  mbrs_by_ref_mnt, obj (dicts: cls, pk, for every class present),
  source (sources present), sources_csv (all of them, comma-separated),
  large_origin (origins with most prefixes, for
  !g/!6 in the bench).
"""

import argparse
import gzip
import heapq
import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict

SET_CLASSES = {"as-set", "route-set"}


def paragraphs(stream):
    buf = []
    for raw in stream:
        line = raw.decode("utf-8", "backslashreplace") if isinstance(raw, bytes) else raw
        line = line.rstrip("\r\n")
        if not line:
            if buf:
                yield buf
                buf = []
            continue
        buf.append(line)
        if len(buf) > 200000:  # no paragraph is this long: bad input, do not hoard it
            yield buf
            buf = []
    if buf:
        yield buf


def parse(lines):
    """Attributes of one object, lower-cased names, continuation joined,
    comments stripped. Good enough to pick names; not a validator."""
    attrs = []
    for line in lines:
        if line.startswith(("#", "%")):
            continue
        if line[:1] in (" ", "\t", "+") and attrs:
            attrs[-1][1] += " " + line[1:].strip()
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):(.*)$", line)
        if not m:
            continue
        attrs.append([m.group(1).lower(), m.group(2)])
    out = []
    for name, value in attrs:
        value = value.split("#", 1)[0].strip()
        out.append((name, value))
    return out


def h(s):
    return hashlib.sha1(s.encode()).hexdigest()


class Lowest:
    """The n values whose key hashes lowest, kept in bounded memory."""

    def __init__(self, n):
        self.n, self.heap, self.seen = n, [], set()

    def add(self, value, key=None):
        k = h(key if key is not None else value)
        if value in self.seen:
            return
        if len(self.heap) < self.n:
            heapq.heappush(self.heap, (_neg(k), value))
            self.seen.add(value)
        elif _neg(k) > self.heap[0][0]:
            _, old = heapq.heapreplace(self.heap, (_neg(k), value))
            self.seen.discard(old)
            self.seen.add(value)

    def values(self):
        return [v for _, v in sorted(self.heap, key=lambda x: x[0], reverse=True)]


def _neg(hexdigest):
    return -int(hexdigest[:15], 16)


def sample(values, n):
    uniq = sorted(set(values), key=lambda v: (h(v if isinstance(v, str) else json.dumps(v, sort_keys=True)),))
    return uniq[:n]


def split_list(value):
    return [v for v in re.split(r"[,\s]+", value) if v]


def is_set_name(name):
    u = name.upper()
    return any(part.startswith(("AS-", "RS-")) for part in u.split(":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per", type=int, default=25, help="values per sampled placeholder")
    ap.add_argument("--rank", type=int, default=10, help="values per ranked placeholder (deep, large, ...)")
    ap.add_argument("--out", default="-")
    ap.add_argument("dumps", nargs="+")
    args = ap.parse_args()

    members = {}  # set name (upper) -> list of member names (upper)
    set_class = {}
    refd_sets = set()
    autnums = set()
    routes = {4: Lowest(args.per), 6: Lowest(args.per)}
    # Every route prefix as one int, (address << 8) | length: compact enough
    # for the 4M+ routes of a full Tier 2 database.
    route_keys = {4: set(), 6: set()}
    origins = {4: defaultdict(int), 6: defaultdict(int)}
    mntners = set()
    mnt_count = defaultdict(int)
    member_of = defaultdict(int)
    mbrs_by_ref = defaultdict(int)
    objs = defaultdict(lambda: Lowest(max(2, args.per // 5)))
    sources = set()

    for path in args.dumps:
        if path == "-":
            stream = sys.stdin.buffer
        elif path.endswith(".gz"):
            stream = gzip.open(path, "rb")
        else:
            stream = open(path, "rb")
        for para in paragraphs(stream):
            attrs = parse(para)
            if not attrs:
                continue
            cls, key = attrs[0]
            if not key:
                continue
            get = defaultdict(list)
            for n, v in attrs:
                get[n].append(v)
            src = (get.get("source") or [""])[0].split()[0].upper() if get.get("source") else ""
            if src:
                sources.add(src)
            for m in get.get("mnt-by", []):
                for x in split_list(m):
                    mnt_count[x.upper()] += 1
            if cls in SET_CLASSES:
                name = key.upper()
                mem = []
                for attr in ("members", "mp-members"):
                    for v in get.get(attr, []):
                        mem += [x.upper() for x in split_list(v)]
                members[name] = mem
                set_class[name] = cls
                if get.get("mbrs-by-ref"):
                    refd_sets.add(name)
                    for v in get["mbrs-by-ref"]:
                        for x in split_list(v):
                            if x.upper() != "ANY":
                                mbrs_by_ref[x.upper()] += 1
                objs[cls].add(key)
            elif cls in ("route", "route6"):
                origin = (get.get("origin") or [""])[0].upper()
                ver = 4 if cls == "route" else 6
                try:
                    net = ipaddress.ip_network(key, strict=False)
                except ValueError:
                    continue
                routes[ver].add(f"{net}|{origin}")
                route_keys[ver].add((int(net.network_address) << 8) | net.prefixlen)
                if origin:
                    origins[ver][origin] += 1
                for v in get.get("member-of", []):
                    for x in split_list(v):
                        member_of[x.upper()] += 1
            else:
                if cls == "aut-num":
                    autnums.add(key.upper())
                    for v in get.get("member-of", []):
                        for x in split_list(v):
                            member_of[x.upper()] += 1
                elif cls == "mntner":
                    mntners.add(key)
                objs[cls].add(key)

    b = {}
    per, rank = args.per, args.rank

    # Sets: depth, loops, dangling members, expansion size.
    # Longest chain of set references below each set, and whether a loop is
    # reachable from it, for every set at once: one iterative DFS, O(V+E).
    # (Members that close a loop count as depth 0 there.)
    depth, loops, state = {}, {}, {}
    for root in members:
        if root in state:
            continue
        stack = [(root, iter(members[root]))]
        state[root] = 1
        while stack:
            node, it = stack[-1]
            advanced = False
            for m in it:
                if m not in members:
                    continue
                st = state.get(m)
                if st is None:
                    state[m] = 1
                    stack.append((m, iter(members[m])))
                    advanced = True
                    break
                if st == 1:
                    loops[node] = True
            if advanced:
                continue
            stack.pop()
            state[node] = 2
            d, lp = 0, loops.get(node, False)
            for m in members[node]:
                if m in depth:
                    d = max(d, depth[m] + 1)
                    lp = lp or loops.get(m, False)
            depth[node], loops[node] = d, lp

    def depth_and_loop(root):
        return depth.get(root, 0), loops.get(root, False)

    def expansion_size(root, limit=500000):
        seen, leaves, stack = {root}, set(), [root]
        while stack and len(leaves) < limit:
            for m in members.get(stack.pop(), []):
                if m in members:
                    if m not in seen:
                        seen.add(m)
                        stack.append(m)
                else:
                    leaves.add(m)
        return len(leaves), len(seen)

    for cls, prefix in (("as-set", "as_set"), ("route-set", "route_set")):
        names = [n for n, c in set_class.items() if c == cls]
        b[prefix] = sample(names, per)
        b[prefix + "_hier"] = sample([n for n in names if ":" in n], per)
        # Candidates for the expensive walks: widest and a hash sample.
        wide = sorted(names, key=lambda n: (-len(members[n]), n))
        cand = list(dict.fromkeys(wide[:300] + sample(names, 300)))
        info = {n: depth_and_loop(n) for n in cand}
        b[prefix + "_deep"] = sorted(names, key=lambda n: (-depth.get(n, 0), n))[:rank]
        b[prefix + "_loop"] = sample([n for n in names if loops.get(n)], rank)
        if cls == "as-set":
            b["as_set_wide"] = wide[:rank]
            sizes = {n: expansion_size(n) for n in sorted(cand, key=lambda n: (-info[n][0], -len(members[n]), n))[:150]}
            b["as_set_large"] = [n for n in sorted(sizes, key=lambda n: (-sizes[n][0], n))[:rank]]
            dangling = [n for n in names if any(is_set_name(m) and m not in members for m in members[n])]
            b["as_set_dangling"] = sample(dangling, rank)
            b["as_set_refd"] = sample([n for n in names if n in refd_sets], rank)
            b["as_set_empty"] = sample([n for n in names if not members[n]], rank)

    # aut-nums and origins.
    for ver in (4, 6):
        b[f"origin{ver}"] = sample(list(origins[ver]), per)
        b[f"origin_many{ver}"] = [o for o, _ in sorted(origins[ver].items(), key=lambda kv: (-kv[1], kv[0]))[:rank]]
    b["aut_num"] = sample(list(autnums), per)
    b["aut_num_no_routes"] = sample([a for a in autnums if a not in origins[4] and a not in origins[6]], rank)
    b["large_origin"] = [o for o, _ in sorted(
        ((o, origins[4][o] + origins[6].get(o, 0)) for o in origins[4]), key=lambda kv: (-kv[1], kv[0]))[:rank * 5]]

    # Routes and the prefix tree around them.
    for ver in (4, 6):
        width = 32 if ver == 4 else 128
        vals = []
        for x in routes[ver].values():
            p, o = x.split("|")
            net = ipaddress.ip_network(p)
            vals.append({"prefix": p, "origin": o, "net": str(net.network_address), "len": str(net.prefixlen)})
        b[f"route{ver}"] = vals
        keys = route_keys[ver]
        step = max(1, len(keys) // 200000)
        nested, covering = Lowest(per), Lowest(per)
        for k in keys:
            if step > 1 and (k * 2654435761 >> 9) % step:
                continue
            addr, plen = k >> 8, k & 0xFF
            for sp in range(plen - 1, max(plen - 17, -1), -1):
                mask = ((1 << sp) - 1) << (width - sp) if sp else 0
                sup = ((addr & mask) << 8) | sp
                if sup in keys:
                    fam = ipaddress.IPv4Network if ver == 4 else ipaddress.IPv6Network
                    nested.add(str(fam((addr, plen))))
                    covering.add(str(fam((addr & mask, sp))))
                    break
        b[f"route{ver}_nested"] = nested.values()
        b[f"route{ver}_covering"] = covering.values()
        hosts = []
        for p in b[f"route{ver}"]:
            net = ipaddress.ip_network(p["prefix"])
            hosts.append(str(net.network_address + (1 if net.num_addresses > 2 else 0)))
        b[f"route{ver}_host"] = hosts

    b["mntner"] = sample(list(mntners), per)
    b["mntner_busy"] = [m for m, _ in sorted(mnt_count.items(), key=lambda kv: (-kv[1], kv[0]))[:rank]]
    b["member_of_target"] = [m for m, _ in sorted(member_of.items(), key=lambda kv: (-kv[1], kv[0]))[:rank]]
    b["mbrs_by_ref_mnt"] = [m for m, _ in sorted(mbrs_by_ref.items(), key=lambda kv: (-kv[1], kv[0]))[:rank]]
    obj = []
    for cls in sorted(objs):
        for pk in objs[cls].values():
            obj.append({"cls": cls, "pk": pk})
    for ver, cls in ((4, "route"), (6, "route6")):
        for r in b[f"route{ver}"][: max(2, per // 5)]:
            obj.append({"cls": cls, "pk": r["prefix"] + r["origin"]})
    b["obj"] = obj
    b["source"] = sorted(sources)
    # What bgpq4 sends back after !s-lc (its own list of the sources it saw).
    b["sources_csv"] = [",".join(sorted(sources))] if sources else []

    text = json.dumps(b, indent=1, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w") as f:
            f.write(text)
    counts = {k: len(v) for k, v in b.items()}
    print("bindings: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)


if __name__ == "__main__":
    main()
