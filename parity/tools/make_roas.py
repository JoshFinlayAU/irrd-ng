#!/usr/bin/env python3
"""Synthetic ROAs for the Tier 1 RPKI profile (parity/load.sh --rpki).

    make_roas.py DUMP [DUMP ...] > roas.json

Writes v4's roa_source JSON format ({"roas": [{"asn", "prefix",
"maxLength", "ta"}]}) so that the route and route6 objects in the dumps end
up in every RPKI state: for each route, by a stable hash of its key,
  1/4  valid      a ROA for its prefix and origin
  1/8  valid      a covering ROA (prefix shortened) with maxLength reaching it
  1/8  invalid    a ROA for its prefix with a different origin
  1/8  invalid    a covering ROA for its origin whose maxLength stops short
  rest not_found  nothing covers it
plus some AS0 ROAs. Duplicates of (asn, prefix, maxLength) are dropped:
v4's import fails on them. The ROAs are invented, not
taken from any RPKI repository, and the output goes to parity/.work, never
into git; the same dumps always give the same file.
"""
import hashlib
import ipaddress
import json
import re
import sys

TAS = ["apnic", "arin", "ripe", "afrinic", "lacnic"]


def routes(paths):
    for path in paths:
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        for para in re.split(r"\n\s*\n", text):
            m = re.search(r"^(route6?):\s*(\S+)", para, re.M | re.I)
            o = re.search(r"^origin:\s*(AS\d+)", para, re.M | re.I)
            if m and o:
                try:
                    yield ipaddress.ip_network(m.group(2), strict=False), o.group(1).upper()
                except ValueError:
                    continue


def main():
    roas = []
    seen = set()
    for net, origin in routes(sys.argv[1:]):
        key = f"{net}{origin}"
        if key in seen:
            continue
        seen.add(key)
        h = int(hashlib.sha1(key.encode()).hexdigest()[:8], 16)
        bucket = h % 8
        ta = TAS[h % len(TAS)]
        asn = int(origin[2:])
        plen = net.prefixlen
        if bucket in (0, 1):
            roas.append((asn, str(net), plen, ta))
        elif bucket == 2 and plen > 8:
            sup = net.supernet(new_prefix=max(plen - 4, 8))
            roas.append((asn, str(sup), plen, ta))
        elif bucket == 3:
            roas.append((asn + 1 if asn < 4294967295 else 1, str(net), plen, ta))
        elif bucket == 4 and plen > 8:
            sup = net.supernet(new_prefix=max(plen - 4, 8))
            roas.append((asn, str(sup), sup.prefixlen, ta))
        if h % 97 == 0:
            roas.append((0, str(net), plen, ta))
    # v4 turns each ROA into an RPKI pseudo-object keyed by prefix, origin and
    # maxLength, and a second ROA with the same three (from another trust
    # anchor) fails its unique constraint, so keep the first of each.
    uniq = {}
    for a, p, m, t in roas:
        uniq.setdefault((a, p, m), t)
    out = [{"asn": f"AS{a}", "prefix": p, "maxLength": m, "ta": t} for (a, p, m), t in uniq.items()]
    json.dump({"roas": out}, sys.stdout, indent=0)
    sys.stdout.write("\n")
    print(f"roas: {len(out)} for {len(seen)} routes", file=sys.stderr)


if __name__ == "__main__":
    main()
