#!/usr/bin/env python3
"""ROA files for the status suite (parity/status/run.sh).

    roas.py base BASE.json > roas1.json     # BASE plus step 1 ROAs
    roas.py mutate BASE.json > roas2.json   # churned BASE plus step 2 ROAs
    roas.py dup IN.json > roas-dup.json     # IN plus two repeats of its first ROA

BASE is what parity/load.sh builds for the rpki profile (make_roas.py over
the fixtures plus corpus/whois/data/roas-static.json). The churn is
deterministic: by a stable hash of each ROA, one in seven is dropped, one in
eleven gets the next origin AS, one in thirteen a longer maxLength, so on
the fixtures routes move between all three RPKI states. The step ROAs move
the synthetic STATUSAUTH routes (parity/status/data) between states in a
known way, so the notification mails have known contents. Everything is
invented; nothing comes from an RPKI repository.
"""
import hashlib
import ipaddress
import json
import sys

STEP1 = [
    ("AS65002", "198.51.100.0/24", 24, "ripe"),
    ("AS65099", "203.0.113.0/24", 25, "arin"),
]
STEP2 = [
    ("AS65001", "192.0.2.0/24", 24, "ripe"),
    ("AS65001", "2001:db8::/32", 32, "apnic"),
    ("AS65009", "192.0.2.0/25", 25, "ripe"),
    ("AS65013", "192.0.2.0/24", 25, "arin"),
    ("AS65007", "198.51.100.0/24", 24, "arin"),
    ("AS65009", "2001:db8:1::/48", 48, "apnic"),
]


def h(roa):
    key = f'{roa["asn"]}{roa["prefix"]}{roa["maxLength"]}'
    return int(hashlib.sha1(key.encode()).hexdigest()[:8], 16)


def entry(a, p, m, t):
    return {"asn": a, "prefix": p, "maxLength": m, "ta": t}


def dedupe(roas):
    seen = set()
    out = []
    for r in roas:
        k = (r["asn"], r["prefix"], r["maxLength"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    roas = json.load(open(path))["roas"]
    if cmd == "base":
        out = roas + [entry(*r) for r in STEP1]
    elif cmd == "mutate":
        out = []
        for r in roas:
            x = h(r)
            if x % 7 == 0:
                continue
            r = dict(r)
            if x % 11 == 0:
                n = int(r["asn"][2:])
                r["asn"] = f"AS{n + 1 if n < 4294967295 else 1}"
            if x % 13 == 0:
                bits = ipaddress.ip_network(r["prefix"], strict=False).max_prefixlen
                r["maxLength"] = min(int(r["maxLength"]) + 2, bits)
            out.append(r)
        out += [entry(*r) for r in STEP2]
    elif cmd == "dup":
        # The same ROA again under the same trust anchor and under another.
        first = dict(roas[0])
        first["ta"] = "duplicate-ta"
        out = roas + [dict(roas[0]), first]
        json.dump({"roas": out}, sys.stdout, indent=0)
        sys.stdout.write("\n")
        return
    else:
        sys.exit("roas.py base|mutate|dup FILE")
    json.dump({"roas": dedupe(out)}, sys.stdout, indent=0)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
