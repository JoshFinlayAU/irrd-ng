#!/usr/bin/env python3
"""Compare two NRTMv4 server repositories (a directory with an Update
Notification File, snapshots and deltas) for the same source.

    compare_nrtm4.py <left dir> <right dir> [--label-left L] [--label-right R]

Two servers fed the same changes cannot write identical files: the session
ID, the random file name tokens, the signature and the timestamps differ,
and how changes are grouped into deltas depends on when each server ran.
What must be identical is everything a client reads:

  - the Update Notification File's fields and field order, with
    session_id, timestamp, file names and hashes masked, and the snapshot
    version;
  - the snapshot's header (session_id masked) and every object record, byte
    for byte, in order;
  - every delta record after the delta headers, byte for byte, in version
    order, i.e. the same changes in the same order;
  - each file's own consistency: hashes match, headers carry the UNF's
    session and the referenced version, deltas are contiguous.

The number of deltas is reported but may differ. Exits 1 on any difference.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import sys

UNF = "update-notification-file.jose"


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def records(path):
    with gzip.open(path, "rb") as f:
        data = f.read()
    parts = data.split(b"\x1e")
    if parts[0] != b"":
        raise ValueError(f"{path}: does not start with RS")
    return [p for p in parts[1:]]


def load(repo):
    with open(os.path.join(repo, UNF), encoding="ascii") as f:
        jws = f.read()
    header, payload, _sig = jws.split(".")
    unf_raw = b64d(payload)
    unf = json.loads(unf_raw)
    problems = []
    if json.loads(b64d(header)) != {"alg": "ES256"}:
        problems.append("JWS header is not {\"alg\":\"ES256\"}")
    session = unf["session_id"]

    def check(ref, kind):
        path = os.path.join(repo, ref["url"])
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        if digest != ref["hash"]:
            problems.append(f"{ref['url']}: hash mismatch")
        recs = records(path)
        head = json.loads(recs[0])
        if head.get("session_id") != session or head.get("version") != ref["version"] or head.get("type") != kind:
            problems.append(f"{ref['url']}: header {head} does not match the UNF")
        if not re.fullmatch(rf"nrtm-{kind}\.{session}\.{ref['version']}\.[0-9a-f]{{32}}\.json\.gz", ref["url"]):
            problems.append(f"{ref['url']}: unexpected file name")
        return recs

    snap = check(unf["snapshot"], "snapshot")
    delta_records = []
    versions = [d["version"] for d in unf["deltas"]]
    if versions and versions != list(range(versions[0], versions[0] + len(versions))):
        problems.append(f"deltas not contiguous: {versions}")
    for d in unf["deltas"]:
        delta_records.extend(check(d, "delta")[1:])
    masked = json.loads(unf_raw)
    masked["session_id"] = "<session>"
    masked["timestamp"] = "<timestamp>" if re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?Z", unf["timestamp"]) else unf["timestamp"]
    masked["snapshot"] = {k: (v if k == "version" else "<masked>") for k, v in unf["snapshot"].items()}
    masked["deltas"] = len(unf["deltas"])
    snap_head = snap[0].replace(session.encode(), b"<session>")
    return {
        "unf_keys": list(json.loads(unf_raw).keys()),
        "unf": masked,
        "snapshot_header": snap_head,
        "snapshot": snap[1:],
        "deltas": delta_records,
        "problems": problems,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--label-left", default="left")
    ap.add_argument("--label-right", default="right")
    a = ap.parse_args()
    l, r = load(a.left), load(a.right)
    failed = False
    for side, label in ((l, a.label_left), (r, a.label_right)):
        for p in side["problems"]:
            print(f"{label}: {p}")
            failed = True
    if l["unf_keys"] != r["unf_keys"]:
        print(f"UNF field order: {l['unf_keys']} vs {r['unf_keys']}")
        failed = True
    lu, ru = dict(l["unf"]), dict(r["unf"])
    nl, nr = lu.pop("deltas"), ru.pop("deltas")
    lu.pop("version"), ru.pop("version")
    if lu != ru:
        print(f"UNF fields differ: {lu} vs {ru}")
        failed = True
    if l["snapshot_header"] != r["snapshot_header"]:
        print(f"snapshot header: {l['snapshot_header']!r} vs {r['snapshot_header']!r}")
        failed = True
    for name in ("snapshot", "deltas"):
        x, y = l[name], r[name]
        if x != y:
            i = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
            print(f"{name} records differ at {i} of {len(x)}/{len(y)}:")
            print(f"  {a.label_left}: {x[i][:300]!r}" if i < len(x) else f"  {a.label_left}: <end>")
            print(f"  {a.label_right}: {y[i][:300]!r}" if i < len(y) else f"  {a.label_right}: <end>")
            failed = True
    print(f"snapshot {len(l['snapshot'])} records, delta records {len(l['deltas'])}; "
          f"deltas {a.label_left} {nl}, {a.label_right} {nr}: {'DIFFERENT' if failed else 'identical'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
