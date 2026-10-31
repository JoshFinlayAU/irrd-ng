#!/usr/bin/env python3
"""Compare two mirrors' canonical exports per source, for the soak.

    soak_compare.py <v4-export-dir> <irrd-ng-export-dir>

Both directories hold rpsl_objects.jsonl and database_status.jsonl in the
canonical export format (parity/tools/export_v4.py and
`irrd-ng export-jsonl`). Mirrors update on their own timers, so a source
is compared only when both mirrors stand at the same position in it (the
same serial_newest_mirror, or the same NRTMv4 session and version);
otherwise it is reported as "moving". Prints one JSON object per source.
"""
import hashlib
import json
import sys

# Assigned independently by each mirror (see parity/mirror/excluded-columns.tsv).
EXCLUDE = {
    "rpsl_objects": {"pk", "created", "updated"},
    "database_status": {
        "pk", "created", "updated", "rpsl_data_updated", "last_error_timestamp",
    },
}


def project(line, table):
    obj = json.loads(line)
    for c in EXCLUDE.get(table, ()):
        obj.pop(c, None)
    return obj


def position(st):
    if st is None:
        return None
    if st.get("nrtm4_client_session_id"):
        return "%s:%s" % (st["nrtm4_client_session_id"], st["nrtm4_client_version"])
    return st.get("serial_newest_mirror")


def load(d):
    status = {}
    with open(f"{d}/database_status.jsonl", encoding="utf-8") as f:
        for line in f:
            obj = project(line, "database_status")
            status[obj["source"]] = obj
    objects = {}
    with open(f"{d}/rpsl_objects.jsonl", encoding="utf-8") as f:
        for line in f:
            obj = project(line, "rpsl_objects")
            key = (obj["object_class"], obj["rpsl_pk"])
            canon = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            objects.setdefault(obj["source"], {})[key] = hashlib.sha256(canon.encode()).hexdigest()
    return status, objects


def main():
    s4, o4 = load(sys.argv[1])
    sng, ong = load(sys.argv[2])
    failed = False
    for source in sorted(set(s4) | set(sng) | set(o4) | set(ong)):
        p4, png = position(s4.get(source)), position(sng.get(source))
        res = {"source": source, "position_v4": p4, "position_irrd_ng": png,
               "objects_v4": len(o4.get(source, {})), "objects_irrd_ng": len(ong.get(source, {}))}
        if p4 != png:
            res["result"] = "moving"
        else:
            a, b = o4.get(source, {}), ong.get(source, {})
            only4 = sorted(set(a) - set(b))
            onlyng = sorted(set(b) - set(a))
            differ = sorted(k for k in set(a) & set(b) if a[k] != b[k])
            status_same = s4.get(source) == sng.get(source)
            res.update({
                "only_v4": len(only4), "only_irrd_ng": len(onlyng), "differ": len(differ),
                "status_same": status_same,
                "examples": [list(k) for k in (only4 + onlyng + differ)[:5]],
            })
            if not status_same:
                res["status_v4"] = s4.get(source)
                res["status_irrd_ng"] = sng.get(source)
            res["result"] = "same" if not (only4 or onlyng or differ) and status_same else "DIFFERENT"
            failed |= res["result"] != "same"
        print(json.dumps(res, sort_keys=True))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
