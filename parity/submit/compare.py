#!/usr/bin/env python3
"""Compare what IRRd v4 and irrd-ng did in the submission differential.

    compare.py WORK [--verbose]

For every step: the response (HTTP status, content type and body, or the
tool's exit code and output) and the mails sent (headers that matter and
the decoded body; v4 sends in Python set order, so the mails of a step are
compared as a multiset). At the end: the canonical exports of both
databases and the NRTMv3 journal.

Masked before comparing, because each server stamps them at write time:
last-modified values, new BCRYPT-PW hashes (random salt), and the columns
in excluded-columns.tsv. Prints a summary and exits 1 on any difference.
"""
import difflib
import email
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = sys.argv[1]
VERBOSE = "--verbose" in sys.argv
OUT = os.path.join(WORK, "out")

LAST_MODIFIED = re.compile(r"(last-modified:\s+)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
BCRYPT = re.compile(r"\$2b\$12\$[./A-Za-z0-9]{53}")


PK_ORDERED = {"change_log", "protected_rpsl_name", "rpsl_objects_suspended", "auth_user", "auth_mntner",
              "auth_api_token", "auth_permission", "auth_webauthn"}


def mask(text):
    text = LAST_MODIFIED.sub(r"\1<masked>", text)
    return BCRYPT.sub("<bcrypt>", text)


def mail_view(raw):
    msg = email.message_from_string(raw)
    head = "".join(f"{h}: {msg[h]}\n" for h in ["Subject", "From", "To", "Content-Type", "MIME-Version",
                                                 "Content-Transfer-Encoding"])
    body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "ascii", "replace")
    return mask(head + "\n" + body)


def diff(a, b, label):
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), f"v4/{label}", f"ng/{label}"))


def main():
    steps = sorted(f for f in os.listdir(os.path.join(OUT, "v4")) if f.endswith(".txt"))
    step_ok = step_bad = mail_total = mail_bad = 0
    failures = []
    for f in steps:
        a = open(os.path.join(OUT, "v4", f)).read()
        b = open(os.path.join(OUT, "ng", f)).read()
        if mask(a) == mask(b):
            step_ok += 1
        else:
            step_bad += 1
            failures.append(diff(mask(a), mask(b), f))
        mf = f.replace(".txt", ".mails.json")
        ma = sorted(mail_view(m) for m in json.load(open(os.path.join(OUT, "v4", mf))))
        mb = sorted(mail_view(m) for m in json.load(open(os.path.join(OUT, "ng", mf))))
        mail_total += max(len(ma), len(mb))
        if ma != mb:
            bad = max(len(ma), len(mb)) - sum(1 for x in ma if x in mb)
            mail_bad += max(bad, 1)
            failures.append(diff("\n=====\n".join(ma), "\n=====\n".join(mb), mf))
    nrtm_a = mask(open(os.path.join(OUT, "v4-nrtm.txt"), errors="replace").read())
    nrtm_b = mask(open(os.path.join(OUT, "ng-nrtm.txt"), errors="replace").read())
    nrtm_ok = nrtm_a == nrtm_b
    if not nrtm_ok:
        failures.append(diff(nrtm_a, nrtm_b, "nrtm"))

    masked = {}
    for side in ["v4", "ng"]:
        src = os.path.join(OUT, f"{side}-export")
        dst = os.path.join(OUT, f"{side}-export-masked")
        os.makedirs(dst, exist_ok=True)
        excl = [l.split("\t", 1)[0].strip() for l in open(os.path.join(HERE, "excluded-columns.tsv"))
                if l.strip() and not l.startswith("#")]
        for name in os.listdir(src):
            table = name.rsplit(".", 1)[0]
            with open(os.path.join(src, name)) as fi:
                lines = [mask(line) for line in fi]
            if table in PK_ORDERED:
                # Ordered by a random row UUID: compare as a multiset of
                # rows without the columns each server generates.
                drop = {c.split(".", 1)[1] for c in excl if c.split(".", 1)[0] in (table, "*")}
                rows = []
                for line in lines:
                    obj = json.loads(line)
                    for c in drop:
                        obj.pop(c, None)
                    rows.append(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
                lines = sorted(rows)
            with open(os.path.join(dst, name), "w") as fo:
                fo.writelines(lines)
        masked[side] = dst
    p = subprocess.run(
        [sys.executable, os.path.join(HERE, "..", "tools", "compare_exports.py"), masked["v4"], masked["ng"],
         "--exclude-file", os.path.join(HERE, "excluded-columns.tsv"), "--label-left", "v4", "--label-right", "irrd-ng"],
        capture_output=True, text=True)
    export_ok = p.returncode == 0

    for fail in failures:
        print(fail if VERBOSE else fail[:3000])
    print(p.stdout)
    print(f"steps: {len(steps)}, responses identical: {step_ok}, different: {step_bad}")
    print(f"mails: {mail_total}, different: {mail_bad}")
    print(f"nrtm journal: {'identical' if nrtm_ok else 'different'}")
    print(f"exports: {'identical' if export_ok else 'different'}")
    sys.exit(0 if (step_bad == 0 and mail_bad == 0 and nrtm_ok and export_ok) else 1)


if __name__ == "__main__":
    main()
