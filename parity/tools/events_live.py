#!/usr/bin/env python3
"""Live event stream check: subscribe to both servers' event streams,
apply the same irrd_update_database run to both, and compare what each
stream sends (parity/run.sh --suite events).

    events_live.py --ref HOST:PORT --test HOST:PORT --v4-cmd CMD --ng-cmd CMD --out DIR

CMD is a shell command that applies the update to that server. The
event ids (Redis stream ids, from the clock) and the journal timestamps
and last-modified values (each server's own clock) are masked; the
serials, operations, object texts and parsed data must be identical.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import http_diff  # noqa: E402

MASKS = [
    (re.compile(r'"event_id":"[0-9]+-[0-9]+"'), '"event_id":"<masked>"'),
    (re.compile(r'"timestamp":"[^"]*"'), '"timestamp":"<masked>"'),
    (re.compile(r"last-modified:  [0-9T:Z-]+"), "last-modified:  <masked>"),
]


def mask(text):
    for r, s in MASKS:
        text = r.sub(s, text)
    return text


def collect(ws, seconds):
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        m = ws.recv(0.5)
        if m is None:
            continue
        out.append(m)
        if m[0] in ("close", "eof"):
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", type=http_diff.addr, required=True)
    ap.add_argument("--test", type=http_diff.addr, required=True)
    ap.add_argument("--v4-cmd", required=True)
    ap.add_argument("--ng-cmd", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    streams = {}
    for name, addr in (("v4", args.ref), ("ng", args.test)):
        ws = http_diff.WS(addr, "", 30)
        header = ws.recv(5)
        ws.send_frame(0x1, json.dumps({"message_type": "subscribe"}).encode())
        streams[name] = (ws, header)
    time.sleep(1)
    for cmd in (args.v4_cmd, args.ng_cmd):
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
    got = {}
    for name, (ws, header) in streams.items():
        # v4 publishes within the commit; irrd-ng's watcher picks up a
        # write from another process within two seconds.
        msgs = collect(ws, 8)
        got[name] = [mask(m[1]) for m in msgs if m[0] == "text"]
        ws.close()
    same = got["v4"] == got["ng"]
    with open(os.path.join(args.out, "live.txt"), "w") as f:
        for name in ("v4", "ng"):
            f.write(f"--- {name}\n" + "\n".join(got[name]) + "\n")
    print(f"events live: {len(got['v4'])} messages from v4, {len(got['ng'])} from irrd-ng, "
          f"{'same' if same else 'differ'}")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
