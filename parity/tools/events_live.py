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
import threading
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


def reader(ws, out, stop):
    """Read continuously (answering pings, which uvicorn expects within
    60 seconds) until told to stop or the server closes."""
    while not stop.is_set():
        m = ws.recv(0.5)
        if m is None:
            continue
        out.append(m)
        if m[0] in ("close", "eof"):
            break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", type=http_diff.addr, required=True)
    ap.add_argument("--test", type=http_diff.addr, required=True)
    ap.add_argument("--v4-cmd", required=True)
    ap.add_argument("--ng-cmd", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    streams, stop = {}, threading.Event()
    for name, addr in (("v4", args.ref), ("ng", args.test)):
        ws = http_diff.WS(addr, "", 30)
        ws.recv(5)
        ws.send_frame(0x1, json.dumps({"message_type": "subscribe"}).encode())
        msgs = []
        t = threading.Thread(target=reader, args=(ws, msgs, stop), daemon=True)
        t.start()
        streams[name] = (ws, msgs, t)
    time.sleep(1)
    for cmd in (args.v4_cmd, args.ng_cmd):
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
    # v4 publishes within the commit; irrd-ng's watcher picks up a write
    # from another process within two seconds.
    time.sleep(8)
    stop.set()
    got = {}
    for name, (ws, msgs, t) in streams.items():
        t.join(5)
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
