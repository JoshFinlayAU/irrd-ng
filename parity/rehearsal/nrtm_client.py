"""An NRTMv3 client across the drop-in cutover (rehearsal/run.sh).

  nrtm_client.py record --addr HOST:PORT --source SRC --state FILE
      Before the cutover, against v4: the journal range (!j) and every
      journal entry (-g SRC:3:FIRST-LAST), as a mirror would have applied
      them, plus !j-* for every source.

  nrtm_client.py follow --addr HOST:PORT --ref HOST:PORT --state FILE
      After the cutover, against irrd-ng, with v4 (on the unchanged
      database, with the same changes applied) as reference: the client
      asks for LAST+1 onwards exactly as it would have asked v4, and gets
      the same answer v4 gives; the history it already has is served
      byte for byte as before; !j-* was preserved.

Exit 0 when every check passes. Prints one line per check.
"""

import argparse
import json
import re
import socket
import sys


def mask(text):
    """Each server stamps `last-modified:` with the time it applied the
    change, which differs by the seconds between the two runs (the events
    live suite masks it the same way)."""
    return re.sub(r"^(last-modified:\s+)\S+$", r"\1<masked>", text, flags=re.M)


def query(addr, q, timeout=60):
    host, port = addr.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=timeout) as s:
        s.sendall(q.encode() + b"\n")
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks).decode("utf-8", "backslashreplace")


def journal_range(addr, source):
    """The journal's serial range, from !J (!j reports mirror serials)."""
    a = query(addr, f"!J{source}")
    body = a.split("\n", 1)[1].rsplit("\nC", 1)[0] if a.startswith("A") else ""
    try:
        st = json.loads(body)[source]
        return int(st["serial_oldest_journal"]), int(st["serial_newest_journal"])
    except (ValueError, KeyError, TypeError):
        raise SystemExit(f"no journal range for {source} from {addr}: {a[:200]!r}")


def record(args):
    first, last = journal_range(args.addr, args.source)
    state = {
        "source": args.source,
        "first": first,
        "last": last,
        "history": query(args.addr, f"-g {args.source}:3:{first}-LAST"),
        "all_sources": query(args.addr, "!j-*"),
    }
    with open(args.state, "w") as f:
        json.dump(state, f)
    print(f"recorded {args.source} serials {first}-{last} from {args.addr}")


def follow(args):
    with open(args.state) as f:
        st = json.load(f)
    src, first, last = st["source"], st["first"], st["last"]
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        ok = ok and cond
        print(f"{'ok  ' if cond else 'FAIL'} {name}{': ' + detail if detail and not cond else ''}")

    # run.sh compares !J-* right after the start; after the changes the
    # untouched sources must still match (!j: mirror serials).
    before = {l.split(":")[0]: l for l in st["all_sources"].splitlines() if ":" in l}
    after = {l.split(":")[0]: l for l in query(args.addr, "!j-*").splitlines() if ":" in l}
    untouched = [s for s in before if s != src]
    check(
        "serials of every other source preserved",
        all(before[s] == after.get(s) for s in untouched),
        str([(before[s], after.get(s)) for s in untouched if before[s] != after.get(s)]),
    )
    tfirst, tlast = journal_range(args.addr, src)
    check(f"{src} journal still starts at {first}", tfirst == first, f"{tfirst}")
    check(f"{src} journal continues past {last}", tlast > last, f"{tlast}")
    history = query(args.addr, f"-g {src}:3:{first}-{last}")
    check("history served as v4 served it", history == st["history"])
    q = f"-g {src}:3:{last + 1}-LAST"
    got, ref = query(args.addr, q), query(args.ref, q)
    check(
        f"'{q}' continues at {last + 1}",
        got.startswith(f"%START Version: 3 {src} {last + 1}-"),
        got[:80],
    )
    check(
        f"'{q}' answered as v4 answers it (last-modified masked)",
        mask(got) == mask(ref),
        f"irrd-ng {got[:200]!r} v4 {ref[:200]!r}",
    )
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--addr", required=True)
    r.add_argument("--source", required=True)
    r.add_argument("--state", required=True)
    f = sub.add_parser("follow")
    f.add_argument("--addr", required=True)
    f.add_argument("--ref", required=True)
    f.add_argument("--state", required=True)
    args = ap.parse_args()
    if args.cmd == "record":
        record(args)
        return 0
    return follow(args)


if __name__ == "__main__":
    sys.exit(main())
