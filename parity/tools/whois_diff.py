#!/usr/bin/env python3
"""Differential whois and /v1/whois/ replay: v4 against irrd-ng, byte for byte.

    whois_diff.py --suite whois|http --corpus FILE [--corpus FILE ...]
                  --ref HOST:PORT --test HOST:PORT [options]

The corpus is the expanded form written by corpus_expand.py (one item per
line, see parity/corpus/whois/README.md). Every item is replayed on its own
connection to both servers, concurrently, and the two byte streams are
compared exactly. Nothing is normalised: framing, ordering, whitespace and
error text all count.

whois sessions are driven the way a client drives them: one query is sent,
then its response is read to its end before the next query goes out. The end
of a response is found from v4's own framing rules (irrd/server/whois/
query_response.py), which depend only on the query, so both servers are read
the same way:

  IRRd style   A<len>\\n + <len> bytes + C\\n, or C\\n, D\\n, F <msg>\\n
               (!! produces no bytes at all)
  RIPE style   the response ends with \\n\\n\\n
  not in keepalive mode (no !! or -k yet) the server closes after one
               answer, so the reader also waits for EOF and keeps anything
               that arrives before it
  !q           the server closes without answering

At the end of a session the client half-closes and reads to EOF, so trailing
bytes, a missing close or a server that hangs are all part of the comparison.
A response that never completes is cut at --timeout and marked.

Reports go to --out: summary.txt, diffs.txt (first differing byte, context
on both sides) and results.jsonl (per item: id, verdict, lengths, sha256).
With --redact no response bytes are written anywhere, only offsets, lengths
and hashes; use it on Tier 2, where responses can hold personal data.
Exit status 0 when every item is identical, 1 when any differs, 2 on usage
or connection errors before the run.
"""

import argparse
import concurrent.futures as cf
import hashlib
import http.client
import json
import os
import re
import socket
import sys
import time
import urllib.parse

# ---------------------------------------------------------------- corpus


class Item:
    """One corpus item: a single query, or a session of queries on one connection."""

    __slots__ = ("id", "lines", "tags")

    def __init__(self, item_id, lines, tags):
        self.id = item_id
        self.lines = lines  # list of bytes, each sent followed by nothing (newline included)
        self.tags = tags

    @property
    def is_session(self):
        return len(self.lines) > 1

    def display(self):
        return " | ".join(ln.rstrip(b"\r\n").decode("utf-8", "backslashreplace") for ln in self.lines)


def unescape(text):
    """Decode the escapes allowed in @raw lines (\\n \\r \\t \\\\ \\xHH)."""
    out = bytearray()
    raw = text.encode("utf-8")
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):
            n = raw[i + 1]
            if n == ord("x") and i + 3 < len(raw):
                out.append(int(raw[i + 2 : i + 4], 16))
                i += 4
                continue
            out.append({ord("n"): 10, ord("r"): 13, ord("t"): 9, 0x5C: 0x5C}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return bytes(out)


def parse_line(text):
    """A corpus query line to the bytes sent on the wire."""
    if text.startswith("@raw "):
        return unescape(text[5:])
    return text.encode("utf-8") + b"\n"


def load_corpus(paths):
    """Read expanded corpus files: `id<TAB>tags<TAB>query`, sessions as
    consecutive lines with the same id."""
    items, order = {}, []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                try:
                    item_id, tags, query = line.split("\t", 2)
                except ValueError:
                    sys.exit(f"{path}:{n}: expected id<TAB>tags<TAB>query")
                if item_id not in items:
                    items[item_id] = Item(item_id, [], tags.split(",") if tags else [])
                    order.append(item_id)
                items[item_id].lines.append(parse_line(query))
    return [items[i] for i in order]


# ---------------------------------------------------------- v4 semantics


def v4_query_text(line):
    """What v4's worker makes of a line (server.py handle_connection)."""
    return line.decode("utf-8", errors="backslashreplace").strip()


# Seconds to wait for the close that follows a non-keepalive answer.
CLOSE_TIMEOUT = 10.0

RIPE_ONE_ARG = {"s", "T", "V", "q", "g"}
RIPE_SEARCH_ONE = {"l", "L", "M", "x", "t"}


def classify(query, keepalive):
    """Return (kind, keepalive_after) for a query as v4 treats it.

    kind: 'skip' (empty line, no answer), 'none' (!!), 'close' (!q),
    'irrd' or 'ripe' (framing of the answer)."""
    if not query:
        return "skip", keepalive
    if query.upper() == "!Q":
        return "close", keepalive
    if chr(0) in query:
        return "irrd", keepalive
    if query.startswith("-V "):
        parts = query.split(" ", 2)
        if len(parts) == 3 and parts[2].startswith("!"):
            query = parts[2]
    if query.startswith("!"):
        if query == "!!":
            return "none", True
        return "irrd", keepalive
    # RIPE style: walk the flags the way handle_ripe_command does, far
    # enough to see whether -k is applied before the query ends.
    comps = re.sub(" +", " ", query).strip().split(" ")
    while comps:
        c = comps.pop(0)
        if not c.startswith("-"):
            continue
        cmd = c[1:]
        if cmd == "k":
            keepalive = True
        elif cmd in RIPE_SEARCH_ONE:
            break
        elif cmd == "i":
            break
        elif cmd in RIPE_ONE_ARG:
            if not comps:
                break
            comps.pop(0)
        elif cmd in ("a", "K", "F", "r"):
            continue
        else:
            break
    return "ripe", keepalive


# --------------------------------------------------------------- reading

HOST_HEADER = "localhost"


class Conn:
    def __init__(self, addr, timeout):
        self.sock = socket.create_connection(addr, timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = bytearray()
        self.eof = False
        self.timeout = timeout

    def _fill(self, deadline):
        if self.eof:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.sock.settimeout(remaining)
        try:
            data = self.sock.recv(1 << 16)
        except ConnectionResetError:
            self.eof = True
            self.buf += b"<<RST>>"
            return False
        except socket.timeout:
            raise TimeoutError from None
        if not data:
            self.eof = True
            return False
        self.buf += data
        return True

    def take(self, n):
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_irrd(self, deadline):
        """One IRRd-style answer: A<len>/C/D/F framing."""
        while True:
            b = self.buf
            if b[:1] == b"A":
                nl = b.find(b"\n")
                if nl >= 0:
                    try:
                        length = int(b[1:nl])
                    except ValueError:
                        return self.take(nl + 1) + self.read_to_quiet()
                    total = nl + 1 + length + 2
                    if len(b) >= total:
                        return self.take(total)
            elif b[:2] in (b"C\n", b"D\n"):
                return self.take(2)
            elif b[:1] == b"F" or (b and b[:1] not in b"ACD"):
                nl = b.find(b"\n")
                if nl >= 0:
                    return self.take(nl + 1)
            if not self._fill(deadline):
                return self.take(len(self.buf))

    def read_ripe(self, deadline):
        """One RIPE-style answer: everything up to and including \\n\\n\\n."""
        start = 0
        while True:
            end = self.buf.find(b"\n\n\n", start)
            if end >= 0:
                return self.take(end + 3)
            start = max(0, len(self.buf) - 2)
            if not self._fill(deadline):
                return self.take(len(self.buf))

    def read_eof(self, deadline):
        while self._fill(deadline):
            pass
        return self.take(len(self.buf))

    def read_to_quiet(self):
        return b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def run_whois_item(addr, item, timeout):
    """Replay one item; returns a list of (label, bytes) segments."""
    segs = []
    try:
        conn = Conn(addr, timeout)
    except OSError as e:
        return [("connect", f"<<CONNECT FAILED: {e.__class__.__name__}>>".encode())]
    keepalive = False
    try:
        for idx, line in enumerate(item.lines):
            if conn.eof and not conn.buf:
                segs.append((f"q{idx}", b"<<CLOSED BEFORE QUERY>>"))
                break
            try:
                conn.sock.sendall(line)
            except OSError:
                segs.append((f"q{idx}", b"<<SEND FAILED>>"))
                break
            kind, keepalive = classify(v4_query_text(line), keepalive)
            deadline = time.monotonic() + timeout
            try:
                if kind in ("skip", "none"):
                    data = b""
                elif kind == "close":
                    data = conn.read_eof(deadline)
                else:
                    data = conn.read_irrd(deadline) if kind == "irrd" else conn.read_ripe(deadline)
                    if not keepalive:
                        # v4 closes right after a single answer.
                        data += conn.read_eof(time.monotonic() + min(timeout, CLOSE_TIMEOUT))
            except TimeoutError:
                data = conn.take(len(conn.buf)) + b"<<TIMEOUT>>"
                segs.append((f"q{idx}", data))
                break
            segs.append((f"q{idx}", data))
        else:
            # Session over: half-close and collect whatever is left.
            try:
                conn.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                tail = conn.read_eof(time.monotonic() + timeout)
            except TimeoutError:
                tail = conn.take(len(conn.buf)) + b"<<TIMEOUT AT EOF>>"
            segs.append(("eof", tail))
    finally:
        conn.close()
    return segs


def run_http_item(base, item, timeout):
    """GET /v1/whois/?q=<query>; one segment each for status+headers and body."""
    host, port = base
    query = item.lines[0]
    if query.endswith(b"\n"):
        query = query[:-1]
    path = "/v1/whois/?q=" + urllib.parse.quote_from_bytes(query, safe="")
    try:
        c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request("GET", path, headers={"Host": HOST_HEADER, "User-Agent": "irrd-ng-parity"})
        r = c.getresponse()
        body = r.read()
        head = f"{r.status} {r.reason}\n".encode()
        for k, v in r.getheaders():
            if k.lower() == "date":
                continue
            head += f"{k.lower()}: {v}\n".encode()
        c.close()
    except (OSError, http.client.HTTPException) as e:
        return [("http", f"<<HTTP FAILED: {e.__class__.__name__}: {e}>>".encode())]
    return [("head", head), ("body", body)]


# ------------------------------------------------------- v4 nondeterminism


def load_unordered(path):
    rules = []
    if not path:
        return rules
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            mode, qre, are, div, _why = line.split("\t", 4)
            if mode not in ("tokens", "objects"):
                sys.exit(f"{path}: unknown mode {mode}")
            rules.append((mode, re.compile(qre), None if are == "-" else re.compile(are.encode()), div))
    return rules


def effective_query(line):
    q = v4_query_text(line)
    if q.startswith("-V "):
        parts = q.split(" ", 2)
        if len(parts) == 3 and parts[2].startswith("!"):
            return parts[2]
    return q


def split_frame(data):
    """(header, payload, trailer) of one answer: IRRd A-frames, RIPE text, or raw."""
    if data[:1] == b"A":
        nl = data.find(b"\n")
        if nl > 0 and data.endswith(b"\nC\n"):
            return data[: nl + 1], data[nl + 1 : -3], b"\nC\n"
    return b"", data, b""


TOKEN_SPLIT = re.compile(rb"[\s,]+")


def same_tokens(a, b):
    ha, pa, ta = split_frame(a)
    hb, pb, tb = split_frame(b)
    if ha != hb or ta != tb:
        return False
    return sorted(TOKEN_SPLIT.split(pa)) == sorted(TOKEN_SPLIT.split(pb))


def object_key(par):
    """v4's sort key for an object answer: (ip_first, asn_first, rpsl_pk),
    approximated by rpsl_pk alone, which determines the other two. rpsl_pk is
    the first attribute's value, except nic-hdl for person and role, and
    prefix plus origin for route and route6, upper-cased without spaces. The
    class is deliberately not part of it: a person and a role with the same
    nic-hdl tie in v4 too."""
    attrs = {}
    first = None
    for ln in par.split(b"\n"):
        if ln[:1] in (b" ", b"\t", b"+", b"#", b"%") or b":" not in ln:
            continue
        name, value = ln.split(b":", 1)
        name = name.strip().lower()
        value = value.split(b"#", 1)[0].strip()
        if first is None:
            first = (name, value)
        attrs.setdefault(name, value)
    if first is None:
        return par
    cls, key = first
    if cls in (b"person", b"role"):
        key = attrs.get(b"nic-hdl", key)
    elif cls in (b"route", b"route6"):
        key = key + attrs.get(b"origin", b"")
    return key.upper().replace(b" ", b"")


def same_objects(a, b):
    ha, pa, ta = split_frame(a)
    hb, pb, tb = split_frame(b)
    if ha != hb or ta != tb:
        return False
    oa, ob = pa.split(b"\n\n"), pb.split(b"\n\n")
    if len(oa) != len(ob) or [object_key(x) for x in oa] != [object_key(x) for x in ob]:
        return False
    if sorted(oa) != sorted(ob):
        return False
    # Only runs of equal sort keys may be permuted.
    i = 0
    while i < len(oa):
        j = i
        while j < len(oa) and object_key(oa[j]) == object_key(oa[i]):
            j += 1
        if sorted(oa[i:j]) != sorted(ob[i:j]):
            return False
        i = j
    return True


def equivalent(rules, query, ref, test):
    """The divergence id if test is an allowed permutation of ref, else None."""
    for mode, qre, are, div in rules:
        if not qre.search(query):
            continue
        if are is not None and not are.search(ref):
            continue
        if mode == "tokens" and same_tokens(ref, test):
            return div
        if mode == "objects" and same_objects(ref, test):
            return div
    return None


# --------------------------------------------------------------- compare


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else -1


def context(data, off, width=60):
    lo = max(0, off - width)
    hi = min(len(data), off + width)
    s = data[lo:off].decode("utf-8", "backslashreplace")
    t = data[off:hi].decode("utf-8", "backslashreplace")
    return f"{'...' if lo else ''}{s!r}  >>>  {t!r}{'...' if hi < len(data) else ''}"


def compare(item, ref, test, rules=()):
    """Compare two segment lists. Returns a result dict."""
    rb = b"".join(d for _, d in ref)
    tb = b"".join(d for _, d in test)
    res = {
        "id": item.id,
        "tags": item.tags,
        "ref_len": len(rb),
        "test_len": len(tb),
        "ref_sha256": hashlib.sha256(rb).hexdigest(),
        "test_sha256": hashlib.sha256(tb).hexdigest(),
    }
    if rb == tb and [x for x, _ in ref] == [x for x, _ in test]:
        res["verdict"] = "same"
        return res, None
    # Permutations v4 itself produces (unordered.tsv), segment by segment.
    if rules and len(ref) == len(test) and [x for x, _ in ref] == [x for x, _ in test]:
        divs = []
        for (label, rd), (_, td) in zip(ref, test):
            if rd == td:
                continue
            idx = int(label[1:]) if label[:1] == "q" and label[1:].isdigit() else None
            if idx is None or idx >= len(item.lines):
                query = effective_query(item.lines[0]) if label in ("head", "body") else None
            else:
                query = effective_query(item.lines[idx])
            div = equivalent(rules, query, rd, td) if query is not None else None
            if div is None:
                divs = None
                break
            divs.append(div)
        if divs:
            res["verdict"] = "equivalent"
            res["divergence"] = ",".join(sorted(set(divs)))
            return res, None
    res["verdict"] = "differ"
    # Locate the first differing segment, by position.
    detail = None
    for i in range(max(len(ref), len(test))):
        rl, rd = ref[i] if i < len(ref) else ("<missing>", b"")
        tl, td = test[i] if i < len(test) else ("<missing>", b"")
        if rd != td or rl != tl:
            off = first_diff(rd, td)
            detail = {"segment": i, "label": rl if rl == tl else f"{rl}/{tl}", "offset": off,
                      "ref_seg_len": len(rd), "test_seg_len": len(td), "ref": rd, "test": td}
            break
    res["segment"] = detail["segment"]
    res["segment_label"] = detail["label"]
    res["offset"] = detail["offset"]
    res["stream_offset"] = first_diff(rb, tb)
    for marker in (b"<<TIMEOUT", b"<<RST>>", b"<<CONNECT", b"<<HTTP FAILED", b"<<CLOSED"):
        if marker in tb and marker not in rb:
            res["test_problem"] = marker.decode().strip("<")
        if marker in rb and marker not in tb:
            res["ref_problem"] = marker.decode().strip("<")
    return res, detail


def classify_difference(detail):
    """A short machine-readable reason, for the summary."""
    r, t = detail["ref"], detail["test"]
    if not t and r:
        return "test-empty"
    if not r and t:
        return "ref-empty"
    if r[:1] != t[:1]:
        return f"frame:{r[:1].decode('latin1')!s}->{t[:1].decode('latin1')!s}"
    if r[:1] == b"A" and r.split(b"\n", 1)[0] != t.split(b"\n", 1)[0]:
        rs, ts = sorted(r.split(b"\n", 1)[-1].split()), sorted(t.split(b"\n", 1)[-1].split())
        if rs == ts:
            return "frame-length-only"
        return "content+length"
    if sorted(r.split()) == sorted(t.split()):
        return "order-or-whitespace"
    return "content"


# ------------------------------------------------------------------ main


def addr(s):
    host, _, port = s.rpartition(":")
    return (host.strip("[]") or "127.0.0.1", int(port))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", choices=["whois", "http"], default="whois")
    ap.add_argument("--corpus", action="append", required=True)
    ap.add_argument("--ref", type=addr, required=True, help="v4 HOST:PORT")
    ap.add_argument("--test", type=addr, required=True, help="irrd-ng HOST:PORT")
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=4, help="items in flight (v4 serves max_connections at once)")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds per response")
    ap.add_argument("--redact", action="store_true", help="never write response bytes")
    ap.add_argument("--save-responses", action="store_true", help="write raw responses of differing items")
    ap.add_argument("--only", help="comma-separated tags; run only items with one of them")
    ap.add_argument("--skip", help="comma-separated tags; leave out items with any of them")
    ap.add_argument("--max-report", type=int, default=200, help="differences written in full to diffs.txt")
    ap.add_argument("--unordered", help="allowlist of v4-nondeterministic answers (corpus/whois/unordered.tsv)")
    ap.add_argument("--strict", action="store_true", help="count permutations allowed by --unordered as differences")
    ap.add_argument("--host-header", default="localhost",
                    help="Host header for http (v4 only accepts the host of server.http.url)")
    args = ap.parse_args()

    items = load_corpus(args.corpus)
    if args.only:
        want = set(args.only.split(","))
        items = [i for i in items if want & set(i.tags)]
    if args.skip:
        drop = set(args.skip.split(","))
        items = [i for i in items if not drop & set(i.tags)]
    if args.suite == "http":
        items = [i for i in items if not i.is_session and "whois-only" not in i.tags]
    os.makedirs(args.out, exist_ok=True)
    if args.save_responses and not args.redact:
        os.makedirs(os.path.join(args.out, "responses"), exist_ok=True)

    runner = run_whois_item if args.suite == "whois" else run_http_item
    rules = [] if args.strict else load_unordered(args.unordered)
    global HOST_HEADER
    HOST_HEADER = args.host_header

    def one(item):
        t0 = time.monotonic()
        with cf.ThreadPoolExecutor(2) as ex:
            fr = ex.submit(runner, args.ref, item, args.timeout)
            ft = ex.submit(runner, args.test, item, args.timeout)
            ref, test = fr.result(), ft.result()
        res, detail = compare(item, ref, test, rules)
        res["seconds"] = round(time.monotonic() - t0, 3)
        return item, res, detail

    start = time.monotonic()
    results, counts, reasons, by_tag = [], {"same": 0, "equivalent": 0, "differ": 0}, {}, {}
    equiv_by_div = {}
    diffs_path = os.path.join(args.out, "diffs.txt")
    with open(os.path.join(args.out, "results.jsonl"), "w") as rj, open(diffs_path, "w") as dt, \
            cf.ThreadPoolExecutor(args.jobs) as pool:
        done = 0
        for item, res, detail in pool.map(one, items):
            done += 1
            counts[res["verdict"]] += 1
            for tag in item.tags or ["untagged"]:
                t = by_tag.setdefault(tag, [0, 0])
                t[0] += 1
                t[1] += res["verdict"] == "differ"
            if res["verdict"] == "equivalent":
                equiv_by_div[res["divergence"]] = equiv_by_div.get(res["divergence"], 0) + 1
            if detail is not None:
                reason = res.get("test_problem") or classify_difference(detail)
                res["reason"] = reason
                reasons[reason] = reasons.get(reason, 0) + 1
                if counts["differ"] <= args.max_report:
                    dt.write(f"=== {item.id} [{','.join(item.tags)}] {reason}\n")
                    dt.write(f"query:   {item.display() if not args.redact else item.display()[:200]}\n")
                    dt.write(f"segment: #{detail['segment']} {detail['label']}, first differing byte at "
                             f"{detail['offset']} (stream offset {res['stream_offset']}); "
                             f"v4 {detail['ref_seg_len']} bytes, irrd-ng {detail['test_seg_len']} bytes "
                             f"(whole: {res['ref_len']} vs {res['test_len']})\n")
                    if not args.redact:
                        off = max(detail["offset"], 0)
                        dt.write(f"v4:      {context(detail['ref'], off)}\n")
                        dt.write(f"irrd-ng: {context(detail['test'], off)}\n")
                    dt.write("\n")
                if args.save_responses and not args.redact:
                    safe = item.id.replace("/", "_").replace(":", "_")
                    with open(os.path.join(args.out, "responses", safe + ".v4"), "wb") as f:
                        f.write(detail["ref"])
                    with open(os.path.join(args.out, "responses", safe + ".ng"), "wb") as f:
                        f.write(detail["test"])
            rj.write(json.dumps(res, sort_keys=True) + "\n")
            if done % 500 == 0:
                print(f"  {done}/{len(items)} items, {counts['differ']} differ", file=sys.stderr)
    elapsed = time.monotonic() - start

    lines = [
        f"suite {args.suite}: {len(items)} items, {counts['same']} identical, "
        f"{counts['equivalent']} equivalent, {counts['differ']} differ "
        f"({elapsed:.1f}s, v4 {args.ref[0]}:{args.ref[1]}, irrd-ng {args.test[0]}:{args.test[1]})",
    ]
    if equiv_by_div:
        lines.append("equivalent (v4 order not fixed, unordered.tsv): "
                     + ", ".join(f"{k} {v}" for k, v in sorted(equiv_by_div.items())))
    if reasons:
        lines.append("differences by reason: " + ", ".join(f"{k} {v}" for k, v in sorted(reasons.items())))
    lines.append("by tag (items / differ):")
    for tag, (n, d) in sorted(by_tag.items()):
        lines.append(f"  {tag:<24} {n:>7} {d:>7}")
    summary = "\n".join(lines) + "\n"
    with open(os.path.join(args.out, "summary.txt"), "w") as f:
        f.write(summary)
    sys.stdout.write(summary)
    if counts["differ"]:
        print(f"details: {diffs_path}")
    sys.exit(1 if counts["differ"] else 0)


if __name__ == "__main__":
    main()
