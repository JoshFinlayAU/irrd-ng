#!/usr/bin/env python3
"""Differential runner for the HTTP API suites: graphql, api (status,
metrics, explorer, static files and error paths) and events (the event
stream WebSocket and its initial download).

    http_diff.py --suite graphql|api|events --corpus FILE [--corpus FILE ...]
                 --ref HOST:PORT --test HOST:PORT --bindings FILE --out DIR
                 [--only TAG,...] [--jobs N] [--timeout S] [--strict]

Corpus syntax (parity/corpus/graphql/README.md has the full description):

  # comment              ignored
  @tags a,b              tags for the items that follow
  @limit N               at most N expansions per templated item
  @gql [OperationName]   a GraphQL request: the query follows, then
                         optionally `@variables <JSON>`; ends with @end
  @request METHOD PATH   a raw request: header lines, a blank line, the
                         body; ends with @end
  @ws [extensions]       a WebSocket session to /v1/event-stream/: lines
                         `send <text>` and `wait`; ends with @end

`{name}` placeholders take values from the bindings, as in the whois
corpus (tools/corpus_expand.py).

Every response is compared after masking what legitimately differs
between two servers or two runs: the `date` header, GraphQL's
`extensions.execution` time and the content length that depends on it,
the `Listening on` line of /v1/status/ (each server's own address), the
time-dependent values in /metrics/, and the initial download's
`generated_at` and `generated_on`. Where v4's own output order is not
stable (rows PostgreSQL returns without ORDER BY, Python set order, the
order async resolvers finish in), a permutation of v4's answer counts as
"equivalent", never as "same"; --strict counts it as a difference.
Exit 0 when nothing differs.
"""

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import re
import socket
import struct
import sys
import time
import zlib

PH = re.compile(r"\{([a-z0-9_]+)(?:\.([a-z0-9_]+))?(?:\|(lower|upper|digits))?\}")


def fill(text, bindings, k):
    """tools/corpus_expand.py's placeholder filling, plus `|digits` (an
    AS number without its `AS`)."""
    def sub(m):
        vals = bindings[m.group(1)]
        v = vals[k % len(vals)]
        v = str(v[m.group(2)]) if m.group(2) else v if isinstance(v, str) else json.dumps(v)
        f = m.group(3)
        if f == "digits":
            return re.sub(r"[^0-9]", "", v)
        return {"lower": v.lower(), "upper": v.upper()}.get(f, v)

    text = text.replace("{{", "\x00").replace("}}", "\x01")
    return PH.sub(sub, text).replace("\x00", "{").replace("\x01", "}")

HOST_HEADER = "localhost"
DATE_RE = re.compile(rb"(?im)^(date:)[^\r\n]*")
# A static file's modification time is a property of the installation.
STATIC_RE = re.compile(rb"(?im)^(last-modified:|etag:)[^\r\n]*")


# ---------------------------------------------------------------- corpus


class Item:
    def __init__(self, item_id, kind, head, lines, tags):
        self.id, self.kind, self.head, self.lines, self.tags = item_id, kind, head, lines, tags

    def display(self):
        return (self.head + " | " + " ".join(self.lines))[:300]


def expand(lines, bindings, limit):
    text = "\n".join(lines)
    names = {m.group(1) for m in PH.finditer(text.replace("{{", "").replace("}}", ""))}
    if not names:
        return [lines]
    if any(not bindings.get(n) for n in names):
        return []
    n = min(limit, max(len(bindings[x]) for x in names))
    return [fill(text, bindings, k).split("\n") for k in range(n)]


def load_corpus(paths, bindings):
    items = []
    for path in paths:
        stem = os.path.splitext(os.path.basename(path))[0]
        tags, limit = [stem], 10
        with open(path, encoding="utf-8") as f:
            raw = f.read().split("\n")
        i = 0
        while i < len(raw):
            line = raw[i]
            n = i + 1
            i += 1
            if not line.strip() or line.startswith("#"):
                continue
            if line.startswith("@tags"):
                tags = list(dict.fromkeys([stem] + [t for t in line[5:].strip().split(",") if t]))
                continue
            if line.startswith("@limit"):
                limit = int(line[6:].strip())
                continue
            kind, _, head = line.partition(" ")
            if kind not in ("@gql", "@request", "@ws"):
                sys.exit(f"{path}:{n}: unknown directive {kind}")
            block = []
            while i < len(raw) and raw[i].strip() != "@end":
                block.append(raw[i])
                i += 1
            if i >= len(raw):
                sys.exit(f"{path}:{n}: {kind} without @end")
            i += 1
            for k, exp in enumerate(expand([head] + block, bindings, limit)):
                item_id = f"{stem}:{n}" + (f"#{k}" if k else "")
                items.append(Item(item_id, kind[1:], exp[0], exp[1:], tags))
    return items


# --------------------------------------------------------------- requests


def http_request(addr, method, path, headers, body, timeout):
    req = f"{method} {path} HTTP/1.1\r\nHost: {HOST_HEADER}\r\nUser-Agent: irrd-ng-parity\r\n"
    for h in headers:
        req += h + "\r\n"
    if body is not None:
        req += f"Content-Length: {len(body)}\r\n"
    req += "Connection: close\r\n\r\n"
    data = req.encode("utf-8") + (body or b"")
    s = socket.create_connection(addr, timeout=timeout)
    try:
        s.sendall(data)
        out = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            out += chunk
    finally:
        s.close()
    return out


def dechunk(body):
    out, rest = b"", body
    while rest:
        line, _, rest = rest.partition(b"\r\n")
        try:
            n = int(line.split(b";")[0], 16)
        except ValueError:
            return body
        if n == 0:
            break
        out += rest[:n]
        rest = rest[n + 2:]
    return out


def gql_request(item):
    query_lines, variables = [], None
    for ln in item.lines:
        if ln.startswith("@variables "):
            variables = json.loads(ln[len("@variables "):])
        else:
            query_lines.append(ln)
    payload = {"query": "\n".join(query_lines)}
    if variables is not None:
        payload["variables"] = variables
    if item.head:
        payload["operationName"] = item.head
    return "POST", "/graphql/", ["Content-Type: application/json"], json.dumps(payload).encode()


def raw_request(item):
    method, _, path = item.head.partition(" ")
    headers, body_lines, in_body = [], [], False
    for ln in item.lines:
        if in_body:
            body_lines.append(ln)
        elif not ln.strip():
            in_body = True
        else:
            headers.append(ln)
    body = "\n".join(body_lines).encode() if in_body else None
    return method, path, headers, body


# -------------------------------------------------------------- websocket


class WS:
    """A minimal RFC 6455 client: text frames, close, permessage-deflate."""

    def __init__(self, addr, extensions, timeout):
        self.s = socket.create_connection(addr, timeout=timeout)
        key = base64.b64encode(b"irrd-ng-parity!!").decode()
        req = (f"GET /v1/event-stream/ HTTP/1.1\r\nHost: {HOST_HEADER}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
        if extensions:
            req += f"Sec-WebSocket-Extensions: {extensions}\r\n"
        self.s.sendall((req + "\r\n").encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        self.head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.inflate = zlib.decompressobj(-15) if b"permessage-deflate" in self.head else None

    def _read(self, n, deadline):
        while len(self.buf) < n:
            self.s.settimeout(max(0.01, deadline - time.monotonic()))
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self, wait):
        """Next message as (kind, text), or None when quiet for `wait`."""
        deadline = time.monotonic() + wait
        try:
            while True:
                h = self._read(2, deadline)
                rsv1, op, n = h[0] & 0x40, h[0] & 0x0F, h[1] & 0x7F
                if n == 126:
                    n = struct.unpack(">H", self._read(2, deadline))[0]
                elif n == 127:
                    n = struct.unpack(">Q", self._read(8, deadline))[0]
                payload = self._read(n, deadline + 30)
                if op == 0x9:
                    self.send_frame(0xA, payload)
                    continue
                if op == 0xA:
                    continue
                if op == 0x8:
                    code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None
                    return ("close", str(code))
                if rsv1 and self.inflate:
                    payload = self.inflate.decompress(payload + b"\x00\x00\xff\xff")
                return ("text", payload.decode("utf-8", "replace"))
        except (socket.timeout, TimeoutError):
            return None
        except (EOFError, OSError):
            return ("eof", "")

    def send_frame(self, op, payload):
        mask = os.urandom(4)
        n = len(payload)
        head = bytes([0x80 | op])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def run_ws(addr, item, timeout):
    segs = []
    try:
        ws = WS(addr, item.head.strip(), timeout)
    except OSError as e:
        return [("ws", f"<<CONNECT FAILED {e.__class__.__name__}>>".encode())]
    segs.append(("head", DATE_RE.sub(rb"\1 <masked>", ws.head)))
    try:
        for ln in item.lines:
            if ln.startswith("send "):
                ws.send_frame(0x1, ln[5:].encode())
            elif ln.strip() == "wait":
                while True:
                    m = ws.recv(1.5)
                    if m is None:
                        break
                    text = EVENT_ID_RE.sub(b'"event_id":"<masked>"', m[1].encode())
                    segs.append((m[0], text))
                    if m[0] in ("close", "eof"):
                        return segs
    finally:
        ws.close()
    return segs


# ------------------------------------------------------------ normalising


EXEC_RE = re.compile(rb'"execution":[0-9.e+-]+')
CL_RE = re.compile(rb"(?im)^(content-length:)[^\r\n]*")
METRIC_TIME_RE = re.compile(rb"(?m)^(irrd_uptime_seconds|irrd_startup_timestamp|irrd_last_[a-z_]+_seconds\{[^}]*\}) [0-9-]+$")
LISTEN_RE = re.compile(rb"(?m)^Listening on [^\n]*$")
GEN_RE = re.compile(rb'"generated_(at|on)":"[^"]*"')
EVENT_ID_RE = re.compile(rb'"event_id":"[0-9]+-[0-9]+"')


def run_item(addr, item, suite, timeout):
    if item.kind == "ws":
        return run_ws(addr, item, timeout)
    method, path, headers, body = gql_request(item) if item.kind == "gql" else raw_request(item)
    try:
        raw = http_request(addr, method, path, headers, body, timeout)
    except OSError as e:
        return [("http", f"<<HTTP FAILED: {e.__class__.__name__}>>".encode())]
    head, sep, body = raw.partition(b"\r\n\r\n")
    head = DATE_RE.sub(rb"\1 <masked>", head + sep)
    if path.startswith("/static/"):
        head = STATIC_RE.sub(rb"\1 <masked>", head)
    if b"transfer-encoding: chunked" in head.lower():
        body = dechunk(body)
    masked = body
    masked = EXEC_RE.sub(b'"execution":0', masked)
    masked = METRIC_TIME_RE.sub(rb"\1 <t>", masked)
    masked = LISTEN_RE.sub(b"Listening on <masked>", masked)
    masked = GEN_RE.sub(rb'"generated_\1":"<masked>"', masked)
    if masked != body or path.startswith(("/v1/status", "/metrics")):
        head = CL_RE.sub(rb"\1 <masked>", head)
    return [("head", head), ("body", masked)]


# ------------------------------------------------------------ comparison


def sortable(key, value):
    """Lists whose order v4 does not fix."""
    if not isinstance(value, list) or len(value) < 2:
        return False
    if key in ("prefixes", "errors", "sql_queries"):
        return True
    if all(isinstance(v, dict) for v in value):
        keys = set().union(*(v.keys() for v in value))
        if "serialNrtm" in keys or "source_type" in keys or "message_type" in keys:
            return False
        return bool(keys & {"rpslPk", "objectClass", "source", "rootSource", "asn", "pk"})
    return False


SELECT_RE = re.compile(r"^(RPSLDatabaseQuery: SELECT )(.*?)( \nFROM )", re.S)


def canonical(value, key=None, count_only=False):
    """`count_only`: lists whose order v4 does not fix compare by length
    only (a LIMIT without ORDER BY picks any rows)."""
    if isinstance(value, dict):
        out = {k: canonical(v, k, count_only) for k, v in value.items()}
        # List indices in an error path follow the row order.
        if key == "errors" and isinstance(out.get("path"), list):
            out["path"] = ["#" if isinstance(p, int) else p for p in out["path"]]
        return out
    if isinstance(value, list):
        if count_only and sortable(key, value):
            return len(value)
        items = [canonical(v, key, count_only) for v in value]
        if sortable(key, value):
            items.sort(key=lambda x: json.dumps(x, sort_keys=True))
        return items
    if isinstance(value, str) and key == "sql_queries" or (isinstance(value, str) and value.startswith("RPSLDatabaseQuery: SELECT ")):
        m = SELECT_RE.match(value)
        if m:
            cols = ", ".join(sorted(m.group(2).split(", ")))
            return m.group(1) + cols + m.group(3) + value[m.end():]
    return value


def equivalent(ref, test, count_only=False):
    """Same JSON (or JSON lines) up to the orders v4 does not fix."""
    try:
        if ref[:1] in (b"{", b"[") and b"}\n{" not in ref:
            return canonical(json.loads(ref), None, count_only) == canonical(json.loads(test), None, count_only)
        rl, tl = ref.split(b"\n"), test.split(b"\n")
        if len(rl) != len(tl) or not rl or rl[0] != tl[0]:
            return False
        return sorted(rl[1:]) == sorted(tl[1:])
    except (ValueError, UnicodeDecodeError):
        return False


def compare(ref, test, strict, count_only=False):
    if ref == test:
        return "same"
    if strict or len(ref) != len(test) or [k for k, _ in ref] != [k for k, _ in test]:
        return "differ"
    for (k, r), (_, t) in zip(ref, test):
        if r == t:
            continue
        if k == "head":
            return "differ"
        if not equivalent(r, t, count_only):
            return "differ"
    return "equivalent"


def addr(s):
    host, _, port = s.rpartition(":")
    return (host.strip("[]") or "127.0.0.1", int(port))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", choices=["graphql", "api", "events"], required=True)
    ap.add_argument("--corpus", action="append", required=True)
    ap.add_argument("--bindings", required=True)
    ap.add_argument("--ref", type=addr, required=True)
    ap.add_argument("--test", type=addr, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--max-report", type=int, default=200)
    args = ap.parse_args()

    bindings = json.load(open(args.bindings))
    items = load_corpus(args.corpus, bindings)
    if args.only:
        want = set(args.only.split(","))
        items = [i for i in items if want & set(i.tags)]
    os.makedirs(args.out, exist_ok=True)

    def one(item):
        with cf.ThreadPoolExecutor(2) as ex:
            fr = ex.submit(run_item, args.ref, item, args.suite, args.timeout)
            ft = ex.submit(run_item, args.test, item, args.suite, args.timeout)
            ref, test = fr.result(), ft.result()
        return item, ref, test, compare(ref, test, args.strict, "limit-unordered" in item.tags)

    counts = {"same": 0, "equivalent": 0, "differ": 0}
    start = time.monotonic()
    jobs = 1 if args.suite == "events" else args.jobs
    with open(os.path.join(args.out, "results.jsonl"), "w") as rj, \
            open(os.path.join(args.out, "diffs.txt"), "w") as dt, cf.ThreadPoolExecutor(jobs) as pool:
        for item, ref, test, verdict in pool.map(one, items):
            counts[verdict] += 1
            rj.write(json.dumps({"id": item.id, "tags": item.tags, "verdict": verdict,
                                 "ref_sha256": hashlib.sha256(b"".join(d for _, d in ref)).hexdigest(),
                                 "test_sha256": hashlib.sha256(b"".join(d for _, d in test)).hexdigest()}) + "\n")
            if verdict == "differ" and counts["differ"] <= args.max_report:
                dt.write(f"=== {item.id} [{','.join(item.tags)}]\nrequest: {item.display()}\n")
                for i in range(max(len(ref), len(test))):
                    r = ref[i] if i < len(ref) else ("<missing>", b"")
                    t = test[i] if i < len(test) else ("<missing>", b"")
                    if r != t:
                        dt.write(f"--- v4 {r[0]}:\n{r[1].decode('utf-8', 'replace')[:3000]}\n")
                        dt.write(f"--- irrd-ng {t[0]}:\n{t[1].decode('utf-8', 'replace')[:3000]}\n")
                dt.write("\n")
    total = sum(counts.values())
    summary = (f"suite {args.suite}: {total} items, {counts['same']} same, {counts['equivalent']} equivalent "
               f"(order v4 does not fix), {counts['differ']} differ, {time.monotonic() - start:.1f}s")
    with open(os.path.join(args.out, "summary.txt"), "w") as f:
        f.write(summary + "\n")
    print(summary)
    if counts["differ"]:
        print(f"differences: {os.path.join(args.out, 'diffs.txt')}")
    return 1 if counts["differ"] else 0


if __name__ == "__main__":
    sys.exit(main())
