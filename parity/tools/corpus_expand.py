#!/usr/bin/env python3
"""Expand the whois corpus templates into the replay list whois_diff.py reads.

    corpus_expand.py --bindings bindings.json [--scale K] [--out FILE] TEMPLATE.q [...]

Template syntax (parity/corpus/whois/README.md has the full description):

  # comment                 ignored
  @tags a,b                 tags for the items that follow (until the next @tags)
  @limit N                  at most N expansions per templated item (default 25)
  @session                  the lines up to @end are one connection
  @end
  @raw <escaped bytes>      sent exactly as given (\\n \\r \\t \\\\ \\xHH), no newline added
  anything else             one query, sent followed by \\n

A `{name}` or `{name.field}` placeholder (optionally `{name|lower}` or `|upper`) takes values from the bindings file
(corpus_bindings.py). A line or session with placeholders is repeated once per
value, up to the limit (times --scale); several placeholders in one item
advance together, and placeholders sharing a name and index take fields of
the same record. `{{` and `}}` are literal braces. An item whose placeholder
has no values in this data set is dropped and counted, not an error.

Output: `id<TAB>tags<TAB>query`, one line per query, sessions as consecutive
lines with the same id. Ids are `<file stem>:<line>[#k]`, stable across runs.
"""

import argparse
import json
import os
import re
import sys

PH = re.compile(r"\{([a-z0-9_]+)(?:\.([a-z0-9_]+))?(?:\|(lower|upper))?\}")


def fill(text, bindings, k):
    def sub(m):
        vals = bindings[m.group(1)]
        v = vals[k % len(vals)]
        v = str(v[m.group(2)]) if m.group(2) else v if isinstance(v, str) else json.dumps(v)
        return {"lower": v.lower(), "upper": v.upper()}.get(m.group(3), v)

    text = text.replace("{{", "\x00").replace("}}", "\x01")
    return PH.sub(sub, text).replace("\x00", "{").replace("\x01", "}")


def expand_item(lines, bindings, limit):
    names = set()
    for ln in lines:
        names.update(m.group(1) for m in PH.finditer(ln.replace("{{", "").replace("}}", "")))
    if not names:
        return [lines], None
    missing = [n for n in names if not bindings.get(n)]
    if missing:
        return [], missing
    n = min(limit, max(len(bindings[x]) for x in names))
    return [[fill(ln, bindings, k) for ln in lines] for k in range(n)], None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bindings", required=True)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--out", default="-")
    ap.add_argument("templates", nargs="+")
    args = ap.parse_args()
    bindings = json.load(open(args.bindings))

    out = sys.stdout if args.out == "-" else open(args.out, "w")
    total_items = total_queries = 0
    dropped = {}
    for path in args.templates:
        stem = os.path.splitext(os.path.basename(path))[0]
        tags, limit = [stem], 25
        session, session_start = None, 0
        with open(path, encoding="utf-8") as f:
            raw_lines = f.read().split("\n")
        items = []  # (line number, lines, tags, limit)
        for n, line in enumerate(raw_lines, 1):
            if session is not None:
                if line.strip() == "@end":
                    items.append((session_start, session, tags, limit))
                    session = None
                elif line and not line.startswith("#"):
                    session.append(line)
                continue
            if not line or line.startswith("#"):
                continue
            if line.startswith("@tags"):
                tags = list(dict.fromkeys([stem] + [t for t in line[5:].strip().split(",") if t]))
            elif line.startswith("@limit"):
                limit = int(line[6:].strip())
            elif line.strip() == "@session":
                session, session_start = [], n
            elif line.startswith("@") and not line.startswith("@raw "):
                sys.exit(f"{path}:{n}: unknown directive {line.split()[0]}")
            else:
                items.append((n, [line], tags, limit))
        if session is not None:
            sys.exit(f"{path}:{session_start}: @session without @end")
        for n, lines, item_tags, item_limit in items:
            expansions, missing = expand_item(lines, bindings, max(1, int(item_limit * args.scale)))
            if missing:
                for m in missing:
                    dropped[m] = dropped.get(m, 0) + 1
                continue
            for k, exp in enumerate(expansions):
                item_id = f"{stem}:{n}" + (f"#{k}" if len(expansions) > 1 else "")
                kind = "session" if len(exp) > 1 else "single"
                t = ",".join(item_tags + [kind])
                for q in exp:
                    if "\t" in q or "\n" in q:
                        sys.exit(f"{path}:{n}: use @raw for tabs and newlines")
                    out.write(f"{item_id}\t{t}\t{q}\n")
                    total_queries += 1
                total_items += 1
    if out is not sys.stdout:
        out.close()
    msg = f"corpus: {total_items} items, {total_queries} queries"
    if dropped:
        msg += "; dropped for lack of data: " + ", ".join(f"{k} x{v}" for k, v in sorted(dropped.items()))
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()
