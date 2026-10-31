#!/usr/bin/env python3
"""Split a (gzipped) RPSL dump into chunks of whole paragraphs.

Chunks are cut only at truly empty lines (after removing \\r and \\n), the
one place v4's split_paragraphs_rpsl ends a paragraph, so every chunk splits
into exactly the paragraphs the whole file would. Bytes are kept verbatim.

    split_dump.py <dump[.gz]> <outdir> <prefix> [paragraphs-per-chunk]
"""
import gzip
import os
import sys


def main():
    src, outdir, prefix = sys.argv[1:4]
    per_chunk = int(sys.argv[4]) if len(sys.argv) > 4 else 100_000
    opener = gzip.open if src.endswith(".gz") else open
    os.makedirs(outdir, exist_ok=True)
    n_chunk, n_para, in_para, out = 0, 0, False, None
    with opener(src, "rb") as f:
        for line in f:
            empty = line.rstrip(b"\r\n") == b""
            if empty and in_para:
                n_para += 1
                in_para = False
            elif not empty:
                in_para = True
            if out is None or (empty and n_para >= per_chunk):
                if out:
                    out.close()
                n_chunk += 1
                n_para = 0
                out = open(os.path.join(outdir, f"{prefix}-{n_chunk:03d}.db"), "wb")
                if empty:
                    continue
            out.write(line)
    if out:
        out.close()
    print(f"{src}: {n_chunk} chunks")


if __name__ == "__main__":
    main()
