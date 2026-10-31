#!/usr/bin/env python3
"""Compare two directories of exported files, byte for byte.

    compare_gzip.py <left dir> <right dir> [--label-left L] [--label-right R]

Every file in either directory must exist in both. Plain files (such as
CURRENTSERIAL) must be identical. Gzip files must be identical except for
two header fields that v4 itself never writes the same way twice:

  MTIME   int(time.time()) when gzip.open() started the file
  FNAME   the base name gzip.open() was given, minus ".gz": for exports a
          NamedTemporaryFile name ("tmp" and 8 random characters), for
          NRTMv4 files the file name with its random token

Both are checked for shape (an export FNAME must look like a temporary file
name), the rest of the header, the deflate stream and the trailer must
match exactly. Prints one line per file and exits 1 on any difference.
"""
import argparse
import os
import re
import sys

TMP_NAME = re.compile(rb"^tmp[a-z0-9_]{8}$")


def split_gzip(data):
    """(flags, xfl, os, fname, rest) of a gzip member, rest from FEXTRA on."""
    if data[:3] != b"\x1f\x8b\x08":
        raise ValueError("not a gzip file")
    flg, xfl, osb = data[3], data[8], data[9]
    pos = 10
    if flg & 0x04:
        xlen = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2 + xlen
    fname = b""
    if flg & 0x08:
        end = data.index(b"\x00", pos)
        fname = data[pos:end]
        pos = end + 1
    return flg, xfl, osb, fname, data[pos:]


def compare_file(name, a, b):
    if not name.endswith(".gz"):
        return "identical" if a == b else "DIFFERENT"
    try:
        ha, hb = split_gzip(a), split_gzip(b)
    except ValueError as e:
        return f"DIFFERENT ({e})"
    if ha[:3] != hb[:3]:
        return f"DIFFERENT header flags/xfl/os {ha[:3]} vs {hb[:3]}"
    for fname in (ha[3], hb[3]):
        stem = name[:-3].encode()
        if fname != stem and not TMP_NAME.match(fname):
            return f"DIFFERENT unexpected FNAME {fname!r}"
    if ha[4] != hb[4]:
        n = min(len(ha[4]), len(hb[4]))
        off = next((i for i in range(n) if ha[4][i] != hb[4][i]), n)
        return f"DIFFERENT stream at byte {off} ({len(ha[4])} vs {len(hb[4])} bytes)"
    return f"identical except MTIME and FNAME ({len(a)} bytes)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--label-left", default="left")
    ap.add_argument("--label-right", default="right")
    args = ap.parse_args()
    names = sorted(set(os.listdir(args.left)) | set(os.listdir(args.right)))
    failed = False
    for name in names:
        pa, pb = os.path.join(args.left, name), os.path.join(args.right, name)
        if not os.path.isfile(pa) or not os.path.isfile(pb):
            print(f"{name}: only in {args.label_left if os.path.isfile(pa) else args.label_right}")
            failed = True
            continue
        with open(pa, "rb") as f:
            a = f.read()
        with open(pb, "rb") as f:
            b = f.read()
        verdict = compare_file(name, a, b)
        print(f"{name}: {verdict}")
        failed |= verdict.startswith("DIFFERENT")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
