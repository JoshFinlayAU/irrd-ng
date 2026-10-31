#!/usr/bin/env python3
"""Split one round of upstream changes into update files with at most one
deletion each.

    split_deletes.py <old state> <new state> <out prefix>

irrd_update_database applies the deletions of one run in Python set order
(MirrorUpdateFileImportParser, `current_pks - file_pks`), which differs
from one v4 process to the next, so two upstreams fed the same file can
journal them in different orders (P-19). The serving differential needs
identical journals, so it applies a round as <prefix>.0 (every addition
and change, nothing deleted), then <prefix>.1, <prefix>.2, ... each
deleting one more object. Prints the number of files written.
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from data import read, write  # noqa: E402


def key(paragraph):
    return paragraph.split("\n", 1)[0].split(":", 1)[0].strip(), paragraph.split("\n", 1)[0].split(":", 1)[1].strip().upper()


def main():
    old, new, prefix = sys.argv[1:4]
    new_objs = read(new)
    new_keys = {key(p) for p in new_objs}
    deleted = [p for p in read(old) if key(p) not in new_keys]
    for i in range(len(deleted) + 1):
        write(f"{prefix}.{i}", new_objs + deleted[i:])
    print(len(deleted) + 1)


if __name__ == "__main__":
    main()
