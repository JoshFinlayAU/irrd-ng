#!/usr/bin/env python3
"""Split one round of upstream changes into update files that each change
at most one existing object.

    split_changes.py <old state> <new state> <out prefix>

irrd_update_database applies one file's deletions in Python set order and
its modifications in PostgreSQL heap order (MirrorUpdateFileImportParser),
neither of which v4 fixes, so two upstreams fed the same file can journal
them in different orders. irrd-ng uses key order for both (P-19). The
serving differential needs identical journals, so it applies a round as
<prefix>.0 (the old state plus every new object, in file order, which v4
keeps), then one file per modified object, then one per deleted object.
Prints the number of files written.
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from data import read, write  # noqa: E402


def key(paragraph):
    first = paragraph.split("\n", 1)[0]
    cls, pk = first.split(":", 1)
    return cls.strip(), pk.strip().upper()


def main():
    old_path, new_path, prefix = sys.argv[1:4]
    old, new = read(old_path), read(new_path)
    old_by_key = {key(p): p for p in old}
    new_keys = {key(p) for p in new}
    added = [p for p in new if key(p) not in old_by_key]
    modified = [p for p in new if key(p) in old_by_key and old_by_key[key(p)] != p]
    deleted = [k for k in old_by_key if k not in new_keys]

    state = {key(p): p for p in old}
    order = [key(p) for p in old]
    for p in added:
        state[key(p)] = p
        order.append(key(p))
    files = [[state[k] for k in order]]
    for p in modified:
        state[key(p)] = p
        files.append([state[k] for k in order])
    for k in deleted:
        order.remove(k)
        files.append([state[k] for k in order])
    for i, objs in enumerate(files):
        write(f"{prefix}.{i}", objs)
    print(len(files))


if __name__ == "__main__":
    main()
