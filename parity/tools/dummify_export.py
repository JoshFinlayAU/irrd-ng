#!/usr/bin/env python3
"""Apply v4's auth hash dummification to an rpsl_objects export.

    dummify_export.py <export dir> <output dir> [source]

Writes <output dir>/rpsl_objects.jsonl and leaves the input alone.

A mirror only ever sees what its upstream publishes, and v4 publishes
mntner objects with their password hashes replaced
(irrd/utils/text.py, remove_auth_hashes). This turns an upstream's own
export into what its mirrors should hold, for comparing a mirror against
the upstream directly: object_text gets v4's substitution, and the
parsed "auth" values become what parsing that text gives.
"""
import json
import os
import re
import sys

# irrd/conf/__init__.py PASSWORD_HASHERS_ALL and PASSWORD_HASH_DUMMY_VALUE.
HASHERS = ["CRYPT-PW", "MD5-PW", "BCRYPT-PW"]
DUMMY = "DummyValue"
re_remove_passwords = re.compile(r"(%s)[^\n]+" % "|".join(HASHERS), flags=re.IGNORECASE)


def main():
    path = os.path.join(sys.argv[1], "rpsl_objects.jsonl")
    out_dir = sys.argv[2]
    source = sys.argv[3] if len(sys.argv) > 3 else None
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row.get("object_class") == "mntner" and (source is None or row.get("source") == source):
                row["object_text"] = re_remove_passwords.sub(
                    r"\1 %s  # Filtered for security" % DUMMY, row["object_text"]
                )
                auth = (row.get("parsed_data") or {}).get("auth")
                if auth:
                    row["parsed_data"]["auth"] = [re_remove_passwords.sub(r"\1 %s" % DUMMY, a) for a in auth]
            out.append(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rpsl_objects.jsonl"), "w", encoding="utf-8") as f:
        f.write("".join(l + "\n" for l in out))


if __name__ == "__main__":
    main()
