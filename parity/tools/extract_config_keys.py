"""Tabulate every irrd.yaml key documented by IRRd v4, with its documented
default and when a change takes effect (SIGHUP or restart).

Reads docs/admins/configuration.rst from the pinned checkout. The docs are
the only place v4 records reload behaviour; known_keys.py is the authority on
which keys exist, so keys missing from either side are flagged.

Usage: python3 -I parity/tools/extract_config_keys.py vendor/irrd-v4 > parity/reference/v4-config-keys.tsv
"""

import re
import sys
from pathlib import Path

ENTRY = re.compile(r"^\* ((?:``[^`]+``(?:,| and| or)?\s*)+):", re.M)


def main(root):
    text = (Path(root) / "docs/admins/configuration.rst").read_text()
    starts = [(m.start(), re.findall(r"``([^`]+)``", m.group(1))) for m in ENTRY.finditer(text)]
    print("key\tdefault\ttakes_effect")
    for i, (pos, keys) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        body = " ".join(text[pos:end].split())
        default = re.search(r"\*\*Default\*\*:\s*(.*?)(?:\|br\||$)", body)
        effect = re.search(r"\*\*Change takes effect\*\*:\s*(.*?)(?:\|br\||$)", body)
        for key in keys:
            print(f"{key}\t{default.group(1).strip() if default else ''}\t{effect.group(1).strip() if effect else ''}")


if __name__ == "__main__":
    main(sys.argv[1])
