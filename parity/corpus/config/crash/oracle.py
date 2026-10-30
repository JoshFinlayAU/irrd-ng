"""Record how IRRd v4 fails on configurations it crashes on.

The configuration oracle (parity/oracle/config_oracle.py) records v4's error
list, but some configurations make v4 raise an exception instead of reporting
an error, which would also stop that oracle. This runs the same check inside
the pinned v4 container and records the exception for every *.yaml in a
directory, in name order, as JSON lines: {file, errors, exception}, where
exception is "ExceptionClass: message" or null. See ../README.md.
"""

import json
import sys
from pathlib import Path

from irrd.conf import Configuration


def main(directory):
    from irrd.conf.known_keys import KNOWN_CONFIG_KEYS, KNOWN_FLEXIBLE_KEYS, KNOWN_SOURCES_KEYS

    for path in sorted(Path(directory).glob("*.yaml")):
        cfg = Configuration.__new__(Configuration)
        cfg.known_config_keys = KNOWN_CONFIG_KEYS
        cfg.known_sources_keys = KNOWN_SOURCES_KEYS
        cfg.known_flexible_keys = KNOWN_FLEXIBLE_KEYS
        cfg.user_config_path = str(path)
        try:
            errors = cfg._staging_reload_check(log_success=False)
            exception = None
        except Exception as e:  # noqa: BLE001 - recording any crash is the point
            errors = None
            exception = f"{type(e).__name__}: {e}"
        row = {"file": path.name, "errors": errors, "exception": exception}
        sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
