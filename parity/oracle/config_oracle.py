"""Record IRRd v4's verdict on every irrd.yaml in a directory.

Runs inside the pinned v4 container (parity/oracle/run.sh config <dir>).
For each *.yaml file, in name order, writes one JSON line with the list of
errors v4's validator returns (empty when valid) and the exact message v4
would exit with at startup. irrd-ng's config crate is diffed against this.
"""

import json
import sys
from pathlib import Path

from irrd.conf import Configuration, ConfigurationError


def main(directory):
    for path in sorted(Path(directory).glob("*.yaml")):
        cfg = Configuration.__new__(Configuration)
        from irrd.conf.known_keys import KNOWN_CONFIG_KEYS, KNOWN_FLEXIBLE_KEYS, KNOWN_SOURCES_KEYS

        cfg.known_config_keys = KNOWN_CONFIG_KEYS
        cfg.known_sources_keys = KNOWN_SOURCES_KEYS
        cfg.known_flexible_keys = KNOWN_FLEXIBLE_KEYS
        cfg.user_config_path = str(path)
        errors = cfg._staging_reload_check(log_success=False)
        try:
            Configuration(str(path), commit=False)
            startup = None
        except ConfigurationError as e:
            startup = str(e)
        row = {"file": path.name, "errors": errors, "startup_error": startup}
        sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
