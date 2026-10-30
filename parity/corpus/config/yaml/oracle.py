"""Record what PyYAML's safe_load makes of every *.yaml file in a directory.

Runs inside the pinned v4 container, so it uses the exact PyYAML v4 reads
irrd.yaml with. Writes one JSON line per file, in name order:
{file, result}, where result is "OK <repr of the document>",
"ERR <str(YAMLError)>" or "CRASH <ExceptionClass: message>". See ../README.md.
"""

import json
import sys
from pathlib import Path

import yaml


def main(directory):
    for path in sorted(Path(directory).glob("*.yaml")):
        try:
            with open(path) as fh:
                result = "OK " + repr(yaml.safe_load(fh))
        except yaml.YAMLError as e:
            result = "ERR " + str(e)
        except Exception as e:  # noqa: BLE001 - recording any failure is the point
            result = f"CRASH {type(e).__name__}: {e}"
        sys.stdout.write(json.dumps({"file": path.name, "result": result}, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
