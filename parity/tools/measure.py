#!/usr/bin/env python3
"""Run a command and report its wall time and peak RSS as one JSON line.

    measure.py <out.json> -- <command> [args...]

Peak RSS is the largest resident set of any waited-for descendant
(getrusage RUSAGE_CHILDREN, ru_maxrss in KiB on Linux). The command's own
stdout and stderr pass through; its exit code is recorded and returned.
"""
import json
import resource
import subprocess
import sys
import time


def main():
    out, sep, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
    if sep != "--" or not cmd:
        sys.exit(__doc__)
    start = time.monotonic()
    rc = subprocess.call(cmd)
    wall = time.monotonic() - start
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    with open(out, "w") as f:
        json.dump(
            {
                "cmd": cmd,
                "exit": rc,
                "wall_s": round(wall, 3),
                "user_s": round(ru.ru_utime, 3),
                "sys_s": round(ru.ru_stime, 3),
                "maxrss_kib": ru.ru_maxrss,
            },
            f,
            sort_keys=True,
        )
        f.write("\n")
    sys.exit(rc)


if __name__ == "__main__":
    main()
