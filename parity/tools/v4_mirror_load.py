#!/usr/bin/env python3
"""Load dumps into v4 the way a v4 mirror loads them. Runs inside the v4 container.

    v4_mirror_load.py <config.yaml> <SOURCE>=<serial>=<dump-path>[,<dump-path>...] ...

irrd_load_database stops at the first object it rejects, so most real dumps
never load with it. A v4 mirror instead runs RPSLMirrorFullImportRunner on
its import_source, which skips (and logs) what it rejects and keeps the
rest verbatim. That is how the data on a real non-authoritative mirror got
there, so it is what the whois suites should be served from. This points
import_source and import_serial_source of each source at local files, runs
v4's own full import runner once per source, and leaves the configuration
on disk untouched (the import keys exist only in a copy under /tmp).
"""
import sys

import yaml

cfg_path, specs = sys.argv[1], sys.argv[2:]
cfg = yaml.safe_load(open(cfg_path))
plan = []
for spec in specs:
    source, serial, paths = spec.split("=", 2)
    serial_file = f"/tmp/{source}.serial"
    with open(serial_file, "w") as f:
        f.write(f"{serial}\n")
    s = cfg["irrd"]["sources"].setdefault(source, {})
    s["import_source"] = [f"file://{p}" for p in paths.split(",")]
    s["import_serial_source"] = f"file://{serial_file}"
    plan.append(source)
tmp = "/tmp/irrd-mirror-load.yaml"
with open(tmp, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False)

from irrd.conf import config_init  # noqa: E402

config_init(tmp)

from irrd.mirroring.mirror_runners_import import RPSLMirrorFullImportRunner  # noqa: E402
from irrd.storage.database_handler import DatabaseHandler  # noqa: E402

for source in plan:
    dh = DatabaseHandler()
    RPSLMirrorFullImportRunner(source).run(dh, force_reload=True)
    dh.commit()
    dh.close()
    print(f"{source}: loaded", flush=True)
