"""Record what IRRd v4 makes of every RPSL sample in irrd/utils/rpsl_samples.py.

v4's own tests parse these strings directly (not through the file splitter),
so this does the same, with the result shape of parity/oracle/rpsl_oracle.py.
One shared keyring, parsing strict then relaxed, in file order.

Runs inside the pinned v4 container (regen.sh).
"""

import importlib.util
import json
import sys

from irrd.conf import config_init

config_init("/etc/irrd/irrd.yaml")

spec = importlib.util.spec_from_file_location("rpsl_oracle", "/oracle/rpsl_oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

from irrd.utils import rpsl_samples  # noqa: E402

for name in vars(rpsl_samples):
    if not name.startswith("SAMPLE_"):
        continue
    text = getattr(rpsl_samples, name)
    if not isinstance(text, str) or ":" not in text:
        continue  # passwords used by the auth tests
    row = {
        "name": name,
        "text": text,
        "strict": oracle.parse(text, True),
        "relaxed": oracle.parse(text, False),
    }
    sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")
