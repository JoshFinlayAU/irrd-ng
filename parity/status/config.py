#!/usr/bin/env python3
"""Write the configurations for one step of the status suite.

    config.py WORK 'STEP-JSON'

STEP-JSON sets what the step changes: "load" (the initial load), "roas" (file name under WORK),
"slurm" (file name or null), "scopefilter" ({"prefixes": [...], "asns":
[...]} or null), "scopefilter_excluded" (source names), "preferences"
({source: preference}). WORK/irrd-v4.yaml is rewritten in place (the v4
container bind-mounts that file, so its inode must not change) and
WORK/irrd-ng.yaml is the same configuration with host paths and ports.
"""
import json
import os
import sys

import yaml

work, step = sys.argv[1], json.loads(sys.argv[2])
smtp_port = os.environ.get("PARITY_SMTP_PORT", "9026")

# Authoritative sources keep a journal, so status changes are journalled,
# and their RPKI invalid routes get notification mails. v4 only allows a
# journal on authoritative sources and NRTM mirrors, and an authoritative
# source can not have an import_source, so the initial load ("load": true)
# runs with every source as a plain mirror.
names = ["STATUSAUTH", "RADB", "STATUSLOW", "ALTDB", "NTTCOM", "RIPE-NONAUTH", "APNIC", "ARIN",
         "AFRINIC", "LACNIC", "EDGE96"]
authoritative = [] if step.get("load") else ["STATUSAUTH", "RADB", "STATUSLOW"]
sources = {n: ({"authoritative": True, "keep_journal": True} if n in authoritative else {}) for n in names}
for name in step.get("scopefilter_excluded", []):
    sources[name]["scopefilter_excluded"] = True
for name, pref in step.get("preferences", {}).items():
    sources[name]["route_object_preference"] = pref

irrd = {
    "database_url": "postgresql://irrd:irrd@postgres/irrd",
    "redis_url": "redis://redis",
    "piddir": "/run/irrd",
    "server": {
        "http": {
            "interface": "0.0.0.0",
            "port": 8080,
            "url": "http://localhost:9080/",
            "status_access_list": "harness",
            "event_stream_access_list": "harness",
        },
        "whois": {"interface": "0.0.0.0", "port": 8043, "max_connections": 4},
    },
    "access_lists": {"harness": ["0.0.0.0/0", "::/0"]},
    "auth": {
        "gnupg_keyring": "/var/lib/irrd/gnupg",
        "override_password": "$1$J6KycItM$MbPaBU6iFSGFV299Rk7Di0",
        "set_creation": {"COMMON": {"prefix_required": True, "autnum_authentication": "opportunistic"}},
        "password_hashers": {"crypt-pw": "legacy", "md5-pw": "legacy", "bcrypt-pw": "enabled"},
    },
    "email": {"from": "irrd@parity.invalid", "smtp": "mailpit:1025", "footer": "status suite"},
    "rpki": {
        "roa_source": f"file:///tier1/{step.get('roas', 'roas1.json')}",
        # Past the Unix time: only the suite starts imports.
        "roa_import_timer": 99999999999,
        "notify_invalid_enabled": True,
    },
    "route_object_preference": {"update_timer": 99999999999},
    "log": {"level": "INFO"},
    "sources_default": list(sources),
    "sources": sources,
}
if step.get("slurm"):
    irrd["rpki"]["slurm_source"] = f"file:///tier1/{step['slurm']}"
if step.get("scopefilter"):
    irrd["scopefilter"] = step["scopefilter"]

text = yaml.safe_dump({"irrd": irrd}, sort_keys=False)
with open(os.path.join(work, "irrd-v4.yaml"), "w") as f:
    f.write(text)

ng = text.replace("file:///tier1/", f"file://{work}/")
ng = ng.replace("smtp: mailpit:1025", f"smtp: 127.0.0.1:{smtp_port}")
ng = ng.replace("piddir: /run/irrd", f"piddir: {work}/run")
ng = ng.replace("gnupg_keyring: /var/lib/irrd/gnupg", f"gnupg_keyring: {work}/gnupg")
ng = ng.replace("interface: 0.0.0.0\n      port: 8080", f"interface: 127.0.0.1\n      port: {os.environ.get('NG_HTTP_PORT', '8080')}")
ng = ng.replace("interface: 0.0.0.0\n      port: 8043", f"interface: 127.0.0.1\n      port: {os.environ.get('NG_WHOIS_PORT', '8043')}")
with open(os.path.join(work, "irrd-ng.yaml"), "w") as f:
    f.write(ng)
