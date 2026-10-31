#!/usr/bin/env python3
"""Make broken NRTMv4 files for the overlay (run inside the v4 image).

    tamper.py expire-unf <unf> <out> <private-key-file> <hours>
        Re-sign the Update Notification File with its timestamp moved
        <hours> into the past.
    tamper.py break-file <in> <out>
        Copy a file with one byte changed, so its hash no longer matches.
"""
import datetime
import json
import sys

import pydantic.main  # noqa: F401  (v4's modules expect it loaded)


def expire_unf(src, out, keyfile, hours):
    from joserfc import jws

    from irrd.utils.crypto import eckey_from_str, jws_serialize

    with open(src) as f:
        token = f.read().strip()
    payload = jws.extract_compact(token.encode()).payload
    unf = json.loads(payload)
    when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=float(hours))
    unf["timestamp"] = when.isoformat().replace("+00:00", "Z")
    with open(keyfile) as f:
        key = eckey_from_str(f.read())
    with open(out, "w") as f:
        f.write(jws_serialize(json.dumps(unf), key))


def break_file(src, out):
    with open(src, "rb") as f:
        data = bytearray(f.read())
    data[len(data) // 2] ^= 0x01
    with open(out, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "expire-unf":
        expire_unf(*sys.argv[2:6])
    elif cmd == "break-file":
        break_file(*sys.argv[2:4])
    else:
        sys.exit(f"unknown command {cmd}")
