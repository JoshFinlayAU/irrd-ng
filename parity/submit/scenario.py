#!/usr/bin/env python3
"""Submission differential: drive IRRd v4 and irrd-ng through the same
submissions and record what each one answers, mails and stores.

    scenario.py WORK

Expects the compose project (compose.yaml) with WORK set and the irrd-ng
binary in WORK/bin. Starts the stack, seeds v4, imports v4's database into
irrd-ng (so both start from the same data), runs every step against both,
and writes WORK/out/{v4,ng}/NNN-name.txt (responses and mails) and
WORK/out/{v4,ng}-export (canonical exports). compare.py does the diffing.

All data here is synthetic: documentation prefixes and ASNs, example.com
addresses, and a PGP key generated for this run only.
"""
import base64
import json
import os
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "vendor", "irrd-v4"))
from irrd.utils import rpsl_samples as S  # noqa: E402  (plain strings only)

WORK = sys.argv[1]
OUT = os.path.join(WORK, "out")
SIDES = {
    "v4": {"http": 9780, "whois": 9743, "mail": 9725, "service": "v4"},
    "ng": {"http": 9781, "whois": 9744, "mail": 9726, "service": "ng"},
}
OVERRIDE = "override-password"
OVERRIDE_HASH = "$1$harness1$0DM.kwoE/9kYUSx27OhPP."
SEED_PW = "seed-password"
SEED_HASH = "$1$harness2$kGMJtGz/2zIPH/.XwCpTf0"
API_TOKEN = "11111111-2222-4333-8444-555555555555"
API_TOKEN_EMAIL = "66666666-7777-4888-8999-aaaaaaaaaaaa"
API_TOKEN_IP = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def dc(*args, stdin=None, check=True):
    env = dict(os.environ, WORK=WORK)
    p = subprocess.run(
        ["docker", "compose", "-f", os.path.join(HERE, "compose.yaml"), "--project-directory", HERE, *args],
        input=stdin,
        capture_output=True,
        env=env,
    )
    if check and p.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)} failed: {p.stderr.decode(errors='replace')}")
    return p


def psql(sql):
    return dc("exec", "-T", "postgres", "psql", "-U", "irrd", "-d", "irrd", "-v", "ON_ERROR_STOP=1", "-Atc", sql).stdout.decode()


# ---------------------------------------------------------------------------
# configuration and data
# ---------------------------------------------------------------------------

def config(side):
    smtp = "mailpit-v4:1025" if side == "v4" else "mailpit-ng:1025"
    return f"""irrd:
  database_url: postgresql://irrd:irrd@postgres/irrd
  redis_url: redis://redis
  piddir: /run/irrd
  server:
    http:
      interface: 0.0.0.0
      port: 8080
      url: http://localhost/
      workers: 1
    whois:
      interface: 0.0.0.0
      port: 8043
      max_connections: 4
  access_lists:
    all: [0.0.0.0/0, "::/0"]
  auth:
    gnupg_keyring: /var/lib/irrd/gnupg
    override_password: "{OVERRIDE_HASH}"
    set_creation:
      COMMON:
        prefix_required: true
        autnum_authentication: opportunistic
      as-set:
        autnum_authentication: required
      rtr-set:
        prefix_required: false
    password_hashers:
      crypt-pw: enabled
      md5-pw: enabled
      bcrypt-pw: enabled
  email:
    from: irrd@parity.invalid
    smtp: {smtp}
    footer: submit harness footer
  rpki:
    roa_source: file:///data/roas.json
    roa_import_timer: 99999999
    notify_invalid_enabled: false
  scopefilter:
    prefixes: [10.0.0.0/8]
    asns: [64496]
  log:
    level: INFO
  sources_default: [TEST]
  sources:
    TEST:
      authoritative: true
      keep_journal: true
      suspension_enabled: true
      nrtm_access_list: all
    FILTERED:
      authoritative: true
      keep_journal: true
      object_class_filter: [route, mntner, person]
    NONSTRICT:
      authoritative: true
      keep_journal: true
      authoritative_non_strict_mode_dangerous: true
    RETAIN:
      authoritative: true
      keep_journal: true
      authoritative_retain_last_modified: true
    MIRROR:
      keep_journal: false
"""


SEED_PERSON = """person:         Seed Person
address:        Seed street
phone:          +31 20 000 0000
e-mail:         seed@example.com
nic-hdl:        PERSON-SEED
mnt-by:         SEED-MNT
notify:         person-notify@example.com
source:         {source}
"""

SEED_MNTNER = """mntner:         SEED-MNT
descr:          Seed maintainer
admin-c:        PERSON-SEED
upd-to:         seed-upd-to@example.com
mnt-nfy:        seed-mnt-nfy@example.com
auth:           MD5-PW {hash}
mnt-by:         SEED-MNT
source:         {source}
"""


def seed_test(keycert, keyid):
    objs = [
        SEED_PERSON.format(source="TEST"),
        SEED_MNTNER.format(source="TEST", hash=SEED_HASH).replace(
            "mnt-by:         SEED-MNT", f"auth:           {keyid}\nmnt-by:         SEED-MNT"),
        f"""mntner:         OTHER-MNT
descr:          Second maintainer
admin-c:        PERSON-SEED
upd-to:         other-upd-to@example.com
mnt-nfy:        other-mnt-nfy@example.com
auth:           MD5-PW {SEED_HASH}
mnt-by:         OTHER-MNT
source:         TEST
""",
        f"""mntner:         API-MNT
descr:          Migrated maintainer with API keys
admin-c:        PERSON-SEED
upd-to:         api-upd-to@example.com
mnt-nfy:        api-mnt-nfy@example.com
auth:           IRRD-INTERNAL-AUTH
mnt-by:         API-MNT
source:         TEST
""",
        f"""mntner:         SUSP-MNT
descr:          Maintainer to be suspended
admin-c:        PERSON-SEED
upd-to:         susp-upd-to@example.com
auth:           MD5-PW {SEED_HASH}
mnt-by:         SUSP-MNT
source:         TEST
""",
        """person:         Suspended Person
address:        street
phone:          +31 20 000 0001
e-mail:         susp@example.com
nic-hdl:        PERSON-SUSP
mnt-by:         SUSP-MNT
source:         TEST
""",
        """route:          203.0.113.0/24
descr:          only maintained by SUSP-MNT
origin:         AS65510
mnt-by:         SUSP-MNT
source:         TEST
""",
        """route:          203.0.113.0/25
descr:          maintained by SUSP-MNT and SEED-MNT
origin:         AS65510
mnt-by:         SUSP-MNT
mnt-by:         SEED-MNT
source:         TEST
""",
        """inetnum:        198.51.100.0 - 198.51.100.255
netname:        SEED-NET
descr:          parent of route tests
country:        NL
admin-c:        PERSON-SEED
tech-c:         PERSON-SEED
status:         ASSIGNED PA
mnt-by:         OTHER-MNT
source:         TEST
""",
        """aut-num:        AS65500
as-name:        SEED-AS
descr:          seed aut-num
admin-c:        PERSON-SEED
tech-c:         PERSON-SEED
mnt-by:         OTHER-MNT
source:         TEST
""",
        """route:          192.0.2.128/25
descr:          maintained by API-MNT
origin:         AS65520
mnt-by:         API-MNT
source:         TEST
""",
        """as-set:         AS65500:AS-REFERENCED
descr:          referred to by others
members:        AS65500
mnt-by:         SEED-MNT
source:         TEST
""",
        keycert,
    ]
    return "\n".join(objs)


def roas():
    return {
        "roas": [
            {"prefix": "192.0.2.0/24", "asn": "AS65537", "maxLength": 24, "ta": "HARNESS"},
            {"prefix": "198.51.100.0/24", "asn": "AS65000", "maxLength": 24, "ta": "HARNESS"},
        ]
    }


# ---------------------------------------------------------------------------
# PGP: a key made for this run
# ---------------------------------------------------------------------------

GNUPGHOME = "/data/gnupg-harness"


def gpg(*args, stdin=None):
    p = dc("exec", "-T", "-e", f"GNUPGHOME={GNUPGHOME}", "v4", "gpg", "--batch", "--yes", *args, stdin=stdin)
    return p.stdout


def make_key():
    dc("exec", "-T", "v4", "sh", "-c", f"rm -rf {GNUPGHOME} && mkdir -m 700 {GNUPGHOME}")
    gpg("--passphrase", "", "--quick-gen-key", "Harness Test Key (test only) <harness-key@example.com>",
        "rsa2048", "sign", "never")
    out = gpg("--with-colons", "--fingerprint").decode()
    fpr = [line.split(":")[9] for line in out.splitlines() if line.startswith("fpr:")][0]
    armored = gpg("--armor", "--export", fpr).decode()
    lines = armored.strip().splitlines()
    certif = "certif:         " + lines[0] + "\n"
    for line in lines[1:]:
        certif += ("+\n" if not line.strip() else f"                {line}\n")
    groups = [fpr[i:i + 4] for i in range(0, 40, 4)]
    formatted = " ".join(groups[:5]) + "  " + " ".join(groups[5:])
    keycert = (
        f"key-cert:       PGPKEY-{fpr[-8:]}\nmethod:         PGP\n"
        "owner:          Harness Test Key (test only) <harness-key@example.com>\n"
        f"fingerpr:       {formatted}\n{certif}mnt-by:         SEED-MNT\nsource:         TEST\n"
    )
    return fpr, keycert


def clearsign(text):
    return gpg("--clearsign", "--digest-algo", "SHA256", stdin=text.encode()).decode()


def detach_sign(data):
    return gpg("--armor", "--detach-sign", "--textmode", "--digest-algo", "SHA256", stdin=data.encode()).decode()


# ---------------------------------------------------------------------------
# submissions
# ---------------------------------------------------------------------------

def email_base64(body, sender="Sasha <sasha@example.com>", subject="my subject", extra=""):
    head = textwrap.dedent(f"""\
        From submitter@example.com  Thu Jan  5 10:04:48 2018
        Message-ID: <1325754288.4989.6.camel@hostname>
        Subject: {subject}
        From: {sender}
        To: irrd@example.com
        Date: Thu, 05 Jan 2018 10:04:48 +0100
        {extra}Content-Transfer-Encoding: base64
        Content-Type: text/plain; charset=utf-8
        Mime-Version: 1.0

        """)
    return head + base64.encodebytes(body.encode()).decode()


def email_plain(body, sender="Sasha <sasha@example.com>", subject="plain subject", headers=""):
    return (
        "Message-ID: <plain-1@example.com>\n"
        f"Subject: {subject}\n"
        f"From: {sender}\n"
        "Date: Thu, 05 Jan 2018 10:04:48 +0100\n"
        f"{headers}"
        "\n" + body
    )


def submit_email(side, raw):
    svc = SIDES[side]["service"]
    if side == "v4":
        cmd = ["exec", "-T", svc, "irrd_submit_email", "--config", "/etc/irrd/irrd.yaml"]
    else:
        cmd = ["exec", "-T", svc, "/ng/irrd-ng", "irrd_submit_email", "--config", "/etc/irrd/irrd.yaml"]
    p = dc(*cmd, stdin=raw.encode() if isinstance(raw, str) else raw, check=False)
    return f"exit {p.returncode}\nstdout:\n{p.stdout.decode(errors='replace')}"


def http(side, method, path, body, headers=None):
    url = f"http://127.0.0.1:{SIDES[side]['http']}{path}"
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Host", "localhost")
    req.add_header("User-Agent", "irrd-submit-harness")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, ctype, out = r.status, r.headers.get("content-type"), r.read()
    except urllib.error.HTTPError as e:
        status, ctype, out = e.code, e.headers.get("content-type"), e.read()
    return f"status {status}\ncontent-type {ctype}\n{out.decode(errors='replace')}"


def tool(side, args, stdin=None):
    svc = SIDES[side]["service"]
    if side == "v4":
        cmd = ["exec", "-T", svc, *args]
    else:
        cmd = ["exec", "-T", svc, "/ng/irrd-ng", *args]
    p = dc(*cmd, stdin=stdin.encode() if stdin else None, check=False)
    err = p.stderr.decode(errors="replace")
    # Log lines differ in format between v4 and irrd-ng; keep what the
    # tool itself prints.
    err = "\n".join(line for line in err.splitlines() if not line[:4].isdigit())
    return f"exit {p.returncode}\nstdout:\n{p.stdout.decode(errors='replace')}\nstderr:\n{err}"


def mails(side):
    for attempt in range(5):
        try:
            return _mails(side)
        except (urllib.error.URLError, ConnectionError, OSError):
            if attempt == 4:
                raise
            time.sleep(2)


def _mails(side):
    port = SIDES[side]["mail"]
    base = f"http://127.0.0.1:{port}/api/v1"
    with urllib.request.urlopen(f"{base}/messages?limit=1000") as r:
        listing = json.load(r)
    out = []
    for m in listing.get("messages", []):
        with urllib.request.urlopen(f"{base}/message/{m['ID']}/raw") as r:
            out.append(r.read().decode(errors="replace"))
    req = urllib.request.Request(f"{base}/messages", method="DELETE")
    urllib.request.urlopen(req).read()
    return out


def record(n, name, results):
    for side, text in results.items():
        d = os.path.join(OUT, side)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{n:03d}-{name}.txt"), "w") as f:
            f.write(text)
        with open(os.path.join(d, f"{n:03d}-{name}.mails.json"), "w") as f:
            json.dump(mails(side), f, indent=1)


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

def wait_http(side, timeout=300):
    end = time.time() + timeout
    while time.time() < end:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{SIDES[side]['http']}/v1/whois/?q=!v")
            req.add_header("Host", "localhost")
            urllib.request.urlopen(req, timeout=5).read()
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"{side} did not come up")


def setup():
    for d in ["v4", "ng", "data", "out", "ng-store"]:
        os.makedirs(os.path.join(WORK, d), exist_ok=True)
        os.chmod(os.path.join(WORK, d), 0o777)
    for side in SIDES:
        with open(os.path.join(WORK, side, "irrd.yaml"), "w") as f:
            f.write(config(side))
    with open(os.path.join(WORK, "data", "roas.json"), "w") as f:
        json.dump(roas(), f)
    dc("down", "-v", "--remove-orphans", check=False)
    dc("up", "-d", "postgres", "redis", "mailpit-v4", "mailpit-ng", "v4")
    wait_http("v4")
    fpr, keycert = make_key()
    with open(os.path.join(WORK, "data", "seed-TEST.db"), "w") as f:
        f.write(seed_test(keycert, f"PGPKEY-{fpr[-8:]}"))
    for source, objs in [
        ("FILTERED", [SEED_PERSON.format(source="FILTERED"), SEED_MNTNER.format(source="FILTERED", hash=SEED_HASH)]),
        ("NONSTRICT", [SEED_PERSON.format(source="NONSTRICT"), SEED_MNTNER.format(source="NONSTRICT", hash=SEED_HASH)]),
        ("RETAIN", [SEED_PERSON.format(source="RETAIN"), SEED_MNTNER.format(source="RETAIN", hash=SEED_HASH)]),
    ]:
        with open(os.path.join(WORK, "data", f"seed-{source}.db"), "w") as f:
            f.write("\n".join(objs))
    for source in ["TEST", "FILTERED", "NONSTRICT", "RETAIN"]:
        p = dc("exec", "-T", "v4", "irrd_load_database", "--config", "/etc/irrd/irrd.yaml", "--source", source,
               f"/data/seed-{source}.db", check=False)
        if p.returncode:
            raise RuntimeError(p.stdout.decode() + p.stderr.decode())
    psql(f"""
INSERT INTO auth_user (pk, email, name, password, totp_secret, active, override, created, updated)
  VALUES ('a0000000-0000-4000-8000-000000000001', 'mfa-user@example.com', 'MFA User', 'x', 'TOTPSECRET', true, false,
          '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00'),
         ('a0000000-0000-4000-8000-000000000002', 'plain-user@example.com', 'Plain User', 'x', NULL, true, false,
          '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00');
INSERT INTO auth_webauthn (pk, user_id, name, credential_id, credential_public_key, credential_sign_count, created, last_used)
  VALUES ('b0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'harness key',
          '\\x0102', '\\x0304', 1, '2026-01-01 10:00:00+00', '2026-02-03 04:05:06+00');
INSERT INTO auth_mntner (pk, rpsl_mntner_pk, rpsl_mntner_obj_id, rpsl_mntner_source, migration_token, created, updated)
  SELECT 'c0000000-0000-4000-8000-000000000001', 'API-MNT', pk, 'TEST', NULL, '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00'
  FROM rpsl_objects WHERE rpsl_pk = 'API-MNT' AND source = 'TEST' AND object_class = 'mntner';
INSERT INTO auth_api_token (pk, token, name, creator_id, mntner_id, ip_restriction, enabled_webapi, enabled_email, created, updated)
  VALUES ('d0000000-0000-4000-8000-000000000001', '{API_TOKEN}', 'web', 'a0000000-0000-4000-8000-000000000002',
          'c0000000-0000-4000-8000-000000000001', NULL, true, false, '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00'),
         ('d0000000-0000-4000-8000-000000000002', '{API_TOKEN_EMAIL}', 'mail', 'a0000000-0000-4000-8000-000000000002',
          'c0000000-0000-4000-8000-000000000001', NULL, false, true, '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00'),
         ('d0000000-0000-4000-8000-000000000003', '{API_TOKEN_IP}', 'ip', 'a0000000-0000-4000-8000-000000000002',
          'c0000000-0000-4000-8000-000000000001', '192.0.2.0/24', true, true, '2026-01-01 10:00:00+00', '2026-01-01 10:00:00+00');
""")
    # The ROA import and the scope filter run once at v4's start.
    end = time.time() + 120
    while time.time() < end and psql("SELECT count(*) FROM roa_object").strip() in ("", "0"):
        time.sleep(1)
    time.sleep(5)
    p = dc("run", "--rm", "--no-deps", "ng", "import", "--from-postgres",
           "postgresql://irrd:irrd@postgres/irrd?sslmode=disable", check=False)
    if p.returncode:
        raise RuntimeError("import failed: " + p.stdout.decode() + p.stderr.decode())
    dc("up", "-d", "ng")
    wait_http("ng")
    time.sleep(5)
    for side in SIDES:
        mails(side)
    return fpr, keycert


# ---------------------------------------------------------------------------
# the steps
# ---------------------------------------------------------------------------

def steps(fpr, keycert):
    keyid = f"PGPKEY-{fpr[-8:]}"
    mntner_clean = S.SAMPLE_MNTNER.replace("mnt-by:         OTHER1-MNT,OTHER2-MNT\n", "")
    large = "\n\n".join([
        S.SAMPLE_AS_BLOCK, S.SAMPLE_AS_SET, S.SAMPLE_AUT_NUM,
        S.SAMPLE_AUT_NUM.replace("aut-num:        as065537", "aut-num: as65538"),
        S.SAMPLE_DOMAIN, S.SAMPLE_FILTER_SET, S.SAMPLE_INET_RTR, S.SAMPLE_INET6NUM, S.SAMPLE_INETNUM,
        S.SAMPLE_PEERING_SET, S.SAMPLE_PERSON.replace("PERSON-TEST", "DUMY2-TEST"), S.SAMPLE_ROLE,
        S.SAMPLE_ROUTE, S.SAMPLE_ROUTE_SET, S.SAMPLE_ROUTE6, S.SAMPLE_RTR_SET,
    ])
    seed_person_modified = SEED_PERSON.format(source="TEST").replace("Seed street", "New street")
    yield "email-mntner-broken-refs", "email", email_base64(S.SAMPLE_MNTNER + f"\n\noverride: {OVERRIDE}")
    yield "email-mntner-no-override", "email", email_base64(mntner_clean + "\n\npassword: md5-password")
    yield "email-mntner-person-override", "email", email_base64(
        mntner_clean + "\n\n" + S.SAMPLE_PERSON + f"\n\noverride: {OVERRIDE}")
    yield "email-large-update", "email", email_base64(large + "\n\npassword: md5-password")
    yield "email-identical", "email", email_base64(S.SAMPLE_PERSON + "\npassword: md5-password")
    yield "email-person-modify", "email", email_base64(
        S.SAMPLE_PERSON.replace("Test person", "Changed person") + "\npassword: crypt-password")
    yield "email-auth-failure", "email", email_base64(S.SAMPLE_PERSON + "\npassword: invalid\noverride: invalid\n")
    yield "email-delete-referenced", "email", email_base64(S.SAMPLE_PERSON + "password: md5-password\ndelete: delete\n")
    yield "email-syntax-errors", "email", email_base64("\n\n".join([
        S.SAMPLE_UNKNOWN_CLASS, S.SAMPLE_MALFORMED_PK, S.SAMPLE_MISSING_MANDATORY_ATTRIBUTE,
        S.SAMPLE_UNKNOWN_ATTRIBUTE, S.SAMPLE_MALFORMED_SOURCE, S.SAMPLE_LINE_NEITHER_CONTINUATION_NOR_ATTR,
    ]) + "\npassword: md5-password")
    yield "email-non-authoritative", "email", email_base64(
        S.SAMPLE_ROUTE.replace("source:         TEST", "source:         MIRROR") + "\npassword: x")
    yield "email-object-class-filter", "email", email_base64(
        S.SAMPLE_AUT_NUM.replace("source:         TEST", "source:         FILTERED") + "\npassword: x")
    yield "email-plain-seed-modify", "email", email_plain(seed_person_modified + f"\npassword: {SEED_PW}\n")
    yield "email-seed-modify-wrong-password", "email", email_plain(
        seed_person_modified.replace("New street", "Other street") + "\npassword: wrong\n")
    yield "email-pgp-keycert-unloaded", "email", email_plain(clearsign(
        seed_person_modified.replace("New street", "PGP street (before load)")))
    yield "tool-load-pgp-keys", "tool", ["irrd_load_pgp_keys", "--config", "/etc/irrd/irrd.yaml", "TEST"]
    yield "email-pgp-inline", "email", email_plain(clearsign(
        seed_person_modified.replace("New street", "PGP street")))
    body = seed_person_modified.replace("New street", "PGP MIME street")
    part = f"Content-Transfer-Encoding: 7bit\nContent-Type: text/plain;\n\tcharset=us-ascii\n\n{body}"
    sig = detach_sign(part)
    mime = (
        "Message-ID: <pgpmime@example.com>\nSubject: pgp mime\nFrom: Sasha <sasha@example.com>\n"
        "Date: Thu, 05 Jan 2018 10:04:48 +0100\nMime-Version: 1.0\n"
        'Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature";\n'
        ' boundary="HARNESS-BOUNDARY"\n\nThis is an OpenPGP/MIME signed message.\n'
        f"--HARNESS-BOUNDARY\n{part}\n--HARNESS-BOUNDARY\n"
        "Content-Type: application/pgp-signature; name=signature.asc\n\n"
        f"{sig}\n--HARNESS-BOUNDARY--\n"
    )
    yield "email-pgp-mime", "email", mime
    yield "email-pgp-mime-tampered", "email", mime.replace("PGP MIME street", "Tampered street")
    yield "email-html-only", "email", (
        "Message-ID: <html@example.com>\nSubject: html\nFrom: sasha@example.com\nMime-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="B"\n\n--B\nContent-Type: text/html\n\n<p>x</p>\n--B--\n')
    yield "email-no-from", "email", "Subject: nofrom\n\nperson: x\n"
    yield "email-two-from", "email", email_plain(S.SAMPLE_PERSON, sender="a@example.com, b@example.com")
    yield "email-quoted-printable", "email", email_plain(
        seed_person_modified.replace("New street", "Stra=C3=9Fe") + f"\npassword: {SEED_PW}\n",
        headers="Content-Transfer-Encoding: quoted-printable\nContent-Type: text/plain; charset=utf-8\n")
    yield "email-latin1", "email", (
        "Message-ID: <l1@example.com>\nSubject: latin1\nFrom: sasha@example.com\n"
        "Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\n"
    ).encode() + seed_person_modified.replace("New street", "Straße 2").encode("latin-1") + f"\npassword: {SEED_PW}\n".encode()
    yield "email-dummy-hash-mntner", "email", email_base64(
        mntner_clean.replace("unįcöde tæst 🌈🦄", "dummy hashes").replace(
            "auth:           CRYPT-Pw LEuuhsBJNFV0Q  # crypt-password\n", "auth:           CRYPT-PW DummyValue\n").replace(
            "auth:           MD5-pw $1$fgW84Y9r$kKEn9MUq8PChNKpQhO6BM.  # md5-password\n", "auth:           MD5-PW DummyValue\n").replace(
            "auth:           bcrypt-pw $2b$12$RMrlONJ0tasnpo.zHDF.yuYm/Gb1ARmIjP097ZoIWBn9YLIM2ao5W # bcrypt-password\n",
            "auth:           BCRYPT-PW DummyValue\n") + "\npassword: md5-password\n")
    yield "email-mntner-new-password", "email", email_base64(
        mntner_clean.replace("unįcöde tæst 🌈🦄", "after dummy") + "\npassword: md5-password\n")
    yield "email-suspension-meta", "email", email_plain(
        f"mntner: OTHER-MNT\nsource: TEST\nsuspension: suspend\n\noverride: wrong\n")
    # HTTP
    yield "http-create-route-parent-fail", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 198.51.100.0/24\norigin: AS65000\nmnt-by: SEED-MNT\nsource: TEST\n"}],
        "passwords": [SEED_PW]})
    yield "http-create-route-parent-ok", "http", ("POST", "/v1/submit/", {
        "objects": [{"attributes": [
            {"name": "route", "value": "198.51.100.0/24"}, {"name": "descr", "value": ["line one", "line two"]},
            {"name": "origin", "value": "AS65000"}, {"name": "mnt-by", "value": "SEED-MNT"},
            {"name": "source", "value": "TEST"}]}],
        "passwords": [SEED_PW, SEED_PW]}, {"X-irrd-metadata": json.dumps({"source": "harness", "n": 1})})
    yield "http-route-rpki-invalid", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 198.51.100.0/25\norigin: AS65999\nmnt-by: SEED-MNT\nsource: TEST\n"}],
        "passwords": [SEED_PW], "override": OVERRIDE})
    yield "http-route-blocklist", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 0.0.0.0/0\norigin: AS65000\nmnt-by: SEED-MNT\nsource: TEST\n"}],
        "passwords": [SEED_PW]})
    yield "http-route-out-of-scope", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 10.1.0.0/16\norigin: AS65000\nmnt-by: SEED-MNT\nsource: TEST\n"},
                    {"object_text": "aut-num: AS64496\nas-name: SCOPE\nmnt-by: SEED-MNT\nadmin-c: PERSON-SEED\ntech-c: PERSON-SEED\nsource: TEST\n"}],
        "passwords": [SEED_PW]})
    yield "http-as-set-autnum-required", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "as-set: AS65501:AS-NOAUTNUM\nmnt-by: SEED-MNT\nsource: TEST\n"},
                    {"object_text": "as-set: AS65500:AS-WITHAUTNUM\nmnt-by: SEED-MNT\nsource: TEST\n"},
                    {"object_text": "as-set: AS-NOTHIERARCHICAL\nmnt-by: SEED-MNT\nsource: TEST\n"},
                    {"object_text": "rtr-set: RTRS-FLAT\nmnt-by: SEED-MNT\nsource: TEST\n"}],
        "passwords": [SEED_PW]})
    yield "http-as-set-with-parent-auth", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "as-set: AS65500:AS-WITHAUTNUM\nmnt-by: SEED-MNT\nsource: TEST\n"}],
        "passwords": [SEED_PW, "seed-password"]})
    yield "http-api-key", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 192.0.2.128/25\ndescr: changed by API key\norigin: AS65520\nmnt-by: API-MNT\nsource: TEST\n"}],
        "api_keys": [API_TOKEN, "not-a-uuid"]})
    yield "http-api-key-email-only", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 192.0.2.128/25\ndescr: email token over http\norigin: AS65520\nmnt-by: API-MNT\nsource: TEST\n"}],
        "api_keys": [API_TOKEN_EMAIL]})
    yield "http-api-key-ip-restricted", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "route: 192.0.2.128/25\ndescr: ip restricted\norigin: AS65520\nmnt-by: API-MNT\nsource: TEST\n"}],
        "api_keys": [API_TOKEN_IP.upper()]})
    yield "email-api-key", "email", email_plain(
        "route: 192.0.2.128/25\ndescr: changed by mail API key\norigin: AS65520\nmnt-by: API-MNT\nsource: TEST\n"
        f"\napi-key: {API_TOKEN_EMAIL}\n")
    yield "http-delete-person-protected", "http", ("DELETE", "/v1/submit/", {
        "objects": [{"object_text": "person: DUMY2 person\nnic-hdl: DUMY2-TEST\nmnt-by: TEST-MNT\nsource: TEST\n"}],
        "override": OVERRIDE, "delete_reason": "harness"})
    yield "http-recreate-protected", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": S.SAMPLE_PERSON.replace("PERSON-TEST", "DUMY2-TEST")}],
        "passwords": ["md5-password"]})
    yield "http-recreate-protected-override", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": S.SAMPLE_PERSON.replace("PERSON-TEST", "DUMY2-TEST")}],
        "override": OVERRIDE})
    yield "http-delete-empty-reason", "http", ("DELETE", "/v1/submit/", {
        "objects": [{"object_text": S.SAMPLE_RTR_SET}], "passwords": ["md5-password"], "delete_reason": ""})
    yield "http-delete-reference-chain", "http", ("DELETE", "/v1/submit/", {
        "objects": [{"object_text": S.SAMPLE_ROUTE_SET}, {"object_text": S.SAMPLE_AS_SET}],
        "passwords": ["md5-password"]})
    yield "http-nonstrict", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": "person: NS Person\nnic-hdl: PERSON-NS\nmnt-by: SEED-MNT\nunknown-attr: x\nadmin-c: NOSUCH\nsource: NONSTRICT\n"}],
        "passwords": [SEED_PW]})
    yield "http-retain-last-modified", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": SEED_PERSON.format(source="RETAIN").replace("Seed street", "Retained") +
                     "last-modified:  2020-01-01T00:00:00Z\n"}],
        "passwords": [SEED_PW]})
    yield "http-too-many-passwords", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": seed_person_modified}], "passwords": [f"p{i}" for i in range(21)]})
    yield "http-bad-json", "http", ("POST", "/v1/submit/", b'{"objects": [')
    yield "http-pydantic-errors", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": 5}, {}, {"attributes": [{"name": "x", "value": ["a", 2]}]}],
        "passwords": "x", "override": 3})
    yield "http-objects-not-dicts", "http", ("POST", "/v1/submit/", {"objects": [1]})
    yield "http-get-submit", "http", ("GET", "/v1/submit/", None)
    yield "http-no-slash", "http", ("POST", "/v1/submit", {"objects": []})
    yield "http-empty-objects", "http", ("POST", "/v1/submit/", {"objects": []})
    # Suspension
    yield "http-suspend-bad-override", "http", ("POST", "/v1/suspension/", {
        "objects": [{"mntner": "SUSP-MNT", "source": "TEST", "request_type": "suspend"}], "override": "wrong"})
    yield "http-suspend", "http", ("POST", "/v1/suspension/", {
        "objects": [{"mntner": "SUSP-MNT", "source": "TEST", "request_type": "suspend"},
                    {"mntner": "NOSUCH-MNT", "source": "TEST", "request_type": "suspend"},
                    {"mntner": "SEED-MNT", "source": "FILTERED", "request_type": "suspend"}],
        "override": OVERRIDE})
    yield "http-create-suspended-mntner", "http", ("POST", "/v1/submit/", {
        "objects": [{"object_text": SEED_MNTNER.format(source="TEST", hash=SEED_HASH).replace("SEED-MNT", "SUSP-MNT")}],
        "override": OVERRIDE})
    yield "http-reactivate", "http", ("POST", "/v1/suspension/", {
        "objects": [{"mntner": "SUSP-MNT", "source": "TEST", "request_type": "reactivate"},
                    {"mntner": "SUSP-MNT", "source": "TEST", "request_type": "reactivate"}],
        "override": OVERRIDE})
    yield "http-suspension-bad-enum", "http", ("POST", "/v1/suspension/", {
        "objects": [{"mntner": "SUSP-MNT", "source": "TEST", "request_type": "pause"}]})
    yield "email-final-deletes", "email", email_base64(
        f"{S.SAMPLE_PERSON}delete: delete\n\n{mntner_clean}delete: delete\npassword: crypt-password\n")
    # irr_rpsl_submit, each against its own server
    url = ["-u", "http://localhost:8080/v1/submit/"]
    # v4's irr_rpsl_submit raises before sending whenever the input has a
    # password: line; overrides go through.
    yield "rpsl-submit-password", "tool-stdin", (["irr_rpsl_submit", *url], seed_person_modified.replace(
        "New street", "Submitted by CLI") + f"\npassword: {SEED_PW}\n")
    yield "rpsl-submit-text", "tool-stdin", (["irr_rpsl_submit", *url], seed_person_modified.replace(
        "New street", "Submitted by CLI") + f"\noverride: {OVERRIDE}\n")
    yield "rpsl-submit-json-failure", "tool-stdin", (["irr_rpsl_submit", "-j", *url, "-m", "a=b,c=d=e"],
        seed_person_modified.replace("New street", "Unauthenticated"))
    yield "rpsl-submit-host", "tool-stdin", (["irr_rpsl_submit", "-h", "localhost", "-p", "8080", "-t"],
        S.SAMPLE_ROUTE6 + f"\noverride: {OVERRIDE}\n")
    yield "rpsl-submit-not-all-deletes", "tool-stdin", (["irr_rpsl_submit", *url],
        S.SAMPLE_ROUTE6 + "delete: x\n\n" + S.SAMPLE_ROUTE + f"\noverride: {OVERRIDE}\n")
    yield "rpsl-submit-override-twice", "tool-stdin", (["irr_rpsl_submit", *url],
        S.SAMPLE_ROUTE6 + "override: a\n\n" + S.SAMPLE_ROUTE + "override: b\n")
    yield "rpsl-submit-delete", "tool-stdin", (["irr_rpsl_submit", *url],
        S.SAMPLE_ROUTE6 + f"delete: cleanup\noverride: {OVERRIDE}\n")
    yield "rpsl-submit-empty", "tool-stdin", (["irr_rpsl_submit", *url], "\n\n")
    yield "rpsl-submit-only-meta", "tool-stdin", (["irr_rpsl_submit", *url], "password: x\n")
    yield "rpsl-submit-refused", "tool-stdin", (["irr_rpsl_submit", "-u", "http://127.0.0.1:1/v1/submit/"], "person: x\n")
    yield "rpsl-submit-redirect", "tool-stdin", (["irr_rpsl_submit", "-u", "http://localhost:8080/v1/submit"], "person: x\n")
    yield "rpsl-submit-args", "tool", ["irr_rpsl_submit", "-h", "a", "-u", "b"]
    # Tools
    yield "tool-irrdctl-mfa-clear-nouser", "tool", ["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-mfa-clear", "nobody@example.com"]
    yield "tool-irrdctl-override-nomfa", "tool", ["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-change-override", "plain-user@example.com"]
    yield "tool-irrdctl-override-enable", "tool-stdin", (["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-change-override", "mfa-user@example.com"], "y\n")
    yield "tool-irrdctl-override-again", "tool", ["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-change-override", "--enable", "mfa-user@example.com"]
    yield "tool-irrdctl-override-disable", "tool", ["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-change-override", "mfa-user@example.com", "--disable"]
    yield "tool-irrdctl-mfa-clear-abort", "tool-stdin", (["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-mfa-clear", "mfa-user@example.com"], "n\n")
    yield "tool-irrdctl-mfa-clear", "tool-stdin", (["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-mfa-clear", "mfa-user@example.com"], "y\n")
    yield "tool-irrdctl-mfa-clear-again", "tool", ["irrdctl", "--config", "/etc/irrd/irrd.yaml", "user-mfa-clear", "mfa-user@example.com"]
    yield "tool-set-last-modified", "tool", ["irrd_set_last_modified_auth", "--config", "/etc/irrd/irrd.yaml"]


def run_steps(fpr, keycert):
    n = 0
    for name, kind, arg in steps(fpr, keycert):
        n += 1
        results = {}
        for side in SIDES:
            if kind == "email":
                results[side] = submit_email(side, arg)
            elif kind == "http":
                method, path, body, *rest = arg
                results[side] = http(side, method, path, body, rest[0] if rest else None)
            elif kind == "tool":
                results[side] = tool(side, arg)
            elif kind == "tool-stdin":
                results[side] = tool(side, arg[0], arg[1])
        record(n, name, results)
        log(f"step {n} {name}")


def whois_query(port, q):
    import socket
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall(q.encode() + b"\n")
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return data


def export():
    dc("exec", "-T", "v4", "sh", "-c", "rm -rf /out/v4-export && /opt/irrd/bin/python /tools/export_v4.py "
       "'postgresql://irrd:irrd@postgres/irrd' /out/v4-export")
    dc("exec", "-T", "ng", "sh", "-c", "rm -rf /out/ng-export && mkdir /out/ng-export && /ng/irrd-ng export-jsonl "
       "--config /etc/irrd/irrd.yaml --table all --output-dir /out/ng-export")
    for side in SIDES:
        whois = SIDES[side]["whois"]
        out = whois_query(whois, "-g TEST:3:1-LAST")
        with open(os.path.join(OUT, f"{side}-nrtm.txt"), "wb") as f:
            f.write(out)


def main():
    if os.path.exists(OUT):
        subprocess.run(["docker", "run", "--rm", "-v", f"{OUT}:/o", "alpine", "sh", "-c", "rm -rf /o/*"], check=True)
    fpr, keycert = setup()
    log(f"stack up, key {fpr}")
    run_steps(fpr, keycert)
    export()
    log("done")


if __name__ == "__main__":
    main()
