#!/usr/bin/env python3
"""Give every v4 table rows, through v4's own code, for the import check.

A plain irrd_load_database fills only rpsl_objects and database_status.
This drives v4's DatabaseHandler the way its update and mirror paths do,
so the journal, ROAs, suspension, protected names, NRTMv4 client and server
state, mirror errors and the web UI tables all hold realistic rows that
`irrd-ng import` must carry over exactly. Runs inside the v4 image.

    seed_v4_extras.py <irrd.yaml> <rpsl dump> <objects to take>

The config must define TEST (authoritative, keep_journal) and MIRROR
(non-authoritative) sources.
"""
import datetime
import sys
import uuid

from irrd.conf import config_init

config_init(sys.argv[1])

from irrd.rpsl.rpsl_objects import rpsl_object_from_text  # noqa: E402
from irrd.storage.database_handler import DatabaseHandler  # noqa: E402
from irrd.storage.models import (  # noqa: E402
    AuthApiToken,
    AuthMntner,
    AuthPermission,
    AuthUser,
    AuthWebAuthn,
    ChangeLog,
    JournalEntryOrigin,
    NRTM4ClientDatabaseStatus,
    NRTM4ServerDatabaseStatus,
    RPSLDatabaseObject,
    Setting,
)
from irrd.utils.text import split_paragraphs_rpsl  # noqa: E402

dump, limit = sys.argv[2], int(sys.argv[3])
UTC = datetime.timezone.utc


def objects(source):
    """The first `limit` parseable objects of the dump, moved to `source`."""
    out = []
    with open(dump, encoding="utf-8", errors="backslashreplace") as f:
        for para in split_paragraphs_rpsl(f):
            lines = [
                (f"source:         {source}" if ln.lower().startswith("source:") else ln)
                for ln in para.strip().splitlines()
            ]
            try:
                obj = rpsl_object_from_text("\n".join(lines) + "\n", strict_validation=False)
            except Exception:
                continue
            if obj.messages.errors():
                continue
            out.append(obj)
            if len(out) >= limit:
                break
    return out


dh = DatabaseHandler()

# Authoritative changes with a journal: creates, modifies, deletes (with
# protected names for mntner/person/role), in several transactions.
test_objs = objects("TEST")
for obj in test_objs:
    dh.upsert_rpsl_object(obj, origin=JournalEntryOrigin.auth_change)
dh.commit()
for obj in test_objs[::7]:
    dh.upsert_rpsl_object(obj, origin=JournalEntryOrigin.auth_change)
dh.commit()
deleted = 0
for obj in test_objs[3::11]:
    dh.delete_rpsl_object(rpsl_object=obj, origin=JournalEntryOrigin.auth_change, protect_rpsl_name=True)
    deleted += 1
dh.commit()

# A mirrored source with NRTM-style serials and every status field set.
mirror_objs = objects("MIRROR")
for serial, obj in enumerate(mirror_objs, start=5000):
    dh.upsert_rpsl_object(obj, origin=JournalEntryOrigin.mirror, source_serial=serial)
    dh.record_serial_seen("MIRROR", serial)
dh.record_serial_newest_mirror("MIRROR", 5000 + len(mirror_objs))
dh.record_serial_exported("MIRROR", 5000 + len(mirror_objs) - 1)
dh.record_mirror_error("MIRROR", "Parsing errors: ['Unrecognised attribute ünïcode'], original object text follows:\n...")
dh.record_nrtm4_client_status(
    "MIRROR",
    NRTM4ClientDatabaseStatus(
        session_id=uuid.UUID("5f8a3a2e-0c4b-4e8e-9d39-1d9b8a6f0c11"),
        version=42,
        current_key="-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n",
        next_key=None,
        previous_file_hashes={"https://example.net/nrtm/snapshot.1.json": ["ab12", "cd34"]},
    ),
)
dh.commit()
dh.record_nrtm4_server_status(
    "TEST",
    NRTM4ServerDatabaseStatus(
        session_id=uuid.UUID("0b7c9f1e-8a3d-4f2b-9c6e-2a1d3e4f5a6b"),
        version=7,
        last_update_notification_file_update=datetime.datetime(2026, 10, 30, 1, 2, 3, 0, tzinfo=UTC),
        last_snapshot_version=5,
        last_snapshot_global_serial=123,
        last_snapshot_filename="nrtm-snapshot.5.0b7c9f1e.json.gz",
        last_snapshot_timestamp=datetime.datetime(2026, 10, 30, 1, 0, 0, 999999, tzinfo=UTC),
        last_snapshot_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        previous_deltas=[
            {"version": 6, "filename": "nrtm-delta.6.json", "hash": "aa", "timestamp": 1793000000},
            {"version": 7, "filename": "nrtm-delta.7.json", "hash": "bb", "timestamp": 1793000100},
        ],
    ),
)
dh.commit()

# ROAs, v4 and v6, with and without a trust anchor.
dh.insert_roa_object(4, "192.0.2.0/24", 65000, 24, "Example TA")
dh.insert_roa_object(4, "198.51.100.0/22", 65001, 24, "Example TA")
dh.insert_roa_object(4, "10.0.0.0/8", 4200000000, 32, "SLURM file")
dh.insert_roa_object(6, "2001:db8::/32", 65000, 48, "Example TA")
dh.insert_roa_object(6, "2001:db8:1234::/48", 0, 48, "Example TA")
dh.commit()

# Suspend a few mirrored objects (moves them to rpsl_objects_suspended).
rows = list(
    dh.execute_statement(
        RPSLDatabaseObject.__table__.select()
        .where(RPSLDatabaseObject.__table__.c.source == "TEST")
        .order_by(RPSLDatabaseObject.__table__.c.rpsl_pk)
        .limit(3)
    )
)
for row in rows:
    dh.suspend_rpsl_object(row.pk)
dh.commit()

# Web UI tables, linked the way v4 links them. Foreign keys are plain
# pg.UUID columns in v4's models, which take strings.
mntner = next(
    dh.execute_statement(
        RPSLDatabaseObject.__table__.select()
        .where(RPSLDatabaseObject.__table__.c.object_class == "mntner")
        .order_by(RPSLDatabaseObject.__table__.c.rpsl_pk)
        .limit(1)
    )
)
user_pk, user2_pk = uuid.uuid4(), uuid.uuid4()
auth_mntner_pk, token_pk = uuid.uuid4(), uuid.uuid4()
ins = dh.execute_statement
ins(
    AuthUser.__table__.insert().values(
        pk=user_pk,
        email="alice@example.net",
        name="Alice Ünïcode",
        password="$2b$12$abcdefghijklmnopqrstuuJ0q2nE2jW7m7c2y8bS1x9QzJ3s7JbKe",
        totp_secret="JBSWY3DPEHPK3PXP",
        totp_last_used="123456",
        active=True,
        override=True,
    )
)
ins(
    AuthUser.__table__.insert().values(
        pk=user2_pk, email="bob@example.net", name="Bob", password="x", active=False, override=False
    )
)
ins(
    AuthMntner.__table__.insert().values(
        pk=auth_mntner_pk,
        rpsl_mntner_pk=mntner.rpsl_pk,
        rpsl_mntner_obj_id=str(mntner.pk),
        rpsl_mntner_source=mntner.source,
        migration_token=None,
    )
)
ins(AuthPermission.__table__.insert().values(user_id=str(user_pk), mntner_id=str(auth_mntner_pk), user_management=True))
ins(AuthPermission.__table__.insert().values(user_id=str(user2_pk), mntner_id=str(auth_mntner_pk), user_management=False))
ins(
    AuthApiToken.__table__.insert().values(
        pk=token_pk,
        name="automation",
        creator_id=str(user_pk),
        mntner_id=str(auth_mntner_pk),
        ip_restriction="192.0.2.0/24,2001:db8::/32",
        enabled_webapi=True,
        enabled_email=False,
    )
)
ins(
    AuthWebAuthn.__table__.insert().values(
        user_id=str(user_pk),
        name="yubikey",
        credential_id=b"\x00\x01\xfe\xff credential",
        credential_public_key=bytes(range(256)),
        credential_sign_count=17,
    )
)
ins(
    ChangeLog.__table__.insert().values(
        auth_by_user_id=str(user_pk),
        auth_by_user_email="alice@example.net",
        auth_through_mntner_id=str(auth_mntner_pk),
        auth_through_rpsl_mntner_pk=mntner.rpsl_pk,
        auth_by_rpsl_mntner_password=False,
        auth_by_rpsl_mntner_pgp_key=False,
        auth_by_override=None,
        from_ip="2001:db8::1",
        rpsl_target_request_type="MODIFY",
        rpsl_target_pk=mntner.rpsl_pk,
        rpsl_target_source=mntner.source,
        rpsl_target_object_class="mntner",
        rpsl_target_object_text_old=mntner.object_text,
        rpsl_target_object_text_new=mntner.object_text + "remarks:        changed\n",
    )
)
ins(
    ChangeLog.__table__.insert().values(
        auth_by_api_key_id=str(token_pk),
        auth_by_api_key_id_fixed=str(token_pk),
        auth_by_rpsl_mntner_password=True,
        auth_by_rpsl_mntner_pgp_key=False,
        auth_by_override=False,
        from_email="noc@example.net",
        from_ip="192.0.2.10",
        auth_change_descr="user bob@example.net added to mntner",
        auth_affected_user_id=str(user2_pk),
        auth_affected_mntner_id=str(auth_mntner_pk),
    )
)
ins(Setting.__table__.insert().values(name="secret_key", value="0123456789abcdef"))
dh.commit()
dh.close()
print(f"seeded: {len(test_objs)} TEST, {len(mirror_objs)} MIRROR, {deleted} deleted, {len(rows)} suspended")
