#!/usr/bin/env python3
"""v4's side of the read-only status comparison (parity/status/tier2.sh).
Runs inside the v4 image.

    v4_dryrun.py CONFIG roa|scopefilter|routepref [ROA_FILE [SLURM_FILE]]

Runs v4's own validators on a read-only database connection and prints
what the job would change, in the same line format as
`irrd-ng run-job --dry-run`:

    pseudo  class  key  sha256(text)  scope filter status  ip_first  ip_last  prefix
    rpki|scopefilter|routepref  pk  new status  journal operation (add, delete, -)

The ROA import's pseudo-IRR objects come from ROADataImporter with a
stand-in for the database handler that only records them, so nothing is
written; the status changes come from BulkRouteROAValidator,
ScopeFilterValidator and the route preference validator over the real
data. The journal operation is decided with v4's own object_is_visible(),
as update_rpki_status() and friends decide it.
"""
import hashlib
import sys

cfg, job = sys.argv[1], sys.argv[2]

from irrd.conf import config_init  # noqa: E402

config_init(cfg)

from irrd.routepref.status import RoutePreferenceStatus  # noqa: E402
from irrd.rpki.status import RPKIStatus  # noqa: E402
from irrd.scopefilter.status import ScopeFilterStatus  # noqa: E402
from irrd.storage.database_handler import DatabaseHandler, object_is_visible  # noqa: E402

dh = DatabaseHandler(readonly=True)
out = sys.stdout


def op(before, now, adding):
    if adding and now and not before:
        return "add"
    if not adding and before and not now:
        return "delete"
    return "-"


if job == "roa":
    from irrd.rpki.importer import ROADataImporter
    from irrd.rpki.validators import BulkRouteROAValidator

    class Recorder:
        """Stands in for the DatabaseHandler while importing."""

        def insert_roa_object(self, **kwargs):
            pass

        def upsert_rpsl_object(self, obj, origin, rpsl_guaranteed_no_existing=False):
            text = obj.render_rpsl_text()
            out.write(
                "\t".join([
                    "pseudo", obj.rpsl_object_class, obj.pk(), hashlib.sha256(text.encode()).hexdigest(),
                    obj.scopefilter_status.name, str(obj.ip_first), str(obj.ip_last), obj.prefix_str,
                ]) + "\n"
            )

    slurm = open(sys.argv[4]).read() if len(sys.argv) > 4 else None
    importer = ROADataImporter(open(sys.argv[3]).read(), slurm, Recorder())
    valid, invalid, not_found = BulkRouteROAValidator(dh, importer.roa_objs).validate_all_routes()
    for objs, adding in ((valid, True), (not_found, True), (invalid, False)):
        for o in objs:
            before = object_is_visible(o["old_status"], o["scopefilter_status"], o["route_preference_status"])
            now = object_is_visible(o["rpki_status"], o["scopefilter_status"], o["route_preference_status"])
            out.write(f"rpki\t{o['pk']}\t{RPKIStatus(o['rpki_status']).name}\t{op(before, now, adding)}\n")
elif job == "scopefilter":
    from irrd.scopefilter.validators import ScopeFilterValidator

    in_scope, out_as, out_prefix = ScopeFilterValidator().validate_all_rpsl_objects(dh)
    for objs, adding in ((in_scope, True), (out_as, False), (out_prefix, False)):
        for o in objs:
            before = object_is_visible(o["rpki_status"], o["old_status"], o["route_preference_status"])
            now = object_is_visible(o["rpki_status"], o["scopefilter_status"], o["route_preference_status"])
            out.write(
                f"scopefilter\t{o['pk']}\t{ScopeFilterStatus(o['scopefilter_status']).name}\t{op(before, now, adding)}\n"
            )
elif job == "routepref":
    from irrd.conf import get_setting
    from irrd.routepref.routepref import build_validator, enrich_pks

    if any(s.get("route_object_preference") for s in get_setting("sources", {}).values()):
        validator = build_validator(dh)
        to_visible, to_suppressed = validator.validate_known_routes()
        visible = list(enrich_pks(dh, to_visible + validator.excluded_currently_suppressed))
        suppressed = list(enrich_pks(dh, to_suppressed))
        for objs, status, operation in ((visible, "visible", "add"), (suppressed, "suppressed", "delete")):
            for o in objs:
                shown = object_is_visible(rpki_status=o["rpki_status"], scopefilter_status=o["scopefilter_status"])
                out.write(f"routepref\t{o['pk']}\t{status}\t{operation if shown else '-'}\n")
else:
    sys.exit(__doc__)
dh.close()
