#!/usr/bin/env python3
"""Keep only the objects v4's irrd_load_database accepts.

v4's loader stops at the first object it rejects (parse error, wrong
source, unknown class), so most real dumps never load in full. This writes
the subset it would accept, judged by v4's own parser with the loader's
exact checks (irrd/mirroring/parsers.py, MirrorFileImportParserBase), so the
three-way check can also compare complete loads of real data. Runs inside
the v4 image.

    v4_clean_dump.py <out> <SOURCE> <dump[.gz]>...

Paragraphs are split as v4 splits them (comments dropped, line ends
normalised) and written back separated by one empty line. Paragraphs with
bytes that are not UTF-8 are dropped too: v4 reads dumps with
errors="backslashreplace", which the raw runs already cover.
"""
import gzip
import sys

from irrd.conf import config_init

config_init("/v4/irrd.yaml")

from irrd.rpsl.parser import UnknownRPSLObjectClassException  # noqa: E402
from irrd.rpsl.rpsl_objects import rpsl_object_from_text  # noqa: E402
from irrd.utils.text import split_paragraphs_rpsl  # noqa: E402

out_path, source, dumps = sys.argv[1], sys.argv[2], sys.argv[3:]
kept = dropped = 0
reasons = {}
with open(out_path, "w", encoding="utf-8", newline="\n") as out:
    for path in dumps:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="surrogateescape") as f:
            for para in split_paragraphs_rpsl(f):
                reason = None
                try:
                    para.encode("utf-8")
                except UnicodeEncodeError:
                    reason = "not utf-8"
                if reason is None:
                    try:
                        obj = rpsl_object_from_text(para.strip(), strict_validation=False)
                        if obj.messages.errors():
                            reason = "parse errors"
                        elif obj.source() != source:
                            reason = "wrong source"
                    except UnknownRPSLObjectClassException:
                        reason = "unknown class"
                if reason:
                    dropped += 1
                    reasons[reason] = reasons.get(reason, 0) + 1
                    continue
                out.write(para)
                out.write("\n")
                kept += 1
print(f"{source}: kept {kept}, dropped {dropped} {reasons}")
