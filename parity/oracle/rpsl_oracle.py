"""Record exactly what IRRd v4 makes of every RPSL paragraph in a file.

Runs inside the pinned v4 container (parity/oracle/run.sh). Reads the input
the way v4's file importers do (UTF-8 with backslashreplace, then
split_paragraphs_rpsl) and writes one JSON line per paragraph with the
paragraph as v4 saw it and the parse result in strict and non-strict mode.
irrd-ng's rpsl crate is diffed against this output field by field.

Usage: python rpsl_oracle.py <input.db> > out.jsonl
"""

import json
import sys

from irrd.conf import config_init
from irrd.rpsl.rpsl_objects import UnknownRPSLObjectClassException, rpsl_object_from_text
from irrd.utils.text import split_paragraphs_rpsl


def plain(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        items = [plain(v) for v in value]
        return sorted(items, key=json.dumps) if isinstance(value, set) else items
    return str(value)


def parse(text, strict):
    try:
        obj = rpsl_object_from_text(text.strip(), strict_validation=strict)
    except UnknownRPSLObjectClassException as e:
        return {"unknown_class": e.rpsl_object_class, "error": str(e)}
    result = {
        "class": obj.rpsl_object_class,
        "messages": [list(m) for m in obj.messages._messages],
    }
    if obj.messages.errors():
        return result
    result.update(
        pk=obj.pk(),
        source=obj.source(),
        parsed_data=plain(obj.parsed_data),
        rendered=obj.render_rpsl_text(),
        ip_first=plain(obj.ip_first),
        ip_last=plain(obj.ip_last),
        ip_version=obj.ip_version(),
        prefix=plain(obj.prefix),
        prefix_length=obj.prefix_length,
        asn_first=obj.asn_first,
        asn_last=obj.asn_last,
        referred_strong_objects=plain(obj.referred_strong_objects()),
        references_strong_inbound=plain(obj.references_strong_inbound()),
    )
    return result


def main(path):
    config_init("/etc/irrd/irrd.yaml")
    with open(path, encoding="utf-8", errors="backslashreplace") as f:
        for i, paragraph in enumerate(split_paragraphs_rpsl(f)):
            row = {"i": i, "paragraph": paragraph, "strict": parse(paragraph, True), "relaxed": parse(paragraph, False)}
            sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
