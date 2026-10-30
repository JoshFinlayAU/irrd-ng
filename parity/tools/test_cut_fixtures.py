"""Regression tests for cut_fixtures.py. Run: python3 -I -m unittest discover -s parity/tools"""

import unittest

from cut_fixtures import attrs, edge_kinds, objects

DUMP = (
    b"# dump header comment\n"
    b"% another header line\n"
    b"\n"
    b"as-set:     AS-EXAMPLE\n"
    b"# explanation inside the object\n"
    b"members:    AS65000,\n"
    b"            AS65001\n"
    b"% percent comment inside the object\n"
    b"descr:      inline # comment\n"
    b" \n"
    b"source:     TEST\n"
    b"\n"
    b"\n"
    b"route:      192.0.2.0/24\n"
    b"origin:     AS65000\n"
    b"source:     TEST\n"
)


class ObjectsTest(unittest.TestCase):
    def test_paragraph_bytes_are_kept_verbatim(self):
        got = list(objects(DUMP))
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0], DUMP[DUMP.index(b"as-set") : DUMP.index(b"\n\n\nroute")] + b"\n")
        self.assertIn(b"# explanation inside the object\n", got[0])
        self.assertIn(b"% percent comment inside the object\n", got[0])

    def test_whitespace_only_line_does_not_split(self):
        self.assertIn(b"\n \nsource:     TEST", list(objects(DUMP))[0])

    def test_header_paragraph_is_skipped(self):
        self.assertTrue(all(not o.startswith(b"#") for o in objects(DUMP)))

    def test_edge_kinds_see_comment_lines(self):
        kinds = edge_kinds(list(objects(DUMP))[0])
        self.assertLessEqual(
            {"comment-line-hash", "comment-line-percent", "whitespace-only-line", "comment", "cont-space"}, kinds
        )

    def test_attrs_ignore_comment_lines(self):
        a = attrs(list(objects(DUMP))[0])
        self.assertEqual(a[0], [b"as-set", b"AS-EXAMPLE"])
        self.assertEqual(a[1], [b"members", b"AS65000, AS65001"])


if __name__ == "__main__":
    unittest.main()
