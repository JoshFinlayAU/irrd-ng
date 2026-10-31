"""Unit tests for whois_diff.py: v4 query classification, framing reads
against a scripted server, and the unordered comparisons.

    python3 -I -m unittest parity/tools/test_whois_diff.py   (from the repo root, with PYTHONPATH=parity/tools)
"""
import socket
import threading
import unittest

import whois_diff as w


def serve(script):
    """A one-connection server: for each expected line, send the scripted bytes;
    None closes the connection."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        c, _ = srv.accept()
        f = c.makefile("rb")
        for reply in script:
            if reply is None:
                break
            if f.readline() == b"":
                break
            c.sendall(reply)
        c.close()
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()


class Classify(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(w.classify("", False), ("skip", False))
        self.assertEqual(w.classify("!!", False), ("none", True))
        self.assertEqual(w.classify("!q", True), ("close", True))
        self.assertEqual(w.classify("!gAS1", False), ("irrd", False))
        self.assertEqual(w.classify("-V ua !v", False), ("irrd", False))
        self.assertEqual(w.classify("-k -t aut-num", False), ("ripe", True))
        self.assertEqual(w.classify("-i origin -k", False), ("ripe", False))
        self.assertEqual(w.classify("x\x00", False), ("irrd", False))


class Framing(unittest.TestCase):
    def test_keepalive_session(self):
        addr = serve([b"", b"A4\nabc\nC\n", b"D\n", b"F err\n", b"x\n\n\n", None])
        item = w.Item("t", [b"!!\n", b"!v\n", b"!gAS1\n", b"!x\n", b"-x 1\n"], [])
        segs = w.run_whois_item(addr, item, 5)
        self.assertEqual([d for _, d in segs], [b"", b"A4\nabc\nC\n", b"D\n", b"F err\n", b"x\n\n\n", b""])

    def test_missing_close_keeps_the_answer(self):
        addr = serve([b"A2\nx\nC\n", b"never"])
        w.CLOSE_TIMEOUT = 0.5
        segs = w.run_whois_item(addr, w.Item("t", [b"!v\n"], []), 5)
        self.assertEqual(segs[0][1], b"A2\nx\nC\n<<TIMEOUT>>")

    def test_single_reads_to_close(self):
        addr = serve([b"A2\nx\nC\ntrailing", None])
        segs = w.run_whois_item(addr, w.Item("t", [b"!v\n"], []), 5)
        self.assertEqual(segs[0][1], b"A2\nx\nC\ntrailing")


class Unordered(unittest.TestCase):
    def test_tokens(self):
        self.assertTrue(w.same_tokens(b"A8\n1 2 3 4\nC\n", b"A8\n4 3 2 1\nC\n"))
        self.assertFalse(w.same_tokens(b"A8\n1 2 3 4\nC\n", b"A9\n4 3 2 1\nC\n"))
        self.assertFalse(w.same_tokens(b"A8\n1 2 3 4\nC\n", b"A8\n1 2 3 5\nC\n"))

    def test_objects_only_equal_pk_may_permute(self):
        a = b"route: 1/8\norigin: AS1\nsource: A\n\nroute: 1/8\norigin: AS1\nsource: B"
        b = b"route: 1/8\norigin: AS1\nsource: B\n\nroute: 1/8\norigin: AS1\nsource: A"
        c = b"route: 1/8\norigin: AS2\nsource: B\n\nroute: 1/8\norigin: AS1\nsource: A"
        d = b"route: 1/8\norigin: AS1\nsource: A\n\nroute: 1/8\norigin: AS2\nsource: B"
        self.assertTrue(w.same_objects(a, b))
        self.assertFalse(w.same_objects(c, d))

    def test_person_role_share_nic_hdl(self):
        a = b"person: X\nnic-hdl: H1\n\nrole: Y\nnic-hdl: H1"
        b = b"role: Y\nnic-hdl: H1\n\nperson: X\nnic-hdl: H1"
        self.assertTrue(w.same_objects(a, b))


if __name__ == "__main__":
    unittest.main()
