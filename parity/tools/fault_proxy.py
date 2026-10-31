#!/usr/bin/env python3
"""TCP proxy that injects differences into a server's answers, to prove the
harness catches them (parity/tools/selftest.sh).

    fault_proxy.py --listen 127.0.0.1:PORT --target HOST:PORT --sub REGEX REPL [--sub ...]

Every chunk the target sends is passed through re.sub(REGEX, REPL) (bytes,
first match per chunk only) before it reaches the client. The client's
bytes and the connection close are passed through untouched. With no --sub
it is a transparent proxy. --log records what clients send, which is how
the bgpq4 query sequences in parity/corpus/whois/bgpq4.q were captured.
"""
import argparse
import re
import socket
import threading


LOG_LOCK = threading.Lock()


def pump(src, dst, subs, log=None):
    try:
        while True:
            data = src.recv(1 << 16)
            if not data:
                break
            if log is not None:
                with LOG_LOCK:
                    log.write(data)
                    log.flush()
            for rx, repl in subs:
                data = rx.sub(repl, data, count=1)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, target, subs, log):
    try:
        server = socket.create_connection(target)
    except OSError:
        client.close()
        return
    if log is not None:
        with LOG_LOCK:
            log.write(b"### connection\n")
    t = threading.Thread(target=pump, args=(client, server, [], log), daemon=True)
    t.start()
    pump(server, client, subs)
    t.join(timeout=5)
    client.close()
    server.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--sub", nargs=2, action="append", default=[], metavar=("REGEX", "REPL"))
    ap.add_argument("--log", help="append what clients send to this file, one '### connection' line per connection")
    args = ap.parse_args()
    lh, lp = args.listen.rsplit(":", 1)
    th, tp = args.target.rsplit(":", 1)
    subs = [(re.compile(a.encode()), b.encode()) for a, b in args.sub]  # re.sub handles \n, \1
    log = open(args.log, "ab") if args.log else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, int(lp)))
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, (th, int(tp)), subs, log), daemon=True).start()


if __name__ == "__main__":
    main()
