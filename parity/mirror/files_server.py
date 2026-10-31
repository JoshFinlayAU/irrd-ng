#!/usr/bin/env python3
"""Serve the upstream's exports and NRTMv4 files over HTTP (port 80) and
FTP (port 21) for the mirroring differential.

    files_server.py <root> <overlay> [<cert> <key>]

With a certificate, HTTPS is served on 443 as well. GET /<path> and FTP
RETR <path> read <overlay>/<path> if it exists, else
<root>/<path>. The harness puts tampered files in the overlay (a broken
delta, an expired Update Notification File) without touching what the
upstream wrote. The FTP server is the minimum urllib's FTP client uses:
anonymous login, CWD, TYPE I, PASV, RETR, SIZE, QUIT.
"""
import http.server
import os
import socket
import socketserver
import sys
import threading

ROOT, OVERLAY = sys.argv[1], sys.argv[2]


def resolve(path):
    path = os.path.normpath("/" + path).lstrip("/")
    for base in (OVERLAY, ROOT):
        p = os.path.join(base, path)
        if os.path.isfile(p):
            return p
    return None


class Http(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = resolve(self.path.split("?", 1)[0])
        if not p:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        with open(p, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("http %s %s\n" % (self.client_address[0], fmt % args))


class Ftp(socketserver.StreamRequestHandler):
    def reply(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        cwd = "/"
        pasv = None
        self.reply("220 irrd-ng parity ftp")
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            sys.stderr.write("ftp %s %s\n" % (self.client_address[0], line))
            if cmd == "USER":
                self.reply("331 ok")
            elif cmd == "PASS":
                self.reply("230 logged in")
            elif cmd == "TYPE":
                self.reply("200 type set")
            elif cmd == "PWD":
                self.reply('257 "%s"' % cwd)
            elif cmd == "CWD":
                new = os.path.normpath(os.path.join(cwd, arg))
                if os.path.isdir(os.path.join(ROOT, new.lstrip("/"))):
                    cwd = new
                    self.reply("250 ok")
                else:
                    self.reply("550 no such directory")
            elif cmd in ("PASV", "EPSV"):
                pasv = socket.socket()
                pasv.bind(("0.0.0.0", 0))
                pasv.listen(1)
                port = pasv.getsockname()[1]
                if cmd == "EPSV":
                    self.reply("229 Entering Extended Passive Mode (|||%d|)" % port)
                else:
                    ip = self.connection.getsockname()[0].replace(".", ",")
                    self.reply("227 Entering Passive Mode (%s,%d,%d)" % (ip, port >> 8, port & 255))
            elif cmd == "SIZE":
                p = resolve(os.path.join(cwd, arg))
                self.reply("213 %d" % os.path.getsize(p) if p else "550 no such file")
            elif cmd == "RETR":
                p = resolve(os.path.join(cwd, arg))
                if not p or not pasv:
                    self.reply("550 Failed to open file.")
                    continue
                self.reply("150 opening data connection")
                conn, _ = pasv.accept()
                with open(p, "rb") as f:
                    conn.sendall(f.read())
                conn.close()
                pasv.close()
                pasv = None
                self.reply("226 transfer complete")
            elif cmd == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("502 not implemented")


class ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ftp = ThreadingTCP(("0.0.0.0", 21), Ftp)
    threading.Thread(target=ftp.serve_forever, daemon=True).start()
    if len(sys.argv) > 4:
        import ssl

        https = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Http)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[3], sys.argv[4])
        https.socket = ctx.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", 80), Http).serve_forever()
