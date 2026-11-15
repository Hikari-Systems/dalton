#!/usr/bin/env python3
"""Stub upstream for the dalton parity harness.

One container per upstream name (its NAME env), listening on the ports it is
asked to. Every response is JSON describing what arrived, so the harness can
compare what Apache-dalton and nginx-dalton pass on:

  {"upstream": NAME, "port": …, "method": …, "target": raw request-target,
   "headers": {lower-case name: value}, "body_len": n, "body_sha256": …}

Special paths (anywhere in the target):
  /__redirect   302 with Location: http://NAME:PORT/landed, and a cookie with
                Domain=NAME:PORT (what ProxyPassReverse* / proxy_redirect and
                proxy_cookie_domain rewrite)
  /__csp        sends its own Content-Security-Policy / X-Frame-Options /
                X-Powered-By / X-Robots-Tag / Access-Control-Allow-Origin
  /__sse        text/event-stream, one event a second for 4 s
  /__sleep/N    waits N seconds before answering
  Upgrade: websocket   completes the handshake and echoes one text frame
"""
import base64
import hashlib
import json
import os
import socketserver
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

NAME = os.environ.get("NAME", "stub")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    return data
                data += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _handle(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._websocket()
        body = self._body()
        port = self.server.server_address[1]
        info = {
            "upstream": NAME,
            "port": port,
            "method": self.command,
            "target": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        if "/__sleep/" in self.path:
            time.sleep(float(self.path.split("/__sleep/")[1].split("/")[0].split("?")[0]))
        if "/__sse" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(4):
                self.wfile.write(f"data: {i} {time.time():.3f}\n\n".encode())
                self.wfile.flush()
                time.sleep(1)
            self.close_connection = True
            return
        out = json.dumps(info, sort_keys=True).encode()
        if "/__redirect" in self.path:
            self.send_response(302)
            self.send_header("Location", f"http://{NAME}:{port}/landed")
            self.send_header("Set-Cookie", f"sid=1; Domain={NAME}:{port}; Path=/")
        else:
            self.send_response(200)
        if "/__csp" in self.path:
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-Powered-By", "stub")
            self.send_header("X-Robots-Tag", "upstream")
            self.send_header("Access-Control-Allow-Origin", "https://upstream.example")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    def _websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        # Read one (masked, client) frame and echo its payload unmasked.
        b1, b2 = self.rfile.read(2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self.rfile.read(2))[0]
        mask = self.rfile.read(4)
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(self.rfile.read(n)))
        reply = f"{NAME} echo: ".encode() + data
        self.wfile.write(bytes([0x81, len(reply)]) + reply)
        self.wfile.flush()
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _handle


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    ports = [int(p) for p in (sys.argv[1:] or ["3000"])]
    servers = [Server(("0.0.0.0", p), Handler) for p in ports]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()
