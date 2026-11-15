#!/usr/bin/env python3
"""dalton parity harness: the same requests against the Apache image and the
nginx image, each with the fleet's sites in its own format, and a diff.

  python3 -I test/parity.py --fleet ../hs-backend-spot \
      --apache-image ghcr.io/hikari-systems/dalton:apache-final \
      --apache-ref origin/develop --nginx-image dalton:nginx-dev [--slow]

The Apache sites come from the fleet repo at --apache-ref (git show), the
nginx sites from its working tree. Every upstream named in either is a stub
container (test/stub.py) that answers with what it received. Requests go from
this host through Docker's published port, so dalton sees the Docker gateway
(a private, trusted address) as the peer, as it sees the ALB in production.

Cases listed in EXPECTED_DIFFERENCES differ on purpose; anything else that
differs is a regression. Exit status 1 if there are any. Extra nginx-only
checks (ModSecurity On, body-streaming speed, startup without upstreams,
missing HS_API_KEY, OpenTelemetry) run after the comparison.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
KEY = "parityKey0123456789abcdefghijklmnopqrstuvwxyzABCD"
NET = "dalton-parity"
TOKEN43 = "A" * 43
SITEKEY = "hs_" + "0" * 32
HOSTS = {
    "LLOQUENT_HOSTNAME": "lloquent.test", "BOTSAFELY_HOSTNAME": "botsafely.test",
    "YAHOO_FINANCE_MCP_HOSTNAME": "yf.test", "CLINICAL_TRIALS_MCP_HOSTNAME": "ct.test",
    "CAMELID_MCP_HOSTNAME": "camelid.test", "BLENDER_GRAPH_MCP_HOSTNAME": "bg.test",
    "EULEGAL_MCP_HOSTNAME": "eulegal.test", "GRAPHVIEW_HOSTNAME": "graphview.test",
    "SSO_HOSTNAME": "sso.test", "LOGIN_HOSTNAME": "login.test",
    "FIVEDRIVE_HOSTNAME": "5drive.test", "WOODHOUSE_HOSTNAME": "woodhouse.test",
    "HS_DEPLOY_HOSTNAME": "hs-deploy.test", "HOMESTRETCH_HOSTNAME": "homestretch.test",
    "BIOALPHAENGINE_MCP_HOSTNAME": "bae.test", "RALLY_HOSTNAME": "rally.test",
}

# Differences that are intended (see the README's "Differences from the Apache
# image"). Keyed by case name; the value says why.
EXPECTED_DIFFERENCES = {
    "login HEAD /": "login.* answers HEAD with 405 at the edge, as 014-login.conf always meant (Apache passed it on as a GET)",
    "5drive photo upload over 32 MiB": "nginx enforces the per-path body limit on proxied bodies; Apache's LimitRequestBody didn't",
    "lloquent POST 14 MB": "nginx enforces the 12.5 MiB default body limit on proxied bodies; Apache didn't",
    "lloquent POST 14 MB chunked": "nginx enforces the default body limit on chunked bodies too",
    "woodhouse github hook chunked over limit": "nginx stops a chunked body past the route's limit; Apache only checked Content-Length",
    "sso redirect + cookie": "upstream redirects become relative (/landed) instead of Apache's http://host/landed",
    "login kratos redirect": "upstream redirects become relative (/api/auth/landed) instead of Apache's http://host/...",
    "lloquent.test redirect + cookie": "upstream redirects become relative instead of Apache's http://host/...",
    "botsafely.test redirect + cookie": "upstream redirects become relative instead of Apache's http://host/...",
    "woodhouse github hook CL over limit no key": "Apache reads the declared body before its 403; nginx answers 403 at once (this test never sends the body)",
    "homestretch ingest CL over limit no key": "Apache reads the declared body before its 403; nginx answers 403 at once (this test never sends the body)",
    "woodhouse artefact CL over limit": "nginx answers 413 for a Content-Length over the route's limit; Apache (no rewrite rule on this route) waited for and passed the body",
    "rally api 504 after 30 s": "an upstream that times out is 504 Gateway Timeout; Apache answered 502 (both at 30 s)",
    "default dotfile": "a dotfile that doesn't exist is refused (403) rather than not found (404)",
    "default backup file": "a backup file that doesn't exist is refused (403) rather than not found (404)",
}
# X-Forwarded-For is compared by its first and last entries: the first is the
# client's own claim (what rally-controller keys on), the last the address
# dalton resolved. Apache dropped the trusted hops in between; nginx keeps them.
# Fields that differ between the servers for every request and carry no
# meaning (connection handling, the forwarded-server name, body framing).
IGNORED_UPSTREAM_HEADERS = {"connection", "x-forwarded-server", "content-length",
                            "transfer-encoding", "te", "traceparent", "tracestate"}
COMPARED_RESPONSE_HEADERS = ["content-security-policy", "x-frame-options",
                             "strict-transport-security", "x-content-type-options",
                             "x-xss-protection", "referrer-policy", "permissions-policy",
                             "x-robots-tag", "access-control-allow-origin",
                             "location", "set-cookie", "content-type"]
# Not compared: X-Powered-By (Apache's unset never removed an upstream's;
# nginx drops it) and Server. Apache's `Header always unset Server` never took effect
# (it sent "Server: Apache", or the upstream's own); nginx sends none, which is
# what security.conf asked for. Checked separately: no response has one.


def sh(*cmd, check=True, capture=True):
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if check and r.returncode:
        raise SystemExit(f"{' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r


# ------------------------------------------------------------------ requests
def raw_request(port, method, path, host, headers=None, body=b"", chunked=False,
                content_length=None, timeout=15, stream_probe=False):
    """One HTTP/1.1 request over a fresh socket. Returns a result dict."""
    headers = dict(headers or {})
    headers.setdefault("Host", host)
    headers.setdefault("Connection", "close")
    if chunked:
        headers["Transfer-Encoding"] = "chunked"
    elif content_length is not None:
        headers["Content-Length"] = str(content_length)
    elif body or method in ("POST", "PUT"):
        headers["Content-Length"] = str(len(body))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    t0 = time.monotonic()
    first_event = None
    try:
        s.sendall(head.encode())
        if chunked:
            for i in range(0, len(body), 65536):
                part = body[i:i + 65536]
                s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        elif body:
            try:
                s.sendall(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the server answered (413/403) without reading it all
        data = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                break
            if not chunk:
                break
            data += chunk
            if stream_probe and first_event is None and b"data: 0" in data:
                first_event = time.monotonic() - t0
            if content_length is not None and not body and b"\r\n\r\n" in data:
                break  # declared-but-unsent body: the status line is all we want
    finally:
        s.close()
    elapsed = time.monotonic() - t0
    head_b, _, payload = data.partition(b"\r\n\r\n")
    lines = head_b.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP/") else None
    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers.setdefault(k.strip().lower(), []).append(v.strip())
    if resp_headers.get("transfer-encoding", [""])[0].lower() == "chunked":
        payload = dechunk(payload)
    upstream = None
    if resp_headers.get("content-type", [""])[0].startswith("application/json"):
        try:
            upstream = json.loads(payload)
        except ValueError:
            pass
    return {"status": status, "headers": resp_headers, "upstream": upstream,
            "elapsed": elapsed, "first_event": first_event, "payload": payload}


def dechunk(b):
    out = b""
    while b:
        size_line, _, rest = b.partition(b"\r\n")
        try:
            n = int(size_line.split(b";")[0], 16)
        except ValueError:
            return out + b
        if n == 0:
            break
        out += rest[:n]
        b = rest[n + 2:]
    return out


def websocket(port, host, path, headers):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n")
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        s.sendall(req.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            c = s.recv(4096)
            if not c:
                break
            data += c
        status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else None
        if status != 101:
            return {"status": status, "echo": None}
        msg = b"hello"
        mask = os.urandom(4)
        s.sendall(bytes([0x81, 0x80 | len(msg)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(msg)))
        rest = data.split(b"\r\n\r\n", 1)[1]
        while len(rest) < 2:
            rest += s.recv(4096)
        n = rest[1] & 0x7F
        while len(rest) < 2 + n:
            rest += s.recv(4096)
        return {"status": 101, "echo": rest[2:2 + n].decode()}
    finally:
        s.close()


# ------------------------------------------------------------------ cases
def cases(fleet):
    k = {"x-hs-api": KEY}
    bad = {"x-hs-api": "wrong"}
    C = []

    def add(name, host, method="GET", path="/", headers=None, **kw):
        C.append(dict(name=name, host=host, method=method, path=path, headers=headers, **kw))

    # Default vhost: ALB health check (Host = node IP), unknown hosts, statics.
    add("default healthcheck", "10.0.1.23", path="/healthcheck")
    add("default unknown host", "nobody.test")
    add("default dotfile", "nobody.test", path="/.env")
    add("default backup file", "nobody.test", path="/index.html.bak")
    add("default server-status", "nobody.test", path="/server-status")
    add("default PUT", "nobody.test", "PUT", "/")
    add("default OPTIONS", "nobody.test", "OPTIONS", "/")
    add("default numeric Host with query", "10.0.1.23", path="/healthcheck?x=1")

    if fleet in ("hs-backend-spot", "hs-bae-spot"):
        sso, login = "sso.test", "login.test"
        add("sso no key", sso, path="/.well-known/openid-configuration")
        add("sso wrong key", sso, path="/.well-known/openid-configuration", headers=bad)
        add("sso discovery", sso, path="/.well-known/openid-configuration", headers=k)
        add("sso resource->audience", sso, path="/oauth2/auth?client_id=c&resource=https%3A%2F%2Fmcp.test%2Fmcp&state=s", headers=k)
        add("sso resource first", sso, path="/oauth2/auth?resource=https%3A%2F%2Fa.test%2F&client_id=c", headers=k)
        add("sso no resource", sso, path="/oauth2/auth?client_id=c&state=s", headers=k)
        add("sso PUT register", sso, "PUT", "/oauth2/register/abc", headers=k, body=b'{"a":1}')
        add("sso DELETE register", sso, "DELETE", "/oauth2/register/abc", headers=k)
        add("sso OPTIONS", sso, "OPTIONS", "/oauth2/token", headers=k)
        add("sso PATCH", sso, "PATCH", "/oauth2/token", headers=k)
        add("sso redirect + cookie", sso, path="/oauth2/__redirect", headers=k)
        add("sso X-Forwarded-Proto", sso, path="/userinfo", headers={**k, "X-Forwarded-Proto": "http"})
        add("login catch-all", login, path="/login?flow=1", headers=k)
        add("login kratos prefix stripped", login, path="/api/auth/self-service/login/browser", headers=k)
        add("login kratos redirect", login, path="/api/auth/__redirect", headers=k)
        add("login DELETE sessions", login, "DELETE", "/api/auth/sessions/123", headers=k)
        add("login DELETE catch-all", login, "DELETE", "/api/x", headers=k)
        add("login PUT", login, "PUT", "/api/x", headers=k)
        add("login HEAD /", login, "HEAD", "/", headers=k)
        add("login image upload", login, "POST", "/api/image/upload", headers={**k, "Content-Type": "multipart/form-data; boundary=b"},
            body=b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJPEG\r\n--b--\r\n")
        add("login dcr register", login, "POST", "/api/dcr/register", headers={**k, "Content-Type": "application/json"}, body=b'{"client_name":"c"}')
        add("login robots + headers", login, path="/__csp", headers=k)

    if fleet == "hs-backend-spot":
        for host, landing in [("yf.test", False), ("ct.test", False), ("camelid.test", True),
                              ("eulegal.test", True), ("graphview.test", True), ("bg.test", True)]:
            add(f"{host} landing no key", host, path="/")
            add(f"{host} index.html no key", host, path="/index.html")
            add(f"{host} mcp no key", host, "POST", "/mcp", body=b"{}")
            add(f"{host} mcp", host, "POST", "/mcp", headers={**k, "Content-Type": "application/json"}, body=b'{"jsonrpc":"2.0","id":1,"method":"initialize"}')
            add(f"{host} mcp DELETE", host, "DELETE", "/mcp", headers=k)
            add(f"{host} DELETE elsewhere", host, "DELETE", "/other", headers=k)
            add(f"{host} landing with key", host, path="/", headers=k)
            add(f"{host} upstream csp replaced", host, path="/__csp", headers=k)
            add(f"{host} mcpx", host, path="/mcpx", headers=k)
        for host in ("lloquent.test", "botsafely.test"):
            add(f"{host} no key", host)
            add(f"{host} root", host, headers=k)
            add(f"{host} graphql", host, "POST", "/api/graphql", headers={**k, "Content-Type": "application/json"}, body=b'{"query":"{a}"}')
            add(f"{host} open-graphql", host, "POST", "/api/open-graphql", headers={**k, "Content-Type": "application/json"}, body=b'{"query":"{a}"}')
            add(f"{host} redirect + cookie", host, path="/__redirect", headers=k)
            add(f"{host} xff from cloudfront", host, path="/x", headers={**k, "X-Forwarded-For": "203.0.113.9, 64.252.64.10"})
            add(f"{host} xff forged", host, path="/x", headers={**k, "X-Forwarded-For": "6.6.6.6, 203.0.113.9, 64.252.64.10"})
            add(f"{host} xff untrusted hop", host, path="/x", headers={**k, "X-Forwarded-For": "203.0.113.9, 198.51.100.7"})
            add(f"{host} detection-only attack", host, path="/search?q=%3Cscript%3Ealert(1)%3C/script%3E", headers=k)
        add("lloquent POST 14 MB", "lloquent.test", "POST", "/upload", headers=k, body=b"a" * (14 * 1024 * 1024), timeout=60)
        add("lloquent POST 14 MB chunked", "lloquent.test", "POST", "/upload", headers=k, body=b"a" * (14 * 1024 * 1024), chunked=True, timeout=60)
        add("lloquent POST 1 MB", "lloquent.test", "POST", "/upload", headers={**k, "Content-Type": "application/octet-stream"}, body=b"a" * (1024 * 1024), timeout=60)
        f = "5drive.test"
        add("5drive no key", f)
        add("5drive catch-all", f, path="/cars", headers=k)
        add("5drive kratos", f, path="/api/auth/self-service/registration/browser", headers=k)
        add("5drive DELETE sessions", f, "DELETE", "/api/auth/sessions", headers=k)
        add("5drive hydra oauth2", f, path="/oauth2/auth?client_id=c", headers=k)
        add("5drive hydra userinfo", f, path="/userinfo", headers=k)
        add("5drive userinfox", f, path="/userinfox", headers=k)
        add("5drive hydra jwks", f, path="/.well-known/jwks.json", headers=k)
        add("5drive hydra discovery", f, path="/.well-known/openid-configuration", headers=k)
        add("5drive other well-known", f, path="/.well-known/oauth-protected-resource", headers=k)
        add("5drive oauth2 callback", f, path="/oauth2/callback?code=1", headers=k)
        add("5drive dev describe csp", f, path="/api/dev/describe", headers=k)
        add("5drive dev describe run csp", f, path="/api/dev/describe/run", headers=k)
        add("5drive sell-chat sse", f, "POST", "/api/sell-chat/__sse", headers={**k, "Content-Type": "application/json"}, body=b"{}", stream_probe=True)
        add("5drive photo upload 12 MB", f, "POST", "/api/car/photo/upload", headers={**k, "Content-Type": "image/jpeg"}, body=b"\xff" * (12 * 1024 * 1024), timeout=60)
        add("5drive photo upload over 32 MiB", f, "POST", "/api/car/photo/upload", headers=k, content_length=33619969)
        add("5drive x-forwarded-proto", f, path="/x", headers={**k, "X-Forwarded-Proto": "http"})
        w = "woodhouse.test"
        add("woodhouse no key", w, path="/api/x")
        add("woodhouse unrouted path", w, path="/elsewhere", headers=k)
        add("woodhouse root", w, path="/", headers=k)
        add("woodhouse api", w, path="/api/me", headers=k)
        add("woodhouse stream sse", w, path="/api/stream/__sse", headers=k, stream_probe=True)
        add("woodhouse streamx", w, path="/api/streamx", headers=k)
        add("woodhouse callbacks", w, path="/callbacks/login?code=1&state=2", headers=k)
        add("woodhouse mcp", w, "POST", "/mcp", headers={**k, "Content-Type": "application/json"}, body=b'{"jsonrpc":"2.0"}')
        add("woodhouse mcpx", w, path="/mcpx", headers=k)
        add("woodhouse protected-resource", w, path="/.well-known/oauth-protected-resource/mcp", headers=k)
        add("woodhouse authorization-server", w, path="/.well-known/oauth-authorization-server", headers=k)
        add("woodhouse healthcheck", w, path="/healthcheck", headers=k)
        add("woodhouse github hook", w, "POST", f"/hooks/{TOKEN43}/github", headers={**k, "Content-Type": "application/json"}, body=b'{"a":1}')
        add("woodhouse github hook GET", w, "GET", f"/hooks/{TOKEN43}/github", headers=k)
        add("woodhouse github hook 24 MiB", w, "POST", f"/hooks/{TOKEN43}/github", headers=k, body=b"a" * (24 * 1024 * 1024), timeout=60)
        add("woodhouse github hook CL over limit", w, "POST", f"/hooks/{TOKEN43}/github", headers=k, content_length=26279937)
        add("woodhouse github hook CL 2^31+5", w, "POST", f"/hooks/{TOKEN43}/github", headers=k, content_length=2147483653)
        add("woodhouse github hook CL over limit no key", w, "POST", f"/hooks/{TOKEN43}/github", content_length=26279937)
        add("woodhouse github hook chunked over limit", w, "POST", f"/hooks/{TOKEN43}/github", headers=k, body=b"a" * 26279937, chunked=True, timeout=60)
        add("woodhouse linear hook CL over limit", w, "POST", f"/hooks/{TOKEN43}/linear", headers=k, content_length=8454145)
        add("woodhouse linear hook", w, "POST", f"/hooks/{TOKEN43}/linear", headers=k, body=b"{}")
        add("woodhouse agent hook", w, "POST", f"/hooks/{TOKEN43}/agent/pi-runner", headers=k, body=b"{}")
        add("woodhouse agent hook CL over limit", w, "POST", f"/hooks/{TOKEN43}/agent/pi-runner", headers=k, content_length=270337)
        add("woodhouse short token hook", w, "POST", "/hooks/short/github", headers=k, body=b"{}")
        add("woodhouse hook attack query", w, "POST", f"/hooks/{TOKEN43}/github?q=%3Cscript%3E", headers=k, body=b"{}")
        add("woodhouse worker claim", w, "POST", "/worker/claim", headers={**k, "Content-Type": "application/json"}, body=b"{}")
        add("woodhouse artefact PUT", w, "PUT", "/worker/jobs/j1/artefacts/bundle", headers=k, body=b"x" * 4096)
        add("woodhouse artefact POST", w, "POST", "/worker/jobs/j1/artefacts/bundle", headers=k, body=b"x")
        add("woodhouse artefact CL over limit", w, "PUT", "/worker/jobs/j1/artefacts/bundle", headers=k, content_length=22020097)
        add("woodhouse PUT elsewhere", w, "PUT", "/api/x", headers=k)
        d = "hs-deploy.test"
        add("hs-deploy api", d, path="/api/oauth2/callback?code=1", headers=k)
        add("hs-deploy stream sse", d, path="/api/stream/__sse", headers=k, stream_probe=True)
        add("hs-deploy graphql", d, "POST", "/api/graphql", headers={**k, "Content-Type": "application/json"}, body=b'{"query":"{a}"}')
        add("hs-deploy mcp", d, "POST", "/mcp", headers=k, body=b"{}")
        add("hs-deploy unrouted", d, path="/nope", headers=k)
        add("hs-deploy no key", d, path="/api/x")
        h = "homestretch.test"
        add("homestretch api", h, path="/api/session/1/events", headers=k)
        add("homestretch stripe webhook", h, "POST", "/api/stripe/webhook", headers={**k, "Content-Type": "application/json"}, body=b'{"id":"evt_1"}')
        add("homestretch ingest batch", h, "POST", f"/ingest/v1/{SITEKEY}/batch", headers={**k, "Content-Type": "text/plain"}, body=b"x" * 2048)
        add("homestretch ingest preflight", h, "OPTIONS", f"/ingest/v1/{SITEKEY}/session", headers={**k, "Origin": "https://site.example", "Access-Control-Request-Method": "POST"})
        add("homestretch ingest GET", h, "GET", f"/ingest/v1/{SITEKEY}/batch", headers=k)
        add("homestretch ingest CL over limit", h, "POST", f"/ingest/v1/{SITEKEY}/batch", headers=k, content_length=5308417)
        add("homestretch ingest CL over limit no key", h, "POST", f"/ingest/v1/{SITEKEY}/batch", content_length=5308417)
        add("homestretch ingest acao passthrough", h, "POST", f"/ingest/v1/{SITEKEY}/__csp", headers=k, body=b"{}")
        add("homestretch other ingest", h, "POST", "/ingest/v2/x", headers=k, body=b"{}")
        add("homestretch stream sse", h, path="/api/stream/__sse", headers=k, stream_probe=True)

    if fleet == "hs-bae-spot":
        add("bae landing no key", "bae.test", path="/")
        add("bae mcp no key", "bae.test", "POST", "/mcp", body=b"{}")
        add("bae mcp", "bae.test", "POST", "/mcp", headers={**k, "Content-Type": "application/json"}, body=b'{"jsonrpc":"2.0"}')
        add("bae mcp DELETE", "bae.test", "DELETE", "/mcp", headers=k)

    if fleet == "rally-backend-spot":
        r = "rally.test"
        add("rally no key", r, path="/api/x")
        add("rally api", r, path="/api/x", headers=k)
        add("rally graphql", r, "POST", "/api/graphql", headers={**k, "Content-Type": "application/json"}, body=b'{"query":"{a}"}')
        add("rally stream sse", r, path="/api/stream/__sse", headers=k, stream_probe=True)
        add("rally healthcheck", r, path="/healthcheck", headers=k)
        add("rally unrouted", r, path="/x", headers=k)
        add("rally xff", r, path="/api/x", headers={**k, "X-Forwarded-For": "6.6.6.6, 203.0.113.9, 64.252.64.10"})
        add("rally voice-note websocket", r, path="/api/voice-note/stream", headers=k, ws=True)
    return C


def normalise(res):
    """The parts of a result that should be identical across servers."""
    if res is None:
        return None
    if "echo" in res:
        return {"status": res["status"], "echo": res["echo"]}
    hdr = {}
    for h in COMPARED_RESPONSE_HEADERS:
        if h in res["headers"]:
            v = res["headers"][h]
            if h == "content-type" and res["upstream"] is None:
                continue  # error pages differ in type; compared by status
            hdr[h] = sorted(v)
    up = res["upstream"]
    if up:
        up = {"upstream": up["upstream"], "port": up["port"], "method": up["method"],
              "target": up["target"], "body_len": up["body_len"],
              "headers": {k: v for k, v in sorted(up["headers"].items()) if k not in IGNORED_UPSTREAM_HEADERS}}
        if "x-forwarded-for" in up["headers"]:
            chain = [e.strip() for e in up["headers"]["x-forwarded-for"].split(",")]
            up["headers"]["x-forwarded-for"] = f"first={chain[0]} last={chain[-1]}"
    out = {"status": res["status"], "headers": hdr, "upstream": up}
    if res.get("first_event") is not None or res["status"] == 200 and res["headers"].get("content-type", [""])[0] == "text/event-stream":
        out["streamed"] = res.get("first_event") is not None and res["first_event"] < 2.0
    return out


def run_case(port, c):
    if c.get("ws"):
        return websocket(port, c["host"], c["path"], c["headers"] or {})
    return raw_request(port, c["method"], c["path"], c["host"], c["headers"], c.get("body", b""),
                       chunked=c.get("chunked", False), content_length=c.get("content_length"),
                       timeout=c.get("timeout", 15), stream_probe=c.get("stream_probe", False))


# ------------------------------------------------------------------ containers
def upstreams(apache_dir, nginx_dir):
    names = {}
    for f in pathlib.Path(apache_dir).glob("*.conf"):
        for line in f.read_text().splitlines():
            if line.lstrip().startswith("#"):
                continue
            for host, port in re.findall(r"ProxyPass\s+\S+\s+https?://([a-z0-9.-]+)(?::(\d+))?", line):
                names.setdefault(host, set()).add(int(port or 80))
    for f in pathlib.Path(nginx_dir).glob("*.conf"):
        for line in f.read_text().splitlines():
            if line.lstrip().startswith("#"):
                continue
            for host, port in re.findall(r"^\s*server\s+([a-z0-9.-]+):(\d+)\s+resolve", line):
                names.setdefault(host, set()).add(int(port))
    return names


def start_stubs(names, skip=()):
    sh("docker", "network", "create", NET, check=False)
    for name, ports in names.items():
        if name in skip:
            continue
        sh("docker", "rm", "-f", f"parity-stub-{name}", check=False)
        sh("docker", "run", "-d", "--name", f"parity-stub-{name}", "--network", NET,
           "--network-alias", name, "-e", f"NAME={name}",
           "-v", f"{HERE / 'stub.py'}:/stub.py:ro", "python:3.12-alpine",
           "python", "-u", "/stub.py", *map(str, sorted(ports)))


def stop_stubs(names):
    for name in names:
        sh("docker", "rm", "-f", f"parity-stub-{name}", check=False)


def start_dalton(name, image, port, sites, kind, extra_env=(), env_key=True):
    sh("docker", "rm", "-f", name, check=False)
    env = []
    for k, v in HOSTS.items():
        env += ["-e", f"{k}={v}"]
    if env_key:
        env += ["-e", f"HS_API_KEY={KEY}"]
    env += ["-e", "ENV_NAME=parity", "-e", "ENV_PREFIX=parity."]
    for e in extra_env:
        env += ["-e", e]
    if kind == "apache":
        mounts = ["-v", f"{sites}:/usr/local/apache2/conf/sites-enabled:ro",
                  "--tmpfs", "/tmp", "--tmpfs", "/usr/local/apache2/run:mode=0777"]
    else:
        mounts = ["-v", f"{sites}:/etc/nginx/templates:ro", "--tmpfs", "/tmp:size=256m"]
    r = sh("docker", "run", "-d", "--name", name, "--network", NET, "-p", f"127.0.0.1:{port}:3000",
           "--read-only", *mounts, *env, image, check=False)
    if r.returncode:
        return False
    for _ in range(60):
        try:
            res = raw_request(port, "GET", "/healthcheck", "10.0.0.1", timeout=2)
            if res["status"] == 200:
                return True
        except OSError:
            pass
        if sh("docker", "inspect", "-f", "{{.State.Running}}", name, check=False).stdout.strip() != "true":
            return False
        time.sleep(0.5)
    return False


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fleet", required=True, help="path to a spot repo (hs-backend-spot, hs-bae-spot, rally-backend-spot)")
    ap.add_argument("--apache-image", default="ghcr.io/hikari-systems/dalton:apache-final")
    ap.add_argument("--apache-ref", default="origin/develop")
    ap.add_argument("--nginx-image", default="dalton:nginx-dev")
    ap.add_argument("--slow", action="store_true", help="also run the 35 s timeout cases")
    ap.add_argument("--out", default=str(HERE / "out"))
    a = ap.parse_args()

    fleet_dir = pathlib.Path(a.fleet).resolve()
    fleet = fleet_dir.name
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="dalton-parity-"))
    apache_sites = tmp / "apache-sites"
    apache_sites.mkdir()
    listing = sh("git", "-C", str(fleet_dir), "ls-tree", "--name-only", f"{a.apache_ref}:sites").stdout.split()
    for f in listing:
        (apache_sites / f).write_text(sh("git", "-C", str(fleet_dir), "show", f"{a.apache_ref}:sites/{f}").stdout)
    nginx_sites = fleet_dir / "sites"

    names = upstreams(apache_sites, nginx_sites)
    print(f"{fleet}: {len(names)} upstream stubs: {', '.join(sorted(names))}")
    start_stubs(names)
    regressions, expected = [], []
    try:
        ok_a = start_dalton("parity-apache", a.apache_image, 18080, apache_sites, "apache")
        ok_n = start_dalton("parity-nginx", a.nginx_image, 18081, nginx_sites, "nginx")
        if not (ok_a and ok_n):
            for n in ("parity-apache", "parity-nginx"):
                print(sh("docker", "logs", n, check=False).stderr[-3000:])
            raise SystemExit("a dalton container didn't come up")
        results = []
        table = cases(fleet)
        if a.slow and fleet == "rally-backend-spot":
            table.append(dict(name="rally stream survives 35 s quiet", host="rally.test", method="GET",
                              path="/api/stream/__sleep/35", headers={"x-hs-api": KEY}, timeout=60))
            table.append(dict(name="rally api 504 after 30 s", host="rally.test", method="GET",
                              path="/api/__sleep/35", headers={"x-hs-api": KEY}, timeout=60))
        for c in table:
            ra = run_case(18080, c)
            rn = run_case(18081, c)
            na, nn = normalise(ra), normalise(rn)
            same = na == nn
            for h in ("server", "x-powered-by"):
                if h in rn.get("headers", {}):
                    regressions.append({"case": f"{c['name']} (nginx sent {h})", "apache": na, "nginx": nn})
            results.append({"case": c["name"], "same": same, "apache": na, "nginx": nn,
                            "elapsed": {"apache": round(ra.get("elapsed", 0), 3), "nginx": round(rn.get("elapsed", 0), 3)}})
            if not same:
                (expected if c["name"] in EXPECTED_DIFFERENCES else regressions).append(results[-1])
        (out / f"{fleet}.json").write_text(json.dumps(results, indent=1, default=str))
        print(f"{len(results)} cases: {len(results) - len(regressions) - len(expected)} identical, "
              f"{len(expected)} expected differences, {len(regressions)} regressions")
        for r in expected:
            why = EXPECTED_DIFFERENCES[r["case"]]
            print(f"  expected: {r['case']}: {why}")
            print(f"      apache: {short(r['apache'])}\n      nginx:  {short(r['nginx'])}")
        for r in regressions:
            print(f"  REGRESSION: {r['case']}")
            print(f"      apache: {json.dumps(r['apache'], sort_keys=True)}")
            print(f"      nginx:  {json.dumps(r['nginx'], sort_keys=True)}")
    finally:
        sh("docker", "rm", "-f", "parity-apache", "parity-nginx", check=False)
        stop_stubs(names)
    sys.exit(1 if regressions else 0)


def short(n):
    if n is None:
        return "-"
    if "echo" in n:
        return json.dumps(n)
    up = n.get("upstream") or {}
    xff = (up.get("headers") or {}).get("x-forwarded-for")
    return (f"status={n['status']} upstream={up.get('upstream')} target={up.get('target')} "
            f"body_len={up.get('body_len')}" + (f" xff={xff!r}" if xff else ""))


if __name__ == "__main__":
    main()
