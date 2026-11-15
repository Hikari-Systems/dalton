#!/bin/sh
# nginx-only checks that have no Apache counterpart to compare with:
#   1. MODSEC_RULE_ENGINE=On blocks a CRS attack (and DetectionOnly doesn't);
#      ModSecurity-off paths pass it even when On.
#   2. dalton starts, and serves its other sites, when upstreams don't exist.
#   3. dalton refuses to start without HS_API_KEY, or with a bad
#      MODSEC_RULE_ENGINE.
#   5. RATE_LIMIT: off by default, dry-run only logs, on refuses with 429;
#      private addresses and the signed webhook routes are exempt.
#   4. OpenTelemetry: a span per request reaches an OTLP/gRPC Collector, an
#      incoming traceparent is continued, and the upstream gets dalton's.
#
#   sh test/nginx-checks.sh [image] [path to hs-backend-spot]
set -u
IMAGE=${1:-dalton:nginx-dev}
FLEET=$(cd "${2:-../hs-backend-spot}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
NET=dalton-checks
KEY=checksKey0123456789abcdefghijklmnopqrstuvwxyzABCD
T43=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
fail=0
ok()   { echo "  ok    $*"; }
bad()  { echo "  FAIL  $*"; fail=1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
cleanup() { docker rm -f checks-dalton checks-otel checks-stub-lloquent checks-stub-woodhouse >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null

stub() { # stub <container name> <alias>
  docker run -d --name "$1" --network $NET --network-alias "$2" -e NAME="$2" \
    -v "$HERE/stub.py:/stub.py:ro" python:3.12-alpine python -u /stub.py 3000 >/dev/null
}
dalton() { # dalton <extra docker args...>
  docker rm -f checks-dalton >/dev/null 2>&1
  docker run -d --name checks-dalton --network $NET -p 127.0.0.1:18090:3000 --read-only \
    --tmpfs /tmp:size=256m -v "$FLEET/sites:/etc/nginx/templates:ro" -e HS_API_KEY=$KEY \
    -e ENV_NAME=checks -e LLOQUENT_HOSTNAME=lloquent.test -e BOTSAFELY_HOSTNAME=botsafely.test \
    -e YAHOO_FINANCE_MCP_HOSTNAME=yf.test -e CLINICAL_TRIALS_MCP_HOSTNAME=ct.test \
    -e CAMELID_MCP_HOSTNAME=camelid.test -e BLENDER_GRAPH_MCP_HOSTNAME=bg.test \
    -e EULEGAL_MCP_HOSTNAME=eulegal.test -e GRAPHVIEW_HOSTNAME=graphview.test \
    -e SSO_HOSTNAME=sso.test -e LOGIN_HOSTNAME=login.test -e FIVEDRIVE_HOSTNAME=5drive.test \
    -e WOODHOUSE_HOSTNAME=woodhouse.test -e HS_DEPLOY_HOSTNAME=hs-deploy.test \
    -e HOMESTRETCH_HOSTNAME=homestretch.test "$@" "$IMAGE" >/dev/null
  for _ in $(seq 40); do
    [ "$(code -H 'Host: 10.0.0.1' http://127.0.0.1:18090/healthcheck)" = 200 ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' checks-dalton 2>/dev/null)" = true ] || break
    sleep 0.5
  done
  docker logs checks-dalton 2>&1 | tail -5; return 1
}
ATTACK='/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'

echo "2. startup with no upstreams at all"
if dalton -e OTEL_ENABLED=false; then
  ok "started with every upstream missing"
  c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" http://127.0.0.1:18090/x)
  [ "$c" = 502 ] && ok "missing upstream answers 502" || bad "missing upstream answered $c"
  c=$(code -H 'Host: lloquent.test' http://127.0.0.1:18090/x)
  [ "$c" = 403 ] && ok "x-hs-api still enforced (403)" || bad "no-key request answered $c"
else bad "didn't start without upstreams"; fi

stub checks-stub-lloquent slackbot-controller
stub checks-stub-woodhouse woodhouse-controller
sleep 1
echo "   upstream appears after start"
c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" http://127.0.0.1:18090/x)
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do [ "$c" = 200 ] && break; sleep 1; c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" http://127.0.0.1:18090/x); done
[ "$c" = 200 ] && ok "a late upstream is picked up (resolve)" || bad "late upstream still $c"

echo "1. ModSecurity engine"
c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" "http://127.0.0.1:18090$ATTACK")
[ "$c" = 200 ] && ok "DetectionOnly (default): attack passes ($c)" || bad "DetectionOnly answered $c"
docker logs checks-dalton 2>&1 | grep -q '949110' && ok "DetectionOnly: 949110 in the audit log" || bad "no 949110 in the log"
dalton -e MODSEC_RULE_ENGINE=On -e OTEL_ENABLED=false || bad "didn't start with On"
c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" "http://127.0.0.1:18090$ATTACK")
[ "$c" = 403 ] && ok "On: attack blocked (403)" || bad "On answered $c"
c=$(code -H 'Host: lloquent.test' -H "x-hs-api: $KEY" http://127.0.0.1:18090/search?q=hello)
[ "$c" = 200 ] && ok "On: a clean request passes" || bad "On: clean request answered $c"
c=$(code -X POST -H 'Host: woodhouse.test' -H "x-hs-api: $KEY" -H 'Content-Type: application/json' --data '{"a":1}' "http://127.0.0.1:18090/hooks/$T43/github?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
[ "$c" = 200 ] && ok "On: ModSecurity-off hook path passes the same query" || bad "hook path answered $c"
c=$(code -X POST -H 'Host: lloquent.test' -H "x-hs-api: $KEY" -H 'Content-Type: application/json' --data '{"query":"{ a }"}' http://127.0.0.1:18090/api/graphql)
[ "$c" = 200 ] && ok "On: a JSON GraphQL body passes (no premature-EOF 200002)" || bad "graphql answered $c"
c=$(code -X POST -H 'Host: lloquent.test' -H "x-hs-api: $KEY" -H 'Content-Type: application/json' --data '{"query":"{ a }"}' http://127.0.0.1:18090/api/other)
[ "$c" = 200 ] && ok "On: a JSON body on a path with no 200002 exemption passes" || bad "JSON body without exemption answered $c"
head -c 25165824 /dev/zero > /tmp/dalton-checks-24m 2>/dev/null || head -c 25165824 /dev/zero > "$HERE/out/24m"
f=/tmp/dalton-checks-24m; [ -f $f ] || f="$HERE/out/24m"
r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -X POST -H 'Host: woodhouse.test' -H "x-hs-api: $KEY" --data-binary @$f "http://127.0.0.1:18090/hooks/$T43/github")
c=${r% *}; s=${r#* }
[ "$c" = 200 ] && awk -v s="$s" 'BEGIN{exit !(s < 1.0)}' && ok "On: 24 MiB hook body streams through in ${s}s" || bad "24 MiB hook: status $c in ${s}s"
rm -f "$f"

echo "5. rate limits (RATE_LIMIT)"
# burst <n> <host> <path> [curl args...]: n requests back to back from a
# public client address (resolved from X-Forwarded-For, as behind the ALB);
# prints how many got 429.
burst() {
  n=$1 h=$2 pth=$3; shift 3
  i=0; c429=0
  while [ $i -lt "$n" ]; do
    [ "$(code -H "Host: $h" -H "x-hs-api: $KEY" "$@" "http://127.0.0.1:18090$pth")" = 429 ] && c429=$((c429 + 1))
    i=$((i + 1))
  done
  echo $c429
}
PUB='X-Forwarded-For: 203.0.113.50'
dalton -e OTEL_ENABLED=false || bad "didn't start (RATE_LIMIT unset)"
r=$(burst 60 lloquent.test /same -H "$PUB")
[ "$r" = 0 ] && ok "off (default): 60 requests to one page, none refused" || bad "off: $r refused"
dalton -e OTEL_ENABLED=false -e RATE_LIMIT=dry-run || bad "didn't start with dry-run"
r=$(burst 60 lloquent.test /same -H "$PUB")
[ "$r" = 0 ] && ok "dry-run: none refused" || bad "dry-run: $r refused"
docker logs checks-dalton 2>&1 | grep -q 'limiting requests, dry run' && ok "dry-run: would-be refusals logged" || bad "dry-run: nothing logged"
dalton -e OTEL_ENABLED=false -e RATE_LIMIT=on || bad "didn't start with on"
r=$(burst 60 lloquent.test /same -H "$PUB")
[ "$r" -gt 0 ] && ok "on: same page 60x from one client, $r refused with 429" || bad "on: none refused"
r=$(burst 10 lloquent.test /same -H 'X-Forwarded-For: 203.0.113.51')
[ "$r" = 0 ] && ok "on: another client isn't affected" || bad "on: another client got $r refusals"
r=$(burst 60 lloquent.test /same)
[ "$r" = 0 ] && ok "on: private address (the ALB, containers) never limited" || bad "on: private address got $r refusals"
r=$(burst 60 woodhouse.test "/hooks/$T43/github" -X POST -H "$PUB" -H 'Content-Type: application/json' --data '{}')
[ "$r" = 0 ] && ok "on: signed webhook route exempt (60 POSTs, none refused)" || bad "on: webhook route got $r refusals"
dalton -e OTEL_ENABLED=false -e RATE_LIMIT=on -e RATE_LIMIT_PAGE_RPS=1000 -e RATE_LIMIT_SITE_RPS=5 || bad "didn't start with custom rates"
r=$(burst 40 lloquent.test "/p" -H 'X-Forwarded-For: 203.0.113.52')
[ "$r" -gt 0 ] && ok "on: RATE_LIMIT_SITE_RPS=5 applies across pages ($r of 40 refused)" || bad "on: site limit didn't apply"

echo "3. refusing to start"
docker rm -f checks-dalton >/dev/null 2>&1
docker run --rm --read-only --tmpfs /tmp -v "$FLEET/sites:/etc/nginx/templates:ro" "$IMAGE" >/dev/null 2>&1 \
  && bad "started without HS_API_KEY" || ok "no HS_API_KEY: exits non-zero"
docker run --rm --read-only --tmpfs /tmp -v "$FLEET/sites:/etc/nginx/templates:ro" -e HS_API_KEY=$KEY -e MODSEC_RULE_ENGINE=on "$IMAGE" >/dev/null 2>&1 \
  && bad "started with MODSEC_RULE_ENGINE=on" || ok "bad MODSEC_RULE_ENGINE: exits non-zero"
docker run --rm --read-only --tmpfs /tmp -v "$FLEET/sites:/etc/nginx/templates:ro" -e HS_API_KEY=$KEY "$IMAGE" >/dev/null 2>&1 \
  && bad "started with *_HOSTNAME unset" || ok "missing *_HOSTNAME: exits non-zero"
docker run --rm --read-only --tmpfs /tmp -v "$FLEET/sites:/etc/nginx/templates:ro" -e HS_API_KEY=$KEY -e RATE_LIMIT=yes "$IMAGE" >/dev/null 2>&1 \
  && bad "started with RATE_LIMIT=yes" || ok "bad RATE_LIMIT: exits non-zero"

echo "4. OpenTelemetry"
mkdir -p "$HERE/out/otel" && chmod 0777 "$HERE/out/otel" && rm -f "$HERE/out/otel/traces.jsonl"
cat > "$HERE/out/otel/config.yaml" <<'EOF'
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }
exporters:
  file: { path: /out/traces.jsonl }
service:
  pipelines:
    traces: { receivers: [otlp], exporters: [file] }
EOF
docker run -d --name checks-otel --network $NET --network-alias otel-collector \
  -v "$HERE/out/otel:/out" docker.io/otel/opentelemetry-collector-contrib:0.115.1 --config=/out/config.yaml >/dev/null
sleep 2
dalton -e OTEL_SAMPLE_RATIO=1.0 || bad "didn't start with OTel on"
PARENT=4bf92f3577b34da6a3ce929d0e0e4736
resp=$(curl -s -H 'Host: lloquent.test' -H "x-hs-api: $KEY" -H "traceparent: 00-$PARENT-00f067aa0ba902b7-01" http://127.0.0.1:18090/traced)
echo "$resp" | grep -q "\"traceparent\": \"00-$PARENT-" && ok "upstream received dalton's traceparent in the same trace" || bad "upstream traceparent: $(echo "$resp" | grep -o '"traceparent": "[^"]*"')"
curl -s -o /dev/null -H 'Host: woodhouse.test' -H "x-hs-api: $KEY" http://127.0.0.1:18090/api/me
sleep 7
if grep -q "$PARENT" "$HERE/out/otel/traces.jsonl" 2>/dev/null; then ok "span with the incoming trace id reached the Collector"; else bad "no span for trace $PARENT"; fi
grep -q '"dalton"' "$HERE/out/otel/traces.jsonl" 2>/dev/null && ok "service.name dalton" || bad "service.name dalton missing"
grep -q 'client.address' "$HERE/out/otel/traces.jsonl" 2>/dev/null && ok "client.address attribute present" || bad "client.address missing"
log=$(docker logs checks-dalton 2>/dev/null | grep '/traced' | tail -1)
echo "$log" | grep -q "trace_id=$PARENT" && ok "access log carries the trace id" || bad "access log: $log"

[ $fail = 0 ] && echo "all nginx checks passed" || echo "SOME CHECKS FAILED"
exit $fail
