# Dalton

The web application firewall and name-based reverse proxy on every spot fleet
node: nginx with ModSecurity v3 and the OWASP Core Rule Set, sending
OpenTelemetry traces to the node's Collector. The ALB (behind CloudFront)
sends every host to port 3000 here; the fleet's site files route each Host to
its controller.

| Part | Version |
|---|---|
| Base | `debian:trixie-slim` (`--build-arg DEBIAN=bookworm` for bookworm-slim) |
| nginx | 1.30.6, nginx.org packages |
| OpenTelemetry | nginx-otel 0.1.2 (`nginx-module-otel`), OTLP/gRPC |
| ModSecurity | libmodsecurity 3.0.17, ModSecurity-nginx 1.0.4 |
| OWASP CRS | 4.30.0 (signature checked) |
| headers-more | 0.41 (to drop the `Server` header) |

Versions are `ARG`s at the top of the `Dockerfile`. Source tarballs are
checked against the signing keys in `nginx-keys.txt` and the CRS project key.

## Configuration (environment)

| Variable | Default | |
|---|---|---|
| `HS_API_KEY` | required | The `x-hs-api` value CloudFront injects. Requests without it get 403. dalton won't start without it. |
| `MODSEC_RULE_ENGINE` | `DetectionOnly` | `On` blocks; `DetectionOnly` only logs to the audit log (stderr); `Off`. The fleets set `On`. |
| `*_HOSTNAME`, `ENV_NAME`, `ENV_PREFIX`, `BRANCH_NAME` | | Filled into the site templates. A site using one that isn't set stops dalton starting. |
| `RATE_LIMIT` | `off` | Per-client request rate limits (what mod_evasive was meant to do; the Apache image built it but never enabled it). `dry-run` logs `limiting requests, dry run` without refusing; `on` answers 429. |
| `RATE_LIMIT_PAGE_RPS` | `20` | Requests a second per client IP to one URI (mod_evasive's `DOSPageCount`), with a burst of the same size. |
| `RATE_LIMIT_SITE_RPS` | `100` | Requests a second per client IP to the whole node (`DOSSiteCount`), with a burst of the same size. |
| `OTEL_ENABLED` | `true` | |
| `OTEL_EXPORTER_ENDPOINT` | `otel-collector:4317` | The node's Collector, OTLP over **gRPC** (its config needs a `grpc` receiver). |
| `OTEL_SERVICE_NAME` | `dalton` | |
| `OTEL_SAMPLE_RATIO` | `1.0` | For requests without a sampled `traceparent`; a sampled parent is always followed. |

dalton continues an incoming W3C `traceparent` and sends its own to the
upstream, so controller spans are children of dalton's. The access log line
ends with `trace_id=…`.

The container runs `read_only` as the `nginx` user and writes only under
`/tmp` (rendered config, pid, spooled request bodies): give it a tmpfs there
(the fleets use 256 MiB). The healthcheck reads `/tmp/nginx/nginx.pid`.

## Site files

The fleet mounts its `sites/` directory read-only at `/etc/nginx/templates`.
Each `NNN-name.conf` is an nginx `server{}` (with its `upstream{}` blocks and
any `map`s) and may use `${SOMETHING_HOSTNAME}` placeholders. A minimal site:

```nginx
upstream s030_example_controller {
  zone s030_example_controller 64k;
  server example-controller:3000 resolve;   # resolved at run time
}
server {
  server_name ${EXAMPLE_HOSTNAME};
  include /etc/nginx/snippets/server-common.conf;    # listen 3000, denies
  include /etc/nginx/snippets/hs-api-required.conf;  # x-hs-api or 403
  set $dalton_forwarded_proto https;                 # X-Forwarded-Proto: https

  location / {
    include /etc/nginx/snippets/methods-default.conf;   # GET HEAD POST
    proxy_pass http://s030_example_controller;
  }
  location /api/graphql {
    include /etc/nginx/snippets/methods-default.conf;
    modsecurity_rules 'SecRuleRemoveById 200002';
    proxy_pass http://s030_example_controller;
  }
}
```

The pieces, in `snippets/`:

- `methods-*.conf`: one per location (nginx `limit_except` can't be
  server-wide). `default` GET/HEAD/POST, `mcp` +DELETE, `sso` +PUT/DELETE,
  `login` GET/POST/DELETE, `post`, `post-options`, `put`.
- `hs-api-required.conf`, `hs-api-required-except-landing.conf` (the latter
  leaves `/` and `/index.html` public).
- `unbuffered-body.conf`: ModSecurity off and the body streamed to the
  upstream (signed webhooks, uploads). Pair it with `client_max_body_size`.
- `websocket.conf`: pass `Upgrade` through (set `proxy_read_timeout` beside it).
- `static-root.conf`: dalton's static page, for paths no proxy covers.
- `ratelimit-exempt.conf`: take a location out of `RATE_LIMIT` (woodhouse's
  signed webhooks use it: GitHub and Linear deliver in bursts from a few
  addresses).
- `security-headers.conf`: include it again in any block that has its own
  `add_header`.

Rules that keep sites correct:

- **Don't use `proxy_set_header` in a site.** One at location level drops
  every header dalton sets (Host, X-Forwarded-*). Switch values through the
  variables: `$dalton_forwarded_proto`, `$dalton_csp`, `$dalton_xfo`,
  `$dalton_hsts`; WebSockets through `websocket.conf`.
- **Set header variables before the x-hs-api `include`**, so its 403s carry
  them too.
- **Upstreams are `server name:port resolve`** in an `upstream` with a `zone`,
  so a controller that isn't running doesn't stop dalton starting (it gets 502).
- Apache's `ProxyPass /x` matched `/x` and `/x/...` but not `/xy`. Where that
  matters, use `location ~ "^/x(/|$)"`.
- A regex location wins over a longer prefix. Anchored regexes without
  metacharacters (`^/api/auth/sessions`) are better written as prefix
  locations, which can also strip a prefix in `proxy_pass`.

## Defaults applied to every site

- Real client IP: `X-Forwarded-For` from the trusted hops in
  `dalton/realip-cloudfront.conf`, generated by `scripts/gen-realip.py` from
  `ip-ranges.json` (private ranges, every `CLOUDFRONT_ORIGIN_FACING` prefix,
  and the 23 the Apache image trusted). Refresh the JSON and rerun it.
- Upstream requests: HTTP/1.1, a new connection each time, `Host` preserved,
  `X-Forwarded-For` (the incoming chain plus the client), `X-Forwarded-Host`,
  `X-Forwarded-Server`, `X-Forwarded-Proto` passed through unless a site sets it.
- Timeouts 30 s (sites raise `proxy_read_timeout` for streams), keep-alive 5 s.
  Responses are never buffered (SSE streams as it's written).
- Body limit 12.5 MiB (`client_max_body_size 13107200`, = ModSecurity's
  `SecRequestBodyLimit`); routes that take more set their own.
- Security headers on every response: CSP `default-src 'self';
  frame-ancestors 'none'`, `X-Frame-Options DENY`, HSTS, nosniff,
  `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`. Like Apache's
  `Header always set`, they are added beside any the upstream sends. No
  `Server` or `X-Powered-By` header is sent.
- Rate limits (`RATE_LIMIT`, off by default): keyed on the real client IP;
  private addresses (the ALB's health checks, other containers) are never
  limited, as mod_evasive's `DOSWhitelist` had it, and neither is `/mcp` on
  any vhost: claude.ai's MCP connector reaches every server from a few shared
  egress addresses, so per-IP limits would throttle all its users together. There's no equivalent of
  `DOSBlockingPeriod`: a client over the rate is refused per request, not
  banned for a time.
- CRS doesn't read the JSON-RPC body on `/mcp` (Claude Code's `_meta`
  argument names and free-form tool arguments set off 930120, 942100,
  932130 and more), nor the GraphQL document (`json.query`) on
  `/api/graphql` and `/api/open-graphql` (its `$variables` and field names
  set off 942290 and 932235). GraphQL variables are still inspected. See
  `modsecurity/crs-overrides.conf`.
- ModSecurity: `modsecurity/modsecurity.conf` (body access, JSON/XML parsers,
  limits, audit log to stderr), CRS 4 with plugins, `crs-overrides.conf`.

## Differences from the Apache image

Measured with `test/parity.py` (below). Everything else matched.

- **Body limits apply to proxied bodies**, with or without a Content-Length.
  Apache's `LimitRequestBody` didn't apply to a proxied body. Over 12.5 MiB is
  413 unless the route sets more (5drive photo uploads 32 MiB, woodhouse
  hooks/artefacts, homestretch ingest), and a chunked body is stopped at the
  same limit.
- **Redirects from upstreams are relative** (`/landed`), where Apache rewrote
  them to `http://host/landed`.
- `X-Forwarded-For` keeps the trusted hops in the middle of the chain. The
  first entry (the client's own claim) and the last (the resolved client) are
  as before.
- `Server` and an upstream's `X-Powered-By` are dropped. Apache's `unset`
  never took effect on them.
- login.* answers `HEAD` with 405, as `014-login.conf` intended (Apache let
  HEAD through as a GET).
- An upstream that doesn't answer in time is 504 (Apache said 502); the
  timeouts themselves are the same.
- A missing dotfile or backup file on the static root is 403 rather than 404.
- A request that declares a body but fails the x-hs-api check is refused at
  once, without reading the body.
- `LimitRequestFields 100` has no nginx equivalent. Header size is still
  bounded (8 KiB per line).

## Testing

```sh
docker build -t dalton:nginx-dev .
# Same requests to the Apache image and this one, per fleet; exit 1 on a regression.
python3 -I test/parity.py --fleet ../hs-backend-spot --apache-image ghcr.io/hikari-systems/dalton:apache-final
python3 -I test/parity.py --fleet ../hs-bae-spot     --apache-image ghcr.io/hikari-systems/dalton:apache-final
python3 -I test/parity.py --fleet ../rally-backend-spot --apache-image ghcr.io/hikari-systems/dalton:apache-final --slow
# CRS false positives: every GraphQL operation in the UIs (extracted from their
# sources under the repos root) and realistic Claude Code MCP calls, with
# ModSecurity On. Fails if anything legitimate is blocked or an attack isn't.
python3 -I test/crs-replay.py dalton:nginx-dev ../hs-backend-spot/sites ..
# nginx-only: ModSecurity On, rate limits, startup without upstreams, refusing bad env, OpenTelemetry.
sh test/nginx-checks.sh dalton:nginx-dev ../hs-backend-spot
```

Each `parity.py` run writes every case's details to `test/out/<fleet>.json`.
