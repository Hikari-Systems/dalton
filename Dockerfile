# dalton: nginx reverse proxy + WAF (ModSecurity v3, OWASP CRS 4) with
# OpenTelemetry tracing, behind AWS ALB / CloudFront.
#
# Runtime: debian:<codename>-slim + nginx.org's nginx and nginx-module-otel
# packages (only those: none of the extra modules the official image carries).
# Builder: libmodsecurity, ModSecurity-nginx and headers-more, compiled as
# dynamic modules against the same nginx version (--with-compat).
#
#   docker build .                          # trixie-slim
#   docker build --build-arg DEBIAN=bookworm .   # bookworm-slim

ARG DEBIAN=trixie
ARG NGINX_VERSION=1.30.6
ARG NGINX_OTEL_VERSION=0.1.2
ARG MODSECURITY_VERSION=3.0.17
ARG MODSECURITY_NGINX_VERSION=1.0.4
ARG HEADERS_MORE_VERSION=0.41
ARG CRS_VERSION=4.30.0

# ============================================================== builder
FROM debian:${DEBIAN} AS builder
ARG NGINX_VERSION
ARG MODSECURITY_VERSION
ARG MODSECURITY_NGINX_VERSION
ARG HEADERS_MORE_VERSION
ARG CRS_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg dirmngr \
        build-essential autoconf automake libtool pkg-config \
        libpcre2-dev zlib1g-dev libssl-dev \
        libyajl-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY nginx-keys.txt /src/

# nginx source, signature checked against the release keys in nginx-keys.txt
# (fingerprints pinned there; keys fetched from nginx.org/keys).
RUN set -eux; \
    export GNUPGHOME="$(mktemp -d)"; \
    grep -vE '^\s*(#|$)' nginx-keys.txt | while read -r name fpr; do \
        curl -fsSL "https://nginx.org/keys/${name}.key" | gpg --batch --import; \
        gpg --batch --list-keys --with-colons "$fpr" | grep -q "^fpr:::::::::${fpr}:"; \
    done; \
    curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \
    curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz.asc"; \
    gpg --batch --status-fd 1 --verify "nginx-${NGINX_VERSION}.tar.gz.asc" "nginx-${NGINX_VERSION}.tar.gz" \
        | grep -E "VALIDSIG ($(grep -vE '^\s*(#|$)' nginx-keys.txt | awk '{print $2}' | paste -sd'|'))"; \
    tar xzf "nginx-${NGINX_VERSION}.tar.gz"; \
    gpgconf --kill all; rm -rf "$GNUPGHOME"

# libmodsecurity v3 (OWASP; pinned tag). Only the features dalton's rules use:
# PCRE2, JSON (yajl) and XML body parsers. Lua, GeoIP/MaxMind, ssdeep, LMDB
# and curl (remote rules) were linked in the Apache image but nothing used them.
RUN set -eux; \
    git clone --depth 1 --branch "v${MODSECURITY_VERSION}" --recurse-submodules --shallow-submodules \
        https://github.com/owasp-modsecurity/ModSecurity.git; \
    cd ModSecurity; \
    ./build.sh; \
    ./configure --prefix=/usr/local/modsecurity \
        --with-pcre2 --with-yajl --with-libxml \
        --without-lua --without-maxmind --without-geoip --without-ssdeep \
        --without-lmdb --without-curl \
        --disable-doxygen-doc --disable-examples --disable-dependency-tracking; \
    make -j"$(nproc)"; \
    make install; \
    strip --strip-unneeded /usr/local/modsecurity/lib/libmodsecurity.so.*.*.*

# ModSecurity-nginx connector and headers-more, as dynamic modules for the
# packaged nginx (--with-compat keeps the module ABI the same).
RUN set -eux; \
    git clone --depth 1 --branch "v${MODSECURITY_NGINX_VERSION}" https://github.com/owasp-modsecurity/ModSecurity-nginx.git; \
    git clone --depth 1 --branch "v${HEADERS_MORE_VERSION}" https://github.com/openresty/headers-more-nginx-module.git; \
    cd "nginx-${NGINX_VERSION}"; \
    MODSECURITY_INC=/usr/local/modsecurity/include MODSECURITY_LIB=/usr/local/modsecurity/lib \
    ./configure --with-compat \
        --add-dynamic-module=../ModSecurity-nginx \
        --add-dynamic-module=../headers-more-nginx-module; \
    make -j"$(nproc)" modules; \
    mkdir -p /out/modules; \
    cp objs/ngx_http_modsecurity_module.so objs/ngx_http_headers_more_filter_module.so /out/modules/; \
    strip --strip-unneeded /out/modules/*.so

# OWASP Core Rule Set, signature checked against the CRS project key.
RUN set -eux; \
    export GNUPGHOME="$(mktemp -d)"; \
    curl -fsSL https://coreruleset.org/security.asc | gpg --batch --import; \
    gpg --batch --list-keys --with-colons 36006F0E0BA167832158821138EEACA1AB8A6E72 >/dev/null; \
    base="https://github.com/coreruleset/coreruleset/releases/download/v${CRS_VERSION}"; \
    curl -fsSLo crs.tar.gz "${base}/coreruleset-${CRS_VERSION}-minimal.tar.gz"; \
    curl -fsSLo crs.tar.gz.asc "${base}/coreruleset-${CRS_VERSION}-minimal.tar.gz.asc"; \
    gpg --batch --status-fd 1 --verify crs.tar.gz.asc crs.tar.gz | grep -q 'VALIDSIG 36006F0E0BA167832158821138EEACA1AB8A6E72'; \
    tar xzf crs.tar.gz; \
    mv "coreruleset-${CRS_VERSION}" /out/coreruleset; \
    cp /out/coreruleset/crs-setup.conf.example /out/coreruleset/crs-setup.conf; \
    # The site files remove these rule IDs per path; fail the build if CRS
    # ever renames or drops one, rather than silently stop exempting.
    for id in 911100 920350 949110; do grep -q "id:${id}," /out/coreruleset/rules/*.conf; done; \
    cp /src/ModSecurity/unicode.mapping /out/unicode.mapping; \
    gpgconf --kill all; rm -rf "$GNUPGHOME"

# The runtime packages libmodsecurity and the modules link against, as Debian
# package names, so the runtime stage installs exactly those.
RUN set -eux; \
    for f in /usr/local/modsecurity/lib/libmodsecurity.so /out/modules/*.so; do \
        ldd "$f" | awk '/=> \// { print $3 }'; \
    done | grep -v /usr/local/modsecurity | sort -u | xargs -r realpath | xargs -r dpkg -S 2>/dev/null \
        | cut -d: -f1 | sort -u > /out/runtime-packages.txt; \
    cat /out/runtime-packages.txt

# ============================================================== runtime
FROM debian:${DEBIAN}-slim
ARG DEBIAN
ARG NGINX_VERSION
ARG NGINX_OTEL_VERSION

COPY --from=builder /out/runtime-packages.txt /tmp/runtime-packages.txt
COPY nginx-keys.txt /tmp/nginx-keys.txt

# nginx and its OpenTelemetry module from nginx.org's repository, pinned to the
# version the modules were built against. The repository key's fingerprint is
# checked before apt trusts it.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx.gpg; \
    gpg --show-keys --with-colons /usr/share/keyrings/nginx.gpg | grep -q "^fpr:::::::::$(awk '$1=="nginx_signing"{print $2}' /tmp/nginx-keys.txt):"; \
    echo "deb [signed-by=/usr/share/keyrings/nginx.gpg] https://nginx.org/packages/debian ${DEBIAN} nginx" \
        > /etc/apt/sources.list.d/nginx.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        "nginx=${NGINX_VERSION}-1~${DEBIAN}" \
        "nginx-module-otel=${NGINX_VERSION}+${NGINX_OTEL_VERSION}-1~${DEBIAN}" \
        gettext-base \
        $(cat /tmp/runtime-packages.txt); \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/* /tmp/runtime-packages.txt /tmp/nginx-keys.txt \
        /etc/nginx/conf.d /etc/nginx/nginx.conf /usr/share/nginx/html/*; \
    ln -sf /dev/stdout /var/log/nginx/access.log; \
    ln -sf /dev/stderr /var/log/nginx/error.log

# The shared library only (the static .a alone is ~200 MB).
COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so* /usr/local/modsecurity/lib/
COPY --from=builder /out/modules/ /usr/lib/nginx/modules/
COPY --from=builder /out/coreruleset/ /usr/local/coreruleset/
COPY --from=builder /out/unicode.mapping /etc/modsecurity/unicode.mapping
RUN echo /usr/local/modsecurity/lib > /etc/ld.so.conf.d/modsecurity.conf && ldconfig \
    && for m in /usr/lib/nginx/modules/*.so; do ! ldd "$m" | grep -q 'not found'; done

COPY nginx.conf /etc/nginx/nginx.conf
COPY dalton/ /etc/nginx/dalton/
COPY snippets/ /etc/nginx/snippets/
COPY modsecurity/ /etc/modsecurity/
COPY html/ /usr/share/nginx/html/
COPY --chmod=0755 docker-entrypoint.sh /docker-entrypoint.sh

# The fleet mounts its sites directory here (read-only).
RUN mkdir -p /etc/nginx/templates

# Non-root; nothing is written outside /tmp (the fleets run it read_only).
USER nginx
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD pid="$(cat /tmp/nginx/nginx.pid 2>/dev/null)" && [ -n "$pid" ] && test -d "/proc/$pid" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
STOPSIGNAL SIGQUIT
