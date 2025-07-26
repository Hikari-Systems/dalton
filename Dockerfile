FROM httpd:2.4-bookworm AS httpd-source

FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libtool \
    autoconf \
    automake \
    pkg-config \
    git \
    wget \
    curl \
    gnupg \
    libpcre3-dev \
    libxml2-dev \
    libcurl4-openssl-dev \
    libyajl-dev \
    libgeoip-dev \
    liblua5.3-dev \
    libfuzzy-dev \
    libmaxminddb-dev \
    apache2-dev \
    libapr1-dev \
    libaprutil1-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Apache installation from official image
COPY --from=httpd-source /usr/local/apache2 /usr/local/apache2

# Create static build directory
RUN mkdir -p /static-build/{lib,modules,apache2}

# Copy Apache installation for later use
RUN cp -r /usr/local/apache2 /static-build/

# Build mod_security
WORKDIR /tmp
RUN git clone --depth 1 --recursive https://github.com/SpiderLabs/ModSecurity.git && \
    cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure --enable-pcre-study \
                --enable-lua \
                --enable-geoip \
                --enable-fuzzy-hashing && \
    make && \
    make install && \
    ldconfig

# Build mod_security Apache connector  
RUN cd /tmp && \
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-apache.git && \
    cd ModSecurity-apache && \
    ./autogen.sh && \
    ./configure --with-libmodsecurity=/usr/local/modsecurity \
                --with-apxs=/usr/local/apache2/bin/apxs && \
    make && \
    # Ensure modules directory exists
    mkdir -p /static-build/modules && \
    # Extract the .so file from the libtool archive
    /usr/share/apr-1.0/build/libtool --mode=install install -c src/mod_security3.la /static-build/ && \
    # Move the .so file to the modules directory
    mv /static-build/mod_security3.so /static-build/modules/ && \
    # Verify it's there
    ls -la /static-build/modules/mod_security3.so

# Build mod_evasive
RUN cd /tmp && \
    git clone --depth 1 https://github.com/jvdmr/mod_evasive.git && \
    cd mod_evasive && \
    /usr/local/apache2/bin/apxs -c mod_evasive24.c && \
    cp .libs/mod_evasive24.so /static-build/modules/mod_evasive24.so

# Download OWASP Core Rule Set with GPG signature verification
RUN cd /tmp && \
    # Download the release file and signature
    wget -O coreruleset-4.0.0.tar.gz https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz && \
    wget -O coreruleset-4.0.0.tar.gz.asc https://github.com/coreruleset/coreruleset/releases/download/v4.0.0/coreruleset-4.0.0.tar.gz.asc && \
    # Import OWASP CRS project's GPG key
    gpg --fetch-key https://coreruleset.org/security.asc || \
    gpg --keyserver pgp.mit.edu --recv-keys 0x38EEACA1AB8A6E72 || \
    gpg --keyserver keyserver.ubuntu.com --recv-keys 36006F0E0BA167832158821138EEACA1AB8A6E72 && \
    # Verify the signature
    gpg --verify coreruleset-4.0.0.tar.gz.asc coreruleset-4.0.0.tar.gz && \
    # Extract the verified archive
    tar -xzf coreruleset-4.0.0.tar.gz && \
    mv coreruleset-4.0.0 /static-build/coreruleset && \
    # Clean up
    rm -f coreruleset-4.0.0.tar.gz coreruleset-4.0.0.tar.gz.asc

# Strip symbols from binaries to reduce size
RUN strip /static-build/modules/*.so

# Copy required runtime libraries (including ModSecurity)
RUN mkdir -p /static-build/runtime-libs && \
    cp /usr/local/modsecurity/lib/libmodsecurity.so* /static-build/runtime-libs/ 2>/dev/null || true && \
    for lib in /static-build/modules/*.so; do \
        ldd "$lib" | grep "=> /" | awk '{print $3}' | xargs -I {} cp {} /static-build/runtime-libs/ 2>/dev/null || true; \
    done

# Production stage - minimal runtime container
FROM debian:bookworm-slim

# Install only essential runtime dependencies that aren't in slim
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    ca-certificates \
    libapr1 \
    libaprutil1 \
    libaprutil1-ldap \
    libpcre3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create www-data user with consistent UID/GID across stages
# RUN groupadd -r -g 33 www-data && useradd -r -u 33 -g www-data www-data

# Copy Apache installation from builder
COPY --from=builder /static-build/apache2 /usr/local/apache2

# Copy security modules
COPY --from=builder /static-build/modules/*.so /usr/local/apache2/modules/

# Copy required runtime libraries
COPY --from=builder /static-build/runtime-libs/* /usr/local/lib/

# Copy OWASP Core Rule Set
COPY --from=builder /static-build/coreruleset /usr/local/coreruleset

# Update library cache
RUN ldconfig

# Set working directory and PATH
WORKDIR /usr/local/apache2
ENV PATH=/usr/local/apache2/bin:$PATH

# Create necessary directories with proper ownership
RUN mkdir -p /var/log/mod_evasive \
    && mkdir -p /var/log/modsec_audit \
    && mkdir -p /etc/modsecurity \
    && mkdir -p /usr/local/apache2/logs \
    && mkdir -p /usr/local/apache2/run \
    && chown -R www-data:www-data /var/log/mod_evasive /var/log/modsec_audit \
    && chown -R www-data:www-data /usr/local/apache2/logs \
    && chown -R www-data:www-data /usr/local/apache2/run

# Copy configuration files
COPY modsecurity.conf /etc/modsecurity/
COPY security.conf /usr/local/apache2/conf/extra/
COPY httpd-nonroot.conf /usr/local/apache2/conf/

# Configure Apache for non-root operation
RUN echo "Include conf/httpd-nonroot.conf" >> /usr/local/apache2/conf/httpd.conf && \
    echo "LoadModule evasive24_module modules/mod_evasive24.so" >> /usr/local/apache2/conf/httpd.conf && \
    echo "LoadModule security3_module modules/mod_security3.so" >> /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/security.conf" >> /usr/local/apache2/conf/httpd.conf

# Switch to non-privileged user
USER www-data

EXPOSE 3000

# Container health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/healthcheck || exit 1

CMD ["httpd", "-D", "FOREGROUND"]