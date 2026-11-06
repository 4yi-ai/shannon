# SQL-backed Temporal, built from checksum-verified official 1.29.1 releases.
# The PostgreSQL Official Image provides psql; no PostgreSQL server runs here.
FROM public.ecr.aws/docker/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139
USER root
RUN apk add --no-cache python3 curl ca-certificates
ARG TARGETARCH
RUN --mount=type=cache,id=shannon-temporal-1.29.1,target=/downloads \
    set -eu; \
    case "${TARGETARCH}" in \
      arm64) binary_sha=07bc2c0e4ce1d3face447c2aec73864909079e56bb79f5c1d0b82000118840b2 ;; \
      amd64) binary_sha=a5df05c0387054e50bbbc1c21cc491644f21ca917eee58baf58df120f2bd3e78 ;; \
      *) exit 1 ;; \
    esac; \
    binary="/downloads/temporal_1.29.1_linux_${TARGETARCH}.tar.gz"; \
    source=/downloads/temporal-source-1.29.1.tar.gz; \
    if ! echo "$binary_sha  $binary" | sha256sum -c - >/dev/null 2>&1; then curl --retry 3 --connect-timeout 20 --max-time 1800 -fsSL "https://github.com/temporalio/temporal/releases/download/v1.29.1/temporal_1.29.1_linux_${TARGETARCH}.tar.gz" -o "$binary"; fi; \
    if ! echo "67cd88fac75f2b398eaf8c131403809121d745be9e957039751e8b391036b7a5  $source" | sha256sum -c - >/dev/null 2>&1; then curl --retry 3 --connect-timeout 20 --max-time 900 -fsSL https://codeload.github.com/temporalio/temporal/tar.gz/refs/tags/v1.29.1 -o "$source"; fi; \
    echo "$binary_sha  $binary" | sha256sum -c -; \
    echo "67cd88fac75f2b398eaf8c131403809121d745be9e957039751e8b391036b7a5  $source" | sha256sum -c -; \
    tar -xzf "$binary" -C /usr/local/bin temporal-server temporal-sql-tool; \
    mkdir -p /tmp/temporal-source /etc/temporal /usr/share/licenses/temporal; \
    tar -xzf "$source" -C /tmp/temporal-source temporal-1.29.1/schema/postgresql temporal-1.29.1/LICENSE; \
    mv /tmp/temporal-source/temporal-1.29.1/schema /etc/temporal/schema; \
    mv /tmp/temporal-source/temporal-1.29.1/LICENSE /usr/share/licenses/temporal/LICENSE; \
    rm -rf /tmp/temporal-source; \
    temporal-server --version
COPY server.py /etc/temporal/standalone-server.py
USER postgres
ENTRYPOINT ["python3", "/etc/temporal/standalone-server.py"]
