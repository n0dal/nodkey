# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# simpay: SIMULATED payment provider for Nodkey Demo P tests. Not a real payment API.
# Build:  docker build -t nodkey/simpay:dev tools/simpay/
# Tests:  docker build --target test --progress=plain tools/simpay/
# TLS:    simpay gen-test-ca --out certs --dns-name simpay.internal   (TEST-ONLY CA)
#         docker run -v $PWD/certs:/etc/simpay/tls:ro nodkey/simpay:dev \
#           --config /etc/simpay/container-config.json --container-bind \
#           --tls-cert /etc/simpay/tls/simpay-TEST-ONLY-server.crt \
#           --tls-key /etc/simpay/tls/simpay-TEST-ONLY-server.key
#         (the key file is 0600: make it readable by uid 10003, e.g. chown, before mounting)
# Base image digests from `docker buildx imagetools inspect` (re-checked 2026-10-25).
# The build stage's gcc compiles ring's C/assembly; no OpenSSL is used anywhere.
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY fixtures ./fixtures
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/simpay /simpay

FROM build AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked 2>&1

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
LABEL org.opencontainers.image.title="simpay (SIMULATOR)" \
      org.opencontainers.image.description="SIMULATED payment provider for Nodkey tests. Not a real payment API." \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd -g 10003 simpay && useradd -u 10003 -g 10003 -M -s /usr/sbin/nologin simpay
COPY --from=build /simpay /usr/local/bin/simpay
COPY fixtures/demo-fixture.json fixtures/container-config.json /etc/simpay/
USER 10003:10003
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/simpay"]
# Binding 0.0.0.0 inside the container requires the explicit flag. Never publish these ports
# on a public interface; publish the admin port (8081) only to the test harness.
CMD ["--config", "/etc/simpay/container-config.json", "--container-bind"]
