# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# nodkey-payments-adapter for Demo P (LOCAL, INTENTIONALLY VULNERABLE demo stack; see compose.yaml).
# Build context: REPOSITORY ROOT. Built WITHOUT rustls' tls12 feature (release binary only).
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src/crates/nodkey-payments-adapter
COPY crates/nodkey-grant /src/crates/nodkey-grant
COPY crates/nodkey-payments-adapter/Cargo.toml crates/nodkey-payments-adapter/Cargo.lock ./
COPY crates/nodkey-payments-adapter/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/crates/nodkey-payments-adapter/target \
    cargo build --locked --release --bin nodkey-payments-adapter \
 && cp target/release/nodkey-payments-adapter /nodkey-payments-adapter

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
# /etc/nodkey-adapter: operator files (registry, config, pinned CA), bind-mounted read-only, root-owned
# directory without group/other write (payments-adapter-v1 §2).
# /run/adapter-secrets: a named volume; files owned by the adapter uid, mode 0400 (filled by the
# one-shot `adapter-secrets-init` service). The directory itself is root-owned 0711.
RUN groupadd -g 10006 nodkey-adapter \
 && useradd -u 10006 -g 10006 -M -s /usr/sbin/nologin nodkey-adapter \
 && install -d -o root -g root -m 0755 /etc/nodkey-adapter \
 && install -d -o root -g root -m 0711 /run/adapter-secrets
COPY --from=build /nodkey-payments-adapter /usr/local/bin/nodkey-payments-adapter
USER 10006:10006
ENTRYPOINT ["/usr/local/bin/nodkey-payments-adapter"]
CMD ["--config", "/etc/nodkey-adapter/config.json"]
