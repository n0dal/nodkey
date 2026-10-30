# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# nodkey-gateway for Demo 2, built WITH the `test-login` feature (R3B-11): a login without
# credentials, for LOCAL development only. Never use this image outside the local demo.
# Build context: REPOSITORY ROOT.
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src/crates/nodkey-gateway
COPY crates/nodkey-grant /src/crates/nodkey-grant
COPY crates/nodkey-gateway/Cargo.toml crates/nodkey-gateway/Cargo.lock ./
COPY crates/nodkey-gateway/src ./src
COPY crates/nodkey-gateway/static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/crates/nodkey-gateway/target \
    cargo build --locked --release --features test-login,dev-tls --bin nodkey-gateway \
 && cp target/release/nodkey-gateway /nodkey-gateway

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
RUN groupadd -g 10005 nodkey-gateway \
 && useradd -u 10005 -g 10005 -M -s /usr/sbin/nologin nodkey-gateway
COPY --from=build /nodkey-gateway /usr/local/bin/nodkey-gateway
LABEL org.nodkey.test-login="compiled-in; LOCAL DEMO ONLY"
USER 10005:10005
ENTRYPOINT ["/usr/local/bin/nodkey-gateway"]
CMD ["--config", "/etc/nodkey/gateway.json"]
