# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# The build context is the REPOSITORY ROOT (the broker depends on crates/nodkey-grant):
# Build: docker build -f broker/Dockerfile -t nodkey/broker:dev .
# Tests: docker build -f broker/Dockerfile --target test --progress=plain .
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src/broker
COPY crates/nodkey-grant /src/crates/nodkey-grant
COPY broker/Cargo.toml broker/Cargo.lock ./
COPY broker/src ./src
COPY tests/vectors/effect-v2/digest-vectors.json /src/tests/vectors/effect-v2/digest-vectors.json
# Dev-only path dependencies (integration tests) are not needed for the release binary.
RUN sed -i '/^\[dev-dependencies\]/,/^\[/{/^nodkey-\(authority\|gateway\)/d}' Cargo.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/broker/target \
    cargo build --release --bin nodkey-broker && cp target/release/nodkey-broker /nodkey-broker

FROM build AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/broker/target \
    cargo test --release --lib 2>&1

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
RUN groupadd -g 10002 nodkey-broker && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin nodkey-broker
COPY --from=build /nodkey-broker /usr/local/bin/nodkey-broker
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/nodkey-broker"]
CMD ["--config", "/etc/nodkey/broker.json"]
