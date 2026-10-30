# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# nodkey-authority for Demo 2 (LOCAL, INTENTIONALLY VULNERABLE demo stack; see compose.yaml).
# Build context: REPOSITORY ROOT.
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src/crates/nodkey-authority
COPY crates/nodkey-grant /src/crates/nodkey-grant
COPY crates/nodkey-authority/Cargo.toml crates/nodkey-authority/Cargo.lock ./
COPY crates/nodkey-authority/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/crates/nodkey-authority/target \
    cargo build --locked --release --bin nodkey-authority \
 && cp target/release/nodkey-authority /nodkey-authority

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
# State directory (key + issuance store). A new named volume copies this directory's owner and
# mode (10004, 0700), so only the authority uid can enter it.
RUN groupadd -g 10004 nodkey-authority \
 && useradd -u 10004 -g 10004 -M -s /usr/sbin/nologin nodkey-authority \
 && install -d -o 10004 -g 10004 -m 0700 /var/lib/nodkey-authority
COPY --from=build /nodkey-authority /usr/local/bin/nodkey-authority
USER 10004:10004
ENTRYPOINT ["/usr/local/bin/nodkey-authority"]
CMD ["run", "--config", "/etc/nodkey/authority.json", "--mounts-verified-externally"]
