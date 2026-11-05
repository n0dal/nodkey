# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# mailsink: SIMULATED mail sink for Demo A (delivers no mail; LOCAL DEMO ONLY). Build context:
# REPOSITORY ROOT.
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src/tools/mailsink
COPY tools/mailsink/Cargo.toml tools/mailsink/Cargo.lock ./
COPY tools/mailsink/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/tools/mailsink/target \
    cargo build --locked --release --bin mailsink && cp target/release/mailsink /mailsink

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
LABEL org.nodkey.warning="SIMULATED mail sink - delivers no mail - local demo only"
RUN groupadd -g 10012 mailsink && useradd -u 10012 -g 10012 -M -s /usr/sbin/nologin mailsink
COPY --from=build /mailsink /usr/local/bin/mailsink
USER 10012:10012
# The DB password is read from the compose secret at start; it never appears in the image or env file.
ENTRYPOINT ["sh", "-c", "MAILSINK_DATABASE=\"host=db port=5432 dbname=ledger user=nodkey_mailsink password=$(cat /run/secrets/db_mailsink_password)\" exec /usr/local/bin/mailsink --admin 172.30.40.40:12121 --poll-ms 250 --container-bind"]
