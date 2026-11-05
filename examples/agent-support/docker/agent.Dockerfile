# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Demo A agent-side image (LOCAL DEMO ONLY): the per-agent MCP front `nodkey-mcp`, the stdio
# shim `nodkey-mcp-stdio` (crates/nodkey-mcp-front) and the scripted, fully prompt-injected
# stand-in agent `demo-agent` (tools/demo-agent). Holds no secret. Build context: REPOSITORY ROOT.
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
COPY crates/nodkey-mcp-front/Cargo.toml crates/nodkey-mcp-front/Cargo.lock /src/crates/nodkey-mcp-front/
COPY crates/nodkey-mcp-front/src /src/crates/nodkey-mcp-front/src
COPY tools/demo-agent/Cargo.toml tools/demo-agent/Cargo.lock /src/tools/demo-agent/
COPY tools/demo-agent/src /src/tools/demo-agent/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/crates/nodkey-mcp-front/target \
    cd /src/crates/nodkey-mcp-front && cargo build --locked --release --bins \
 && cp target/release/nodkey-mcp target/release/nodkey-mcp-stdio /
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/tools/demo-agent/target \
    cd /src/tools/demo-agent && cargo build --locked --release --bin demo-agent \
 && cp target/release/demo-agent /

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
LABEL org.nodkey.warning="Demo A scripted agent (untrusted test tool) - local demo only"
# 10011 = the agent's registered uid (broker socket W peer, mcp.sock peer).
RUN groupadd -g 10011 support-bot && useradd -u 10011 -g 10011 -M -s /usr/sbin/nologin support-bot
COPY --from=build /nodkey-mcp /nodkey-mcp-stdio /demo-agent /usr/local/bin/
COPY tools/demo-agent/fixtures/ticket-T-1.txt /opt/demo-agent/ticket-T-1.txt
USER 10011:10011
