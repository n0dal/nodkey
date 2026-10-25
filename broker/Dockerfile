# syntax=docker/dockerfile:1
# Build: docker build -t nodkey/broker:dev broker/
# Tests: docker build --target test --progress=plain broker/
FROM rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/nodkey-broker /nodkey-broker

FROM build AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked 2>&1

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
RUN groupadd -g 10002 nodkey-broker && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin nodkey-broker
COPY --from=build /nodkey-broker /usr/local/bin/nodkey-broker
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/nodkey-broker"]
CMD ["--config", "/etc/nodkey/broker.json"]
