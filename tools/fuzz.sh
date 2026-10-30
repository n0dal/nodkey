#!/bin/sh
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Short cargo-fuzz pass for nodkey-grant, the broker (protocol v2 request lines) and the
# payments adapter (provider-response classification). See docs/supply-chain.md.
#
# Runs INSIDE a container (nightly toolchain and cargo-fuzz are never installed on the host):
#   docker run -d --name nodkey-fuzz -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/build/target \
#     rust:1.99-slim-trixie@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb sleep infinity
#   docker exec nodkey-fuzz sh -c 'apt-get update && apt-get install -y g++ python3 && \
#     rustup toolchain install nightly --profile minimal && cargo install --locked cargo-fuzz'
#   docker exec nodkey-fuzz sh tools/fuzz.sh seeds
#   docker exec nodkey-fuzz sh tools/fuzz.sh build
#   docker exec nodkey-fuzz sh tools/fuzz.sh run 600      # seconds per target, targets in parallel
#   docker rm -f -v nodkey-fuzz
#
# Working corpora live under /build/corpus (container filesystem); only seeds and minimized
# reproducers are written into the repository (fuzz/seeds, fuzz/artifacts).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${FUZZ_WORK:-/build/fuzzwork}
# crate-dir:target
TARGETS="crates/nodkey-grant:verify_raw crates/nodkey-grant:verify_resigned broker:v2_request_line crates/nodkey-payments-adapter:provider_response"

seeds() {
python3 -I - "$ROOT" <<'PY'
import base64, json, os, sys
root = sys.argv[1]
vec = os.path.join(root, "tests/vectors/grant-v1")
m = json.load(open(os.path.join(vec, "manifest.json")))
reqs = []
for v in m["vectors"]:
    for st in v.get("steps", []):
        r = st.get("request")
        if r is None:
            continue
        # Same order as fuzz_targets/common.rs (first appearance; serde_json key order = sorted).
        k = json.dumps(r, sort_keys=True, separators=(",", ":"))
        if k not in reqs:
            reqs.append(k)
def req_index(v):
    for st in v.get("steps", []):
        if "request" in st:
            return reqs.index(json.dumps(st["request"], sort_keys=True, separators=(",", ":")))
    return 0
raw = os.path.join(root, "crates/nodkey-grant/fuzz/seeds/verify_raw")
res = os.path.join(root, "crates/nodkey-grant/fuzz/seeds/verify_resigned")
os.makedirs(raw, exist_ok=True); os.makedirs(res, exist_ok=True)
def head(b, i):  # CBOR major-type head, definite length
    ai = b[i] & 0x1f; i += 1
    if ai < 24: return ai, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    return int.from_bytes(b[i:i+n], "big"), i + n
n = 0
for v in m["vectors"]:
    if "grant" not in v:
        continue
    g = bytes.fromhex(open(os.path.join(vec, v["grant"])).read().strip())
    idx = req_index(v)
    open(os.path.join(raw, v["id"]), "wb").write(bytes([idx, 0]) + g)
    t = base64.urlsafe_b64encode(g).rstrip(b"=")
    open(os.path.join(raw, v["id"] + ".b64"), "wb").write(bytes([idx, 1]) + t)
    # payload = 3rd element of the COSE_Sign1 array (only for well-formed d2 84 envelopes)
    try:
        if g[:2] != b"\xd2\x84": raise ValueError
        i = 2
        L, i = head(g, i); i += L          # protected bstr
        if g[i] != 0xa0: raise ValueError
        i += 1
        L, i = head(g, i)
        open(os.path.join(res, v["id"]), "wb").write(bytes([idx]) + g[i:i+L])
    except Exception:
        pass
    n += 1
print("grant seeds:", n, "requests:", len(reqs))
PY
python3 -I - "$ROOT" <<'PY'
import os, sys
root = sys.argv[1]
d = os.path.join(root, "broker/fuzz/seeds/v2_request_line"); os.makedirs(d, exist_ok=True)
lines = [
 '{"v":2,"id":"r1","op":"effect.propose","args":{"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_cents":12500},"approver":{"ten":"acme","sub":"alice"}}}',
 '{"v":2,"id":"r2","op":"effect.status","args":{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA"}}',
 '{"v":2,"id":"r3","op":"effect.execute","args":{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA","grant":"0oRYJaMBMgRQ"}}',
 '{"v":1,"id":"x","op":"a","args":{}}',
 '{"v":2,"id":"r4","op":"refund.attempt","args":{"subject":{"ten":"t","sub":"s"},"n":1.5e3,"s":"\\u00e9\\ud83d\\ude00"}}',
 '{"v":2,"id":"r5","op":"x","args":{"a":[[[[[[[[1]]]]]]]],"b":{"c":null,"d":true}}}',
]
for i, l in enumerate(lines):
    open(os.path.join(d, "seed%02d" % i), "wb").write(l.encode())
p = os.path.join(root, "crates/nodkey-payments-adapter/fuzz/seeds/provider_response"); os.makedirs(p, exist_ok=True)
ok = b'{"id":"re_ABCDEFGH1234","object":"refund","amount":500,"charge":"ch_demoorder0001","currency":"usd","status":"succeeded","reference":"REFabc_-","reason":null,"created":1}'
bodies = {
 "created": (200, ok),
 "find1": (200, b'{"object":"list","data":[' + ok + b'],"has_more":false}'),
 "find0": (200, b'{"object":"list","data":[],"has_more":false}'),
 "idem": (200, b'{"key":"idem_key_fixture","state":"done"}'),
 "e400": (400, b'{"error":{"code":"charge_already_refunded","message":"x"}}'),
 "e404": (404, b'{"error":{"code":"resource_missing"}}'),
 "e409": (409, b'{"error":{"code":"idempotency_key_in_progress"}}'),
 "e429": (429, b'{}'),
 "e500": (500, b''),
}
# layout: status u16 BE, flags (bit0 json content type, bit1 body present, bit2 body read error), body
for k, (st, b) in bodies.items():
    open(os.path.join(p, k), "wb").write(st.to_bytes(2, "big") + bytes([0b011]) + b)
print("broker seeds:", len(lines), "payments seeds:", len(bodies))
PY
}

build() {
  for t in $TARGETS; do
    dir=${t%%:*}; name=${t##*:}
    # Start from the crate's own Cargo.lock so the fuzzed dependency versions are the shipped ones
    # (cargo only adds the harness-only packages such as libfuzzer-sys).
    [ -f "$ROOT/$dir/fuzz/Cargo.lock" ] || cp "$ROOT/$dir/Cargo.lock" "$ROOT/$dir/fuzz/Cargo.lock"
    (cd "$ROOT/$dir" && cargo +nightly fuzz build -O "$name")
  done
}

run() {
  secs=${1:-600}
  mkdir -p "$WORK"
  for t in $TARGETS; do
    dir=${t%%:*}; name=${t##*:}
    corpus="$WORK/corpus/$name"; mkdir -p "$corpus" "$ROOT/$dir/fuzz/artifacts/$name"
    (cd "$ROOT/$dir" && cargo +nightly fuzz run -O "$name" "$corpus" "fuzz/seeds/$name" -- \
        -max_total_time="$secs" -rss_limit_mb=2048 -timeout=10 -max_len=8192 -print_final_stats=1 \
        -artifact_prefix="$ROOT/$dir/fuzz/artifacts/$name/" \
        > "$WORK/$name.log" 2>&1; echo "exit=$?" >> "$WORK/$name.log") &
  done
  wait
  for t in $TARGETS; do name=${t##*:}; echo "== $name"; tail -n 25 "$WORK/$name.log"; done
}

cmd=${1:-}; shift || true
case "$cmd" in
  seeds) seeds ;;
  build) build ;;
  run) run "$@" ;;
  *) echo "usage: $0 seeds|build|run [seconds]" >&2; exit 2 ;;
esac
