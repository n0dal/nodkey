#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0

"""Second code path for the effect-v2 pending-effect digest vectors (spec section 3.2).

Python stdlib only. Shares no code with the Rust generator in gen/:
  1. re-encodes M from each vector's record with its own deterministic-CBOR encoder and compares
     it with cbor_hex;
  2. recomputes SHA-256("nodkey.pending.v1" || 0x00 || cbor) with hashlib and compares it with digest;
  3. requires every "reject" vector to be rejected by this encoder too.

  python3 -I verify_digest.py [digest-vectors.json]
"""
import base64, hashlib, json, os, re, sys

MAX_UINT = 2**53 - 1
LABEL = b"nodkey.pending.v1"


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")


def enc_uint(n):
    if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= MAX_UINT:
        raise ValueError("not a uint")
    return head(0, n)


def enc_text(s):
    b = s.encode("utf-8")
    return head(3, len(b)) + b


def enc_map(entries):
    entries = sorted(entries, key=lambda kv: kv[0])  # bytewise order of encoded keys
    if len({k for k, _ in entries}) != len(entries):
        raise ValueError("duplicate key")
    return head(5, len(entries)) + b"".join(k + v for k, v in entries)


def pending_id_bytes(s):
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}", s):
        raise ValueError("pending_id grammar")
    b = base64.urlsafe_b64decode(s + "==")
    if len(b) != 16 or base64.urlsafe_b64encode(b).decode().rstrip("=") != s:
        raise ValueError("pending_id not canonical")
    return b


def is_id(s, mx):
    return isinstance(s, str) and 1 <= len(s.encode()) <= mx and all(0x21 <= c <= 0x7E for c in s.encode())


GRAMMAR = {
    "account_id": r"[a-z0-9_]{1,32}",
    "currency": r"[A-Z]{3}",
    "text64": r"[\x20-\x7e]{0,64}",
    "text256": r"[\x20-\x7e]{0,256}",
}


def encode_record(r):
    pid = pending_id_bytes(r["pending_id"])
    for k, mx in (("broker_id", 128), ("wid", 256), ("ten", 128), ("approver_sub", 256)):
        if not is_id(r[k], mx):
            raise ValueError(k)
    types, params = r["param_types"], r["params"]
    if set(types) != set(params):
        raise ValueError("param key set")
    pm, tm = [], []
    for name, ty in types.items():
        v = params[name]
        if ty == "uint":
            pm.append((enc_text(name), enc_uint(v)))
        else:
            if not isinstance(v, str) or not re.fullmatch(GRAMMAR[ty], v):
                raise ValueError(name)
            pm.append((enc_text(name), enc_text(v)))
        tm.append((enc_text(name), enc_text(ty)))
    dm = []
    for k, v in r["display"].items():
        if isinstance(v, str):
            if not re.fullmatch(r"[\x20-\x7e]{0,64}", v):
                raise ValueError("display")
            dm.append((enc_text(k), enc_text(v)))
        else:
            dm.append((enc_text(k), enc_uint(v)))
    return enc_map([
        (enc_uint(0), head(2, 16) + pid),
        (enc_uint(1), enc_text(r["broker_id"])),
        (enc_uint(2), enc_text(r["wid"])),
        (enc_uint(3), enc_text(r["ten"])),
        (enc_uint(4), enc_text(r["approver_sub"])),
        (enc_uint(5), enc_text(r["op"])),
        (enc_uint(6), enc_uint(r["opv"])),
        (enc_uint(7), enc_map(pm)),
        (enc_uint(8), enc_uint(r["created_at"])),
        (enc_uint(9), enc_uint(r["expires_at"])),
        (enc_uint(10), enc_map(tm)),
        (enc_uint(11), enc_map(dm)),
    ])


def main(path):
    doc = json.load(open(path))
    ok = bad = 0
    for v in doc["vectors"]:
        try:
            m = encode_record(v["record"])
        except (ValueError, KeyError, TypeError) as e:
            m, err = None, e
        if v.get("expected") == "reject":
            if m is None:
                ok += 1
            else:
                bad += 1
                print(f"MISMATCH {v['id']}: expected reject, encoded")
            continue
        if m is None:
            bad += 1
            print(f"MISMATCH {v['id']}: rejected ({err})")
            continue
        d = hashlib.sha256(LABEL + b"\x00" + bytes.fromhex(v["cbor_hex"])).hexdigest()
        if m.hex() == v["cbor_hex"] and d == v["digest"] and re.fullmatch(r"[0-9a-f]{64}", v["digest"]):
            ok += 1
        else:
            bad += 1
            print(f"MISMATCH {v['id']}: cbor_equal={m.hex() == v['cbor_hex']} digest_equal={d == v['digest']}")
    print(f"digest vectors: {ok} agree, {bad} mismatches")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "digest-vectors.json")))
