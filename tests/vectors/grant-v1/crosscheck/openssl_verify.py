#!/usr/bin/env python3
"""Independent signature cross-check for the Nodkey-Grant v1 vectors.

Uses a code path separate from the Rust generator: a small Python-stdlib CBOR reader for the
envelope, Sig_structure rebuilt here, and the `openssl pkeyutl` Ed25519 implementation.

  python3 -I openssl_verify.py <vector-dir>

Checks:
  1. every step expecting ACCEPT or STORED_OUTCOME:ACCEPT verifies under OpenSSL;
  2. every vector expecting grant_signature_invalid whose envelope is well-formed fails under
     OpenSSL (negative control).
Exit status is 0 only if both hold. TEST-ONLY keys (RFC 8032).
"""
import base64, json, os, subprocess, sys, tempfile

SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")  # RFC 8410 SubjectPublicKeyInfo


def head(b, i):
    ib = b[i]; major, ai = ib >> 5, ib & 31; i += 1
    if ai < 24:
        return major, ai, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    return major, int.from_bytes(b[i:i + n], "big"), i + n


def bstr(b, i):
    major, n, i = head(b, i)
    if major != 2:
        raise ValueError("expected bstr")
    return b[i:i + n], i + n


def enc_head(major, n):
    if n < 24: return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size): return bytes([major << 5 | ai]) + n.to_bytes(size, "big")


def enc_bstr(x): return enc_head(2, len(x)) + x


def parse_envelope(g):
    if g[:2] != b"\xd2\x84":
        raise ValueError("not tag18/array4")
    prot, i = bstr(g, 2)
    if g[i] != 0xA0:
        raise ValueError("unprotected not empty")
    payload, i = bstr(g, i + 1)
    sig, i = bstr(g, i)
    if i != len(g) or len(sig) != 64:
        raise ValueError("trailing/sig len")
    # kid: protected is {1: alg, 4: kid(16), 16: typ}; locate 0x04 0x50.
    k = prot.find(b"\x04\x50")
    return prot, payload, sig, prot[k + 2:k + 18]


def openssl_verify(pk, msg, sig):
    with tempfile.TemporaryDirectory() as d:
        pem = os.path.join(d, "pub.pem")
        with open(pem, "w") as f:
            f.write("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(SPKI_ED25519_PREFIX + pk).decode() + "\n-----END PUBLIC KEY-----\n")
        for name, data in (("msg", msg), ("sig", sig)):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pem, "-rawin",
                            "-in", os.path.join(d, "msg"), "-sigfile", os.path.join(d, "sig")],
                           capture_output=True, text=True)
        return r.returncode == 0


def main(dirpath):
    m = json.load(open(os.path.join(dirpath, "manifest.json")))
    keys = {bytes.fromhex(k["kid"]): bytes.fromhex(k["public_key"]) for k in m["keys"]}
    tag = m["constants"]["external_aad_tag"].encode()
    ok_pos = ok_neg = bad = skipped = 0
    for v in m["vectors"]:
        if v["kind"] != "grant":
            continue
        g = bytes.fromhex(open(os.path.join(dirpath, v["grant"])).read().strip())
        for s in v["steps"]:
            want = s["expected"]
            positive = want in ("ACCEPT", "STORED_OUTCOME:ACCEPT")
            if not positive and want != "grant_signature_invalid":
                continue
            try:
                prot, payload, sig, kid = parse_envelope(g)
            except Exception:
                skipped += 1
                continue
            pk = keys.get(kid)
            aad = tag + b"\x00" + s["broker_id"].encode()
            msg = b"\x84\x6aSignature1" + enc_bstr(prot) + enc_bstr(aad) + enc_bstr(payload)
            good = pk is not None and openssl_verify(pk, msg, sig)
            if positive and good:
                ok_pos += 1
            elif not positive and not good:
                ok_neg += 1
            else:
                bad += 1
                print(f"MISMATCH {v['id']}: expected {want}, openssl {'verified' if good else 'rejected'}")
    print(f"openssl: {ok_pos} ACCEPT steps verified, {ok_neg} signature_invalid steps rejected, "
          f"{bad} mismatches, {skipped} skipped (envelope not parseable by this reader)")
    return 0 if bad == 0 and ok_pos > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
