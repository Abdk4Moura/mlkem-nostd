"""Slow, obviously-correct Python reference for FIPS 203.

Used to validate the Rust implementation and to settle details (inverse NTT
convention, ByteDecode12 reduction, key-check semantics) against the official
NIST ACVP vectors.  Not constant time, not fast, not shipped.
"""

import hashlib
import json
import os
import sys

Q = 3329
N = 256


def brv7(x):
    return int(f"{x:07b}"[::-1], 2)


ZETAS = [pow(17, brv7(i), Q) for i in range(128)]
ZETAS_INV = [pow(17, (Q - 1 - brv7(i)) % (Q - 1), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * brv7(i) + 1, Q) for i in range(128)]


def ntt(f, inverse=False):
    f = list(f)
    if not inverse:
        i = 1
        length = 128
        while length >= 2:
            start = 0
            while start < 256:
                zeta = ZETAS[i]
                i += 1
                for j in range(start, start + length):
                    t = zeta * f[j + length] % Q
                    f[j + length] = (f[j] - t) % Q
                    f[j] = (f[j] + t) % Q
                start += 2 * length
            length //= 2
        return f
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
            start += 2 * length
        length *= 2
    return [x * 3303 % Q for x in f]


def ntt_inv_alt(f):
    """Variant using explicit inverse roots."""
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS_INV[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
            start += 2 * length
        length *= 2
    return [x * 3303 % Q for x in f]


def base_case_multiply(a0, a1, b0, b1, gamma):
    return ((a0 * b0 + a1 * b1 * gamma) % Q,
            (a0 * b1 + a1 * b0) % Q)


def multiply_ntts(a, b):
    c = [0] * 256
    for i in range(128):
        c[2 * i], c[2 * i + 1] = base_case_multiply(
            a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], GAMMAS[i])
    return c


def byte_encode(f, d):
    if d == 12:
        bits = []
        for x in f:
            assert 0 <= x < Q
            bits.extend((x >> b) & 1 for b in range(12))
        out = bytearray()
        for i in range(0, len(bits), 8):
            v = 0
            for j in range(8):
                v |= bits[i + j] << j
            out.append(v)
        return bytes(out)
    mask = (1 << d) - 1
    bits = []
    for x in f:
        assert 0 <= x <= mask
        bits.extend((x >> b) & 1 for b in range(d))
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v |= bits[i + j] << j
        out.append(v)
    return bytes(out)


def byte_decode(b, d):
    bits = []
    for byte in b:
        bits.extend((byte >> i) & 1 for i in range(8))
    out = []
    for i in range(256):
        v = 0
        for j in range(d):
            v |= bits[i * d + j] << j
        if d == 12:
            v %= Q
        out.append(v)
    return out


def compress(x, d):
    return ((x << d) + Q // 2) // Q % (1 << d)


def decompress(x, d):
    return (Q * x + (1 << (d - 1))) >> d


def compress_vec(f, d):
    return [compress(x, d) for x in f]


def decompress_vec(f, d):
    return [decompress(x, d) for x in f]


def sample_ntt(seed, i, j):
    xof = hashlib.shake_128(seed + bytes([j, i])).digest(3 * 256)
    out = []
    for k in range(0, 3 * 256, 3):
        d1 = xof[k] + 256 * (xof[k + 1] & 0x0F)
        d2 = (xof[k + 1] >> 4) + 16 * xof[k + 2]
        if d1 < Q:
            out.append(d1)
        if d2 < Q and len(out) < 256:
            out.append(d2)
        if len(out) == 256:
            break
    assert len(out) == 256, len(out)
    return out


def sample_cbd(seed, eta, counter):
    prf = hashlib.shake_256(seed + bytes([counter])).digest(64 * eta)
    bits = []
    for byte in prf:
        bits.extend((byte >> i) & 1 for i in range(8))
    out = []
    for i in range(256):
        x = sum(bits[i * 2 * eta + k] for k in range(eta))
        y = sum(bits[i * 2 * eta + eta + k] for k in range(eta))
        out.append((x - y) % Q)
    return out


def sample_matrix(seed, k):
    a = [[None] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            # A_hat[i][j] = SampleNTT(rho || j || i)
            a[i][j] = sample_ntt(seed, i, j)
    return a


def add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def poly_vec_add(a, b):
    return [add(x, y) for x, y in zip(a, b)]


def poly_vec_sub(a, b):
    return [sub(x, y) for x, y in zip(a, b)]


def poly_vec_ntt(a):
    return [ntt(x) for x in a]


def poly_vec_invntt(a):
    return [ntt(x, inverse=True) for x in a]


def dot_ntts(a, b):
    acc = [0] * 256
    for x, y in zip(a, b):
        p = multiply_ntts(x, y)
        acc = add(acc, p)
    return acc


G = lambda x: hashlib.sha3_512(x).digest()
H = lambda x: hashlib.sha3_256(x).digest()
J = lambda x: hashlib.shake_256(x).digest(32)
PRF = lambda x, n: hashlib.shake_256(x).digest(n)


def kpke_keygen(d, k, eta1):
    g = G(d + bytes([k]))
    rho, sigma = g[:32], g[32:]
    a = sample_matrix(rho, k)
    n = 0
    s = []
    for i in range(k):
        s.append(sample_cbd(sigma, eta1, n))
        n += 1
    e = []
    for i in range(k):
        e.append(sample_cbd(sigma, eta1, n))
        n += 1
    shat = poly_vec_ntt(s)
    ehat = poly_vec_ntt(e)
    that = [add(dot_ntts(a[i], shat), ehat[i]) for i in range(k)]
    ek = b"".join(byte_encode(x, 12) for x in that) + rho
    dk = b"".join(byte_encode(x, 12) for x in shat)
    return ek, dk


def kpke_encrypt(ek, m, r, k, eta1, du, dv, eta2=2):
    that = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:]
    a = sample_matrix(rho, k)
    n = 0
    y = []
    for i in range(k):
        y.append(sample_cbd(r, eta1, n))
        n += 1
    e1 = []
    for i in range(k):
        e1.append(sample_cbd(r, eta2, n))
        n += 1
    e2 = sample_cbd(r, eta2, n)
    yhat = poly_vec_ntt(y)
    # u = NTT^-1(A^T yhat) + e1
    u = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = add(acc, multiply_ntts(a[j][i], yhat[j]))
        u.append(add(poly_vec_invntt([acc])[0], e1[i]))
    v = add(poly_vec_invntt([dot_ntts(that, yhat)])[0], e2)
    v = add(v, decompress_vec(byte_decode(m, 1), 1))
    c1 = b"".join(byte_encode(compress_vec(x, du), du) for x in u)
    c2 = byte_encode(compress_vec(v, dv), dv)
    return c1 + c2


def kpke_decrypt(dk, c, k, du, dv):
    shat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    c1 = c[:32 * du * k]
    c2 = c[32 * du * k:]
    u = [decompress_vec(byte_decode(c1[32 * du * i:32 * du * (i + 1)], du), du) for i in range(k)]
    v = decompress_vec(byte_decode(c2, dv), dv)
    uhat = poly_vec_ntt(u)
    w = sub(v, poly_vec_invntt([dot_ntts(shat, uhat)])[0])
    return byte_encode(compress_vec(w, 1), 1)


def kem_keygen(d, z, k, eta1):
    ek, dk_pke = kpke_keygen(d, k, eta1)
    dk = dk_pke + ek + H(ek) + z
    return ek, dk


def kem_encaps(ek, m, k, eta1, du, dv):
    g = G(m + H(ek))
    key, r = g[:32], g[32:]
    c = kpke_encrypt(ek, m, r, k, eta1, du, dv)
    return c, key


def kem_decaps(dk, c, k, eta1, du, dv):
    dk_pke = dk[:384 * k]
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m = kpke_decrypt(dk_pke, c, k, du, dv)
    g = G(m + h)
    key, r = g[:32], g[32:]
    c2 = kpke_encrypt(ek_pke, m, r, k, eta1, du, dv)
    if c2 != c:
        key = J(z + c)
    return key


PARAMS = {
    "ML-KEM-512": dict(k=2, eta1=3, du=10, dv=4),
    "ML-KEM-768": dict(k=3, eta1=2, du=10, dv=4),
    "ML-KEM-1024": dict(k=4, eta1=2, du=11, dv=5),
}


def main():
    base = os.path.join(os.path.dirname(__file__), "..", "vectors")
    ok = bad = 0

    # NTT sanity
    import random
    random.seed(1)
    for _ in range(3):
        f = [random.randrange(Q) for _ in range(256)]
        assert ntt(ntt(f, inverse=True)) == f, "same-zeta inverse failed"
        # ntt_inv_alt uses explicit inverse roots; it does not round-trip with
        # this scaling convention, which is why FIPS 203 Algorithm 10 reuses
        # the forward zeta table in reverse.
    print("NTT roundtrip: ok")

    kg = json.load(open(os.path.join(base, "ML-KEM-keyGen-FIPS203", "expectedResults.json")))
    kgp = json.load(open(os.path.join(base, "ML-KEM-keyGen-FIPS203", "prompt.json")))
    exp = {g["tgId"]: {t["tcId"]: t for t in g["tests"]} for g in kg["testGroups"]}
    for pg, g in zip(kgp["testGroups"], kg["testGroups"]):
        p = PARAMS[pg["parameterSet"]]
        for t in pg["tests"]:
            ek, dk = kem_keygen(bytes.fromhex(t["d"]), bytes.fromhex(t["z"]), p["k"], p["eta1"])
            e = exp[g["tgId"]][t["tcId"]]
            if ek.hex().upper() == e["ek"] and dk.hex().upper() == e["dk"]:
                ok += 1
            else:
                bad += 1
                print("keyGen mismatch", pg["parameterSet"], t["tcId"])
    print(f"keyGen: {ok} ok, {bad} bad")

    ok = bad = 0
    ed = json.load(open(os.path.join(base, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")))
    edp = json.load(open(os.path.join(base, "ML-KEM-encapDecap-FIPS203", "prompt.json")))
    exp = {g["tgId"]: {t["tcId"]: t for t in g["tests"]} for g in ed["testGroups"]}
    for pg, eg in zip(edp["testGroups"], ed["testGroups"]):
        p = PARAMS[pg["parameterSet"]]
        fn = pg["function"]
        for t in pg["tests"]:
            e = exp[pg["tgId"]][t["tcId"]]
            if fn == "encapsulation":
                c, key = kem_encaps(bytes.fromhex(t["ek"]), bytes.fromhex(t["m"]), **p)
                good = c.hex().upper() == e["c"] and key.hex().upper() == e["k"]
            elif fn == "decapsulation":
                key = kem_decaps(bytes.fromhex(t["dk"]), bytes.fromhex(t["c"]), **p)
                good = key.hex().upper() == e["k"]
            elif fn == "encapsulationKeyCheck":
                raw = bytes.fromhex(t["ek"])
                k = p["k"]
                ok_bytes = all(
                    byte_encode(byte_decode(raw[384 * i:384 * (i + 1)], 12), 12)
                    == raw[384 * i:384 * (i + 1)]
                    for i in range(k)
                )
                good = len(raw) == 384 * k + 32 and ok_bytes
                # compare to expected below
            elif fn == "decapsulationKeyCheck":
                raw = bytes.fromhex(t["dk"])
                k = p["k"]
                good = len(raw) == 768 * k + 96 and H(raw[384 * k:768 * k + 32]) == raw[768 * k + 32:768 * k + 64]
            if "testPassed" in e:
                good = good == e["testPassed"]
            if good:
                ok += 1
            else:
                bad += 1
                print("mismatch", fn, pg["parameterSet"], t["tcId"],
                      "expected", e.get("testPassed"))
    print(f"encapDecap: {ok} ok, {bad} bad")


if __name__ == "__main__":
    main()
