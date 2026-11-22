# Development reference

`reference.py` is a deliberately slow, straightforward Python transcription of
FIPS 203 used while developing the Rust implementation. It checks all 75 ACVP
key-generation vectors and all 165 encapsulation/decapsulation vectors,
including the key-check cases.

It settled several details that are easy to get wrong:

* `SamplePolyCBD` sums individual bits; it does not use powers of two.
* K-PKE encryption samples `e1` and `e2` with `eta2`, not `eta1`.
* The inverse NTT uses the forward zeta table in reverse and scales by 3303.
* `ByteDecode_12` reduces 12-bit values modulo `q`; non-canonical values are
  rejected by the encapsulation key modulus check after re-encoding.
* The decapsulation key hash check is a hash comparison, not a length check.

Run it with:

```bash
python3 tools/reference.py
```

Expected output:

```text
NTT roundtrip: ok
keyGen: 75 ok, 0 bad
encapDecap: 165 ok, 0 bad
```

This script is not constant time, not fast, and not part of the library.
