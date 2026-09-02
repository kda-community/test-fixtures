# Chainweb SLH-DSA signature verification vectors

Test vectors for the **Chainweb signing mode of SLH-DSA** defined by
[KIP-0041](https://github.com/kda-community/KIPs/blob/main/kip-0041.md):
HashSLH-DSA (FIPS 205 §10.2.2) with context `"CHAINWEB"` and BLAKE2b-256 as the
pre-hash. They complement the NIST ACVP vectors in `../SLH-DSA-ACVP/`, which
exercise the primitive but not the Chainweb framing, and they were produced by
an implementation **independent from the Haskell one** in `pact-5`.

| File | Contents |
|---|---|
| `SLH-DSA-SHA2-128s-chainweb-sigver.json` | 15 verification tests: 13 interoperability (5 valid, 8 must-reject), 2 encoding conformance |

## What is being verified

```
hash  = BLAKE2b-256(cmd)                                  -- the Chainweb transaction hash
M'    = 0x01 || len("CHAINWEB") || "CHAINWEB" || DER(OID) || hash
OID   = 1.3.6.1.4.1.1722.12.2.1.8  (BLAKE2b-256), DER = 06 0b 2b 06 01 04 01 8d 3a 0c 02 01 08
valid = slh_verify_internal(M', signature, pk)          -- SLH-DSA-SHA2-128s
```

This is exactly what `Pact.Crypto.SlhDsa.ChainwebSlhDsa.verifySig` computes on
the `post_quantum` branch.

## File layout

ACVP-like: `testGroups[].tests[]`, each test with `tcId`, `pk`, `hash`,
`signature` and the expected verdict `testPassed`.

| Field | Encoding |
|---|---|
| `cmd` | UTF-8 string, present on valid tests; `hash` is BLAKE2b-256 of these exact bytes |
| `pk` | hex, 32 bytes |
| `hash` | hex, 32 bytes (base64url on the wire) |
| `signature` | base64url **without padding**, 7856 bytes / 10475 characters |
| `testPassed` | `true` = must verify, `false` = must be rejected |
| `derivedFrom` | on negative tests, which valid test(s) the material comes from |

Two groups:

- **`interop` (tgId 1, binding).** V1–V5 are valid signatures and must verify:
  a `coin.transfer` with a `q:` signer, a `coin.transfer-create` with a `q…`
  keyset, non-JSON content, the empty command, and multibyte UTF-8 (accents,
  `ñ`, kanji — catches text-encoding mismatches between hash implementations).
  N1–N8 must be rejected: flipped bit at the start and at the end of the
  signature, valid signature against another hash, another account's public
  key, signature truncated by one byte, 31-byte hash, 31-byte public key,
  public key with one byte changed.
- **`encoding` (tgId 2, conformance).** C1 and C2 carry the valid signature of
  V1 encoded with one and two trailing `=`. KIP-0041 mandates unpadded
  base64url, so a conforming decoder rejects both (`testPassed: false`).

## Determinism

Nothing in the file is random; anyone with an SLH-DSA-SHA2-128s implementation
can regenerate it byte for byte from the labels stored in each test:

- key seed (48 bytes) = `BLAKE2b(seedLabel, 48)`, fed to FIPS 205
  `slh_keygen_internal` as `SK.seed || SK.prf || PK.seed` (16 bytes each);
- hedged signing per `slh_sign_internal` with `addrnd = BLAKE2b(entropyLabel, 16)`;
- `hash = BLAKE2b-256(cmd)`.

Generated with `@noble/post-quantum` 0.7.1 (`internal.sign` over the framed
message `M'`, since the library's `prehash()` API only accepts NIST OIDs).

## Results against pact-5 `post_quantum`

Run with `verifySig` of `kda-community/pact-5` at `00b9b8e` (GHC 9.6.7,
`base64-bytestring` 1.2.1.0, `crypton` 1.1.4):

| Group | Result |
|---|---|
| interop (13) | 13/13 agree: all valid signatures verify, all manipulated inputs are rejected (`Signature verification failed`, `Invalid signature length`, `Unsupported TxHash`, `Invalid key`) |
| encoding (2) | C2 rejected (`invalid size`); **C1 accepted** at `00b9b8e` — the decoder tolerates a single `=`. Rejected as expected with kda-community/pact-5#23 applied |

The BLAKE2b-256 of every `cmd` matched between the JavaScript (`blakejs`) and
Haskell (`crypton`) sides.

## Verifying with pact-5

```haskell
import Pact.Core.Hash (Hash(..))
import Pact.Core.Scheme (PPKScheme(..))
import Pact.Crypto.SlhDsa.ChainwebSlhDsa (verifySig)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Short as SB

-- pk, sig :: Text (as in the file); hashHex :: ByteString
check :: Text -> Text -> ByteString -> Bool
check pk sig hashHex =
  let Right bs = B16.decode hashHex
  in either (const False) (const True) (verifySig SlhDsaSha128s pk sig (Hash (SB.toShort bs)))
-- compare `check pk signature hash` with `testPassed` for every test
```

The 31-byte hash (N6) is passed as raw bytes on purpose: the test checks that
the verifier rejects an unsupported hash length rather than guessing.

## License

Public domain (CC0 1.0). Use freely.
