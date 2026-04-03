# FIDO SSH Key Format Notes

This document captures wire format details, byte-level structure, and signature
verification mechanics for FIDO2/WebAuthn-backed SSH keys (`ecdsa-sk`,
`ed25519-sk`), as implemented by OpenSSH.  All formats were verified against
real keys and OpenSSH's authoritative `PROTOCOL.u2f` document.

---

## Key Type Identifiers

OpenSSH uses two FIDO-backed key types.  Each has a short name used by tools
and a full wire-format name used in SSH messages.

| Short name    | Wire-format name                            |
|---------------|---------------------------------------------|
| `ecdsa-sk`    | `sk-ecdsa-sha2-nistp256@openssh.com`        |
| `ed25519-sk`  | `sk-ssh-ed25519@openssh.com`               |

The wire-format names are what appear as the leading `string` in every public
key blob and every signature blob.

---

## SSH Wire Encoding Primitives

All multi-byte integers are big-endian.

| Type     | Encoding                                                       |
|----------|----------------------------------------------------------------|
| `uint32` | 4 bytes, big-endian                                            |
| `string` | `uint32` length prefix followed by raw bytes                  |
| `mpint`  | `uint32` length prefix followed by big-endian integer bytes.  If the high bit of the first byte is 1, a leading `0x00` is prepended to preserve sign.  Length therefore varies: a 32-byte scalar is encoded as 32 bytes if its high bit is 0, or 33 bytes (with `0x00` prefix) if its high bit is 1. |
| `ec_point` | Encoded as `string`: uncompressed point `0x04 \|\| X \|\| Y`, 65 bytes for P-256. |
| `byte`   | 1 byte                                                         |

---

## Public Key Wire Format

### ECDSA-SK (`sk-ecdsa-sha2-nistp256@openssh.com`)

```
string    key-type    ("sk-ecdsa-sha2-nistp256@openssh.com")
string    curve-name  ("nistp256")
ec_point  Q           (uncompressed: 0x04 || X[32] || Y[32] = 65 bytes)
string    application (typically "ssh:")
```

### Ed25519-SK (`sk-ssh-ed25519@openssh.com`)

```
string    key-type    ("sk-ssh-ed25519@openssh.com")
string    public-key  (32 bytes, Ed25519 public key)
string    application (typically "ssh:")
```

### Private Key (both types, extends the public key fields)

The public key fields above are followed by:

```
uint8     flags       (key flags, e.g. SSH_SK_USER_PRESENCE_REQD = 0x01)
string    key_handle  (opaque blob; re-presented to the token at sign time)
string    reserved    (empty string, reserved for future use)
```

The actual ECDSA/Ed25519 private scalar is **never stored on disk**.  It lives
on the hardware token.  The `key_handle` is an opaque blob the token uses to
derive it.

---

## Real Key Inspection

### Key 1: ECDSA-SK (OpenSSH test key, `ecdsa_sk1.pub`)

Generated with OpenSSH by djm@djm.syd.corp.google.com.

**`ssh-keygen -vv -lf ecdsa_sk1.pub` output:**

```
256 SHA256:9H4Upkmt0536hnYUFDAM8WgHNL6KCskXi+pfnACKmYc djm@djm.syd.corp.google.com (ECDSA-SK)
+-[ECDSA-SK 256]--+
|         .*+o... |
|         . *...  |
| .      . = *.   |
|o+.    . + O o.. |
|E ...   S B o o. |
| o ooo.. o o ..  |
|  = o+. . . oo   |
| . o..     .o.o  |
|o....      . o.  |
+----[SHA256]-----+
```

**Raw bytes (`cut -d' ' -f2 ecdsa_sk1.pub | base64 -d | xxd`):**

```
00000000: 0000 0022 736b 2d65 6364 7361 2d73 6861  ..."sk-ecdsa-sha
00000010: 322d 6e69 7374 7032 3536 406f 7065 6e73  2-nistp256@opens
00000020: 7368 2e63 6f6d 0000 0008 6e69 7374 7032  sh.com....nistp2
00000030: 3536 0000 0041 0467 553e 428e 2d43 19ed  56...A.gU>B.-C..
00000040: beab 65f4 bc04 e1e8 b627 3835 7e0c 9aec  ..e......'85~...
00000050: 849a 2baf 91a7 8a95 b6f5 17ee 6835 ecd1  ..+.........h5..
00000060: 607a 5c17 a3f5 d38b 6b35 510e 342b b55d  `z\.....k5Q.4+.]
00000070: 7d42 03ba 71f9 0500 0000 0473 7368 3a    }B..q......ssh:
```

**Field-by-field breakdown (127 bytes total):**

```
Offset  Len  Hex                                  Value
------  ---  -----------------------------------  -----
0x00    4    00 00 00 22                          string length = 34
0x04    34   73 6b 2d 65 63 64 73 61 2d 73 68 61  "sk-ecdsa-sha2-
             32 2d 6e 69 73 74 70 32 35 36 40 6f   nistp256@openssh
             70 65 6e 73 73 68 2e 63 6f 6d          .com"
0x26    4    00 00 00 08                          string length = 8
0x2a    8    6e 69 73 74 70 32 35 36              "nistp256"
0x32    4    00 00 00 41                          ec_point length = 65
0x36    1    04                                   uncompressed point
0x37    32   67 55 3e 42 8e 2d 43 19 ed be ab 65  X coordinate
             f4 bc 04 e1 e8 b6 27 38 35 7e 0c 9a
             ec 84 9a 2b af 91 a7 8a
0x57    32   95 b6 f5 17 ee 68 35 ec d1 60 7a 5c  Y coordinate
             17 a3 f5 d3 8b 6b 35 51 0e 34 2b b5
             5d 7d 42 03 ba 71 f9 05
0x77    4    00 00 00 04                          string length = 4
0x7b    4    73 73 68 3a                          "ssh:"
```

---

### Key 2: Ed25519-SK (real hardware key, `id_ed25519_sk.pub`)

Generated with a real FIDO2 token by eric@rauer.dev.

**`ssh-keygen -vv -lf id_ed25519_sk.pub` output:**

```
256 SHA256:A4CdGKV1YzWQVohsElR76c20Vdysp3dNQEBElEV+1s0 eric@rauer.dev (ED25519-SK)
+[ED25519-SK 256]-+
| .+X=o=*+  *BO+  |
|  +o*=+o . .o.+.o|
|  .o..+ . .  ...E|
|     o = o  . .o.|
|      . S    o ..|
|         .  . . o|
|             . . |
|                 |
|                 |
+----[SHA256]-----+
```

**Raw bytes (`cut -d' ' -f2 id_ed25519_sk.pub | base64 -d | xxd`):**

```
00000000: 0000 001a 736b 2d73 7368 2d65 6432 3535  ....sk-ssh-ed255
00000010: 3139 406f 7065 6e73 7368 2e63 6f6d 0000  19@openssh.com..
00000020: 0020 2ced 62f7 ea03 9fe7 398a 2fb1 c7ad  . ,.b.....9./...
00000030: 0a16 5180 d1a0 2f9d bafc 54e7 abfa fac0  ..Q.../...T.....
00000040: f2f3 0000 0004 7373 683a                 ......ssh:
```

**Field-by-field breakdown (74 bytes total):**

```
Offset  Len  Hex                                  Value
------  ---  -----------------------------------  -----
0x00    4    00 00 00 1a                          string length = 26
0x04    26   73 6b 2d 73 73 68 2d 65 64 32 35 35  "sk-ssh-ed25519
             31 39 40 6f 70 65 6e 73 73 68 2e 63   @openssh.com"
             6f 6d
0x1e    4    00 00 00 20                          string length = 32
0x22    32   2c ed 62 f7 ea 03 9f e7 39 8a 2f b1  Ed25519 public key
             c7 ad 0a 16 51 80 d1 a0 2f 9d ba fc
             54 e7 ab fa fa c0 f2 f3
0x42    4    00 00 00 04                          string length = 4
0x46    4    73 73 68 3a                          "ssh:"
```

---

## Signature Wire Format

### ECDSA-SK Signature

```
string    key-type         ("sk-ecdsa-sha2-nistp256@openssh.com")
string    ecdsa_sig_blob   (see inner format below)
byte      flags
uint32    counter
```

**Inner `ecdsa_sig_blob`:**

```
mpint     r
mpint     s
```

`r` and `s` are SSH `mpint` values, **not** fixed-width strings.  Each is
encoded as a 4-byte length followed by the big-endian integer bytes.  A
leading `0x00` is prepended when the high bit of the first byte is set, making
the encoded length 33 rather than 32 for ~50 % of real signatures.  Code that
assumes 32 bytes for `r` or `s` will fail on roughly half of all inputs.

### Ed25519-SK Signature

```
string    key-type     ("sk-ssh-ed25519@openssh.com")
string    signature    (64 bytes, raw Ed25519 signature)
byte      flags
uint32    counter
```

For Ed25519 the inner signature is a fixed 64-byte value and is encoded as a
`string` (not `mpint`).

---

## Real Signature Inspection

Source: OpenSSH regression test vectors
(`regress/unittests/sshsig/testdata/`).  The signed message was:
`"This is a test, this is only a test"`, namespace `"unittest"`,
hash `sha512`, application `"ssh:"`, flags `0x01`, counter `0x12345678`.

### ECDSA-SK Signature Blob (119 bytes)

Extracted from the SSHSIG envelope; these are the bytes passed to and from
the SSH protocol layer.

```
Offset  Len  Hex                                  Field
------  ---  -----------------------------------  -----
0x00    4    00 00 00 22                          alg-name length = 34
0x04    34   73 6b 2d 65 63 64 73 61 2d 73 68 61  "sk-ecdsa-sha2-
             32 2d 6e 69 73 74 70 32 35 36 40 6f   nistp256@openssh
             70 65 6e 73 73 68 2e 63 6f 6d          .com"
0x26    4    00 00 00 48                          ecdsa_sig_blob length = 72
  -- ecdsa_sig_blob (72 bytes) --
  0x2a  4    00 00 00 20                          r length = 32 (high bit = 0, no padding)
  0x2e  32   7a 21 1b 0c b2 f2 22 93 df 3c 1d d5  r value
             36 00 f5 5f c8 a2 8e e1 ff 7c c2 25
             4b 72 ab f4 22 82 df c7
  0x4e  4    00 00 00 20                          s length = 32 (high bit = 0, no padding)
  0x52  32   6c e2 75 3c 2a ec 3f e4 15 ae d7 8d  s value
             ca 7f 2a 47 5b 22 ce 0c 7d 0a 5f 01
             6f f4 39 c8 9a 8e 5a 73
  -- end ecdsa_sig_blob --
0x72    1    01                                   flags = 0x01 (user presence)
0x73    4    12 34 56 78                          counter = 0x12345678
```

Note: in this test vector both `r` (`0x7a…`) and `s` (`0x6c…`) have high bits
clear, so no padding byte is needed and both are encoded as 32 bytes.  In
production keys either value could require a 33-byte encoding.

---

### Ed25519-SK Signature Blob (103 bytes)

```
Offset  Len  Hex                                  Field
------  ---  -----------------------------------  -----
0x00    4    00 00 00 1a                          alg-name length = 26
0x04    26   73 6b 2d 73 73 68 2d 65 64 32 35 35  "sk-ssh-ed25519
             31 39 40 6f 70 65 6e 73 73 68 2e 63   @openssh.com"
             6f 6d
0x1e    4    00 00 00 40                          signature length = 64
0x22    64   22 fb b7 93 8d 6f fe 2d 0d 8c fa c0  Ed25519 signature
             83 f8 a1 6d 1f 59 fb 54 51 49 a2 7f  (fixed 64 bytes,
             d2 64 5b 31 38 3c 95 f1 c5 93 94 52   not mpint)
             a3 eb 5e d8 b3 55 2b e5 35 7a b9 a1
             17 42 17 24 f2 b0 40 da 84 08 1d 33
             c0 34 b2 0f
0x62    1    01                                   flags = 0x01 (user presence)
0x63    4    12 34 56 78                          counter = 0x12345678
```

---

## Authenticator Flags Byte

| Bit | Mask   | Name | Meaning                                   |
|-----|--------|------|-------------------------------------------|
| 0   | `0x01` | UP   | User presence verified (touch)            |
| 2   | `0x04` | UV   | User verified (PIN or biometric)          |
| 6   | `0x40` | AT   | Attested credential data included         |
| 7   | `0x80` | ED   | Extension data present in signed blob     |

Common values seen in practice:
- `0x01` — user touched the key (most common SSH case)
- `0x05` — touch + PIN/biometric verified

---

## Signature Verification

### What the SSH Layer Signs

For `publickey` authentication, the data to be signed is:

```
string    session_id     (H from key exchange)
byte      0x32           (SSH_MSG_USERAUTH_REQUEST)
string    username
string    "ssh-connection"
string    "publickey"
boolean   TRUE
string    algorithm-name (e.g. "sk-ecdsa-sha2-nistp256@openssh.com")
string    public-key-blob
```

Call this entire blob `M`.

### What the FIDO Authenticator Actually Signs

The authenticator does **not** sign `M` directly.  It signs the following
69-byte blob (assuming no extensions):

```
byte[32]  SHA-256(application)     -- 32 bytes
byte      flags                    --  1 byte
uint32    counter                  --  4 bytes  (big-endian)
byte[]    extensions               --  0 bytes  (none defined for SSH yet)
byte[32]  SHA-256(M)               -- 32 bytes
```

Total: **69 bytes** when no extensions are present.

The `extensions` field is included only when the `ED` flag bit (`0x80`) is
set.  No extensions are currently defined for SSH use in `PROTOCOL.u2f`;
all current implementations produce a 69-byte blob.

### Verification Steps

To verify an ECDSA-SK or Ed25519-SK signature on the server:

1. Parse the signature blob to extract: algorithm name, inner EC/Ed signature,
   `flags`, and `counter`.
2. Reconstruct the 69-byte authenticator blob:
   - `SHA-256(application_string)` — the application stored in the public key
   - `flags` byte from the signature
   - `counter` as 4-byte big-endian uint32
   - (no extensions for SSH)
   - `SHA-256(M)` where `M` is the SSH auth message constructed above
3. Verify the underlying cryptographic signature:
   - **ECDSA-SK**: verify the `(r, s)` ECDSA/P-256 signature over the 69-byte
     blob using the `ECPoint Q` from the public key
   - **Ed25519-SK**: verify the 64-byte Ed25519 signature over the 69-byte
     blob using the 32-byte public key
4. Optionally check `flags & 0x01` (user presence) if the application policy
   requires it.
5. Optionally check that `counter > last_seen_counter` to detect cloned tokens.

**Important**: hardware is NOT required for verification.  The token has
already produced the signature.  Verification only needs standard SHA-256,
ECDSA P-256, and Ed25519 primitives — all available in OTP's `crypto`
application.

---

## Key File Formats

### `authorized_keys` Entry

```
sk-ecdsa-sha2-nistp256@openssh.com AAAA...base64...== user@host
sk-ssh-ed25519@openssh.com AAAA...base64...== user@host
```

The base64 payload is the public key wire format documented above.

### Private Key Storage

FIDO private keys use the standard OpenSSH private key PEM envelope
(`-----BEGIN OPENSSH PRIVATE KEY-----`) but the inner structure replaces
the private scalar with `key_handle` + `flags` + `reserved`:

```
string    type          (e.g. "sk-ssh-ed25519@openssh.com")
string    pubkey        (public key wire format as above)
string    application
uint8     flags
string    key_handle    (opaque; passed back to token when signing)
string    reserved      (empty)
```

---

## Protocol References

- **`PROTOCOL.u2f`** — authoritative OpenSSH specification:
  https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
- **RFC 4251** — SSH Protocol Architecture (wire encoding primitives)
- **RFC 4252** — SSH Authentication Protocol
- **RFC 5656** — ECDSA/EC key integration in SSH (mpint r/s format)
- **RFC 8709** — Ed25519 in SSH

---

## Implementation Notes for OTP

- The `application` string from the public key blob is **required** at
  verification time (needed to compute `SHA-256(application)`).  It must be
  preserved in the decoded key term and cannot be discarded after parsing.
- `r` and `s` in ECDSA-SK signatures are `mpint`, not fixed-width strings.
  Allocate up to 33 bytes per value when decoding.
- SK algorithm name atoms (`'sk-ecdsa-sha2-nistp256@openssh.com'`,
  `'sk-ssh-ed25519@openssh.com'`) must exist in the atom table before any
  call to `list_to_existing_atom/1`.
- SK keys do not map to OIDs.  Use tagged tuples (e.g.
  `{ecdsa_sk, ECPoint, Curve, Application}`) rather than forcing them into
  the `{namedCurve, OID}` structure used by standard EC keys.
- No new exported functions are needed: all touch points
  (`ssh2_pubkey_decode2/1`, `ssh2_pubkey_encode/1`, `do_verify/5`,
  `valid_key_sha_alg/3`, `sha/1`, `key_alg/1`) can be extended via new
  pattern-matched function heads.

---

**Document status**: Complete — byte-level formats verified against real keys
and OpenSSH test vectors.  Signature format corrected: ECDSA inner `r`/`s`
are `mpint`, not `string`.