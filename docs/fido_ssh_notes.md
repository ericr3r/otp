# FIDO SSH Key Format Documentation

This document describes the wire format and signature structure for FIDO2/WebAuthn-backed SSH keys as implemented by OpenSSH.

## Overview

OpenSSH supports two FIDO security key types:
- `ecdsa-sk` (ECDSA with NIST P-256 curve)
- `ed25519-sk` (Ed25519)

These keys are backed by hardware authenticators compliant with the FIDO2/U2F/WebAuthn standards.

---

## Key Type Identifiers

### ECDSA Security Keys
- **Short form**: `ecdsa-sk`
- **Full form**: `sk-ecdsa-sha2-nistp256@openssh.com`

### Ed25519 Security Keys
- **Short form**: `ed25519-sk`
- **Full form**: `sk-ssh-ed25519@openssh.com`

---

## Public Key Wire Format

FIDO SSH public keys use SSH's standard wire format with additional fields.

### General Structure
```
string    key-type
<key-specific-data>
string    application
uint32    flags (optional, added in later OpenSSH versions)
string    key_handle (optional, added in later OpenSSH versions)
string    reserved (optional)
```

### ECDSA-SK Public Key Format
```
string    "sk-ecdsa-sha2-nistp256@openssh.com"
string    curve name ("nistp256")
string    EC point (uncompressed format: 0x04 || x || y)
string    application (typically "ssh:")
```

**Byte-level details:**
- **EC point**: 65 bytes for P-256
  - Byte 0: `0x04` (uncompressed point indicator)
  - Bytes 1-32: X coordinate (big-endian)
  - Bytes 33-64: Y coordinate (big-endian)
- **Application**: UTF-8 string, typically "ssh:" (4 bytes)

### Ed25519-SK Public Key Format
```
string    "sk-ssh-ed25519@openssh.com"
string    public key (32 bytes)
string    application (typically "ssh:")
```

**Byte-level details:**
- **Public key**: Exactly 32 bytes (Ed25519 public key)
- **Application**: UTF-8 string, typically "ssh:" (4 bytes)

### SSH String Encoding
All `string` types in SSH wire format are encoded as:
```
uint32    length (4 bytes, big-endian)
byte[]    data (length bytes)
```

---

## Signature Structure

FIDO SSH signatures contain additional authenticator data beyond the cryptographic signature.

### ECDSA-SK Signature Format
```
string    "sk-ecdsa-sha2-nistp256@openssh.com"
string    ecdsa_signature
byte      flags
uint32    counter
```

**ECDSA signature blob (inner string):**
```
string    r (ECDSA signature component)
string    s (ECDSA signature component)
```

### Ed25519-SK Signature Format
```
string    "sk-ssh-ed25519@openssh.com"
string    ed25519_signature (64 bytes)
byte      flags
uint32    counter
```

### Authenticator Flags

The `flags` byte indicates properties of the authentication:

| Bit | Mask | Meaning |
|-----|------|---------|
| 0   | 0x01 | User presence verified (UP) |
| 2   | 0x04 | User verified (UV) - PIN or biometric |
| 6   | 0x40 | Attested credential data included (AT) |
| 7   | 0x80 | Extension data included (ED) |

**Common values:**
- `0x01`: User touched the key (most common)
- `0x05`: User touched + verified (PIN/biometric)

### Counter

A 32-bit unsigned integer (big-endian) that increments with each signature operation. Used to detect cloned authenticators.

---

## Signature Verification Process

### Data to Sign

For SSH authentication, the signature is computed over:
```
string    session identifier (H from key exchange)
byte      SSH_MSG_USERAUTH_REQUEST (0x32)
string    user name
string    service name ("ssh-connection")
string    "publickey"
boolean   TRUE
string    public key algorithm name
string    public key blob
```

### FIDO Signature Computation

The authenticator actually signs:
```
sha256(application) || flags || counter || sha256(message_to_sign)
```

**Step-by-step:**
1. Hash the application string with SHA-256 (32 bytes)
2. Append authenticator flags (1 byte)
3. Append counter (4 bytes, big-endian)
4. Hash the SSH authentication message with SHA-256 (32 bytes)
5. Append this hash
6. Sign the resulting 69-byte blob with the FIDO key

**Total blob signed by authenticator: 69 bytes**
- Bytes 0-31: SHA-256(application)
- Byte 32: flags
- Bytes 33-36: counter
- Bytes 37-68: SHA-256(SSH auth message)

### Verification Steps

1. Parse the signature structure
2. Extract flags and counter
3. Reconstruct the 69-byte blob as above
4. Verify the cryptographic signature against this blob using the public key from the FIDO key

---

## OpenSSH Key File Format

FIDO keys stored in OpenSSH private key format include additional metadata.

### Authorized Keys Format

In `~/.ssh/authorized_keys`, FIDO keys appear as:
```
sk-ecdsa-sha2-nistp256@openssh.com AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... user@host
```

or

```
sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t... user@host
```

### Private Key Storage

FIDO private keys are NOT stored on disk. Instead, the key file contains:
- Key handle (opaque blob returned by the authenticator)
- Application string
- Flags
- Public key

The actual private key remains on the hardware token.

---

## Testing with OpenSSH

### Generate a FIDO Key

```bash
# ECDSA
ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ecdsa_sk

# Ed25519
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk

# With resident key (stored on authenticator)
ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/id_ed25519_sk
```

### Inspect a Public Key

```bash
ssh-keygen -vv -lf ~/.ssh/id_ecdsa_sk.pub
```

Output includes:
- Key type
- Fingerprint
- Randomart
- Public key in base64

### Extract Raw Bytes

```bash
# Get base64-encoded public key
cut -d' ' -f2 ~/.ssh/id_ecdsa_sk.pub | base64 -d | xxd
```

This shows the byte-level structure described above.

---

## Protocol Specifications

### Relevant RFCs and Standards

- **RFC 4251**: SSH Protocol Architecture
- **RFC 4252**: SSH Authentication Protocol
- **RFC 4253**: SSH Transport Layer Protocol
- **RFC 5656**: Elliptic Curve Algorithm Integration in SSH
- **RFC 8709**: Ed25519 and Ed448 Public Key Algorithms for SSH

### FIDO2 Specifications

- **FIDO2 CTAP**: Client to Authenticator Protocol
- **WebAuthn**: W3C Web Authentication standard
- **FIDO U2F**: Universal 2nd Factor (legacy)

### OpenSSH Documentation

- `PROTOCOL.u2f` in OpenSSH source tree
- https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f

---

## Example Key Inspection

### Sample ECDSA-SK Public Key (hex dump)

```
00 00 00 33                                    # String length: 51 bytes
   73 6b 2d 65 63 64 73 61 2d 73 68 61 32 2d  # "sk-ecdsa-sha2-"
   6e 69 73 74 70 32 35 36 40 6f 70 65 6e 73  # "nistp256@opens"
   73 68 2e 63 6f 6d                          # "sh.com"

00 00 00 08                                    # String length: 8 bytes
   6e 69 73 74 70 32 35 36                    # "nistp256"

00 00 00 41                                    # String length: 65 bytes
   04                                          # Uncompressed point
   [32 bytes: X coordinate]
   [32 bytes: Y coordinate]

00 00 00 04                                    # String length: 4 bytes
   73 73 68 3a                                # "ssh:"
```

### Sample Ed25519-SK Public Key (hex dump)

```
00 00 00 1a                                    # String length: 26 bytes
   73 6b 2d 73 73 68 2d 65 64 32 35 35 31 39  # "sk-ssh-ed25519"
   40 6f 70 65 6e 73 73 68 2e 63 6f 6d        # "@openssh.com"

00 00 00 20                                    # String length: 32 bytes
   [32 bytes: Ed25519 public key]

00 00 00 04                                    # String length: 4 bytes
   73 73 68 3a                                # "ssh:"
```

---

## Implementation Notes

### Required Cryptographic Operations

- **SHA-256**: For hashing application string and authentication message
- **ECDSA P-256 verification**: For `ecdsa-sk` signatures
- **Ed25519 verification**: For `ed25519-sk` signatures

### No Hardware Required for Verification

**Important**: Signature verification does NOT require hardware access. The authenticator has already produced the signature; verification only needs:
1. The public key
2. The signature blob
3. Standard cryptographic primitives

Hardware is only needed for:
- Key generation
- Signing operations (authentication)

### Backward Compatibility

Standard SSH keys continue to work unchanged. FIDO keys are additive:
- Different key type identifiers
- Additional fields in wire format
- Modified signature structure

---

## Key Differences from Standard SSH Keys

| Aspect | Standard SSH | FIDO SSH |
|--------|--------------|----------|
| Private key location | Disk file | Hardware token |
| Key type identifier | `ecdsa-sha2-nistp256`, `ssh-ed25519` | `sk-ecdsa-sha2-nistp256@openssh.com`, `sk-ssh-ed25519@openssh.com` |
| Public key fields | Key material only | Key material + application |
| Signature fields | Signature only | Signature + flags + counter |
| User presence | N/A | Required (touch) |
| Cloning detection | N/A | Counter mechanism |

---

## Next Steps for Implementation

1. ✅ Document format (this file)
2. Locate SSH parsing code in OTP
3. Add key type recognition
4. Implement public key parsing
5. Implement signature verification
6. Test against OpenSSH

---

## References

- OpenSSH `PROTOCOL.u2f`: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
- OpenSSH source: `sshkey.c`, `ssh-sk.c`, `sk-usbhid.c`
- RFC 4251-4253: SSH Protocol
- FIDO Alliance specifications: https://fidoalliance.org/specifications/

---

**Document Status**: Initial version - covers format specification and byte-level details
**Last Updated**: 2024
**Verification**: Formats documented based on OpenSSH 8.2+ implementation