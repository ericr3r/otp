# FIDO/Security Key Test Data

This directory contains test public key files for FIDO/U2F security keys (also known as sk-* keys in OpenSSH).

## Key Files

### Basic Format Keys (OpenSSH 8.2+)

These keys contain the minimal FIDO format with just the application field:

- **id_ecdsa_sk.pub**: FIDO ECDSA-SK (sk-ecdsa-sha2-nistp256@openssh.com) public key
  - Contains: key type, curve, EC point, application
  - Application field: "ssh:"

- **id_ed25519_sk.pub**: FIDO Ed25519-SK (sk-ssh-ed25519@openssh.com) public key
  - Contains: key type, public key, application
  - Application field: "ssh:"

### Full Format Keys (OpenSSH 8.3+)

These keys contain all optional FIDO fields including flags and key handle:

- **id_ecdsa_sk_full.pub**: FIDO ECDSA-SK with all fields
  - Contains: key type, curve, EC point, application, flags, key_handle
  - Flags: 1 (user presence verified)
  - Key handle: included

- **id_ed25519_sk_full.pub**: FIDO Ed25519-SK with all fields
  - Contains: key type, public key, application, flags, key_handle
  - Flags: 1 (user presence verified)
  - Key handle: included

## FIDO Key Format

FIDO keys use the following wire format:

### ECDSA-SK (sk-ecdsa-sha2-nistp256@openssh.com)
```
string    key-type ("sk-ecdsa-sha2-nistp256@openssh.com")
string    curve ("nistp256")
string    ec-point (65 bytes: 0x04 || X || Y)
string    application (e.g., "ssh:")
[uint32   flags]          # Optional (OpenSSH 8.3+)
[string   key-handle]     # Optional (OpenSSH 8.3+)
```

### Ed25519-SK (sk-ssh-ed25519@openssh.com)
```
string    key-type ("sk-ssh-ed25519@openssh.com")
string    public-key (32 bytes)
string    application (e.g., "ssh:")
[uint32   flags]          # Optional (OpenSSH 8.3+)
[string   key-handle]     # Optional (OpenSSH 8.3+)
```

## Flags Field

The flags field is a 32-bit unsigned integer with the following bits:

- Bit 0 (0x01): User presence verified (touch detected)
- Bit 2 (0x04): User verification (PIN/biometric) performed

## Test Coverage

These files are used by test case 2.3 in ssh_fido_SUITE.erl to verify:

1. Parsing of real FIDO public key files from disk
2. Correct handling of both basic and full FIDO key formats
3. Compatibility with OpenSSH-generated FIDO keys
4. Round-trip encoding/decoding of FIDO metadata

## References

- OpenSSH PROTOCOL.u2f: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
- RFC 8709: Ed25519 and Ed448 Public Key Algorithms for SSH
- FIDO U2F specification: https://fidoalliance.org/specs/