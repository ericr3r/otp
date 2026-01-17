# Task 2.1: Add Key Type Recognition - Implementation Notes

## Summary

Task 2.1 implements recognition for FIDO/Security Key SSH key types without crashing. This is Phase 1 of FIDO support - keys are parsed but treated as their underlying cryptographic key types.

## Changes Made

### 1. Modified `lib/ssh/src/ssh_message.erl`

#### Added FIDO key type parsing in `ssh2_pubkey_decode2/1`

Added two new pattern matches to handle FIDO key wire formats:

**ECDSA-SK** (`sk-ecdsa-sha2-nistp256@openssh.com`):
- Parses: key type, curve name, EC point, application string
- Discards: application string (for now)
- Returns: Standard ECDSA key structure with `secp256r1` OID

**Ed25519-SK** (`sk-ssh-ed25519@openssh.com`):
- Parses: key type, public key, application string  
- Discards: application string (for now)
- Returns: Standard Ed25519 key structure with `id-Ed25519` OID

#### Added FIDO key type mappings in `ssh_curvename2oid/1`

```erlang
ssh_curvename2oid(<<"sk-ecdsa-sha2-nistp256@openssh.com">>) -> ?'secp256r1';
ssh_curvename2oid(<<"sk-ssh-ed25519@openssh.com">>) -> ?'id-Ed25519'.
```

These mappings allow FIDO key type strings to be recognized and mapped to their underlying cryptographic curve OIDs.

### 2. Created Test Suite `lib/ssh/test/ssh_fido_SUITE.erl`

Comprehensive test suite with 6 test cases organized in 2 groups:

**Group: fido_key_parsing**
- `decode_ecdsa_sk_pubkey/1` - Verifies ECDSA-SK public key parsing
- `decode_ed25519_sk_pubkey/1` - Verifies Ed25519-SK public key parsing
- `ecdsa_sk_key_type_mapping/1` - Tests key type to OID mapping
- `ed25519_sk_key_type_mapping/1` - Tests key type to OID mapping

**Group: fido_key_encoding**
- `round_trip_ecdsa_sk/1` - Tests decode followed by encode
- `round_trip_ed25519_sk/1` - Tests decode followed by encode

Note: Round-trip tests currently encode back to non-FIDO format since we don't yet track the FIDO variant in the key structure.

## Design Decisions

### 1. Reuse Existing OIDs

FIDO keys map to the same OIDs as their non-FIDO counterparts:
- `sk-ecdsa-sha2-nistp256@openssh.com` → `secp256r1` (same as regular ECDSA P-256)
- `sk-ssh-ed25519@openssh.com` → `id-Ed25519` (same as regular Ed25519)

**Rationale**: The underlying cryptography is identical. The difference is in:
- Wire format (additional application field)
- Signature format (additional authenticator data)
- Key storage (private key stays on hardware)

### 2. Discard Application Field (Phase 1)

The application string (typically `"ssh:"`) is parsed but not stored.

**Rationale**: 
- Phase 1 goal is "recognition without crashing"
- Application field is needed for signature verification (Phase 3)
- Will be preserved in extended key structure in Phase 2

### 3. No FIDO-Specific Encoding Yet

When encoding keys back to wire format, FIDO keys become regular keys.

**Rationale**:
- Current key representation doesn't distinguish FIDO vs non-FIDO
- Phase 2 will add extended key structures to preserve FIDO metadata
- For Phase 1, one-way parsing (FIDO → internal format) is sufficient

## Key Type Summary

| Short Form | Full Form | OID | Underlying Crypto |
|------------|-----------|-----|-------------------|
| `ecdsa-sk` | `sk-ecdsa-sha2-nistp256@openssh.com` | `secp256r1` | ECDSA P-256 |
| `ed25519-sk` | `sk-ssh-ed25519@openssh.com` | `id-Ed25519` | Ed25519 |

## Wire Format Reference

### ECDSA-SK Public Key
```
string    "sk-ecdsa-sha2-nistp256@openssh.com"
string    "nistp256"
string    EC point (65 bytes: 0x04 || X || Y)
string    application (typically "ssh:")
```

### Ed25519-SK Public Key
```
string    "sk-ssh-ed25519@openssh.com"
string    public key (32 bytes)
string    application (typically "ssh:")
```

## What Works Now

✅ Parse FIDO public keys without crashing
✅ Recognize both FIDO key type identifiers
✅ Map FIDO key types to correct OIDs
✅ Decode FIDO keys into standard Erlang key structures
✅ Test coverage for parsing and key type mapping

## What Doesn't Work Yet

❌ Preserving application field in key structure
❌ Parsing optional flags and key_handle fields (OpenSSH 8.3+)
❌ Encoding keys back to FIDO format
❌ FIDO signature parsing
❌ FIDO signature verification
❌ Distinguishing FIDO keys from non-FIDO keys after parsing

## Next Steps (Phase 2: Full Parsing)

1. Define extended key structure to preserve FIDO metadata:
   ```erlang
   {{#'ECPoint'{point = Q}, {namedCurve, OID}}, 
    [{application, <<"ssh:">>}, {flags, undefined}, {key_handle, undefined}]}
   ```

2. Parse and store application field

3. Parse optional flags and key_handle fields (if present)

4. Update `ssh2_pubkey_encode/1` to handle FIDO key structures

5. Update `ssh_file.erl` to recognize FIDO keys in authorized_keys

6. Ensure round-trip encoding preserves FIDO format

## Testing

Run the test suite:
```bash
cd lib/ssh/test
ct_run -suite ssh_fido_SUITE
```

Or run specific test groups:
```bash
ct_run -suite ssh_fido_SUITE -group fido_key_parsing
ct_run -suite ssh_fido_SUITE -group fido_key_encoding
```

## Compliance

This implementation follows OpenSSH's FIDO key format as documented in:
- OpenSSH `PROTOCOL.u2f` 
- `docs/fido_ssh_notes.md` (this repository)

## Notes for Future Work

- FIDO keys will require different signature verification (69-byte authenticator data blob)
- Private keys are never stored on disk (only key handles)
- User presence verification (touch) will need to be surfaced to application layer
- Counter field in signatures enables cloned authenticator detection