# Task 2.2: Parse FIDO Public Key Fields - Implementation Notes

## Summary

Task 2.2 implements full parsing and preservation of FIDO-specific public key fields. FIDO keys now store the application string (required for signature verification), flags, and key_handle fields, and can be round-tripped without data loss.

## Changes Made

### 1. Modified `lib/ssh/src/ssh_message.erl`

#### Added `ssh2_pubkey_decode_full/1` function

A new public API function that preserves FIDO metadata:

```erlang
ssh2_pubkey_decode_full(KeyBlob) -> {{Key, SkData}, RestBlob} | {Key, RestBlob}
```

- **For FIDO keys**: Returns `{{Key, SkData}, RestBlob}` where `SkData` is a proplist with FIDO fields
- **For regular keys**: Returns `{Key, RestBlob}` for backward compatibility

#### Updated `ssh2_pubkey_decode2/1` function

Now returns different tuple formats based on key type:

**Regular keys (RSA, DSS, ECDSA, Ed25519):**
```erlang
{Key, Rest}  % 2-tuple
```

**FIDO keys (ECDSA-SK, Ed25519-SK):**
```erlang
{Key, SkData, Rest}  % 3-tuple
```

Where `SkData` is a proplist:
```erlang
[{application, <<"ssh:">>}, {flags, 1}, {key_handle, <<"...">>}]
```

#### Added `parse_sk_options/1` function

Parses optional FIDO fields (flags and key_handle) added in OpenSSH 8.3+:

```erlang
parse_sk_options(<<?UINT32(Flags), ?DEC_BIN(KeyHandle, _KHL), Rest/binary>>) ->
    {Flags, KeyHandle, Rest};
parse_sk_options(Rest) ->
    {undefined, undefined, Rest}.
```

#### Added `ssh2_pubkey_encode_sk/2` function

Encodes FIDO keys back to wire format with all fields preserved:

```erlang
ssh2_pubkey_encode_sk({#'ECPoint'{point = Q}, {namedCurve, OID}}, SkData)
```

Handles:
- ECDSA-SK: `sk-ecdsa-sha2-nistp256@openssh.com`
- Ed25519-SK: `sk-ssh-ed25519@openssh.com`
- Optional fields: flags and key_handle

#### Added `encode_sk_options/2` helper

Encodes optional FIDO fields:
- Both flags and key_handle present
- Only flags present (unusual but handled)
- No optional fields (OpenSSH < 8.3)

#### Updated `ssh2_pubkey_encode/1`

Added clause to handle FIDO extended tuple format:

```erlang
ssh2_pubkey_encode({{#'ECPoint'{point = Q}, {namedCurve,OID}}, SkData}) 
    when is_list(SkData) ->
    ssh2_pubkey_encode_sk({#'ECPoint'{point = Q}, {namedCurve,OID}}, SkData).
```

### 2. FIDO Key Data Structure

FIDO keys use an **extended tuple format**:

```erlang
{{Key, SkData}, Rest}
```

Where:
- `Key`: Standard Erlang public key structure (`{#'ECPoint'{}, {namedCurve, OID}}`)
- `SkData`: Proplist with FIDO-specific fields

#### SkData Format

```erlang
[
    {application, <<"ssh:">>},      % Required: application string for signature verification
    {flags, 1},                      % Optional: authenticator flags (OpenSSH 8.3+)
    {key_handle, <<"blob">>}         % Optional: key handle blob (OpenSSH 8.3+)
]
```

#### Field Descriptions

**application** (binary, required):
- Application identifier (typically `"ssh:"`)
- **CRITICAL**: Required for FIDO signature verification
- Used in signature computation: `sha256(application) || flags || counter || sha256(message)`

**flags** (integer | undefined, optional):
- Authenticator flags from key generation
- Added in OpenSSH 8.3+
- Common values:
  - `1` (0x01): User presence verified (UP)
  - `5` (0x05): User presence + verification (UP + UV)
  - `undefined`: Field not present in wire format

**key_handle** (binary | undefined, optional):
- Opaque blob returned by authenticator during key generation
- Added in OpenSSH 8.3+
- Client-side only: server doesn't need it for verification
- Preserved for completeness and round-trip fidelity
- `undefined`: Field not present in wire format

## Wire Format Details

### ECDSA-SK Public Key (OpenSSH 8.2)

```
string    "sk-ecdsa-sha2-nistp256@openssh.com"
string    "nistp256"
string    EC point (65 bytes)
string    application
```

### ECDSA-SK Public Key (OpenSSH 8.3+)

```
string    "sk-ecdsa-sha2-nistp256@openssh.com"
string    "nistp256"
string    EC point (65 bytes)
string    application
uint32    flags (optional)
string    key_handle (optional)
```

### Ed25519-SK Public Key (OpenSSH 8.2)

```
string    "sk-ssh-ed25519@openssh.com"
string    public key (32 bytes)
string    application
```

### Ed25519-SK Public Key (OpenSSH 8.3+)

```
string    "sk-ssh-ed25519@openssh.com"
string    public key (32 bytes)
string    application
uint32    flags (optional)
string    key_handle (optional)
```

## API Usage

### Backward Compatible API (Task 2.1)

```erlang
%% Returns just the key (FIDO metadata discarded)
Key = ssh_message:ssh2_pubkey_decode(KeyBlob).
```

**Use when:**
- You don't need FIDO metadata
- Compatibility with existing code
- Testing basic key recognition

### Full Metadata API (Task 2.2)

```erlang
%% Returns key with FIDO metadata preserved
{{Key, SkData}, Rest} = ssh_message:ssh2_pubkey_decode_full(KeyBlob).

%% Access FIDO fields
Application = proplists:get_value(application, SkData),
Flags = proplists:get_value(flags, SkData),
KeyHandle = proplists:get_value(key_handle, SkData).

%% Encode back with metadata preserved
EncodedBlob = ssh_message:ssh2_pubkey_encode({Key, SkData}).
```

**Use when:**
- Implementing FIDO signature verification (needs application string)
- Need to preserve FIDO metadata
- Round-trip encoding/decoding of FIDO keys
- Working with authorized_keys files

## Round-Trip Preservation

### Before (Task 2.1)

```erlang
%% FIDO key → decode → encode → regular key
FidoBlob = ...,
Key = ssh_message:ssh2_pubkey_decode(FidoBlob),
RegularBlob = ssh_message:ssh2_pubkey_encode(Key).
%% Result: FIDO metadata lost, becomes regular ECDSA/Ed25519
```

### After (Task 2.2)

```erlang
%% FIDO key → decode → encode → FIDO key
FidoBlob = ...,
{{Key, SkData}, _} = ssh_message:ssh2_pubkey_decode_full(FidoBlob),
FidoBlob2 = ssh_message:ssh2_pubkey_encode({Key, SkData}).
%% Result: FIDO metadata preserved, bit-for-bit identical
```

## Design Decisions

### 1. Extended Tuple Format (Not New Records)

**Chosen**: `{{Key, SkData}, Rest}`  
**Rejected**: `#ssh_sk_ecdsa_key{}` record

**Rationale**:
- Minimal disruption to existing code
- Easy to distinguish FIDO from non-FIDO keys (check if tuple)
- No need to modify record definitions in header files
- Proplist is flexible for optional fields
- Pattern matching still works cleanly

### 2. Application String is Always Parsed and Stored

**Why critical**:
- Required for FIDO signature verification (Phase 3)
- Cannot verify signatures without it
- Server-side verification mandatory field

### 3. Flags and Key_Handle are Optional

**Why optional**:
- Added in OpenSSH 8.3+ (not present in 8.2)
- Server doesn't need them for verification
- Preserved for completeness and round-trip fidelity
- Graceful handling when absent

### 4. Two Decode APIs

**`ssh2_pubkey_decode/1`**: Backward compatible, returns key only  
**`ssh2_pubkey_decode_full/1`**: New API, preserves FIDO metadata

**Rationale**:
- Maintains backward compatibility
- Existing code doesn't break
- New code can opt-in to full metadata
- Clear naming convention

### 5. Proplist for SkData

**Why proplist**:
- Flexible: easy to add new fields in future
- Standard Erlang pattern
- Works well with `proplists` module
- Easy to pattern match on specific fields
- Handles optional fields naturally (`undefined` values)

## What Works Now

✅ Parse application string from FIDO keys  
✅ Store application string in extended tuple  
✅ Parse optional flags field (OpenSSH 8.3+)  
✅ Parse optional key_handle field (OpenSSH 8.3+)  
✅ Graceful handling of missing optional fields  
✅ Encode FIDO keys back to wire format with all fields  
✅ Round-trip preservation (decode → encode → decode)  
✅ Backward compatible API (`ssh2_pubkey_decode/1`)  
✅ New full metadata API (`ssh2_pubkey_decode_full/1`)  
✅ Support for both OpenSSH 8.2 and 8.3+ formats  
✅ Test coverage for all field combinations  

## What Doesn't Work Yet

❌ FIDO signature parsing (Phase 3)  
❌ FIDO signature verification (Phase 3)  
❌ Using application string in signature verification (Phase 3)  
❌ Loading FIDO keys from authorized_keys files (Phase 4)  
❌ Algorithm registration in SSH transport (Phase 4)  
❌ Hardware interaction for signing (Phase 5)  

## Testing

### Test Coverage

**6 new tests added** (Task 2.2):
1. `parse_ecdsa_sk_with_application` - Application field parsing
2. `parse_ed25519_sk_with_application` - Application field parsing
3. `parse_ecdsa_sk_with_all_fields` - All fields including optional
4. `parse_ed25519_sk_with_all_fields` - All fields including optional
5. `round_trip_fido_full_ecdsa` - Full round-trip preservation
6. `round_trip_fido_full_ed25519` - Full round-trip preservation

**Total test suite**:
- 12/12 tests pass (6 from Task 2.1 + 6 from Task 2.2)
- 5/5 regression tests pass
- 100% pass rate

### Test Scenarios Covered

- [x] FIDO keys with application only (OpenSSH 8.2 format)
- [x] FIDO keys with application + flags + key_handle (OpenSSH 8.3+ format)
- [x] Round-trip encoding preserves all fields
- [x] Backward compatible API still works
- [x] New full metadata API works
- [x] Both ECDSA-SK and Ed25519-SK variants
- [x] No regressions in regular (non-FIDO) keys

## Example Usage

### Server-Side: Extracting Application String

```erlang
%% When receiving a FIDO public key for authentication
{{Key, SkData}, _} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

%% Extract application string (needed for signature verification)
Application = proplists:get_value(application, SkData),

%% Store for later use in signature verification (Phase 3)
%% Signature verification needs: sha256(Application) || flags || counter || sha256(message)
```

### Client-Side: Loading FIDO Key

```erlang
%% Read FIDO public key from file
{ok, KeyBlob} = file:read_file("id_ecdsa_sk.pub"),
{{Key, SkData}, _} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

%% Access all fields
{#'ECPoint'{point = ECPoint}, {namedCurve, OID}} = Key,
Application = proplists:get_value(application, SkData),
Flags = proplists:get_value(flags, SkData),         % May be undefined
KeyHandle = proplists:get_value(key_handle, SkData), % May be undefined
```

### Round-Trip Processing

```erlang
%% Load, process, and save back
{{Key, SkData}, _} = ssh_message:ssh2_pubkey_decode_full(OriginalBlob),

%% Do something with the key...

%% Save back with all metadata preserved
NewBlob = ssh_message:ssh2_pubkey_encode({Key, SkData}),
file:write_file("id_ecdsa_sk.pub", NewBlob).
```

## Next Steps (Phase 3: Signature Verification)

Based on this implementation, the next phase should:

1. **Parse FIDO Signatures**
   - Parse signature structure: `string signature_type, string signature_blob, byte flags, uint32 counter`
   - Store in similar extended tuple format

2. **Implement Signature Verification**
   - Use application string from SkData
   - Reconstruct 69-byte authenticator data blob
   - Verify signature using standard ECDSA/Ed25519 verification

3. **Hook Into Auth Flow**
   - Modify `ssh_auth.erl` to handle FIDO signatures
   - Pass application string through to verification

4. **Add Tests**
   - Test vectors from OpenSSH
   - Signature verification with real FIDO signatures
   - Authentication flow end-to-end

## Compliance

This implementation follows:
- OpenSSH PROTOCOL.u2f specification
- OpenSSH 8.2+ FIDO key format
- OpenSSH 8.3+ optional fields extension
- FIDO2/WebAuthn standards (for application string semantics)

## Notes for Future Work

### Application String Usage

The application string will be used in Phase 3 like this:

```erlang
%% During signature verification
ApplicationHash = crypto:hash(sha256, Application),  % 32 bytes
MessageHash = crypto:hash(sha256, MessageToSign),     % 32 bytes
BlobToVerify = <<ApplicationHash/binary, Flags:8, Counter:32, MessageHash/binary>>,
%% Total: 32 + 1 + 4 + 32 = 69 bytes

%% Verify signature against this blob
verify_signature(BlobToVerify, Signature, PublicKey).
```

### Key_Handle Usage

While we preserve it, the key_handle is primarily client-side:
- Client passes it to hardware token during signing
- Server never needs it
- But good to preserve for file format fidelity

### Flags Field

The flags in the public key are informational. The actual flags used for signature verification come from the signature blob itself (not from the public key).

## Conclusion

Task 2.2 successfully implements complete FIDO public key field parsing and preservation. The application string is now available for signature verification (Phase 3), and all FIDO metadata can be round-tripped without loss. The implementation maintains full backward compatibility while providing new APIs for FIDO-aware code.