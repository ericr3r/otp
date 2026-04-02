# OTP SSH Touchpoints for FIDO Key Support

This document identifies the key modules, functions, and code paths in Erlang/OTP's SSH implementation that need modification to support FIDO security keys (`ecdsa-sk`, `ed25519-sk`).

---

## Overview

The OTP SSH implementation is located in `lib/ssh/src/`. Key areas for FIDO support:

1. **Key Type Recognition** - Where key type strings are parsed
2. **Public Key Parsing** - Binary decoding of SSH wire format
3. **Signature Verification** - Cryptographic verification of signatures
4. **Authentication Flow** - Server-side publickey authentication
5. **Key Callbacks** - User-provided key validation hooks

---

## Module: `ssh_message.erl`

**Purpose**: Encodes and decodes SSH protocol messages, including public/private keys.

### Key Functions

#### `ssh2_pubkey_encode/1` (Lines 581-608)
Encodes Erlang public key records to SSH wire format.

**Current support:**
- `#'RSAPublicKey'{}` → `"ssh-rsa"`
- `{Y, #'Dss-Parms'{}}` → `"ssh-dss"`
- `{#'ECPoint'{}, {namedCurve, OID}}` → `"ecdsa-sha2-nistp256"` etc.
- Ed25519/Ed448 → `"ssh-ed25519"`, `"ssh-ed448"`

**Required changes:**
- Add clauses for FIDO key types with application string and flags

#### `ssh2_pubkey_decode2/1` (Lines 611-650)
Decodes SSH wire format to Erlang public key records.

**Current parsing:**
```erlang
ssh2_pubkey_decode2(<<?UINT32(7), "ssh-rsa", ...>>) -> ...
ssh2_pubkey_decode2(<<?UINT32(7), "ssh-dss", ...>>) -> ...
ssh2_pubkey_decode2(<<?DEC_BIN(SshCurveName,SCNL), Rest0/binary>>) -> ...
```

**Required changes:**
- Add pattern matching for `"sk-ecdsa-sha2-nistp256@openssh.com"` (51 bytes)
- Add pattern matching for `"sk-ssh-ed25519@openssh.com"` (26 bytes)
- Parse additional fields: application string, flags (optional), key_handle (optional)
- Store FIDO-specific data in new record types or extended tuples

**Entry point**: This is THE primary location for adding FIDO public key parsing.

#### `ssh_curvename2oid/1` and `oid2ssh_curvename/1` (Lines 774-790)
Convert between SSH curve names and OIDs.

**Current mappings:**
- `"ssh-ed25519"` ↔ `?'id-Ed25519'`
- `"ecdsa-sha2-nistp256"` ↔ `?'secp256r1'`

**Required changes:**
- Add mappings for `"sk-ecdsa-sha2-nistp256@openssh.com"` (could map to same OID + metadata)
- Add mappings for `"sk-ssh-ed25519@openssh.com"`

#### `encode_signature/3` (Lines 870+)
Encodes signatures for transmission.

**Required changes:**
- Add clauses for FIDO signature encoding (signature + flags + counter)

---

## Module: `ssh_transport.erl`

**Purpose**: SSH transport layer, including key exchange and signature verification.

### Key Functions

#### `verify/5` (Line 1581)
Main entry point for signature verification.

```erlang
verify(PlainText, Alg, Sig, Key, Ssh) ->
    do_verify(PlainText, sha(Alg), Sig, Key, Ssh).
```

**Required changes:**
- Add algorithm atom for FIDO key types (e.g., `'sk-ecdsa-sha2-nistp256@openssh.com'`)
- Route to FIDO-specific verification function

#### `do_verify/5` (Lines 1587-1616)
Algorithm-specific signature verification.

**Current clauses:**
- DSA signatures: Decode R/S components, call `public_key:verify/4`
- ECDSA signatures: Decode R/S, DER-encode, call `public_key:verify/4`
- RSA signatures: Direct call to `public_key:verify/4`
- Ed25519/Ed448: Direct call to `public_key:verify/4`

**Required changes:**
- Add new clause for FIDO keys:
  1. Parse signature structure (extract flags, counter, inner signature)
  2. Reconstruct the 69-byte authenticator data blob:
     - SHA-256(application) || flags || counter || SHA-256(PlainText)
  3. Verify inner signature against this blob using standard crypto
  4. Optionally check flags (user presence, user verification)

**Critical**: This is where FIDO signature verification logic goes.

#### `verify_host_key/4` (Lines 988-1000)
Verifies host keys (client-side).

**Current logic:**
- Check algorithm name matches
- Call `verify/5`
- Check against known_hosts

**Required changes:**
- Should work with FIDO keys once `verify/5` is updated
- May need algorithm name normalization

#### `sha/1` (Referenced in verify/5)
Maps algorithm atoms to hash algorithms.

**Required changes:**
- Add mappings:
  - `'sk-ecdsa-sha2-nistp256@openssh.com'` → `sha256`
  - `'sk-ssh-ed25519@openssh.com'` → undefined (Ed25519 is prehashed)

#### `default_algorithms1/1` (Line 195)
Defines supported algorithm lists.

**Current:**
```erlang
default_algorithms1(public_key) ->
    supported_algorithms(public_key, [
        'ssh-rsa',
        'ssh-dss'
    ]);
```

**Required changes:**
- Add `'sk-ecdsa-sha2-nistp256@openssh.com'`
- Add `'sk-ssh-ed25519@openssh.com'`
- Consider making them opt-in initially

---

## Module: `ssh_auth.erl`

**Purpose**: User authentication (both client and server sides).

### Key Functions

#### `handle_userauth_request/3` (Lines 233-350+)
Handles SSH_MSG_USERAUTH_REQUEST messages on the server.

**Publickey auth flow:**

1. **Pre-verification request** (Lines 301-330):
   - Client sends: `?FALSE, algorithm, key_blob`
   - Server calls `pre_verify_sig/3` → checks if key is authorized
   - Server responds with `SSH_MSG_USERAUTH_PK_OK`

2. **Actual authentication** (Lines 332-360):
   - Client sends: `?TRUE, algorithm, key_blob, signature`
   - Server calls `verify_sig/7` → validates signature
   - Server responds with `SUCCESS` or `FAILURE`

**Required changes:**
- None directly needed here if lower-level functions handle FIDO keys
- May want to check FIDO-specific flags or expose "user presence required" errors

#### `pre_verify_sig/3` (Lines 557-565)
Checks if a public key is authorized for a user (before signature check).

```erlang
pre_verify_sig(User, KeyBlob, #ssh{opts=Opts}) ->
    try
        Key = ssh_message:ssh2_pubkey_decode(KeyBlob),
        ssh_transport:call_KeyCb(is_auth_key, [Key, User], Opts)
    catch
        _:_ -> false
    end.
```

**Required changes:**
- Will automatically work once `ssh2_pubkey_decode/1` handles FIDO keys
- Key callback receives parsed key (including FIDO metadata)

#### `verify_sig/7` (Lines 567-579)
Verifies the signature during actual authentication.

```erlang
verify_sig(SessionId, User, Service, AlgBin, KeyBlob, SigWLen, #ssh{opts=Opts} = Ssh) ->
    try
        Alg = binary_to_list(AlgBin),
        true = lists:member(list_to_existing_atom(Alg), 
                            proplists:get_value(public_key, ...)),
        Key = ssh_message:ssh2_pubkey_decode(KeyBlob),
        true = ssh_transport:call_KeyCb(is_auth_key, [Key, User], Opts),
        PlainText = build_sig_data(SessionId, User, Service, KeyBlob, Alg),
        <<?UINT32(AlgSigLen), AlgSig:AlgSigLen/binary>> = SigWLen,
        <<?UINT32(AlgLen), _Alg:AlgLen/binary,
          ?UINT32(SigLen), Sig:SigLen/binary>> = AlgSig,
        ssh_transport:verify(PlainText, list_to_existing_atom(Alg), Sig, Key, Ssh)
    catch
        _:_ -> false
    end.
```

**Required changes:**
- May need to parse FIDO signature differently (has flags + counter after signature)
- Current code expects: `algorithm_name || signature`
- FIDO format: `algorithm_name || signature || flags || counter`
- **Option 1**: Parse here and pass components separately to `verify/5`
- **Option 2**: Pass entire blob to `verify/5` and parse there (cleaner)

#### `build_sig_data/5` (Lines 581-592)
Builds the SSH authentication message that was signed.

**Current:**
```erlang
Sig = [?binary(SessionId),
       ?SSH_MSG_USERAUTH_REQUEST,
       ?string_utf8(User),
       ?string(Service),
       ?binary(<<"publickey">>),
       ?TRUE,
       ?string(Alg),
       ?binary(KeyBlob)],
```

**Required changes:**
- None needed here
- This message is hashed and included in the FIDO authenticator data
- The FIDO signature is over a *different* blob (see docs/fido_ssh_notes.md)

#### `key_alg/1` (Lines 589-591)
Normalizes algorithm names (e.g., RSA signature variants).

**Required changes:**
- May need to normalize FIDO algorithm names if short forms are used

---

## Module: `ssh_file.erl`

**Purpose**: Reads/writes SSH key files (authorized_keys, known_hosts, identity files).

### Key Functions

#### `decode/2` (Lines 490-550+)
Decodes various key file formats.

**Relevant for:**
- `authorized_keys` format: `decode(KeyBin, auth_keys)`
- `known_hosts` format: `decode(KeyBin, known_hosts)`
- OpenSSH public key: `decode(KeyBin, openssh_key)`

**Current key type detection** (Line 581):
```erlang
case binary:match(L, [<<"ssh-rsa">>,
                      <<"rsa-sha2-">>,
                      <<"ssh-dss">>,
                      <<"ecdsa-sha2-nistp">>,
                      <<"ssh-ed">>]) of
```

**Required changes:**
- Add `<<"sk-ecdsa-sha2-">>` to pattern list
- Add `<<"sk-ssh-ed">>` to pattern list
- Ensure base64 decoding works for longer FIDO key blobs

#### `file_base_name/2` (Lines 1247-1282)
Maps key types to file names.

**Required changes:**
- Add mappings for FIDO key types:
  - `'sk-ecdsa-sha2-nistp256@openssh.com'` → `"id_ecdsa_sk"` (user) / `"ssh_host_ecdsa_sk_key"` (system)
  - `'sk-ssh-ed25519@openssh.com'` → `"id_ed25519_sk"` (user) / `"ssh_host_ed25519_sk_key"` (system)

---

## Module: `ssh_options.erl`

**Purpose**: Handles SSH configuration options and algorithm preferences.

### Key Functions

#### Algorithm preference handling (Line 959)
Validates and processes preferred algorithm lists.

**Required changes:**
- Add FIDO key types to validation
- Allow atoms like `'sk-ecdsa-sha2-nistp256@openssh.com'` or binary strings

---

## Module: `ssh_client_key_api.erl` and `ssh_server_key_api.erl`

**Purpose**: Behavior definitions for key callbacks.

### Key Callbacks

#### `is_auth_key/3` (server-side)
Called by server to check if a public key is authorized for a user.

**Signature:**
```erlang
is_auth_key(Key :: public_key:public_key(), User :: string(), Options) -> boolean()
```

**Required changes:**
- None to the behavior definition
- Implementations (like `ssh_file`) need to handle FIDO key records
- FIDO keys will include additional metadata (application, flags)

#### `user_key/2` (client-side)
Called by client to get private key for authentication.

**Required changes:**
- FIDO keys cannot be loaded from disk (no private key stored)
- Would need new callback or behavior for hardware interaction
- Initially: just support verification (server-side only)

---

## Data Structures and Records

### Existing Records (from ssh.hrl, ssh_auth.hrl)

```erlang
#ssh{} - Main SSH connection state
#alg{} - Algorithm configuration
#ssh_msg_userauth_request{} - Authentication request message
```

### New Records Needed

**Option 1: Extend existing key tuples**
```erlang
% ECDSA-SK
{{#'ECPoint'{point = Q}, {namedCurve, OID}}, 
 [{application, <<"ssh:">>}, 
  {flags, undefined}, 
  {key_handle, undefined}]}

% Ed25519-SK  
{{#'ECPoint'{point = PubKey}, {namedCurve, ?'id-Ed25519'}},
 [{application, <<"ssh:">>}]}
```

**Option 2: New record types**
```erlang
-record(ssh_sk_ecdsa_key, {
    ec_point :: #'ECPoint'{},
    curve_oid :: tuple(),
    application :: binary(),
    flags :: undefined | integer(),
    key_handle :: undefined | binary()
}).

-record(ssh_sk_ed25519_key, {
    public_key :: binary(),
    application :: binary(),
    flags :: undefined | integer(),
    key_handle :: undefined | binary()
}).
```

**Recommendation**: Start with Option 1 (extended tuples) for minimal disruption.

---

## Call Graph: Publickey Authentication (Server-Side)

```
ssh_fsm_userauth_server:handle_event/4
  └─> ssh_auth:handle_userauth_request/3
       │
       ├─> [Pre-verification phase]
       │    └─> ssh_auth:pre_verify_sig/3
       │         └─> ssh_message:ssh2_pubkey_decode/1  ← NEEDS FIDO SUPPORT
       │              └─> ssh_transport:call_KeyCb(is_auth_key, ...)
       │
       └─> [Actual authentication phase]
            └─> ssh_auth:verify_sig/7
                 ├─> ssh_message:ssh2_pubkey_decode/1  ← NEEDS FIDO SUPPORT
                 ├─> ssh_auth:build_sig_data/5
                 └─> ssh_transport:verify/5             ← NEEDS FIDO SUPPORT
                      └─> ssh_transport:do_verify/5     ← ADD FIDO CLAUSE
                           └─> public_key:verify/4      (standard crypto)
```

---

## Call Graph: Key File Parsing

```
ssh_file:decode/2
  └─> [various format handlers]
       └─> ssh_message:ssh2_pubkey_decode/1  ← NEEDS FIDO SUPPORT
            └─> ssh_message:ssh2_pubkey_decode2/1
```

---

## Implementation Strategy

### Phase 1: Recognition Only (No Crash)
1. Add FIDO key type strings to `ssh_message:ssh2_pubkey_decode2/1`
2. Parse basic structure but ignore FIDO-specific fields
3. Return standard key records (treat as regular ECDSA/Ed25519)
4. **Goal**: System doesn't crash when encountering FIDO keys

### Phase 2: Full Parsing
1. Parse application string, flags, key_handle from public keys
2. Store in extended record/tuple format
3. Preserve data through encode/decode round-trips
4. Update `ssh_file.erl` to recognize FIDO keys in files
5. **Goal**: FIDO keys can be loaded from authorized_keys

### Phase 3: Signature Verification
1. Add FIDO signature parsing in `ssh_auth:verify_sig/7` or `ssh_transport:do_verify/5`
2. Implement 69-byte authenticator data reconstruction
3. Add SHA-256 hashing of application string and message
4. Call standard ECDSA/Ed25519 verification on modified blob
5. **Goal**: FIDO signatures can be verified (no hardware needed)

### Phase 4: Algorithm Registration
1. Add FIDO algorithms to `ssh_transport:default_algorithms1/1`
2. Update `ssh_options.erl` validation
3. Add file name mappings in `ssh_file.erl`
4. **Goal**: FIDO keys work in standard SSH flows

### Phase 5: Hardware Support (Future)
1. Define authenticator behavior/callback
2. Implement key generation support
3. Implement signing support (requires hardware interaction)
4. **Goal**: Full client-side FIDO support

---

## Testing Touchpoints

### Unit Tests
- `ssh_message_SUITE.erl` - Key encoding/decoding
- `ssh_auth_SUITE.erl` - Authentication flows

### Integration Tests  
- `ssh_basic_SUITE.erl` - Basic SSH operations
- `ssh_protocol_SUITE.erl` - Protocol compliance

### Test Data Needed
- Sample FIDO public keys (ECDSA-SK, Ed25519-SK)
- Sample FIDO signatures with flags and counter
- OpenSSH-generated test vectors

---

## External Dependencies

### Required Modules
- `public_key` - Already used for standard verification
- `crypto` - SHA-256 hashing (already available)

### No New Dependencies Needed
- FIDO verification uses standard ECDSA/Ed25519
- No libfido2 or hardware interaction required for verification
- Signing (client-side) would need hardware, but that's Phase 5

---

## Files Requiring Modification

### Critical Path (Minimum Viable Implementation)
1. **`ssh_message.erl`** - Add FIDO key parsing (most important)
2. **`ssh_transport.erl`** - Add FIDO signature verification
3. **`ssh_file.erl`** - Recognize FIDO keys in key files

### Supporting Changes
4. **`ssh_options.erl`** - Algorithm validation
5. **`ssh_transport.hrl`** or **`ssh.hrl`** - Add macros/constants for FIDO

### Optional/Future
6. **`ssh_client_key_api.erl`** - New callback for hardware interaction
7. **Test suites** - Add FIDO-specific tests

---

## Key Insights

### What's Easy
- **Signature verification**: No hardware needed, just different blob format
- **Public key parsing**: Additive changes to existing decoder
- **Server-side support**: Can be done without client changes

### What's Hard
- **Client-side signing**: Requires hardware interaction (libfido2 or similar)
- **Key generation**: Also requires hardware
- **PIN/biometric prompts**: UI concerns (out of scope per project constraints)

### What's Tricky
- **FIDO signature format**: Different structure than standard SSH signatures
- **Authenticator data**: Need to reconstruct the 69-byte blob correctly
- **Backward compatibility**: Must not break existing SSH keys

---

## Next Steps

1. ✅ Document formats (see `docs/fido_ssh_notes.md`)
2. ✅ Document touchpoints (this file)
3. Add FIDO key type atoms to `ssh_transport:default_algorithms1/1` (commented out initially)
4. Implement `ssh_message:ssh2_pubkey_decode2/1` clause for ECDSA-SK
5. Test parsing with real OpenSSH ECDSA-SK public key
6. Implement `ssh_transport:do_verify/5` clause for FIDO signatures
7. Test verification with real signature + test vector
8. Repeat for Ed25519-SK

---

**Document Status**: Initial touchpoint analysis complete  
**Last Updated**: 2024  
**Next Review**: After implementing Task 2.1 (Key Type Recognition)