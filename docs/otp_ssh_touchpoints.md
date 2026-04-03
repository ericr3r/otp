# OTP SSH Touchpoints for FIDO Key Support

This document identifies every function in Erlang/OTP's SSH implementation that
must be extended to support FIDO security keys (`ecdsa-sk`, `ed25519-sk`).  All
line numbers were verified by direct inspection of the source tree.

---

## Ground Rules for All Changes

Per project constraints, **no new exported functions are to be added**.  Every
change is a new pattern-matched function head inserted into an existing function
before any existing catch-all clause.  Private (non-exported) helpers may be
added freely.

---

## Recommended Internal Key Term Representation

SK keys have no OIDs.  Do **not** force them into the `{#'ECPoint'{},
{namedCurve, OID}}` representation — that would pollute the OID machinery and
cause false matches throughout `ssh_transport.erl`.

Use plain tagged tuples:

```erlang
%% ECDSA-SK public key
{ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application :: binary()}

%% Ed25519-SK public key
{ed25519_sk, PublicKey :: binary(), Application :: binary()}
```

`Application` is the string from the wire format (typically `<<"ssh:">>`).  It
is **mandatory** at verification time (needed for `SHA-256(application)`) and
must be preserved through every encode/decode round-trip.

---

## Module: `ssh_message.erl`

### 1. `ssh2_pubkey_decode2/1`  —  L680–712

**What it does**: Pattern-matches the raw wire-format binary and returns
`{KeyTerm, RestBinary}`.

**Current heads** (in order):
- L680: `ssh-rsa`
- L687: `ssh-dss`
- L698: catch-all for any other `SshCurveName` — handles `ecdsa-sha2-*` and
  `ssh-ed*` by delegating to `ssh_curvename2oid/1`

**Required new heads** — insert BEFORE the catch-all at L698:

```erlang
%% ECDSA-SK
ssh2_pubkey_decode2(<<?UINT32(34), "sk-ecdsa-sha2-nistp256@openssh.com",
                      ?DEC_BIN(_Curve, _CL),
                      ?DEC_BIN(Q, _QL),
                      ?DEC_BIN(Application, _AL),
                      Rest/binary>>) ->
    {{ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application}, Rest};

%% Ed25519-SK
ssh2_pubkey_decode2(<<?UINT32(26), "sk-ssh-ed25519@openssh.com",
                      ?DEC_BIN(PubKey, _PL),
                      ?DEC_BIN(Application, _AL),
                      Rest/binary>>) ->
    {{ed25519_sk, PubKey, Application}, Rest};
```

Key points:
- Both heads match on the exact byte-length of the key-type string (34 and 26
  respectively) so they can never be reached by the existing catch-all.
- `Application` is captured and stored — it is required for verification.
- Optional `flags` and `key_handle` fields (private key format only) are not
  present in public key blobs and should not be matched here.
- These heads must precede L698 or the catch-all will consume them first and
  crash in `ssh_curvename2oid/1`.

---

### 2. `ssh2_pubkey_encode/1`  —  L649–673

**What it does**: Encodes an Erlang key term back to SSH wire-format binary.

**Current heads** (in order): RSA (L649), DSS (L652), Ed25519/Ed448 ECPoint
(L655), Ed25519/Ed448 ECPrivateKey (L660), ECPrivateKey catch (L666), ECPoint
catch (L671).

**Required new heads** — insert before the RSA head so they match first:

```erlang
%% ECDSA-SK
ssh2_pubkey_encode({ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application}) ->
    CurveName = <<"nistp256">>,
    <<?STRING(<<"sk-ecdsa-sha2-nistp256@openssh.com">>),
      ?STRING(CurveName),
      ?Estring(Q),
      ?Estring(Application)>>;

%% Ed25519-SK
ssh2_pubkey_encode({ed25519_sk, PubKey, Application}) ->
    <<?STRING(<<"sk-ssh-ed25519@openssh.com">>),
      ?Estring(PubKey),
      ?Estring(Application)>>;
```

---

### 3. `ssh_curvename2oid/1` and `oid2ssh_curvename/1`  —  L841–856

**No changes needed or wanted.**

SK key names (`sk-ecdsa-sha2-nistp256@openssh.com`, `sk-ssh-ed25519@openssh.com`)
do not correspond to OIDs.  Adding them here would cause incorrect behaviour in
any caller that uses the returned OID for crypto operations.  The new
`ssh2_pubkey_decode2` heads above bypass these functions entirely.

---

### 4. `encode_signature/3`  —  L944–946

**What it does**: Encodes a host-key signature for KEX reply messages.

FIDO keys are user authentication keys, not host keys.  They will not appear in
KEX reply messages.  **No changes needed here.**

---

## Module: `ssh_transport.erl`

### 5. `supported_algorithms(public_key)`  —  L231–243

**What it does**: Returns the full list of public-key algorithms this OTP build
supports, filtered by what OTP's `crypto` application actually provides.

**Required change** — add SK algorithms to the list:

```erlang
supported_algorithms(public_key) ->
    select_crypto_supported(
      [
       {'sk-ssh-ed25519@openssh.com',          [{public_keys,eddsa}, {curves,ed25519}]},
       {'sk-ecdsa-sha2-nistp256@openssh.com',  [{public_keys,ecdsa}, {hashs,sha256}, {curves,secp256r1}]},
       {'ssh-ed25519',          [{public_keys,eddsa}, {curves,ed25519}]},
       %% ... existing entries unchanged ...
      ]);
```

The crypto requirements for SK algorithms are identical to their non-SK
counterparts (both rely on ECDSA/P-256 and Ed25519 already present in OTP).

---

### 6. `default_algorithms1(public_key)`  —  L197–202

**What it does**: Returns the subset of supported algorithms that are enabled
by default (i.e., not in the blacklist).

**Required change** — SK algorithms should be in `supported_algorithms` but
may initially be kept off the default list until verification is complete.
Once Milestone 3 is done, add them:

```erlang
default_algorithms1(public_key) ->
    supported_algorithms(public_key, [
        'ssh-rsa',
        'ssh-dss'
        %% sk algorithms are enabled by default once verified
    ]);
```

---

### 7. `sha/1`  —  L2293–2327

**What it does**: Maps an algorithm atom to the hash algorithm used for signing.

**Required new heads** — insert before the catch-all `sha(Str)` at L2327:

```erlang
sha('sk-ecdsa-sha2-nistp256@openssh.com') -> sha256;
sha('sk-ssh-ed25519@openssh.com')         -> undefined; % Ed25519 is prehashed
```

These match the same hash choices as their non-SK equivalents:
`ecdsa-sha2-nistp256` → `sha256`, `ssh-ed25519` → `undefined`.

---

### 8. `valid_key_sha_alg/3`  —  L2255–2276

**What it does**: Asserts that a given key term is compatible with a given
algorithm atom.  Called by `ssh_file:decode_ssh_file/4` (L1176) and
`ssh_auth:get_public_key/2` (L154) to validate keys before use.

**Required new heads** — insert before the catch-all `valid_key_sha_alg(_, _, _) -> false` at L2276:

```erlang
valid_key_sha_alg(public,  {ecdsa_sk, #'ECPoint'{}, secp256r1, _App},
                  'sk-ecdsa-sha2-nistp256@openssh.com') -> true;
valid_key_sha_alg(public,  {ed25519_sk, _Key, _App},
                  'sk-ssh-ed25519@openssh.com')         -> true;
```

No `private` heads are needed: SK private keys live on hardware and are never
represented as OTP terms.

---

### 9. `public_algo/1`  —  L2288–2292

**What it does**: Returns the algorithm atom for a public key term.  Used by
`ssh_file:is_auth_key/3` (L320) to build the key-type string for
`authorized_keys` lookup.

**Required new heads** — insert before the existing heads:

```erlang
public_algo({ecdsa_sk, #'ECPoint'{}, secp256r1, _App}) ->
    'sk-ecdsa-sha2-nistp256@openssh.com';
public_algo({ed25519_sk, _Key, _App}) ->
    'sk-ssh-ed25519@openssh.com';
```

---

### 10. `verify/5`  —  L1703–1704

```erlang
verify(PlainText, Alg, Sig, Key, Ssh) ->
    do_verify(PlainText, sha(Alg), Sig, Key, Ssh).
```

**No change needed here.**  `sha/1` will return the right hash for SK algs
once item 7 above is in place, and `do_verify/5` handles the rest.

---

### 11. `do_verify/5`  —  L1707–1734

**What it does**: Algorithm-specific cryptographic verification.  Receives
`PlainText` (the SSH auth message `M`), `HashAlg`, raw `Sig` bytes, the decoded
public key term, and the SSH connection state.

**The FIDO verification problem**: For SK keys the `Sig` bytes arriving here
are NOT a direct EC/Ed signature over `PlainText`.  The authenticator signed a
different 69-byte blob:

```
SHA-256(application) || flags_byte || counter_uint32_be || SHA-256(M)
```

Additionally, `Sig` as received contains the inner signature blob **plus**
the flags byte and counter uint32 appended after it (see sig parsing note in
`verify_sig/7` below).

**Required new heads** — insert before the existing DSS head at L1707:

```erlang
%% ECDSA-SK: Sig = <<ecdsa_sig_blob/binary, Flags:8, Counter:32>>
do_verify(PlainText, sha256, Sig,
          {ecdsa_sk, #'ECPoint'{} = Point, secp256r1, Application}, _Ssh) ->
    try
        InnerSigLen = byte_size(Sig) - 5,   % subtract 1 (flags) + 4 (counter)
        <<EcdsaSigBlob:InnerSigLen/binary, Flags:8, Counter:32>> = Sig,
        AuthData = fido_authenticator_data(Application, Flags, Counter, PlainText),
        <<?UINT32(Rlen), R:Rlen/big-signed-integer-unit:8,
          ?UINT32(Slen), S:Slen/big-signed-integer-unit:8>> = EcdsaSigBlob,
        DerSig = public_key:der_encode('ECDSA-Sig-Value',
                                       #'ECDSA-Sig-Value'{r=R, s=S}),
        public_key:verify(AuthData, sha256, DerSig,
                          {Point, {namedCurve, ?'secp256r1'}})
    catch
        _:_ -> false
    end;

%% Ed25519-SK: Sig = <<ed25519_sig:64/binary, Flags:8, Counter:32>>
do_verify(PlainText, undefined, Sig,
          {ed25519_sk, PubKey, Application}, _Ssh) ->
    try
        <<Ed25519Sig:64/binary, Flags:8, Counter:32>> = Sig,
        AuthData = fido_authenticator_data(Application, Flags, Counter, PlainText),
        public_key:verify(AuthData, none,
                          Ed25519Sig,
                          {#'ECPoint'{point=PubKey}, {namedCurve, ?'id-Ed25519'}})
    catch
        _:_ -> false
    end;
```

With the private helper:

```erlang
%% Reconstruct the 69-byte blob that the FIDO authenticator signed.
%% See docs/fido_ssh_notes.md for byte-level detail.
fido_authenticator_data(Application, Flags, Counter, SshMessage) ->
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, SshMessage),
    <<AppHash:32/binary, Flags:8, Counter:32, MsgHash:32/binary>>.
```

No extensions are defined for SSH use, so the extensions field is always empty
and the blob is always exactly 69 bytes.

---

### 12. `sign/4` and `sign/3`  —  L1671–1695

FIDO signing requires hardware and is out of scope until Milestone 5.
**No changes needed now.**

---

## Module: `ssh_auth.erl`

### 13. `key_alg/1`  —  L594–596

**What it does**: Maps a signature algorithm atom to its corresponding key
algorithm atom.  This exists to handle RSA variants (`rsa-sha2-256` → `ssh-rsa`,
`rsa-sha2-512` → `ssh-rsa`).  Called by `get_public_key/2` (L146).

**Required new heads** — insert before the existing heads:

```erlang
key_alg('sk-ecdsa-sha2-nistp256@openssh.com') -> 'sk-ecdsa-sha2-nistp256@openssh.com';
key_alg('sk-ssh-ed25519@openssh.com')         -> 'sk-ssh-ed25519@openssh.com';
```

For SK algorithms the signature algorithm and key algorithm are the same atom
(there are no SK signing variants like there are for RSA).

---

### 14. `verify_sig/7`  —  L563–579

**What it does**: Orchestrates signature verification on the server.  Calls
`ssh_message:ssh2_pubkey_decode/1`, checks preferred algorithms, builds the
SSH auth message, then parses the raw sig blob and calls
`ssh_transport:verify/5`.

**The parsing problem**: The current sig parsing at L573–577:

```erlang
<<?UINT32(AlgSigLen), AlgSig:AlgSigLen/binary>> = SigWLen,
<<?UINT32(AlgLen), _Alg:AlgLen/binary,
  ?UINT32(SigLen), Sig:SigLen/binary>> = AlgSig,
ssh_transport:verify(PlainText, list_to_existing_atom(Alg), Sig, Key, Ssh)
```

requires `AlgSig` to be **exactly** `4 + AlgLen + 4 + SigLen` bytes.  For SK
signatures `AlgSig` has 5 trailing bytes after the inner string (`Flags:8,
Counter:32`), so the binary pattern match raises `badmatch`, which the
surrounding `try/catch` silently turns into `false`.

**Fix**: Add a new `verify_sig/7` function head pattern-matched on the SK
algorithm binary, placed before the existing clause, that allows trailing bytes:

```erlang
verify_sig(SessionId, User, Service, BAlg, KeyBlob, SigWLen,
           #ssh{opts=Opts} = Ssh)
  when BAlg =:= <<"sk-ecdsa-sha2-nistp256@openssh.com">>;
       BAlg =:= <<"sk-ssh-ed25519@openssh.com">> ->
    try
        Alg = binary_to_list(BAlg),
        true = lists:member(list_to_existing_atom(Alg),
                            proplists:get_value(public_key,
                                                ?GET_OPT(preferred_algorithms,Opts))),
        Key = ssh_message:ssh2_pubkey_decode(KeyBlob),
        true = ssh_transport:call_KeyCb(is_auth_key, [Key, User], Opts),
        PlainText = build_sig_data(SessionId, User, Service, KeyBlob, Alg),
        <<?UINT32(AlgSigLen), AlgSig:AlgSigLen/binary>> = SigWLen,
        %% SK sigs: alg_name || inner_sig_string || flags_byte || counter_u32
        %% Allow trailing bytes by matching the inner string then capturing remainder
        <<?UINT32(AlgLen), _Alg:AlgLen/binary,
          ?UINT32(SigLen), InnerSig:SigLen/binary,
          FlagsAndCounter/binary>> = AlgSig,
        Sig = <<InnerSig/binary, FlagsAndCounter/binary>>,
        ssh_transport:verify(PlainText, list_to_existing_atom(Alg), Sig, Key, Ssh)
    catch
        _:_ -> false
    end;
verify_sig(SessionId, User, Service, AlgBin, KeyBlob, SigWLen, Ssh) ->
    %% existing clause unchanged
    ...
```

`Sig` passed to `do_verify/5` is therefore `InnerSig ++ FlagsAndCounter`,
matching what the new `do_verify` heads in item 11 expect.

---

### 15. `pre_verify_sig/3`  —  L554–561

```erlang
pre_verify_sig(User, KeyBlob, #ssh{opts=Opts}) ->
    try
        Key = ssh_message:ssh2_pubkey_decode(KeyBlob),
        ssh_transport:call_KeyCb(is_auth_key, [Key, User], Opts)
    catch
        _:_ -> false
    end.
```

**No change needed.**  Once `ssh2_pubkey_decode/1` handles SK key blobs this
function works automatically.  The SK key term (with application string) is
passed directly to `is_auth_key`, giving the key callback access to all FIDO
metadata.

---

### 16. `build_sig_data/5`  —  L581–590

**No change needed.**  This constructs the SSH authentication message `M` — the
plain-text that FIDO's `SHA-256(M)` is computed over.  Its output is correct
as-is.

---

### 17. `handle_userauth_request/3`  —  L293–323 and L325–352

**No change needed.**  The two `publickey` clauses (pre-verify at L293 and
actual-auth at L325) both delegate fully to `pre_verify_sig` and `verify_sig`
respectively.  Once those work for SK keys, these clauses work automatically.

---

## Module: `ssh_file.erl`

### 18. `decode(Bin, auth_keys)`  —  L572–604

**What it does**: Parses lines from an `authorized_keys` file.  Uses
`binary:match/2` to locate the start of the key type field on each line, then
calls `ssh_message:ssh2_pubkey_decode/1` on the base64-decoded key blob.

**Current key type prefix list** (L591–597):

```erlang
case binary:match(L, [<<"ssh-rsa">>,
                      <<"rsa-sha2-">>,
                      <<"ssh-dss">>,
                      <<"ecdsa-sha2-nistp">>,
                      <<"ssh-ed">>
                     ]) of
```

**Required change** — add SK prefixes to the list:

```erlang
case binary:match(L, [<<"ssh-rsa">>,
                      <<"rsa-sha2-">>,
                      <<"ssh-dss">>,
                      <<"ecdsa-sha2-nistp">>,
                      <<"ssh-ed">>,
                      <<"sk-ecdsa-sha2-">>,   %% NEW
                      <<"sk-ssh-ed25519">>     %% NEW
                     ]) of
```

Without this change SK key lines match `nomatch` and are silently dropped, so
`is_auth_key/3` always returns `false` regardless of what `ssh2_pubkey_decode`
does.

---

### 19. `is_auth_key/3`  —  L318–326

```erlang
is_auth_key(Key0, User, Opts) ->
    Dir = ssh_dir({remoteuser,User}, Opts),
    ok = assure_file_mode(Dir, user_read),
    KeyType = normalize_alg(
                erlang:atom_to_binary(ssh_transport:public_algo(Key0), latin1)),
    Key = encode_key(Key0),
    lookup_auth_keys(KeyType, Key, ...)
```

**No direct change needed**, but depends on:
- `ssh_transport:public_algo/1` handling SK key terms (item 9)
- `ssh_message:ssh2_pubkey_encode/1` handling SK key terms (item 2), called
  via `encode_key/1` at L845

---

### 20. `extract_public_key/1`  —  L708–734

**What it does**: Extracts a public key term from a private key term.  Called
by `ssh_auth:get_public_key/2` (L155) on the client side.

**Current heads**: RSA (L708), DSA (L710), Ed25519/Ed448 ECPrivateKey (L712),
ECDSA ECPrivateKey (L725), engine key (L728).

For SK keys the "private key" loaded by `user_key/2` would be whatever the key
callback returns — likely a map or tuple containing the key handle, application
string, and public key material.

**Required new head** — shape depends on what `user_key` returns for SK keys
(to be determined when implementing Milestone 5).  At minimum the public
portion must be extracted as an SK key term:

```erlang
%% SK key: the private side is hardware; "private" file contains public key + handle
extract_public_key({ecdsa_sk, #'ECPoint'{} = Point, Curve, App, _KeyHandle}) ->
    {ecdsa_sk, Point, Curve, App};
extract_public_key({ed25519_sk, PubKey, App, _KeyHandle}) ->
    {ed25519_sk, PubKey, App};
```

---

### 21. `file_base_name/2`  —  L1249–1269

**What it does**: Maps `{role, algorithm_atom}` to the base filename for that
key type.

**Required new heads** — insert before the system catch-all at L1269:

```erlang
file_base_name(user,   'sk-ecdsa-sha2-nistp256@openssh.com') -> "id_ecdsa_sk";
file_base_name(user,   'sk-ssh-ed25519@openssh.com'        ) -> "id_ed25519_sk";
file_base_name(system, 'sk-ecdsa-sha2-nistp256@openssh.com') -> "ssh_host_ecdsa_sk_key";
file_base_name(system, 'sk-ssh-ed25519@openssh.com'        ) -> "ssh_host_ed25519_sk_key";
```

These match the filenames OpenSSH uses (`id_ecdsa_sk`, `id_ed25519_sk`).

---

### 22. Atom table seeding

`verify_sig/7` calls `list_to_existing_atom(Alg)` where `Alg` is a string from
the wire.  The atoms `'sk-ecdsa-sha2-nistp256@openssh.com'` and
`'sk-ssh-ed25519@openssh.com'` must exist in the atom table before this call or
it throws `badarg`.

The function heads added to `sha/1`, `key_alg/1`, and `valid_key_sha_alg/3`
above cause the compiler to intern those atoms at load time, which is sufficient.
No additional seeding mechanism is needed.

---

## Call Graphs

### Server-Side Publickey Authentication (full path)

```
ssh_fsm_userauth_server:handle_event/4
  └─> ssh_auth:handle_userauth_request/3
       │
       ├─> [PRE-VERIFY — client sends ?FALSE probe]          L293
       │    └─> ssh_auth:pre_verify_sig/3                    L554
       │         ├─> ssh_message:ssh2_pubkey_decode/1        L676  ← (A)
       │         │    └─> ssh_message:ssh2_pubkey_decode2/1  L680  ← NEW HEAD
       │         └─> KeyCb:is_auth_key/3
       │              └─> ssh_file:is_auth_key/3             L318
       │                   ├─> ssh_transport:public_algo/1   L2288 ← NEW HEAD
       │                   └─> ssh_message:ssh2_pubkey_encode/1 L649 ← NEW HEAD
       │
       └─> [ACTUAL AUTH — client sends ?TRUE + sig]          L325
            └─> ssh_auth:verify_sig/7                        L563  ← NEW HEAD
                 ├─> list_to_existing_atom(Alg)                    ← atoms seeded
                 ├─> ssh_message:ssh2_pubkey_decode/1        L676  ← (A)
                 ├─> KeyCb:is_auth_key/3
                 ├─> ssh_auth:build_sig_data/5               L581  (no change)
                 └─> ssh_transport:verify/5                  L1703
                      └─> ssh_transport:do_verify/5          L1707 ← NEW HEAD
                           ├─> fido_authenticator_data/4           (new private helper)
                           │    └─> crypto:hash(sha256, ...)
                           └─> public_key:verify/4                 (standard OTP)
```

### `authorized_keys` Parsing Path

```
ssh_file:decode/2 (auth_keys)                               L572
  ├─> binary:match(L, KeyTypePrefixes)                      L591  ← ADD sk- PREFIXES
  └─> ssh_message:ssh2_pubkey_decode/1                      L676  ← (A)
       └─> ssh_message:ssh2_pubkey_decode2/1                L680  ← NEW HEAD
```

### Key File Loading Path (Client Side)

```
ssh_auth:get_public_key/2                                   L145
  ├─> ssh_auth:key_alg/1                                    L594  ← NEW HEAD
  ├─> KeyCb:user_key/2
  │    └─> ssh_file:user_key/2                              L359
  │         └─> ssh_file:read_ssh_key_file/4                L1121
  │              └─> ssh_file:file_base_name/2              L1249 ← NEW HEAD
  ├─> ssh_transport:valid_key_sha_alg/3                     L2255 ← NEW HEAD
  ├─> ssh_file:extract_public_key/1                         L708  ← NEW HEAD
  └─> ssh_message:ssh2_pubkey_encode/1                      L649  ← NEW HEAD
```

---

## Complete Change Inventory

| # | Module              | Function                  | Lines      | Change        |
|---|---------------------|---------------------------|------------|---------------|
| 1 | `ssh_message.erl`   | `ssh2_pubkey_decode2/1`   | L698       | 2 new heads before catch-all |
| 2 | `ssh_message.erl`   | `ssh2_pubkey_encode/1`    | L649       | 2 new heads   |
| 3 | `ssh_transport.erl` | `supported_algorithms/1`  | L231       | 2 new entries |
| 4 | `ssh_transport.erl` | `default_algorithms1/1`   | L197       | 2 new entries (Milestone 4) |
| 5 | `ssh_transport.erl` | `sha/1`                   | L2327      | 2 new heads before catch-all |
| 6 | `ssh_transport.erl` | `valid_key_sha_alg/3`     | L2276      | 2 new heads before false catch-all |
| 7 | `ssh_transport.erl` | `public_algo/1`           | L2288      | 2 new heads   |
| 8 | `ssh_transport.erl` | `do_verify/5`             | L1707      | 2 new heads + private `fido_authenticator_data/4` |
| 9 | `ssh_auth.erl`      | `key_alg/1`               | L594       | 2 new heads   |
|10 | `ssh_auth.erl`      | `verify_sig/7`            | L563       | 1 new head (SK variant with trailing-byte parsing) |
|11 | `ssh_file.erl`      | `decode/2` (auth_keys)    | L591       | 2 new binary match patterns |
|12 | `ssh_file.erl`      | `extract_public_key/1`    | L708       | 2 new heads   |
|13 | `ssh_file.erl`      | `file_base_name/2`        | L1249      | 4 new heads   |

Functions that need **no changes** because they delegate entirely to the above:
- `ssh_transport:verify/5` (L1703)
- `ssh_auth:pre_verify_sig/3` (L554)
- `ssh_auth:handle_userauth_request/3` (L293, L325)
- `ssh_auth:build_sig_data/5` (L581)
- `ssh_file:is_auth_key/3` (L318)

---

## Implementation Order

Work can proceed strictly milestone by milestone.  Within each milestone the
changes are independent enough to compile and test incrementally.

**Milestone 2 (Parsing)**
- Items 1, 2 — `ssh2_pubkey_decode2` and `ssh2_pubkey_encode`
- Item 11 — `decode(auth_keys)` prefix patterns
- Item 13 — `file_base_name`
- Verify: round-trip encode/decode of both key types

**Milestone 3 (Verification)**
- Items 3, 5, 6, 7 — algorithm registration and key validation
- Item 8 — `do_verify` + `fido_authenticator_data`
- Item 9, 10 — `key_alg` and `verify_sig` SK head
- Verify: signature verification against OpenSSH test vectors

**Milestone 4 (Auth Flow)**
- Item 4 — `default_algorithms1` enable SK by default
- Item 12 — `extract_public_key` (client path)
- Verify: full server-side auth against OpenSSH client

**Milestone 5 (Hardware / Client)**
- `sign/3,4` in `ssh_transport.erl` — hardware signing
- `user_key/2` in `ssh_file.erl` / key callback — load SK keys

---

**Document status**: Complete — all line numbers verified by direct source
inspection.  All call paths traced end-to-end.