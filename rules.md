# Agents: Add FIDO (Security Key) Support to Erlang SSH

This project adds **server-side** support for FIDO2 / WebAuthn-backed SSH keys
(`ecdsa-sk`, `ed25519-sk`) to Erlang/OTP's `ssh` application.  The goal is to
allow an OTP SSH server to accept connections from clients that authenticate
with a FIDO hardware token.  The OTP SSH client acting as a FIDO key holder
(i.e. signing with hardware) is explicitly out of scope.

Work should proceed in **small, verifiable steps** with tests and
comparison against OpenSSH behavior at each stage.

---

## High-Level Goals

- Parse and handle `*-sk` public key formats
- Allow an OTP SSH **server** to verify FIDO-backed client authentication
- Interoperate with OpenSSH **clients** authenticating with FIDO keys
- Avoid introducing hard dependencies where possible
- Keep changes isolated and incremental

---

## Constraints & Non-Goals

- **Server-side only** — signing with a FIDO token (OTP acting as a FIDO client) is out of scope; signing happens on the user's machine before the request reaches OTP
- **No UI work** (PIN prompts may be delegated)
- **No proprietary libraries**
- Avoid breaking existing `ssh` public key auth
- Prefer pure Erlang where feasible, NIFs only if unavoidable
- **Do NOT add new public exported functions** — use existing exported functions and add new function heads via pattern matching to support the new FIDO key types
- **Test coverage must not regress** — for every modified module (`ssh_message`, `ssh_transport`, `ssh_auth`, `ssh_file`), test coverage after changes must match or exceed the coverage baseline before changes.  Measure with the existing `ssh.cover` / `ssh_all.cover` configurations and Common Test's coverage support.  New code paths (SK-specific function heads, FIDO blob construction, etc.) must be exercised by at least Tier 1 or Tier 2 tests.
- **Do NOT reformat existing code** — follow the OTP contributing guidelines
  (`CONTRIBUTING.md`):
  - Match the coding and indentation style of the surrounding code.
  - 4-space indentation, spaces only (no tabs in Erlang source).
  - Do not fix preexisting whitespace errors in otherwise untouched lines.
  - Run `git diff --check` before committing to catch whitespace errors.
  - Diffs must be minimal: only the new function heads, new list entries, or
    new clauses should appear.  If a diff touches hundreds of lines in a file
    where only a handful were added, the change must be redone.
  - Do NOT use auto-formatters (erlfmt, ELP format, editor reformat-on-save)
    on OTP source files — the upstream project does not use one and
    auto-formatting rewrites the entire file, creating noise that obscures
    the real change and will be rejected by reviewers.

---

## Milestones Overview

1. Protocol & format understanding
2. Public key parsing
3. Signature verification
4. Auth flow integration
5. ~~Hardware interaction~~ (out of scope — signing requires hardware; not needed for server-side verification)
6. Testing & interoperability
7. Documentation & cleanup
8. Docker image with `sk-dummy.so` (optional)

Each milestone is broken into atomic tasks below.

---

## Milestone 1: Research & Ground Truth

### Task 1.1: Document OpenSSH `-sk` Behavior
- Identify key types:
  - `ecdsa-sk`
  - `ed25519-sk`
- Capture:
  - Public key wire format
  - Signature structure
  - Authenticator flags
- Output:
  - `docs/fido_ssh_notes.md`

**Done when**
- Formats are written down with byte-level detail
- At least one real key inspected via `ssh-keygen -vv`

**Status**: COMPLETE ✅
- Verified both key type wire formats with byte-level hex dumps from real keys
- Inspected real ECDSA-SK key (OpenSSH test key by djm@google.com) via `ssh-keygen -vv`
- Inspected real Ed25519-SK key (hardware token, eric@rauer.dev) via `ssh-keygen -vv`
- Corrected inaccuracy: ECDSA inner `r`/`s` are `mpint`, not `string` — length may be 33 bytes when high bit is set
- Documented full FIDO-signed blob: `SHA-256(application) || flags || counter || extensions || SHA-256(M)`
- Verified signature format using OpenSSH regression test vectors (`sshsig/testdata/`)
- See `docs/fido_ssh_notes.md` for full byte-level details

---

### Task 1.2: Locate OTP SSH Touchpoints
- Identify:
  - Key parsing modules
  - Signature verification code paths
  - Auth callback interfaces
- Output:
  - Commented call graph or notes

**Done when**
- Entry points for new key types are clearly identified

**Status**: COMPLETE ✅
- Identified all 13 functions requiring new pattern-matched heads across 3 modules
- Traced full server-side auth call graph end-to-end (pre-verify and actual-auth paths)
- Traced `authorized_keys` parsing path and key file loading path
- Identified critical correctness issues: `verify_sig/7` binary match bug with SK trailing bytes, `list_to_existing_atom` atom seeding, OID machinery must not be used for SK keys
- Documented exact line numbers verified by direct source inspection
- See `docs/otp_ssh_touchpoints.md` for full call graphs and change inventory

---

## Milestone 2: Public Key Parsing

### Task 2.1: Decode and Encode SK Public Keys

Add support for decoding and encoding FIDO public key blobs in wire format.
Public key blobs contain only the key material and application string — flags
and key handle are private-key-only fields and are out of scope here.

**Wire-format key type names** (these are what appear on the wire, in
`authorized_keys` files, and in the code — the short forms `ecdsa-sk` /
`ed25519-sk` are `ssh-keygen` CLI aliases and never appear in protocol
messages):
- `sk-ecdsa-sha2-nistp256@openssh.com` (34 bytes)
- `sk-ssh-ed25519@openssh.com` (26 bytes)

**Internal term representation** (tagged tuples, no OID machinery):
- `{ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application}`
- `{ed25519_sk, PubKey, Application}`

The `Application` field (typically `<<"ssh:">>``) **must be preserved** — it is
required at verification time to compute `SHA-256(application)` for the FIDO
authenticator data blob.

**Code changes** (all in `ssh_message.erl`, see `docs/otp_ssh_touchpoints.md`
items 1–2 for exact line numbers and code):

1. `ssh2_pubkey_decode2/1` — add 2 new function heads **before** the catch-all
   at L698 that would otherwise consume SK blobs and crash in
   `ssh_curvename2oid/1`
2. `ssh2_pubkey_encode/1` — add 2 new function heads that produce the correct
   wire-format binary from the SK key tuples

**Done when**
- `ssh2_pubkey_decode2(Blob)` returns the correct tagged tuple for both key
  types, with `Application` captured
- `ssh2_pubkey_encode(Term)` produces a binary identical to the input blob
  (byte-for-byte round-trip)
- Existing non-SK key decode/encode is unaffected (run `ssh_basic_SUITE` to
  confirm zero regressions)

**Status**: COMPLETE ✅
- Added 2 new `ssh2_pubkey_decode2/1` heads in `ssh_message.erl` (before the
  catch-all) for ECDSA-SK and Ed25519-SK wire format blobs
- Added 2 new `ssh2_pubkey_encode/1` heads in `ssh_message.erl` (before the
  RSA head) producing correct wire-format binaries
- Both files compile cleanly with the bootstrap Erlang 28

---

### Task 2.2: Recognize SK Keys in `authorized_keys` and File Paths

Make SK public keys discoverable by the server's key-loading infrastructure so
that SK entries in `authorized_keys` files are not silently dropped.

**Code changes** (all in `ssh_file.erl`, see `docs/otp_ssh_touchpoints.md`
items 18 and 21):

1. `decode(Bin, auth_keys)` (L591–596) — add `<<"sk-ecdsa-sha2-">>` and
   `<<"sk-ssh-ed25519">>` to the `binary:match/2` prefix list.  Without this,
   SK key lines match `nomatch` and are silently skipped.
2. `file_base_name/2` (L1249–1269) — add 4 new heads mapping the SK algorithm
   atoms to OpenSSH file names:
   - `(user, 'sk-ecdsa-sha2-nistp256@openssh.com')` → `"id_ecdsa_sk"`
   - `(user, 'sk-ssh-ed25519@openssh.com')` → `"id_ed25519_sk"`
   - `(system, 'sk-ecdsa-sha2-nistp256@openssh.com')` → `"ssh_host_ecdsa_sk_key"`
   - `(system, 'sk-ssh-ed25519@openssh.com')` → `"ssh_host_ed25519_sk_key"`

   Insert before the `system` catch-all `(system, _) -> "ssh_host_key"` at
   L1269.

**Done when**
- Parsing an `authorized_keys` file containing SK key lines finds and decodes
  those keys (not silently dropped)
- Parsing a mixed `authorized_keys` file with both SK and non-SK keys returns
  all keys
- `file_base_name` returns correct filenames for both SK key types
- Existing non-SK `authorized_keys` parsing is unaffected

**Status**: COMPLETE ✅
- Added `<<"sk-ecdsa-sha2-">>` and `<<"sk-ssh-ed25519">>` to the
  `binary:match/2` prefix list in `decode(Bin, auth_keys)` in `ssh_file.erl`
- Added 4 new `file_base_name/2` heads in `ssh_file.erl` (before the system
  catch-all) mapping SK algorithm atoms to OpenSSH file names
- Both files compile cleanly with the bootstrap Erlang 28

---

## Milestone 3: Signature Handling (No Hardware Yet)

### Task 3.1: Accept `-sk` Signatures
- Parse incoming signature blobs
- Validate structure only (no crypto yet)

**Done when**
- Signatures parse without errors

**Code changes:**

1. `ssh_transport.erl` — `supported_algorithms(public_key)` (L231): add
   `'sk-ssh-ed25519@openssh.com'` and `'sk-ecdsa-sha2-nistp256@openssh.com'`
   at top of list.  Crypto requirements identical to non-SK counterparts.
2. `ssh_transport.erl` — `default_algorithms1(public_key)` (L197): add both
   SK atoms to the blacklist.  SK algorithms are in `supported_algorithms` but
   disabled by default until `do_verify/5` handles SK sigs (Milestone 3.2).
3. `ssh_transport.erl` — `sha/1` (L2303): add 2 heads mapping SK atoms to
   `sha256` (ECDSA-SK) and `undefined` (Ed25519-SK, prehashed).
4. `ssh_transport.erl` — `valid_key_sha_alg/3` (L2276): add 2 heads before
   catch-all accepting SK key tuples with their algorithm atoms (public only).
5. `ssh_transport.erl` — `public_algo/1` (L2288): add 2 heads mapping SK key
   tuples to their wire-format algorithm atoms.
6. `ssh_auth.erl` — `verify_sig/7` (L563): add new SK-aware clause (guard on
   algorithm binary) that parses SK signature format
   (`inner_sig_string || flags_byte || counter_u32`) before delegating to
   `ssh_transport:verify/5`.  The existing clause would `badmatch` on the 5
   trailing bytes.
7. `ssh_auth.erl` — `key_alg/1` (L594): add 2 identity-mapping heads for SK
   algorithm atoms (no aliasing like RSA).

**Tests** (6 new, in `ssh_pubkey_SUITE.erl` `ssh_public_key_decode_encode` group):
- `sk_supported_algorithms` — SK in supported, not in default
- `sk_sha_mapping` — `sha/1` returns correct hash for both SK types
- `sk_valid_key_sha_alg` — correct pairings `true`, cross-type/non-SK `false`
- `sk_public_algo` — correct algorithm atom for both SK key tuples
- `sk_verify_sig_parse_ecdsa` — well-formed ECDSA-SK sig blob through
  `verify/5` returns `false` (no crash); catch-all `do_verify` rejects
  unknown key type gracefully
- `sk_verify_sig_parse_ed25519` — same for Ed25519-SK

**Status**: COMPLETE ✅

---

### Task 3.2: Verify Signature Without User Presence
- Implement verification using:
  - Embedded public key
- Ignore:
  - Touch / PIN requirements

**Done when**
- Signature verification passes for test vectors

**Code changes:**

1. `ssh_transport.erl` — `do_verify/5` ECDSA-SK head (before catch-all):
   splits `Sig` into inner ECDSA sig + flags(1) + counter(4), extracts
   `Application` from key tuple, reconstructs 69-byte authenticator data
   blob via `fido_authenticator_data/4`, DER-encodes `(r, s)` from SSH
   `mpint` format, and calls `public_key:verify/4` with `{Q, {namedCurve,
   secp256r1}}`.
2. `ssh_transport.erl` — `do_verify/5` Ed25519-SK head (before catch-all):
   splits `Sig` into inner Ed25519 sig (64 bytes) + flags(1) + counter(4),
   reconstructs authenticator data blob, and calls `public_key:verify/4`
   with `{#'ECPoint'{point=PubKey}, {namedCurve, ?'id-Ed25519'}}` and
   hash `undefined` (EdDSA handles its own internal hashing).
3. `ssh_transport.erl` — new private `fido_authenticator_data/4` helper:
   constructs `SHA-256(Application) || Flags:8 || Counter:32 ||
   SHA-256(Message)` (69 bytes).  Shared by both SK `do_verify` heads.
4. `ssh_transport.erl` — `default_algorithms1(public_key)` (L197): removed
   SK atoms from the blacklist.  SK algorithms are now fully functional
   and enabled by default.

**Tests** (6 new, in `ssh_pubkey_SUITE.erl` `ssh_public_key_decode_encode` group):
- `sk_verify_ecdsa_correct` — real ECDSA/P-256 keypair, sign authenticator
  data blob, verify through `ssh_transport:verify/5` → `true`
- `sk_verify_ed25519_correct` — real Ed25519 keypair, sign authenticator
  data blob, verify through `ssh_transport:verify/5` → `true`
- `sk_verify_wrong_application` — correct Ed25519-SK signature but key
  has wrong application string → `false`; same sig with correct app → `true`
- `sk_verify_tampered_flags` — sign with flags=0x01, verify with
  flags=0x05 in sig → `false`; original flags → `true`
- `sk_verify_wrong_key` — sign with ECDSA key A, verify with key B →
  `false`; verify with key A → `true`
- `sk_verify_ecdsa_padded_mpint` — repeatedly sign until `r` or `s`
  requires 33-byte mpint encoding (high-bit padding), verify → `true`

**Test updates** (from Milestone 3.1):
- `sk_supported_algorithms` — updated: SK atoms now in BOTH
  `supported_algorithms` AND `default_algorithms` (no longer blacklisted)
- `sk_verify_sig_parse_ecdsa` — updated comments: do_verify/5 SK head now
  handles ECDSA-SK; random key still → `false` (no crash)
- `sk_verify_sig_parse_ed25519` — fixed: `crypto:generate_key(eddsa,
  ed25519)` returns `{Pub, Priv}` tuple, not a map; random sig → `false`

**Status**: COMPLETE ✅

**All SK tests (18 total):** 6 Milestone 2 + 6 Milestone 3.1 + 6 Milestone 3.2 — all passing.

---

## Milestone 4: Auth Flow Integration

### Task 4.1: Hook Into Public Key Auth
- Wire `-sk` verification into:
  - `ssh_auth`
- Ensure fallback behavior unchanged

**Done when**
- `-sk` keys are attempted during auth

**Code changes:**

1. `ssh_auth.erl` — exported `build_sig_data/5`: previously internal-only,
   now exported to enable integration testing of the full auth message flow.
   No functional changes to the function itself.

**Verification of existing hooks** (all confirmed working end-to-end):

- `verify_sig/7` SK-aware clause (from M3.1): correctly parses SK signature
  format (`inner_sig || flags || counter`) and delegates to
  `ssh_transport:verify/5` for both `sk-ecdsa-sha2-nistp256@openssh.com`
  and `sk-ssh-ed25519@openssh.com`.
- `handle_userauth_request/3` with `?FALSE` (pre-check): calls
  `pre_verify_sig/3` → `ssh2_pubkey_decode/1` → `is_auth_key/3` —
  correctly handles SK key tuples and returns `ssh_msg_userauth_pk_ok`.
- `handle_userauth_request/3` with `?TRUE` (actual auth): calls
  `verify_sig/7` (SK clause) → `build_sig_data/5` →
  `ssh_transport:verify/5` → `do_verify/5` (SK heads) — full
  cryptographic verification succeeds for valid SK signatures.
- `ssh_file:is_auth_key/3`: `public_algo/1` returns correct SK algorithm
  atom, `encode_key/1` produces correct base64 blob, `find_key/3` matches
  SK key type strings in `authorized_keys` files.
- `key_alg/1` identity mappings: SK algorithm atoms pass through unchanged
  (no aliasing like RSA), ensuring `get_public_key/2` resolves correctly.
- Fallback behavior: SK auth failure returns `{not_authorized, ...}` with
  `ssh_msg_userauth_failure` containing the full methods list, allowing
  the client to fall back to password or keyboard-interactive auth.

**Tests** (6 new, in `ssh_pubkey_SUITE.erl` `ssh_public_key_decode_encode` group):
- `sk_auth_precheck_ecdsa` — constructs `userauth_request` with
  `has_sig=false` and ECDSA-SK key blob, verifies server responds with
  `ssh_msg_userauth_pk_ok` (key accepted for auth attempt)
- `sk_auth_precheck_ed25519` — same for Ed25519-SK key type
- `sk_auth_verify_ecdsa` — constructs `userauth_request` with
  `has_sig=true` and valid ECDSA-SK signature over `build_sig_data`
  output, verifies `{authorized, User, {ssh_msg_userauth_success, _}}`
- `sk_auth_verify_ed25519` — same for Ed25519-SK with real Ed25519
  keypair sign+verify through full `handle_userauth_request/3` path
- `sk_auth_wrong_sig_rejected` — signs with wrong ECDSA private key,
  verifies `{not_authorized, ...}` (graceful rejection, no crash)
- `sk_auth_fallback` — sends deliberately bad Ed25519-SK signature,
  verifies server returns `ssh_msg_userauth_failure` with
  `partial_success=false` and non-empty methods list (fallback works)

**Test helpers** (4 new):
- `sk_make_server_ssh/3`: builds minimal `#ssh{}` record with proper
  `ssh_options:handle_options/2` opts, temp dir with `authorized_keys`
  containing the given SK key, and SK algorithms in `preferred_algorithms`
- `sk_cleanup_dir/1`: removes temp dir and `authorized_keys` file
- `sk_sign_ecdsa/5`: constructs FIDO authenticator data blob, signs with
  ECDSA/P-256, encodes r/s as SSH mpint, returns composite SK signature
- `sk_sign_ed25519/5`: same for Ed25519 (64-byte inner sig)
- `sk_build_userauth_data/4`: constructs the binary `data` field for
  `ssh_msg_userauth_request` with correct wire format for both
  `has_sig=false` (pre-check) and `has_sig=true` (actual auth) cases

**Status**: COMPLETE ✅

**All SK tests (24 total):** 6 Milestone 2 + 6 Milestone 3.1 + 6 Milestone 3.2 + 6 Milestone 4.1 — all passing.

---

### Task 4.2: Surface Required User Presence
- Detect flags:
  - User presence required
- Expose via callback or error tuple

**Done when**
- Caller can distinguish "touch required" vs "invalid key"

**Code changes:**

1. `ssh_options.erl` — added `sk_fido_verify_fun` server option:
   - Default: `undefined` (backward compatible — all SK auths accepted)
   - Type: `fun(FidoInfo :: map()) -> ok | {error, Reason}`
   - Validated by `check_function1/1` or `undefined`
   - Class: `user_option`

2. `ssh_auth.erl` — modified `verify_sig/7` SK clause:
   - After successful cryptographic verification via `ssh_transport:verify/5`,
     extracts `Flags` and `Counter` from the last 5 bytes of the `Sig` binary
     (same split point used by `do_verify/5` in `ssh_transport`)
   - Constructs a `FidoInfo` map:
     ```
     #{flags => integer(),           %% raw flags byte
       counter => integer(),         %% 32-bit monotonic counter
       user_presence => boolean(),   %% flags band 0x01 =/= 0
       user_verification => boolean(), %% flags band 0x04 =/= 0
       user => string(),             %% SSH username
       algorithm => atom()}          %% e.g. 'sk-ecdsa-sha2-nistp256@openssh.com'
     ```
   - Invokes `sk_fido_verify_fun` callback if configured:
     - `ok` → auth succeeds (`true`)
     - `{error, _}` → auth fails (`false`)
     - Any other return → auth fails (`false`, graceful rejection)
   - If `sk_fido_verify_fun` is `undefined`, auth succeeds (backward compat)
   - All callback errors are caught by the existing `try/catch` in `verify_sig`

**Design decisions:**

- **Callback over error tuple**: A callback (`fun/1`) was chosen over an error
  tuple because it allows the application to implement arbitrary policy:
  - Require user presence (UP flag, bit 0)
  - Require user verification (UV flag, bit 2)
  - Enforce counter monotonicity (compare against stored last-seen counter)
  - Log FIDO metadata for audit trails
  - Combine multiple checks in a single callback
- **Counter exposed but not enforced**: The counter value is passed to the
  callback but OTP SSH does not maintain counter state itself.  Counter
  monotonicity enforcement requires persistent storage, which is
  application-specific.  The callback enables this without prescribing a
  storage mechanism.
- **Flags byte exposed raw**: Both the raw `flags` integer and decoded
  booleans (`user_presence`, `user_verification`) are provided, allowing
  the callback to check any FIDO flag bit including future extensions
  (AT=0x40, ED=0x80).

**Tests** (6 new, in `ssh_pubkey_SUITE.erl` `ssh_public_key_decode_encode` group):

- `sk_fido_callback_receives_info` — verifies the callback receives a map
  with all expected keys (`flags`, `counter`, `user_presence`,
  `user_verification`, `user`, `algorithm`) and correct values for an
  ECDSA-SK auth with flags=0x05 (UP+UV) and counter=0x42
- `sk_fido_callback_rejects_no_presence` — policy callback requires UP
  (bit 0); signature has flags=0x00 → callback returns
  `{error, user_presence_required}` → auth rejected with
  `ssh_msg_userauth_failure`
- `sk_fido_callback_accepts_presence` — same policy callback; Ed25519-SK
  signature has flags=0x01 (UP set) → callback returns `ok` → auth
  succeeds with `ssh_msg_userauth_success`
- `sk_fido_counter_monotonicity` — demonstrates counter delivery to
  callback across two sequential auth attempts (counter=100, then
  counter=200); verifies the callback receives both values in order,
  enabling monotonicity enforcement
- `sk_fido_default_no_callback` — with `sk_fido_verify_fun` unset
  (default `undefined`), Ed25519-SK auth with flags=0x00 (no UP, no UV)
  still succeeds — confirms backward compatibility
- `sk_fido_callback_bad_return` — callback returns `banana` (not `ok`
  or `{error,_}`) → auth rejected gracefully (no crash), returns
  `ssh_msg_userauth_failure`

**Test helpers** (1 new):

- `sk_make_server_ssh/4`: extended version of `sk_make_server_ssh/3`
  accepting an `ExtraOpts` list that is appended to the server options
  passed to `ssh_options:handle_options/2`, enabling tests to set
  `sk_fido_verify_fun` and other options

**Status**: COMPLETE ✅

**All SK tests (30 total):** 6 Milestone 2 + 6 Milestone 3.1 + 6 Milestone 3.2 + 6 Milestone 4.1 + 6 Milestone 4.2 — all passing.

---

## Milestone 5: Hardware Interaction — OUT OF SCOPE

Signing a challenge with a FIDO token is only required when OTP SSH acts as a
FIDO **client**.  This project targets server-side verification only.  The
client's OpenSSH (or other SSH client) handles all hardware interaction before
the authentication request arrives at the OTP server.

No tasks in this milestone will be implemented.

---

## Milestone 6: Testing & Interop

All FIDO testing must work **without real hardware**.  Tests are organized in
three tiers; Tiers 1 and 2 always run, Tier 3 is optional and gated on the
availability of OpenSSH's `sk-dummy.so` software token.

### Task 6.1: Tier 1 — Synthetic Unit Tests (always runs)
- Generate regular ECDSA P-256 and Ed25519 key pairs with OTP `crypto`
- Manually construct the 69-byte FIDO authenticator blob
  (`SHA-256(application) || flags || counter || SHA-256(M)`)
- Sign the blob with the generated private key
- Package the signature in SK wire format
  (ECDSA: `mpint(r) || mpint(s) || flags || counter`;
   Ed25519: `sig_64bytes || flags || counter`)
- Feed through `do_verify/5` and `verify_sig/7` code paths
- Test cases:
  - Correct signature verifies (`true`)
  - Wrong application string → `false`
  - Tampered flags/counter → `false`
  - Signature from a different key → `false`
  - `mpint` r/s with high-bit padding (33-byte encoding) → still verifies
- Run existing OTP SSH test suites (`ssh_basic_SUITE`, etc.) to confirm
  zero regressions in non-SK key handling

**Done when**
- All synthetic verification tests pass for both key types
- No regressions in existing SSH test suites

**Code changes:**

No production code changes were needed for M6.1.  All required synthetic test
infrastructure was already in place from M2–M4.2.  M6.1 adds 10 new tests to
`ssh_pubkey_SUITE.erl` that fill coverage gaps and confirm zero regressions.

**Tests** (10 new, in `ssh_pubkey_SUITE.erl` `ssh_public_key_decode_encode` group):

Regression tests (verify non-SK paths unaffected by SK changes):

- `sk_regression_non_sk_options` — verifies `ssh_options:handle_options/2`
  still works for non-SK server/client options; confirms `sk_fido_verify_fun`
  defaults to `undefined` on server and is absent from client options;
  confirms `no_auth_needed`, `max_sessions`, and `preferred_algorithms`
  with non-SK algos still function correctly
- `sk_regression_non_sk_pubkey_decode` — round-trip encode/decode for
  standard ECDSA P-256, Ed25519, and SK ECDSA keys through
  `ssh_message:ssh2_pubkey_encode/1` and `ssh2_pubkey_decode/1`; confirms
  no interference between SK and non-SK key type handling
- `sk_regression_non_sk_verify` — standard ECDSA P-256 and Ed25519
  signatures through `ssh_transport:verify/5` (and therefore `do_verify/5`)
  still verify correctly and reject wrong messages; exercises the non-SK
  code paths alongside our new SK heads
- `sk_regression_non_sk_auth` — full non-SK publickey auth flow through
  `handle_userauth_request/3` for standard Ed25519: both `?FALSE`
  (pre-check → `ssh_msg_userauth_pk_ok`) and `?TRUE` (actual auth →
  `ssh_msg_userauth_success`) paths work correctly

Edge-case tests (boundary conditions for SK verification):

- `sk_verify_both_key_types_sequential` — ECDSA-SK verification immediately
  followed by Ed25519-SK verification; confirms no state leakage between
  the two SK key type code paths in `do_verify/5`
- `sk_verify_zero_counter` — Ed25519-SK with flags=0x00 and counter=0
  (minimum values) verifies correctly; boundary test for the 5-byte
  flags+counter extraction
- `sk_verify_max_counter` — ECDSA-SK with counter=0xFFFFFFFF (maximum
  uint32) verifies correctly; confirms no overflow in the 32-bit counter
  handling
- `sk_verify_all_flags` — Ed25519-SK with flags=0xFF (all 8 bits set)
  verifies correctly; confirms flags byte is passed through to the
  authenticator data blob without interpretation by the crypto layer

Integration/mixed tests:

- `sk_mixed_auth_sk_then_standard_fallback` — SK ECDSA auth with bad
  signature fails gracefully, then standard Ed25519 auth succeeds on
  the same server SSH state; proves SK auth failure does not corrupt
  auth state or prevent fallback to non-SK key types; uses mixed
  `authorized_keys` file containing both SK and non-SK keys
- `sk_option_validate_fido_fun` — exercises `sk_fido_verify_fun` option
  validation: accepts `undefined` and `fun/1`; rejects integer, `fun/0`,
  `fun/2`, and non-`undefined` atoms; confirms the check function in
  `ssh_options:default(server)` works correctly

**Regression validation** (existing non-SK tests confirmed passing):

- 11/11 non-SK decode/encode tests from `ssh_public_key_decode_encode`
  group: `ssh_rsa_public_key`, `ssh_dsa_public_key`, `ssh_ecdsa_public_key`,
  `ssh_rfc4716_rsa_comment`, `ssh_rfc4716_dsa_comment`,
  `ssh_rfc4716_rsa_subject`, `ssh_list_public_key`, `ssh_known_hosts`,
  `ssh_auth_keys`, `ssh_openssh_key_with_comment`,
  `ssh_openssh_key_long_header` — all passing ✅
- 7/7 fingerprint tests from `ssh_hostkey_fingerprint` group — all passing ✅
- All modified source files compile cleanly with `+warnings_as_errors`

**Synthetic test coverage mapping** (M6.1 spec → tests):

| M6.1 Requirement | Test(s) | Milestone |
|---|---|---|
| Correct signature verifies (`true`) | `sk_verify_ecdsa_correct`, `sk_verify_ed25519_correct` | M3.2 |
| Wrong application → `false` | `sk_verify_wrong_application` | M3.2 |
| Tampered flags/counter → `false` | `sk_verify_tampered_flags` | M3.2 |
| Different key → `false` | `sk_verify_wrong_key` | M3.2 |
| mpint high-bit padding → verifies | `sk_verify_ecdsa_padded_mpint` | M3.2 |
| `do_verify/5` code path | All M3.2 tests + `sk_verify_*` M6.1 tests | M3.2, M6.1 |
| `verify_sig/7` code path | All M4.1 tests + `sk_regression_non_sk_auth` | M4.1, M6.1 |
| Non-SK key handling unchanged | `sk_regression_non_sk_*` (4 tests) | M6.1 |
| Counter/flags boundary values | `sk_verify_zero_counter`, `sk_verify_max_counter`, `sk_verify_all_flags` | M6.1 |
| Mixed SK + non-SK auth | `sk_mixed_auth_sk_then_standard_fallback` | M6.1 |

**Status**: COMPLETE ✅

**All SK tests (40 total):** 6 M2 + 6 M3.1 + 6 M3.2 + 6 M4.1 + 6 M4.2 + 10 M6.1 — all passing.
**Non-SK regression tests:** 18/18 passing (zero regressions).

---

### Task 6.2: Tier 2 — Fixture-Based Parsing Tests (always runs)
- Ship OpenSSH test keys as fixtures in the repo:
  - `ecdsa_sk1.pub`, `ed25519_sk1.pub` (from OpenSSH `regress/unittests/sshkey/testdata/`)
  - These are already published under a permissive license
- Test cases:
  - Decode each key blob → verify field values (key type atom, application =
    `<<"ssh:">>"`, EC point length = 65, Ed25519 key length = 32)
  - Encode the decoded key → byte-for-byte match with original (round-trip)
  - Parse an `authorized_keys` line containing an SK key → key is found
  - Parse an `authorized_keys` file mixing SK and non-SK keys → all keys found
  - Malformed SK key blob (truncated application) → decode fails gracefully

**Done when**
- Round-trip encode/decode passes for both key types
- `authorized_keys` parsing finds SK keys

---

### Task 6.3: Tier 3 — `sk-dummy.so` Integration Tests (optional, gated)

OpenSSH ships `sk-dummy.so` — a software FIDO token used by their own CI
(`regress/misc/sk-dummy/`).  It implements the `sk-api.h` interface without
hardware, so `ssh-keygen` and `ssh` can generate keys and sign transparently.

- Build or locate `sk-dummy.so`
- Generate a test key: `ssh-keygen -t ecdsa-sk -w /path/to/sk-dummy.so`
- Put the public key in an `authorized_keys` file
- Start an OTP SSH daemon configured with SK algorithms enabled
- Connect with OpenSSH client:
  `ssh -o SecurityKeyProvider=/path/to/sk-dummy.so ...`
- Assert authentication succeeds
- Repeat for `ed25519-sk`
- Gate on test config: skip with a clear message when `sk-dummy.so` is not
  available (e.g., `{require, sk_dummy}` in CT config)

**Done when**
- At least one successful end-to-end auth (OpenSSH client → OTP server) using
  `sk-dummy.so` for both `ecdsa-sk` and `ed25519-sk`
- Test is skippable and CI passes when `sk-dummy.so` is absent

---

## Milestone 7: Cleanup & Docs

### Task 7.1: Documentation
- Update:
  - `ssh(6)`
  - `ssh_daemon`
- Include limitations, in particular:
  - **No counter monotonicity enforcement** — the FIDO signature counter is
    included in the cryptographic verification (tampering causes verification
    failure), but the server does not track `last_seen_counter` per key or
    reject signatures where `counter <= last_seen_counter`.  This means cloned
    tokens cannot be detected via counter regression.  OpenSSH's own `sshd`
    also does not enforce this by default.  Document this as a known limitation
    and potential future enhancement (would require persistent per-key state
    and a storage/callback mechanism).

---

### Task 7.2: Refactor & Stabilize
- Remove dead code
- Normalize naming
- Add comments where protocol-specific

---

## Milestone 8: Docker Image with `sk-dummy.so` (optional)

This milestone is **optional** and independent of Milestones 1–7.  It provides
a self-contained Docker image that includes OpenSSH built with `sk-dummy.so`,
enabling fully reproducible Tier 3 integration tests without requiring the host
to have OpenSSH source or FIDO libraries installed.

### Background

`sk-dummy.so` is a software FIDO token emulator that lives in OpenSSH's source
tree (`regress/misc/sk-dummy/`).  It implements the `sk-api.h` middleware
interface — the same pluggable C API that real FIDO libraries like `libfido2`
use — but backs key enrollment and signing with in-process OpenSSL/Ed25519
crypto instead of hardware.  OpenSSH's own CI uses it for all SK regression
tests.

`sk-dummy.so` is **not** distributed as a pre-built package by any Linux
distribution.  It must be compiled from the OpenSSH source tree, and it depends
on OpenSSH internal headers (`includes.h`, `crypto_api.h`, `sk-api.h`),
OpenSSL, and OpenSSH's Ed25519 implementation.  The build system uses BSD make
conventions, so building on Linux requires adaptation.  The `.so` is also
version-coupled to the OpenSSH it was built against via a compile-time
`SSH_SK_VERSION_MAJOR` check.

### Task 8.1: Create Docker Build Script

Extend the existing `ssh_compat_SUITE_data/build_scripts/` pattern to produce
a Docker image that:

- Starts from an existing `ssh_compat_suite-ssh:*` base (or builds OpenSSH
  from source with `--enable-sk` and `libfido2-dev` installed)
- Compiles `regress/misc/sk-dummy/sk-dummy.so` from the same OpenSSH source
  tree used for the main build
- Installs the `.so` at a well-known path inside the container
  (e.g., `/buildroot/ssh/lib/sk-dummy.so`)
- Configures `SecurityKeyProvider /buildroot/ssh/lib/sk-dummy.so` in the
  container's `sshd_config` and `ssh_config`
- Pre-generates `ecdsa-sk` and `ed25519-sk` host keys and user keys using
  the built-in `sk-dummy.so` provider
- Tags the image as `ssh_compat_suite-ssh-sk:<openssh_version>`

Script location: `lib/ssh/test/ssh_compat_SUITE_data/build_scripts/create-sk-dummy-image`

**Done when**
- Script builds successfully and `docker run ... ssh -Q key` lists
  `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com`
- `ssh-keygen -t ecdsa-sk` and `ssh-keygen -t ed25519-sk` work inside the
  container without hardware

---

### Task 8.2: Verify End-to-End Inside Docker

Manually verify (or script a smoke test) that the Docker image can:

- Start an OpenSSH sshd with SK host keys
- Use `ssh-keygen -t ecdsa-sk -w /buildroot/ssh/lib/sk-dummy.so` to generate
  a client key pair
- Connect from the container's OpenSSH client to an OTP SSH daemon on the host
  (or vice versa) using the SK key for `publickey` authentication
- Both `ecdsa-sk` and `ed25519-sk` key types authenticate successfully

**Done when**
- At least one round-trip authentication (OpenSSH client in Docker → OTP SSH
  server on host) succeeds for each SK key type
- The verification steps are documented so Tier 3 tests (Task 6.3) can
  reference the image

---

### Task 8.3: Integrate with Tier 3 Tests

Wire the Docker image into the Tier 3 test infrastructure from Task 6.3:

- Detect the `ssh_compat_suite-ssh-sk:*` image via `docker images` (same
  pattern as `ssh_compat_SUITE`)
- If the image is present, start the container, generate SK keys with
  `sk-dummy.so`, run the OTP daemon, connect with the containerized OpenSSH
  client, and assert auth success
- If the image is absent, skip with a clear message
- Gate independently of any local `sk-dummy.so` — the Docker image is fully
  self-contained

**Done when**
- Tier 3 tests pass when the Docker image is available
- Tier 3 tests skip cleanly when the Docker image is absent
- CI passes in both cases

---

## Definition of Done

- `*-sk` keys authenticate successfully
- No regressions in existing SSH auth
- Tests cover parsing, verification, and failure modes
- Clear documentation of limitations and requirements
- Test coverage for each modified module (`ssh_message`, `ssh_transport`, `ssh_auth`, `ssh_file`) is equal to or greater than the pre-change baseline

---

## Notes for Agents

- Prefer **small PRs**
- Every task should compile independently
- Compare behavior against OpenSSH often
- When unsure, dump raw bytes and inspect
