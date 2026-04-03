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

---

## Milestone 4: Auth Flow Integration

### Task 4.1: Hook Into Public Key Auth
- Wire `-sk` verification into:
  - `ssh_auth`
- Ensure fallback behavior unchanged

**Done when**
- `-sk` keys are attempted during auth

---

### Task 4.2: Surface Required User Presence
- Detect flags:
  - User presence required
- Expose via callback or error tuple

**Done when**
- Caller can distinguish "touch required" vs "invalid key"

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
