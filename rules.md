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

### Task 2.1: Add Key Type Recognition
- Accept 2 key types (each has a short form and full form):
  - **ECDSA-SK**: `ecdsa-sk` or `sk-ecdsa-sha2-nistp256@openssh.com`
  - **Ed25519-SK**: `ed25519-sk` or `sk-ssh-ed25519@openssh.com`
- No functional behavior yet

**Done when**
- Both key types are recognized without crashing
- Unknown fields are preserved (application field parsed but discarded)

**Status**: NOT STARTED

---

### Task 2.2: Parse FIDO Public Key Fields
- Parse:
  - Application string
  - Flags
  - Key handle
- Store in structured Erlang term

**Done when**
- Parsed key can round-trip without loss

**Status**: NOT STARTED

---

## Milestone 3: Signature Handling (No Hardware Yet)

### Task 3.1: Accept `-sk` Signatures
- Parse incoming signature blobs
- Validate structure only (no crypto yet)

**Done when**
- Signatures parse without errors

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
- Include limitations

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
