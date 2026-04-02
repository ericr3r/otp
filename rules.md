# Agents: Add FIDO (Security Key) Support to Erlang SSH

This project adds support for FIDO2 / WebAuthn-backed SSH keys
(`ecdsa-sk`, `ed25519-sk`) to Erlang/OTP's `ssh` application.

Work should proceed in **small, verifiable steps** with tests and
comparison against OpenSSH behavior at each stage.

---

## High-Level Goals

- Parse and handle `*-sk` public key formats
- Support SSH authentication using FIDO-backed keys
- Interoperate with OpenSSH clients and servers
- Avoid introducing hard dependencies where possible
- Keep changes isolated and incremental

---

## Constraints & Non-Goals

- **No UI work** (PIN prompts may be delegated)
- **No proprietary libraries**
- Avoid breaking existing `ssh` public key auth
- Prefer pure Erlang where feasible, NIFs only if unavoidable

---

## Milestones Overview

1. Protocol & format understanding
2. Public key parsing
3. Signature verification
4. Auth flow integration
5. Hardware interaction
6. Testing & interoperability
7. Documentation & cleanup

Each milestone is broken into atomic tasks below.

---

## Milestone 1: Research & Ground Truth

### Task 1.1: Document OpenSSH `-sk` Behavior ✅
- Identify key types:
  - `ecdsa-sk`
  - `ed25519-sk`
- Capture:
  - Public key wire format
  - Signature structure
  - Authenticator flags
- Output:
  - `docs/fido_ssh_notes.md` ✅

**Done when**
- ✅ Formats are written down with byte-level detail
- ✅ At least one real key inspected via `ssh-keygen -vv`

**Status**: COMPLETE - See `docs/fido_ssh_notes.md`

---

### Task 1.2: Locate OTP SSH Touchpoints ✅
- Identify:
  - Key parsing modules
  - Signature verification code paths
  - Auth callback interfaces
- Output:
  - Commented call graph or notes ✅

**Done when**
- ✅ Entry points for new key types are clearly identified

**Status**: COMPLETE - See `docs/otp_ssh_touchpoints.md`
- Key modules identified: ssh_message.erl, ssh_transport.erl, ssh_auth.erl
- Full call graphs documented
- Implementation strategy outlined

---

## Milestone 2: Public Key Parsing

### Task 2.1: Add Key Type Recognition ✅
- Accept 2 key types (each has a short form and full form):
  - **ECDSA-SK**: `ecdsa-sk` or `sk-ecdsa-sha2-nistp256@openssh.com`
  - **Ed25519-SK**: `ed25519-sk` or `sk-ssh-ed25519@openssh.com`
- No functional behavior yet

**Done when**
- ✅ Both key types are recognized without crashing
- ✅ Unknown fields are preserved (application field parsed but discarded)

**Status**: COMPLETE ✅
- Modified `ssh_message.erl` to parse FIDO key formats
- Added key type to OID mappings for both FIDO key types
- Created comprehensive test suite `ssh_fido_SUITE.erl` (6 tests, all passing)
- Created regression test suite `test_fido_regression.erl` (5 tests, all passing)
- Added to test Makefile
- **Test Results**: 11/11 tests passed (100% pass rate)
- No compilation errors or warnings
- No regressions detected in existing SSH functionality
- See `TASK_2.1_TEST_RESULTS.md` for full test report
- See `docs/task_2.1_implementation_notes.md` for implementation details

---

### Task 2.2: Parse FIDO Public Key Fields ✅
- Parse:
  - Application string
  - Flags
  - Key handle
- Store in structured Erlang term

**Done when**
- ✅ Parsed key can round-trip without loss

**Status**: COMPLETE ✅
- Implemented extended tuple format for FIDO keys: `{{Key, SkData}, Rest}`
- Added `ssh2_pubkey_decode_full/1` API to preserve FIDO metadata
- Added `ssh2_pubkey_encode_sk/2` to encode FIDO keys with all fields
- Added `parse_sk_options/1` to handle optional fields (flags, key_handle)
- Application string now stored and preserved (required for signature verification)
- Optional flags and key_handle fields parsed and stored (OpenSSH 8.3+)
- Full round-trip preservation: FIDO key → decode → encode → identical FIDO key
- Backward compatible: `ssh2_pubkey_decode/1` still works without FIDO metadata
- Added 6 new tests, all passing (12/12 total tests pass)
- No regressions in existing functionality
- See `docs/task_2.2_implementation_notes.md` for full details

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

## Milestone 5: Hardware Interaction (Optional / Pluggable)

### Task 5.1: Define Authenticator Interface
- Behavior for:
  - Signing challenge
  - PIN entry
- No implementation yet

**Done when**
- Interface is stable and documented

---

### Task 5.2: Reference Implementation (Optional)
- Implement via:
  - External helper
  - or libfido2 (NIF)

**Done when**
- Hardware-backed auth works in at least one environment

---

## Milestone 6: Testing & Interop

### Task 6.1: Golden Test Vectors
- Capture:
  - Public key
  - Signature
  - Challenge
- Store as fixtures

**Done when**
- Tests pass without hardware

---

### Task 6.2: OpenSSH Interop Tests
- Scenarios:
  - OpenSSH client → Erlang server
  - Erlang client → OpenSSH server
- Document failures

**Done when**
- At least one successful end-to-end auth

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

## Definition of Done

- `*-sk` keys authenticate successfully
- No regressions in existing SSH auth
- Tests cover parsing, verification, and failure modes
- Clear documentation of limitations and requirements

---

## Notes for Agents

- Prefer **small PRs**
- Every task should compile independently
- Compare behavior against OpenSSH often
- When unsure, dump raw bytes and inspect
