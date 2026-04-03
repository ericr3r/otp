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
- **Do NOT add new public exported functions** — use existing exported functions and add new function heads via pattern matching to support the new FIDO key types

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
