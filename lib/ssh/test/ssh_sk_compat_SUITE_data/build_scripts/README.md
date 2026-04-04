# FIDO/U2F Security Key Docker Test Infrastructure

This directory contains build scripts and Docker configuration for
end-to-end integration testing of FIDO/U2F security key authentication
between a real OpenSSH client and the Erlang OTP SSH daemon.

## Overview

The Erlang SSH application supports server-side verification of FIDO/U2F
security key authentication (`sk-ecdsa-sha2-nistp256@openssh.com` and
`sk-ssh-ed25519@openssh.com`). To test the full protocol flow without
requiring a physical hardware token, we use OpenSSH's **`sk-dummy.so`**
middleware — a software-only FIDO authenticator built from the OpenSSH
regression test tree.

The Docker image built by these scripts contains:

- **OpenSSH** (portable, >= 9.2p1) compiled from source
- **`sk-dummy.so`** built from `regress/misc/sk-dummy/sk-dummy.c`
- Pre-generated ECDSA-SK and Ed25519-SK test key pairs
- A test user (`sshtester` / `foobar`) with password and pubkey auth
- `sshd` configured to accept SK key types on port 1234

## Test Tiers

The FIDO test coverage is organized into three tiers:

| Tier | Suite | Description | Hardware Required |
|------|-------|-------------|-------------------|
| 1 | `ssh_pubkey_SUITE` | Synthetic unit tests: encode/decode, signature verification with programmatically constructed signatures | No |
| 2 | `ssh_pubkey_SUITE` | Fixture-based tests: parse and verify real OpenSSH-generated public keys and authorized_keys files | No |
| **3** | **`ssh_sk_compat_SUITE`** | **Docker integration tests: full SSH protocol flow with OpenSSH client using `sk-dummy.so`** | **No (uses sk-dummy.so)** |

This directory supports **Tier 3** testing.

## Prerequisites

- **Docker** installed and the Docker daemon running
- Network access to download OpenSSH source tarballs (only during image build)
- Sufficient disk space for the Docker image (~500 MB)

## Building the Docker Image

```sh
cd lib/ssh/test/ssh_sk_compat_SUITE_data/build_scripts/
./create-sk-image           # builds with default OpenSSH version (9.9p1)
./create-sk-image 9.6p1    # or specify a version
```

The script will:

1. Download the OpenSSH portable tarball (cached for subsequent builds)
2. Generate a `Dockerfile.sk` from a template
3. Build a Docker image that compiles OpenSSH with `sk-dummy.so`
4. Tag the image as `ssh_sk_compat_suite-sk:openssh<version>`
5. Also tag as `ssh_sk_compat_suite:latest` for the test suite

### Manual Build (Alternative)

If you prefer to build manually:

```sh
docker build \
    --build-arg OPENSSH_VER=9.9p1 \
    -t ssh_sk_compat_suite:latest \
    -f Dockerfile \
    .
```

## Verifying the Image

```sh
# Start the container
docker run -d --rm -p 2222:1234 --name sk-test ssh_sk_compat_suite:latest

# Verify sk-dummy.so is present
docker exec sk-test ls -la /buildroot/ssh/lib/sk-dummy.so

# Verify pre-generated SK keys exist
docker exec sk-test ls -la /home/sshtester/.ssh/id_ecdsa_sk.pub
docker exec sk-test ls -la /home/sshtester/.ssh/id_ed25519_sk.pub

# Generate a new SK key using sk-dummy.so
docker exec sk-test /bin/sh -c \
    'SSH_SK_PROVIDER=/buildroot/ssh/lib/sk-dummy.so \
     /buildroot/ssh/bin/ssh-keygen -t ecdsa-sk -f /tmp/test_key -N ""'

# View the generated public key
docker exec sk-test cat /tmp/test_key.pub

# Clean up
docker kill sk-test
```

## Running the Integration Tests

The test suite `ssh_sk_compat_SUITE` is designed to be run via Common Test:

```sh
# From the OTP build root
cd lib/ssh
ct_run -suite test/ssh_sk_compat_SUITE -logdir /tmp/ct_logs
```

Or from the Erlang shell:

```erlang
ct:run_test([{suite, "test/ssh_sk_compat_SUITE"},
             {logdir, "/tmp/ct_logs"}]).
```

The suite will automatically:

1. Check for Docker availability (skips gracefully if unavailable)
2. Check for the `ssh_sk_compat_suite:latest` image
3. Start a container per test group
4. Generate fresh SK keys inside the container using `sk-dummy.so`
5. Start an Erlang SSH daemon and have the Docker OpenSSH client authenticate to it
6. Verify authentication succeeds/fails as expected
7. Clean up containers after each group

### Test Cases

| Test Case | Description |
|-----------|-------------|
| `check_docker_sk_present` | Verifies Docker and the SK image are available |
| `sk_keygen_ecdsa_in_docker` | Generates an ECDSA-SK key with sk-dummy.so and verifies OTP can parse it |
| `sk_keygen_ed25519_in_docker` | Generates an Ed25519-SK key with sk-dummy.so and verifies OTP can parse it |
| `sk_login_ecdsa_otp_is_server` | End-to-end: OpenSSH client authenticates to Erlang sshd with ECDSA-SK |
| `sk_login_ed25519_otp_is_server` | End-to-end: OpenSSH client authenticates to Erlang sshd with Ed25519-SK |
| `sk_login_both_types_otp_is_server` | Tests both SK key types in sequence |
| `sk_login_fido_callback_enforced` | Verifies `sk_fido_verify_fun` callback is invoked with correct FIDO info |
| `sk_login_fido_callback_rejects` | Verifies a rejecting callback causes auth failure |
| `sk_login_wrong_key_rejected` | Verifies an unauthorized SK key is rejected |
| `sk_login_password_fallback_from_sk` | Verifies fallback to password auth when SK key is not authorized |
| `sk_exec_after_sk_auth` | Verifies exec channel works after SK authentication |
| `sk_sftp_after_sk_auth` | Verifies SFTP subsystem works after SK authentication |
| `sk_counter_increases` | Verifies the FIDO counter (0x12345678 from sk-dummy.so) is propagated |
| `sk_flags_propagated` | Verifies FIDO flags (UP, UV) are correctly propagated to the callback |

## How sk-dummy.so Works

OpenSSH's `sk-dummy.so` implements the FIDO security key middleware API
(`sk-api.h`) entirely in software:

- **`sk_enroll()`**: Generates a real ECDSA-P256 or Ed25519 key pair using
  OpenSSL. The private key is stored in the `key_handle` (returned to
  OpenSSH), unlike real hardware where the key never leaves the device.

- **`sk_sign()`**: Reconstructs the private key from the `key_handle` and
  signs the FIDO authenticator data blob:
  `SHA256(application) || flags || counter || SHA256(message)`

- **Counter**: Hardcoded to `0x12345678` (does not increment).

- **Flags**: Sets the UP (User Presence) bit (`0x01`). Does not set UV
  (User Verification, `0x04`).

This is sufficient for testing the complete SSH FIDO authentication flow
because the cryptographic signatures produced are genuine — only the
key storage mechanism differs from real hardware.

## Architecture

```
┌──────────────────────────────────────────────┐
│              Docker Container                 │
│                                               │
│  ┌─────────────┐    ┌──────────────────────┐ │
│  │  sk-dummy.so │◄───│ OpenSSH ssh-keygen   │ │
│  │  (software   │    │ (generates SK keys)  │ │
│  │   FIDO token)│    └──────────────────────┘ │
│  │              │                              │
│  │              │◄───┌──────────────────────┐ │
│  └─────────────┘    │ OpenSSH ssh client    │ │
│                      │ (signs auth request) │──┼──┐
│                      └──────────────────────┘ │  │
└──────────────────────────────────────────────┘  │
                                                   │ SSH protocol
                                                   │ (publickey auth
                                                   │  with SK signature)
┌──────────────────────────────────────────────┐  │
│              Erlang VM                        │  │
│                                               │  │
│  ┌──────────────────────────────────────────┐│  │
│  │         Erlang SSH Daemon                 ││◄─┘
│  │                                           ││
│  │  ssh_auth:verify_sig/7                    ││
│  │    → ssh_transport:do_verify/5            ││
│  │      → fido_authenticator_data/4          ││
│  │      → public_key:verify/5                ││
│  │    → sk_fido_verify_fun callback          ││
│  └──────────────────────────────────────────┘│
└──────────────────────────────────────────────┘
```

## Troubleshooting

### "Docker image not found"

Build the image first:
```sh
./create-sk-image
```

### "Docker daemon not running"

Start the Docker daemon:
```sh
sudo systemctl start docker
# or
sudo dockerd &
```

### "sk-dummy.so not found" in the image

The OpenSSH version may be too old. sk-dummy.so requires OpenSSH >= 8.2.
Use a newer version:
```sh
./create-sk-image 9.9p1
```

### Tests skip with "No docker"

Ensure Docker is installed and the current user has permission to run
Docker commands (is in the `docker` group or using rootless Docker).

### Connection refused during tests

The Erlang SSH daemon binds to `0.0.0.0` by default. If the Docker
container cannot reach the host, check Docker networking configuration.
On Linux, the default bridge network usually works. On macOS/Windows
with Docker Desktop, you may need `host.docker.internal`.

## References

- [OpenSSH PROTOCOL.u2f](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f) — Wire format specification
- [OpenSSH sk-api.h](https://github.com/openssh/openssh-portable/blob/master/sk-api.h) — Security key middleware API
- [OpenSSH sk-dummy.c](https://github.com/openssh/openssh-portable/tree/master/regress/misc/sk-dummy) — Dummy middleware source
- [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252) — SSH Authentication Protocol
- [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656) — ECDSA in SSH
- [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709) — Ed25519 in SSH