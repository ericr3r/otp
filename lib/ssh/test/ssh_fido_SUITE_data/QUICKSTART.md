# Task 2.3 Quick Start Guide

## What is Task 2.3?

Task 2.3 adds testing for parsing real FIDO/U2F security key public files, similar to how `ssh_pubkey_SUITE` tests traditional SSH keys.

## Quick Test Run

```bash
# Run all FIDO tests
cd $OTP_ROOT/lib/ssh/test
ct_run -suite ssh_fido_SUITE

# Run only Task 2.3 tests
ct_run -suite ssh_fido_SUITE -group fido_real_key_files

# Run a single test case
ct_run -suite ssh_fido_SUITE -case parse_real_ecdsa_sk_pubkey_file
```

## What Was Added

### Test Files (4 files)
- `id_ecdsa_sk.pub` - Basic FIDO ECDSA key
- `id_ed25519_sk.pub` - Basic FIDO Ed25519 key
- `id_ecdsa_sk_full.pub` - ECDSA with all FIDO metadata
- `id_ed25519_sk_full.pub` - Ed25519 with all FIDO metadata

### Test Cases (4 cases in new group)
```erlang
{fido_real_key_files, [], [
    parse_real_ecdsa_sk_pubkey_file,        % Test 1: Basic ECDSA-SK
    parse_real_ed25519_sk_pubkey_file,      % Test 2: Basic Ed25519-SK
    parse_real_ecdsa_sk_full_pubkey_file,   % Test 3: Full ECDSA-SK
    parse_real_ed25519_sk_full_pubkey_file  % Test 4: Full Ed25519-SK
]}
```

## File Locations

```
otp/lib/ssh/test/
├── ssh_fido_SUITE.erl                    [MODIFIED]
│   └── Added 4 new test cases (~100 lines)
│
└── ssh_fido_SUITE_data/                  [NEW DIRECTORY]
    ├── id_ecdsa_sk.pub                   [NEW]
    ├── id_ed25519_sk.pub                 [NEW]
    ├── id_ecdsa_sk_full.pub              [NEW]
    ├── id_ed25519_sk_full.pub            [NEW]
    ├── README.md                         [NEW]
    ├── TASK_2.3_SUMMARY.md               [NEW]
    ├── COMPARISON_WITH_SSH_PUBKEY_SUITE.md [NEW]
    └── QUICKSTART.md                     [NEW - this file]
```

## What Each Test Does

### Test 1: parse_real_ecdsa_sk_pubkey_file
- Reads `id_ecdsa_sk.pub`
- Parses FIDO ECDSA key (sk-ecdsa-sha2-nistp256@openssh.com)
- Verifies curve is secp256r1
- Checks structure matches expected format

### Test 2: parse_real_ed25519_sk_pubkey_file
- Reads `id_ed25519_sk.pub`
- Parses FIDO Ed25519 key (sk-ssh-ed25519@openssh.com)
- Verifies 32-byte public key
- Checks structure matches expected format

### Test 3: parse_real_ecdsa_sk_full_pubkey_file
- Reads `id_ecdsa_sk_full.pub`
- Parses ECDSA-SK with flags and key_handle fields
- Tests OpenSSH 8.3+ format with full metadata

### Test 4: parse_real_ed25519_sk_full_pubkey_file
- Reads `id_ed25519_sk_full.pub`
- Parses Ed25519-SK with flags and key_handle fields
- Tests OpenSSH 8.3+ format with full metadata

## Test Pattern

All tests follow this simple pattern:

```erlang
test_case(Config) ->
    %% 1. Get data directory
    DataDir = proplists:get_value(data_dir, Config),
    KeyFile = filename:join(DataDir, "key_file.pub"),
    
    %% 2. Read file
    {ok, RawData} = file:read_file(KeyFile),
    
    %% 3. Decode
    [{PubKey, Attributes}] = ssh_file:decode(RawData, openssh_key),
    
    %% 4. Verify structure
    {#'ECPoint'{}, {namedCurve, _OID}} = PubKey,
    
    %% 5. Log and return
    ct:log("Success!"),
    ok.
```

## Expected Output

When tests pass, you'll see:

```
Testing ssh_fido_SUITE.parse_real_ecdsa_sk_pubkey_file... ok
Testing ssh_fido_SUITE.parse_real_ed25519_sk_pubkey_file... ok
Testing ssh_fido_SUITE.parse_real_ecdsa_sk_full_pubkey_file... ok
Testing ssh_fido_SUITE.parse_real_ed25519_sk_full_pubkey_file... ok

All tests passed.
```

## Key File Format

All public key files follow OpenSSH format:
```
<key-type> <base64-data> [comment]
```

Example:
```
sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr...c3NoOg== user@host
```

The base64 data encodes:
- Key type string
- Curve name (ECDSA) or key length (Ed25519)
- Public key material
- Application string ("ssh:")
- Optional: flags (uint32)
- Optional: key_handle (string)

## Verification Checklist

✓ Files created in `ssh_fido_SUITE_data/`
✓ Test cases added to `ssh_fido_SUITE.erl`
✓ New group `fido_real_key_files` in `all()` and `groups()`
✓ No compilation errors
✓ Tests use `ssh_file:decode/2` API
✓ Pattern matches `ssh_pubkey_SUITE` style

## Relationship to Other Tests

```
ssh_fido_SUITE groups:
├── fido_key_parsing       [Existing: Group 1]
│   └── Synthetic wire format tests
├── fido_key_encoding      [Existing: Group 2]
│   └── Round-trip encoding tests
├── fido_field_parsing     [Existing: Group 3]
│   └── Metadata extraction tests
└── fido_real_key_files    [NEW: Group 4 - Task 2.3]
    └── Real OpenSSH key file tests
```

## Documentation

- **README.md** - Detailed format documentation
- **TASK_2.3_SUMMARY.md** - Complete implementation overview
- **COMPARISON_WITH_SSH_PUBKEY_SUITE.md** - Pattern analysis
- **QUICKSTART.md** - This file

## Troubleshooting

### "File not found"
- Check you're in the OTP root directory
- Verify test data files exist in `ssh_fido_SUITE_data/`

### "Decode failed"
- Verify key files have correct OpenSSH format
- Check base64 encoding is valid
- Ensure key type strings are correct

### "Pattern match failed"
- Key structure might not match expected format
- Check OID constants are imported from public_key.hrl

## Next Steps

To extend this work:
1. Add more key variations (different applications, flags)
2. Add negative tests (malformed keys)
3. Test authorized_keys-style multi-key files
4. Add integration tests with actual FIDO authentication

## Questions?

See the detailed documentation:
- `README.md` - Format specifications
- `TASK_2.3_SUMMARY.md` - Implementation details
- `COMPARISON_WITH_SSH_PUBKEY_SUITE.md` - Design patterns