-module(test_fido_regression).
-export([run/0]).

run() ->
    application:start(crypto),
    application:start(public_key),

    io:format("~n========================================~n"),
    io:format("Testing SSH Key Parsing (Regression Test)~n"),
    io:format("========================================~n~n"),

    %% Test 1: Regular ECDSA key (non-FIDO)
    test_regular_ecdsa(),

    %% Test 2: Regular Ed25519 key (non-FIDO)
    test_regular_ed25519(),

    %% Test 3: FIDO ECDSA-SK key
    test_fido_ecdsa(),

    %% Test 4: FIDO Ed25519-SK key
    test_fido_ed25519(),

    %% Test 5: OID mappings
    test_oid_mappings(),

    io:format("~n========================================~n"),
    io:format("✅ All regression tests passed!~n"),
    io:format("========================================~n"),
    ok.

test_regular_ecdsa() ->
    KeyType = <<"ecdsa-sha2-nistp256">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,

    KeyBlob = <<
        (byte_size(KeyType)):32, KeyType/binary,
        (byte_size(Curve)):32, Curve/binary,
        (byte_size(ECPoint)):32, ECPoint/binary
    >>,

    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify it's a tuple with EC point
    true = is_tuple(Key),

    io:format("✅ Regular ECDSA key parsing works~n"),
    ok.

test_regular_ed25519() ->
    KeyType = <<"ssh-ed25519">>,
    PubKey = <<1:256>>,

    KeyBlob = <<
        (byte_size(KeyType)):32, KeyType/binary,
        (byte_size(PubKey)):32, PubKey/binary
    >>,

    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify it's a tuple
    true = is_tuple(Key),

    io:format("✅ Regular Ed25519 key parsing works~n"),
    ok.

test_fido_ecdsa() ->
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<
        (byte_size(KeyType)):32, KeyType/binary,
        (byte_size(Curve)):32, Curve/binary,
        (byte_size(ECPoint)):32, ECPoint/binary,
        (byte_size(Application)):32, Application/binary
    >>,

    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify it's a tuple (doesn't crash)
    true = is_tuple(Key),

    io:format("✅ FIDO ECDSA-SK key parsing works~n"),
    ok.

test_fido_ed25519() ->
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<
        (byte_size(KeyType)):32, KeyType/binary,
        (byte_size(PubKey)):32, PubKey/binary,
        (byte_size(Application)):32, Application/binary
    >>,

    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify it's a tuple (doesn't crash)
    true = is_tuple(Key),

    io:format("✅ FIDO Ed25519-SK key parsing works~n"),
    ok.

test_oid_mappings() ->
    %% Test FIDO key type to OID mappings
    OID1 = ssh_message:ssh_curvename2oid(<<"sk-ecdsa-sha2-nistp256@openssh.com">>),
    OID2 = ssh_message:ssh_curvename2oid(<<"ecdsa-sha2-nistp256">>),

    %% FIDO ECDSA should map to same OID as regular ECDSA
    true = (OID1 =:= OID2),

    OID3 = ssh_message:ssh_curvename2oid(<<"sk-ssh-ed25519@openssh.com">>),
    OID4 = ssh_message:ssh_curvename2oid(<<"ssh-ed25519">>),

    %% FIDO Ed25519 should map to same OID as regular Ed25519
    true = (OID3 =:= OID4),

    io:format("✅ OID mappings correct (FIDO keys map to standard OIDs)~n"),
    ok.
