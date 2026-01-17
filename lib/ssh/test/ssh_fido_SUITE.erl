%%
%% %CopyrightBegin%
%%
%% SPDX-License-Identifier: Apache-2.0
%%
%% Copyright Ericsson AB 2025. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

%%
-module(ssh_fido_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("ssh.hrl").

%% Common Test exports
-export([
         suite/0,
         all/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_group/2,
         end_per_group/2
        ]).

%% Test cases
-export([
         decode_ecdsa_sk_pubkey/1,
         decode_ed25519_sk_pubkey/1,
         round_trip_ecdsa_sk/1,
         round_trip_ed25519_sk/1,
         ecdsa_sk_key_type_mapping/1,
         ed25519_sk_key_type_mapping/1,
         parse_ecdsa_sk_with_application/1,
         parse_ed25519_sk_with_application/1,
         parse_ecdsa_sk_with_all_fields/1,
         parse_ed25519_sk_with_all_fields/1,
         round_trip_fido_full_ecdsa/1,
         round_trip_fido_full_ed25519/1
        ]).

%%--------------------------------------------------------------------
%% Common Test interface functions
%%--------------------------------------------------------------------

suite() ->
    [{ct_hooks, [ts_install_cth]},
     {timetrap, {seconds, 40}}].

all() ->
    [
     {group, fido_key_parsing},
     {group, fido_key_encoding},
     {group, fido_field_parsing}
    ].

groups() ->
    [
     {fido_key_parsing, [], [
                             decode_ecdsa_sk_pubkey,
                             decode_ed25519_sk_pubkey,
                             ecdsa_sk_key_type_mapping,
                             ed25519_sk_key_type_mapping
                            ]},
     {fido_key_encoding, [], [
                              round_trip_ecdsa_sk,
                              round_trip_ed25519_sk
                             ]},
     {fido_field_parsing, [], [
                               parse_ecdsa_sk_with_application,
                               parse_ed25519_sk_with_application,
                               parse_ecdsa_sk_with_all_fields,
                               parse_ed25519_sk_with_all_fields,
                               round_trip_fido_full_ecdsa,
                               round_trip_fido_full_ed25519
                              ]}
    ].

init_per_suite(Config) ->
    case application:start(crypto) of
        ok -> ok;
        {error, {already_started, crypto}} -> ok
    end,
    case application:start(ssh) of
        ok -> ok;
        {error, {already_started, ssh}} -> ok
    end,
    Config.

end_per_suite(_Config) ->
    application:stop(ssh),
    application:stop(crypto),
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
%% Test Cases
%%--------------------------------------------------------------------

%% Test parsing of sk-ecdsa-sha2-nistp256@openssh.com public key
decode_ecdsa_sk_pubkey(_Config) ->
    %% Construct a FIDO ECDSA-SK public key in wire format
    %% Format: string key-type, string curve, string ec-point, string application
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    %% Sample EC point (uncompressed format: 0x04 || X || Y)
    ECPoint = <<4:8,
                1:256, % X coordinate (32 bytes)
                2:256  % Y coordinate (32 bytes)
              >>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(Curve),
                ?STRING(ECPoint),
                ?STRING(Application)>>,

    %% Decode the key
    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify the key structure
    {#'ECPoint'{point = ECPoint}, {namedCurve, OID}} = Key,

    %% Verify OID is secp256r1
    ?'secp256r1' = OID,

    ok.

%% Test parsing of sk-ssh-ed25519@openssh.com public key
decode_ed25519_sk_pubkey(_Config) ->
    %% Construct a FIDO Ed25519-SK public key in wire format
    %% Format: string key-type, string public-key, string application
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    %% Sample Ed25519 public key (32 bytes)
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(PubKey),
                ?STRING(Application)>>,

    %% Decode the key
    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Verify the key structure
    {#'ECPoint'{point = PubKey}, {namedCurve, OID}} = Key,

    %% Verify OID is id-Ed25519
    ?'id-Ed25519' = OID,

    ok.

%% Test that ECDSA-SK key types map to correct OID
ecdsa_sk_key_type_mapping(_Config) ->
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    OID = ssh_message:ssh_curvename2oid(KeyType),

    %% Should map to secp256r1
    ?'secp256r1' = OID,

    ok.

%% Test that Ed25519-SK key types map to correct OID
ed25519_sk_key_type_mapping(_Config) ->
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    OID = ssh_message:ssh_curvename2oid(KeyType),

    %% Should map to id-Ed25519
    ?'id-Ed25519' = OID,

    ok.

%% Test round-trip encode/decode for ECDSA-SK keys
round_trip_ecdsa_sk(_Config) ->
    %% For now, FIDO keys decode to the same structure as non-FIDO keys
    %% This test verifies that once decoded, they can be encoded back
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(Curve),
                ?STRING(ECPoint),
                ?STRING(Application)>>,

    %% Decode
    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Encode back (note: will encode as regular ECDSA, not FIDO)
    EncodedBlob = ssh_message:ssh2_pubkey_encode(Key),

    %% Verify it's valid (though it will be in non-FIDO format)
    _Key2 = ssh_message:ssh2_pubkey_decode(EncodedBlob),

    ok.

%% Test round-trip encode/decode for Ed25519-SK keys
round_trip_ed25519_sk(_Config) ->
    %% For now, FIDO keys decode to the same structure as non-FIDO keys
    %% This test verifies that once decoded, they can be encoded back
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(PubKey),
                ?STRING(Application)>>,

    %% Decode
    Key = ssh_message:ssh2_pubkey_decode(KeyBlob),

    %% Encode back (note: will encode as regular Ed25519, not FIDO)
    EncodedBlob = ssh_message:ssh2_pubkey_encode(Key),

    %% Verify it's valid (though it will be in non-FIDO format)
    _Key2 = ssh_message:ssh2_pubkey_decode(EncodedBlob),

    ok.

%% Test parsing ECDSA-SK key with application field preserved
parse_ecdsa_sk_with_application(_Config) ->
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(Curve),
                ?STRING(ECPoint),
                ?STRING(Application)>>,

    %% Use decode_full to get FIDO metadata
    {{Key, SkData}, _Rest} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

    %% Verify key structure
    {#'ECPoint'{point = ECPoint}, {namedCurve, ?'secp256r1'}} = Key,

    %% Verify FIDO fields
    Application = proplists:get_value(application, SkData),
    undefined = proplists:get_value(flags, SkData),
    undefined = proplists:get_value(key_handle, SkData),

    ok.

%% Test parsing Ed25519-SK key with application field preserved
parse_ed25519_sk_with_application(_Config) ->
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(PubKey),
                ?STRING(Application)>>,

    %% Use decode_full to get FIDO metadata
    {{Key, SkData}, _Rest} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

    %% Verify key structure
    {#'ECPoint'{point = PubKey}, {namedCurve, ?'id-Ed25519'}} = Key,

    %% Verify FIDO fields
    Application = proplists:get_value(application, SkData),
    undefined = proplists:get_value(flags, SkData),
    undefined = proplists:get_value(key_handle, SkData),

    ok.

%% Test parsing ECDSA-SK key with all optional fields (OpenSSH 8.3+)
parse_ecdsa_sk_with_all_fields(_Config) ->
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,
    Application = <<"ssh:">>,
    Flags = 1,  %% User presence verified
    KeyHandle = <<"test_key_handle_blob">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(Curve),
                ?STRING(ECPoint),
                ?STRING(Application),
                ?UINT32(Flags),
                ?STRING(KeyHandle)>>,

    %% Use decode_full to get FIDO metadata
    {{Key, SkData}, _Rest} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

    %% Verify key structure
    {#'ECPoint'{point = ECPoint}, {namedCurve, ?'secp256r1'}} = Key,

    %% Verify all FIDO fields are preserved
    Application = proplists:get_value(application, SkData),
    Flags = proplists:get_value(flags, SkData),
    KeyHandle = proplists:get_value(key_handle, SkData),

    ok.

%% Test parsing Ed25519-SK key with all optional fields (OpenSSH 8.3+)
parse_ed25519_sk_with_all_fields(_Config) ->
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,
    Flags = 5,  %% User presence + verification (PIN/biometric)
    KeyHandle = <<"another_key_handle">>,

    KeyBlob = <<?STRING(KeyType),
                ?STRING(PubKey),
                ?STRING(Application),
                ?UINT32(Flags),
                ?STRING(KeyHandle)>>,

    %% Use decode_full to get FIDO metadata
    {{Key, SkData}, _Rest} = ssh_message:ssh2_pubkey_decode_full(KeyBlob),

    %% Verify key structure
    {#'ECPoint'{point = PubKey}, {namedCurve, ?'id-Ed25519'}} = Key,

    %% Verify all FIDO fields are preserved
    Application = proplists:get_value(application, SkData),
    Flags = proplists:get_value(flags, SkData),
    KeyHandle = proplists:get_value(key_handle, SkData),

    ok.

%% Test full round-trip for ECDSA-SK with all fields
round_trip_fido_full_ecdsa(_Config) ->
    KeyType = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    Curve = <<"nistp256">>,
    ECPoint = <<4:8, 1:256, 2:256>>,
    Application = <<"ssh:">>,
    Flags = 1,
    KeyHandle = <<"test_handle">>,

    OriginalBlob = <<?STRING(KeyType),
                     ?STRING(Curve),
                     ?STRING(ECPoint),
                     ?STRING(Application),
                     ?UINT32(Flags),
                     ?STRING(KeyHandle)>>,

    %% Decode with full metadata
    {{Key, SkData}, <<>>} = ssh_message:ssh2_pubkey_decode_full(OriginalBlob),

    %% Encode back (should preserve FIDO format)
    EncodedBlob = ssh_message:ssh2_pubkey_encode({Key, SkData}),

    %% Decode again and verify all fields match
    {{Key2, SkData2}, <<>>} = ssh_message:ssh2_pubkey_decode_full(EncodedBlob),

    %% Verify key is the same
    Key = Key2,

    %% Verify all FIDO fields are preserved
    Application = proplists:get_value(application, SkData2),
    Flags = proplists:get_value(flags, SkData2),
    KeyHandle = proplists:get_value(key_handle, SkData2),

    ok.

%% Test full round-trip for Ed25519-SK with all fields
round_trip_fido_full_ed25519(_Config) ->
    KeyType = <<"sk-ssh-ed25519@openssh.com">>,
    PubKey = <<1:256>>,
    Application = <<"ssh:">>,
    Flags = 5,
    KeyHandle = <<"ed25519_handle">>,

    OriginalBlob = <<?STRING(KeyType),
                     ?STRING(PubKey),
                     ?STRING(Application),
                     ?UINT32(Flags),
                     ?STRING(KeyHandle)>>,

    %% Decode with full metadata
    {{Key, SkData}, <<>>} = ssh_message:ssh2_pubkey_decode_full(OriginalBlob),

    %% Encode back (should preserve FIDO format)
    EncodedBlob = ssh_message:ssh2_pubkey_encode({Key, SkData}),

    %% Decode again and verify all fields match
    {{Key2, SkData2}, <<>>} = ssh_message:ssh2_pubkey_decode_full(EncodedBlob),

    %% Verify key is the same
    Key = Key2,

    %% Verify all FIDO fields are preserved
    Application = proplists:get_value(application, SkData2),
    Flags = proplists:get_value(flags, SkData2),
    KeyHandle = proplists:get_value(key_handle, SkData2),

    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
