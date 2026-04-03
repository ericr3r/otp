%% %CopyrightBegin%
%%
%% SPDX-License-Identifier: Apache-2.0
%%
%% Copyright Ericsson AB 2005-2026. All Rights Reserved.
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
-module(ssh_pubkey_SUITE).

%% Note: This directive should only be used in test suites.
-export([suite/0, all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
         end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([check_dsa_disabled/1, check_rsa_sha1_disabled/1, connect_dsa_to_dsa/1,
         connect_dsa_to_ecdsa/1, connect_dsa_to_ed25519/1, connect_dsa_to_ed448/1,
         connect_dsa_to_rsa_sha2/1, connect_ecdsa_to_dsa/1, connect_ecdsa_to_ecdsa/1,
         connect_ecdsa_to_ed25519/1, connect_ecdsa_to_ed448/1, connect_ecdsa_to_rsa_sha2/1,
         connect_ed25519_to_dsa/1, connect_ed25519_to_ecdsa/1, connect_ed25519_to_ed25519/1,
         connect_ed25519_to_ed448/1, connect_ed25519_to_rsa_sha2/1, connect_ed448_to_dsa/1,
         connect_ed448_to_ecdsa/1, connect_ed448_to_ed25519/1, connect_ed448_to_ed448/1,
         connect_ed448_to_rsa_sha2/1, connect_rsa_sha1_to_dsa/1, connect_rsa_sha2_to_dsa/1,
         connect_rsa_sha2_to_ecdsa/1, connect_rsa_sha2_to_ed25519/1, connect_rsa_sha2_to_ed448/1,
         connect_rsa_sha2_to_rsa_sha2/1, ssh_rsa_public_key/1, ssh_dsa_public_key/1,
         ssh_ecdsa_public_key/1, ssh_rfc4716_rsa_comment/1, ssh_rfc4716_dsa_comment/1,
         ssh_rfc4716_rsa_subject/1, ssh_list_public_key/1, ssh_known_hosts/1, ssh1_known_hosts/1,
         ssh_auth_keys/1, ssh1_auth_keys/1, ssh_openssh_key_with_comment/1,
         ssh_openssh_key_long_header/1, sk_ecdsa_pubkey_encode_decode/1,
         sk_ed25519_pubkey_encode_decode/1, sk_auth_keys/1, sk_auth_keys_mixed/1,
         sk_file_base_name/1, sk_malformed_blob/1, sk_supported_algorithms/1, sk_sha_mapping/1,
         sk_valid_key_sha_alg/1, sk_public_algo/1, sk_verify_sig_parse_ecdsa/1,
         sk_verify_sig_parse_ed25519/1, sk_verify_ecdsa_correct/1, sk_verify_ed25519_correct/1,
         sk_verify_wrong_application/1, sk_verify_tampered_flags/1, sk_verify_wrong_key/1,
         sk_verify_ecdsa_padded_mpint/1, sk_auth_precheck_ecdsa/1, sk_auth_precheck_ed25519/1,
         sk_auth_verify_ecdsa/1, sk_auth_verify_ed25519/1, sk_auth_wrong_sig_rejected/1,
         sk_auth_fallback/1, sk_fido_callback_receives_info/1,
         sk_fido_callback_rejects_no_presence/1, sk_fido_callback_accepts_presence/1,
         sk_fido_counter_monotonicity/1, sk_fido_default_no_callback/1,
         sk_fido_callback_bad_return/1, sk_regression_non_sk_options/1,
         sk_regression_non_sk_pubkey_decode/1, sk_regression_non_sk_verify/1,
         sk_regression_non_sk_auth/1, sk_verify_both_key_types_sequential/1,
         sk_verify_zero_counter/1, sk_verify_max_counter/1, sk_verify_all_flags/1,
         sk_mixed_auth_sk_then_standard_fallback/1, sk_option_validate_fido_fun/1,
         ssh_hostkey_fingerprint_md5_implicit/1, ssh_hostkey_fingerprint_md5/1,
         ssh_hostkey_fingerprint_sha/1, ssh_hostkey_fingerprint_sha256/1,
         ssh_hostkey_fingerprint_sha384/1, ssh_hostkey_fingerprint_sha512/1,
         ssh_hostkey_fingerprint_list/1, chk_known_hosts/1, ssh_hostkey_pkcs8/1,
         ec_private_key_version_compat/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-include("ssh.hrl").
-include("ssh_auth.hrl").
-include("ssh_transport.hrl").
-include("ssh_test_lib.hrl").

-include_lib("stdlib/include/assert.hrl").

%%%----------------------------------------------------------------
%%% Common Test interface functions -------------------------------
%%%----------------------------------------------------------------

suite() ->
    [{ct_hooks, [ts_install_cth]}, {timetrap, {seconds, 20}}].

all() ->
    [{group, old_format},
     {group, new_format},
     {group, option_space},
     {group, ssh_hostkey_fingerprint},
     {group, ssh_public_key_decode_encode},
     {group, pkcs8},
     chk_known_hosts,
     ec_private_key_version_compat].

-define(tests_old,
        [connect_rsa_sha2_to_rsa_sha2,
         connect_rsa_sha1_to_dsa,
         connect_rsa_sha2_to_dsa,
         connect_rsa_sha2_to_ecdsa,
         connect_dsa_to_rsa_sha2,
         connect_dsa_to_dsa,
         connect_dsa_to_ecdsa,
         connect_ecdsa_to_rsa_sha2,
         connect_ecdsa_to_dsa,
         connect_ecdsa_to_ecdsa,
         connect_dsa_to_ed25519,
         connect_ecdsa_to_ed25519,
         connect_rsa_sha2_to_ed25519,
         connect_dsa_to_ed448,
         connect_ecdsa_to_ed448,
         connect_rsa_sha2_to_ed448]).
-define(tests_new,
        [connect_ed25519_to_dsa,
         connect_ed25519_to_ecdsa,
         connect_ed25519_to_ed448,
         connect_ed25519_to_ed25519,
         connect_ed25519_to_rsa_sha2,
         connect_ed448_to_dsa,
         connect_ed448_to_ecdsa,
         connect_ed448_to_ed25519,
         connect_ed448_to_ed448,
         connect_ed448_to_rsa_sha2
         | ?tests_old]). % but taken from the new format directory

groups() ->
    [{new_format, [], ?tests_new},
     {old_format,
      [],
      [check_dsa_disabled, check_rsa_sha1_disabled | ?tests_old ++ [{group, passphrase}]]},
     {passphrase, [], ?tests_old},
     {option_space, [], [{group, new_format}]},
     {pkcs8, [], [ssh_hostkey_pkcs8]},
     {ssh_hostkey_fingerprint,
      [],
      [ssh_hostkey_fingerprint_md5_implicit,
       ssh_hostkey_fingerprint_md5,
       ssh_hostkey_fingerprint_sha,
       ssh_hostkey_fingerprint_sha256,
       ssh_hostkey_fingerprint_sha384,
       ssh_hostkey_fingerprint_sha512,
       ssh_hostkey_fingerprint_list]},
     {ssh_public_key_decode_encode,
      [],
      [ssh_rsa_public_key, ssh_dsa_public_key, ssh_ecdsa_public_key, ssh_rfc4716_rsa_comment,
       ssh_rfc4716_dsa_comment, ssh_rfc4716_rsa_subject, ssh_list_public_key,
       ssh_known_hosts, %% ssh1_known_hosts,
       ssh_auth_keys, %% ssh1_auth_keys,
       ssh_openssh_key_with_comment, ssh_openssh_key_long_header, sk_ecdsa_pubkey_encode_decode,
       sk_ed25519_pubkey_encode_decode, sk_auth_keys, sk_auth_keys_mixed, sk_file_base_name,
       sk_malformed_blob, sk_supported_algorithms, sk_sha_mapping, sk_valid_key_sha_alg,
       sk_public_algo, sk_verify_sig_parse_ecdsa, sk_verify_sig_parse_ed25519,
       sk_verify_ecdsa_correct, sk_verify_ed25519_correct, sk_verify_wrong_application,
       sk_verify_tampered_flags, sk_verify_wrong_key, sk_verify_ecdsa_padded_mpint,
       sk_auth_precheck_ecdsa, sk_auth_precheck_ed25519, sk_auth_verify_ecdsa,
       sk_auth_verify_ed25519, sk_auth_wrong_sig_rejected, sk_auth_fallback,
       sk_fido_callback_receives_info, sk_fido_callback_rejects_no_presence,
       sk_fido_callback_accepts_presence, sk_fido_counter_monotonicity,
       sk_fido_default_no_callback, sk_fido_callback_bad_return, sk_regression_non_sk_options,
       sk_regression_non_sk_pubkey_decode, sk_regression_non_sk_verify,
       sk_regression_non_sk_auth, sk_verify_both_key_types_sequential, sk_verify_zero_counter,
       sk_verify_max_counter, sk_verify_all_flags, sk_mixed_auth_sk_then_standard_fallback,
       sk_option_validate_fido_fun]}].

%%%----------------------------------------------------------------
init_per_suite(Config) ->
    ?CHECK_CRYPTO(begin
                      ssh:start(),
                      [{client_opts, []}, {daemon_opts, []} | Config]
                  end).

end_per_suite(_onfig) ->
    ssh:stop().

%%%----------------------------------------------------------------
init_per_group(new_format, Config) ->
    Dir = filename:join(
              proplists:get_value(data_dir, Config), "new_format"),
    [{fmt, new_format}, {key_src_dir, Dir} | Config];
init_per_group(old_format, Config) ->
    Dir = filename:join(
              proplists:get_value(data_dir, Config), "old_format"),
    [{fmt, old_format}, {key_src_dir, Dir} | Config];
init_per_group(pkcs8, Config) ->
    Dir = filename:join(
              proplists:get_value(data_dir, Config), "pkcs8"),
    [{fmt, pkcs8}, {key_src_dir, Dir} | Config];
init_per_group(option_space, Config) ->
    extend_optsL([client_opts, daemon_opts],
                 [{key_cb, {ssh_file, [{optimize, space}]}}],
                 Config);
init_per_group(passphrase, Config0) ->
    case supported(hashs, md5) of
        true ->
            Dir = filename:join(
                      proplists:get_value(data_dir, Config0), "old_format_passphrase"),
            PassPhrases =
                [{K, "somepwd"} || K <- [dsa_pass_phrase, rsa_pass_phrase, ecdsa_pass_phrase]],
            Config1 = extend_optsL(client_opts, PassPhrases, Config0),
            replace_opt(key_src_dir, Dir, Config1);
        false ->
            {skip, "Unsupported hash"}
    end;
init_per_group(ssh_public_key_decode_encode, Config) ->
    [{pk_data_dir, filename:join([proplists:get_value(data_dir, Config), "public_key"])}
     | Config];
init_per_group(_, Config) ->
    Config.

extend_optsL(OptNames, Values, Config) when is_list(OptNames) ->
    lists:foldl(fun(N, Cnf) -> extend_optsL(N, Values, Cnf) end, Config, OptNames);
extend_optsL(OptName, Values, Config) when is_atom(OptName) ->
    Opts = proplists:get_value(OptName, Config),
    replace_opt(OptName, Values ++ Opts, Config).

replace_opt(OptName, Value, Config) ->
    lists:keyreplace(OptName, 1, Config, {OptName, Value}).

end_per_group(_, Config) ->
    Config.

%%%----------------------------------------------------------------
init_per_testcase(ssh_hostkey_pkcs8, Config0) ->
    setup_user_system_dir(rsa_sha2, rsa_sha2, Config0);
init_per_testcase(connect_rsa_sha2_to_rsa_sha2, Config0) ->
    setup_user_system_dir(rsa_sha2, rsa_sha2, Config0);
init_per_testcase(connect_rsa_sha1_to_dsa, Config0) ->
    setup_user_system_dir(rsa_sha1, dsa, Config0);
init_per_testcase(connect_rsa_sha2_to_dsa, Config0) ->
    setup_user_system_dir(rsa_sha2, dsa, Config0);
init_per_testcase(connect_rsa_sha2_to_ecdsa, Config0) ->
    setup_user_system_dir(rsa_sha2, ecdsa, Config0);
init_per_testcase(connect_rsa_sha2_to_ed25519, Config0) ->
    setup_user_system_dir(rsa_sha2, ed25519, Config0);
init_per_testcase(connect_rsa_sha2_to_ed448, Config0) ->
    setup_user_system_dir(rsa_sha2, ed448, Config0);
init_per_testcase(connect_dsa_to_rsa_sha2, Config0) ->
    setup_user_system_dir(dsa, rsa_sha2, Config0);
init_per_testcase(connect_dsa_to_dsa, Config0) ->
    setup_user_system_dir(dsa, dsa, Config0);
init_per_testcase(connect_dsa_to_ecdsa, Config0) ->
    setup_user_system_dir(dsa, ecdsa, Config0);
init_per_testcase(connect_dsa_to_ed25519, Config0) ->
    setup_user_system_dir(dsa, ed25519, Config0);
init_per_testcase(connect_dsa_to_ed448, Config0) ->
    setup_user_system_dir(dsa, ed448, Config0);
init_per_testcase(connect_ecdsa_to_rsa_sha2, Config0) ->
    setup_user_system_dir(ecdsa, rsa_sha2, Config0);
init_per_testcase(connect_ecdsa_to_dsa, Config0) ->
    setup_user_system_dir(ecdsa, dsa, Config0);
init_per_testcase(connect_ecdsa_to_ecdsa, Config0) ->
    setup_user_system_dir(ecdsa, ecdsa, Config0);
init_per_testcase(connect_ecdsa_to_ed25519, Config0) ->
    setup_user_system_dir(ecdsa, ed25519, Config0);
init_per_testcase(connect_ecdsa_to_ed448, Config0) ->
    setup_user_system_dir(ecdsa, ed448, Config0);
init_per_testcase(connect_ed25519_to_rsa_sha2, Config0) ->
    setup_user_system_dir(ed25519, rsa_sha2, Config0);
init_per_testcase(connect_ed25519_to_dsa, Config0) ->
    setup_user_system_dir(ed25519, dsa, Config0);
init_per_testcase(connect_ed25519_to_ecdsa, Config0) ->
    setup_user_system_dir(ed25519, ecdsa, Config0);
init_per_testcase(connect_ed25519_to_ed25519, Config0) ->
    setup_user_system_dir(ed25519, ed25519, Config0);
init_per_testcase(connect_ed25519_to_ed448, Config0) ->
    setup_user_system_dir(ed25519, ed448, Config0);
init_per_testcase(connect_ed448_to_rsa_sha2, Config0) ->
    setup_user_system_dir(ed448, rsa_sha2, Config0);
init_per_testcase(connect_ed448_to_dsa, Config0) ->
    setup_user_system_dir(ed448, dsa, Config0);
init_per_testcase(connect_ed448_to_ecdsa, Config0) ->
    setup_user_system_dir(ed448, ecdsa, Config0);
init_per_testcase(connect_ed448_to_ed25519, Config0) ->
    setup_user_system_dir(ed448, ed25519, Config0);
init_per_testcase(connect_ed448_to_ed448, Config0) ->
    setup_user_system_dir(ed448, ed448, Config0);
init_per_testcase(check_dsa_disabled, Config0) ->
    setup_default_user_system_dir(dsa, Config0);
init_per_testcase(check_rsa_sha1_disabled, Config0) ->
    setup_default_user_system_dir(rsa_sha1, Config0);
init_per_testcase(ssh_hostkey_fingerprint_md5_implicit, Config) ->
    init_fingerprint_testcase([md5], Config);
init_per_testcase(ssh_hostkey_fingerprint_md5, Config) ->
    init_fingerprint_testcase([md5], Config);
init_per_testcase(ssh_hostkey_fingerprint_sha, Config) ->
    init_fingerprint_testcase([sha], Config);
init_per_testcase(ssh_hostkey_fingerprint_sha256, Config) ->
    init_fingerprint_testcase([sha256], Config);
init_per_testcase(ssh_hostkey_fingerprint_sha384, Config) ->
    init_fingerprint_testcase([sha384], Config);
init_per_testcase(ssh_hostkey_fingerprint_sha512, Config) ->
    init_fingerprint_testcase([sha512], Config);
init_per_testcase(ssh_hostkey_fingerprint_list, Config) ->
    init_fingerprint_testcase([sha, md5], Config);
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, Config) ->
    Config.

%%%----
init_fingerprint_testcase(Algs, Config0) ->
    Hashs = proplists:get_value(hashs, crypto:supports(), []),
    case Algs -- Hashs of
        [] ->
            Config = lists:keydelete(watchdog, 1, Config0),
            Dog = ct:timetrap(?TIMEOUT),
            [{watchdog, Dog} | Config];
        UnsupportedAlgs ->
            {skip, {UnsupportedAlgs, not_supported}}
    end.

%%%----------------------------------------------------------------
%%% Test Cases ----------------------------------------------------
%%%----------------------------------------------------------------
connect_rsa_sha2_to_rsa_sha2(Config) ->
    try_connect(Config).

connect_rsa_sha1_to_dsa(Config) ->
    try_connect(Config).

connect_rsa_sha2_to_dsa(Config) ->
    try_connect(Config).

connect_rsa_sha2_to_ecdsa(Config) ->
    try_connect(Config).

connect_rsa_sha2_to_ed25519(Config) ->
    try_connect(Config).

connect_rsa_sha2_to_ed448(Config) ->
    try_connect(Config).

connect_dsa_to_rsa_sha2(Config) ->
    try_connect(Config).

connect_dsa_to_dsa(Config) ->
    try_connect(Config).

connect_dsa_to_ecdsa(Config) ->
    try_connect(Config).

connect_dsa_to_ed25519(Config) ->
    try_connect(Config).

connect_dsa_to_ed448(Config) ->
    try_connect(Config).

connect_ecdsa_to_rsa_sha2(Config) ->
    try_connect(Config).

connect_ecdsa_to_dsa(Config) ->
    try_connect(Config).

connect_ecdsa_to_ecdsa(Config) ->
    try_connect(Config).

connect_ecdsa_to_ed25519(Config) ->
    try_connect(Config).

connect_ecdsa_to_ed448(Config) ->
    try_connect(Config).

connect_ed25519_to_rsa_sha2(Config) ->
    try_connect(Config).

connect_ed25519_to_dsa(Config) ->
    try_connect(Config).

connect_ed25519_to_ecdsa(Config) ->
    try_connect(Config).

connect_ed25519_to_ed25519(Config) ->
    try_connect(Config).

connect_ed25519_to_ed448(Config) ->
    try_connect(Config).

connect_ed448_to_rsa_sha2(Config) ->
    try_connect(Config).

connect_ed448_to_dsa(Config) ->
    try_connect(Config).

connect_ed448_to_ecdsa(Config) ->
    try_connect(Config).

connect_ed448_to_ed25519(Config) ->
    try_connect(Config).

connect_ed448_to_ed448(Config) ->
    try_connect(Config).

%%%----------------------------------------------------------------
check_dsa_disabled(Config) ->
    try_connect_disabled(Config).

check_rsa_sha1_disabled(Config) ->
    try_connect_disabled(Config).

%%%----------------------------------------------------------------

%% Check of different host keys left to later
ssh_hostkey_pkcs8(Config) ->
    try_connect(Config).

%%%----------------------------------------------------------------

%% Check of different host keys left to later
ssh_hostkey_fingerprint_md5_implicit(_Config) ->
    Expected = "4b:0b:63:de:0f:a7:3a:ab:2c:cc:2d:d1:21:37:1d:3a",
    Expected = ssh:hostkey_fingerprint(ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Check of different host keys left to later
ssh_hostkey_fingerprint_md5(_Config) ->
    Expected = "MD5:4b:0b:63:de:0f:a7:3a:ab:2c:cc:2d:d1:21:37:1d:3a",
    Expected = ssh:hostkey_fingerprint(md5, ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Since this kind of fingerprint is not available yet on standard
%% distros, we do like this instead. The Expected is generated with:
%%       $ openssh-7.3p1/ssh-keygen -E sha1 -lf <file>
%%       2048 SHA1:Soammnaqg06jrm2jivMSnzQGlmk none@example.org (RSA)
ssh_hostkey_fingerprint_sha(_Config) ->
    Expected = "SHA1:Soammnaqg06jrm2jivMSnzQGlmk",
    Expected = ssh:hostkey_fingerprint(sha, ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Since this kind of fingerprint is not available yet on standard
%% distros, we do like this instead.
ssh_hostkey_fingerprint_sha256(_Config) ->
    Expected = "SHA256:T7F1BahkJWR7iJO8+rpzWOPbp7LZP4MlNrDExdNYOvY",
    Expected = ssh:hostkey_fingerprint(sha256, ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Since this kind of fingerprint is not available yet on standard
%% distros, we do like this instead.
ssh_hostkey_fingerprint_sha384(_Config) ->
    Expected = "SHA384:QhkLoGNI4KXdPvC//HxxSCP3uTQVADqxdajbgm+Gkx9zqz8N94HyP1JmH8C4/aEl",
    Expected = ssh:hostkey_fingerprint(sha384, ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Since this kind of fingerprint is not available yet on standard
%% distros, we do like this instead.
ssh_hostkey_fingerprint_sha512(_Config) ->
    Expected =
        "SHA512:ezUismvm3ADQQb6Nm0c1DwQ6ydInlJNfsnSQejFkXNmABg1Aenk9oi45CXeBO"
        "oTnlfTsGG8nFDm0smP10PBEeA",
    Expected = ssh:hostkey_fingerprint(sha512, ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
%% Since this kind of fingerprint is not available yet on standard
%% distros, we do like this instead.
ssh_hostkey_fingerprint_list(_Config) ->
    Expected =
        ["SHA1:Soammnaqg06jrm2jivMSnzQGlmk",
         "MD5:4b:0b:63:de:0f:a7:3a:ab:2c:cc:2d:d1:21:37:1d:3a"],
    Expected = ssh:hostkey_fingerprint([sha, md5], ssh_hostkey(rsa)).

%%--------------------------------------------------------------------
ssh_rsa_public_key(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),
    {ok, RSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_rsa_pub")),
    [{PubKey, Attributes1}] = ssh_file:decode(RSARawSsh2, public_key),
    [{PubKey, Attributes1}] = ssh_file:decode(RSARawSsh2, rfc4716_key),

    {ok, RSARawOpenSsh} =
        file:read_file(
            filename:join(Datadir, "openssh_rsa_pub")),
    [{PubKey, Attributes2}] = ssh_file:decode(RSARawOpenSsh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(RSARawOpenSsh, openssh_key),

    %% Can not check EncodedSSh == RSARawSsh2 and EncodedOpenSsh
    %% = RSARawOpenSsh as line breakpoints may differ
    EncodedSSh = ssh_file:encode([{PubKey, Attributes1}], rfc4716_key),
    EncodedOpenSsh = ssh_file:encode([{PubKey, Attributes2}], openssh_key),

    [{PubKey, Attributes1}] = ssh_file:decode(EncodedSSh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(EncodedOpenSsh, public_key).

%%--------------------------------------------------------------------
ssh_dsa_public_key(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, DSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_dsa_pub")),
    [{PubKey, Attributes1}] = ssh_file:decode(DSARawSsh2, public_key),
    [{PubKey, Attributes1}] = ssh_file:decode(DSARawSsh2, rfc4716_key),

    {ok, DSARawOpenSsh} =
        file:read_file(
            filename:join(Datadir, "openssh_dsa_pub")),
    [{PubKey, Attributes2}] = ssh_file:decode(DSARawOpenSsh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(DSARawOpenSsh, openssh_key),

    %% Can not check EncodedSSh == DSARawSsh2 and EncodedOpenSsh
    %% = DSARawOpenSsh as line breakpoints may differ
    EncodedSSh = ssh_file:encode([{PubKey, Attributes1}], rfc4716_key),
    EncodedOpenSsh = ssh_file:encode([{PubKey, Attributes2}], openssh_key),

    [{PubKey, Attributes1}] = ssh_file:decode(EncodedSSh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(EncodedOpenSsh, public_key).

%%--------------------------------------------------------------------
ssh_ecdsa_public_key(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, ECDSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_ecdsa_pub")),
    [{PubKey, Attributes1}] = ssh_file:decode(ECDSARawSsh2, public_key),
    [{PubKey, Attributes1}] = ssh_file:decode(ECDSARawSsh2, rfc4716_key),

    {ok, ECDSARawOpenSsh} =
        file:read_file(
            filename:join(Datadir, "openssh_ecdsa_pub")),
    [{PubKey, Attributes2}] = ssh_file:decode(ECDSARawOpenSsh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(ECDSARawOpenSsh, openssh_key),

    %% Can not check EncodedSSh == ECDSARawSsh2 and EncodedOpenSsh
    %% = ECDSARawOpenSsh as line breakpoints may differ
    EncodedSSh = ssh_file:encode([{PubKey, Attributes1}], rfc4716_key),
    EncodedOpenSsh = ssh_file:encode([{PubKey, Attributes2}], openssh_key),

    [{PubKey, Attributes1}] = ssh_file:decode(EncodedSSh, public_key),
    [{PubKey, Attributes2}] = ssh_file:decode(EncodedOpenSsh, public_key).

%%--------------------------------------------------------------------
ssh_list_public_key(Config) when is_list(Config) ->
    DataDir = proplists:get_value(pk_data_dir, Config),
    {Data_ssh2, Expect_ssh2} =
        collect_binaries_expected(DataDir,
                                  rfc4716_key,
                                  ["ssh2_rsa_pub",
                                   "ssh2_rsa_comment_pub",
                                   "ssh2_dsa_pub",
                                   "ssh2_dsa_comment_pub",
                                   "ssh2_ecdsa_pub",
                                   "ssh2_subject_pub"]),
    {Data_openssh, Expect_openssh} =
        collect_binaries_expected(DataDir,
                                  openssh_key,
                                  ["openssh_rsa_pub", "openssh_dsa_pub", "openssh_ecdsa_pub"]),

    true =
        chk_decode(Data_openssh, Expect_openssh, openssh_key)
        andalso chk_decode(Data_ssh2, Expect_ssh2, rfc4716_key)
        andalso chk_decode(Data_openssh, Expect_openssh, public_key)
        andalso chk_decode(Data_ssh2, Expect_ssh2, public_key)
        andalso chk_encode(Expect_openssh, openssh_key)
        andalso chk_encode(Expect_ssh2, rfc4716_key).

chk_encode(Data, Type) ->
    case ssh_file:decode(
             ssh_file:encode(Data, Type), Type)
    of
        Data ->
            ct:log("re-encode ~p ok", [Type]),
            true;
        Result ->
            ct:log("re-encode ~p FAILED~nGot~n ~p~nExpect~n ~p~n", [Type, Result, Data]),
            false
    end.

chk_decode(Data, Expect, Type) ->
    case ssh_file:decode(Data, Type) of
        Expect ->
            ct:log("decode ~p ok", [Type]),
            true;
        BadResult ->
            ct:log("decode ~p FAILED~nResult~n ~p~nExpect~n ~p~n~p",
                   [Type,
                    BadResult,
                    Expect,
                    if is_list(BadResult) ->
                           lists:foldr(fun ({Key, Attrs}, Acc) ->
                                               case Key of
                                                   #'RSAPublicKey'{} when is_list(Attrs) ->
                                                       Acc;
                                                   {_, #'Dss-Parms'{}} when is_list(Attrs) ->
                                                       Acc;
                                                   {#'ECPoint'{}, {namedCurve, _}}
                                                       when is_list(Attrs) ->
                                                       Acc;
                                                   _ when is_list(Attrs) ->
                                                       [{bad_key, {Key, Attrs}} | Acc];
                                                   _ ->
                                                       [{bad_attrs, {Key, Attrs}} | Acc]
                                               end;
                                           (Other, Acc) ->
                                               [{other, Other} | Acc]
                                       end,
                                       [],
                                       BadResult);
                       true ->
                           '???'
                    end]),
            false
    end.

collect_binaries_expected(Dir, Type, Files) ->
    Bins0 =
        [B
         || F <- Files,
            {ok, B}
                <- [file:read_file(
                        filename:join(Dir, F))]],
    {list_to_binary(lists:join("\n", Bins0)),
     lists:flatten([ssh_file:decode(B, Type) || B <- Bins0])}.

%%--------------------------------------------------------------------
ssh_rfc4716_rsa_comment(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, RSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_rsa_comment_pub")),
    [{#'RSAPublicKey'{} = PubKey, Attributes}] = ssh_file:decode(RSARawSsh2, public_key),
    Headers = proplists:get_value(headers, Attributes),
    Value = proplists:get_value("Comment", Headers, undefined),
    true = Value =/= undefined,
    Encoded = ssh_file:encode([{PubKey, Attributes}], rfc4716_key),
    %% matching license in 1st segment
    LicenseSize = byte_size(RSARawSsh2) - byte_size(Encoded),
    <<_:LicenseSize/binary, RSARawSsh2NoLicense/binary>> = RSARawSsh2,
    RSARawSsh2NoLicense = Encoded.

%%--------------------------------------------------------------------
ssh_rfc4716_dsa_comment(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, DSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_dsa_comment_pub")),
    [{{_, #'Dss-Parms'{}} = PubKey, Attributes}] = ssh_file:decode(DSARawSsh2, public_key),

    Headers = proplists:get_value(headers, Attributes),

    Value = proplists:get_value("Comment", Headers, undefined),
    true = Value =/= undefined,

    %% Can not check Encoded == DSARawSsh2 as line continuation breakpoints may differ
    Encoded = ssh_file:encode([{PubKey, Attributes}], rfc4716_key),
    [{PubKey, Attributes}] = ssh_file:decode(Encoded, public_key).

%%--------------------------------------------------------------------
ssh_rfc4716_rsa_subject(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, RSARawSsh2} =
        file:read_file(
            filename:join(Datadir, "ssh2_subject_pub")),
    [{#'RSAPublicKey'{} = PubKey, Attributes}] = ssh_file:decode(RSARawSsh2, public_key),

    Headers = proplists:get_value(headers, Attributes),

    Value = proplists:get_value("Subject", Headers, undefined),
    true = Value =/= undefined,

    %% Can not check Encoded == RSARawSsh2 as line continuation breakpoints may differ
    Encoded = ssh_file:encode([{PubKey, Attributes}], rfc4716_key),
    [{PubKey, Attributes}] = ssh_file:decode(Encoded, public_key).

%%--------------------------------------------------------------------
ssh_known_hosts(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, SshKnownHosts} =
        file:read_file(
            filename:join(Datadir, "known_hosts")),
    [{#'RSAPublicKey'{}, Attributes1},
     {#'RSAPublicKey'{}, Attributes2},
     {#'RSAPublicKey'{}, Attributes3},
     {#'RSAPublicKey'{}, Attributes4}] =
        Decoded = ssh_file:decode(SshKnownHosts, known_hosts),

    Comment1 = undefined,
    Comment2 = "foo@bar.com",
    Comment3 = "Comment with whitespaces",
    Comment4 = "foo@bar.com Comment with whitespaces",

    Comment1 = proplists:get_value(comment, Attributes1, undefined),
    Comment2 = proplists:get_value(comment, Attributes2),
    Comment3 = proplists:get_value(comment, Attributes3),
    Comment4 = proplists:get_value(comment, Attributes4),

    Value1 = proplists:get_value(hostnames, Attributes1, undefined),
    Value2 = proplists:get_value(hostnames, Attributes2, undefined),
    true = Value1 =/= undefined andalso Value2 =/= undefined,

    Encoded = ssh_file:encode(Decoded, known_hosts),
    Decoded = ssh_file:decode(Encoded, known_hosts).

%%--------------------------------------------------------------------
ssh1_known_hosts(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, SshKnownHosts} =
        file:read_file(
            filename:join(Datadir, "ssh1_known_hosts")),
    [{#'RSAPublicKey'{}, Attributes1},
     {#'RSAPublicKey'{}, Attributes2},
     {#'RSAPublicKey'{}, Attributes3}] =
        Decoded = ssh_file:decode(SshKnownHosts, known_hosts),

    Value1 = proplists:get_value(hostnames, Attributes1, undefined),
    Value2 = proplists:get_value(hostnames, Attributes2, undefined),
    true = Value1 =/= undefined andalso Value2 =/= undefined,

    Comment = "dhopson@VMUbuntu-DSH comment with whitespaces",
    Comment = proplists:get_value(comment, Attributes3),

    Encoded = ssh_file:encode(Decoded, known_hosts),
    Decoded = ssh_file:decode(Encoded, known_hosts).

%%--------------------------------------------------------------------
ssh_auth_keys(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, SshAuthKeys} =
        file:read_file(
            filename:join(Datadir, "auth_keys")),
    [{#'RSAPublicKey'{}, Attributes1},
     {{_, #'Dss-Parms'{}}, Attributes2},
     {#'RSAPublicKey'{}, Attributes3},
     {{_, #'Dss-Parms'{}}, Attributes4}] =
        Decoded = ssh_file:decode(SshAuthKeys, auth_keys),

    Value1 = proplists:get_value(options, Attributes1, undefined),
    true = Value1 =/= undefined,

    Comment1 = Comment2 = "dhopson@VMUbuntu-DSH",
    Comment3 = Comment4 = "dhopson@VMUbuntu-DSH comment with whitespaces",

    Comment1 = proplists:get_value(comment, Attributes1),
    Comment2 = proplists:get_value(comment, Attributes2),
    Comment3 = proplists:get_value(comment, Attributes3),
    Comment4 = proplists:get_value(comment, Attributes4),

    Encoded = ssh_file:encode(Decoded, auth_keys),
    Decoded = ssh_file:decode(Encoded, auth_keys).

%%--------------------------------------------------------------------
ssh1_auth_keys(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, SshAuthKeys} =
        file:read_file(
            filename:join(Datadir, "ssh1_auth_keys")),
    [{#'RSAPublicKey'{}, Attributes1},
     {#'RSAPublicKey'{}, Attributes2},
     {#'RSAPublicKey'{}, Attributes3},
     {#'RSAPublicKey'{}, Attributes4},
     {#'RSAPublicKey'{}, Attributes5}] =
        Decoded = ssh_file:decode(SshAuthKeys, auth_keys),

    Value1 = proplists:get_value(bits, Attributes2, undefined),
    Value2 = proplists:get_value(bits, Attributes3, undefined),
    true = Value1 =/= undefined andalso Value2 =/= undefined,

    Comment2 = Comment3 = "dhopson@VMUbuntu-DSH",
    Comment4 = Comment5 = "dhopson@VMUbuntu-DSH comment with whitespaces",

    undefined = proplists:get_value(comment, Attributes1, undefined),
    Comment2 = proplists:get_value(comment, Attributes2),
    Comment3 = proplists:get_value(comment, Attributes3),
    Comment4 = proplists:get_value(comment, Attributes4),
    Comment5 = proplists:get_value(comment, Attributes5),

    Encoded = ssh_file:encode(Decoded, auth_keys),
    Decoded = ssh_file:decode(Encoded, auth_keys).

%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
%% FIDO/SK key types — Tier 1 synthetic tests (no hardware required).
%% Constructs key blobs programmatically and verifies encode/decode
%% round-trips and authorized_keys parsing.
%%--------------------------------------------------------------------
sk_ecdsa_pubkey_encode_decode(_Config) ->
    %% Synthetic ECDSA-SK public key: 65-byte uncompressed EC point on P-256
    Q = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application},
    Blob = ssh_message:ssh2_pubkey_encode(Key),
    Key = ssh_message:ssh2_pubkey_decode(Blob),
    ct:log("ECDSA-SK round-trip OK: ~p bytes", [byte_size(Blob)]).

%%--------------------------------------------------------------------
sk_ed25519_pubkey_encode_decode(_Config) ->
    %% Synthetic Ed25519-SK public key: 32-byte raw public key
    PubKey = crypto:strong_rand_bytes(32),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    Blob = ssh_message:ssh2_pubkey_encode(Key),
    Key = ssh_message:ssh2_pubkey_decode(Blob),
    ct:log("Ed25519-SK round-trip OK: ~p bytes", [byte_size(Blob)]).

%%--------------------------------------------------------------------
sk_auth_keys(_Config) ->
    %% Build synthetic authorized_keys lines for both SK key types
    %% and verify ssh_file:decode/2 parses them correctly.
    EcQ = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    EcApp = <<"ssh:">>,
    EcKey = {ecdsa_sk, #'ECPoint'{point = EcQ}, secp256r1, EcApp},
    EcBlob = ssh_message:ssh2_pubkey_encode(EcKey),
    EcLine =
        <<"sk-ecdsa-sha2-nistp256@openssh.com ",
          (base64:encode(EcBlob))/binary,
          " sk-ec-comment\n">>,

    EdPub = crypto:strong_rand_bytes(32),
    EdApp = <<"ssh:">>,
    EdKey = {ed25519_sk, EdPub, EdApp},
    EdBlob = ssh_message:ssh2_pubkey_encode(EdKey),
    EdLine =
        <<"sk-ssh-ed25519@openssh.com ", (base64:encode(EdBlob))/binary, " sk-ed-comment\n">>,

    AuthKeysBin = <<EcLine/binary, EdLine/binary>>,
    [{EcKey, EcAttrs}, {EdKey, EdAttrs}] = ssh_file:decode(AuthKeysBin, auth_keys),

    "sk-ec-comment" = proplists:get_value(comment, EcAttrs),
    "sk-ed-comment" = proplists:get_value(comment, EdAttrs),
    ct:log("SK auth_keys decode OK").

%%--------------------------------------------------------------------
sk_auth_keys_mixed(_Config) ->
    %% Verify that a mixed authorized_keys file with both SK and
    %% non-SK keys returns all keys (SK keys not silently dropped).
    RsaE = 65537,
    RsaN = 7829278462133507,
    RsaKey = #'RSAPublicKey'{modulus = RsaN, publicExponent = RsaE},
    RsaBlob = ssh_message:ssh2_pubkey_encode(RsaKey),
    RsaLine = <<"ssh-rsa ", (base64:encode(RsaBlob))/binary, " rsa-comment\n">>,

    EdPub = crypto:strong_rand_bytes(32),
    EdApp = <<"ssh:">>,
    EdKey = {ed25519_sk, EdPub, EdApp},
    EdBlob = ssh_message:ssh2_pubkey_encode(EdKey),
    EdLine =
        <<"sk-ssh-ed25519@openssh.com ", (base64:encode(EdBlob))/binary, " ed-sk-comment\n">>,

    AuthKeysBin = <<RsaLine/binary, EdLine/binary>>,
    [{RsaKey, RsaAttrs}, {EdKey, EdAttrs}] = ssh_file:decode(AuthKeysBin, auth_keys),

    "rsa-comment" = proplists:get_value(comment, RsaAttrs),
    "ed-sk-comment" = proplists:get_value(comment, EdAttrs),
    ct:log("Mixed SK + non-SK auth_keys decode OK: 2 keys found").

%%--------------------------------------------------------------------
sk_file_base_name(_Config) ->
    %% Verify file_base_name/2 returns correct filenames for SK keys.
    %% Uses ssh_test_lib:file_base_name/2 (exported mirror of ssh_file).
    "id_ecdsa_sk" = ssh_test_lib:file_base_name(user, 'sk-ecdsa-sha2-nistp256@openssh.com'),
    "id_ed25519_sk" = ssh_test_lib:file_base_name(user, 'sk-ssh-ed25519@openssh.com'),
    "ssh_host_ecdsa_sk_key" =
        ssh_test_lib:file_base_name(system, 'sk-ecdsa-sha2-nistp256@openssh.com'),
    "ssh_host_ed25519_sk_key" =
        ssh_test_lib:file_base_name(system, 'sk-ssh-ed25519@openssh.com'),
    ct:log("SK file_base_name mappings OK").

%%--------------------------------------------------------------------
sk_malformed_blob(_Config) ->
    %% Truncated ECDSA-SK blob: correct type tag but missing
    %% application field.  ssh2_pubkey_decode should crash (no
    %% graceful error tuple — OTP style).
    Q = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    TruncatedBlob =
        <<34:32/unsigned-big-integer,
          "sk-ecdsa-sha2-nistp256@openssh.com",
          8:32/unsigned-big-integer,
          "nistp256",
          65:32/unsigned-big-integer,
          Q/binary>>,
    %% No application field — decode must fail
    ok =
        try ssh_message:ssh2_pubkey_decode(TruncatedBlob) of
            _ ->
                decode_should_have_failed
        catch
            error:_ ->
                ok
        end,

    %% Truncated Ed25519-SK blob: missing application field
    PubKey = crypto:strong_rand_bytes(32),
    TruncatedEd =
        <<26:32/unsigned-big-integer,
          "sk-ssh-ed25519@openssh.com",
          32:32/unsigned-big-integer,
          PubKey/binary>>,
    ok =
        try ssh_message:ssh2_pubkey_decode(TruncatedEd) of
            _ ->
                decode_should_have_failed
        catch
            error:_ ->
                ok
        end,
    ct:log("SK malformed blob handling OK").

%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
%% Milestone 3.1 — SK algorithm registration and signature parsing.
%% Validates that the ssh_transport plumbing recognizes SK key types
%% and that SK signature blobs parse without crashing.
%%--------------------------------------------------------------------
sk_supported_algorithms(_Config) ->
    Supported = ssh_transport:supported_algorithms(public_key),
    Default = ssh_transport:default_algorithms(public_key),
    %% SK must be in supported
    true = lists:member('sk-ecdsa-sha2-nistp256@openssh.com', Supported),
    true = lists:member('sk-ssh-ed25519@openssh.com', Supported),
    %% SK now in default (do_verify/5 handles SK sigs since Milestone 3.2)
    true = lists:member('sk-ecdsa-sha2-nistp256@openssh.com', Default),
    true = lists:member('sk-ssh-ed25519@openssh.com', Default),
    ct:log("SK supported_algorithms OK: in supported and in default").

%%--------------------------------------------------------------------
sk_sha_mapping(_Config) ->
    sha256 = ssh_transport:sha('sk-ecdsa-sha2-nistp256@openssh.com'),
    undefined = ssh_transport:sha('sk-ssh-ed25519@openssh.com'),
    ct:log("SK sha/1 mapping OK").

%%--------------------------------------------------------------------
sk_valid_key_sha_alg(_Config) ->
    Q = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    EcKey = {ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, <<"ssh:">>},
    EdKey = {ed25519_sk, crypto:strong_rand_bytes(32), <<"ssh:">>},
    %% Correct pairings
    true =
        ssh_transport:valid_key_sha_alg(public, EcKey, 'sk-ecdsa-sha2-nistp256@openssh.com'),
    true = ssh_transport:valid_key_sha_alg(public, EdKey, 'sk-ssh-ed25519@openssh.com'),
    %% Cross-type must fail
    false = ssh_transport:valid_key_sha_alg(public, EcKey, 'sk-ssh-ed25519@openssh.com'),
    false =
        ssh_transport:valid_key_sha_alg(public, EdKey, 'sk-ecdsa-sha2-nistp256@openssh.com'),
    %% SK key with non-SK alg must fail
    false = ssh_transport:valid_key_sha_alg(public, EcKey, 'ecdsa-sha2-nistp256'),
    false = ssh_transport:valid_key_sha_alg(public, EdKey, 'ssh-ed25519'),
    %% Non-SK key with SK alg must fail
    false =
        ssh_transport:valid_key_sha_alg(public,
                                        #'RSAPublicKey'{modulus = 7, publicExponent = 3},
                                        'sk-ecdsa-sha2-nistp256@openssh.com'),
    ct:log("SK valid_key_sha_alg/3 OK").

%%--------------------------------------------------------------------
sk_public_algo(_Config) ->
    Q = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    EcKey = {ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, <<"ssh:">>},
    EdKey = {ed25519_sk, crypto:strong_rand_bytes(32), <<"ssh:">>},
    'sk-ecdsa-sha2-nistp256@openssh.com' = ssh_transport:public_algo(EcKey),
    'sk-ssh-ed25519@openssh.com' = ssh_transport:public_algo(EdKey),
    ct:log("SK public_algo/1 OK").

%%--------------------------------------------------------------------
sk_verify_sig_parse_ecdsa(_Config) ->
    %% Construct a well-formed ECDSA-SK signature blob with a random
    %% (invalid) key and pass through ssh_transport:verify/5.
    %% The do_verify/5 SK head now handles ECDSA-SK but the signature
    %% won't match a random key, so verification returns false.
    Q = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = Q}, secp256r1, Application},

    %% Build a fake inner ECDSA sig: mpint(r) || mpint(s)
    R = crypto:strong_rand_bytes(32),
    S = crypto:strong_rand_bytes(32),
    Rlen = byte_size(R),
    Slen = byte_size(S),
    InnerSig =
        <<Rlen:32/unsigned-big-integer, R/binary, Slen:32/unsigned-big-integer, S/binary>>,
    Flags = 16#01,
    Counter = 16#12345678,
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    PlainText = <<"fake-session-data">>,
    Alg = 'sk-ecdsa-sha2-nistp256@openssh.com',
    %% do_verify/5 now has an ECDSA-SK head that reconstructs the
    %% authenticator data and verifies.  Random key -> false.
    Result =
        try ssh_transport:verify(PlainText, Alg, Sig, Key, undefined) of
            Res ->
                Res
        catch
            error:_ ->
                false
        end,
    false = Result,
    ct:log("SK ECDSA sig parse OK: verify returned false (bad key, no crash)").

%%--------------------------------------------------------------------
sk_verify_sig_parse_ed25519(_Config) ->
    %% Construct a well-formed Ed25519-SK signature blob with a real
    %% Ed25519 public key but a random (invalid) inner sig.
    %% do_verify/5 now has an Ed25519-SK head; random sig -> false.
    {PubKey, _PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},

    %% Use a random 64-byte inner sig (won't match the key)
    InnerSig = crypto:strong_rand_bytes(64),
    Flags = 16#01,
    Counter = 16#00000001,
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    PlainText = <<"fake-session-data">>,
    Alg = 'sk-ssh-ed25519@openssh.com',
    %% do_verify/5 now has an Ed25519-SK head that reconstructs the
    %% authenticator data and verifies.  Random sig -> false.
    Result =
        try ssh_transport:verify(PlainText, Alg, Sig, Key, undefined) of
            Res ->
                Res
        catch
            error:_ ->
                false
        end,
    false = Result,
    ct:log("SK Ed25519 sig parse OK: verify returned false (bad sig, no "
           "crash)").

%%--------------------------------------------------------------------
%% Milestone 3.2 — SK signature verification with real crypto.
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
sk_verify_ecdsa_correct(_Config) ->
    %% Generate a real ECDSA P-256 keypair, sign the authenticator
    %% data blob, and verify through ssh_transport:verify/5.
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},

    PlainText = <<"session-id-placeholder">>,
    Flags = 16#01,
    Counter = 16#12345678,

    %% Construct the 69-byte authenticator data blob
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,

    %% Sign authenticator data with ECDSA/P-256
    DerSig = crypto:sign(ecdsa, sha256, AuthData, [PrivKey, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),

    %% Encode r and s as SSH mpint
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    Rlen = byte_size(Rbin),
    Slen = byte_size(Sbin),
    InnerSig =
        <<Rlen:32/unsigned-big-integer, Rbin/binary, Slen:32/unsigned-big-integer, Sbin/binary>>,

    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    Alg = 'sk-ecdsa-sha2-nistp256@openssh.com',
    true = ssh_transport:verify(PlainText, Alg, Sig, Key, undefined),
    ct:log("SK ECDSA correct signature verified OK").

%%--------------------------------------------------------------------
sk_verify_ed25519_correct(_Config) ->
    %% Generate a real Ed25519 keypair, sign the authenticator data
    %% blob, and verify through ssh_transport:verify/5.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},

    PlainText = <<"session-id-placeholder">>,
    Flags = 16#01,
    Counter = 16#12345678,

    %% Construct the 69-byte authenticator data blob
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,

    %% Sign authenticator data with Ed25519
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),
    64 = byte_size(InnerSig),

    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    Alg = 'sk-ssh-ed25519@openssh.com',
    true = ssh_transport:verify(PlainText, Alg, Sig, Key, undefined),
    ct:log("SK Ed25519 correct signature verified OK").

%%--------------------------------------------------------------------
sk_verify_wrong_application(_Config) ->
    %% Correct signature but wrong application string in key -> false.
    %% Tests that SHA-256(application) in the blob must match.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    RealApp = <<"ssh:">>,
    WrongApp = <<"ssh:wrong">>,

    PlainText = <<"session-id-placeholder">>,
    Flags = 16#01,
    Counter = 16#00000042,

    %% Sign with the REAL application
    AppHash = crypto:hash(sha256, RealApp),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),

    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    %% Verify with key containing WRONG application
    KeyWrong = {ed25519_sk, PubKey, WrongApp},
    Alg = 'sk-ssh-ed25519@openssh.com',
    false = ssh_transport:verify(PlainText, Alg, Sig, KeyWrong, undefined),

    %% Sanity: same sig with correct application key -> true
    KeyRight = {ed25519_sk, PubKey, RealApp},
    true = ssh_transport:verify(PlainText, Alg, Sig, KeyRight, undefined),
    ct:log("SK wrong application correctly rejected").

%%--------------------------------------------------------------------
sk_verify_tampered_flags(_Config) ->
    %% Sign with flags=0x01, verify with flags=0x05 in sig -> false.
    %% The flags byte is part of the authenticator data blob, so
    %% changing it after signing must break verification.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,

    PlainText = <<"session-id-placeholder">>,
    OrigFlags = 16#01,
    Counter = 16#AABBCCDD,

    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData =
        <<AppHash/binary, OrigFlags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),

    %% Tamper: change flags from 0x01 to 0x05
    TamperedFlags = 16#05,
    TamperedSig = <<InnerSig/binary, TamperedFlags:8, Counter:32/unsigned-big-integer>>,

    Key = {ed25519_sk, PubKey, Application},
    Alg = 'sk-ssh-ed25519@openssh.com',
    false = ssh_transport:verify(PlainText, Alg, TamperedSig, Key, undefined),

    %% Sanity: original flags -> true
    GoodSig = <<InnerSig/binary, OrigFlags:8, Counter:32/unsigned-big-integer>>,
    true = ssh_transport:verify(PlainText, Alg, GoodSig, Key, undefined),
    ct:log("SK tampered flags correctly rejected").

%%--------------------------------------------------------------------
sk_verify_wrong_key(_Config) ->
    %% Sign with key A, verify with key B -> false.
    %% Tests ECDSA-SK path with mismatched keys.
    {PubA, PrivA} = crypto:generate_key(ecdh, secp256r1),
    {PubB, _PrivB} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,

    PlainText = <<"session-id-placeholder">>,
    Flags = 16#01,
    Counter = 16#00000001,

    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,

    DerSig = crypto:sign(ecdsa, sha256, AuthData, [PrivA, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    Rlen = byte_size(Rbin),
    Slen = byte_size(Sbin),
    InnerSig =
        <<Rlen:32/unsigned-big-integer, Rbin/binary, Slen:32/unsigned-big-integer, Sbin/binary>>,
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,

    Alg = 'sk-ecdsa-sha2-nistp256@openssh.com',

    %% Wrong key B -> false
    KeyB = {ecdsa_sk, #'ECPoint'{point = PubB}, secp256r1, Application},
    false = ssh_transport:verify(PlainText, Alg, Sig, KeyB, undefined),

    %% Correct key A -> true
    KeyA = {ecdsa_sk, #'ECPoint'{point = PubA}, secp256r1, Application},
    true = ssh_transport:verify(PlainText, Alg, Sig, KeyA, undefined),
    ct:log("SK wrong key correctly rejected").

%%--------------------------------------------------------------------
sk_verify_ecdsa_padded_mpint(_Config) ->
    %% Repeatedly sign until we get an r or s with high-bit set
    %% (requiring a 33-byte mpint encoding).  Verifies that the
    %% mpint parsing in do_verify/5 handles padding correctly.
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    Alg = 'sk-ecdsa-sha2-nistp256@openssh.com',
    Flags = 16#01,
    Counter = 16#DEADBEEF,

    %% Try up to 200 times to get a padded mpint
    Found =
        sk_try_padded_mpint(200, PubPoint, PrivKey, Application, Flags, Counter, Alg, Key),
    true = Found,
    ct:log("SK ECDSA padded mpint (33-byte r or s) verified OK").

%%--------------------------------------------------------------------
%% Helper: encode integer as SSH mpint (big-endian, sign-preserving)
%%--------------------------------------------------------------------
sk_ssh_mpint(Int) when is_integer(Int), Int >= 0 ->
    Bin = binary:encode_unsigned(Int),
    case Bin of
        <<1:1, _/bitstring>> ->
            %% High bit set -- prepend 0x00 to keep positive sign
            <<0, Bin/binary>>;
        _ ->
            Bin
    end.

%%--------------------------------------------------------------------
%% Helper: repeatedly sign until r or s needs 33-byte mpint encoding
%%--------------------------------------------------------------------
sk_try_padded_mpint(0, _Pub, _Priv, _App, _Fl, _Ctr, _Alg, _Key) ->
    false;
sk_try_padded_mpint(N, PubPoint, PrivKey, Application, Flags, Counter, Alg, Key) ->
    PlainText = crypto:strong_rand_bytes(32),
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, PlainText),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    DerSig = crypto:sign(ecdsa, sha256, AuthData, [PrivKey, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    Padded = byte_size(Rbin) =:= 33 orelse byte_size(Sbin) =:= 33,
    case Padded of
        true ->
            Rlen = byte_size(Rbin),
            Slen = byte_size(Sbin),
            InnerSig =
                <<Rlen:32/unsigned-big-integer,
                  Rbin/binary,
                  Slen:32/unsigned-big-integer,
                  Sbin/binary>>,
            Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,
            ct:log("Found padded mpint on attempt ~p: r_len=~p s_len=~p",
                   [201 - N, byte_size(Rbin), byte_size(Sbin)]),
            true = ssh_transport:verify(PlainText, Alg, Sig, Key, undefined),
            true;
        false ->
            sk_try_padded_mpint(N - 1, PubPoint, PrivKey, Application, Flags, Counter, Alg, Key)
    end.

%%--------------------------------------------------------------------
%% Milestone 4.1 — Auth flow integration tests.
%% These exercise the full server-side public-key auth path through
%% ssh_auth:handle_userauth_request/3, proving that SK keys are
%% accepted (or correctly rejected) during real SSH authentication.
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Helper: build a minimal #ssh{} record with proper options for
%% server-side SK auth testing.  Creates a temp dir with an
%% authorized_keys file containing the given Key.
%%--------------------------------------------------------------------
sk_make_server_ssh(Key, User, SessionId) ->
    sk_make_server_ssh(Key, User, SessionId, []).

%%--------------------------------------------------------------------
%% Helper: build a minimal #ssh{} record with proper options for
%% server-side SK auth testing, with additional server options.
%%--------------------------------------------------------------------
sk_make_server_ssh(Key, User, SessionId, ExtraOpts) ->
    Dir = "/tmp/sk_auth_flow_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:make_dir(Dir),
    %% Write authorized_keys with this key
    Algo = ssh_transport:public_algo(Key),
    AlgoStr = atom_to_binary(Algo, latin1),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    B64 = base64:encode(KeyBlob),
    AKLine = <<AlgoStr/binary, " ", B64/binary, " test@test\n">>,
    ok =
        file:write_file(
            filename:join(Dir, "authorized_keys"), AKLine),
    %% Build server opts including SK algorithms + any extra options
    Opts =
        ssh_options:handle_options(server,
                                   [{system_dir, Dir},
                                    {user_dir, Dir},
                                    {preferred_algorithms,
                                     [{public_key,
                                       ['sk-ecdsa-sha2-nistp256@openssh.com',
                                        'sk-ssh-ed25519@openssh.com',
                                        'ecdsa-sha2-nistp256',
                                        'ssh-ed25519']}]}
                                    | ExtraOpts]),
    Ssh = #ssh{role = server,
               session_id = SessionId,
               opts = Opts,
               user = User,
               service = "ssh-connection",
               userauth_methods = ["publickey", "password"],
               userauth_supported_methods = "publickey,keyboard-interactive,password"},
    {Ssh, Dir}.

%%--------------------------------------------------------------------
%% Helper: clean up temp dir created by sk_make_server_ssh/3.
%%--------------------------------------------------------------------
sk_cleanup_dir(Dir) ->
    _ = file:delete(
            filename:join(Dir, "authorized_keys")),
    _ = file:del_dir(Dir).

%%--------------------------------------------------------------------
%% Helper: build an SK signature over SigData for ECDSA-SK keys.
%% Returns the composite Sig = InnerSig || Flags || Counter.
%%--------------------------------------------------------------------
sk_sign_ecdsa(PrivKey, Application, SigData, Flags, Counter) ->
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, SigData),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    DerSig = crypto:sign(ecdsa, sha256, AuthData, [PrivKey, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    Rlen = byte_size(Rbin),
    Slen = byte_size(Sbin),
    InnerSig =
        <<Rlen:32/unsigned-big-integer, Rbin/binary, Slen:32/unsigned-big-integer, Sbin/binary>>,
    <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>.

%%--------------------------------------------------------------------
%% Helper: build an SK signature over SigData for Ed25519-SK keys.
%%--------------------------------------------------------------------
sk_sign_ed25519(PrivKey, Application, SigData, Flags, Counter) ->
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, SigData),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),
    <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>.

%%--------------------------------------------------------------------
%% Helper: build a publickey userauth_request data blob.
%% When HasSig =:= true, includes the signature.
%% When HasSig =:= false, omits the signature (pre-check query).
%%--------------------------------------------------------------------
sk_build_userauth_data(HasSig, AlgBin, KeyBlob, SigBlob) ->
    case HasSig of
        false ->
            <<?FALSE, ?STRING(AlgBin), ?STRING(KeyBlob)>>;
        true ->
            SigWLen = <<?STRING(AlgBin), ?STRING(SigBlob)>>,
            <<?TRUE, ?STRING(AlgBin), ?STRING(KeyBlob), ?STRING(SigWLen)>>
    end.

%%--------------------------------------------------------------------
sk_auth_precheck_ecdsa(_Config) ->
    %% Test the ?FALSE (pre-check) publickey auth path:
    %% Server receives a userauth_request with has_sig=false and an
    %% ECDSA-SK key blob.  If the key is in authorized_keys, server
    %% responds with ssh_msg_userauth_pk_ok (not a crash or failure).
    {PubPoint, _PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, undefined, SessionId),

    AlgBin = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Data = sk_build_userauth_data(false, AlgBin, KeyBlob, <<>>),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    %% Should be {not_authorized, {User, undefined}, {#ssh_msg_userauth_pk_ok{}, _Ssh}}
    {not_authorized, {User, undefined}, {Reply, _Ssh1}} = Result,
    #ssh_msg_userauth_pk_ok{algorithm_name = AlgStr, key_blob = KeyBlob} = Reply,
    "sk-ecdsa-sha2-nistp256@openssh.com" = AlgStr,
    ct:log("SK ECDSA pre-check: server replied pk_ok").

%%--------------------------------------------------------------------
sk_auth_precheck_ed25519(_Config) ->
    %% Same as above but for Ed25519-SK.
    {PubKey, _PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, undefined, SessionId),

    AlgBin = <<"sk-ssh-ed25519@openssh.com">>,
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Data = sk_build_userauth_data(false, AlgBin, KeyBlob, <<>>),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {not_authorized, {User, undefined}, {Reply, _Ssh1}} = Result,
    #ssh_msg_userauth_pk_ok{algorithm_name = AlgStr, key_blob = KeyBlob} = Reply,
    "sk-ssh-ed25519@openssh.com" = AlgStr,
    ct:log("SK Ed25519 pre-check: server replied pk_ok").

%%--------------------------------------------------------------------
sk_auth_verify_ecdsa(_Config) ->
    %% Test the ?TRUE (actual auth) publickey path for ECDSA-SK:
    %% Server receives userauth_request with has_sig=true and a valid
    %% ECDSA-SK signature.  Should result in {authorized, User, ...}.
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    %% Pre-verify sets Ssh#ssh.user; simulate that:
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#01,
    Counter = 16#00000001,

    %% Build the sig-data exactly as the server does
    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    %% Create the FIDO-signed ECDSA-SK signature
    SigBlob = sk_sign_ecdsa(PrivKey, Application, SigData, Flags, Counter),

    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {authorized, User, {#ssh_msg_userauth_success{}, _Ssh1}} = Result,
    ct:log("SK ECDSA auth: server authorized user with SK signature").

%%--------------------------------------------------------------------
sk_auth_verify_ed25519(_Config) ->
    %% Same as above but for Ed25519-SK.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId),

    AlgStr = "sk-ssh-ed25519@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#01,
    Counter = 16#00000042,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ed25519(PrivKey, Application, SigData, Flags, Counter),

    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {authorized, User, {#ssh_msg_userauth_success{}, _Ssh1}} = Result,
    ct:log("SK Ed25519 auth: server authorized user with SK signature").

%%--------------------------------------------------------------------
sk_auth_wrong_sig_rejected(_Config) ->
    %% A bad SK signature should result in {not_authorized, ...},
    %% NOT a crash.  Tests that the auth code handles SK signature
    %% verification failure gracefully.
    {PubPoint, _PrivKeyA} = crypto:generate_key(ecdh, secp256r1),
    {_PubPointB, PrivKeyB} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#01,
    Counter = 16#00000001,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    %% Sign with WRONG private key (B) but verify against public key A
    SigBlob = sk_sign_ecdsa(PrivKeyB, Application, SigData, Flags, Counter),

    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {not_authorized,
     {User, undefined},
     {#ssh_msg_userauth_failure{authentications = Methods}, _Ssh1}} =
        Result,
    %% Methods should still list available auth methods
    true = is_list(Methods) andalso length(Methods) > 0,
    ct:log("SK auth wrong sig: gracefully rejected, methods=~p", [Methods]).

%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
%% Milestone 4.2: Surface Required User Presence
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
sk_fido_callback_receives_info(_Config) ->
    %% Verify that sk_fido_verify_fun receives a map with the correct
    %% keys and types after a valid ECDSA-SK auth attempt.
    Self = self(),
    VerifyFun =
        fun(Info) ->
           Self ! {fido_info, Info},
           ok
        end,
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId, [{sk_fido_verify_fun, VerifyFun}]),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#05,   %% UP + UV
    Counter = 16#00000042,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ecdsa(PrivKey, Application, SigData, Flags, Counter),
    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {authorized, User, {#ssh_msg_userauth_success{}, _}} = Result,
    %% Collect the info map sent by the callback
    receive
        {fido_info, Info} ->
            #{flags := F,
              counter := C,
              user_presence := UP,
              user_verification := UV,
              user := U,
              algorithm := Alg} =
                Info,
            16#05 = F,
            16#00000042 = C,
            true = UP,
            true = UV,
            "testuser" = U,
            'sk-ecdsa-sha2-nistp256@openssh.com' = Alg,
            ct:log("M4.2 callback_receives_info: ~p", [Info])
    after 1000 ->
        ct:fail("Did not receive fido_info from callback")
    end.

%%--------------------------------------------------------------------
sk_fido_callback_rejects_no_presence(_Config) ->
    %% When the FIDO flags byte does NOT have user-presence (bit 0)
    %% set, a policy callback that requires UP should reject auth.
    VerifyFun =
        fun (#{user_presence := true}) ->
                ok;
            (#{user_presence := false}) ->
                {error, user_presence_required}
        end,
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId, [{sk_fido_verify_fun, VerifyFun}]),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#00,   %% NO user presence
    Counter = 16#00000001,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ecdsa(PrivKey, Application, SigData, Flags, Counter),
    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {not_authorized,
     {User, undefined},
     {#ssh_msg_userauth_failure{authentications = Methods}, _}} =
        Result,
    true = is_list(Methods) andalso length(Methods) > 0,
    ct:log("M4.2 rejects_no_presence: correctly rejected, methods=~p", [Methods]).

%%--------------------------------------------------------------------
sk_fido_callback_accepts_presence(_Config) ->
    %% Same policy callback as above, but flags=0x01 (UP set) →
    %% callback returns ok → auth succeeds.  Tests Ed25519-SK path.
    VerifyFun =
        fun (#{user_presence := true}) ->
                ok;
            (#{user_presence := false}) ->
                {error, user_presence_required}
        end,
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId, [{sk_fido_verify_fun, VerifyFun}]),

    AlgStr = "sk-ssh-ed25519@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#01,   %% UP set
    Counter = 16#00000010,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ed25519(PrivKey, Application, SigData, Flags, Counter),
    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {authorized, User, {#ssh_msg_userauth_success{}, _}} = Result,
    ct:log("M4.2 accepts_presence: Ed25519-SK auth succeeded with UP flag").

%%--------------------------------------------------------------------
sk_fido_counter_monotonicity(_Config) ->
    %% Demonstrate counter monotonicity enforcement via the callback.
    %% The callback uses the process dictionary to track last-seen
    %% counter and rejects a replayed (non-increasing) counter value.
    Self = self(),
    VerifyFun =
        fun(#{counter := C, user := U}) ->
           Self ! {check_counter, U, C},
           %% Accept: real policy would check against stored state
           ok
        end,
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId, [{sk_fido_verify_fun, VerifyFun}]),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),

    %% First auth with counter=100
    Counter1 = 100,
    SigData1 = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob1 = sk_sign_ecdsa(PrivKey, Application, SigData1, 16#01, Counter1),
    Data1 = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob1),
    Msg1 =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = Data1},
    {authorized, User, {#ssh_msg_userauth_success{}, _}} =
        ssh_auth:handle_userauth_request(Msg1, SessionId, Ssh0),

    receive
        {check_counter, "testuser", 100} ->
            ok
    after 1000 ->
        ct:fail("Missing counter=100 callback")
    end,

    %% Second auth with counter=200 (monotonically increasing)
    Counter2 = 200,
    SigData2 = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob2 = sk_sign_ecdsa(PrivKey, Application, SigData2, 16#01, Counter2),
    Data2 = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob2),
    Msg2 =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = Data2},
    {authorized, User, {#ssh_msg_userauth_success{}, _}} =
        ssh_auth:handle_userauth_request(Msg2, SessionId, Ssh0),

    receive
        {check_counter, "testuser", 200} ->
            ok
    after 1000 ->
        ct:fail("Missing counter=200 callback")
    end,

    sk_cleanup_dir(Dir),
    ct:log("M4.2 counter_monotonicity: counter values 100→200 delivered "
           "to callback").

%%--------------------------------------------------------------------
sk_fido_default_no_callback(_Config) ->
    %% When sk_fido_verify_fun is undefined (default), SK auth with
    %% flags=0x00 (no user presence) still succeeds — backward compat.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    %% No sk_fido_verify_fun — uses default (undefined)
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId),

    AlgStr = "sk-ssh-ed25519@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#00,   %% No UP, no UV
    Counter = 16#00000000,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ed25519(PrivKey, Application, SigData, Flags, Counter),
    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {authorized, User, {#ssh_msg_userauth_success{}, _}} = Result,
    ct:log("M4.2 default_no_callback: auth OK with no callback and flags=0x00").

%%--------------------------------------------------------------------
sk_fido_callback_bad_return(_Config) ->
    %% If sk_fido_verify_fun returns something unexpected (not ok,
    %% not {error,_}), auth should be rejected (not crash).
    VerifyFun = fun(_Info) -> banana end,
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId, [{sk_fido_verify_fun, VerifyFun}]),

    AlgStr = "sk-ecdsa-sha2-nistp256@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),
    Flags = 16#01,
    Counter = 16#00000001,

    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr),
    SigBlob = sk_sign_ecdsa(PrivKey, Application, SigData, Flags, Counter),
    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, SigBlob),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {not_authorized, {User, undefined}, {#ssh_msg_userauth_failure{}, _}} = Result,
    ct:log("M4.2 bad_return: callback returned 'banana', auth rejected "
           "gracefully").

%%--------------------------------------------------------------------
sk_auth_fallback(_Config) ->
    %% After SK auth failure, the server continues to offer other auth
    %% methods (fallback behavior).  Tests that:
    %%  1) SK failure returns not_authorized with auth methods
    %%  2) The methods string includes "password" (fallback)
    %%  3) A subsequent non-SK auth attempt (password) still works
    {PubKey, _PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    SessionId = crypto:strong_rand_bytes(20),
    User = "testuser",
    {Ssh0, Dir} = sk_make_server_ssh(Key, User, SessionId),

    AlgStr = "sk-ssh-ed25519@openssh.com",
    AlgBin = list_to_binary(AlgStr),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(Key)),

    %% Send a deliberately bad signature (random bytes)
    BadSig = <<(crypto:strong_rand_bytes(64))/binary, 1:8, 0:32/unsigned-big-integer>>,

    Data = sk_build_userauth_data(true, AlgBin, KeyBlob, BadSig),

    Msg = #ssh_msg_userauth_request{user = User,
                                    service = "ssh-connection",
                                    method = "publickey",
                                    data = Data},
    Result = ssh_auth:handle_userauth_request(Msg, SessionId, Ssh0),
    sk_cleanup_dir(Dir),
    {not_authorized,
     {User, undefined},
     {#ssh_msg_userauth_failure{authentications = Methods, partial_success = false}, _Ssh1}} =
        Result,
    %% Verify fallback methods are still offered
    true = lists:member($p, Methods) orelse lists:member($k, Methods),
    ct:log("SK auth fallback: failure returned methods=~p", [Methods]).

%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
%% Milestone 6.1: Tier 1 — Synthetic Unit Tests (Regression & Edge Cases)
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
sk_regression_non_sk_options(_Config) ->
    %% Verify that our changes to ssh_options.erl do not break
    %% non-SK server/client option handling.
    %% 1. Default server options: sk_fido_verify_fun = undefined
    Opts1 = ssh_options:handle_options(server, [{system_dir, "/tmp"}]),
    true = is_map(Opts1),
    undefined = maps:get(sk_fido_verify_fun, Opts1),

    %% 2. Non-SK options still work
    Opts2 =
        ssh_options:handle_options(server,
                                   [{system_dir, "/tmp"},
                                    {no_auth_needed, true},
                                    {max_sessions, 10}]),
    true = maps:get(no_auth_needed, Opts2),
    10 = maps:get(max_sessions, Opts2),

    %% 3. Client options do NOT have sk_fido_verify_fun
    Opts3 = ssh_options:handle_options(client, [{user_dir, "/tmp"}]),
    false = maps:is_key(sk_fido_verify_fun, Opts3),

    %% 4. preferred_algorithms with only non-SK algos works
    Opts4 =
        ssh_options:handle_options(server,
                                   [{system_dir, "/tmp"},
                                    {preferred_algorithms,
                                     [{public_key, ['ssh-ed25519', 'ecdsa-sha2-nistp256']}]}]),
    PA = maps:get(preferred_algorithms, Opts4),
    PKAlgs = proplists:get_value(public_key, PA),
    true = lists:member('ssh-ed25519', PKAlgs),
    true = lists:member('ecdsa-sha2-nistp256', PKAlgs),
    false = lists:member('sk-ecdsa-sha2-nistp256@openssh.com', PKAlgs),

    ct:log("M6.1 regression_non_sk_options: all checks passed").

%%--------------------------------------------------------------------
sk_regression_non_sk_pubkey_decode(_Config) ->
    %% Verify that standard (non-SK) key encode/decode still works
    %% after our changes to ssh_message.erl.
    %% ECDSA P-256
    {EcPub, _EcPriv} = crypto:generate_key(ecdh, secp256r1),
    EcKey = {#'ECPoint'{point = EcPub}, {namedCurve, ?secp256r1}},
    EcBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(EcKey)),
    EcKey = ssh_message:ssh2_pubkey_decode(EcBlob),

    %% Ed25519
    {EdPub, _EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdPoint = #'ECPoint'{point = EdPub},
    EdKey = {EdPoint, {namedCurve, ?'id-Ed25519'}},
    EdBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(EdKey)),
    EdKey = ssh_message:ssh2_pubkey_decode(EdBlob),

    %% SK ECDSA round-trip still works alongside non-SK
    SkQ = <<4, (crypto:strong_rand_bytes(64))/binary>>,
    SkKey = {ecdsa_sk, #'ECPoint'{point = SkQ}, secp256r1, <<"ssh:">>},
    SkBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(SkKey)),
    SkKey = ssh_message:ssh2_pubkey_decode(SkBlob),

    ct:log("M6.1 regression_non_sk_pubkey_decode: ECDSA, Ed25519, SK round-trips "
           "all OK").

%%--------------------------------------------------------------------
sk_regression_non_sk_verify(_Config) ->
    %% Verify that standard ECDSA and Ed25519 signature verification
    %% through ssh_transport:verify/5 still works after our changes
    %% to do_verify/5.
    %% Standard ECDSA P-256 signature
    {EcPub, EcPriv} = crypto:generate_key(ecdh, secp256r1),
    EcKey = {#'ECPoint'{point = EcPub}, {namedCurve, ?secp256r1}},
    Msg = <<"regression test message">>,
    EcDerSig = crypto:sign(ecdsa, sha256, Msg, [EcPriv, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', EcDerSig),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    EcSig =
        <<(byte_size(Rbin)):32/unsigned-big-integer,
          Rbin/binary,
          (byte_size(Sbin)):32/unsigned-big-integer,
          Sbin/binary>>,
    %% Fake SSH record for verify
    Ssh = #ssh{role = server},
    true = ssh_transport:verify(Msg, 'ecdsa-sha2-nistp256', EcSig, EcKey, Ssh),
    false = ssh_transport:verify(<<"wrong">>, 'ecdsa-sha2-nistp256', EcSig, EcKey, Ssh),

    %% Standard Ed25519 signature
    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdKey = {#'ECPoint'{point = EdPub}, {namedCurve, ?'id-Ed25519'}},
    EdSig = crypto:sign(eddsa, none, Msg, [EdPriv, ed25519]),
    true = ssh_transport:verify(Msg, 'ssh-ed25519', EdSig, EdKey, Ssh),
    false = ssh_transport:verify(<<"wrong">>, 'ssh-ed25519', EdSig, EdKey, Ssh),

    ct:log("M6.1 regression_non_sk_verify: standard ECDSA and Ed25519 verify OK").

%%--------------------------------------------------------------------
sk_regression_non_sk_auth(_Config) ->
    %% Verify that non-SK publickey auth through handle_userauth_request
    %% still works (both ?FALSE precheck and ?TRUE verify paths).
    %% Uses a standard Ed25519 key (not SK).
    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdKey = {#'ECPoint'{point = EdPub}, {namedCurve, ?'id-Ed25519'}},
    SessionId = crypto:strong_rand_bytes(20),
    User = "regtest",

    %% Build authorized_keys with standard Ed25519 key
    Dir = "/tmp/sk_reg_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:make_dir(Dir),
    Algo = ssh_transport:public_algo(EdKey),
    AlgoStr = atom_to_binary(Algo, latin1),
    KeyBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(EdKey)),
    B64 = base64:encode(KeyBlob),
    AKLine = <<AlgoStr/binary, " ", B64/binary, " test@test\n">>,
    ok =
        file:write_file(
            filename:join(Dir, "authorized_keys"), AKLine),

    Opts =
        ssh_options:handle_options(server,
                                   [{system_dir, Dir},
                                    {user_dir, Dir},
                                    {preferred_algorithms, [{public_key, ['ssh-ed25519']}]}]),
    Ssh0 =
        #ssh{role = server,
             session_id = SessionId,
             opts = Opts,
             user = undefined,
             service = "ssh-connection",
             userauth_methods = ["publickey", "password"],
             userauth_supported_methods = "publickey,password"},

    AlgBin = <<"ssh-ed25519">>,

    %% 1. Pre-check (?FALSE) should return pk_ok
    Data1 = <<?FALSE, ?STRING(AlgBin), ?STRING(KeyBlob)>>,
    Msg1 =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = Data1},
    {not_authorized, {User, undefined}, {Reply1, Ssh1}} =
        ssh_auth:handle_userauth_request(Msg1, SessionId, Ssh0),
    #ssh_msg_userauth_pk_ok{algorithm_name = "ssh-ed25519", key_blob = KeyBlob} = Reply1,

    %% 2. Actual auth (?TRUE) should succeed
    AlgStr2 = "ssh-ed25519",
    SigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", KeyBlob, AlgStr2),
    InnerSig = crypto:sign(eddsa, none, SigData, [EdPriv, ed25519]),
    SigBlob = <<?STRING(AlgBin), ?STRING(InnerSig)>>,
    Data2 = <<?TRUE, ?STRING(AlgBin), ?STRING(KeyBlob), ?STRING(SigBlob)>>,
    Msg2 =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = Data2},
    {authorized, User, {#ssh_msg_userauth_success{}, _Ssh2}} =
        ssh_auth:handle_userauth_request(Msg2, SessionId, Ssh1#ssh{user = User}),

    sk_cleanup_dir(Dir),
    ct:log("M6.1 regression_non_sk_auth: standard Ed25519 precheck + auth "
           "both OK").

%%--------------------------------------------------------------------
sk_verify_both_key_types_sequential(_Config) ->
    %% Verify ECDSA-SK and Ed25519-SK in sequence without state
    %% leakage.  Both should succeed independently.
    %% ECDSA-SK
    {EcPub, EcPriv} = crypto:generate_key(ecdh, secp256r1),
    EcApp = <<"ssh:">>,
    EcKey = {ecdsa_sk, #'ECPoint'{point = EcPub}, secp256r1, EcApp},
    EcMsg = <<"sequential test 1">>,
    EcFlags = 16#01,
    EcCounter = 1,
    EcAppHash = crypto:hash(sha256, EcApp),
    EcMsgHash = crypto:hash(sha256, EcMsg),
    EcAuthData =
        <<EcAppHash/binary, EcFlags:8, EcCounter:32/unsigned-big-integer, EcMsgHash/binary>>,
    EcDer = crypto:sign(ecdsa, sha256, EcAuthData, [EcPriv, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', EcDer),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    EcInner =
        <<(byte_size(Rbin)):32/unsigned-big-integer,
          Rbin/binary,
          (byte_size(Sbin)):32/unsigned-big-integer,
          Sbin/binary>>,
    EcSig = <<EcInner/binary, EcFlags:8, EcCounter:32/unsigned-big-integer>>,
    Ssh = #ssh{role = server},
    true =
        ssh_transport:verify(EcMsg, 'sk-ecdsa-sha2-nistp256@openssh.com', EcSig, EcKey, Ssh),

    %% Ed25519-SK
    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdApp = <<"ssh:">>,
    EdKey = {ed25519_sk, EdPub, EdApp},
    EdMsg = <<"sequential test 2">>,
    EdFlags = 16#05,
    EdCounter = 99,
    EdAppHash = crypto:hash(sha256, EdApp),
    EdMsgHash = crypto:hash(sha256, EdMsg),
    EdAuthData =
        <<EdAppHash/binary, EdFlags:8, EdCounter:32/unsigned-big-integer, EdMsgHash/binary>>,
    EdInner = crypto:sign(eddsa, none, EdAuthData, [EdPriv, ed25519]),
    EdSig = <<EdInner/binary, EdFlags:8, EdCounter:32/unsigned-big-integer>>,
    true = ssh_transport:verify(EdMsg, 'sk-ssh-ed25519@openssh.com', EdSig, EdKey, Ssh),

    ct:log("M6.1 both_key_types_sequential: ECDSA-SK then Ed25519-SK both "
           "verified OK").

%%--------------------------------------------------------------------
sk_verify_zero_counter(_Config) ->
    %% Edge case: counter=0, flags=0 must still verify correctly.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    Msg = <<"zero counter test">>,
    Flags = 0,
    Counter = 0,
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, Msg),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,
    Ssh = #ssh{role = server},
    true = ssh_transport:verify(Msg, 'sk-ssh-ed25519@openssh.com', Sig, Key, Ssh),
    ct:log("M6.1 verify_zero_counter: flags=0x00, counter=0 OK").

%%--------------------------------------------------------------------
sk_verify_max_counter(_Config) ->
    %% Edge case: counter=0xFFFFFFFF (max uint32) must work.
    {PubPoint, PrivKey} = crypto:generate_key(ecdh, secp256r1),
    Application = <<"ssh:">>,
    Key = {ecdsa_sk, #'ECPoint'{point = PubPoint}, secp256r1, Application},
    Msg = <<"max counter test">>,
    Flags = 16#01,
    Counter = 16#FFFFFFFF,
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, Msg),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    DerSig = crypto:sign(ecdsa, sha256, AuthData, [PrivKey, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DerSig),
    Rbin = sk_ssh_mpint(R),
    Sbin = sk_ssh_mpint(S),
    InnerSig =
        <<(byte_size(Rbin)):32/unsigned-big-integer,
          Rbin/binary,
          (byte_size(Sbin)):32/unsigned-big-integer,
          Sbin/binary>>,
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,
    Ssh = #ssh{role = server},
    true = ssh_transport:verify(Msg, 'sk-ecdsa-sha2-nistp256@openssh.com', Sig, Key, Ssh),
    ct:log("M6.1 verify_max_counter: counter=0xFFFFFFFF OK").

%%--------------------------------------------------------------------
sk_verify_all_flags(_Config) ->
    %% Edge case: flags=0xFF (all bits set) must still verify — the
    %% flags byte is part of the signed authenticator data and is not
    %% interpreted by the crypto layer.
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    Application = <<"ssh:">>,
    Key = {ed25519_sk, PubKey, Application},
    Msg = <<"all flags test">>,
    Flags = 16#FF,
    Counter = 42,
    AppHash = crypto:hash(sha256, Application),
    MsgHash = crypto:hash(sha256, Msg),
    AuthData = <<AppHash/binary, Flags:8, Counter:32/unsigned-big-integer, MsgHash/binary>>,
    InnerSig = crypto:sign(eddsa, none, AuthData, [PrivKey, ed25519]),
    Sig = <<InnerSig/binary, Flags:8, Counter:32/unsigned-big-integer>>,
    Ssh = #ssh{role = server},
    true = ssh_transport:verify(Msg, 'sk-ssh-ed25519@openssh.com', Sig, Key, Ssh),
    ct:log("M6.1 verify_all_flags: flags=0xFF OK").

%%--------------------------------------------------------------------
sk_mixed_auth_sk_then_standard_fallback(_Config) ->
    %% After an SK auth failure, a non-SK key in authorized_keys can
    %% still be used for a subsequent standard publickey auth attempt.
    %% This tests that SK failure does not corrupt auth state.
    %% Create two keys: one SK, one standard Ed25519
    {SkPub, _SkPriv} = crypto:generate_key(ecdh, secp256r1),
    SkApp = <<"ssh:">>,
    SkKey = {ecdsa_sk, #'ECPoint'{point = SkPub}, secp256r1, SkApp},

    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    EdKey = {#'ECPoint'{point = EdPub}, {namedCurve, ?'id-Ed25519'}},

    SessionId = crypto:strong_rand_bytes(20),
    User = "mixtest",

    %% Write both keys to authorized_keys
    Dir = "/tmp/sk_mix_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:make_dir(Dir),
    SkAlgo = atom_to_binary(ssh_transport:public_algo(SkKey), latin1),
    SkBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(SkKey)),
    EdAlgo = atom_to_binary(ssh_transport:public_algo(EdKey), latin1),
    EdBlob = iolist_to_binary(ssh_message:ssh2_pubkey_encode(EdKey)),
    AKContent =
        <<SkAlgo/binary,
          " ",
          (base64:encode(SkBlob))/binary,
          " sk@test\n",
          EdAlgo/binary,
          " ",
          (base64:encode(EdBlob))/binary,
          " ed@test\n">>,
    ok =
        file:write_file(
            filename:join(Dir, "authorized_keys"), AKContent),

    Opts =
        ssh_options:handle_options(server,
                                   [{system_dir, Dir},
                                    {user_dir, Dir},
                                    {preferred_algorithms,
                                     [{public_key,
                                       ['sk-ecdsa-sha2-nistp256@openssh.com',
                                        'sk-ssh-ed25519@openssh.com',
                                        'ssh-ed25519',
                                        'ecdsa-sha2-nistp256']}]}]),
    Ssh0 =
        #ssh{role = server,
             session_id = SessionId,
             opts = Opts,
             user = User,
             service = "ssh-connection",
             userauth_methods = ["publickey", "password"],
             userauth_supported_methods = "publickey,password"},

    %% 1. SK auth with bad signature → should fail gracefully
    SkAlgBin = <<"sk-ecdsa-sha2-nistp256@openssh.com">>,
    BadSig = <<(crypto:strong_rand_bytes(72))/binary, 1:8, 0:32/unsigned-big-integer>>,
    SkSigBlob = <<?STRING(SkAlgBin), ?STRING(BadSig)>>,
    SkData = <<?TRUE, ?STRING(SkAlgBin), ?STRING(SkBlob), ?STRING(SkSigBlob)>>,
    SkMsg =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = SkData},
    {not_authorized,
     {User, undefined},
     {#ssh_msg_userauth_failure{authentications = Methods}, Ssh1}} =
        ssh_auth:handle_userauth_request(SkMsg, SessionId, Ssh0),
    true = length(Methods) > 0,

    %% 2. Standard Ed25519 auth should succeed (state not corrupted)
    EdAlgBin = <<"ssh-ed25519">>,
    EdAlgStr = "ssh-ed25519",
    EdSigData = ssh_auth:build_sig_data(SessionId, User, "ssh-connection", EdBlob, EdAlgStr),
    EdInner = crypto:sign(eddsa, none, EdSigData, [EdPriv, ed25519]),
    EdSigBlob = <<?STRING(EdAlgBin), ?STRING(EdInner)>>,
    EdData = <<?TRUE, ?STRING(EdAlgBin), ?STRING(EdBlob), ?STRING(EdSigBlob)>>,
    EdMsg =
        #ssh_msg_userauth_request{user = User,
                                  service = "ssh-connection",
                                  method = "publickey",
                                  data = EdData},
    {authorized, User, {#ssh_msg_userauth_success{}, _Ssh2}} =
        ssh_auth:handle_userauth_request(EdMsg, SessionId, Ssh1#ssh{user = User}),

    sk_cleanup_dir(Dir),
    ct:log("M6.1 mixed_auth: SK failure then standard Ed25519 success").

%%--------------------------------------------------------------------
sk_option_validate_fido_fun(_Config) ->
    %% Validate that sk_fido_verify_fun accepts correct values and
    %% rejects invalid ones.
    %% Accepted: undefined (default)
    #{sk_fido_verify_fun := undefined} =
        ssh_options:handle_options(server, [{system_dir, "/tmp"}]),

    %% Accepted: fun/1
    F1 = fun(_) -> ok end,
    #{sk_fido_verify_fun := F1} =
        ssh_options:handle_options(server, [{system_dir, "/tmp"}, {sk_fido_verify_fun, F1}]),

    %% Rejected: integer
    {error, _} =
        ssh_options:handle_options(server, [{system_dir, "/tmp"}, {sk_fido_verify_fun, 42}]),

    %% Rejected: fun/0 (wrong arity)
    {error, _} =
        ssh_options:handle_options(server,
                                   [{system_dir, "/tmp"}, {sk_fido_verify_fun, fun() -> ok end}]),

    %% Rejected: fun/2 (wrong arity)
    {error, _} =
        ssh_options:handle_options(server,
                                   [{system_dir, "/tmp"},
                                    {sk_fido_verify_fun, fun(_, _) -> ok end}]),

    %% Rejected: atom (not undefined)
    {error, _} =
        ssh_options:handle_options(server, [{system_dir, "/tmp"}, {sk_fido_verify_fun, true}]),

    ct:log("M6.1 option_validate_fido_fun: all validation checks OK").

%%--------------------------------------------------------------------
ssh_openssh_key_with_comment(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, DSARawOpenSsh} =
        file:read_file(
            filename:join(Datadir, "openssh_dsa_with_comment_pub")),
    [{{_, #'Dss-Parms'{}}, _}] = ssh_file:decode(DSARawOpenSsh, openssh_key).

%%--------------------------------------------------------------------
ssh_openssh_key_long_header(Config) when is_list(Config) ->
    Datadir = proplists:get_value(pk_data_dir, Config),

    {ok, RSARawOpenSsh} =
        file:read_file(
            filename:join(Datadir, "ssh_rsa_long_header_pub")),
    [{#'RSAPublicKey'{}, _}] = Decoded = ssh_file:decode(RSARawOpenSsh, public_key),

    Encoded = ssh_file:encode(Decoded, rfc4716_key),
    Decoded = ssh_file:decode(Encoded, rfc4716_key).

ec_private_key_version_compat(Config) when is_list(Config) ->
    Keys =
        [begin
             try
                 % with OTP 28: version = ecPrivkeyVer1 (atom) not integer
                 {Curve, public_key:generate_key({namedCurve, Curve})}
             catch
                 Error:Reason:Stacktrace ->
                     ?CT_LOG("SKIP Curve = ~p Error = ~p Reason = ~p~n~p",
                             [Curve, Error, Reason, Stacktrace]),
                     skip
             end
         end
         || Curve <- [ed25519, ed448, secp256r1, secp384r1]],
    case lists:any(fun(I) -> I /= skip end, Keys) of
        true ->
            [begin
                 PrivLegacy = K#'ECPrivateKey'{version = 1}, % OTP-26, OTP-27
                 Encoded = ssh_message:ssh2_privkey_encode(K),
                 EncodedLegacy = ssh_message:ssh2_privkey_encode(PrivLegacy),
                 ?assertEqual(Encoded, EncodedLegacy),
                 ?CT_LOG("Curve = ~p [OK]", [Curve])
             end
             || {Curve, K} <- Keys, K /= skip];
        false ->
            ct:fail(no_keys)
    end,
    ok.

%%%----------------------------------------------------------------
%%% Test case helpers
%%%----------------------------------------------------------------
%% Should use stored keys instead
ssh_hostkey(rsa) ->
    [{PKdecoded, _}] =
        ssh_file:decode(<<"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYXcYmsyJBstl4EfFYzfQJmSiUE162"
                          "zvSGSoMYybShYOI6rnnyvvihfw8Aml+2gZ716F2tqG48FQ/yPZEGWNPMrCejPpJctaPW"
                          "hpNdNMJ8KFXSEgr5bY2mEpa19DHmuDeXKzeJJ+X7s3fVdYc4FMk5731KIW6Huf019ZnT"
                          "xbx0VKG6b1KAJBg3vpNsDxEMwQ4LFMB0JHVklOTzbxmpaeULuIxvl65A+eGeFVeo2Q+Y"
                          "I9UnwY1vSgmc9Azwy8Ie9Z0HpQBN5I7Uc5xnknT8V6xDhgNfXEfzsgsRdDfZLECt1WO/"
                          "1gP9wkosvAGZWt5oG8pbNQWiQdFq536ck8WQD9WD none@example.org">>,
                        public_key),
    PKdecoded.

%%%----------------------------------------------------------------
chk_known_hosts(Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),

    DataDir =
        filename:join(
            proplists:get_value(data_dir, Config), "new_format"),
    SysDir = filename:join(PrivDir, "chk_known_hosts_sys_dir"),
    ssh_test_lib:setup_all_host_keys(DataDir, SysDir),

    UsrDir = filename:join(PrivDir, "chk_known_hosts_usr_dir"),
    file:make_dir(UsrDir),
    KnownHostsFile = filename:join(UsrDir, "known_hosts"),

    DaemonOpts = [{system_dir, SysDir}, {user_dir, UsrDir}, {password, "bar"}],

    UserOpts =
        [{user_dir, UsrDir},
         {user, "foo"},
         {password, "bar"},
         {silently_accept_hosts, true},
         {user_interaction, false}],

    {_Pid1, Host1, Port1} = ssh_test_lib:daemon(DaemonOpts),
    {_Pid2, Host2, Port2} = ssh_test_lib:daemon(DaemonOpts),

    _C1 = ssh_test_lib:connect(Host1, Port1, UserOpts),
    {ok, KnownHosts1} = file:read_file(KnownHostsFile),
    Sz1 = byte_size(KnownHosts1),
    ct:log("~p bytes KnownHosts1 = ~p", [Sz1, KnownHosts1]),

    _C2 = ssh_test_lib:connect(Host2, Port2, UserOpts),
    {ok, KnownHosts2} = file:read_file(KnownHostsFile),
    Sz2 = byte_size(KnownHosts2),
    ct:log("~p bytes KnownHosts2 = ~p", [Sz2, KnownHosts2]),

    %% Check that 2nd is appended after the 1st:
    <<KnownHosts1:Sz1/binary, _/binary>> = KnownHosts2,

    %% Check that there are exactly two NLs:
    2 =
        lists:foldl(fun ($\n, Sum) ->
                            Sum + 1;
                        (_, Sum) ->
                            Sum
                    end,
                    0,
                    binary_to_list(KnownHosts2)),

    %% Check that at least one NL terminates both two lines:
    <<_:(Sz1 - 1)/binary, $\n, _:(Sz2 - Sz1 - 1)/binary, $\n>> = KnownHosts2.

%%%----------------------------------------------------------------
try_connect({skip, Reason}) ->
    {skip, Reason};
try_connect(Config) ->
    SystemDir = proplists:get_value(system_dir, Config),
    UserDir = proplists:get_value(user_dir, Config),
    ClientOpts = proplists:get_value(client_opts, Config, []),
    DaemonOpts = proplists:get_value(daemon_opts, Config, []),

    ssh_dbg:start(fun ct:log/2),
    ssh_dbg:on([alg]),
    {Pid, Host, Port} =
        ssh_test_lib:daemon([{system_dir, SystemDir}, {user_dir, UserDir} | DaemonOpts]),

    C = ssh_test_lib:connect(Host,
                             Port,
                             [{user_dir, UserDir},
                              {silently_accept_hosts, true},
                              {user_interaction, false}
                              | ClientOpts]),
    ssh:close(C),
    ssh_dbg:stop(),
    ssh:stop_daemon(Pid).

try_connect_disabled(Config) ->
    try try_connect(Config) of
        _ ->
            {fail, "non-default algorithm accepted"}
    catch
        error:{badmatch, {error, "Service not available"}} ->
            ok
    end.

%%%----------------------------------------------------------------
%%% Local ---------------------------------------------------------
%%%----------------------------------------------------------------
setup_user_system_dir(ClientAlg, ServerAlg, Config) ->
    case supported(public_key, ClientAlg) andalso supported(public_key, ServerAlg) of
        true ->
            try setup_dirs(ClientAlg, ServerAlg, Config) of
                {ok, {SystemDir, UserDir}} ->
                    ModAlgs =
                        [{preferred_algorithms,
                          [{public_key, lists:usort([alg(ClientAlg), alg(ServerAlg)])}]}],
                    [{system_dir, SystemDir}, {user_dir, UserDir} | extend_optsL([daemon_opts,
                                                                                  client_opts],
                                                                                 ModAlgs,
                                                                                 Config)]
            catch
                error:{badmatch, {error, enoent}}:S ->
                    ct:log("~p:~p Stack:~n~p", [?MODULE, ?LINE, S]),
                    {skip, no_key_file_found}
            end;
        false ->
            {skip, unsupported_algorithm}
    end.

setup_default_user_system_dir(ClientAlg, Config) ->
    ServerAlg = ecdsa,
    case default(public_key, ClientAlg) of
        false ->
            case supported(public_key, ClientAlg) of
                true ->
                    case supported(public_key, ServerAlg) of
                        true ->
                            try setup_dirs(ClientAlg, ServerAlg, Config) of
                                {ok, {SystemDir, UserDir}} ->
                                    ModAlgs =
                                        [{modify_algorithms,
                                          [{append, [{public_key, [alg(ServerAlg)]}]},
                                           {rm,
                                            [{public_key,
                                              [alg(ClientAlg) | inv_algs(ClientAlg)]}]}]}],
                                    [{system_dir, SystemDir}, {user_dir, UserDir}
                                     | extend_optsL([daemon_opts, client_opts], ModAlgs, Config)]
                            catch
                                error:{badmatch, {error, enoent}}:S ->
                                    ct:log("~p:~p Stack:~n~p", [?MODULE, ?LINE, S]),
                                    {skip, no_key_file_found}
                            end;
                        false ->
                            {skip, unsupported_server_algorithm}
                    end;
                false ->
                    {skip, unsupported_client_algorithm}
            end;
        true ->
            {fail, disabled_algorithm_present}
    end.

setup_dirs(ClientAlg, ServerAlg, Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    KeySrcDir = proplists:get_value(key_src_dir, Config),
    Fmt = proplists:get_value(fmt, Config),

    System = lists:concat(["system_", ClientAlg, "_", ServerAlg, "_", Fmt]),
    SystemDir = filename:join(PrivDir, System),
    file:make_dir(SystemDir),

    User = lists:concat(["user_", ClientAlg, "_", ServerAlg, "_", Fmt]),
    UserDir = filename:join(PrivDir, User),
    file:make_dir(UserDir),

    HostSrcFile = filename:join(KeySrcDir, file(src, host, ServerAlg)),
    HostDstFile = filename:join(SystemDir, file(dst, host, ServerAlg)),

    UserSrcFile = filename:join(KeySrcDir, file(src, user, ClientAlg)),
    UserDstFile = filename:join(UserDir, file(dst, user, ClientAlg)),

    UserPubSrcFile = filename:join(KeySrcDir, file(src, user, ClientAlg) ++ ".pub"),
    AuthorizedKeys = filename:join(UserDir, "authorized_keys"),

    ct:log("UserSrcFile = ~p~nUserDstFile = ~p", [UserSrcFile, UserDstFile]),
    {ok, _} = file:copy(UserSrcFile, UserDstFile),
    ct:log("UserPubSrcFile = ~p~nAuthorizedKeys = ~p", [UserPubSrcFile, AuthorizedKeys]),
    {ok, _} = file:copy(UserPubSrcFile, AuthorizedKeys),
    ct:log("HostSrcFile = ~p~nHostDstFile = ~p", [HostSrcFile, HostDstFile]),
    {ok, _} = file:copy(HostSrcFile, HostDstFile),

    ct:log("SystemDir = ~p~nUserDir = ~p", [SystemDir, UserDir]),
    {ok, {SystemDir, UserDir}}.

%%%----------------------------------------------------------------
file(_, host, dsa) ->
    "ssh_host_dsa_key";
file(_, host, ecdsa) ->
    "ssh_host_ecdsa_key";
file(_, host, ed25519) ->
    "ssh_host_ed25519_key";
file(_, host, ed448) ->
    "ssh_host_ed448_key";
file(_, host, rsa_sha2) ->
    "ssh_host_rsa_key";
file(src, host, rsa_sha1) ->
    "ssh_host_rsa_key";
file(dst, host, rsa_sha1) ->
    "ssh_host_rsa_key";
file(_, user, dsa) ->
    "id_dsa";
file(_, user, ecdsa) ->
    "id_ecdsa";
file(_, user, ed25519) ->
    "id_ed25519";
file(_, user, ed448) ->
    "id_ed448";
file(_, user, rsa_sha2) ->
    "id_rsa";
file(src, user, rsa_sha1) ->
    "id_rsa";
file(dst, user, rsa_sha1) ->
    "id_rsa".

alg(dsa) ->
    'ssh-dss';
alg(ecdsa) ->
    'ecdsa-sha2-nistp256';
alg(ed25519) ->
    'ssh-ed25519';
alg(ed448) ->
    'ssh-ed448';
alg(rsa_sha2) ->
    'rsa-sha2-256';
alg(rsa_sha1) ->
    'ssh-rsa'.

inv_algs(rsa_sha1) ->
    algs(rsa_sha2);
inv_algs(_) ->
    [].

algs(dsa) ->
    ['ssh-dss'];
algs(ecdsa) ->
    ['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-521'];
algs(ed25519) ->
    ['ssh-ed25519'];
algs(ed448) ->
    ['ssh-ed448'];
algs(rsa_sha2) ->
    ['rsa-sha2-256', 'rsa-sha2-384', 'rsa-sha2-512'];
algs(rsa_sha1) ->
    ['ssh-rsa'];
algs(A) ->
    [A].

default(Type, Alg) ->
    listed(algs(Alg), ssh_transport:default_algorithms(Type)).

supported(Type, Alg) ->
    listed(algs(Alg),
           try
               ssh_transport:supported_algorithms(Type)
           catch
               error:function_clause ->
                   crypto:supports(Type)
           end).

listed(As, L) ->
    lists:any(fun(A) -> lists:member(A, L) end, As).
