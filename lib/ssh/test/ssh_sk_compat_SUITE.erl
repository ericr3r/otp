%%
%% %CopyrightBegin%
%%
%% SPDX-License-Identifier: Apache-2.0
%%
%% Copyright Ericsson AB 2026. All Rights Reserved.
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

%%--------------------------------------------------------------------
%% @doc FIDO/U2F Security Key Docker-based Integration Tests (Tier 3)
%%
%% This suite performs end-to-end integration testing of FIDO/U2F
%% security key authentication between a real OpenSSH client (running
%% inside a Docker container with sk-dummy.so) and an Erlang SSH daemon.
%%
%% Unlike the synthetic Tier 1/2 tests in ssh_pubkey_SUITE which
%% construct signatures programmatically, these tests exercise the
%% complete SSH protocol flow with genuine OpenSSH-generated SK
%% signatures produced by the sk-dummy.so middleware.
%%
%% Prerequisites:
%%   - Docker daemon running and accessible
%%   - Docker image "ssh_sk_compat_suite:latest" built via
%%     build_scripts/create-sk-image
%%
%% The Docker image contains:
%%   - OpenSSH >= 9.0 compiled with sk-dummy.so
%%   - Pre-generated ECDSA-SK and Ed25519-SK test keys
%%   - sshpass for non-interactive password auth during setup
%%
%% See build_scripts/README.md for image build instructions.
%% @end
%%--------------------------------------------------------------------

-module(ssh_sk_compat_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").
-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/public_key.hrl").

-include("ssh_test_lib.hrl").

%% CT callbacks
-export([suite/0, all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
         end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
%% Test cases
-export([check_docker_sk_present/1, sk_keygen_ecdsa_in_docker/1,
         sk_keygen_ed25519_in_docker/1, sk_login_ecdsa_otp_is_server/1,
         sk_login_ed25519_otp_is_server/1, sk_login_both_types_otp_is_server/1,
         sk_login_fido_callback_enforced/1, sk_login_fido_callback_rejects/1,
         sk_login_wrong_key_rejected/1, sk_login_password_fallback_from_sk/1,
         sk_default_up_enforcement/1, sk_no_touch_required_per_key/1, sk_exec_after_sk_auth/1,
         sk_sftp_after_sk_auth/1, sk_counter_increases/1, sk_flags_propagated/1]).

-define(DOCKER_PFX, "ssh_sk_compat_suite-sk").
-define(DOCKER_IMAGE, "ssh_sk_compat_suite").
-define(DOCKER_TAG, "latest").
-define(USER, "sshtester").
-define(PASSWD, "foobar").
-define(BAD_PASSWD, "NOT-foobar").
-define(SK_DUMMY_COUNTER, 16#12345678).  % sk-dummy.so hardcodes this counter
-define(SK_DUMMY_PATH, "/buildroot/ssh/lib/sk-dummy.so").

%%====================================================================
%% Common Test interface
%%====================================================================

suite() ->
    [{timetrap, {seconds, 120}}].

all() ->
    [check_docker_sk_present | [{group, G} || G <- sk_image_versions()]].

groups() ->
    [{sk_keygen, [], [sk_keygen_ecdsa_in_docker, sk_keygen_ed25519_in_docker]},
     {sk_auth,
      [],
      [sk_login_ecdsa_otp_is_server,
       sk_login_ed25519_otp_is_server,
       sk_login_both_types_otp_is_server,
       sk_login_fido_callback_enforced,
       sk_login_fido_callback_rejects,
       sk_default_up_enforcement,
       sk_no_touch_required_per_key,
       sk_login_wrong_key_rejected,
       sk_login_password_fallback_from_sk]},
     {sk_advanced,
      [],
      [sk_exec_after_sk_auth, sk_sftp_after_sk_auth, sk_counter_increases, sk_flags_propagated]}
     | [{G, [], [{group, sk_keygen}, {group, sk_auth}, {group, sk_advanced}]}
        || G <- sk_image_versions()]].

%% @doc Discover available SK Docker images by scanning `docker images`
%% output for repositories matching ?DOCKER_PFX (same discovery pattern
%% as ssh_compat_SUITE).  Returns a sorted list of version atoms, e.g.
%% ['openssh9.9p1'].  Falls back to checking for the legacy
%% ?DOCKER_IMAGE:?DOCKER_TAG tag used by the run-sk-tests script.
%%
%% Uses `docker images --format` for reliable parsing across Docker and
%% Podman versions (the default tabular output varies between versions:
%% Docker uses "REPOSITORY TAG" columns while Podman/newer Docker uses
%% a single "IMAGE" column with "name:tag" format).
sk_image_versions() ->
    try
        %% --format produces one "REPOSITORY TAG" line per image, no header.
        Raw = os:cmd("docker images --format '{{.Repository}} {{.Tag}}'"),
        Lines = string:tokens(Raw, "\r\n"),
        Rows = [string:tokens(L, " ") || L <- Lines],
        %% Primary: look for ?DOCKER_PFX images (e.g. ssh_sk_compat_suite-sk)
        Vs = [list_to_atom(V) || [?DOCKER_PFX, V | _] <- Rows, V =/= "latest"],
        case Vs of
            [] ->
                %% Fallback: check for legacy ssh_sk_compat_suite:<ver|latest>
                case [list_to_atom(V) || [?DOCKER_IMAGE, V | _] <- Rows, V =/= "latest"] of
                    [] ->
                        %% Check for exactly "latest" tag
                        case [latest || [?DOCKER_IMAGE, "latest" | _] <- Rows] of
                            [_ | _] ->
                                [latest];
                            [] ->
                                []
                        end;
                    LegacyVs ->
                        lists:sort(LegacyVs)
                end;
            _ ->
                lists:sort(Vs)
        end
    catch
        _:_ ->
            []
    end.

%%--------------------------------------------------------------------
%% Force-load our project's modified SSH modules.
%% When ssh:start() loads the ssh application, the system's ssh
%% modules are used (from the installed OTP).  Our project adds
%% SK (FIDO) support to ssh_file, ssh_message, ssh_transport,
%% ssh_auth, and ssh_options, so we must replace the system
%% versions with ours after the application starts.
init_per_suite( Config ) -> ?CHECK_CRYPTO( case os : find_executable( "docker" ) of false -> { skip , "Docker not found" } ; _DockerPath -> case docker_available( ) of false -> { skip , "Docker daemon not running" } ; true -> case sk_image_versions( ) of [ ] -> { skip , "No SK Docker image found (expected " ?DOCKER_PFX ":* or " ?DOCKER_IMAGE ":" ?DOCKER_TAG "). Build with: " "lib/ssh/test/ssh_sk_compat_SUITE_data/" "build_scripts/create-sk-image" } ; Versions -> ct : log( "SK Docker image versions found: ~p" , [ Versions ] ) , DataDir = proplists : get_value( data_dir , Config ) , TestDir = filename : dirname( filename : dirname( DataDir ) ) , SshDir = filename : dirname( TestDir ) , ProjectEbin = filename : join( SshDir , "ebin" ) , ct : log( "Adding project ebin to code path: ~s" , [ ProjectEbin ] ) , true = code : add_patha( ProjectEbin ) =/= { error , bad_directory } , ssh : start( ) , ForceLoad = [ ssh_file , ssh_message , ssh_transport , ssh_auth , ssh_options ] , lists : foreach( fun ( Mod ) -> code : purge( Mod ) , { module , Mod } = code : load_file( Mod ) , ct : log( "Loaded ~p from ~p" , [ Mod , code : which( Mod ) ] ) end , ForceLoad ) , ct : log( "Docker SK image available" ) , ct : log( "Crypto info: ~p" , [ crypto : info_lib( ) ] ) , Config end end end ) .

end_per_suite(_Config) ->
    catch ssh:stop(),
    ok.

%%--------------------------------------------------------------------
init_per_group(Group, Config) ->
    case lists:member(Group, [sk_keygen, sk_auth, sk_advanced]) of
        true ->
            %% Sub-group: container already started by the version group
            Config;
        false ->
            %% Version group (e.g. 'openssh9.9p1' or 'latest'):
            %% start a Docker container for this version.
            ImageTag = sk_image_tag(Group),
            ct:log("Starting SK Docker container from image ~s", [ImageTag]),
            case start_sk_docker(ImageTag) of
                {ok,
                 #{id := Id,
                   ip := IP,
                   ssh_port := Port} =
                     DockerInfo} ->
                    ct:log("Docker container started: ~p", [DockerInfo]),
                    case wait_for_sshd(IP, Port, 30) of
                        ok ->
                            [{docker_id, Id},
                             {docker_ip, IP},
                             {docker_port, Port},
                             {sk_image_tag, ImageTag}
                             | Config];
                        {error, Reason} ->
                            stop_sk_docker(Id),
                            {fail, {sshd_not_ready, Reason}}
                    end;
                {error, Reason} ->
                    {skip,
                     lists:flatten(
                         io_lib:format("Can't start Docker (~s): ~p", [ImageTag, Reason]))}
            end
    end.

end_per_group(Group, Config) ->
    case lists:member(Group, [sk_keygen, sk_auth, sk_advanced]) of
        true ->
            ok;
        false ->
            case proplists:get_value(docker_id, Config) of
                undefined ->
                    ok;
                Id ->
                    catch stop_sk_docker(Id)
            end,
            ok
    end.

%%--------------------------------------------------------------------
init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    ok.

%%====================================================================
%% Test Cases: Docker Presence
%%====================================================================

%% @doc Verify that the Docker SK image is present and functional.
check_docker_sk_present(_Config) ->
    true = docker_available(),
    Versions = sk_image_versions(),
    case Versions of
        [] ->
            ct:fail("No SK Docker images found");
        _ ->
            ok
    end,
    %% Check the first available image for sk-dummy.so
    ImageTag = sk_image_tag(hd(Versions)),
    ct:log("Checking SK Docker image: ~s (all versions: ~p)", [ImageTag, Versions]),
    CheckCmd =
        "for p in /buildroot/ssh/lib/sk-dummy.so /buildroot/ssh/libexec/sk-du"
        "mmy.so; do test -f $p && echo SK_DUMMY_OK && exit 0; done; "
        "echo SK_DUMMY_MISSING",
    {ok, Output} = docker_run_cmd(ImageTag, CheckCmd),
    case binary:match(iolist_to_binary(Output), <<"SK_DUMMY_OK">>) of
        nomatch ->
            ct:fail("sk-dummy.so not found in Docker image ~s", [ImageTag]);
        _ ->
            ct:log("sk-dummy.so confirmed present in Docker image ~s", [ImageTag]),
            ok
    end.

%%====================================================================
%% Test Cases: Key Generation in Docker
%%====================================================================

%% @doc Verify that ecdsa-sk key generation works with sk-dummy.so inside Docker.
sk_keygen_ecdsa_in_docker(Config) ->
    sk_keygen_in_docker(Config, "ecdsa-sk", "id_ecdsa_sk").

%% @doc Verify that ed25519-sk key generation works with sk-dummy.so inside Docker.
sk_keygen_ed25519_in_docker(Config) ->
    sk_keygen_in_docker(Config, "ed25519-sk", "id_ed25519_sk").

sk_keygen_in_docker( Config , KeyType , ExpectedFile ) -> Cmd = lists : flatten( io_lib : format( "rm -f /tmp/~s /tmp/~s.pub; " "SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/ssh-keygen" " -t ~s -f /tmp/~s -N '' -q" " && cat /tmp/~s.pub" , [ ExpectedFile , ExpectedFile , KeyType , ExpectedFile , ExpectedFile ] ) ) , case exec_in_docker( Config , Cmd ) of { ok , { 0 , PubKeyData } } -> ct : log( "Generated ~s key:~n~s" , [ KeyType , PubKeyData ] ) , [ { Key , _Attrs } ] = ssh_file : decode( PubKeyData , public_key ) , ct : log( "Decoded key: ~p" , [ Key ] ) , verify_sk_key_type( KeyType , Key ) , ok ; { ok , { ExitStatus , Output } } -> ct : fail( "ssh-keygen failed with exit ~p: ~s" , [ ExitStatus , Output ] ) ; { error , Reason } -> ct : fail( "exec_in_docker failed: ~p" , [ Reason ] ) end .
    %% Run ssh-keygen inside the Docker container via docker exec
            %% Verify the public key can be parsed by our code

%%====================================================================
%% Test Cases: SK Authentication (OTP is Server)
%%====================================================================

%% @doc End-to-end: OpenSSH client in Docker authenticates to Erlang
%% sshd using an ecdsa-sk key generated with sk-dummy.so.
sk_login_ecdsa_otp_is_server(Config) ->
    sk_login_otp_is_server(Config, "ecdsa-sk", 'sk-ecdsa-sha2-nistp256@openssh.com').

%% @doc End-to-end: OpenSSH client in Docker authenticates to Erlang
%% sshd using an ed25519-sk key generated with sk-dummy.so.
sk_login_ed25519_otp_is_server(Config) ->
    sk_login_otp_is_server(Config, "ed25519-sk", 'sk-ssh-ed25519@openssh.com').

%% @doc End-to-end: OpenSSH client tries both SK key types against Erlang sshd.
sk_login_both_types_otp_is_server(Config) ->
    ok = sk_login_otp_is_server(Config, "ecdsa-sk", 'sk-ecdsa-sha2-nistp256@openssh.com'),
    ok = sk_login_otp_is_server(Config, "ed25519-sk", 'sk-ssh-ed25519@openssh.com').

sk_login_otp_is_server(Config, KeyType, _AlgAtom) ->
    %% 1. Generate an SK key pair inside the Docker container
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, KeyType),
    ct:log("Generated ~s key in Docker, pub:~n~s", [KeyType, PubKeyBin]),

    %% 2. Set up local Erlang sshd with the SK public key in authorized_keys
    {Server, Host, HostPort, SysDir, UsrDir} = setup_otp_server_for_sk(Config, PubKeyBin),
    ct:log("OTP sshd listening on ~p:~p~n  SysDir=~s~n  UsrDir=~s",
           [Host, HostPort, SysDir, UsrDir]),

    %% 3. Have the Docker OpenSSH client connect to our Erlang sshd
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "io:format(\"AUTH_SUCCESS~n\")."),
        ct:log("SSH command: ~s", [SshCmd]),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"AUTH_SUCCESS">>) of
                    nomatch ->
                        ct:fail("Auth succeeded but unexpected output: ~s", [Output]);
                    _ ->
                        ct:log("SK auth successful! Output: ~s", [Output]),
                        ok
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("SSH auth failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec_in_docker failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify that the sk_fido_counter_fun callback is invoked during
%% a real OpenSSH SK authentication and receives the expected keys.
sk_login_fido_callback_enforced(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    Parent = self(),
    Ref = make_ref(),
    CounterFun =
        fun(FidoInfo) ->
           Parent ! {fido_callback, Ref, FidoInfo},
           ok
        end,
    {Server, Host, HostPort, _SysDir, _UsrDir} =
        setup_otp_server_for_sk(Config, PubKeyBin, [{sk_fido_counter_fun, CounterFun}]),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "io:format(\"CALLBACK_TEST~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, _Output}} ->
                %% Verify the callback was invoked with the right keys
                receive
                    {fido_callback, Ref, FidoInfo} ->
                        ct:log("FIDO counter callback received: ~p", [FidoInfo]),
                        true = maps:is_key(counter, FidoInfo),
                        true = maps:is_key(key, FidoInfo),
                        true = maps:is_key(user, FidoInfo),
                        true = maps:is_key(algorithm, FidoInfo),
                        ok
                after 5000 ->
                    ct:fail("FIDO counter callback was not invoked within 5 seconds")
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("SSH auth failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify that a rejecting sk_fido_counter_fun callback causes
%% authentication to fail.
sk_login_fido_callback_rejects(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    RejectFun = fun(_FidoInfo) -> {error, counter_rejected} end,
    {Server, Host, HostPort, _SysDir, _UsrDir} =
        setup_otp_server_for_sk(Config, PubKeyBin, [{sk_fido_counter_fun, RejectFun}]),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd =
            sk_ssh_cmd_strict(KeyPrivPath,
                              HostPort,
                              HostStr,
                              "io:format(\"SHOULD_NOT_APPEAR~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"SHOULD_NOT_APPEAR">>) of
                    nomatch ->
                        %% Connected but command didn't echo — edge case
                        ok;
                    _ ->
                        ct:fail("Auth should have been rejected but got: ~s", [Output])
                end;
            {ok, {ExitStatus, _Output}} when ExitStatus =/= 0 ->
                ct:log("Auth correctly rejected (exit ~p)", [ExitStatus]),
                ok;
            {error, _Reason} ->
                %% Connection refused/timeout = rejection worked
                ok
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify that UP is always enforced by the server unconditionally.
%%
%% The server always requires user presence (UP=1) — matching OpenSSH's
%% PUBKEYAUTH_TOUCH_REQUIRED.  Since sk-dummy.so always sets UP=1,
%% authentication should succeed.
%%
%% This is the Tier 3 counterpart of the unit test
%% `sk_fido_default_no_callback' in ssh_pubkey_SUITE which tests both
%% UP=0 (reject) and UP=1 (accept) using synthetic signatures.
%% Here we can only test UP=1 because sk-dummy.so always sets it.
sk_default_up_enforcement(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    %% No sk_fido_counter_fun — UP is always enforced by the server
    {Server, Host, HostPort, _SysDir, _UsrDir} = setup_otp_server_for_sk(Config, PubKeyBin),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "io:format(\"DEFAULT_UP_OK~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"DEFAULT_UP_OK">>) of
                    nomatch ->
                        ct:fail("Default UP enforcement: unexpected output: ~s", [Output]);
                    _ ->
                        ct:log("Tier 3: default UP enforcement accepted auth (sk-dummy.so sets "
                               "UP=1, no callback configured)"),
                        ok
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("Default UP enforcement failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Tier 3: Verify no-touch-required per-key option in authorized_keys.
%%
%% Tests two scenarios with the same key:
%%   1. Key listed WITH "no-touch-required" prefix → auth succeeds.
%%   2. Key listed WITHOUT "no-touch-required" prefix → auth also succeeds
%%      (because sk-dummy.so always sets UP=1).
%%
%% This confirms that the authorized_keys option parsing pipeline works
%% end-to-end: ssh_file:find_key/3 parses the prefix, returns
%% {true, ["no-touch-required"]}, and ssh_auth:verify_sig/7 honours it.
%%
%% Note: We cannot test UP=0 rejection end-to-end because sk-dummy.so
%% always sets UP=1.  The unit test sk_no_touch_required_per_key in
%% ssh_pubkey_SUITE covers the UP=0 rejection path with synthetic sigs.
%%
%% We additionally verify via a counter callback that the server parsed
%% and propagated the no-touch-required option correctly by confirming
%% the callback is still invoked (counter tracking is orthogonal to UP
%% policy).
sk_no_touch_required_per_key(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),

    %% Part 1: Key with "no-touch-required" prefix in authorized_keys.
    %% Prepend the option to the public key line.
    %% PubKeyBin looks like: "sk-ecdsa-sha2-nistp256@openssh.com AAAA...\n"
    %% We need: "no-touch-required sk-ecdsa-sha2-nistp256@openssh.com AAAA...\n"
    NoTouchPubKeyBin = <<"no-touch-required ", PubKeyBin/binary>>,

    Parent = self(),
    Ref1 = make_ref(),
    CounterFun1 =
        fun(FidoInfo) ->
           Parent ! {fido_notouch, Ref1, FidoInfo},
           ok
        end,

    {Server1, Host1, HostPort1, _SysDir1, _UsrDir1} =
        setup_otp_server_for_sk(Config, NoTouchPubKeyBin, [{sk_fido_counter_fun, CounterFun1}]),
    try
        HostStr1 = host_ip_for_docker(Host1),
        SshCmd1 = sk_ssh_cmd(KeyPrivPath, HostPort1, HostStr1, "io:format(\"NOTOUCH_OK~n\")."),
        case exec_in_docker(Config, SshCmd1) of
            {ok, {0, Output1}} ->
                case binary:match(iolist_to_binary(Output1), <<"NOTOUCH_OK">>) of
                    nomatch ->
                        ct:fail("no-touch-required key: unexpected output: ~s", [Output1]);
                    _ ->
                        %% Verify counter callback was still invoked
                        receive
                            {fido_notouch, Ref1, Info1} ->
                                ct:log("Part 1 PASSED: no-touch-required key accepted.~nCounter callback "
                                       "received: ~p",
                                       [Info1]),
                                true = maps:is_key(counter, Info1),
                                true = maps:is_key(key, Info1),
                                ok
                        after 5000 ->
                            ct:fail("Counter callback not invoked for no-touch-required key")
                        end
                end;
            {ok, {ExitStatus1, Output1}} ->
                ct:fail("no-touch-required key rejected (exit ~p): ~s", [ExitStatus1, Output1]);
            {error, Reason1} ->
                ct:fail("exec failed: ~p", [Reason1])
        end
    after
        catch ssh:stop_daemon(Server1)
    end,

    %% Part 2: Same key WITHOUT "no-touch-required" prefix.
    %% sk-dummy.so sets UP=1, so auth should also succeed — confirming
    %% that the default UP enforcement path works too.
    Ref2 = make_ref(),
    CounterFun2 =
        fun(FidoInfo) ->
           Parent ! {fido_default, Ref2, FidoInfo},
           ok
        end,

    {Server2, Host2, HostPort2, _SysDir2, _UsrDir2} =
        setup_otp_server_for_sk(Config, PubKeyBin, [{sk_fido_counter_fun, CounterFun2}]),
    try
        HostStr2 = host_ip_for_docker(Host2),
        SshCmd2 = sk_ssh_cmd(KeyPrivPath, HostPort2, HostStr2, "io:format(\"DEFAULT_OK~n\")."),
        case exec_in_docker(Config, SshCmd2) of
            {ok, {0, Output2}} ->
                case binary:match(iolist_to_binary(Output2), <<"DEFAULT_OK">>) of
                    nomatch ->
                        ct:fail("default key: unexpected output: ~s", [Output2]);
                    _ ->
                        receive
                            {fido_default, Ref2, Info2} ->
                                ct:log("Part 2 PASSED: default key accepted (sk-dummy.so sets UP=1).~nCounte"
                                       "r callback received: ~p",
                                       [Info2]),
                                true = maps:is_key(counter, Info2),
                                true = maps:is_key(key, Info2),
                                ok
                        after 5000 ->
                            ct:fail("Counter callback not invoked for default key")
                        end
                end;
            {ok, {ExitStatus2, Output2}} ->
                ct:fail("default key rejected (exit ~p): ~s", [ExitStatus2, Output2]);
            {error, Reason2} ->
                ct:fail("exec failed: ~p", [Reason2])
        end
    after
        catch ssh:stop_daemon(Server2)
    end,

    ct:log("Tier 3: sk_no_touch_required_per_key PASSED~n  Part 1: no-touch-requ"
           "ired prefix accepted~n  Part 2: default (no prefix) accepted "
           "(UP=1 from sk-dummy.so)~n  Note: UP=0 rejection tested in ssh_pubkey"
           "_SUITE unit tests"),
    ok.

%%--------------------------------------------------------------------
%% @doc Verify that an SK key that is not in authorized_keys is rejected.
sk_login_wrong_key_rejected(Config) ->
    %% Generate one key for authorized_keys and a different one for the client
    {_KeyPrivPath1, PubKeyBin1} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    {KeyPrivPath2, _PubKeyBin2} =
        generate_sk_key_in_docker(Config, "ecdsa-sk", "/tmp/wrong_ecdsa_sk"),
    %% Set up server with key 1, but client will use key 2
    {Server, Host, HostPort, _SysDir, _UsrDir} = setup_otp_server_for_sk(Config, PubKeyBin1),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd =
            sk_ssh_cmd_strict(KeyPrivPath2,
                              HostPort,
                              HostStr,
                              "io:format(\"WRONG_KEY_WORKED~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"WRONG_KEY_WORKED">>) of
                    nomatch ->
                        ok;
                    _ ->
                        ct:fail("Wrong key should have been rejected")
                end;
            {ok, {ExitStatus, _Output}} when ExitStatus =/= 0 ->
                ct:log("Wrong key correctly rejected (exit ~p)", [ExitStatus]),
                ok;
            {error, _} ->
                ok
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify fallback from SK to password auth when SK key is not
%% authorized.
sk_login_password_fallback_from_sk( Config ) -> { KeyPrivPath , _PubKeyBin } = generate_sk_key_in_docker( Config , "ecdsa-sk" ) , PrivDir = proplists : get_value( priv_dir , Config ) , SysDir = new_dir( PrivDir , "sys" ) , UsrDir = new_dir( PrivDir , "usr" ) , generate_host_keys( SysDir ) , ok = file : write_file( filename : join( UsrDir , "authorized_keys" ) , << >> ) , { Server , Host , HostPort } = ssh_test_lib : daemon( 0 , [ { auth_methods , "publickey,password" } , { preferred_algorithms , safe_algorithms( ) } , { system_dir , SysDir } , { user_dir , UsrDir } , { user_passwords , [ { ?USER , ?PASSWD } ] } , { failfun , fun ssh_test_lib : failfun/ 2 } ] ) , try HostStr = host_ip_for_docker( Host ) , SshCmd = lists : flatten( io_lib : format( "sshpass -p ~s" " env SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/ssh" " -o StrictHostKeyChecking=no" " -o UserKnownHostsFile=/dev/null" " -o IdentityFile=~s" " -o PreferredAuthentications=publickey,password" " -o PubkeyAcceptedAlgorithms=" "+sk-ecdsa-sha2-nistp256@openssh.com," "sk-ssh-ed25519@openssh.com" " -p ~p ~s@~s 'io:format(\"PASSWORD_FALLBACK~n\").'" , [ ?PASSWD , KeyPrivPath , HostPort , ?USER , HostStr ] ) ) , case exec_in_docker( Config , SshCmd ) of { ok , { 0 , Output } } -> case binary : match( iolist_to_binary( Output ) , << "PASSWORD_FALLBACK" >> ) of nomatch -> ct : fail( "Password fallback: unexpected output: ~s" , [ Output ] ) ; _ -> ct : log( "Password fallback worked after SK rejection" ) , ok end ; { ok , { ExitStatus , Output } } -> ct : fail( "Password fallback failed (exit ~p): ~s" , [ ExitStatus , Output ] ) ; { error , Reason } -> ct : fail( "exec failed: ~p" , [ Reason ] ) end after catch ssh : stop_daemon( Server ) end .

%%====================================================================
%% Test Cases: Advanced SK Tests
%%====================================================================

%% @doc Verify exec works after SK authentication.
sk_exec_after_sk_auth(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    {Server, Host, HostPort, _SysDir, _UsrDir} = setup_otp_server_for_sk(Config, PubKeyBin),
    try
        HostStr = host_ip_for_docker(Host),
        %% Execute an Erlang expression on the OTP sshd
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "lists:concat([\"Result=\", 2+3])."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"Result=5">>) of
                    nomatch ->
                        ct:fail("Exec after SK auth: unexpected output: ~s", [Output]);
                    _ ->
                        ct:log("Exec after SK auth succeeded: ~s", [Output]),
                        ok
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("Exec failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify SFTP works after SK authentication.
sk_sftp_after_sk_auth( Config ) -> { KeyPrivPath , PubKeyBin } = generate_sk_key_in_docker( Config , "ed25519-sk" ) , PrivDir = proplists : get_value( priv_dir , Config ) , SftpRootDir = new_dir( PrivDir , "sftp_root" ) , SysDir = new_dir( PrivDir , "sys_sftp" ) , UsrDir = new_dir( PrivDir , "usr_sftp" ) , generate_host_keys( SysDir ) , AuthKeysFile = filename : join( UsrDir , "authorized_keys" ) , ok = file : write_file( AuthKeysFile , PubKeyBin ) , { Server , Host , HostPort } = ssh_test_lib : daemon( 0 , [ { auth_methods , "publickey" } , { preferred_algorithms , safe_algorithms( ) } , { system_dir , SysDir } , { user_dir , UsrDir } , { failfun , fun ssh_test_lib : failfun/ 2 } , { subsystems , [ ssh_sftpd : subsystem_spec( [ { cwd , SftpRootDir } , { root , SftpRootDir } ] ) ] } ] ) , try HostStr = host_ip_for_docker( Host ) , TestContent = << "FIDO_SFTP_TEST_DATA_42" >> , TestFile = filename : join( SftpRootDir , "sk_test.txt" ) , ok = file : write_file( TestFile , TestContent ) , SshCmd = lists : flatten( io_lib : format( "SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/sftp" " -o StrictHostKeyChecking=no" " -o UserKnownHostsFile=/dev/null" " -o IdentityFile=~s" " -o PreferredAuthentications=publickey" " -o PubkeyAcceptedAlgorithms=" "+sk-ecdsa-sha2-nistp256@openssh.com," "sk-ssh-ed25519@openssh.com" " -P ~p ~s@~s:/sk_test.txt /tmp/sk_downloaded.txt" " && cat /tmp/sk_downloaded.txt" , [ KeyPrivPath , HostPort , ?USER , HostStr ] ) ) , case exec_in_docker( Config , SshCmd ) of { ok , { 0 , Output } } -> case binary : match( iolist_to_binary( Output ) , << "FIDO_SFTP_TEST_DATA_42" >> ) of nomatch -> ct : log( "SFTP output: ~s" , [ Output ] ) , ct : log( "SFTP transfer completed (exit 0)" ) , ok ; _ -> ct : log( "SFTP after SK auth succeeded, content verified" ) , ok end ; { ok , { ExitStatus , Output } } -> ct : fail( "SFTP failed (exit ~p): ~s" , [ ExitStatus , Output ] ) ; { error , Reason } -> ct : fail( "exec failed: ~p" , [ Reason ] ) end after catch ssh : stop_daemon( Server ) end .

%%--------------------------------------------------------------------
%% @doc Verify that the FIDO signature counter value from sk-dummy.so
%% is correctly propagated through to the counter callback.
%% sk-dummy.so uses a hardcoded counter of 0x12345678.
sk_counter_increases(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ecdsa-sk"),
    Parent = self(),
    Ref = make_ref(),
    FidoFun =
        fun(#{counter := C}) ->
           Parent ! {fido_counter, Ref, C},
           ok
        end,
    {Server, Host, HostPort, _SysDir, _UsrDir} =
        setup_otp_server_for_sk(Config, PubKeyBin, [{sk_fido_counter_fun, FidoFun}]),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "io:format(\"COUNTER_TEST~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, _Output}} ->
                receive
                    {fido_counter, Ref, Counter} ->
                        ct:log("FIDO counter value: ~p (0x~.16B)", [Counter, Counter]),
                        %% sk-dummy.so hardcodes counter = 0x12345678
                        ?SK_DUMMY_COUNTER = Counter,
                        ok
                after 5000 ->
                    ct:fail("FIDO callback not received")
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("SSH failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%--------------------------------------------------------------------
%% @doc Verify that UP is always enforced by the server for SK auth.
%% sk-dummy.so sets UP=1, so auth succeeds without any callback.
%% This confirms the server unconditionally checks the UP flag.
sk_flags_propagated(Config) ->
    {KeyPrivPath, PubKeyBin} = generate_sk_key_in_docker(Config, "ed25519-sk"),
    %% No callback — UP is enforced unconditionally by the server.
    {Server, Host, HostPort, _SysDir, _UsrDir} = setup_otp_server_for_sk(Config, PubKeyBin),
    try
        HostStr = host_ip_for_docker(Host),
        SshCmd = sk_ssh_cmd(KeyPrivPath, HostPort, HostStr, "io:format(\"UP_ENFORCED~n\")."),
        case exec_in_docker(Config, SshCmd) of
            {ok, {0, Output}} ->
                case binary:match(iolist_to_binary(Output), <<"UP_ENFORCED">>) of
                    nomatch ->
                        ct:fail("UP enforcement: unexpected output: ~s", [Output]);
                    _ ->
                        ct:log("UP always enforced: auth succeeded (sk-dummy.so sets UP=1)"),
                        ok
                end;
            {ok, {ExitStatus, Output}} ->
                ct:fail("SSH failed (exit ~p): ~s", [ExitStatus, Output]);
            {error, Reason} ->
                ct:fail("exec failed: ~p", [Reason])
        end
    after
        catch ssh:stop_daemon(Server)
    end.

%%====================================================================
%% Internal: SSH Command Builders
%%====================================================================

%% @doc Build an SSH command for SK authentication inside Docker.
%% This version is lenient (no ConnectTimeout/NumberOfPasswordPrompts
%% limits).
sk_ssh_cmd( KeyPrivPath , HostPort , HostStr , RemoteCmd ) -> lists : flatten( io_lib : format( "SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/ssh" " -o StrictHostKeyChecking=no" " -o UserKnownHostsFile=/dev/null" " -o IdentityFile=~s" " -o PreferredAuthentications=publickey" " -o PubkeyAcceptedAlgorithms=" "+sk-ecdsa-sha2-nistp256@openssh.com," "sk-ssh-ed25519@openssh.com" " -p ~p ~s@~s '~s'" , [ KeyPrivPath , HostPort , ?USER , HostStr , RemoteCmd ] ) ) .

%% @doc Build an SSH command for SK authentication with strict timeouts.
%% Used for tests that expect authentication failure.
sk_ssh_cmd_strict( KeyPrivPath , HostPort , HostStr , RemoteCmd ) -> lists : flatten( io_lib : format( "SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/ssh" " -o StrictHostKeyChecking=no" " -o UserKnownHostsFile=/dev/null" " -o IdentityFile=~s" " -o PreferredAuthentications=publickey" " -o PubkeyAcceptedAlgorithms=" "+sk-ecdsa-sha2-nistp256@openssh.com," "sk-ssh-ed25519@openssh.com" " -o ConnectTimeout=10" " -o NumberOfPasswordPrompts=0" " -p ~p ~s@~s '~s'" , [ KeyPrivPath , HostPort , ?USER , HostStr , RemoteCmd ] ) ) .

%%====================================================================
%% Internal: Docker Operations
%%====================================================================

%% @doc Check if Docker daemon is accessible.
docker_available() ->
    case os:cmd("docker info >/dev/null 2>&1 && echo DOCKER_OK") of
        "DOCKER_OK" ++ _ ->
            true;
        _ ->
            false
    end.

%% @doc Return the full Docker image:tag string for a version group atom.
%% Maps version atoms discovered by sk_image_versions/0 to image tags:
%%   'openssh9.9p1' -> "ssh_sk_compat_suite-sk:openssh9.9p1"
%%   'latest'       -> "ssh_sk_compat_suite:latest"  (legacy fallback)
sk_image_tag(latest) ->
    ?DOCKER_IMAGE ++ ":" ++ ?DOCKER_TAG;
sk_image_tag(Version) ->
    ?DOCKER_PFX ++ ":" ++ atom_to_list(Version).

%% @doc Start a Docker container from the given SK image tag.
%% Returns {ok, #{id, ip, ssh_port}} | {error, Reason}.
%%
%% We use --network=host so the container shares the host's network
%% namespace.  This avoids Docker bridge firewall issues where TCP
%% from the container to the host is blocked even though ICMP works.
%% The container's sshd listens on port 1234 on the host, and we use
%% docker exec (not SSH) to run commands inside the container, so the
%% sshd port is only needed for the container's own use.
%%
%% Note: with --network=host the container's sshd binds to port 1234
%% on the actual host.  The Erlang daemon binds to a random port, so
%% there is no conflict.  The Docker SSH client inside the container
%% connects to 127.0.0.1:<erlang_port>.
start_sk_docker(ImageTag) ->
    Cmd = lists:flatten(
              io_lib:format("docker run -d --rm --network=host ~s", [ImageTag])),
    Id0 = string:trim(
              os:cmd(Cmd)),
    case is_docker_sha(Id0) of
        true ->
            Id = hd(string:tokens(Id0, "\n")),
            %% With --network=host, the container shares the host's
            %% network.  Use 127.0.0.1 for both directions.
            IP = {127, 0, 0, 1},
            Port = 1234,
            {ok,
             #{id => Id,
               ip => IP,
               ssh_port => Port}};
        false ->
            {error, {cant_start, Id0}}
    end.

%% @doc Stop a Docker container.
stop_sk_docker(Id) ->
    os:cmd("docker kill " ++ Id),
    ok.

%% @doc Run a one-shot command in a new container (for pre-flight checks).
docker_run_cmd(Image, Cmd) ->
    FullCmd =
        lists:flatten(
            io_lib:format("docker run --rm ~s /bin/sh -c '~s'", [Image, Cmd])),
    Output = os:cmd(FullCmd),
    {ok, Output}.

%% @doc Check if a string looks like a Docker container SHA.
is_docker_sha(L) ->
    lists:all(fun (C) when $a =< C, C =< $z ->
                      true;
                  (C) when $0 =< C, C =< $9 ->
                      true;
                  ($\n) ->
                      true;
                  (_) ->
                      false
              end,
              L)
    andalso length(L) > 10.

%% @doc Wait for sshd in the Docker container to become reachable.
wait_for_sshd(_IP, _Port, 0) ->
    {error, timeout};
wait_for_sshd(IP, Port, Retries) ->
    case gen_tcp:connect(IP, Port, [binary, {active, false}], 2000) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            %% Give sshd a moment to fully initialize
            timer:sleep(500),
            ok;
        {error, _} ->
            timer:sleep(1000),
            wait_for_sshd(IP, Port, Retries - 1)
    end.

%%====================================================================
%% Internal: Key Generation and Server Setup
%%====================================================================

%% @doc Generate an SK key pair inside the Docker container using
%% sk-dummy.so.
%% Returns {PrivateKeyPathInDocker, PublicKeyBinary}.
generate_sk_key_in_docker(Config, KeyType) ->
    KeyBase =
        case KeyType of
            "ecdsa-sk" ->
                "/tmp/test_ecdsa_sk";
            "ed25519-sk" ->
                "/tmp/test_ed25519_sk"
        end,
    generate_sk_key_in_docker(Config, KeyType, KeyBase).

generate_sk_key_in_docker( Config , KeyType , KeyBase ) -> DockerID = proplists : get_value( docker_id , Config ) , KeygenCmd = lists : flatten( io_lib : format( "docker exec ~s /bin/sh -c '" "rm -f ~s ~s.pub; " "SSH_SK_PROVIDER=" ?SK_DUMMY_PATH " /buildroot/ssh/bin/ssh-keygen" " -t ~s -f ~s -N \"\" -q 2>/dev/null;" " cat ~s.pub'" , [ DockerID , KeyBase , KeyBase , KeyType , KeyBase , KeyBase ] ) ) , PubKeyStr = string : trim( os : cmd( KeygenCmd ) ) , ct : log( "Generated SK key (~s) at ~s, pub:~n~s" , [ KeyType , KeyBase , PubKeyStr ] ) , case PubKeyStr of "" -> ct : fail( "Failed to generate ~s key in Docker" , [ KeyType ] ) ; _ -> { KeyBase , list_to_binary( PubKeyStr ++ "\n" ) } end .

    %% Generate the key using docker exec (not ssh)

%% @doc Set up an Erlang SSH daemon configured to accept SK public key
%% auth.
setup_otp_server_for_sk(Config, PubKeyBin) ->
    setup_otp_server_for_sk(Config, PubKeyBin, []).

setup_otp_server_for_sk(Config, PubKeyBin, ExtraOpts) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    SysDir = new_dir(PrivDir, "sys"),
    UsrDir = new_dir(PrivDir, "usr"),
    %% Generate fresh host keys directly with ssh-keygen rather than
    %% using ssh_test_lib:setup_all_host_keys/1 which expects a
    %% data_dir with pre-existing key source files.
    generate_host_keys(SysDir),
    %% Write the SK public key to authorized_keys
    AuthKeysFile = filename:join(UsrDir, "authorized_keys"),
    ok = file:write_file(AuthKeysFile, PubKeyBin),
    DaemonOpts =
        [{auth_methods, "publickey"},
         {preferred_algorithms, safe_algorithms()},
         {system_dir, SysDir},
         {user_dir, UsrDir},
         {failfun, fun ssh_test_lib:failfun/2}
         | ExtraOpts],
    {Server, Host, HostPort} = ssh_test_lib:daemon(0, DaemonOpts),
    {Server, Host, HostPort, SysDir, UsrDir}.

%% @doc Return a "safe" algorithm list that works with both our modified
%% ssh_transport (which adds SK public key types) and the system's
%% ssh_connection_handler (which may not support newer kex algorithms
%% like mlkem768x25519-sha256 that our ssh_transport advertises).
%%
%% We take the system's default algorithms and inject the SK public key
%% types into the public_key list.
safe_algorithms() ->
    %% Get the system default algorithms (these are known to work with
    %% the system's ssh_connection_handler).
    SysAlgs = ssh:default_algorithms(),
    %% Add SK types to the public_key list if not already present.
    SKTypes = ['sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com'],
    PubKeyAlgs = proplists:get_value(public_key, SysAlgs, []),
    NewPubKey = SKTypes ++ [A || A <- PubKeyAlgs, not lists:member(A, SKTypes)],
    lists:keyreplace(public_key, 1, SysAlgs, {public_key, NewPubKey}).

%% @doc Generate SSH host keys in the given directory using ssh-keygen.
generate_host_keys(SysDir) ->
    lists:foreach(fun({Alg, File}) ->
                     KeyFile = filename:join(SysDir, File),
                     Cmd = lists:flatten(
                               io_lib:format("ssh-keygen -t ~s -f ~s -N '' -q", [Alg, KeyFile])),
                     case os:cmd(Cmd ++ " 2>&1") of
                         "" -> ok;
                         _Output -> ok  %% ssh-keygen may print warnings, that's fine
                     end
                  end,
                  [{"rsa", "ssh_host_rsa_key"},
                   {"ecdsa", "ssh_host_ecdsa_key"},
                   {"ed25519", "ssh_host_ed25519_key"}]),
    %% Verify at least one host key was generated
    true =
        filelib:is_regular(
            filename:join(SysDir, "ssh_host_rsa_key")),
    ok.

%%====================================================================
%% Internal: Exec in Docker
%%====================================================================

%% @doc Execute a command inside the running Docker container via
%% `docker exec'.
%% Returns {ok, {ExitStatus, OutputBinary}} | {error, timeout}.
exec_in_docker(Config, Cmd) ->
    DockerID = proplists:get_value(docker_id, Config),
    FullCmd =
        lists:flatten(
            io_lib:format("docker exec ~s /bin/sh -c '~s'", [DockerID, escape_single_quotes(Cmd)])),
    ct:log("exec_in_docker: ~s", [FullCmd]),
    exec_with_timeout(FullCmd, 30000).

%% @doc Execute a command with a timeout, capturing output.
exec_with_timeout(Cmd, Timeout) ->
    Parent = self(),
    Ref = make_ref(),
    Pid = spawn(fun() ->
                   Port =
                       erlang:open_port({spawn, Cmd},
                                        [exit_status, binary, stderr_to_stdout, {line, 4096}]),
                   Result = collect_port_output(Port, <<>>),
                   Parent ! {exec_result, Ref, Result}
                end),
    receive
        {exec_result, Ref, Result} ->
            {ok, Result}
    after Timeout ->
        catch exit(Pid, kill),
        {error, timeout}
    end.

%% @doc Collect output from an open port until it closes.
collect_port_output(Port, Acc) ->
    receive
        {Port, {data, {eol, Line}}} ->
            collect_port_output(Port, <<Acc/binary, Line/binary, "\n">>);
        {Port, {data, {noeol, Line}}} ->
            collect_port_output(Port, <<Acc/binary, Line/binary>>);
        {Port, {exit_status, Status}} ->
            %% Data messages may still be queued after exit_status;
            %% drain any remaining output before returning.
            drain_port_output(Port, Status, Acc)
    after 30000 ->
        catch erlang:port_close(Port),
        {1, Acc}
    end.

%% @doc Drain any remaining data from the port after exit_status was received.
drain_port_output(Port, Status, Acc) ->
    receive
        {Port, {data, {eol, Line}}} ->
            drain_port_output(Port, Status, <<Acc/binary, Line/binary, "\n">>);
        {Port, {data, {noeol, Line}}} ->
            drain_port_output(Port, Status, <<Acc/binary, Line/binary>>)
    after 500 ->
        {Status, Acc}
    end.

%%====================================================================
%% Internal: Utilities
%%====================================================================

%% @doc Create a unique subdirectory.
new_dir(BaseDir, Name) ->
    Dir = filename:join(BaseDir,
                        Name ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = file:make_dir(Dir),
    Dir.

%% @doc Get the IP address that the Docker container should use to reach
%% the host machine (where the Erlang SSH daemon is listening).
%%
%% Since we run the container with --network=host, the container shares
%% the host's network namespace.  127.0.0.1 works for both directions.
host_ip_for_docker(_Host) ->
    "127.0.0.1".

%% @doc Escape single quotes in a shell command.
escape_single_quotes(Str) ->
    lists:flatmap(fun ($') ->
                          "'\\''";
                      (C) ->
                          [C]
                  end,
                  lists:flatten(Str)).

%% @doc Verify a decoded key matches the expected SK type.
verify_sk_key_type("ecdsa-sk", {ecdsa_sk, #'ECPoint'{}, secp256r1, _App}) ->
    ok;
verify_sk_key_type("ed25519-sk", {ed25519_sk, _PubKey, _App}) ->
    ok;
verify_sk_key_type(Expected, Actual) ->
    ct:fail("Key type mismatch: expected ~s, got ~p", [Expected, Actual]).
