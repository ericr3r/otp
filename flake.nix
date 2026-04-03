{
  description = "Erlang/OTP FIDO SSH development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "otp-fido-dev";

          nativeBuildInputs = with pkgs; [
            # Bootstrap Erlang — used by otp_build to compile this OTP
            # source tree, and by ELP for editor intelligence.  After
            # ./otp_build setup -a the self-built OTP 29 in $ERL_TOP/bin
            # takes priority via the PATH ordering in shellHook below.
            erlang_28

            # Language server (successor to the archived erlang-ls).
            # Configured via the existing .elp.toml in the repo root.
            erlang-language-platform

            # Core build tools
            gnumake
            gcc
            autoconf
            automake
            libtool
            m4
            perl
            pkg-config
            git

            # OTP build dependencies
            ncurses
            openssl
            libxslt
            libxml2
            zlib

            # SSH test suite: local OpenSSH interop (ssh_to_openssh_SUITE,
            # ssh_algorithms_SUITE, ssh_connection_SUITE)
            openssh

            # SSH compat suite: Docker-based cross-version testing
            # (ssh_compat_SUITE) and optional sk-dummy.so image (Milestone 8)
            docker
            docker-compose

            # Common Test runs in a browser for result inspection
            # (release/tests/test_server/index.html)
            which
            coreutils
            findutils
            gawk
            gnused
            gnugrep
            gnutar
            gzip
            wget
            curl

            # Optional: wxWidgets for wx app (not needed for SSH tests,
            # but avoids configure warnings)
            # wxGTK32

            # Documentation tooling (Milestone 7)
            # ex_doc is fetched by otp_build download_ex_doc
          ];

          buildInputs = with pkgs; [
            ncurses
            openssl
            zlib
          ];

          shellHook = ''
            export ERL_TOP="$(pwd)"

            # After ./otp_build setup -a, prefer the self-built OTP 29
            # for running tests and ct_run.  Before that first build,
            # the nix-provided Erlang 28 is used (bootstrap + ELP).
            if [ -x "$ERL_TOP/bin/erl" ]; then
              export PATH="$ERL_TOP/bin:$PATH"
            fi

            # Point configure at nix-provided OpenSSL so crypto/ssh/ssl build
            export KERL_CONFIGURE_OPTIONS="--with-ssl=${pkgs.openssl.dev}"

            # Parallel build (adjust to your machine)
            export MAKEFLAGS="''${MAKEFLAGS:--j$(nproc)}"

            # Erlang compiler server speeds up rebuilds
            export ERLC_USE_SERVER=yes

            # Ensure the nix-provided ssh is found first for interop tests
            export SSH_BIN="${pkgs.openssh}/bin/ssh"

            # Resolve which erl is active for the status message
            _active_erl="$(command -v erl 2>/dev/null || echo "not found")"
            _active_vsn="$(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().' 2>/dev/null || echo "?")"

            echo ""
            echo "  OTP FIDO SSH dev environment"
            echo "  ERL_TOP=$ERL_TOP"
            echo "  Active erl: $_active_erl (OTP $_active_vsn)"
            echo "  Bootstrap:  ${pkgs.erlang_28}/bin/erl (OTP 28)"
            echo "  ELP:        ${pkgs.erlang-language-platform}/bin/elp"
            echo "  OpenSSL:    ${pkgs.openssl.dev}"
            echo "  OpenSSH:    ${pkgs.openssh}"
            echo ""
            echo "  Quick start:"
            echo "    ./otp_build setup -a           # configure + build OTP 29"
            echo "    (cd lib/ssh && make test)       # run all SSH tests"
            echo "    make ssh_test ARGS=\"-suite ssh_basic_SUITE\""
            echo ""
            if [ ! -x "$ERL_TOP/bin/erl" ]; then
              echo "  ⚠  Self-built OTP not found yet — using Erlang 28 bootstrap."
              echo "     Run ./otp_build setup -a to build OTP 29 from source."
              echo ""
            fi

            unset _active_erl _active_vsn
          '';
        };
      }
    );
}
