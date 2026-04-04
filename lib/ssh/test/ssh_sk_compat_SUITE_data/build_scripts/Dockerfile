# %CopyrightBegin%
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright Ericsson AB 2025. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# %CopyrightEnd%
#
# Docker image for OpenSSH with sk-dummy.so FIDO middleware.
#
# This image builds OpenSSH from source with the sk-dummy.so shared
# library that implements the FIDO/U2F security key middleware API
# entirely in software (no hardware token required). This enables
# end-to-end integration testing of SK key types:
#
#   - sk-ecdsa-sha2-nistp256@openssh.com
#   - sk-ssh-ed25519@openssh.com
#
# The sk-dummy.so library is used by setting the SSH_SK_PROVIDER
# environment variable before invoking ssh-keygen or ssh:
#
#   SSH_SK_PROVIDER=/buildroot/ssh/lib/sk-dummy.so \
#       ssh-keygen -t ecdsa-sk -f /tmp/id_ecdsa_sk -N "" -C "test"
#
# See OpenSSH PROTOCOL.u2f and regress/misc/sk-dummy/sk-dummy.c for
# details on the dummy middleware implementation.

FROM ubuntu:22.04

ARG OPENSSH_VERSION=9.9p1

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies.
# Note: we do NOT install libfido2-dev here.  sk-dummy.so only needs
# libcrypto (from libssl-dev) and the OpenSSH sk-api.h header.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        zlib1g-dev \
        libssl-dev \
        libpam0g-dev \
        wget \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /buildroot

# ---------- Build OpenSSH ----------
# SK key types (sk-ecdsa-sha2-nistp256, sk-ssh-ed25519) are supported by
# default in OpenSSH >= 8.2.  We do NOT use --with-security-key-builtin
# because that requires a working libfido2 shared library at configure
# time.  Instead we build sk-dummy.so as an external middleware that is
# loaded at runtime via the SSH_SK_PROVIDER environment variable.
RUN wget -q "https://ftp.eu.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" \
        -O openssh.tar.gz \
    && tar xf openssh.tar.gz \
    && cd "openssh-${OPENSSH_VERSION}" \
    && ./configure \
            --prefix=/buildroot/ssh \
            --with-pam \
            --without-pie \
    && make -j"$(nproc)" \
    && make install \
    && echo "Built OpenSSH ${OPENSSH_VERSION}"

# ---------- Build sk-dummy.so ----------
# Use the top-level OpenSSH Makefile's SK_DUMMY_LIBRARY target.  It
# handles all the complexity: recompiling ed25519.c/hash.c with -fPIC,
# linking the openbsd-compat library, and resolving all internal symbols
# (crypto_sign_ed25519, arc4random_buf, etc.).  This is far more
# reliable than trying to replicate the build by hand.
RUN cd "openssh-${OPENSSH_VERSION}" \
    && make regress/misc/sk-dummy/sk-dummy.so \
    && mkdir -p /buildroot/ssh/lib \
    && cp regress/misc/sk-dummy/sk-dummy.so /buildroot/ssh/lib/sk-dummy.so \
    && echo "Built sk-dummy.so successfully"

# Verify sk-dummy.so was built and all symbols resolve
RUN ls -la /buildroot/ssh/lib/sk-dummy.so \
    && ldd /buildroot/ssh/lib/sk-dummy.so \
    && echo "sk-dummy.so dependencies OK"

# Clean up source trees to reduce image size
RUN rm -rf /buildroot/openssh-* /buildroot/openssh.tar.gz

# Create privilege separation directory and user for sshd
RUN mkdir -p /var/empty \
    && chmod 755 /var/empty \
    && (getent group sshd > /dev/null || groupadd -r sshd) \
    && (getent passwd sshd > /dev/null || useradd -r -g sshd -d /var/empty -s /bin/false sshd)

# Create test user with a known password for password-based auth
RUN useradd -m -s /bin/bash sshtester \
    && echo 'sshtester:foobar' | chpasswd

# Install runtime packages needed for testing
RUN apt-get update && apt-get install -y --no-install-recommends \
        sshpass \
        iputils-ping \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Configure sshd: enable PAM + pubkey + SK algorithms
RUN cat >> /buildroot/ssh/etc/sshd_config <<'SSHD_CONF'
UsePAM yes
PasswordAuthentication yes
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms +sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519@openssh.com
AllowUsers sshtester
AuthorizedKeysFile .ssh/authorized_keys
LogLevel DEBUG
UseDNS no
SSHD_CONF

# Generate host keys — standard host keys suffice since SK is for user
# authentication only; host keys use standard algorithms.
# Note: ssh-keygen -A without -f uses the --prefix path from configure.
RUN mkdir -p /buildroot/ssh/etc \
    && /buildroot/ssh/bin/ssh-keygen -A

# Pre-generate SK test keys using sk-dummy.so.
# These will be available inside the container for test use.
RUN mkdir -p /home/sshtester/.ssh \
    && chmod 700 /home/sshtester/.ssh \
    && SSH_SK_PROVIDER=/buildroot/ssh/lib/sk-dummy.so \
       /buildroot/ssh/bin/ssh-keygen -t ecdsa-sk \
           -f /home/sshtester/.ssh/id_ecdsa_sk \
           -N "" -C "ecdsa-sk test key" \
    && SSH_SK_PROVIDER=/buildroot/ssh/lib/sk-dummy.so \
       /buildroot/ssh/bin/ssh-keygen -t ed25519-sk \
           -f /home/sshtester/.ssh/id_ed25519_sk \
           -N "" -C "ed25519-sk test key" \
    && cat /home/sshtester/.ssh/id_ecdsa_sk.pub \
           /home/sshtester/.ssh/id_ed25519_sk.pub \
       > /home/sshtester/.ssh/authorized_keys \
    && chmod 600 /home/sshtester/.ssh/authorized_keys \
    && chmod 600 /home/sshtester/.ssh/id_ecdsa_sk \
    && chmod 600 /home/sshtester/.ssh/id_ed25519_sk \
    && chown -R sshtester:sshtester /home/sshtester/.ssh

# Expose the sk-dummy.so path for convenience
ENV SSH_SK_PROVIDER=/buildroot/ssh/lib/sk-dummy.so

# Verify the build
RUN /buildroot/ssh/bin/ssh -V \
    && ls -la /buildroot/ssh/lib/sk-dummy.so \
    && echo "=== ECDSA-SK public key ===" \
    && cat /home/sshtester/.ssh/id_ecdsa_sk.pub \
    && echo "=== Ed25519-SK public key ===" \
    && cat /home/sshtester/.ssh/id_ed25519_sk.pub

EXPOSE 1234

# Run sshd in foreground on port 1234 (matching ssh_compat_SUITE convention).
# -e sends log output to stderr for easy debugging with docker logs.
CMD ["/buildroot/ssh/sbin/sshd", "-D", "-p", "1234", "-e"]
