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

ARG BASE_IMAGE=ubuntu:22.04

FROM ${BASE_IMAGE} AS builder

ARG OPENSSH_VERSION=9.6p1
ARG OPENSSL_VERSION=3.2.1

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        zlib1g-dev \
        libpam0g-dev \
        wget \
        ca-certificates \
        pkg-config \
        autoconf \
        automake \
        libtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /buildroot

# ---------- Build OpenSSL ----------
RUN wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" \
        -O openssl.tar.gz \
    && tar xf openssl.tar.gz \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./config --prefix=/buildroot/ssl \
                --openssldir=/buildroot/ssl \
                shared \
                no-tests \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd /buildroot \
    && rm -rf "openssl-${OPENSSL_VERSION}" openssl.tar.gz

# ---------- Build OpenSSH ----------
RUN wget -q "https://ftp.eu.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" \
        -O openssh.tar.gz \
    && tar xf openssh.tar.gz \
    && cd "openssh-${OPENSSH_VERSION}" \
    && ./configure \
            --prefix=/buildroot/ssh \
            --with-ssl-dir=/buildroot/ssl \
            --with-pam \
            --without-pie \
            --with-security-key-builtin \
            LDFLAGS="-Wl,-R/buildroot/ssl/lib" \
    && make -j"$(nproc)" \
    && make install \
    && echo "Built OpenSSH ${OPENSSH_VERSION} with OpenSSL ${OPENSSL_VERSION}"

# ---------- Build sk-dummy.so ----------
# The sk-dummy middleware is in the regress/misc/sk-dummy/ directory of
# the OpenSSH source tree. It implements the sk-api.h interface using
# software crypto only (no hardware authenticator required).
RUN cd "openssh-${OPENSSH_VERSION}" \
    && if [ -d regress/misc/sk-dummy ]; then \
           cd regress/misc/sk-dummy \
           && if [ -f Makefile ]; then \
                  make clean 2>/dev/null; true; \
              fi \
           && cc -shared -fPIC -Wall \
                  -I../../.. \
                  -I/buildroot/ssl/include \
                  -o sk-dummy.so \
                  sk-dummy.c \
                  -L/buildroot/ssl/lib \
                  -Wl,-R/buildroot/ssl/lib \
                  -lcrypto \
           && cp sk-dummy.so /buildroot/ssh/lib/sk-dummy.so \
           && echo "Built sk-dummy.so successfully"; \
       else \
           echo "ERROR: sk-dummy source not found" && exit 1; \
       fi

# Clean up source trees to reduce image size
RUN rm -rf /buildroot/openssh-* /buildroot/openssh.tar.gz

# ---------- Runtime image ----------
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g \
        libpam0g \
        sshpass \
        iputils-ping \
        net-tools \
        passwd \
    && rm -rf /var/lib/apt/lists/*

# Copy built artifacts from builder stage
COPY --from=builder /buildroot/ssl /buildroot/ssl
COPY --from=builder /buildroot/ssh /buildroot/ssh

# Configure the runtime linker to find our custom OpenSSL
RUN echo "/buildroot/ssl/lib" > /etc/ld.so.conf.d/buildroot-ssl.conf \
    && ldconfig

# Create privilege separation directory and user for sshd
RUN mkdir -p /var/empty \
    && chmod 755 /var/empty \
    && groupadd -r sshd 2>/dev/null || true \
    && useradd -r -g sshd -d /var/empty -s /bin/false sshd 2>/dev/null || true

# Create a test user with a known password for password-based auth
RUN useradd -m -s /bin/bash sshtester \
    && echo 'sshtester:foobar' | chpasswd

# Configure sshd: enable PAM + pubkey + SK algorithms
RUN cat >> /buildroot/ssh/etc/sshd_config <<'SSHD_CONF'
UsePAM yes
PasswordAuthentication yes
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms +sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519@openssh.com
AuthorizedKeysFile .ssh/authorized_keys
LogLevel DEBUG2
SSHD_CONF

# Generate host keys (including SK types are not needed for host keys,
# standard host keys suffice since SK is for user authentication)
RUN /buildroot/ssh/bin/ssh-keygen -A

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

# Run sshd in foreground on port 1234 (matching ssh_compat_SUITE convention)
CMD ["/buildroot/ssh/sbin/sshd", "-D", "-p", "1234", "-e"]
