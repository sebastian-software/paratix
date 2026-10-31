# OpenSSH target of the @paratix/ssh-native integration suite.
#
# The image holds no per-run key material: the build context is this
# directory (this file, sshd_config and start.sh only).
# test/integration/lib/docker-target.mjs creates the container, copies the
# per-run host key, user CA and authorized_keys into it with `docker cp`
# before it starts, and start.sh fixes their ownership and modes for
# StrictModes, validates the configuration with `sshd -t` and only then
# runs sshd. The password of `paratix` is generated per run and set through
# `docker exec ... chpasswd` (stdin) after the container started, so it is
# in neither the image nor its history.
#
# The base image is pinned to the multi-arch index digest (CI runs amd64 and
# arm64); the tag stays for readability and update tooling.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    coreutils openssh-client openssh-server procps \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /run/sshd /etc/ssh/ssh-native-it \
  && rm -f /etc/ssh/ssh_host_*

RUN useradd --create-home --shell /bin/bash paratix \
  && mkdir /home/paratix/.ssh \
  && chown paratix:paratix /home/paratix/.ssh \
  && chmod 0700 /home/paratix/.ssh

COPY sshd_config /etc/ssh/sshd_config
COPY start.sh /usr/local/bin/ssh-native-it-start
RUN chmod 0755 /usr/local/bin/ssh-native-it-start

# Profiles by port, see sshd_config.
EXPOSE 2222 2223 2224 2225

CMD ["/usr/local/bin/ssh-native-it-start"]
