# THROWAWAY SPIKE (issue #254): OpenSSH target for the russh binding proofs.
# Build context is the fixture directory written by generate.sh:
#   bash spike-fixture/generate.sh "$FIXTURES"
#   docker build -t paratix-spike-sshd "$FIXTURES"
FROM debian:bookworm-slim

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client coreutils \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /run/sshd /etc/ssh/spike \
  && rm -f /etc/ssh/ssh_host_*

# Password login (password + keyboard-interactive via PAM) needs a real password.
RUN useradd --create-home --shell /bin/bash paratix \
  && echo 'paratix:paratix-spike-password' | chpasswd

COPY host_ed25519 host_ed25519.pub host_ed25519-cert.pub host_ecdsa host_ecdsa.pub host_rsa host_rsa.pub user_ca.pub /etc/ssh/spike/
COPY authorized_keys /home/paratix/.ssh/authorized_keys
COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0600 /etc/ssh/spike/host_ed25519 /etc/ssh/spike/host_ecdsa /etc/ssh/spike/host_rsa \
  && chmod 0644 /etc/ssh/spike/*.pub \
  && chown -R paratix:paratix /home/paratix/.ssh \
  && chmod 0700 /home/paratix/.ssh \
  && chmod 0600 /home/paratix/.ssh/authorized_keys \
  && /usr/sbin/sshd -t

# 22: main profile; 2223: MaxSessions 1; 2224: password only; 2225: keyboard-interactive only.
EXPOSE 22 2223 2224 2225

CMD ["/usr/sbin/sshd", "-D", "-e"]
