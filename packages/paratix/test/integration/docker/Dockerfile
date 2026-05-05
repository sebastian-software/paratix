FROM debian:bookworm-slim

ARG CLIENT_PUBLIC_KEY

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl openssh-server python3 sudo \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash paratix \
  && passwd -d root \
  && passwd -d paratix \
  && echo 'paratix ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/paratix \
  && chmod 0440 /etc/sudoers.d/paratix

RUN mkdir -p /home/paratix/.ssh /root/.ssh /run/sshd \
  && printf '%s\n' "$CLIENT_PUBLIC_KEY" > /home/paratix/.ssh/authorized_keys \
  && printf '%s\n' "$CLIENT_PUBLIC_KEY" > /root/.ssh/authorized_keys \
  && chown -R paratix:paratix /home/paratix/.ssh \
  && chmod 0700 /home/paratix/.ssh \
  && chmod 0700 /root/.ssh \
  && chmod 0600 /home/paratix/.ssh/authorized_keys \
  && chmod 0600 /root/.ssh/authorized_keys \
  && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
  && ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key >/dev/null \
  && ssh-keygen -t rsa -b 3072 -N '' -f /etc/ssh/ssh_host_rsa_key >/dev/null

COPY test/integration/docker/sshd_config /etc/ssh/sshd_config
COPY test/integration/docker/start-sshd.sh /usr/local/bin/start-sshd.sh

RUN chmod 0755 /usr/local/bin/start-sshd.sh

EXPOSE 22 2222

CMD ["/usr/local/bin/start-sshd.sh"]
