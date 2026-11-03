#!/bin/sh
set -eu

# Only this main daemon reads the file managed by the modules. Root has a
# separate bootstrap identity; the non-root login has no authorized-key path.
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/main-sshd.pid
UsePAM no
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile none
AuthorizedKeysCommand none
AuthorizedPrincipalsCommand none
AllowAgentForwarding no
AllowUsers root deploy
LogLevel VERBOSE
Subsystem sftp internal-sftp
Match User root
    AuthorizedKeysFile /root/.ssh/authorized_keys
CONFIG
cp /etc/ssh/sshd_config /run/initial-sshd-config
/usr/sbin/sshd -t
/usr/sbin/sshd -D -E /run/main-sshd.log &
main_pid=$!
printf '%s\n' "$main_pid" > /run/recorded-main-pid
trap 'kill -TERM "$main_pid" 2>/dev/null || true' TERM INT EXIT
wait "$main_pid"
