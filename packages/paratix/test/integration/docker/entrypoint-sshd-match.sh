#!/bin/sh
set -eu

# Debian layout: the drop-in Include comes first, global directives follow it.
# A Match block that leaked out of a drop-in would make `Port`, `HostKey` and
# `PidFile` below invalid (not allowed in Match) and scope MaxAuthTries to the
# drop-in's users only.
cat > /etc/ssh/sshd_config <<'CONFIG'
Include /etc/ssh/sshd_config.d/*.conf
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/main-sshd.pid
UsePAM no
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
PermitTTY yes
X11Forwarding no
AllowUsers root deploy ops-ro
LogLevel VERBOSE
Subsystem sftp internal-sftp
Match User root
    AllowTcpForwarding yes
CONFIG
cp /etc/ssh/sshd_config /run/initial-sshd-config
/usr/sbin/sshd -t
/usr/sbin/sshd -D -E /run/main-sshd.log &
main_pid=$!
printf '%s\n' "$main_pid" > /run/recorded-main-pid
trap 'kill -TERM "$main_pid" 2>/dev/null || true' TERM INT EXIT
wait "$main_pid"
