#!/bin/sh
# Start command of the integration sshd container (see Dockerfile). The
# per-run host key, user CA and authorized_keys were copied in with
# `docker cp` before the start; fix their ownership and modes for
# StrictModes, validate the configuration and run sshd in the foreground.
set -eu

keys=/etc/ssh/ssh-native-it
authorized=/home/paratix/.ssh/authorized_keys

chown root:root "$keys/host_ed25519" "$keys/user_ca.pub"
chmod 0600 "$keys/host_ed25519"
chmod 0644 "$keys/user_ca.pub"
chown paratix:paratix "$authorized"
chmod 0600 "$authorized"

/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
