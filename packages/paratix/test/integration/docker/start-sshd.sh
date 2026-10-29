#!/bin/bash
set -eu

mkdir -p /run/sshd
pids=()
cleanup() {
  kill "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 1' TERM INT

for config in /etc/ssh/sshd_config /etc/ssh/sshd_config.*; do
  [ -f "$config" ] || continue
  /usr/sbin/sshd -D -e -f "$config" &
  pids+=("$!")
done

# Any daemon ending, including exit zero, invalidates the whole fixture.
wait -n "${pids[@]}" || true
exit 1
