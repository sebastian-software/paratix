#!/bin/sh
set -eu

# A fixture adapter, never installed by product code. Reject every operation
# except the actual service lookup, merged unit read and confirmed reload.
case "$*" in
  'cat ssh.service'|'cat ssh')
    printf '[Service]\nExecStart=/usr/sbin/sshd -D -E /run/main-sshd.log\nExecReload=/bin/kill -HUP $MAINPID\n'
    exit 0 ;;
  'show --property=CanReload --value ssh') test ! -f /run/no-reload || { printf 'no\n'; exit 0; }; printf 'yes\n'; exit 0 ;;
  'is-active --quiet ssh')
    main_pid=$(cat /run/recorded-main-pid)
    test "$(cat /run/main-sshd.pid)" = "$main_pid" && kill -0 "$main_pid"
    exit $? ;;
  'reload ssh') ;;
  *) printf 'Unsupported fixture systemctl command: %s\n' "$*" >&2; exit 64 ;;
esac

if test -f /run/fail-reload-once; then
  rm /run/fail-reload-once
  printf 'Injected reload failure\n' >&2
  exit 1
fi
if test -f /run/fail-all-reloads; then
  printf 'Injected persistent reload failure\n' >&2
  exit 1
fi
main_pid=$(cat /run/recorded-main-pid)
test "$(cat /run/main-sshd.pid)" = "$main_pid"
test "$(readlink /proc/"$main_pid"/exe)" = /usr/sbin/sshd
kill -0 "$main_pid"
before=$(grep -c 'Received SIGHUP; restarting' /run/main-sshd.log || true)
listening_before=$(grep -c 'Server listening on' /run/main-sshd.log || true)
/usr/sbin/sshd -t
kill -HUP "$main_pid"
attempt=0
while test "$attempt" -lt 100; do
  after=$(grep -c 'Received SIGHUP; restarting' /run/main-sshd.log || true)
  listening_after=$(grep -c 'Server listening on' /run/main-sshd.log || true)
  if test "$after" -gt "$before" && test "$listening_after" -gt "$listening_before" && test "$(cat /run/main-sshd.pid)" = "$main_pid"; then
    kill -0 "$main_pid"
    ca=absent
    test ! -e /etc/ssh/trusted_user_ca_keys || ca=present
    printf '%s %s\n' "$main_pid" "$ca" >> /run/confirmed-reloads
    /usr/sbin/sshd -T > /run/last-confirmed-configuration
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 0.02
done
printf 'Main daemon did not confirm SIGHUP\n' >&2
exit 1
