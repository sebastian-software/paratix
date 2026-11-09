#!/bin/sh
# Forced command of the restricted login: names its caller (key or Match),
# the requested command and the PTY state.
printf 'forced %s via %s\n' "${SSH_ORIGINAL_COMMAND:-none}" "${1:-none}"
if tty -s; then printf 'tty\n'; else printf 'no-tty\n'; fi
