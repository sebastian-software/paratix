# Plan 0054: rsync Session Host-Key Trust Reuse

## Context

`rsync.sync()` starts an external SSH process and previously rebuilt its host-key trust
only from local SSH options such as `StrictHostKeyChecking`, private key and agent socket.
When the active Paratix SSH session had already verified a fresh host via
`ssh.expectedHostFingerprint` or `ssh.expectedHostPublicKey`, the rsync subprocess still
depended on the local `known_hosts` file and could fail despite an already trusted session.

## Decision

The SSH layer now exports the effectively verified host public key of the active session
via `getConnectionInfo()`, but only when the session was accepted through a real verifier
path such as:

- `strictHostKeyChecking: "yes"`
- `strictHostKeyChecking: "accept-new"`
- `strictHostKeyChecking: "no"` combined with `expectedHostFingerprint` or
  `expectedHostPublicKey`

`rsync.sync()` uses that verified key to create a temporary local `known_hosts` file for
the external rsync SSH transport and forces:

- `UserKnownHostsFile=<tempfile>`
- `GlobalKnownHostsFile=/dev/null`
- `StrictHostKeyChecking=yes`

This removes the dependency on local `known_hosts` state without weakening host-key
verification.

## Scope

- `packages/paratix/src/types.ts`
- `packages/paratix/src/ssh.ts`
- `packages/paratix/src/modules/rsync.ts`
- `packages/paratix/src/modules/rsync.ts`
- `packages/paratix/test/ssh.test.ts`
- `packages/paratix/test/modules/rsync.test.ts`
- `packages/paratix/llm-guide.md`

## Validation

- verifier-backed SSH sessions expose `verifiedHostPublicKey`
- non-verified `strictHostKeyChecking: "no"` sessions do not expose it
- `rsync.sync()` writes a temporary `known_hosts` file for verified session keys
- rsync transport does not depend on local `known_hosts` when a verified session key exists
- `pnpm agent:check`
