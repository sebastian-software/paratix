# Plan 0053: ssh.knownHosts Non-Standard-Port Support

## Context

`ssh.knownHosts()` only supported plain host lookups and scans on the default SSH port.
That made it impossible to safely pre-provision `known_hosts` entries for hardened hosts
that expose SSH on a non-standard port such as `2222`.

Paratix already supports bracketed host keys like `[host]:port` in the lower-level
host-key verification stack, but the module API did not expose that capability.

## Decision

`ssh.knownHosts()` now accepts an optional `port`.

- `check()` uses `ssh-keygen -F '[host]:port'` for non-standard ports
- `apply()` uses `ssh-keyscan -p <port> -H <host>` for non-standard ports
- `state: "absent"` removes entries via `ssh-keygen -R '[host]:port'`
- port `22` keeps the existing unbracketed behavior for backward compatibility with
  standard `known_hosts` entries

This aligns the module with OpenSSH `known_hosts` semantics without changing the behavior
for existing port-22 playbooks.

## Scope

- `packages/paratix/src/modules/ssh.ts`
- `packages/paratix/test/modules/ssh.test.ts`
- `packages/paratix/llm-guide.md`
- `review-report-2026-03-21.md`

## Validation

- `ssh.knownHosts(..., { port: 2222 })` uses bracketed `ssh-keygen -F` lookups
- `ssh.knownHosts(..., { port: 2222 })` uses `ssh-keyscan -p 2222`
- `ssh.knownHosts(..., { port: 2222, state: "absent" })` uses bracketed `ssh-keygen -R`
- `pnpm agent:check`
