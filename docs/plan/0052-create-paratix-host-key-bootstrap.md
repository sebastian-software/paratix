# Plan 0052: create-paratix Host-Key Bootstrap

## Context

`create-paratix` scaffolded a `server.ts` without any explicit host-key bootstrap strategy.
Paratix itself defaults to strict host-key checking, so the first `apply:dry` against a fresh
host could fail immediately unless the user had already prepared `known_hosts` or manually
edited the generated file.

## Decision

The scaffold now generates an explicit transitional host-key bootstrap:

- `strictHostKeyChecking: "accept-new"` is included by default in generated `server.ts`
- commented placeholders for `expectedHostFingerprint` and `expectedHostPublicKey` are shown
  directly next to it
- comments in the template make it explicit that `accept-new` is for the first verified
  connection only and should then be replaced by pinned host-key trust

This keeps the generated project directly usable on fresh hosts while still making the secure
long-term configuration obvious in the scaffold itself.

## Scope

- `packages/create-paratix/src/index.ts`
- `packages/create-paratix/README.md`
- `packages/create-paratix/test/index.test.ts`

## Validation

- generated hardened-admin template contains explicit host-key bootstrap settings
- generated bootstrap-root template contains the same explicit host-key bootstrap settings
- README documents the transition from `accept-new` to pinned host-key trust
- `pnpm agent:check`
