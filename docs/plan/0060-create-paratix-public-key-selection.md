# Plan 0060: create-paratix Public Key Selection

## Goal

Offer existing public keys from `~/.ssh` during `create-paratix` scaffolding so the generated
`server.ts` can embed a real bootstrap admin key instead of always starting with a placeholder.

## Decision

- Keep the placeholder as the safe fallback.
- Offer a clear interactive choice:
  - use a local public key from `~/.ssh`
  - keep the placeholder and paste a key manually later
- If multiple `.pub` files exist, let the operator choose via the existing arrow-key prompt UI.

## Scope

- `packages/create-paratix/src/index.ts`
- `packages/create-paratix/src/publicKeySelection.ts`
- `packages/create-paratix/src/templates.ts`
- `packages/create-paratix/test/index.test.ts`
- `packages/create-paratix/README.md`

## Validation

- unit tests for placeholder fallback, multi-key selection, and no-key fallback
- `pnpm agent:check`
