# 0072 - Swap module for file-backed swap and tuning

## Summary

Add a dedicated `swap` module to Paratix for common swap provisioning and swap-related kernel tuning.

## Motivation

- Swap setup is a common VPS hardening and baseline task.
- Today users would have to compose shell commands, file edits, `mkswap`, `swapon`, and sysctl tuning manually.
- A first-class module keeps playbooks declarative and idempotent.

## Decision

- Introduce `swap.file(...)` for file-backed swap management.
- Support both `present` and `absent` lifecycle states.
- Add two common tuning helpers:
  - `swap.swappiness(...)`
  - `swap.vfsCachePressure(...)`
- Keep V1 intentionally focused:
  - file-backed swap only
  - no zram support
  - no partition-based swap management

## Implementation

- `packages/paratix/src/modules/swap.ts`
  - public module API and sysctl-based tuning wrappers
- `packages/paratix/src/modules/swapHelpers.ts`
  - internal swap file orchestration helpers
- `packages/paratix/src/modules/index.ts`
  - exports `swap`
- `packages/paratix/test/modules/swap.test.ts`
  - regression coverage for check/apply/absent/tuning wrapper paths
- `packages/paratix/llm-guide.md`
  - import list and module reference updated
- `packages/paratix/README.md`
  - user-facing feature and usage note updated

## Validation

- Targeted tests for `swap` pass.
- TypeScript check passes.
- Full validation passes via `pnpm agent:check`.
