# 0071 - `when` host-state guards and `ufw.disabled()`

## Summary

Extend Paratix with declarative host-state guards on top of the existing `when(...)` builtin and add a dedicated `ufw.disabled()` module.

## Motivation

- Playbooks should stay declarative.
- Common host-state checks should not require shell-heavy string conditions.
- Disabling UFW should be idempotent and safe even when the `ufw` package is not installed.

## Decision

- Keep the existing `when(condition, ...modules)` API.
- Extend `when` with explicit host-state guard helpers:
  - `packageInstalled` / `packageAbsent`
  - `commandExists` / `commandMissing`
  - `fileExists` / `fileMissing`
  - `pathExists` / `pathMissing`
  - `symlinkExists` / `symlinkMissing`
  - `socketExists` / `socketMissing`
- Add `ufw.disabled()` as a first-class UFW module.

## Semantics

- Guards are scope-local conditional wrappers, not a new orchestration layer.
- When a guard condition is not met, inner modules are skipped cleanly.
- Filesystem guards are typed:
  - `file*` for regular files
  - `path*` for directories
  - `symlink*` for symlinks
  - `socket*` for Unix sockets
- `ufw.disabled()` treats a missing `ufw` package as already satisfied.

## Validation

- Added unit coverage for `ufw.disabled()`.
- Added unit coverage for all new `when.*` host-state guard variants.
- Validated with `pnpm agent:check`.
