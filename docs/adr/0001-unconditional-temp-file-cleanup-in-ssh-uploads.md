# ADR-0001: Unconditional temp file cleanup in SSH uploads

**Status:** Accepted
**Date:** 2026-03-19
**Context:** /refactor - design review of `uploadFile`/`writeFile`

## Context

The `uploadFile` (ssh.ts:296-314) and `writeFile` (ssh.ts:332-366) methods use an
atomic-write pattern: content is written to a temporary file and moved to its destination with
`mv`. The `finally` block runs `rm -f` on the temporary file regardless of whether `mv`
succeeded.

A refactoring proposal suggested introducing a `moved` flag and running `rm -f` only when
`mv` had not succeeded (the moved-flag pattern). This would avoid the redundant `rm -f` call
after a successful `mv`.

## Decision

Keep the current behavior: unconditional `rm -f` in the `finally` block.

## Rationale

- **Harmless no-op:** After a successful `mv`, the temporary file no longer exists. `rm -f`
  does not return an error for a nonexistent file; the call is a no-op.
- **Robust cleanup guarantee:** The `finally` block ensures that the temporary file is cleaned
  up in every failure case, including errors in `sftpUpload`, `chmod`, or `mv`. A `moved` flag
  would add complexity without improving the behavior.
- **Simplicity:** The unconditional pattern is easier to read and maintain. A `moved` flag
  would have to be set correctly and would introduce another potential source of errors.
- **No performance impact:** A single `rm -f` call on a nonexistent file has no measurable
  performance impact.

## Source

- **Finding:** uploadFile/writeFile finally-block cleanup
- **Severity:** Note
- **Files:** packages/paratix/src/ssh.ts:296-314, packages/paratix/src/ssh.ts:332-366
