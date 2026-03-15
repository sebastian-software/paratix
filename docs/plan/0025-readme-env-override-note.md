# 0025 — Add env override note to create-paratix README

## Requirement

Add a note to `packages/create-paratix/README.md` explaining that env values defined in `server()` override CLI flags, so secrets and overridable values should not be set there.

## Background

The `initializeEnvironment()` function in `packages/paratix/src/runner.ts` merges environment values in this order (last wins):

1. `--env-file <path>`
2. `--env <key=value>` CLI flags
3. `definition.env` from `server()`

Because `server({ env })` has the highest priority, values defined there cannot be overridden at runtime via CLI flags or `.env` files. This is a common source of confusion — users may put secrets in `server({ env })` thinking they can override them later, but they cannot.

## Changes

### `packages/create-paratix/README.md`

Added a blockquote note after the existing merge-order list (line 167) with three key points:

1. Values in `server({ env })` cannot be overridden from the CLI
2. Secrets and per-run values should go into `.env` files or `--env` flags
3. The `env` field in `server()` should be reserved for static defaults

## Review

- Accuracy: Confirmed against `runner.ts:58-72` — merge order is correct
- Clarity: Note is structured as fact → consequence → recommendation
- Tone: Matches the README's concise, imperative style
- Placement: Directly after the merge-order list it refers to
- No critical or important findings
