# 0025 — Add env override note to create-paratix README

## Requirement

Add a note to `packages/create-paratix/README.md` explaining that env values defined in `server()` override CLI flags, so secrets and overridable values should not be set there.

## Background

Status: überholt. Die ursprüngliche Annahme zur Priorität von `server({ env })`
war falsch; CLI-Overrides gewinnen.

The `initializeEnvironment()` function in `packages/paratix/src/runner.ts` merges environment values in this order (last wins):

1. `--env-file <path>`
2. `definition.env` from `server()`
3. `--env <key=value>` CLI flags

Because CLI flags have the highest priority, values defined in `server({ env })` can be overridden at runtime via `--env`. `.env` files remain the lowest-priority defaults.

## Changes

### `packages/create-paratix/README.md`

Added a blockquote note after the existing merge-order list (line 167) with three key points:

1. Values in `server({ env })` can be overridden from the CLI
2. Secrets and per-run values should go into `.env` files or `--env` flags
3. The `env` field in `server()` should be reserved for static defaults

## Review

- Accuracy: Corrected against `runner.ts` — merge order is `.env` < `server({ env })` < `--env`
- Clarity: Note is structured as fact → consequence → recommendation
- Tone: Matches the README's concise, imperative style
- Placement: Directly after the merge-order list it refers to
- No critical or important findings
