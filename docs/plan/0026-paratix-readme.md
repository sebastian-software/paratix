# 0026 — Paratix README

## Requirement

Create a user-facing README.md for the `paratix` npm package, written in English, targeting library users who install and use paratix to configure servers.

## Architecture Decisions

- **Single file**: README.md in `packages/paratix/` — standard npm convention.
- **Scope**: Covers all public API from `"paratix"` and `"paratix/modules"`, but intentionally shorter than the full `llm-guide.md`. The README is an entry point; the llm-guide and type definitions provide deeper reference.
- **Structure**: 10 sections progressing from overview → getting started → concepts → reference → advanced.

## Affected Files

- `packages/paratix/README.md` (new file, ~350 lines)

## Implementation Details

### Sections

1. **Title & badges** — npm version, license, node engine
2. **Overview** — 2-paragraph positioning (what, why, vs Ansible)
3. **Getting started** — scaffold with create-paratix, minimal playbook, run/dry-run
4. **Core concepts** — playbook, module, recipe, signals, environment, templates
5. **CLI reference** — `paratix apply` with all flags from `cli.ts`
6. **Module reference** — all 22 namespaces grouped by category with method lists
7. **Custom modules** — check/apply pattern, code example with explicit return types
8. **SshConnection API** — 10 primary methods + note about 5 advanced methods
9. **Built-in helpers** — assert, when, debug, fail, pause, shellQuote, NEEDS_APPLY
10. **License** — MIT

### Review Findings

| ID    | Severity | Description                                                 | Status                                                       |
| ----- | -------- | ----------------------------------------------------------- | ------------------------------------------------------------ | ------ |
| R-001 | Wichtig  | SshConnection table missing 5 advanced methods              | Fixed — added note referencing type definitions              |
| R-002 | Hinweis  | CLI --reconnect-timeout default (300s CLI vs 120s internal) | No action — README documents CLI context correctly           |
| R-003 | Hinweis  | recipe missing from built-in helpers table                  | Not implemented — recipe has dedicated Core Concepts section |
| R-004 | Hinweis  | Verified: all 22 module namespaces correct                  | N/A — validation pass                                        |
| R-005 | Wichtig  | Custom module check() missing explicit return type          | Fixed — added `Promise<"needs-apply"                         | "ok">` |

## Validation

- `pnpm agent:check`: Pre-existing lint errors in test files (not caused by README). No new issues introduced.
- All code examples verified against actual source exports.
