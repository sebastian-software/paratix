# 0024 — create-paratix README.md

## Requirement

Create a user-facing README.md for the `create-paratix` package that explains how to scaffold a new Paratix project and how to apply it to a server.

## Architecture Decisions

- **Location:** `packages/create-paratix/README.md` — standard npm package location
- **Audience:** End users of Paratix, not contributors
- **Language:** English
- **Scope:** Covers the full lifecycle: create → edit → apply

## Implementation

### Created Files

- `packages/create-paratix/README.md`

### README Structure

1. **Header** — one-line description with link to Paratix repo
2. **Quick Start** — 4-step guide (create, cd, edit, apply) with all package managers
3. **Project Structure** — table of scaffolded files and their purpose
4. **Writing Your Playbook** — server.ts example, key concepts (modules, recipes, signals, env)
5. **Applying to a Server** — dry-run first, then apply, CLI flags table
6. **Environment Variables** — .env setup, merge priority, template files
7. **Requirements** — Node.js >= 24
8. **License** — MIT

## Review Findings

| ID    | Severity  | Status    | Description                                                                     |
| ----- | --------- | --------- | ------------------------------------------------------------------------------- |
| R-001 | Important | Fixed     | Import mismatch — README omitted `file` and `user` from import statement        |
| R-002 | Important | Not fixed | Env merge priority is unusual (code > CLI) — accurate but potentially confusing |
| R-003 | Note      | Not fixed | Minor wording difference ("errors" vs "error") in --verbose description         |
| R-004 | Note      | Fixed     | Quick Start assumed pnpm — added npm variant                                    |
| R-005 | Note      | Fixed     | Auto-install not mentioned — added note about automatic dependency installation |

### Not Implemented

- **R-002**: The env merge priority documentation is accurate to the code. Adding a warning about it would be a design discussion, not a README fix.
- **R-003**: Trivial wording difference, not worth changing.
