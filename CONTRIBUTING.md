# Contributing

## Before you start

To report a security vulnerability, follow the process in [SECURITY.md](./SECURITY.md) rather than opening a public issue.

Bug reports and feature requests go through [GitHub Issues](https://github.com/sebastian-software/paratix/issues).

## Development setup

**Requirements**

- Node.js `>=24.0.0`
- pnpm — the exact version is pinned in the `packageManager` field (`pnpm@11.5.3`). Run `corepack enable`
  once and Corepack will activate the right version automatically.

**Clone and install**

```bash
git clone https://github.com/sebastian-software/paratix.git
cd paratix
pnpm install
```

## Monorepo structure

| Package                   | Description                         |
| ------------------------- | ----------------------------------- |
| `packages/paratix`        | CLI and TypeScript API              |
| `packages/create-paratix` | Project scaffold (`create-paratix`) |

## Running checks

`pnpm agent:check` is the single command to run before committing. It covers:

| Step         | Command                        |
| ------------ | ------------------------------ |
| Lint         | `pnpm lint` (oxlint + eslint)  |
| Format check | `pnpm format:check` (Prettier) |
| Type check   | `pnpm typecheck`               |
| Build        | `pnpm build`                   |
| Unit tests   | `pnpm test`                    |

```bash
pnpm agent:check
```

**Integration tests** connect to a real SSH target and require Docker:

```bash
pnpm test:integration
```

To run both in sequence:

```bash
pnpm agent:check:integration
```

Auto-fix formatting with:

```bash
pnpm format
```

## Authoring guidance

For Paratix-specific API patterns and common mistakes, read
[`packages/paratix/llm-guide.md`](./packages/paratix/llm-guide.md).

If you use an AI assistant or agent for code changes, point it at [`AGENTS.md`](./AGENTS.md) first — it
covers the project conventions that matter most for automated tooling.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and
[release-please](https://github.com/googleapis/release-please) for automated versioning.

| Prefix      | When to use                        |
| ----------- | ---------------------------------- |
| `feat:`     | New feature                        |
| `fix:`      | Bug fix                            |
| `docs:`     | Documentation only                 |
| `chore:`    | Build, deps, tooling               |
| `refactor:` | Code change without fix or feature |
| `test:`     | Adding or updating tests           |

Breaking changes: add `!` after the prefix (`feat!:`) or include `BREAKING CHANGE:` in the commit footer.

## Pull requests

- Link the related GitHub issue in the PR description.
- Keep changes focused — one concern per PR.
- `pnpm agent:check` must pass before requesting review.
