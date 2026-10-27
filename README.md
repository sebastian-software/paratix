# Paratix

[GitHub](https://github.com/sebastian-software/paratix)

Paratix is an idempotent server automation tool for people who want the control of code without the overhead of a larger infrastructure platform. You describe the desired state of a VPS in TypeScript, run it over SSH, and Paratix makes only the changes that are actually needed.

It is designed for operators, developers, and small teams who want reliable server setup with a modern developer experience. Playbooks are regular `.ts` files, so you get type safety, refactoring support, editor tooling, and a workflow that fits naturally into a JavaScript or TypeScript stack.

If you already know tools like Ansible, the core idea will feel familiar. The difference is that Paratix focuses on a compact TypeScript-first workflow for SSH-based VPS management, with explicit bootstrap support, resilient reconnect handling, and readable run output.

## Features

- **Idempotent by default**: every module checks current state before it changes anything.
- **TypeScript-native workflow**: write real `.ts` playbooks with types, imports, conditions, and editor support.
- **SSH-aware orchestration**: Paratix reconnects across SSH port changes and reboots when modules require it.
- **Practical server hardening**: firewall, SSH, sysctl, service, package, file, and user management are built in.
- **Readable execution model**: recipes, signals, and checkpoints keep larger playbooks structured and predictable.
- **Bootstrap support for real servers**: scaffold a hardened first-run flow and continue from a dedicated admin user.

## Prerequisites

- Node.js `>=24.0.0`
- pnpm 12, or pnpm 11.28.6 or newer (the repo pins the exact version in the `packageManager` field and a global pnpm switches to it automatically; see [pnpm installation](https://pnpm.io/installation))

## Usage

For most users, the fastest way to start is the scaffold:

```bash
pnpm create paratix my-server
cd my-server
pnpm apply:first-run:dry
pnpm apply:first-run
pnpm apply:dry
pnpm apply
```

The scaffold gives you a ready-to-edit `server.ts`, a `files/` directory for templates, and a project setup that runs directly with `tsx`. The first run is designed for bootstrapping and hardening a fresh server; later runs continue on the hardened baseline.

If you want to start from the package directly, install `paratix` and write a playbook like this:

```typescript
import { server } from "paratix"
import { hostname, package as pkg, service } from "paratix/modules"

export default server({
  name: "web-01",
  host: "10.0.0.1",
  ssh: {
    user: "root",
    ports: [22],
    privateKey: "~/.ssh/id_ed25519",
  },
  run: [
    hostname.set("web-01"),
    pkg.update("2026-03-01"),
    pkg.installed("nginx", "curl"),
    service.enabled("nginx"),
    service.running("nginx"),
  ],
})
```

Apply it with:

```bash
npx paratix apply server.ts
```

Useful flags:

```text
paratix apply <file> [options]

Options:
  --diff
  --dry-run
  --env <key=value>
  --env-file <path>
  --filter <names>
  --first-run
  --reconnect-timeout <seconds>
  --verbose
```

`--reconnect-timeout <seconds>` controls how long Paratix keeps retrying the SSH connection after a module forces it to drop. Reboots (`system.reboot`) get a 300 second reconnect window by default so slow-booting VPS hosts still reconnect, while SSH port changes use a shorter default. The retry count follows the time window instead of a fixed attempt cap, so the window is never truncated. Override the default (up to 86400 seconds) for exceptionally slow reboots.

## Packages

This repository contains two user-facing packages:

| Package                                     | Purpose                                                          |
| ------------------------------------------- | ---------------------------------------------------------------- |
| [paratix](./packages/paratix)               | The CLI and TypeScript API for writing and applying playbooks    |
| [create-paratix](./packages/create-paratix) | The project scaffold for bootstrapping a new Paratix server repo |

If you are starting on GitHub, use this README as the overview and then jump into the package README that matches your entry point:

- [packages/paratix/README.md](./packages/paratix/README.md)
- [packages/create-paratix/README.md](./packages/create-paratix/README.md)

## Documentation

- [TypeScript API, module, and agent reference](./packages/paratix/llm-guide.md) — the current normative reference
- [User-guide overview](./docs/user-guide/README.md) — current user documentation, including [troubleshooting](./docs/user-guide/troubleshooting.md), [tool comparison](./docs/user-guide/comparison.md), and [migration notes](./docs/user-guide/migration.md)
- [`docs/adr/`](./docs/adr/) — durable architecture decision records
- [`docs/plan/`](./docs/plan/) — time-bound implementation plans, including completed work; not a current product reference
- `docs/review/` — historical review reports when present
- [`docs/review-areas.md`](./docs/review-areas.md) — the current internal review scope
- [`docs/module.md`](./docs/module.md) and [`docs/initialbeschreibung.md`](./docs/initialbeschreibung.md) — historical design documents

## Vitest dependency compatibility in CI

`pnpm check:vitest` checks resolved, installed Vitest tools in every workspace importer,
including the root, `packages/*`, and `website`. `pnpm agent:check` runs it first in the
existing `CI` workflow's required `check` job, after `pnpm install --frozen-lockfile`.
A mismatch exits with status 1 and identifies the importer and incompatible peer.
Ordinary tests and a frozen install alone do not establish peer compatibility.

The supported input is this repository's pnpm 12 workspace with its isolated,
symlinked `node_modules` layout and Node.js 24 or newer. Use the pinned package
manager from `package.json`. The checker reads installed package manifests after
installation; it does not parse the pnpm 12 lockfile's two YAML documents. The
frozen install in CI connects those installed files to the committed lockfile.
It uses `pnpm --recursive list --depth -1 --json` to discover all importers and
checks declared `vitest`, coverage V8/Istanbul, UI, and browser packages
(`@vitest/browser`, `browser-playwright`, `browser-preview`, `browser-webdriverio`).
Their applicable family peer requirements are checked with SemVer against both
direct tools used together and their resolved pnpm peer contexts. Different
compatible contexts may use different versions. An absent optional peer is allowed;
`@vitest/eslint-plugin` is independently versioned and is excluded. Missing declared
links, invalid metadata, unsupported peer ranges, and filesystem errors fail the
check. Other package managers and nonstandard layouts are outside this check's
supported scope; adapt and verify the checker before changing that input contract.
This is a repository quality check within the existing CI trust model.

Renovate's regular Vitest grouping does not guarantee inclusion of non-vulnerable
companions in a security PR. Its vulnerability-alert defaults use `groupName: null`
and `rangeStrategy: update-lockfile`. If such a PR fails the compatibility check:

1. Review the advisory and its fixed Vitest version.
2. Update only the required installed companions in that same security PR.
3. Regenerate the lockfile with the pinned pnpm version, avoiding unrelated updates.
4. Run `pnpm check:vitest` and `pnpm agent:check`, then wait for required CI checks.

This manual repair can delay a security update; automatic or zero-delay repair is
not promised. See the [shared Renovate preset guidance](https://github.com/sebastian-software/renovate-config#vitest-grouping-and-verification)
for the grouping and security-update policy. The regression fixtures simulate
installed package trees, including an incomplete security update and its paired
repair; they do not prove deployed CI enforcement or reproduce a real advisory.

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
