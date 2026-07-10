# Paratix

[Homepage](https://paratix.oss.sebastian-software.com) · [GitHub](https://github.com/sebastian-software/paratix)

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
- pnpm 11 or newer (the repo pins the exact version in the `packageManager` field; use Corepack to activate it automatically)

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

## User Guide

- [TypeScript API and Module Reference](./packages/paratix/llm-guide.md)
- [User-guide overview](./docs/user-guide/README.md)
- [Troubleshooting](./docs/user-guide/troubleshooting.md)
- [Choosing between Paratix, Ansible, and pyinfra](./docs/user-guide/comparison.md)
- [Migration notes](./docs/user-guide/migration.md)

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
