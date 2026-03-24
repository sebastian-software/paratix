# Paratix

Idempotent VPS automation in TypeScript.

[![npm version](https://img.shields.io/npm/v/paratix)](https://www.npmjs.com/package/paratix)
[![license](https://img.shields.io/npm/l/paratix)](https://opensource.org/licenses/MIT)
[![node](https://img.shields.io/node/v/paratix)](https://nodejs.org/)

Paratix lets you manage Linux servers over SSH with TypeScript playbooks instead of YAML or ad-hoc shell scripts. You describe the desired end state of a machine, run the playbook, and Paratix changes only what is necessary.

It is built for developers and operators who want infrastructure automation that feels like application code: typed, reviewable, composable, and easy to keep in version control. You can start small on a single VPS and still keep a disciplined, repeatable workflow.

The result is a practical server automation tool with a compact mental model: modules check state, modules apply state, recipes group related work, and signals run only when changes actually happened.

## Features

- **Idempotent runs**: rerunning the same playbook on an already configured server is safe.
- **TypeScript authoring**: use regular `.ts` files with imports, conditions, and editor tooling.
- **Resilient SSH flow**: reconnects after reboots and SSH port changes when modules require it.
- **Structured orchestration**: recipes and signals keep service reloads and grouped changes explicit.
- **Declarative host guards**: gate modules on package, command, file, directory, symlink, or socket state without embedding shell checks in strings.
- **Strong bootstrap story**: supports explicit first-run flows and strict host-key handling.
- **Practical built-in modules**: packages, files, services, users, SSH, firewall, systemd, sysctl, swap, mount, rsync, and more.

## Getting Started

If you want the fastest path, scaffold a project first:

```bash
npm create paratix my-server
cd my-server
npm run apply:dry
npm run apply -- --first-run
npm run apply
```

If you want to install `paratix` directly:

```bash
npm install paratix
```

Create a playbook:

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

Apply it:

```bash
npx paratix apply server.ts
```

Preview changes without applying them:

```bash
npx paratix apply server.ts --dry-run
```

## How Paratix Works

### Playbooks

A playbook is a TypeScript file that default-exports `server(...)`. It defines the target host, SSH configuration, optional environment values, and an ordered list of modules to run.

### Modules

Modules are the smallest units of work. Each module checks whether its target state already exists and only applies changes when needed.

### Recipes

Recipes group related modules into a named unit. They help structure larger playbooks and keep the CLI output readable.

### Signals

Signals are deferred side effects such as `service.reload(...)` or `service.restart(...)`. They run when the surrounding scope actually changed, and can also be flushed explicitly with `signals.flush()` when you need a checkpoint inside a larger flow.

### Compose + systemd

`compose.systemd(...)` can generate a native systemd unit for Docker Compose or Podman Compose projects. By default it now starts the stack with `compose up --remove-orphans`; set `detached: true` if you explicitly want the old `-d` behaviour in the generated `ExecStart`.

### Podman Quadlets

For Podman-native services, Paratix now also includes `quadlet.container(...)`. It writes a `.container` file under `/etc/containers/systemd`, reloads systemd when the content changes, and works cleanly with `service.enabled(...)` and `service.running(...)` for the generated service.

### Guards

Paratix also supports declarative host-state guards. Use `when.packageInstalled(...)`, `when.commandExists(...)`, `when.fileExists(...)`, `when.pathExists(...)`, `when.symlinkExists(...)`, or `when.socketExists(...)` and their inverted forms to gate modules or recipes on remote host state without shell-heavy playbooks.

### Swap

Paratix can also manage file-backed swap directly. Use `swap.file(...)` to provision and persist a swap file, then tune common memory behaviour with `swap.swappiness(...)` or `swap.vfsCachePressure(...)`.

## CLI

```text
paratix apply <file> [options]

Options:
  --dry-run
  --env <key=value>
  --env-file <path>
  --first-run
  --reconnect-timeout <seconds>
  --verbose
  --version
  --help
```

`--first-run` is meant for explicit bootstrap flows where a fresh server must be hardened first and the rest of the system should only be applied later.

## Documentation

- For project scaffolding, see [`create-paratix`](https://www.npmjs.com/package/create-paratix).
- For detailed authoring guidance and module reference inside this repo, see [llm-guide.md](./llm-guide.md).

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
