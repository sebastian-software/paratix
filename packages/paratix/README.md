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
npm run apply:first-run:dry
npm run apply:first-run
npm run apply:dry
npm run apply
```

Use the first-run dry-run to preview the bootstrap changes before hardening a fresh server.

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

For filesystem metadata, you can now also use dedicated modules such as `file.chmod(...)` and `file.chown(...)` when you want to manage permissions or ownership without coupling that change to a file upload or template render.

### Recipes

Recipes group related modules into a named unit. They help structure larger playbooks and keep the CLI output readable.

### Signals

Signals are deferred side effects such as `service.reload(...)` or `service.restart(...)`. They run when the surrounding scope actually changed, and can also be flushed explicitly with `signals.flush()` when you need a checkpoint inside a larger flow.

### Compose + systemd

`compose.systemd(...)` can generate a native systemd unit for Docker Compose or Podman Compose projects. By default it now starts the stack with `compose up --remove-orphans`; set `detached: true` if you explicitly want the old `-d` behaviour in the generated `ExecStart`.

### Podman Quadlets

For Podman-native services, Paratix now also includes `quadlet.container(...)`. It writes a `.container` file under `/etc/containers/systemd`, reloads systemd when the content changes, and works cleanly with `service.enabled(...)` and `service.running(...)` for the generated service.

When you need a targeted image refresh outside the normal deploy flow, `quadlet.updateImage(...)` pulls exactly one image, reuses existing Podman registry auth on the host, optionally supports `authFile`, and only restarts the generated service when the pull actually downloaded a newer image. Changed runs now also print the new registry digest in parentheses in the CLI output, with a local image ID fallback when no repo digest is available.

### Guards

Paratix also supports declarative host-state guards. Use `when.packageInstalled(...)`, `when.commandExists(...)`, `when.fileExists(...)`, `when.pathExists(...)`, `when.symlinkExists(...)`, or `when.socketExists(...)` and their inverted forms to gate modules or recipes on remote host state without shell-heavy playbooks.

### Swap

Paratix can also manage file-backed swap directly. Use `swap.file(...)` to provision and persist a swap file, then tune common memory behaviour with `swap.swappiness(...)` or `swap.vfsCachePressure(...)`.

## CLI

`paratix --help` lists these options directly, so they are discoverable without drilling into `paratix apply --help` first.

```text
paratix apply <file> [options]

Options:
  --diff                         Combined with --dry-run: unified diff per changed module
  --dry-run                      Only check, do not apply (some runtime restarts stay unverified)
  --env <key=value...>           Set environment values for the playbook (repeatable)
  --env-file <path>              Load environment values from a dotenv file
  --filter <names>               Run only the named recipes/modules (comma-separated, repeatable)
  --first-run                    Set PARATIX_FIRST_RUN=true before loading the playbook
  --reconnect-timeout <seconds>  SSH reconnect timeout for reboots/port changes (max 86400)
  --verbose                      Show full stack traces on error
  --help                         Show help
```

`--filter <names>` restricts the run to the named recipes and modules. Names are matched anywhere in the tree, and every node that is not selected is shown as `skipped` instead of being executed. The option is comma-separated and repeatable, so `--filter rybbit,palamedes-examples` and `--filter rybbit --filter palamedes-examples` are equivalent. Selecting a recipe runs its whole subtree; a recipe that is not selected but contains a selected descendant is still descended into, so only the matching children run while its siblings are skipped. If several nodes share the same name, every one of them is selected. An unknown filter name aborts the run before it connects (exit code 2). The final run summary counts only top-level nodes, so nested skipped nodes are still shown but are not added to the `skipped` tally. `--filter` composes with `--dry-run` and the other flags.

`--first-run` is meant for explicit bootstrap flows where a fresh server must be hardened first and the rest of the system should only be applied later.

`--diff` only works together with `--dry-run`. When enabled, modules that opt in print a unified diff below their status line, showing exactly which lines or values would change. Without `--diff`, the dry-run output is unchanged. Diff-producing modules: `file.copy`, `file.template`, `sysctl.set`, `hostname.set`, `swap.file`, `swap.swappiness`, `swap.vfsCachePressure`, `cron.job`, `cron.absent`, `timer.scheduled`, `timer.absent`, `net.hosts`, `quadlet.container`.

`--reconnect-timeout <seconds>` sets how long Paratix keeps retrying the SSH connection after a module forces the connection to drop — after a `system.reboot` or after an SSH port change. When a module reboots the host, Paratix waits a short grace period and then reconnects within a **300 second window by default**, so hosts that need a few minutes to come back (fsck, cloud-init, slow POST) still succeed. The number of attempts follows the time window rather than a fixed cap, so the window is never cut short. Port-change reconnects use a shorter 120 second default because the port comes back almost immediately. Set `--reconnect-timeout` (up to 86400 seconds) to override both paths for exceptionally slow reboots.

## Documentation

- For project scaffolding, see [`create-paratix`](https://www.npmjs.com/package/create-paratix).
- See the complete [TypeScript API and Module Reference](./llm-guide.md).
- For common runtime and connection failures, see [Troubleshooting](../../docs/user-guide/troubleshooting.md).
- Before upgrading an existing project, see the [migration notes](../../docs/user-guide/migration.md).

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
