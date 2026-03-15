# Paratix

Idempotent VPS configuration in TypeScript.

[![npm version](https://img.shields.io/npm/v/paratix)](https://www.npmjs.com/package/paratix)
[![license](https://img.shields.io/npm/l/paratix)](https://opensource.org/licenses/MIT)
[![node](https://img.shields.io/node/v/paratix)](https://nodejs.org/)

## Overview

Paratix configures Linux servers over SSH using TypeScript playbooks. Each playbook declares the desired state of a server -- packages, files, services, firewall rules -- and Paratix enforces that state idempotently. Every module follows a check/apply pattern: `check` determines whether work is needed, `apply` makes it so.

If you have used Ansible, the idea is the same. The difference is that you write TypeScript instead of YAML, with full type safety and your existing toolchain.

## Getting started

Scaffold a new project:

```bash
npm create paratix my-server
# or: pnpm create paratix my-server
# or: yarn create paratix my-server
# or: bun create paratix my-server
```

This creates a project with the following structure:

```
my-server/
  server.ts          # Your playbook
  files/             # Templates and config files
  package.json
  tsconfig.json
```

Open `server.ts` and define your server:

```typescript
import { server } from "paratix"
import { hostname, package as pkg } from "paratix/modules"

export default server({
  name: "web-01",
  host: "10.0.0.1",
  ssh: {
    user: "root",
    ports: [22],
    privateKey: "~/.ssh/id_ed25519",
  },
  run: [hostname.set("web-01"), pkg.update("2025-03-01"), pkg.installed("nginx", "curl", "git")],
})
```

Apply the playbook:

```bash
npx paratix apply server.ts
```

Preview changes without applying them:

```bash
npx paratix apply server.ts --dry-run
```

## Core concepts

### Playbook

A playbook is a TypeScript file that default-exports a `server()` call. It declares the target host, SSH credentials, environment variables, and an ordered list of modules to run.

```typescript
import { server } from "paratix"

export default server({
  name: "web-01",
  host: "10.0.0.1",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/id_ed25519" },
  env: {
    DOMAIN: "example.com",
    APP_PORT: 3000,
  },
  run: [
    // modules go here
  ],
  signals: [
    // fire after run if anything changed
  ],
})
```

### Module

A module is the smallest unit of configuration. Each module has a `check` function (is the desired state already in place?) and an `apply` function (enforce the desired state). Modules are idempotent: running them twice produces the same result as running them once.

```typescript
import { package as pkg, service } from "paratix/modules"

pkg.installed("nginx") // installs nginx if missing, does nothing if present
service.running("nginx") // starts nginx if stopped, does nothing if running
```

### Recipe

A recipe groups related modules into a reusable unit with its own signals. Signals on a recipe fire only when a module inside that recipe reported a change.

```typescript
import { recipe } from "paratix"
import { package as pkg, file, service } from "paratix/modules"

const nginx = recipe(
  "nginx",
  [
    pkg.installed("nginx"),
    file.template("/etc/nginx/nginx.conf", "./files/nginx.conf.tmpl"),
    service.enabled("nginx"),
    service.running("nginx"),
  ],
  {
    signals: [service.reload("nginx")],
  }
)
```

If the config file changes, `service.reload("nginx")` fires. If nothing changed, the reload is skipped.

### Signals

Signals are modules that run only when something changed. Use them for actions like reloading a service after a config file update.

At the server level, `signals` fire when any module in `run` reported a change. Inside a recipe, signals fire only when that recipe's modules changed.

```typescript
export default server({
  // ...
  run: [file.template("/etc/myapp/config.yml", "./files/config.yml.tmpl")],
  signals: [service.restart("myapp")],
})
```

**Note:** `service.restart()` and `service.reload()` always apply when called. Place them in `signals`, not directly in `run`.

### Environment

The `env` object makes values available to templates and conditional logic. Values can be strings, numbers, or async functions (resolved lazily on first access).

```typescript
export default server({
  // ...
  env: {
    DOMAIN: "example.com",
    APP_PORT: 3000,
    DB_PASSWORD: async () => fetchFromVault("db-password"),
  },
  run: [
    /* ... */
  ],
})
```

Modules can return `meta` in their result, which merges into the environment for subsequent modules.

### Templates

`file.template()` deploys a file with `{{KEY}}` placeholders resolved from the environment.

Template file (`files/nginx.conf.tmpl`):

```
server {
    listen 80;
    server_name {{DOMAIN}};
    proxy_pass http://127.0.0.1:{{APP_PORT}};
}
```

```typescript
file.template("/etc/nginx/sites-available/default", "./files/nginx.conf.tmpl")
```

Use `\{{` to produce a literal `{{` in the output. Unknown keys throw an error at runtime.

## CLI reference

```
paratix apply <file>

Options:
  --dry-run                Check only, don't apply
  --env <key=value>        Set environment variable (repeatable)
  --env-file <path>        Load .env file
  --reconnect-timeout <s>  SSH reconnect timeout in seconds (default: 300)
  --verbose                Show full stack traces on error
  --version                Show version number
  --help                   Show help
```

## Module reference

All modules are imported from `"paratix/modules"`.

**Note:** `package` is a reserved word in JavaScript. Import it as: `import { package as pkg } from "paratix/modules"`.

### System

| Namespace  | Methods                     |
| ---------- | --------------------------- |
| `hostname` | `set`                       |
| `system`   | `facts`, `reboot`, `uptime` |
| `sysctl`   | `set`                       |
| `mount`    | `present`, `absent`         |

### Packages

| Namespace        | Methods                                       |
| ---------------- | --------------------------------------------- |
| `package`        | `installed`, `absent`, `update`, `upgrade`    |
| `apt`            | `debconf`, `distUpgrade`, `key`, `repository` |
| `releaseUpgrade` | `upgrade`                                     |

### Files

| Namespace  | Methods                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------- |
| `file`     | `absent`, `assemble`, `block`, `copy`, `directory`, `line`, `properties`, `replace`, `stat`, `template` |
| `archive`  | `extract`                                                                                               |
| `download` | `url`, `github`, `large`                                                                                |
| `git`      | `clone`                                                                                                 |
| `rsync`    | `sync`                                                                                                  |

### Services

| Namespace | Methods                                                                   |
| --------- | ------------------------------------------------------------------------- |
| `service` | `running`, `stopped`, `enabled`, `disabled`, `restart`, `reload`, `facts` |
| `systemd` | `unit`, `daemonReload`, `masked`, `unmasked`                              |

### Users and groups

| Namespace | Methods             |
| --------- | ------------------- |
| `user`    | `present`, `absent` |
| `group`   | `present`, `absent` |

### Network and security

| Namespace | Methods                        |
| --------- | ------------------------------ |
| `ufw`     | `enabled`, `rule`              |
| `ssh`     | `authorizedKeys`, `knownHosts` |
| `sshd`    | `config`, `port`               |

### Scheduling

| Namespace | Methods |
| --------- | ------- |
| `cron`    | `job`   |

### Commands

| Namespace | Methods |
| --------- | ------- |
| `command` | `shell` |

### Secrets

| Namespace | Methods   |
| --------- | --------- |
| `op`      | `resolve` |

## Custom modules

A custom module is an object with `name`, `check`, and `apply`:

```typescript
import type { Module, ModuleResult, SshConnection, Environment } from "paratix"
import { NEEDS_APPLY } from "paratix"

function ensureFile(path: string, content: string): Module {
  return {
    name: `ensure-file: ${path}`,

    async check(ssh: SshConnection | null, env: Environment): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const current = await ssh.readFile(path).catch(() => null)
      return current === content ? "ok" : NEEDS_APPLY
    },

    async apply(ssh: SshConnection | null, env: Environment): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }
      await ssh.writeFile(path, content)
      return { status: "changed" }
    },
  }
}
```

Rules for custom modules:

- `check` returns `"ok"` or `NEEDS_APPLY` (use the exported constant, not the string `"needs-apply"`).
- `apply` returns `{ status }` where status is `"changed"`, `"failed"`, `"ok"`, or `"skipped"`.
- Always handle the case where `ssh` is `null` (happens for local-only modules).
- Return `meta` from `apply` to pass data to subsequent modules via the environment.
- Set `local: true` on the module object if it runs on the local machine instead of over SSH.

## SshConnection API

Methods available on the `ssh` parameter in custom modules:

| Method                        | Returns                   | Description                                                                                               |
| ----------------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------- |
| `exec(cmd, options?)`         | `Promise<ExecResult>`     | Run a command. Returns `{ code, stdout, stderr }`. Throws on non-zero exit unless `ignoreExitCode: true`. |
| `test(cmd)`                   | `Promise<boolean>`        | Run a command, return `true` if exit code is 0.                                                           |
| `output(cmd)`                 | `Promise<string>`         | Run a command, return trimmed stdout.                                                                     |
| `lines(cmd)`                  | `Promise<string[]>`       | Run a command, return stdout split into lines.                                                            |
| `exists(path)`                | `Promise<boolean>`        | Check if a remote path exists.                                                                            |
| `readFile(path)`              | `Promise<string>`         | Read a remote file.                                                                                       |
| `writeFile(path, content)`    | `Promise<void>`           | Write content to a remote file.                                                                           |
| `uploadFile(local, remote)`   | `Promise<void>`           | Upload a local file via SFTP.                                                                             |
| `downloadFile(remote, local)` | `Promise<void>`           | Download a remote file.                                                                                   |
| `sha256(path)`                | `Promise<string \| null>` | Get SHA-256 hex digest, or `null` if the file does not exist.                                             |

Additional methods (`addPort`, `disconnect`, `getConnectionInfo`, `probeSudo`, `updateHost`) are available for advanced use cases. See the type definitions for details.

## Built-in helpers

Import these from `"paratix"`:

| Helper                         | Description                                                                                       |
| ------------------------------ | ------------------------------------------------------------------------------------------------- |
| `recipe(name, modules, opts?)` | Group modules into a reusable unit with optional signals. See [Recipes](#recipe) above.           |
| `assert(condition, message)`   | Abort the run if `condition` returns false. The condition receives the current environment.       |
| `when(condition, ...modules)`  | Run modules only if `condition` returns true. Skipped modules report `"skipped"`, not `"failed"`. |
| `debug(message)`               | Print a debug message during the run.                                                             |
| `fail(message)`                | Abort the run unconditionally with a failure.                                                     |
| `pause(message?)`              | Wait for the operator to press Enter before continuing.                                           |
| `shellQuote(value)`            | Safely quote a string for shell interpolation.                                                    |
| `NEEDS_APPLY`                  | Constant to return from `check` when work is needed.                                              |

## License

MIT
