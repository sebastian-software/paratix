# Paratix -- LLM Code Guide

> This file helps LLMs write correct Paratix code. Read this before generating playbooks or modules.

## Overview

Paratix is a CLI tool for idempotent VPS configuration via SSH using TypeScript playbooks. Each playbook exports a `server()` definition containing an ordered list of modules that are checked and applied over SSH. Modules follow a check/apply pattern: `check` determines if work is needed, `apply` enforces the desired state.

## Imports

Paratix has exactly two import paths:

```typescript
// Core API
import {
  server,
  recipe,
  assert,
  debug,
  fail,
  firstRun,
  pause,
  resolveEnvironment,
  signals,
  when,
  shellQuote,
  NEEDS_APPLY,
  failed,
  meta,
} from "paratix"

// Types (only when needed)
import type {
  Module,
  EnvironmentMetaEntry,
  ModuleMetaEntry,
  ModuleResult,
  ServerDefinition,
  SshConnection,
  SshConfig,
  Environment,
  EnvironmentValue,
  ExecResult,
  ExecOptions,
} from "paratix"

// Built-in modules
import {
  apt,
  archive,
  command,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  op,
  package as pkg,
  releaseUpgrade,
  rsync,
  service,
  ssh,
  sshd,
  swap,
  sysctl,
  system,
  systemd,
  timer,
  ufw,
  user,
} from "paratix/modules"
```

## Playbook Structure

A playbook is a TypeScript file with a default export of `server()`:

```typescript
import { server, recipe, when, shellQuote } from "paratix"
import { package as pkg, file, service, ufw, hostname } from "paratix/modules"

export default server({
  // Required fields
  name: "web-01",
  host: "10.0.0.1",
  ssh: {
    user: "root",
    ports: [22], // Array -- runner tries each port in order
    privateKey: "~/.ssh/id_ed25519", // Optional -- "~" is expanded; omit to use SSH agent
    // Optional:
    // agentForward: false,          // Forward SSH agent to remote
    // passwordFallback: false,
    // sudoPassword: "...",
    // reconnectTimeout: 30000,
    // strictHostKeyChecking: "yes", // default; set "accept-new" only for explicit TOFU
    // expectedHostFingerprint: "SHA256:...",
    // expectedHostPublicKey: "ssh-ed25519 AAAA...",
  },

  // Optional: env values available in templates and conditions
  env: {
    DOMAIN: "example.com",
    APP_PORT: 3000,
    SECRET: async () => fetchFromVault("secret"), // Lazy async values supported
  },

  // Required: ordered list of modules to apply
  run: [
    hostname.set("web-01"),
    pkg.update("2025-03-01"),
    pkg.installed("nginx", "curl"),
    file.template("/etc/nginx/sites-available/default", "./files/nginx.conf.tmpl"),
    service.enabled("nginx"),
    service.running("nginx"),
    ufw.enabled(),
    ufw.rule("allow", 80),
    ufw.rule("allow", 443),

    // Conditional module
    when((env) => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban")),
  ],

  // Optional: signals fire when ANY module in run reported "changed"
  signals: [service.reload("nginx")],
})
```

## Module Reference

### `apt`

| Method            | Signature                                                                                | Idempotent           |
| ----------------- | ---------------------------------------------------------------------------------------- | -------------------- |
| `apt.debconf`     | `(packageName: string, selections: Record<string, string>): Module`                      | Yes                  |
| `apt.distUpgrade` | `(date: string, options?: UpgradeOptions): Module`                                       | Yes (versioned flag) |
| `apt.key`         | `(name: string, url: string, options: { fingerprint: string }): Module`                  | Yes                  |
| `apt.repository`  | `(nameOrPpa: string, source?: string, options?: { signedBy?: false \| string }): Module` | Yes                  |

### `archive`

| Method            | Signature                                                                                       | Idempotent        |
| ----------------- | ----------------------------------------------------------------------------------------------- | ----------------- |
| `archive.extract` | `(source: string, destination: string, options?: { owner?: string; upload?: boolean }): Module` | Yes (SHA256 flag) |

### `command`

| Method          | Signature                                                            | Idempotent        |
| --------------- | -------------------------------------------------------------------- | ----------------- |
| `command.shell` | `(cmd: string, options?: { check?: string; name?: string }): Module` | Only with `check` |

### `cron`

| Method        | Signature                                                                                       | Idempotent |
| ------------- | ----------------------------------------------------------------------------------------------- | ---------- |
| `cron.job`    | `(user: string, name: string, options: { job: string; state?: "absent" \| "present" }): Module` | Yes        |
| `cron.absent` | `(user: string, name: string): Module`                                                          | Yes        |

`cron.absent(user, name)` is the dedicated uninstall variant: it removes a
managed cron entry without requiring a placeholder `job` argument. Use it as
the idiomatic way to ensure a previously installed cron job is gone.

### `compose`

| Method            | Signature                                                                                                            | Idempotent |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| `compose.config`  | `(options: { content?: string; projectDirectory: string; runtime?: "docker" \| "podman"; src?: string }): Module`    | Yes        |
| `compose.up`      | `(options: { projectDirectory: string; runtime?: "docker" \| "podman"; services?: string[] }): Module`               | Yes        |
| `compose.down`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | Yes        |
| `compose.pull`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | Partial    |
| `compose.restart` | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | No         |
| `compose.systemd` | `(options: { detached?: boolean; name?: string; projectDirectory: string; runtime?: "docker" \| "podman" }): Module` | Yes        |

### `download`

| Method            | Signature                                                                                                                                                                     | Idempotent |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `download.url`    | `(destination: string, url: string, options?: { force?: boolean; headers?: Record<string, string>; sha256?: string; mode?: string; owner?: string; group?: string }): Module` | Yes        |
| `download.github` | `(destination: string, options: { repo: string; tag: string; asset: string; token?: string; sha256?: string; mode?: string; owner?: string; group?: string }): Module`        | Yes        |
| `download.large`  | `(destination: string, url: string, options?: { group?: string; headers?: Record<string, string>; mode?: string; owner?: string; sha256?: string }): Module`                  | Yes (flag) |

### `file`

| Method            | Signature                                                                                                           | Idempotent          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `file.absent`     | `(remotePath: string): Module`                                                                                      | Yes                 |
| `file.assemble`   | `(remotePath: string, fragments: string[], options?: { mode?: string; owner?: string }): Module`                    | Yes                 |
| `file.block`      | `(remotePath: string, options: { content: string; name: string; prefix?: string }): Module`                         | Yes                 |
| `file.chmod`      | `(remotePath: string, mode: string): Module`                                                                        | Yes                 |
| `file.chown`      | `(remotePath: string, owner: string): Module`                                                                       | Yes                 |
| `file.copy`       | `(remotePath: string, localPath: string, options?: { mode?: string; owner?: string }): Module`                      | Yes                 |
| `file.directory`  | `(remotePath: string, options?: { mode?: string; owner?: string }): Module`                                         | Yes                 |
| `file.line`       | `(remotePath: string, line: string, options?: { match?: string }): Module`                                          | Yes                 |
| `file.properties` | `(remotePath: string, options: { group?: string; mode?: string; owner?: string }): Module`                          | Yes                 |
| `file.replace`    | `(remotePath: string, pattern: string, replacement: string): Module`                                                | Yes                 |
| `file.stat`       | `(remotePath: string): Module`                                                                                      | No (always-applies) |
| `file.template`   | `(remotePath: string, templatePath: string, options?: { mode?: string; owner?: string; strict?: boolean }): Module` | Yes                 |

**Hinweis zu `file.copy` und Default-Mode:** Wenn `options.mode` weggelassen wird, setzt `file.copy` den Modus auf den dokumentierten Default `0644`. Der Modus wird sowohl beim Hochladen (`uploadFile` mit `{ mode }`) als auch in `check` gegen den Soll-Wert verglichen, damit nachfolgende Läufe Mode-Drift (z. B. manuelles `chmod 0600`) als `needs-apply` erkennen. Wer ein restriktiveres Recht braucht (z. B. für Secrets), übergibt explizit `{ mode: "0600" }`.

### `git`

| Method      | Signature                                                                 | Idempotent |
| ----------- | ------------------------------------------------------------------------- | ---------- |
| `git.clone` | `(repo: string, destination: string, options?: { ref?: string }): Module` | Yes        |

### `group`

| Method          | Signature                                            | Idempotent |
| --------------- | ---------------------------------------------------- | ---------- |
| `group.present` | `(name: string, options?: { gid?: number }): Module` | Yes        |
| `group.absent`  | `(name: string): Module`                             | Yes        |

### `hostname`

| Method         | Signature                | Idempotent |
| -------------- | ------------------------ | ---------- |
| `hostname.set` | `(name: string): Module` | Yes        |

### `mount`

| Method          | Signature                                                                                           | Idempotent |
| --------------- | --------------------------------------------------------------------------------------------------- | ---------- |
| `mount.present` | `(options: { fstype: string; opts: string; path: string; persist?: boolean; src: string }): Module` | Yes        |
| `mount.absent`  | `(options: { path: string; persist?: boolean }): Module`                                            | Yes        |

### `op`

| Method       | Signature                                      | Idempotent                        |
| ------------ | ---------------------------------------------- | --------------------------------- |
| `op.resolve` | `(references: Record<string, string>): Module` | No (always-applies, runs locally) |

### `package`

Import with renaming: `import { package as pkg } from "paratix/modules"`. The word `package` is reserved in JavaScript, so you must alias it.

| Method              | Signature                                                          | Idempotent           |
| ------------------- | ------------------------------------------------------------------ | -------------------- |
| `package.installed` | `(...packagesAndOptions: Array<string \| UpgradeOptions>): Module` | Yes                  |
| `package.absent`    | `(...packagesAndOptions: Array<string \| UpgradeOptions>): Module` | Yes                  |
| `package.update`    | `(date: string, options?: UpgradeOptions): Module`                 | Yes (versioned flag) |
| `package.upgrade`   | `(date: string, options?: UpgradeOptions): Module`                 | Yes (versioned flag) |

#### `UpgradeOptions`

```typescript
type UpgradeOptions = {
  timeout?: number // Override SSH command timeout (ms). Same value applies to every step
  // of multi-step pipelines (apt upgrade, apk upgrade, apt dist-upgrade).
}
```

For `package.installed` / `package.absent`, pass the options object as the **last** argument
after the package names; existing variadic call sites such as `pkg.installed("git", "curl")`
keep working unchanged. Use a longer `timeout` for slow operations on production servers
with large update backlogs:

```typescript
pkg.upgrade("2026-05-01", { timeout: 900_000 })
pkg.installed("texlive-full", { timeout: 900_000 })
apt.distUpgrade("2026-05-01", { timeout: 1_200_000 })
```

### `quadlet`

| Method                | Signature                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Idempotent |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `quadlet.container`   | `(options: { addCapability?: string[]; addDevice?: string[]; annotation?: Record<string, string>; autoUpdate?: "local" \| "registry"; containerName?: string; description?: string; dns?: string[]; dnsOption?: string[]; dnsSearch?: string[]; dropCapability?: string[]; entrypoint?: string[]; environment?: Record<string, string>; environmentFiles?: string[]; exec?: string[]; exposeHostPort?: string[]; groupAdd?: string[]; healthCmd?: string; healthInterval?: string; healthOnFailure?: "kill" \| "none" \| "restart" \| "stop"; healthRetries?: number; healthStartPeriod?: string; healthTimeout?: string; hostName?: string; image: string; ip?: string; ip6?: string; label?: Record<string, string>; logDriver?: string; mask?: string[]; mount?: string[]; name: string; networks?: string[]; noNewPrivileges?: boolean; notify?: boolean; podmanArgs?: string[]; publishPorts?: string[]; pull?: "always" \| "missing" \| "never" \| "newer"; readOnly?: boolean; restart?: "always" \| "no" \| "on-abnormal" \| "on-abort" \| "on-failure" \| "on-success" \| "on-watchdog"; runInit?: boolean; secret?: string[]; seccompProfile?: string; securityLabelDisable?: boolean; securityLabelType?: string; stopTimeout?: number; sysctl?: Record<string, string>; timeoutStartSec?: number; timeoutStopSec?: number; timezone?: string; tmpfs?: string[]; ulimit?: string[]; unmask?: string[]; user?: string; userNs?: string; volumes?: string[]; wantedBy?: string; workingDir?: string }): Module` | Yes        |
| `quadlet.updateImage` | `(options: { authFile?: string; image: string; name: string; serviceName?: string }): Module` — returns `changed` with the new registry digest (or local image ID fallback) in parentheses when a newer image was pulled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Partial    |

### `releaseUpgrade`

| Method                   | Signature                                                                                         | Idempotent |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ---------- |
| `releaseUpgrade.upgrade` | `(options?: { dryRun?: boolean; resolveHost?: () => Promise<string>; timeout?: number }): Module` | Yes        |

### `rsync`

| Method       | Signature                                                                                                                                                                                                                    | Idempotent |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `rsync.sync` | `(options: { src: string; dest: string; chmod?: string; delete?: boolean; exclude?: string[]; group?: string; include?: string[]; owner?: string; strictHostKeyChecking?: "accept-new" \| "no" \| "off" \| "yes" }): Module` | Yes        |

When the active Paratix SSH session already verified the host via `ssh.expectedHostFingerprint`
or `ssh.expectedHostPublicKey`, `rsync.sync()` reuses that verified host key for the external
rsync SSH process and does not depend on a local `known_hosts` entry.

### `service`

| Method             | Signature                | Idempotent                                                |
| ------------------ | ------------------------ | --------------------------------------------------------- |
| `service.running`  | `(name: string): Module` | Yes                                                       |
| `service.stopped`  | `(name: string): Module` | Yes                                                       |
| `service.enabled`  | `(name: string): Module` | Yes                                                       |
| `service.disabled` | `(name: string): Module` | Yes                                                       |
| `service.restart`  | `(name: string): Module` | No (always-applies, use as signal)                        |
| `service.reload`   | `(name: string): Module` | No (always-applies, use as signal)                        |
| `service.facts`    | `(): Module`             | No (always-applies, collects facts into `service.*` meta) |

### `ssh`

| Method               | Signature                                                                                                                              | Idempotent |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `ssh.authorizedKeys` | `(user: string, key: string, options?: { state?: "absent" \| "present" }): Module`                                                     | Yes        |
| `ssh.knownHosts`     | `(host: string, options?: { expectedFingerprint?: string; port?: number; publicKey?: string; state?: "absent" \| "present" }): Module` | Yes        |

**Trust-Anchor-Pflicht für `ssh.knownHosts` (state `present`):** Im Default-State `present` muss entweder `expectedFingerprint` oder `publicKey` gesetzt sein. Ohne Trust Anchor wirft der Modul-Konstruktor sofort, denn `check` würde sonst jeden vorhandenen `known_hosts`-Eintrag (auch ältere, möglicherweise kompromittierte TOFU-Akzeptanzen) als „ok" werten und den Anchor-Vergleich überspringen. Für `state: "absent"` ist kein Anchor nötig — dort wird der Eintrag ohnehin entfernt.

### `sshd`

| Method        | Signature                                    | Idempotent                         |
| ------------- | -------------------------------------------- | ---------------------------------- |
| `sshd.config` | `(settings: Record<string, string>): Module` | Yes                                |
| `sshd.port`   | `(targetPort: number): Module`               | Yes (emits typed `sshd.port` meta) |

### `swap`

| Method                  | Signature                                                                                                                      | Idempotent |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `swap.file`             | `(options: { path: string; size: number \| string; mode?: string; priority?: number; state?: "absent" \| "present" }): Module` | Yes        |
| `swap.swappiness`       | `(value: number): Module`                                                                                                      | Yes        |
| `swap.vfsCachePressure` | `(value: number): Module`                                                                                                      | Yes        |

### `sysctl`

| Method       | Signature                                                                           | Idempotent |
| ------------ | ----------------------------------------------------------------------------------- | ---------- |
| `sysctl.set` | `(key: string, value: string, options?: { state?: "absent" \| "present" }): Module` | Yes        |

### `system`

| Method          | Signature                                                     | Idempotent                                          |
| --------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| `system.facts`  | `(): Module`                                                  | No (always-applies, emits typed `env` meta entries) |
| `system.reboot` | `(options?: { resolveHost?: () => Promise<string> }): Module` | No (always-applies)                                 |
| `system.uptime` | `(): Module`                                                  | No (always-applies, emits typed `env` meta entries) |

### `systemd`

| Method                 | Signature                                 | Idempotent                         |
| ---------------------- | ----------------------------------------- | ---------------------------------- |
| `systemd.unit`         | `(name: string, content: string): Module` | Yes                                |
| `systemd.daemonReload` | `(): Module`                              | No (always-applies, use as signal) |
| `systemd.masked`       | `(name: string): Module`                  | Yes                                |
| `systemd.unmasked`     | `(name: string): Module`                  | Yes                                |

### `timer`

| Method            | Signature                                                                                                                                                                                                                                                                                                                             | Idempotent |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `timer.scheduled` | `(name: string, options: { accuracySec?: number \| string; description?: string; environment?: Record<string, string>; exec: string; group?: string; onCalendar: string \| string[]; persistent?: boolean; randomizedDelaySec?: number \| string; state?: "absent" \| "present"; user?: string; workingDirectory?: string }): Module` | Yes        |
| `timer.absent`    | `(name: string): Module`                                                                                                                                                                                                                                                                                                              | Yes        |

`timer.absent(name)` is the dedicated uninstall variant: it disables and stops
the timer, removes both unit files, and reloads systemd, without requiring
placeholder `exec`/`onCalendar` values.

`timer.scheduled` is the systemd-timer equivalent of `cron.job`. It writes
`<name>.service` (`Type=oneshot`) and `<name>.timer` to `/etc/systemd/system/`,
reloads systemd, and runs `systemctl enable --now <name>.timer`. Use it as the
default for new scheduled tasks: `Persistent=true` is on by default so missed
runs are caught up after downtime, and logs land in journald (`journalctl -u
<name>.service`). Cron remains a fit for ad-hoc per-user crontab entries.

```typescript
timer.scheduled("backup", {
  exec: "/usr/local/bin/backup",
  onCalendar: "*-*-* 03:00:00",
})

timer.scheduled("cleanup", {
  exec: "/usr/local/bin/cleanup",
  onCalendar: ["Mon..Fri 02:00", "Sat 04:00"],
  user: "deploy",
  randomizedDelaySec: 300,
})

timer.absent("legacy-task")
```

### `ufw`

| Method         | Signature                                                        | Idempotent |
| -------------- | ---------------------------------------------------------------- | ---------- |
| `ufw.disabled` | `(): Module`                                                     | Yes        |
| `ufw.enabled`  | `(): Module`                                                     | Yes        |
| `ufw.rule`     | `(action: "allow" \| "deny", ports: number \| number[]): Module` | Yes        |

### `user`

| Method         | Signature                                                                                                                 | Idempotent |
| -------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `user.present` | `(name: string, options?: { uid?: number; shell?: string; home?: string; groups?: string[]; password?: string }): Module` | Yes        |
| `user.absent`  | `(name: string, options?: { removeHome?: boolean }): Module`                                                              | Yes        |

## Custom Modules

A custom module must implement `check` and `apply`, both async:

```typescript
import type { Module, ModuleResult, SshConnection, Environment } from "paratix"
import { NEEDS_APPLY, failed, meta } from "paratix"

function myCustomModule(configPath: string, content: string): Module {
  return {
    name: `my-module: ${configPath}`,

    async check(ssh: SshConnection | null, env: Environment): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const exists = await ssh.exists(configPath)
      if (!exists) return NEEDS_APPLY
      const current = await ssh.readFile(configPath)
      return current === content ? "ok" : NEEDS_APPLY
    },

    async apply(ssh: SshConnection | null, env: Environment): Promise<ModuleResult> {
      if (!ssh) return failed(`[my-module: ${configPath}] SSH connection is required`)
      await ssh.writeFile(configPath, content)
      return {
        meta: [meta.env("MY_MODULE_PATH", configPath)],
        status: "changed",
      }
    },
  }
}
```

### Key rules for custom modules

- Always check `if (!ssh) return NEEDS_APPLY` in check and return `failed("...")` with a useful message in apply.
- Prefer `failedCommand("...", result)` when you used `ssh.exec(..., { ignoreExitCode: true })` and want stdout/stderr preserved for central runner output.
- Return `NEEDS_APPLY` (the exported constant), never the string literal `"needs-apply"`.
- `ModuleResult.status` must be one of: `"changed"`, `"failed"`, `"ok"`, `"skipped"`.
- Use typed `meta` entries in the return value, not loose objects.
- For normal downstream environment propagation, use `meta.env(name, value)`.
- `meta.env(...)` accepts strings, numbers, booleans, sync lazy functions, and async lazy functions.
- `meta.env(...)` is normalized internally to an async resolver, so downstream code should treat propagated environment values as lazily async and resolve them via `resolveEnvironment(...)` when it needs the concrete primitive.
- Use dedicated built-in meta entries only for runner control-plane effects, for example `meta.sshdPort(...)`, `meta.systemHost(...)`, and `meta.systemReboot()`.
- Use the exported guards such as `isEnvironmentMetaEntry(...)`, `isStringEnvironmentMetaEntry(...)`, `isNumberEnvironmentMetaEntry(...)`, `isBooleanEnvironmentMetaEntry(...)`, `isLazyEnvironmentMetaEntry(...)`, `isSshdPortMetaEntry(...)`, `isSystemHostMetaEntry(...)`, and `isSystemRebootMetaEntry(...)` when you need to inspect meta entries safely.
- Set `local: true` on the module object if it runs on the local machine (ssh will be `null`).

### SshConnection API

Methods available on the `ssh` parameter:

| Method                            | Return type                             | Description                                                                                    |
| --------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `ssh.exec(cmd, options?)`         | `Promise<ExecResult>`                   | Run command, get `{ code, stdout, stderr }`. Throws on non-zero unless `ignoreExitCode: true`. |
| `ssh.test(cmd)`                   | `Promise<boolean>`                      | Run command, return `true` if exit code is 0.                                                  |
| `ssh.output(cmd)`                 | `Promise<string>`                       | Run command, return trimmed stdout.                                                            |
| `ssh.lines(cmd)`                  | `Promise<string[]>`                     | Run command, return stdout split into lines.                                                   |
| `ssh.exists(path)`                | `Promise<boolean>`                      | Check if remote path exists.                                                                   |
| `ssh.readFile(path)`              | `Promise<string>`                       | Read remote file content.                                                                      |
| `ssh.writeFile(path, content)`    | `Promise<void>`                         | Write content to remote file.                                                                  |
| `ssh.uploadFile(local, remote)`   | `Promise<void>`                         | Upload local file via SFTP.                                                                    |
| `ssh.downloadFile(remote, local)` | `Promise<void>`                         | Download remote file.                                                                          |
| `ssh.sha256(path)`                | `Promise<string \| null>`               | Get SHA-256 hex digest, or null if not found.                                                  |
| `ssh.addPort(port)`               | `void`                                  | Register an additional port opened on the remote host (advanced).                              |
| `ssh.disconnect()`                | `void`                                  | Close the SSH connection.                                                                      |
| `ssh.getConnectionInfo()`         | `{ host, port, privateKeyPath?, user }` | Return current connection parameters.                                                          |
| `ssh.probeSudo()`                 | `Promise<void>`                         | Probe/cache sudo access; prompts interactively if needed.                                      |
| `ssh.updateHost(host)`            | `void`                                  | Update the target host address (e.g., after IP change).                                        |

### ExecOptions

```typescript
{
  env?: Record<string, string>       // Extra environment variables
  ignoreExitCode?: boolean           // Don't throw on non-zero exit
  secrets?: string[]                 // Strings to mask in error output
  silent?: boolean                   // Suppress stdout/stderr
  timeout?: number                   // Abort after N milliseconds
}
```

## Template System

Files deployed via `file.template(remotePath, localTemplatePath)` can contain `{{KEY}}` placeholders.

- Placeholders are resolved at runtime from the `env` object of `server()` and from typed `meta.env(...)` entries returned by previous modules.
- Environment values can be strings, numbers, booleans, sync lazy functions, or async lazy functions.
- Values propagated through `meta.env(...)` are normalized to async resolution before downstream modules or templates consume them.
- Escaping: `\{{` produces a literal `{{` in the output.
- Unknown keys throw an error at runtime.
- **Modifiers:** `{{KEY|shell}}` applies `shellQuote()` to the value. This is the only built-in modifier.
- **Strict mode (default: on).** Every placeholder must have an explicit modifier (`|shell` or `|raw`). Bare `{{KEY}}` placeholders throw at render time. Pass `strict: false` in the options to disable this check.
- **Security: No default escaping.** Values are inserted verbatim. If the template produces a shell script or shell config, **always** use `{{KEY|shell}}` for every variable — omitting `|shell` can lead to shell injection.

Example template file (`nginx.conf.tmpl`):

```
server {
    listen 80;
    server_name {{DOMAIN|raw}};
    proxy_pass http://127.0.0.1:{{APP_PORT|raw}};
}
```

With `env: { DOMAIN: "example.com", APP_PORT: 3000 }` in the server definition.

## Recipes

A recipe groups modules into a named, reusable unit with optional signals:

```typescript
import { recipe } from "paratix"
import { package as pkg, file, service } from "paratix/modules"

export const nginxRecipe = recipe(
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

**How recipes work:**

- Modules run in order; execution stops on first `"failed"` status.
- `meta.env(...)` values propagate from one module to all subsequent ones within the recipe and resolve lazily when later modules or templates consume them.
- If any module reports `"changed"`, the `signals` array fires after all modules complete.
- `signals.flush()` can be used inside the same scope to execute currently pending signals early.
- Recipes can be nested: include a recipe in another recipe's module list.

**When to use recipes:**

- Group related modules that form a logical unit (e.g., "install and configure nginx").
- When you need signals to fire only if that specific group changed (not the entire server run).

## Built-in Functions

### `assert(condition, message)`

Fail the run if a condition is not met.

```typescript
assert((env) => !!env["APP_SECRET"], "APP_SECRET must be set")
```

### `when(condition, ...modules)`

Conditionally run modules. Skipped modules report `"skipped"`, not `"failed"`.

```typescript
when((env) => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban"), ufw.enabled())
```

### `when.packageInstalled(name, ...modules)` / `when.packageAbsent(name, ...modules)`

Conditionally run modules based on package state on the remote host.

```typescript
when.packageInstalled("ufw", ufw.disabled())
when.packageAbsent("docker-ce", package.installed("docker-ce"))
```

### `when.commandExists(name, ...modules)` / `when.commandMissing(name, ...modules)`

Conditionally run modules based on whether a command exists on the remote host.

```typescript
when.commandExists("docker", service.running("docker"))
when.commandMissing("docker", package.installed("docker-ce"))
```

### Filesystem guard variants

Use explicit filesystem-type guards when a module or recipe should only run for a specific entry type:

- `when.fileExists(path, ...modules)` / `when.fileMissing(path, ...modules)` for regular files
- `when.pathExists(path, ...modules)` / `when.pathMissing(path, ...modules)` for directories
- `when.symlinkExists(path, ...modules)` / `when.symlinkMissing(path, ...modules)` for symlinks
- `when.socketExists(path, ...modules)` / `when.socketMissing(path, ...modules)` for Unix sockets

```typescript
when.fileExists("/etc/myapp/config.yml", service.reload("myapp"))
when.pathMissing("/etc/traefik", file.directory("/etc/traefik"))
when.symlinkExists("/etc/myapp/current", service.restart("myapp"))
when.socketExists("/run/docker.sock", service.running("docker"))
```

### `swap.file(options)`

Create, activate, and persist a file-backed swap area.

```typescript
swap.file({ path: "/swapfile", size: "2G" })
swap.file({ path: "/swapfile", size: "2G", priority: 10 })
swap.file({ path: "/swapfile", size: "2G", state: "absent" })
```

### `swap.swappiness(value)` / `swap.vfsCachePressure(value)`

Apply common swap-related sysctl tuning without writing the sysctl keys manually.

```typescript
swap.swappiness(10)
swap.vfsCachePressure(50)
```

### `debug(message)`

Print a debug message during apply. Always runs.

```typescript
debug("Starting database setup")
```

### `fail(message)`

Unconditionally abort the run with a failure.

```typescript
fail("This branch should be unreachable")
```

### `firstRun.stop(message?)`

Stoppt den aktuellen Lauf kontrolliert, wenn Paratix mit `--first-run` gestartet wurde. Nützlich als explizite Staging-Grenze in Bootstrap-Playbooks.

```typescript
firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")
```

### `signals.flush(message?)`

Führt alle aktuell offenen Signale des aktiven Scopes sofort aus und setzt deren Pending-Zustand zurück.

```typescript
signals.flush("Reload services before the next bootstrap stage")
```

### `pause(message?)`

Wait for operator to press Enter. Useful for interactive confirmation.

```typescript
pause("Review changes above, then press Enter to continue")
```

### `shellQuote(value)`

Safely quote a string for shell interpolation. Use this when building shell commands with dynamic values.

```typescript
await ssh.exec(`cat ${shellQuote(filePath)}`)
```

### `NEEDS_APPLY`

Constant for the check return value indicating work is needed. Always use this instead of the string `"needs-apply"`.

```typescript
import { NEEDS_APPLY } from "paratix"

async check(ssh) {
  if (!ssh) return NEEDS_APPLY
  // ...
}
```

## Do's and Don'ts

### DO

1. Always use `export default server({...})` as the default export of a playbook.
2. Import modules from `"paratix/modules"`, not from `"paratix"`.
3. `package` must be aliased on import: `import { package as pkg } from "paratix/modules"` -- `package` is a reserved word in JavaScript.
4. For idempotency with `command.shell()`, always provide a `check` command.
5. Use `{{KEY|shell}}` or `{{KEY|raw}}` placeholders in `.tmpl` files — strict mode is on by default and bare `{{KEY}}` will throw. Provide values via `env` in `server()`.
6. Use `service.restart()` and `service.reload()` as `signals` in recipes, not directly in `run`.
7. Use `signals.flush()` only als expliziten Checkpoint, wenn gestufte Flows einen vorgezogenen Signal-Flush brauchen.
8. Always pass a date string to `package.upgrade()` and `package.update()` -- it is the idempotency key.
9. Specify `ssh.ports` as an array -- the runner tries each port in order.
10. Custom modules must implement both `check` and `apply`, both async.
11. Use `shellQuote()` when interpolating dynamic values into shell commands.
12. Emit downstream values via `meta.env(...)` and use dedicated built-in meta entries only for runner control-plane behavior.
13. When you need a concrete propagated value inside custom code, use `await resolveEnvironment(env, "KEY")` instead of assuming `env["KEY"]` is already a plain primitive.

### DON'T

1. Do NOT `import { package } from "paratix"` -- modules come from `"paratix/modules"`.
2. Do NOT use `service.restart()` directly in `run` -- it runs EVERY time. Use it as a signal in a `recipe()`.
3. Do NOT use the string literal `"needs-apply"` -- always use the exported constant `NEEDS_APPLY`.
4. Do NOT assume `ssh` is non-null in custom modules -- always check it and return `failed("...")` with context.
5. Do NOT forget that `package.upgrade("2025-01-15")` needs a date as IDEMPOTENCY KEY -- the date controls when the upgrade re-runs.
6. Do NOT interpolate `env` values directly in shell commands -- use `shellQuote()` for safe quoting.
7. Do NOT store module methods as variables and call them later -- modules are configured at creation time, not at call time.
8. Do NOT use `ssh.exec()` without `ignoreExitCode: true` when you need to inspect the exit code -- without it, a non-zero exit throws an exception.
9. Do NOT use template syntax `{{key}}` in TypeScript code -- templates are only for files rendered via `file.template()`.
10. Do NOT use `signals` on the top-level `server()` when you mean a recipe signal -- `server.signals` fire when ANY module in `run` changed.
11. Do NOT treat `signals.flush()` as a global queue flush -- it only affects the current scope.
12. `signals.flush()` flusht immer nur den aktuellen Scope:
    - in einer Recipe deren Recipe-Signale
    - auf Top-Level `server(...).signals`
13. Do NOT call `server()` without all required fields (`name`, `host`, `ssh`, `run`) -- it throws at construction time. `name` and `host` must not be empty strings.
14. Do NOT use empty arrays for `ssh.ports` or empty strings for `ssh.user`/`ssh.privateKey` -- validation rejects these. `ssh.privateKey` may be omitted entirely to use the SSH agent instead.
15. Do NOT return loose `meta: { ... }` maps from custom modules -- always use typed meta entries.

## Testing Patterns

Tests use vitest with a `createMockSsh` helper:

```typescript
import { describe, expect, it } from "vitest"
import { createMockSsh } from "./helpers/mockSsh.js"
import { NEEDS_APPLY } from "../src/types.js"

describe("myModule", () => {
  it("should detect needs-apply when file is missing", async () => {
    const ssh = createMockSsh({
      // Map command strings to partial ExecResult { code?, stdout?, stderr? }
      "[ -e '/etc/myconfig' ]": { code: 1 },
    })

    const mod = myCustomModule("/etc/myconfig", "desired content")
    const result = await mod.check(ssh, {})
    expect(result).toBe(NEEDS_APPLY)
  })

  it("should apply changes", async () => {
    const ssh = createMockSsh({})

    const mod = myCustomModule("/etc/myconfig", "desired content")
    const result = await mod.apply(ssh, {})
    expect(result.status).toBe("changed")
  })

  it("should track executed commands", async () => {
    const ssh = createMockSsh({})

    const mod = myCustomModule("/etc/myconfig", "content")
    await mod.apply(ssh, {})

    // ssh.calls contains all commands executed in order
    expect(ssh.calls).toContain("some-expected-command")
  })
})
```

### `createMockSsh` behavior

- Accepts `Record<string, Partial<ExecResult>>` mapping command strings to responses.
- Default response: `{ code: 0, stdout: "", stderr: "" }`.
- `ssh.test(cmd)` returns `code === 0`.
- `ssh.exists(path)` delegates to `ssh.test("[ -e '<path>' ]")`.
- `ssh.readFile(path)` delegates to `ssh.output("cat '<path>'")`.
- Returns a `{ calls: string[] } & SshConnection` object -- `calls` records all commands in execution order.
