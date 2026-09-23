# Paratix TypeScript API and Module Reference

This is the complete reference for writing Paratix playbooks and custom modules. It covers the
TypeScript API, built-in modules, authoring patterns, and common mistakes.

## Overview

Paratix is a CLI tool for idempotent VPS configuration via SSH using TypeScript playbooks. Each playbook exports a `server()` definition containing an ordered list of modules that are checked and applied over SSH. Modules follow a check/apply pattern: `check` determines if work is needed, `apply` enforces the desired state.

## Agent authoring guidance

When generating or changing Paratix playbooks or custom modules, automated coding agents should use
this document as the complete API reference. Read the relevant API and module sections before making
changes, and follow the [Do's and Don'ts](#dos-and-donts) and [testing patterns](#testing-patterns).

## Imports

Paratix has exactly two import paths:

<!-- public-api-imports:start -->

```typescript
import {
  assert,
  assertValidModuleMetaEntries,
  assertValidModuleMetaEntry,
  debug,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  fail,
  failed,
  failedCommand,
  failedCommandWithDiagnostic,
  firstRun,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isFirstRun,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
  NEEDS_APPLY,
  pause,
  recipe,
  resolveEnvironment,
  server,
  shellQuote,
  signals,
  sshdPortMeta,
  systemHostMeta,
  systemRebootMeta,
  when,
} from "paratix"

import type {
  Environment,
  EnvironmentMetaEntry,
  EnvironmentValue,
  ExecOptions,
  ExecResult,
  MetaEnvironmentValue,
  Module,
  ModuleMetaEntry,
  ModuleResult,
  ServerDefinition,
  ShutdownSignal,
  SshConfig,
  SshConnection,
  SshdPortMetaEntry,
  SystemHostMetaEntry,
  SystemRebootMetaEntry,
  UnifiedDiffOptions,
} from "paratix"

import {
  apt,
  archive,
  buildKeyValueDiff,
  buildUnifiedDiff,
  command,
  compose,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  net,
  op,
  package as pkg,
  quadlet,
  releaseUpgrade,
  restartSystemdUnit,
  rsync,
  script,
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

import type {
  PackageSpec,
  UnifiedDiffOptions as ModulesUnifiedDiffOptions,
  UpgradeOptions,
} from "paratix/modules"
```

<!-- public-api-imports:end -->

Use `paratix/modules` for built-in modules in new playbooks. The same 28 module values are also
re-exported from `paratix` for compatibility with existing playbooks, and both entry points return
the same references. Only these two package entry points are public; do not use deep imports.

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

| Method            | Signature                                                                                | Idempotent       |
| ----------------- | ---------------------------------------------------------------------------------------- | ---------------- |
| `apt.debconf`     | `(packageName: string, selections: Record<string, string>): Module`                      | Yes              |
| `apt.distUpgrade` | `(date: string, options?: UpgradeOptions): Module`                                       | Yes (dated flag) |
| `apt.key`         | `(name: string, url: string, options: { fingerprint: string }): Module`                  | Yes              |
| `apt.repository`  | `(nameOrPpa: string, source?: string, options?: { signedBy?: false \| string }): Module` | Yes              |

### `archive`

| Method            | Signature                                                                                       | Idempotent        |
| ----------------- | ----------------------------------------------------------------------------------------------- | ----------------- |
| `archive.extract` | `(source: string, destination: string, options?: { owner?: string; upload?: boolean }): Module` | Yes (SHA256 flag) |

### `command`

| Method          | Signature                                                                                                  | Idempotent        |
| --------------- | ---------------------------------------------------------------------------------------------------------- | ----------------- |
| `command.shell` | `(cmd: string, options?: { check?: string; name?: string; secrets?: string[]; timeout?: number }): Module` | Only with `check` |

`command.shell` accepts `timeout` in milliseconds to limit the runtime of the applied command. The
idempotency guard configured through `check` is not affected by this timeout.

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
| `compose.down`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman"; volumes?: boolean }): Module`                 | Yes        |
| `compose.pull`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | Partial    |
| `compose.restart` | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | No         |
| `compose.systemd` | `(options: { detached?: boolean; name?: string; projectDirectory: string; runtime?: "docker" \| "podman" }): Module` | Yes        |

> **`compose.pull` change detection:** `compose.pull` compares image digests before and after the pull to report `ok` (nothing new) vs `changed`. This needs `compose config --format json`. With `runtime: "podman"`, when the compose provider is the Python `podman-compose` (which does not support `--format json`), digest-based detection is unavailable: the pull still runs, but always reports `changed`. The Docker and Compose v2 paths are unaffected.

### `download`

| Method            | Signature                                                                                                                                                                                                                                                                                                                    | Idempotent |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `download.url`    | `(destination: string, url: string, options?: { allowInsecureHttp?: boolean; allowInsecureHttpHeaders?: boolean; allowUnverifiedDownload?: boolean; connectTimeout?: number; force?: boolean; headers?: Record<string, string>; sha256?: string; mode?: string; owner?: string; group?: string; timeout?: number }): Module` | Yes        |
| `download.github` | `(destination: string, options: { repo: string; tag: string; asset: string; token?: string; allowUnverifiedDownload?: boolean; connectTimeout?: number; sha256?: string; mode?: string; owner?: string; group?: string; timeout?: number }): Module`                                                                         | Yes        |
| `download.large`  | `(destination: string, url: string, options?: { allowInsecureHttp?: boolean; allowInsecureHttpHeaders?: boolean; allowUnverifiedDownload?: boolean; connectTimeout?: number; group?: string; headers?: Record<string, string>; mode?: string; owner?: string; sha256?: string; timeout?: number }): Module`                  | Yes (flag) |

Downloads require an explicit integrity decision at runtime: provide `sha256`
for verification, or set `allowUnverifiedDownload: true` when the remote
artifact is intentionally trusted without a pinned digest. `download.url` and
`download.large` allow only HTTPS by default; set `allowInsecureHttp: true`
only when an `http://` source or redirect is intentional. Sensitive headers
such as `Authorization`, `Cookie`, and `X-Api-Key` are still rejected over
plaintext HTTP unless `allowInsecureHttpHeaders: true` is also set.
Curl-based downloads use bounded transfer timing by default (`connectTimeout:
10000`, `timeout: 300000`, both in milliseconds). Override these options for
very slow artifact hosts or large downloads.

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

**Note on `owner` and `group` values:** Every ownership option accepts either a POSIX name or a
numeric id — `owner: "www-data:www-data"` and `owner: "65532:65532"` are both valid, and the two
components may be mixed (`owner: "root:65532"`). Numeric ids are the only option for accounts that
have no passwd or group entry on the target host, such as `65532` in distroless images or `70` in
the postgres image. Drift detection compares the declared value against both the name and the id
reported by the host, so a numerically declared owner converges to `status: "ok"` like a named one.
`file.properties` keeps `owner` and `group` as separate options and therefore rejects a combined
`"user:group"` spec.

**Note on `file.copy` and the default mode:** When `options.mode` is omitted, `file.copy` sets the mode to the documented default of `0644`. The mode is applied during upload (`uploadFile` with `{ mode }`) and compared with the desired value in `check`, so subsequent runs detect mode drift (for example, a manual `chmod 0600`) as `needs-apply`. Pass `{ mode: "0600" }` explicitly when more restrictive permissions are required, such as for secrets.

**Note on `file.line`:** The `line` value must be a single line without CR/LF characters. Use `file.block` for multiline content.

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

### `net`

| Method          | Signature                                                                                                                                                                                               | Idempotent |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `net.hosts`     | `(ip: string, hostnames: string[], options?: { state?: "absent" \| "present" }): Module`                                                                                                                | Yes        |
| `net.interface` | `(name: string, options: { addresses?: string[]; dhcp?: boolean; gateway?: string; nameservers?: string[] }): Module`                                                                                   | Yes        |
| `net.request`   | `(url: string, options?: { allowInsecureHttpHeaders?: boolean; body?: string; connectTimeout?: number; headers?: Record<string, string>; method?: string; status?: number; timeout?: number }): Module` | Yes        |
| `net.resolv`    | `(options: { nameservers: string[]; search?: string[] }): Module`                                                                                                                                       | Yes        |
| `net.route`     | `(destination: string, gateway: string, options?: { device?: string; state?: "absent" \| "present" }): Module`                                                                                          | Yes        |
| `net.waitFor`   | `(options: { contains?: string; file?: string; host?: string; interval?: number; port?: number; timeout?: number }): Module`                                                                            | Yes        |

`net.request` uses bounded curl timing by default (`connectTimeout: 10000`,
`timeout: 300000`, both in milliseconds). Override these values for endpoints
that are expected to respond more slowly.

### `op`

| Method       | Signature                                      | Idempotent                        |
| ------------ | ---------------------------------------------- | --------------------------------- |
| `op.resolve` | `(references: Record<string, string>): Module` | No (always-applies, runs locally) |

Inside a `runPlaybook` run, every `op.resolve` reference in the definition
is read up front, before the SSH connect: all `op read` calls (and any
provider prompt they trigger, e.g. a biometric unlock or `op signin`) happen
once, right after the command starts, instead of somewhere in the middle of
the run at the module's own position. The module still runs at its position
in `run` and emits the same meta as before -- it just serves the value from
that up-front resolution instead of invoking `op` again. A failure during
this phase aborts the whole run before any connection is opened, with exit
code 2, instead of surfacing as a failed module later on. This phase also
runs during `--dry-run`, and `--filter` prints a warning (without changing
run behavior) when it removes a module that would have resolved secrets.
This up-front timing does not change what `op.resolve()` can feed into
`SshConfig` -- see [Anti-Pattern 16](#dos-and-donts) below.

### `package`

Import with renaming: `import { package as pkg } from "paratix/modules"`. The word `package` is reserved in JavaScript, so you must alias it.

| Method              | Signature                                                                         | Idempotent       |
| ------------------- | --------------------------------------------------------------------------------- | ---------------- |
| `package.installed` | `(...packagesAndOptions: Array<string \| PackageSpec \| UpgradeOptions>): Module` | Yes              |
| `package.absent`    | `(...packagesAndOptions: Array<string \| PackageSpec \| UpgradeOptions>): Module` | Yes              |
| `package.update`    | `(date: string, options?: UpgradeOptions): Module`                                | Yes (dated flag) |
| `package.upgrade`   | `(date: string, options?: UpgradeOptions): Module`                                | Yes (dated flag) |

#### `UpgradeOptions`

```typescript
type UpgradeOptions = {
  timeout?: number // Override SSH command timeout (ms). Same value applies to every step
  // of multi-step pipelines (apt upgrade, apk upgrade, apt dist-upgrade).
}
```

For `package.installed` and `package.absent`, pass the options object as the **last** argument after
the package names. Existing variadic calls such as `pkg.installed("git", "curl")` continue to work
unchanged. Use a higher `timeout` for slow operations on production servers with a large update
backlog:

```typescript
pkg.upgrade("2026-05-01", { timeout: 900_000 })
pkg.installed("texlive-full", { timeout: 900_000 })
apt.distUpgrade("2026-05-01", { timeout: 1_200_000 })
```

#### `PackageSpec` — Version Pinning

```typescript
type PackageSpec = {
  name: string
  version?: string // Exact target version. Without `version`, only presence is enforced.
}
```

Pin a package to an exact version by passing a `PackageSpec` object instead of a string. A plain
`"grafana"` string is equivalent to `{ name: "grafana" }` without a pin. Package-manager-specific
syntax such as `name=version` or `name-version` is **not** accepted as a pass-through string; a
string containing `=` remains an invalid package name. Arguments are distinguished by their
**shape**, not their position: an object **with** a `name` field is a `PackageSpec` and may also be
the last argument, while a final object **without** a `name` field is `UpgradeOptions`.

```typescript
pkg.installed({ name: "grafana", version: "13.1.0" })
pkg.installed("curl", { name: "grafana", version: "13.1.0" }, { timeout: 600_000 })
```

Installation token by package manager:

| Package manager | Installation token | Example                |
| --------------- | ------------------ | ---------------------- |
| apt             | `name=version`     | `grafana=13.1.0`       |
| apk             | `name=version`     | `grafana=13.1.0-r0`    |
| dnf / yum       | `name-version`     | `grafana-13.1.0-1.el9` |

Semantics:

- **`check`** compares the installed version with the pinned version; any mismatch returns
  `needs-apply`. Without a pinned version, it remains a presence check.
- **`apply`** installs exactly the pinned version, including a **downgrade**. For apt, a pinned
  version automatically adds `--allow-downgrades`. If dnf/yum finds a newer installed version, it
  uses `dnf downgrade` or `yum downgrade` instead of `install` (apk installs the exact version in
  either direction without an extra flag). The dnf/yum direction check uses a version-aware
  comparison on the target host (`sort -V`) so multi-digit components such as `13.9.0` and
  `13.10.0` are ordered correctly.
- After installation, Paratix verifies the installed version. A partial or incorrect version
  reports `failed`, not `changed`.
- **No hold.** Paratix only installs the version; it creates no `apt-mark hold` marker or
  `preferences.d` file. A later `apt upgrade` can therefore upgrade the package again unless the
  pinned playbook runs again.

Valid versions start with an alphanumeric character and may contain `[A-Za-z0-9]` plus
`. + ~ : _ -`. This covers apt epoch/revision values such as `1:2.3-1ubuntu0.2` and RPM
`version-release` values such as `13.1.0-1.el9`. Whitespace and shell metacharacters are rejected.
`package.absent` is name-based; passing a `PackageSpec` with `version` produces a clear error.

### `quadlet`

| Method                | Signature                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Idempotent |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `quadlet.container`   | `(options: { addCapability?: string[]; addDevice?: string[]; annotation?: Record<string, string>; autoUpdate?: "local" \| "registry"; containerName?: string; description?: string; dns?: string[]; dnsOption?: string[]; dnsSearch?: string[]; dropCapability?: string[]; entrypoint?: string[]; environment?: Record<string, string>; environmentFiles?: string[]; exec?: string[]; exposeHostPort?: string[]; groupAdd?: string[]; healthCmd?: string; healthInterval?: string; healthOnFailure?: "kill" \| "none" \| "restart" \| "stop"; healthRetries?: number; healthStartPeriod?: string; healthTimeout?: string; hostName?: string; image: string; ip?: string; ip6?: string; label?: Record<string, string>; logDriver?: string; mask?: string[]; mount?: string[]; name: string; networks?: string[]; noNewPrivileges?: boolean; notify?: boolean; podmanArgs?: string[]; publishPorts?: string[]; pull?: "always" \| "missing" \| "never" \| "newer"; readOnly?: boolean; restart?: "always" \| "no" \| "on-abnormal" \| "on-abort" \| "on-failure" \| "on-success" \| "on-watchdog"; runInit?: boolean; secret?: string[]; seccompProfile?: string; securityLabelDisable?: boolean; securityLabelType?: string; stopTimeout?: number; sysctl?: Record<string, string>; timeoutStartSec?: number; timeoutStopSec?: number; timezone?: string; tmpfs?: string[]; ulimit?: string[]; unmask?: string[]; user?: string; userNs?: string; volumes?: string[]; wantedBy?: string; workingDir?: string }): Module` | Yes        |
| `quadlet.network`     | `(options: { description?: string; disableDns?: boolean; dns?: string[]; driver?: string; gateway?: string; internal?: boolean; ipRange?: string; ipamDriver?: string; ipv6?: boolean; label?: Record<string, string>; name: string; options?: Record<string, string>; podmanArgs?: string[]; subnet?: string }): Module` — writes `/etc/containers/systemd/<name>.network`; reference it from a container via `networks: ["<name>.network"]`. When the change lands and a network with the same name is already live, `changed` carries an advisory detail that the running network is not recreated until removed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Yes        |
| `quadlet.updateImage` | `(options: { authFile?: string; containerName?: string; image: string; name: string; serviceName?: string }): Module` — returns `changed` with the new registry digest (or local image ID fallback) in parentheses when a newer image was pulled. Fails before pulling when a container of the managed name is owned by something other than this unit (see [Quadlet conflict guard](#quadlet-conflict-guard))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Partial    |

### `releaseUpgrade`

| Method                   | Signature                                                                                                                                            | Idempotent |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `releaseUpgrade.upgrade` | `(options?: { dryRun?: boolean; resolveHost?: (signal?: AbortSignal) => Promise<string>; resolveHostTimeoutMs?: number; timeout?: number }): Module` | Yes        |

### `rsync`

| Method       | Signature                                                                                                                                                                                                                                      | Idempotent |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `rsync.sync` | `(options: { src: string; dest: string; chmod?: string; delete?: boolean; exclude?: string[]; group?: string; include?: string[]; owner?: string; strictHostKeyChecking?: "accept-new" \| "no" \| "off" \| "yes"; timeout?: number }): Module` | Yes        |

When the active Paratix SSH session already verified the host via `ssh.expectedHostFingerprint`
or `ssh.expectedHostPublicKey`, `rsync.sync()` reuses that verified host key for the external
rsync SSH process and does not depend on a local `known_hosts` entry.

### `script`

| Method        | Signature                                                                                    | Idempotent           |
| ------------- | -------------------------------------------------------------------------------------------- | -------------------- |
| `script.once` | `(name: string, localPath: string, options?: { args?: string[]; version?: string }): Module` | Yes (versioned flag) |

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

**Trust anchor requirement for `ssh.knownHosts` (`state: "present"`):** In the default `present` state, either `expectedFingerprint` or `publicKey` must be set. Without a trust anchor, the module constructor throws immediately because `check` would otherwise treat any existing `known_hosts` entry, including older and potentially compromised TOFU acceptances, as `ok` and skip the anchor comparison. No anchor is required for `state: "absent"`, because that state removes the entry.

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

| Method       | Signature                                                                                                | Idempotent                                                                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `sysctl.set` | `(key: string, value: string, options?: { resetValue?: string; state?: "absent" \| "present" }): Module` | Yes for `present`. For `absent`: only the persistence file is removed by default; pass `resetValue` to also restore the live runtime value. |

### `system`

| Method          | Signature                                                                                                        | Idempotent                                          |
| --------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `system.facts`  | `(): Module`                                                                                                     | No (always-applies, emits typed `env` meta entries) |
| `system.reboot` | `(options?: { resolveHost?: (signal?: AbortSignal) => Promise<string>; resolveHostTimeoutMs?: number }): Module` | No (always-applies)                                 |
| `system.uptime` | `(): Module`                                                                                                     | No (always-applies, emits typed `env` meta entries) |

### `systemd`

| Method                 | Signature                                 | Idempotent                         |
| ---------------------- | ----------------------------------------- | ---------------------------------- |
| `systemd.unit`         | `(name: string, content: string): Module` | Yes                                |
| `systemd.daemonReload` | `(): Module`                              | No (always-applies, use as signal) |
| `systemd.masked`       | `(name: string): Module`                  | Yes                                |
| `systemd.unmasked`     | `(name: string): Module`                  | Yes                                |

### `timer`

| Method            | Signature                                                                                                                                                                                                                                                                                                                                                             | Idempotent |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `timer.scheduled` | `(name: string, options: { accuracySec?: number \| string; description?: string; environment?: Record<string, string>; exec: string; group?: string; onCalendar: string \| string[]; onFailure?: string \| string[]; persistent?: boolean; randomizedDelaySec?: number \| string; state?: "absent" \| "present"; user?: string; workingDirectory?: string }): Module` | Yes        |
| `timer.absent`    | `(name: string): Module`                                                                                                                                                                                                                                                                                                                                              | Yes        |

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

Use `onFailure` to attach a notification unit, so an unattended job that starts
failing does not stay silent until someone reads journald. Each entry becomes
one `OnFailure=` line in the `[Unit]` section of the generated `.service`, and
systemd specifiers are passed through unescaped, so `%n` resolves to the failing
unit's name:

```typescript
timer.scheduled("restic-backup", {
  exec: "/usr/local/bin/restic-backup",
  onCalendar: "*-*-* 02:30:00",
  onFailure: "notify@%n.service",
})
```

The referenced handler unit is yours to provide, for example as a
`notify@.service` template via `systemd.unit`. Entries are restricted to
systemd unit-name characters plus `%`; a value containing whitespace, `#` or a
line break is rejected. For anything the option cannot express, write the unit
yourself with `systemd.unit`.

### `ufw`

| Method         | Signature                                                        | Idempotent |
| -------------- | ---------------------------------------------------------------- | ---------- |
| `ufw.disabled` | `(): Module`                                                     | Yes        |
| `ufw.enabled`  | `(): Module`                                                     | Yes        |
| `ufw.rule`     | `(action: "allow" \| "deny", ports: number \| number[]): Module` | Yes        |

### `user`

| Method         | Signature                                                                                                                                    | Idempotent |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `user.present` | `(name: string, options?: { uid?: number; shell?: string; home?: string; homeMode?: string; groups?: string[]; password?: string }): Module` | Yes        |
| `user.absent`  | `(name: string, options?: { removeHome?: boolean }): Module`                                                                                 | Yes        |

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
      await ssh.writeFile(configPath, content, { mode: "0644" })
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
- Prefer `failedCommand("...", result)` when you used `ssh.exec(..., { ignoreExitCode: true })` and want stdout/stderr preserved for central runner output. It carries the first few non-empty output lines (bounded by a line and byte budget) so multi-line diagnostics such as systemd's `See "journalctl -xeu <unit>"` hint are not dropped; the full streams stay on `CommandError.fullStderr`/`fullStdout` for `--verbose`.
- Use `failedCommandWithDiagnostic({ ... })` when a best-effort follow-up probe supplies the cause missing from a failed command's own output.
- Use `restartSystemdUnit({ ... })` from `paratix/modules` for a bounded, attempt-scoped systemd restart diagnostic.
- Return `NEEDS_APPLY` (the exported constant), never the string literal `"needs-apply"`.
- `ModuleResult.status` must be one of: `"changed"`, `"failed"`, `"ok"`, `"skipped"`.
- Optionally return `ModuleResult.detail` with a short single-line reason; the runner appends it to the step line. Use it to say what a `changed` step actually did, and leave it unset when the step did no work. See [Status Detail on Changed Steps](#status-detail-on-changed-steps).
- Use typed `meta` entries in the return value, not loose objects.
- For normal downstream environment propagation, use `meta.env(name, value)`.
- `meta.env(...)` accepts strings, numbers, booleans, sync lazy functions, and async lazy functions.
- `meta.env(...)` is normalized internally to an async resolver, so downstream code should treat propagated environment values as lazily async and resolve them via `resolveEnvironment(...)` when it needs the concrete primitive.
- Use dedicated built-in meta entries only for runner control-plane effects, for example `meta.sshdPort(...)`, `meta.systemHost(...)`, and `meta.systemReboot()`.
- Use the exported guards such as `isEnvironmentMetaEntry(...)`, `isStringEnvironmentMetaEntry(...)`, `isNumberEnvironmentMetaEntry(...)`, `isBooleanEnvironmentMetaEntry(...)`, `isLazyEnvironmentMetaEntry(...)`, `isSshdPortMetaEntry(...)`, `isSystemHostMetaEntry(...)`, and `isSystemRebootMetaEntry(...)` when you need to inspect meta entries safely.
- Set `local: true` on the module object if it runs on the local machine (ssh will be `null`).

### Failure, restart, and diff helpers

| Helper                        | Signature                                                                                                                       | Result                                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `failedCommandWithDiagnostic` | `(parameters: { diagnostic: null \| string; message: string; result: ExecResult; secrets?: string[] }): ModuleResult`           | A failed result with bounded command output and the optional, secret-masked diagnostic. |
| `restartSystemdUnit`          | `(parameters: { failureMessage: string; secrets?: string[]; ssh: SshConnection; unit: string }): Promise<ModuleResult \| null>` | `null` on success; otherwise a failed result with a best-effort journal excerpt.        |
| `buildUnifiedDiff`            | `(current: string, desired: string, options?: UnifiedDiffOptions): string`                                                      | Unified diff text, or `""` when the normalized inputs are identical.                    |
| `buildKeyValueDiff`           | `(key: string, currentValue: null \| string, desiredValue: string): string`                                                     | A compact scalar diff, or `""` when both values match.                                  |

`UnifiedDiffOptions` has three optional fields: `contextLines?: number` (default `3`, clamped to
at least `0`), `currentLabel?: string` (default `"current"`), and `desiredLabel?: string` (default
`"desired"`). The diff helpers are available from `paratix/modules` and are re-exported at the
root for compatibility; `UnifiedDiffOptions` is exported as a type from both entry points.

### Meta API

Use the `meta` object for normal module authoring. Its `env`, `sshdPort`, `systemHost`, and
`systemReboot` methods create the four public meta-entry variants. The same constructors are also
available as `environmentMeta`, `sshdPortMeta`, `systemHostMeta`, and `systemRebootMeta` for
advanced code that prefers standalone functions.

The remaining public helpers cover validation, narrowing, and conversion:

| Purpose                      | Public helpers                                                                                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Validate entries             | `assertValidModuleMetaEntry`, `assertValidModuleMetaEntries`                                                                                            |
| Narrow environment entries   | `isEnvironmentMetaEntry`, `isBooleanEnvironmentMetaEntry`, `isLazyEnvironmentMetaEntry`, `isNumberEnvironmentMetaEntry`, `isStringEnvironmentMetaEntry` |
| Narrow control-plane entries | `isSshdPortMetaEntry`, `isSystemHostMetaEntry`, `isSystemRebootMetaEntry`                                                                               |
| Convert environments         | `environmentToMetaEntries`, `diffEnvironmentToMetaEntries`, `mergeEnvironmentFromMeta`                                                                  |

### SshConnection API

Methods available on the `ssh` parameter:

| Method                                            | Return type                                                                                                 | Description                                                                                            |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `ssh.addPort(port)`                               | `boolean`                                                                                                   | Register a reconnect candidate; return `true` when it was added.                                       |
| `ssh.disconnect()`                                | `void`                                                                                                      | Close the SSH connection.                                                                              |
| `ssh.downloadFile(remotePath, localPath)`         | `Promise<void>`                                                                                             | Download a remote file.                                                                                |
| `ssh.exec(command, options?)`                     | `Promise<ExecResult>`                                                                                       | Run a command and return `{ code, stdout, stderr }`. Throws on non-zero unless `ignoreExitCode: true`. |
| `ssh.exists(remotePath)`                          | `Promise<boolean>`                                                                                          | Check whether a remote path exists.                                                                    |
| `ssh.getConnectionInfo()`                         | `{ agentSocket?, authMethod?, configuredPorts, host, port, privateKeyPath?, user, verifiedHostPublicKey? }` | Return the active connection and authentication details.                                               |
| `ssh.lines(command)`                              | `Promise<string[]>`                                                                                         | Run a command and return stdout split into lines.                                                      |
| `ssh.output(command)`                             | `Promise<string>`                                                                                           | Run a command and return trimmed stdout.                                                               |
| `ssh.probeSudo()`                                 | `Promise<void>`                                                                                             | Probe and cache sudo access, prompting interactively if needed.                                        |
| `ssh.readFile(remotePath)`                        | `Promise<string>`                                                                                           | Read the full contents of a remote file.                                                               |
| `ssh.reconnect(options?)`                         | `Promise<void>`                                                                                             | Reconnect; `options.defaultTimeout` supplies a call-specific fallback in milliseconds.                 |
| `ssh.removePort(port)`                            | `void`                                                                                                      | Remove a registered reconnect candidate.                                                               |
| `ssh.sha256(remotePath)`                          | `Promise<string \| null>`                                                                                   | Return the SHA-256 hex digest, or `null` when the file is not found.                                   |
| `ssh.test(command)`                               | `Promise<boolean>`                                                                                          | Run a command and return whether its exit code is zero.                                                |
| `ssh.updateHost(host)`                            | `void`                                                                                                      | Update the target host address.                                                                        |
| `ssh.uploadFile(localPath, remotePath, options?)` | `Promise<void>`                                                                                             | Upload through SFTP; `options.mode` defaults to `"0600"`.                                              |
| `ssh.writeFile(remotePath, content, options?)`    | `Promise<void>`                                                                                             | Create or replace a remote file; `options.mode` defaults to `"0600"`.                                  |

`getConnectionInfo().authMethod`, when present, is `"agent"`, `"password"`, or `"privateKey"`.
`reconnect` accepts `options?: { defaultTimeout?: number }`; `uploadFile` and `writeFile` accept
`options?: { mode?: string }`.

### ExecOptions

```typescript
{
  env?: Record<string, string>       // Extra environment variables
  ignoreExitCode?: boolean           // Don't throw on non-zero exit
  input?: string                     // Payload written to stdin before EOF
  maxOutputBytes?: number            // Cap stored stdout/stderr bytes
  secrets?: string[]                 // Strings to mask in error output
  silent?: boolean                   // Suppress stdout/stderr
  timeout?: number                   // Abort after N milliseconds
}
```

Prefer `input` for secret payloads instead of shell arguments, so values do not
leak through process lists, `/proc/<pid>/cmdline`, or SSH logs. Add the same
values to `secrets` only as an additional masking guard for error output.

## Template System

Files deployed via `file.template(remotePath, localTemplatePath)` can contain `{{KEY}}` placeholders.

- Placeholders are resolved at runtime from the `env` object of `server()` and from typed `meta.env(...)` entries returned by previous modules.
- Environment values can be strings, numbers, booleans, sync lazy functions, or async lazy functions.
- Values propagated through `meta.env(...)` are normalized to async resolution before downstream modules or templates consume them.
- Escaping: `\{{` produces a literal `{{` in the output.
- Unknown keys throw an error at runtime.
- **Modifiers:** the built-in modifiers are `shell` (applies `shellQuote()` to the value), `raw` (explicit verbatim insertion) and `b64decode` (see below).
- **Modifier chains.** Modifiers can be chained and are applied left to right: `{{KEY|b64decode|shell}}` decodes first and quotes the result. The order is yours to get right — `{{KEY|shell|b64decode}}` tries to decode the quoted string and fails.
- **`b64decode`.** Decodes a base64-encoded value into the text it represents. Use it for multi-line secrets — PEM/OpenSSH private keys, certificates — that are stored base64-encoded on a single line because the secret manager mangles embedded newlines. Whitespace is stripped and missing padding is normalized; a foreign alphabet (including base64url), a non-canonical final group, or bytes that are not valid UTF-8 throw instead of writing corrupted output. Error messages never contain the value or the decoded bytes.
- **`b64decode` is for file targets.** It fits SSH keys, certificates and kubeconfigs rendered with `file.template`. It does **not** make a multi-line value usable inside a systemd `EnvironmentFile` — those have their own quoting rules, and a decoded PEM still breaks the parser.
- **Strict mode (default: on).** Every placeholder must have at least one explicit modifier. Bare `{{KEY}}` placeholders throw at render time. Pass `strict: false` in the options to disable this check.
- **Security: No default escaping.** Values are inserted verbatim. If the template produces a shell script or shell config, **always** use `{{KEY|shell}}` for every variable — omitting `|shell` can lead to shell injection. `b64decode` is a transform, not an escape: a chain without `shell` inserts the decoded value verbatim.
- **Secrets in dry runs.** `file.template` renders its `--dry-run` diff from the final content, unmasked. A decoded private key is therefore visible in that diff.

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
- Signals follow the same failure rule as modules: a failed signal stops the remaining signals of
  that list, and the recipe or run status becomes `"failed"`. There is no `continueOnError`. Put
  restarts that must all be attempted independently into separate signal lists. See
  [ADR-0006](../../docs/adr/0006-signal-lists-stop-at-the-first-failed-signal.md).
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
A block whose condition holds is itemized like a recipe — header, one line per
guarded module, closing line; a block whose condition is false reports a single
`skipped` line. See [Dry-Run Diff Output](#dry-run-diff-output---diff).

```typescript
when((env) => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban"), ufw.enabled())
```

### `when.packageInstalled(name, ...modules)` / `when.packageAbsent(name, ...modules)`

Conditionally run modules based on package state on the remote host.

```typescript
when.packageInstalled("ufw", ufw.disabled())
when.packageAbsent("docker-ce", pkg.installed("docker-ce"))
```

### `when.commandExists(name, ...modules)` / `when.commandMissing(name, ...modules)`

Conditionally run modules based on whether a command exists on the remote host.

```typescript
when.commandExists("docker", service.running("docker"))
when.commandMissing("docker", pkg.installed("docker-ce"))
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

Stops the current run cleanly when Paratix was started with `--first-run`. Useful as an explicit staging boundary in bootstrap playbooks.

```typescript
firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")
```

### `isFirstRun()`

Returns `true` while the CLI imports and evaluates a playbook passed to `paratix apply --first-run`.
Use it only while constructing the exported server definition:

```typescript
import { isFirstRun, server, type Module } from "paratix"

const bootstrapModules: Module[] = []
const regularModules: Module[] = []

export default server({
  host: "10.0.0.1",
  name: "web-01",
  run: isFirstRun() ? bootstrapModules : regularModules,
  ssh: { ports: [22], user: "root" },
})
```

The first-run context ends after import and definition generation. `isFirstRun()` therefore
returns `false` later inside module `check` and `apply` methods, and there is no public `init` hook.
The helper reads an async-local context; the CLI does not mutate
`process.env.PARATIX_FIRST_RUN`.

### `signals.flush(message?)`

Immediately runs all currently pending signals in the active scope and clears their pending state.

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

## Status Detail on Changed Steps

A module may return a short `detail` next to its status. The runner appends it to
the step line, both for top-level modules and for steps inside a recipe:

```
· · ↺  package.upgrade: 2026-03-01    changed  no packages upgraded  4.1s
```

The dated-flag modules use this to say **why** they ran. Their step name already
carries the date, so the detail reports the outcome instead of repeating the key.
This matters most for the upgrade modules: they report `changed` whenever their
dated marker is absent, even when the package manager upgraded nothing.

| Module            | Detail on `changed`                                                     |
| ----------------- | ----------------------------------------------------------------------- |
| `package.update`  | `marker was missing, package index refreshed`                           |
| `package.upgrade` | `12 packages upgraded`, `1 package upgraded`, or `no packages upgraded` |
| `apt.distUpgrade` | same forms as `package.upgrade`                                         |

Rules:

- The count is parsed from apt's upgrade summary. `package.upgrade` also serves
  `dnf`, `yum` and `apk`, whose summaries differ; those report
  `upgrade completed, package count unavailable`.
- The same fallback applies when the summary line is missing from the output, or
  when the captured output was truncated at `maxOutputBytes`. apt prints its
  summary last, so a truncated capture loses exactly that line, and reporting no
  count is preferred over reporting a wrong one.
- A step that did no work carries no detail: the flag-already-exists path returns
  a plain `ok`, and failures report through the normal error path.
- Dry runs keep the generic `changed (dry-run)` suffix. The detail is produced by
  `apply`, which does not run in dry-run mode.

Custom modules may return `detail` the same way; see
[Key rules for custom modules](#key-rules-for-custom-modules).

## Dry-Run Diff Output (`--diff`)

Paratix runs a playbook in dry-run mode via `paratix apply <file> --dry-run`, which
reports per-module `changed (dry-run)` or `ok` based on each module's `check()`.
A recipe is always itemized in a dry run — at any nesting depth it prints its
`[name]` header plus one line per child, and that itemization on its own says
nothing about diffs. A `when(...)` block is itemized the same way: when its
condition holds it prints its own `[name]` header, one line per guarded module
and a closing line with the aggregated status, in a dry run as well as in an
apply. When the condition is false the block reports a single `skipped` line
without a header, and the run summary counts it under `skipped`.

`--diff` enables a second, opt-in layer: modules that mark themselves as diff
producers also render a unified-diff block under their status line so the user
sees _what_ would change, not only _that_ something would change.

```
$ paratix apply server.ts --dry-run --diff
  ↺  /etc/ssh/sshd_config                            changed  (dry-run)
     │ --- /etc/ssh/sshd_config
     │ +++ /local/path/sshd_config
     │ -Port 22
     │ +Port 2222
```

Rules:

- `--diff` requires `--dry-run`. The CLI rejects `paratix apply <file> --diff`
  without `--dry-run` before any SSH connection or playbook side effect.
- Without `--diff`, the dry-run runs are byte-identical to before: no extra
  remote round-trips, no diff output.
- Modules that do not opt in keep showing only `changed (dry-run)`.
- Every diff line is masked through the registered-secret sink and a terminal
  sanitizer before printing, so secret-laden file contents never leak verbatim.
- Inline status detail and multi-line diff blocks are independent output layers. A built-in module
  may emit both at once; the runner renders detail next to the status line and the diff below it.

Diff-producing built-in modules:

| Module                                      | Diff content                                                                                                                                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `file.copy`                                 | Unified diff between the remote file and the local source.                                                                                                                                                                                                               |
| `file.template`                             | Unified diff between the remote file and the rendered template.                                                                                                                                                                                                          |
| `sysctl.set`                                | `key = old → new` for the desired configuration.                                                                                                                                                                                                                         |
| `hostname.set`                              | `hostname = old → new`.                                                                                                                                                                                                                                                  |
| `swap.file`                                 | Diff of the `/etc/fstab` entry (or removal of the line for `state: "absent"`).                                                                                                                                                                                           |
| `swap.swappiness`                           | `vm.swappiness = old → new` (via `sysctl.set`).                                                                                                                                                                                                                          |
| `swap.vfsCachePressure`                     | `vm.vfs_cache_pressure = old → new` (via `sysctl.set`).                                                                                                                                                                                                                  |
| `cron.job` / `cron.absent`                  | Unified diff of the target user's crontab.                                                                                                                                                                                                                               |
| `timer.scheduled` (present)                 | Concatenated diffs of the `.service` and `.timer` unit files.                                                                                                                                                                                                            |
| `timer.scheduled` (absent) / `timer.absent` | List of unit files to remove.                                                                                                                                                                                                                                            |
| `net.hosts`                                 | Unified diff of `/etc/hosts`.                                                                                                                                                                                                                                            |
| `quadlet.container`                         | Unified diff of the `.container` unit file. If the file already matches but the `daemon-reload` flag is missing, `(dry-run, daemon-reload pending)` also appears as a detail suffix. A conflicting foreign container is reported in every dry run, `--diff` or not.      |
| `quadlet.network`                           | Unified diff of the `.network` unit file. If the file already matches but the `daemon-reload` flag is missing, `(dry-run, daemon-reload pending)` also appears as a detail suffix. When a network with the same name is already live, the advisory hint is appended too. |

### Quadlet conflict guard

`quadlet.container` and `quadlet.updateImage` inspect the container the unit
manages before doing any work, and fail with an actionable message when that
container is owned by something other than the unit. Podman refuses to replace a
foreign container, and without the guard the failure surfaced only as
`systemctl restart failed (exit code 1)` — or not at all, because an unchanged
image skips the restart entirely and the module reported `ok` while a foreign
container was the one actually running.

The managed container name is `containerName ?? systemd-<name>`, mirroring
Quadlet's own default. Set `containerName` on `quadlet.updateImage` whenever
`quadlet.container` sets it, so both inspect the same container.

The guard reports a conflict only on **positive** evidence of foreign ownership:

- a Compose project label (`com.docker.compose.project` or
  `io.podman.compose.project`), which is what a Compose-to-Quadlet migration
  leaves behind, or
- a `PODMAN_SYSTEMD_UNIT` value naming a different unit.

Anything else — no metadata, an unreadable projection, or a probe that fails —
is deliberately **not** treated as evidence and the apply proceeds unchanged. A
false positive would fail every rollout, while a false negative merely falls back
to the journal excerpt that a failed `systemctl restart` already carries. A
container that a Quadlet unit started itself is never a conflict:
`PODMAN_SYSTEMD_UNIT` holds the full unit name (`%n`), so both sides are
normalized before comparison.

The `quadlet.container` conflict guard also runs in a plain `--dry-run`; its unit-file diff still
requires `--diff`.

### Custom-module diff output

`buildUnifiedDiff` and `buildKeyValueDiff` from `paratix/modules` are public formatting helpers.
`UnifiedDiffOptions` is available as a type from either public entry point. Runner integration for a
custom diff is not a stable extension API, however: custom modules should use the documented `check`
and `apply` contract and may return a short `detail`; do not depend on internal module fields.

## Do's and Don'ts

### DO

1. Always use `export default server({...})` as the default export of a playbook.
2. Import modules from `"paratix/modules"` in new code. Root re-exports remain supported for compatibility.
3. `package` must be aliased on import: `import { package as pkg } from "paratix/modules"` -- `package` is a reserved word in JavaScript.
4. For idempotency with `command.shell()`, always provide a `check` command.
5. Use `{{KEY|shell}}`, `{{KEY|raw}}` or a chain such as `{{KEY|b64decode|shell}}` in `.tmpl` files — strict mode is on by default and bare `{{KEY}}` will throw. Provide values via `env` in `server()`.
6. Use `service.restart()` and `service.reload()` as `signals` in recipes, not directly in `run`.
7. Use `signals.flush()` only as an explicit checkpoint when staged flows require an early signal flush.
8. Always pass a date string to `package.upgrade()` and `package.update()` -- it is the idempotency key. Each distinct date keeps its own flag file, so several calls with different dates coexist; a date that was already applied stays applied and is not re-run. Read the step's [status detail](#status-detail-on-changed-steps) to tell a real upgrade from a step that only wrote its marker.
9. Specify `ssh.ports` as an array -- the runner tries each port in order.
10. Custom modules must implement both `check` and `apply`, both async.
11. Use `shellQuote()` when interpolating dynamic values into shell commands.
12. Emit downstream values via `meta.env(...)` and use dedicated built-in meta entries only for runner control-plane behavior.
13. When you need a concrete propagated value inside custom code, use `await resolveEnvironment(env, "KEY")` instead of assuming `env["KEY"]` is already a plain primitive.

### DON'T

1. Do NOT use deep imports. The only public paths are `"paratix"` and `"paratix/modules"`.
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
12. `signals.flush()` always flushes only the current scope:
    - inside a recipe, that recipe's signals
    - at the top level, `server(...).signals`
13. Do NOT call `server()` without all required fields (`name`, `host`, `ssh`, `run`) -- it throws at construction time. `name` and `host` must not be empty strings.
14. Do NOT use empty arrays for `ssh.ports` or empty strings for `ssh.user`/`ssh.privateKey` -- validation rejects these. `ssh.privateKey` may be omitted entirely to use the SSH agent instead.
15. Do NOT return loose `meta: { ... }` maps from custom modules -- always use typed meta entries.
16. Do NOT set `ssh.sudoPassword` to a value from `op.resolve()` or `meta.env()` -- `SshConfig` is frozen at server construction time, before any module in `run` executes. This still holds even though `op.resolve` now resolves its references up front, right after the command starts: that up-front resolution runs inside `runPlaybook`, which is already after construction time, so it is exactly as unreachable for `SshConfig` as the module's own `apply()` step always was. Use a static source like `process.env.SUDO_PASSWORD` or a variable populated before the server definition is imported.

## Testing Patterns

Tests use vitest with a `createMockSsh` helper:

```typescript
import { describe, expect, it } from "vitest"
import { NEEDS_APPLY } from "paratix"

import { createMockSsh } from "./helpers/mockSsh.js"

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
- Unknown commands fail closed with an error. Add every expected command to the
  response map, or the helper throws instead of returning a successful default.
- `ssh.test(cmd)` returns `code === 0`.
- `ssh.exists(path)` delegates to `ssh.test("[ -e '<path>' ]")`.
- `ssh.readFile(path)` delegates to `ssh.output("cat '<path>'")`.
- Returns a `{ calls: string[] } & SshConnection` object -- `calls` records all commands in execution order.
