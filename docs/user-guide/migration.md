# Migration Notes

This page lists only confirmed changes that require action in an existing project. Additive features, internal changes, and fixes that require no user action remain in the package changelogs.

## `paratix`

### 0.2.0: Node.js 24 or newer

**Before:** Paratix could run on older Node.js versions.

**Now:** The package requires Node.js `>=24.0.0`.

**Upgrade:** Upgrade the local and CI runtimes to Node.js 24 or newer before installing.

### 0.2.0: environment type names

**Before:** Consumers imported `Env` and `EnvValue`.

**Now:** The public types are named `Environment` and `EnvironmentValue`.

**Upgrade:** Rename imports and type annotations from `Env` to `Environment` and from `EnvValue` to `EnvironmentValue`.

### 0.2.0: typed module metadata

**Before:** `ModuleResult.meta` accepted untyped metadata values.

**Now:** `ModuleResult.meta` is `ModuleMetaEntry[]`.

**Upgrade:** Convert custom module metadata to supported `ModuleMetaEntry` objects and import that type from `paratix`.

### 0.2.0: SSH authentication details became optional

**Before:** Consumers of `SshConnection.getConnectionInfo()` could assume that `privateKeyPath` was present.

**Now:** `privateKeyPath` is optional because a connection can authenticate through an SSH agent or password instead.

**Upgrade:** Check `authMethod` and handle an undefined `privateKeyPath` before passing connection details to custom transports or commands.

### 0.2.0 to 0.12.8: explicit mode for `writeFile`

**Before:** `SshConnection.writeFile` did not require write options.

**Then:** Versions 0.2.0 through 0.12.8 required an options object with an explicit `mode`.

**Now:** Since 0.13.0, the options object is optional again and an omitted mode defaults to `0600`.

**Upgrade:** Custom code that must also run on 0.2.0 through 0.12.8 should pass `{ mode: "0600" }` or another intentional mode. Code targeting 0.13.0 or newer may omit the object only when the restrictive `0600` default is correct.

### 0.2.0: strict templates by default

**Before:** Template substitutions did not require an explicit output modifier.

**Now:** `file.template` uses strict mode by default and requires each substitution to choose `|shell` or `|raw`.

**Upgrade:** Add the appropriate modifier to every template substitution. Use `{ strict: false }` only as a temporary compatibility step while migrating reviewed templates.

### 0.2.0: strict host-key checking by default

**Before:** An unconfigured SSH connection could accept an unknown host key.

**Now:** `ssh.strictHostKeyChecking` defaults to `"yes"` and rejects hosts without a matching verified trust anchor.

**Upgrade:** Pin `expectedHostFingerprint` or `expectedHostPublicKey`, or pre-populate `known_hosts` with a key verified through an independent channel. Use `"accept-new"` only for an intentional trust-on-first-use policy.

### 0.11.0: `compose.systemd` requires an absolute directory

**Before:** `compose.systemd` accepted a relative `projectDirectory`, even though systemd requires an absolute `WorkingDirectory`.

**Now:** The module fails before unit generation when `projectDirectory` is not an absolute POSIX path.

**Upgrade:** Replace relative values such as `./app` with the intended absolute remote path, for example `/srv/app`.

### 0.11.0: `ssh.knownHosts` requires a trust anchor

**Before:** `ssh.knownHosts(host)` could treat an existing or scanned key as trusted without an explicit expected key.

**Now:** The default `state: "present"` requires either `expectedFingerprint` or `publicKey`; construction fails without one. `state: "absent"` does not require an anchor.

**Upgrade:** Pass the independently verified fingerprint or public key when ensuring an entry is present.

### 0.11.0: cron orphan adoption is opt-in

**Before:** `cron.job` could adopt an identical unmarked crontab line automatically.

**Now:** Existing unmarked lines are not adopted unless `adoptOrphans: true` is set.

**Upgrade:** Set `adoptOrphans: true` only when deliberately recovering an orphan left by a legacy Paratix marker; otherwise remove or reconcile duplicate unmanaged lines explicitly.

### 0.11.0: CLI second values must be positive integers

**Before:** CLI options expressed in seconds could accept non-integer numeric values.

**Now:** Second-based values such as `--reconnect-timeout` must be positive integers.

**Upgrade:** Replace zero, negative, or fractional values with a positive whole number of seconds.

## `create-paratix`

### 0.2.0: Node.js 24 or newer

**Before:** The generator could run on older Node.js versions.

**Now:** `create-paratix` requires Node.js `>=24.0.0`.

**Upgrade:** Upgrade local, CI, and automation runtimes to Node.js 24 or newer before invoking the generator.

### 0.2.0: interactive bootstrap prompts

**Before:** The generator did not prompt for the target host and initial SSH user.

**Now:** When these values are missing, the generator asks for the host and initial user interactively.

**Upgrade:** Set both `--host` and `--initial-user` in unattended automation so it never waits for an interactive prompt.

### 0.2.0: restricted project names

**Before:** Generator target names could contain a broader range of characters.

**Now:** Project names may contain only lowercase ASCII letters, digits, and hyphens.

**Upgrade:** Rename generator targets to match `a-z`, `0-9`, and `-`, and update automation that derives the target directory name.

### 0.11.0: root bootstrap requires an admin public key

**Before:** A non-interactive root-bootstrap invocation could omit the key for the dedicated admin user.

**Now:** With `--initial-user root`, the generator requires either `--admin-public-key` or `--admin-public-key-file`. An existing admin-user bootstrap may still run without an explicit key.

**Upgrade:** Add one of the admin-key flags to unattended root-bootstrap commands. Do not add a key merely to satisfy this entry when `--initial-user` already names an existing admin user.

### 0.11.0: non-interactive runs require `--host`

**Before:** A non-interactive invocation without `--host` could reach the interactive prompt path.

**Now:** A non-interactive run fails early when `--host` is missing.

**Upgrade:** Pass `--host` explicitly in every unattended generator command.

## Unreleased

There are no confirmed unreleased breaking changes that require user action.

## Toward 1.0

Confirmed unreleased breaking changes will be collected above. When the actual `paratix` or `create-paratix` package version 1.0.0 is prepared, those entries will move into a short versioned section with concrete upgrade steps. No future changes are assumed here.

## Audit note

Reviewed on 2026-07-10 from the 0.1 baseline commit `ee125596` through all package tags from `paratix-v0.2.0` and `create-paratix-v0.2.0` to their respective `v0.13.0` tags, plus the then-current repository state. The review covered public API exports and types, CLI options, defaults, and generated scaffold files. The former unprefixed root metadata `v1.0.0` and `v1.0.1` was excluded because it did not represent a release of either package.

[Back to the user guide](./README.md)
