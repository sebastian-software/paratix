# Migration Notes

This page lists only confirmed changes that require action in an existing project. Additive features, internal changes, and fixes that require no user action remain in the package changelogs.

## `paratix`

### 0.24.0: native SSH transport and authentication changes

**Before:** Paratix used `ssh2` at runtime, could prompt for a password after key-file authentication failed, and accepted key files together with `passwordFallback` or `agentForward`.

**Now:** The default transport is `@paratix/ssh-native`. Playbook execution supports Linux x64/arm64 with glibc 2.35 or newer or musl, and macOS x64/arm64 13.5 or newer; Windows is unsupported. Installation, imports, `--help`, and `--version` still work without the binding, but a playbook checks it before resolving secrets. A configured `privateKey` never falls back to a password. Both `privateKey` with `passwordFallback: true` and `privateKey` with `agentForward: true` are rejected. Without a key file, password fallback after agent failure connects without the agent. Forwarding requires a usable agent and successful agent authentication; missing or failed agents do not lead to a password prompt when forwarding is enabled. Native errors contain `[CODE]`; other failures after all ports append `; last error on port <p>: <native message> [<CODE>]`. `ENCRYPTED_KEY` and `UNSUPPORTED_KEY` stop after the first attempt, including during reconnect.

**Upgrade:** Run local and CI playbooks on a [supported controller](./README.md#supported-platforms) and keep optional dependencies enabled so its prebuilt binary is installed. Published packages need no Rust toolchain; only contributors building the repository need Rust. Remove `passwordFallback` and `agentForward` when keeping `privateKey`. To use an encrypted key or agent forwarding, load the key into a working SSH agent and omit `privateKey`. For a password fallback after agent failure, omit `privateKey` and disable `agentForward`. Replace unsupported DSA, hardware-backed `sk-*`, binary, or corrupt key files with a supported file or use a capable agent; see [key requirements](../../packages/ssh-native/README.md#authentication-and-key-formats). Update automation that matches `ssh2` error text, then rerun to verify the intended authentication and port. See [troubleshooting](./troubleshooting.md) for error recovery.

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

### 0.18.0: signal lists stop at the first failure

**Before:** In versions before 0.18.0, playbook authors could rely on later signals in the same list still running after an earlier signal returned a `"failed"` status or threw an exception. The surrounding recipe or run handled the failure only after the list finished.

**Now:** Since 0.18.0, the first signal that returns a `"failed"` status or throws an exception stops the current signal list; its remaining signals are skipped and the list reports `"failed"`. There is no `continueOnError` option. The stop is scoped to the current list, but the surrounding recipe or run may also stop before any later list is reached.

**Upgrade:** Keep dependent signals together when fail-fast behavior is intended. Move work that must be attempted independently despite another failure into separate playbook runs; a separate signal list in the same run does not guarantee execution. After a failure, fix the first cause. A normal rerun attempts the skipped signals only if at least one module in the same recipe or top-level scope reports `changed` again. If the entire scope reports `ok`, its signal list is not pending, and `signals.flush()` cannot force it. To recover, either make a real, intended state change that causes `changed` in that scope or have the operator perform the skipped operation directly; for a service signal, run the appropriate `systemctl reload <unit>` or `systemctl restart <unit>` command with the required privileges. If an older Paratix version already left a Quadlet stack split, follow [A Quadlet container cannot be replaced](./troubleshooting.md#a-quadlet-container-cannot-be-replaced); upgrading does not repair that host state automatically.

## `create-paratix`

### 0.24.0: native host-key scanning

**Before:** The interactive generator scanned host keys through `ssh2` without a native platform binary.

**Now:** Host-key scanning uses `@paratix/ssh-native` on the [supported controller platforms](./README.md#supported-platforms). The generator offers “Scan host key” only when the native binding can be loaded. Otherwise it explains the alternatives and offers the placeholder path; an actual scan failure still aborts scaffolding. Scans accept Ed25519 and ECDSA host keys; RSA pins must be supplied explicitly. Generated playbooks use Paratix's native transport and its platform and authentication requirements.

**Upgrade:** For scanning, run the generator on a supported controller with optional dependencies enabled. Otherwise pass `--expected-host-fingerprint` with an independently verified value, or keep the placeholder and configure verified `known_hosts` or a host-key pin before connecting. Compare any scanned fingerprint against an independent trusted source before pinning it. Execute the generated project on a supported controller; published packages need no Rust toolchain.

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

The 0.24.0 entries above describe the native-transport migration prepared for the next release.

## Toward 1.0

Confirmed unreleased breaking changes will be collected above. When the actual `paratix` or `create-paratix` package version 1.0.0 is prepared, those entries will move into a short versioned section with concrete upgrade steps. No future changes are assumed here.

## Audit note

Reviewed on 2026-07-10 from the 0.1 baseline commit `ee125596` through all package tags from `paratix-v0.2.0` and `create-paratix-v0.2.0` to their respective `v0.13.0` tags, plus the then-current repository state. The review covered public API exports and types, CLI options, defaults, and generated scaffold files. The former unprefixed root metadata `v1.0.0` and `v1.0.1` was excluded because it did not represent a release of either package.

On 2026-09-23, a targeted follow-up verified only the 0.18.0 signal-list change against `paratix-v0.17.0`, `paratix-v0.18.0`, the Paratix changelog, ADR-0006, the implementation, regression tests, and the agent guide. This was not a full re-audit of releases 0.14.0 through 0.19.0.

[Back to the user guide](./README.md)
