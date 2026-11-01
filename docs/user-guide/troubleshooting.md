# Troubleshooting

Start with the exact error message. Use `--verbose` when a failed remote command needs more context, but review output before sharing it because it can contain host-specific information.

## The native SSH binding cannot be loaded

**Symptom:** A playbook reports `Paratix could not load its native SSH binding for platform ...` and exits before resolving playbook secrets. `--help`, `--version`, and package imports may still work.

**Likely cause:** The controller is outside the [supported platforms](./README.md#supported-platforms), its Linux glibc is older than 2.35, or the optional platform package was not installed.

**Diagnose:** Compare the platform and architecture in the error with the supported-platform table. On a supported system, run with `--verbose` to inspect the underlying loader error. Check whether installation omitted optional dependencies or reused a lockfile that lacks the current platform's optional package.

**Fix:** Run playbooks on a supported controller. On a supported system, reinstall with optional dependencies enabled and follow the loader's installation details. Building Rust is a contributor workflow and is not required to use published packages.

**Verify:** Rerun the playbook. It should pass the binding check before resolving its secrets.

## A key file fails with `ENCRYPTED_KEY` or `UNSUPPORTED_KEY`

**Symptom:** The error ends with `[ENCRYPTED_KEY]` or `[UNSUPPORTED_KEY]`. Paratix stops after the first attempt without trying further ports; reconnect also stops immediately for these codes.

**Likely cause:** The private key is encrypted, has an unsupported algorithm or format, or is corrupt. DSA and hardware-backed `sk-*` private key files are unsupported. Supported files are unencrypted PEM/OpenSSH text for Ed25519, RSA, or ECDSA; see the [key requirements](../../packages/ssh-native/README.md#authentication-and-key-formats).

**Diagnose:** Check the configured `ssh.privateKey` path and identify its format locally without printing key material into logs.

**Fix:** For an encrypted key, load it into a working SSH agent and omit `privateKey`. For an unsupported file, configure a supported key or use an agent that can sign with the intended identity. `passwordFallback: true` cannot be combined with `privateKey` and does not recover a rejected key file.

**Verify:** Rerun with the corrected authentication configuration and confirm that the first connection succeeds.

## Agent forwarding or password fallback is rejected

**Symptom:** Validation reports `agentForward requires authentication through an SSH agent; remove privateKey or agentForward` or `passwordFallback requires authentication through an SSH agent; remove privateKey or passwordFallback`. A runtime forwarding failure reports `agentForward requires authentication through an SSH agent; remove agentForward or configure a working SSH agent` without a password prompt.

**Likely cause:** A key file was combined with one of these options, or forwarding was requested without a usable agent or after an agent login failed.

**Diagnose:** Check `ssh.privateKey`, `ssh.agentForward`, `ssh.passwordFallback`, and whether `SSH_AUTH_SOCK` points to the intended running agent. Confirm that the agent holds an identity authorized on the target.

**Fix:** Choose key-file authentication without forwarding or password fallback, or omit `privateKey` and configure a working agent. If a password fallback is intended after a failed agent login, disable `agentForward`; the password attempt does not reuse or forward the agent.

**Verify:** Rerun and confirm that validation succeeds and the intended authentication method connects.

## A connection failure includes a native error code

**Symptom:** A native SSH failure contains `[CODE]`. When all candidate ports fail, the existing final-message prefix is followed by `; last error on port <p>: <native message> [<CODE>]`.

**Diagnose:** Use the last port and error code together. `AUTH_FAILED` means login was refused; `CONNECT_FAILED` points to TCP connection failure; `TIMEOUT` means the handshake, host verification, or login did not finish in time. The [binding error reference](../../packages/ssh-native/README.md#errors) lists the codes. Tools that matched old `ssh2` message text need to account for these messages.

**Fix:** Correct the credentials, host reachability, or timeout cause indicated by the error. A configured key file is tried without a password fallback. For a password attempt after agent failure, omit `privateKey` and use `passwordFallback: true` without `agentForward`.

**Verify:** Rerun and confirm that the intended host and port connect.

## `tsx` cannot be loaded

**Symptom:** A TypeScript playbook exits with code 2 and reports that `tsx` is required but could not be loaded.

**Likely cause:** The project dependencies were not installed, or the project uses a `paratix` installation that cannot resolve `tsx`.

**Diagnose:** Run the project's package-manager install command, then check that `tsx` is present with `pnpm exec tsx --version` (or the equivalent command for your package manager). Do not replace the TypeScript playbook with generated JavaScript merely to bypass the error.

**Fix:** Install the project dependencies. For a manually assembled project, add `tsx` as a development dependency:

```bash
pnpm add --save-dev tsx
```

The Paratix CLI also suggests a global installation, but a project-local dependency makes the runtime version reproducible.

**Verify:** Run the same playbook again. It should load before Paratix attempts an SSH connection.

## An unknown host key is rejected

**Symptom:** The first connection to a host fails because strict host-key checking has no trusted key for that host and port.

**Likely cause:** `strictHostKeyChecking` defaults to `"yes"`, and neither `known_hosts` nor the playbook contains a matching trust anchor.

**Diagnose:** Obtain the server's SSH host-key fingerprint through an independent trusted channel, such as the hosting provider's console. Compare it with the fingerprint shown by the provider or by a console-side `ssh-keygen` command. A network-only `ssh-keyscan` result is useful for collecting a key, but does not independently authenticate it.

**Fix:** After verification, pin the key with `ssh.expectedHostFingerprint` or `ssh.expectedHostPublicKey`, or add the verified key to `~/.ssh/known_hosts`. Use `strictHostKeyChecking: "accept-new"` only when trust on first use is an intentional policy: it accepts and stores a previously unknown key, but still rejects a changed key.

**Verify:** Connect again and confirm that the accepted or pinned fingerprint is the one verified through the independent channel.

## A changed host key is rejected

**Symptom:** Paratix reports `HOST KEY VERIFICATION FAILED` and says that the remote key does not match `known_hosts` or a configured pin.

**Likely cause:** The server was rebuilt or its SSH host keys were rotated. The same symptom can indicate DNS or routing drift, an unexpected host, or a man-in-the-middle attack. `accept-new` does not accept replacement keys.

**Diagnose:** Stop the run. Confirm the target hostname and port, then verify the new fingerprint through the provider console or another independent trusted channel. Do not delete the old entry before establishing why it changed.

**Fix:** Only after the change is authenticated, update the configured fingerprint/public key or replace the specific `known_hosts` entry for that host and port. Leave unrelated entries intact.

**Verify:** Run again and confirm that Paratix accepts exactly the newly verified key. An unexplained mismatch must remain a hard failure.

## Reconnect fails after an SSH port change

**Symptom:** The run reports `Failed to reconnect on port(s) ... after port change`.

**Likely cause:** The new port is not listening, a host or provider firewall blocks it, or the SSH daemon rejected the updated configuration.

**Diagnose:** Keep the current administrative session open. From a second terminal, test the new port with `ssh -p <port> <user>@<host>`. Check the host firewall, provider firewall, SSH daemon status, and listening sockets from the existing session or provider console.

**Fix:** Make the new port reachable before removing access through the old port. Correct the firewall or SSH configuration and rerun the playbook. Increase `--reconnect-timeout` only when the service is expected to become available slowly; it cannot repair a blocked or invalid port.

**Verify:** Establish a separate SSH session on the new port, then rerun Paratix and confirm that the reconnect completes.

## Reconnect fails after a reboot

**Symptom:** The run reports `Failed to reconnect after reboot` after waiting for the server to return.

**Likely cause:** The host is still booting, its address changed, SSH did not start, or the host is unreachable. Reboots use a 300-second reconnect window by default.

**Diagnose:** Check the hosting console and boot logs. Confirm the current address, SSH service state, network configuration, and host firewall. Distinguish a connection refusal (host reachable, SSH unavailable) from a timeout or unreachable route.

**Fix:** Resolve the boot, network, or SSH failure through the provider console. For a healthy host that legitimately takes longer than five minutes, rerun with a larger bounded value such as `--reconnect-timeout 600`.

**Verify:** Connect with SSH directly, then rerun Paratix and confirm that it reconnects within the configured window.

## A step fails with `CHANNEL_OPEN_FAILED`

**Symptom:** A step fails with `[CHANNEL_OPEN_FAILED]`, often on `archive.extract` against an archive with many members. The message mentions `MaxSessions`. The failure is not cumulative — it reproduces on a rerun in which every preceding step reports `ok` — and it looks like a transport or upload problem rather than a limit being reached.

**Likely cause:** The SSH server refused a new session channel. Every remote command runs on its own channel, and OpenSSH caps concurrent channels per connection through `MaxSessions` (default 10). Paratix opens at most 4 concurrent channels per connection, which stays under that default and leaves room for a parallel SFTP transfer. A host whose `sshd_config` lowers `MaxSessions` below that can still refuse them.

**Diagnose:** Read the effective ceiling on the target host with `sshd -T | grep -i maxsessions`. A value below 5 leaves no room for the concurrent channels plus an SFTP transfer.

**Fix:** Raise `MaxSessions` on the target back to the default of 10 (or higher) and reload the SSH daemon. Paratix does not exceed 4 concurrent channels per connection, so no playbook change is needed.

**Verify:** Rerun the failing step and confirm it completes. If the same error persists at the default `MaxSessions`, something else on the host is consuming session channels on the same connection.

## A package step reports `changed` on every run

**Symptom:** `package.update`, `package.upgrade` or `apt.distUpgrade` reports `changed` on every apply, even when the playbook and its date arguments have not changed.

**Likely cause:** Two causes look identical in the output.

Before 0.17.0, several calls of the same dated module shared one host-global marker namespace, so each call deleted the other's marker on every run and neither could ever converge. Two calls of the same module with different dates are the signature of this.

Otherwise the step is converging correctly but its work is genuinely empty: these modules report `changed` whenever their dated marker is absent, including when the package manager had nothing to upgrade.

**Diagnose:** Read the step's status detail. `no packages upgraded` means the marker was missing but the system was already current; a count such as `12 packages upgraded` means real work happened. `marker was missing, package index refreshed` is the expected detail for `package.update`. If the detail is absent entirely, the installed version predates it — upgrade before diagnosing further.

Inspect the markers on the host to confirm which dates are recorded:

```bash
sudo ls -la /var/lib/paratix/flags/
```

Each dated call must have its own file. A call whose marker is missing after a successful run indicates the pre-0.17.0 behavior.

**Fix:** Upgrade to 0.17.0 or newer, where each dated call keeps its own marker. No playbook change is required, and existing markers stay valid. On a host that ran an affected version, the previously evicted call runs once more and reports `changed`; from the next run on it reports `ok`.

**Verify:** Apply the playbook twice without changing it. The second run must report `ok` for every dated module.

## A Quadlet container cannot be replaced

**Symptom:** A `quadlet.container` or `quadlet.updateImage` step fails with
`container '<name>' already exists and is not owned by unit '<unit>'`, naming the marker that proved
foreign ownership — a Compose project label or a `PODMAN_SYSTEMD_UNIT` of another unit.

Where that ownership marker is absent, the step instead fails later with
`systemctl restart failed (exit code 1)`, and the attached journal excerpt names the real cause, for
example `container <id> has dependent containers which must be removed before it` or
`container already exists`.

**Likely cause:** A container of that name already exists on the host and was not created by this
Quadlet unit — typically a leftover from a Compose-based deployment during a migration, or a
manually started container. Podman refuses to replace it while other containers depend on it. The
blocking condition is host state, not configuration, so re-running the playbook reproduces it
exactly.

**Diagnose:** Inspect what currently holds the name and who owns it:

```bash
sudo podman ps -a --filter name=<container> --format '{{.Names}} {{.Status}} {{.Labels}}'
```

Read the unit's own journal for the failed attempt:

```bash
sudo journalctl -xeu <unit>
```

**Fix:** Remove the foreign container together with whatever depends on it, then let the unit
recreate it. Confirm what would be removed before running this — it deletes running containers:

```bash
sudo podman rm --depend <container>
```

Then clear the failed unit state and start it again:

```bash
sudo systemctl reset-failed <unit>
```

**Verify:** Apply the playbook again. The step must report `changed` once and `ok` afterwards. Check
that every container of the stack sits on the same network:

```bash
sudo podman inspect --format '{{.Name}} {{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}' <container>
```

A stack whose containers span two networks is the split state described in issue #149: since a
failed signal now stops the remaining signals of its list, a partial rollout no longer produces it,
but a host that was left in that state by an older version still needs the manual repair above.

**Detecting it before it bites:** a plain `--dry-run` now reports the same conflict from
`quadlet.container`, so a migration can be checked against the host before anything is applied.
The check only fires when the leftover container carries a Compose project label or another unit's
`PODMAN_SYSTEMD_UNIT`; a container started by hand with no such metadata is not detected and still
surfaces through the journal excerpt above.

[Back to the user guide](./README.md)
