# Troubleshooting

Start with the exact error message. Use `--verbose` when a failed remote command needs more context, but review output before sharing it because it can contain host-specific information.

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

## A step fails with `Channel open failure`

**Symptom:** A step fails with `(SSH) Channel open failure: open failed`, often on `archive.extract` against an archive with many members. The message mentions `MaxSessions`. The failure is not cumulative — it reproduces on a rerun in which every preceding step reports `ok` — and it looks like a transport or upload problem rather than a limit being reached.

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
