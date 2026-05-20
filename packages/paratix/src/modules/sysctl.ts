import { createHash } from "node:crypto"

import { failed, failedCommand } from "../moduleFailure.js"
import { registerSecret, unregisterSecret } from "../secretSink.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SYSCTL_DIR = "/etc/sysctl.d"
const SYSCTL_CONFIG_MODE = "0644"
// R-0000650: keep 24 hex digits (96 bits) so two sysctl entries that share
// the same sanitized prefix but differ in their suffix cannot collide on the
// persistence-file path. A 12-hex (48 bit) digest hits the birthday bound
// around 2^24 keys, well inside the parameter space of a realistic playbook
// that manages dozens of kernel parameters; 24 hex digits push the bound
// past 2^48 while staying comfortably below the 255-byte filename limit.
const SYSCTL_KEY_HASH_LENGTH = 24
const SYSCTL_KEY_PATTERN = /^\w[\w.\-]*$/iv

/**
 * Sanitize a sysctl key for safe use in a filesystem path.
 * Replaces `.` with `-` so the key can be embedded in a filename without
 * creating accidental sub-directories or conflicting with file extensions.
 *
 * @param key - The sysctl key (e.g. "net.ipv4.ip_forward").
 * @returns The sanitized string (e.g. "net-ipv4-ip_forward").
 */
function sanitizeKey(key: string): string {
  return key.replaceAll(".", "-")
}

function keyHash(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, SYSCTL_KEY_HASH_LENGTH)
}

/**
 * Validate a sysctl key. It must start with an alphanumeric or underscore
 * character, and only alphanumerics, dot, underscore, and hyphen are allowed so
 * the key can be embedded in shell commands and filenames without enabling
 * injection, option parsing, or path-separator tricks.
 *
 * @param key - The sysctl key to validate.
 * @throws {Error} When the key is empty or contains disallowed characters.
 */
function validateKey(key: string): void {
  if (key.length === 0) throw new Error("sysctl.set: key must not be empty")
  if (!SYSCTL_KEY_PATTERN.test(key)) {
    throw new Error(
      `sysctl.set: key must match ${String(SYSCTL_KEY_PATTERN)}, got: ${JSON.stringify(key)}`
    )
  }
}

/**
 * Validate a sysctl value. Newline and carriage return characters are rejected
 * because they would let callers inject additional directives into the
 * generated `sysctl.d` configuration file.
 *
 * @param value - The sysctl value to validate.
 * @throws {Error} When the value contains a newline or carriage return.
 */
function validateValue(value: string): void {
  if (/[\n\r]/v.test(value)) {
    throw new Error(
      `sysctl.set: value must not contain newline or carriage return characters, got: ${JSON.stringify(value)}`
    )
  }
}

function validateState(state: unknown): asserts state is "absent" | "present" {
  if (state !== "present" && state !== "absent")
    throw new Error('sysctl.set: state must be "present" or "absent"')
}

/**
 * Build the content of a sysctl.d configuration file.
 * The trailing newline is required by the sysctl.d(5) format.
 *
 * @param key - The sysctl parameter name (e.g. "net.ipv4.ip_forward").
 * @param value - The desired value to assign to the parameter.
 * @returns The file content in `key = value\n` format.
 */
function buildSysctlConfig(key: string, value: string): string {
  return `${key} = ${value}\n`
}

type CheckPresentStateInput = {
  configPath: string
  expectedContent: string
  key: string
  value: string
}

/**
 * Check whether the live sysctl value and the persisted configuration file
 * match the desired state.
 *
 * @param conn - The SSH connection to the remote host.
 * @param input - The desired key/value plus the persistence file location and
 *   expected content.
 * @returns `"ok"` when both live and persisted state match, otherwise
 *   `"needs-apply"`.
 */
async function checkPresentState(
  conn: SshConnection,
  input: CheckPresentStateInput
): Promise<"needs-apply" | "ok"> {
  const { configPath, expectedContent, key, value } = input
  const result = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
  if (result.code !== 0) return NEEDS_APPLY
  if (result.stdout.trim() !== value) return NEEDS_APPLY

  const configExists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
  if (configExists.code !== 0) return NEEDS_APPLY

  // R-0000817: mirror the `snapshotPersistenceFile` pattern (R-0000682) and
  // treat a transient readFile failure after a positive `test -f` as
  // NEEDS_APPLY rather than letting the exception escape the check phase. A
  // permission denial or SFTP hiccup must not crash the planner; the apply
  // path is responsible for producing a structured diagnostic.
  try {
    const fileContent = await conn.readFile(configPath)
    return fileContent.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
  } catch {
    return NEEDS_APPLY
  }
}

/**
 * Options for {@link sysctl.set}.
 */
export type SysctlSetOptions = {
  /**
   * When `state` is `"absent"`, optionally restore this live runtime value
   * after removing the persistence file. Without `resetValue`, only the
   * persistence file is removed and the live kernel value remains unchanged
   * until the next reboot.
   *
   * Use this for security-relevant parameters (e.g. resetting
   * `net.ipv4.ip_forward` to `"0"`) where leaving the live value in place
   * would silently violate the desired absent state.
   */
  resetValue?: string
  state?: "absent" | "present"
}

type ApplyPresentStateInput = {
  configPath: string
  expectedContent: string
  key: string
  value: string
}

async function readLiveValueBeforeApply(
  conn: SshConnection,
  key: string
): Promise<ModuleResult | string> {
  const previous = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
  if (previous.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] failed to read live value before applying`, previous)
  }
  return previous.stdout.trim()
}

// R-0000651: the live previousValue is captured from `sysctl -n` and may be
// security sensitive (crypto parameters, hashing rounds, network secrets
// embedded as kernel state). Register it with the process-scoped secret
// sink for the duration of the rollback so any stderr/stdout that
// `failedCommand` lifts into the rendered error message is masked, and
// keep the user-visible message abstract — the operator still sees that
// the rollback failed without learning the previous value verbatim.
async function rollbackLiveValue(
  conn: SshConnection,
  key: string,
  previousValue: string
): Promise<ModuleResult | string> {
  registerSecret(previousValue)
  try {
    const rollbackAssignment = `${key}=${previousValue}`
    const rollback = await conn.exec(`sysctl -w ${shellQuote(rollbackAssignment)}`, {
      ...EXEC_OPTS,
      secrets: [previousValue],
    })
    if (rollback.code === 0) {
      return "rolled back live value to previous value"
    }
    return failedCommand(`[sysctl.set: ${key}] rollback to previous value failed`, rollback, [
      previousValue,
    ])
  } finally {
    unregisterSecret(previousValue)
  }
}

/**
 * Build the persistence-failure ModuleResult, chaining the rollback outcome
 * (success message or masked rollback failure) into a single user-visible
 * diagnostic. R-0000651: the previousValue itself never appears verbatim —
 * the rollback failure is routed through `failedCommand`, which respects
 * the registered secret sink.
 *
 * @param input - The sysctl key, persistence-file path, captured writeFile
 *   error reason, and the rollback outcome to chain into the final message.
 * @param input.configPath - The persistence-file path under /etc/sysctl.d/.
 * @param input.key - The sysctl key whose write failed.
 * @param input.rollbackStatus - Either the success message string or the
 *   failed ModuleResult from `rollbackLiveValue`.
 * @param input.writeReason - The captured writeFile error reason.
 * @returns A failed ModuleResult that chains both causes.
 */
function buildPersistenceFailureResult(input: {
  configPath: string
  key: string
  rollbackStatus: ModuleResult | string
  writeReason: string
}): ModuleResult {
  const { configPath, key, rollbackStatus, writeReason } = input
  if (typeof rollbackStatus !== "string") {
    const rollbackMessage = rollbackStatus.error?.message ?? "rollback to previous value failed"
    return failed(
      `[sysctl.set: ${key}] failed to persist config to ${configPath}: ${writeReason}; ${rollbackMessage}`
    )
  }
  return failed(
    `[sysctl.set: ${key}] failed to persist config to ${configPath}: ${writeReason}; ${rollbackStatus}`
  )
}

/**
 * Apply the `present` state: write the live value via `sysctl -w` and
 * persist the configuration file.
 *
 * @param conn - The SSH connection to the remote host.
 * @param input - The desired key/value plus the persistence file location and
 *   expected content.
 * @returns A `ModuleResult` indicating success (`changed`) or a command
 *   failure.
 */

async function applyPresentState(
  conn: SshConnection,
  input: ApplyPresentStateInput
): Promise<ModuleResult> {
  const { configPath, expectedContent, key, value } = input
  const previousValue = await readLiveValueBeforeApply(conn, key)
  if (typeof previousValue !== "string") return previousValue
  const assignment = `${key}=${value}`
  const result = await conn.exec(`sysctl -w ${shellQuote(assignment)}`, {
    ...EXEC_OPTS,
    secrets: [value],
  })
  if (result.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] sysctl -w failed`, result, [value])
  }
  // R-0000242: convert a `writeFile` exception into a structured `failed`
  // ModuleResult. Without the catch, a failure of the persistence write
  // (e.g. read-only mount, missing parent directory, permission denied)
  // would propagate as an unstructured exception while the live kernel
  // value already drifted via `sysctl -w`. Mirrors the R-0000182 fix in
  // similar persist-after-mutation paths.
  //
  // R-0000549: no explicit cleanup of `configPath` is needed before the
  // rollback. `ssh.writeFile` is atomic via `finalizeRemoteTempFile`
  // (mktemp + chmod + chown + `mv -T` into place) with a `try/finally`
  // that runs `cleanupWriteFileTemporaryPath` on every failure path.
  // The final destination is therefore never observable in a partially
  // written state: on failure, `configPath` is either still the previous
  // content (untouched) or non-existent. A `rm -f -- configPath` here
  // could only delete a pre-existing, untouched file and would mask the
  // intended atomic semantics, so we deliberately do not remove it.
  try {
    await conn.writeFile(configPath, expectedContent, { mode: SYSCTL_CONFIG_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    const rollbackStatus = await rollbackLiveValue(conn, key, previousValue)
    return buildPersistenceFailureResult({
      configPath,
      key,
      rollbackStatus,
      writeReason: reason,
    })
  }
  return { status: "changed" }
}

/**
 * Restore the live runtime value when `state` is `"absent"` and a
 * `resetValue` was provided. The reset is verified via `sysctl -n`.
 *
 * @param conn - The SSH connection to the remote host.
 * @param key - The sysctl key to reset.
 * @param resetValue - The desired live value to write back.
 * @returns A failure `ModuleResult` if the reset did not converge,
 *   otherwise `undefined` to signal success.
 */
async function resetLiveValue(
  conn: SshConnection,
  key: string,
  resetValue: string
): Promise<ModuleResult | undefined> {
  const assignment = `${key}=${resetValue}`
  const writeResult = await conn.exec(`sysctl -w ${shellQuote(assignment)}`, {
    ...EXEC_OPTS,
    secrets: [resetValue],
  })
  if (writeResult.code !== 0) {
    return failedCommand(
      `[sysctl.set: ${key}] sysctl -w failed while resetting live value`,
      writeResult,
      [resetValue]
    )
  }
  const verify = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
  if (verify.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] failed to read live value after reset`, verify)
  }
  if (verify.stdout.trim() !== resetValue) {
    return failed(`[sysctl.set: ${key}] live value did not converge to reset value`)
  }
  return undefined
}

type AbsentStateInput = {
  configPath: string
  key: string
  resetValue: string | undefined
}

/**
 * Outcome of a persistence-file snapshot: a captured string, an explicit
 * "missing" marker, or a structured read failure that callers must treat as
 * uncertain.
 *
 * R-0000682: the original implementation collapsed a vanished file and a
 * permission-denied read into the same `null`. That made `applyAbsentState`
 * remove the file anyway and `restorePersistenceFile` report "no snapshot to
 * restore", masking the loss. Distinguish the two so the apply can abort
 * before the rm when the snapshot is uncertain.
 */
type PersistenceFileSnapshot =
  | { content: string; kind: "captured" }
  | { kind: "failed"; reason: string }
  | { kind: "missing" }

/**
 * Capture the current content of the sysctl persistence file so the absent
 * flow can roll it back when the subsequent live-reset fails. R-0000658:
 * without the snapshot, a failed `sysctl -w` left the host with neither the
 * persistence entry nor a converged live value, and the next reboot
 * silently loaded the kernel default.
 *
 * R-0000682: distinguish "file missing" (legitimate `kind: "missing"`) from
 * "readFile failed after a positive `test -f`" (`kind: "failed"`). The
 * apply path translates a structured failure into a refusal to remove the
 * file, instead of pretending there was nothing to restore.
 *
 * @param conn - The SSH connection to the remote host.
 * @param configPath - The persistence-file path the absent flow will remove.
 * @returns A {@link PersistenceFileSnapshot} describing the outcome of the
 *   capture.
 */
async function snapshotPersistenceFile(
  conn: SshConnection,
  configPath: string
): Promise<PersistenceFileSnapshot> {
  // R-0000770: probe for a symlink before the existence/read pair. A
  // persistence path that resolves to a symlink cannot be safely captured
  // — `test -f` follows the link and `readFile` would snapshot the link
  // target, so a subsequent rollback would write back foreign content into
  // the original location. Treat the symlink case as an uncertain
  // snapshot so `applyAbsentState` aborts before the rm. Mirrors the
  // `classifySwapFilePath` symlink probe (R-0000648).
  const symlinkProbe = await conn.exec(`[ -L ${shellQuote(configPath)} ]`, EXEC_OPTS)
  if (symlinkProbe.code === 0) {
    return { kind: "failed", reason: `${configPath} is a symbolic link` }
  }
  const exists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
  if (exists.code !== 0) return { kind: "missing" }
  try {
    const content = await conn.readFile(configPath)
    return { content, kind: "captured" }
  } catch (error) {
    // R-0000682: a readFile failure after `test -f` reported the file as
    // present means the snapshot is uncertain. The caller must abort the
    // absent flow before the rm rather than silently dropping the file.
    const reason = error instanceof Error ? error.message : String(error)
    return { kind: "failed", reason }
  }
}

/**
 * Restore the sysctl persistence file from a previously captured snapshot.
 * R-0000658: invoked when the absent flow already removed the file but the
 * subsequent `sysctl -w` reset failed, leaving the host out of spec on the
 * next reboot. Failures inside the rollback are returned as a human-readable
 * status string so the caller can chain it into the original reset failure
 * without throwing.
 *
 * @param conn - The SSH connection to the remote host.
 * @param configPath - The persistence-file path to restore into.
 * @param snapshot - The previously captured snapshot outcome.
 * @returns A short status string describing the rollback outcome.
 */
async function restorePersistenceFile(
  conn: SshConnection,
  configPath: string,
  snapshot: PersistenceFileSnapshot
): Promise<string> {
  if (snapshot.kind === "missing") {
    return "no persistence-file snapshot to restore"
  }
  if (snapshot.kind === "failed") {
    // R-0000682: applyAbsentState aborts before the rm when the snapshot
    // capture failed, so this branch is defensive. Surface the original
    // reason so the operator can correlate a stale call site with the
    // uncertain snapshot.
    return `persistence-file snapshot was uncertain: ${snapshot.reason}`
  }
  // R-0000769: refuse to write back through a symlink that materialized at
  // `configPath` between the rm and this rollback. Without the `[ ! -L ]`
  // probe an attacker who plants a symlink between the two steps would
  // redirect the `writeFile` to its target. Mirrors the `moveSwapToBackup`
  // / `restoreSwapBackup` guards (R-0000624 / R-0000647) and the
  // `restoreUnitFileSnapshot` check (R-0000683).
  const symlinkProbe = await conn.exec(`[ -L ${shellQuote(configPath)} ]`, EXEC_OPTS)
  if (symlinkProbe.code === 0) {
    return `persistence file restore refused: ${configPath} is a symbolic link`
  }
  try {
    await conn.writeFile(configPath, snapshot.content, { mode: SYSCTL_CONFIG_MODE })
    return "persistence file restored from snapshot"
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return `persistence file restore failed: ${reason}`
  }
}

/**
 * Apply the `absent` state: remove the persistence file and, if a
 * `resetValue` is given, restore the live runtime value. R-0000658: the
 * persistence file is snapshotted before the rm so a failing live-reset
 * can roll it back, instead of leaving the host with neither persistence
 * nor a converged live value.
 *
 * @param conn - The SSH connection to the remote host.
 * @param input - The persistence file location, the sysctl key, and the
 *   optional `resetValue` to restore on the live system.
 * @returns A `ModuleResult` indicating success (`changed`) or a command
 *   failure (possibly chained with the rollback outcome).
 */
async function applyAbsentState(
  conn: SshConnection,
  input: AbsentStateInput
): Promise<ModuleResult> {
  const { configPath, key, resetValue } = input
  const snapshot = await snapshotPersistenceFile(conn, configPath)
  // R-0000682: refuse to proceed with the rm when the snapshot capture
  // failed after `test -f` reported the file as present. Otherwise a
  // transient SFTP error or a permission denial after a positive existence
  // probe would silently destroy the persistence file with no chance of
  // rollback; the operator must reconcile the situation manually before
  // re-running the absent flow.
  if (snapshot.kind === "failed") {
    return failed(
      `[sysctl.set: ${key}] persistence-file snapshot failed; refusing to remove ${configPath}: ${snapshot.reason}`
    )
  }
  // R-0000769: refuse to `rm -f` a configPath that is currently a symlink.
  // Without the guard, a symlink planted between the snapshot capture and
  // the rm would let `rm -f` unlink the link itself; the subsequent
  // rollback would `writeFile` through the dangling path. Combine the
  // `[ ! -L ]` probe with the `rm -f` in a single shell statement so the
  // kernel evaluates both atomically — mirrors the swap backup guards
  // (R-0000649).
  const quotedConfigPath = shellQuote(configPath)
  const removeResult = await conn.exec(
    `[ ! -L ${quotedConfigPath} ] || { echo 'sysctl persistence file must not be a symlink' >&2; exit 1; }; rm -f ${quotedConfigPath}`,
    EXEC_OPTS
  )
  if (removeResult.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] failed to remove config file`, removeResult)
  }
  if (resetValue !== undefined) {
    const resetFailure = await resetLiveValue(conn, key, resetValue)
    if (resetFailure) {
      // R-0000658: chain the rollback outcome into the reset failure so the
      // operator sees both the original reset error and the rollback status
      // in a single ModuleResult. Mirrors the chained-rollback messages in
      // applyPresentState (R-0000242) and the swap absent-flow recovery.
      const rollbackStatus = await restorePersistenceFile(conn, configPath, snapshot)
      const resetMessage = resetFailure.error?.message ?? "live reset failed"
      return failed(`${resetMessage}; ${rollbackStatus}`)
    }
  }
  return { status: "changed" }
}

/**
 * Check whether the `absent` state has converged: the persistence file is
 * gone and (if `resetValue` is set) the live runtime value matches.
 *
 * @param conn - The SSH connection to the remote host.
 * @param input - The persistence file location, the sysctl key, and the
 *   optional `resetValue` to compare against the live runtime value.
 * @returns `"ok"` when the absent state has converged, otherwise
 *   `"needs-apply"`.
 */
async function checkAbsentState(
  conn: SshConnection,
  input: AbsentStateInput
): Promise<"needs-apply" | "ok"> {
  const { configPath, key, resetValue } = input
  const fileExists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
  if (fileExists.code === 0) return NEEDS_APPLY
  if (resetValue !== undefined) {
    const live = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
    if (live.code !== 0) return NEEDS_APPLY
    if (live.stdout.trim() !== resetValue) return NEEDS_APPLY
  }
  return "ok"
}

/**
 * Modules for managing kernel parameters via sysctl on the remote host.
 */
export const sysctl = {
  /**
   * Set a sysctl kernel parameter and persist it across reboots.
   *
   * The live value is applied immediately via `sysctl -w` and a configuration
   * file is written to `/etc/sysctl.d/99-paratix-<sanitized-key>-<hash>.conf`
   * for persistence.
   *
   * When `state` is `"absent"`, the persistence file is removed. By default
   * the live value is not reverted (a reboot will restore the default). Pass
   * `resetValue` to additionally write the desired runtime value back to the
   * kernel via `sysctl -w` so the absent state converges on the live system
   * as well.
   *
   * @param key - The sysctl key (e.g. "net.ipv4.ip_forward").
   * @param value - The desired value (e.g. "1").
   * @param options - Optional settings.
   * @param options.state - Whether the parameter should be "present" (default) or "absent".
   * @param options.resetValue - Live runtime value to restore when `state` is `"absent"`.
   *   Ignored when `state` is `"present"`.
   * @returns A Module that manages the sysctl parameter.
   */
  set(key: string, value: string, options?: SysctlSetOptions): Module {
    validateKey(key)
    validateValue(value)
    const state = options?.state ?? "present"
    validateState(state)
    const resetValue = options?.resetValue
    if (resetValue !== undefined) {
      validateValue(resetValue)
    }
    const configPath = `${SYSCTL_DIR}/99-paratix-${sanitizeKey(key)}-${keyHash(key)}.conf`
    const expectedContent = buildSysctlConfig(key, value)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[sysctl.set: ${key}] SSH connection is required`)
        if (state === "present") {
          return applyPresentState(conn, { configPath, expectedContent, key, value })
        }
        return applyAbsentState(conn, { configPath, key, resetValue })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY
        if (state === "present") {
          return checkPresentState(conn, { configPath, expectedContent, key, value })
        }
        return checkAbsentState(conn, { configPath, key, resetValue })
      },
      name: state === "present" ? `sysctl.set: ${key}=${value}` : `sysctl.set: absent ${key}`,
    }
  },
}
