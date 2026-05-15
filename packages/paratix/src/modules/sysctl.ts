import { createHash } from "node:crypto"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SYSCTL_DIR = "/etc/sysctl.d"
const SYSCTL_CONFIG_MODE = "0644"
const SYSCTL_KEY_HASH_LENGTH = 12
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
  if (key.length === 0) {
    throw new Error("sysctl.set: key must not be empty")
  }
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
  if (state !== "present" && state !== "absent") {
    throw new Error('sysctl.set: state must be "present" or "absent"')
  }
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

  const fileContent = await conn.readFile(configPath)
  return fileContent.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
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

async function rollbackLiveValue(
  conn: SshConnection,
  key: string,
  previousValue: string
): Promise<string> {
  const rollbackAssignment = `${key}=${previousValue}`
  const rollback = await conn.exec(`sysctl -w ${shellQuote(rollbackAssignment)}`, EXEC_OPTS)
  if (rollback.code === 0) {
    return `rolled back live value to ${JSON.stringify(previousValue)}`
  }
  return `rollback to ${JSON.stringify(previousValue)} failed: ${rollback.stderr || rollback.stdout}`
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
  const result = await conn.exec(`sysctl -w ${shellQuote(assignment)}`, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] sysctl -w failed`, result)
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
    return failed(
      `[sysctl.set: ${key}] failed to persist config to ${configPath}: ${reason}; ${rollbackStatus}`
    )
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
  const writeResult = await conn.exec(`sysctl -w ${shellQuote(assignment)}`, EXEC_OPTS)
  if (writeResult.code !== 0) {
    return failedCommand(
      `[sysctl.set: ${key}] sysctl -w failed while resetting live value`,
      writeResult
    )
  }
  const verify = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
  if (verify.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] failed to read live value after reset`, verify)
  }
  if (verify.stdout.trim() !== resetValue) {
    return failed(
      `[sysctl.set: ${key}] live value did not converge to reset value: expected ${JSON.stringify(resetValue)}, got ${JSON.stringify(verify.stdout.trim())}`
    )
  }
  return undefined
}

type AbsentStateInput = {
  configPath: string
  key: string
  resetValue: string | undefined
}

/**
 * Apply the `absent` state: remove the persistence file and, if a
 * `resetValue` is given, restore the live runtime value.
 *
 * @param conn - The SSH connection to the remote host.
 * @param input - The persistence file location, the sysctl key, and the
 *   optional `resetValue` to restore on the live system.
 * @returns A `ModuleResult` indicating success (`changed`) or a command
 *   failure.
 */
async function applyAbsentState(
  conn: SshConnection,
  input: AbsentStateInput
): Promise<ModuleResult> {
  const { configPath, key, resetValue } = input
  const removeResult = await conn.exec(`rm -f ${shellQuote(configPath)}`, EXEC_OPTS)
  if (removeResult.code !== 0) {
    return failedCommand(`[sysctl.set: ${key}] failed to remove config file`, removeResult)
  }
  if (resetValue !== undefined) {
    const resetFailure = await resetLiveValue(conn, key, resetValue)
    if (resetFailure) return resetFailure
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
