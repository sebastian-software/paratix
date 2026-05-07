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
   * When `state` is `"absent"`, the persistence file is removed but the live
   * value is not reverted (a reboot will restore the default).
   *
   * @param key - The sysctl key (e.g. "net.ipv4.ip_forward").
   * @param value - The desired value (e.g. "1").
   * @param options - Optional settings.
   * @param options.state - Whether the parameter should be "present" (default) or "absent".
   * @returns A Module that manages the sysctl parameter.
   */
  set(key: string, value: string, options?: { state?: "absent" | "present" }): Module {
    validateKey(key)
    validateValue(value)
    const state = options?.state ?? "present"
    const configPath = `${SYSCTL_DIR}/99-paratix-${sanitizeKey(key)}-${keyHash(key)}.conf`
    const expectedContent = buildSysctlConfig(key, value)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[sysctl.set: ${key}] SSH connection is required`)

        if (state === "present") {
          const assignment = `${key}=${value}`
          const result = await conn.exec(`sysctl -w ${shellQuote(assignment)}`, EXEC_OPTS)
          if (result.code !== 0) {
            return failedCommand(`[sysctl.set: ${key}] sysctl -w failed`, result)
          }
          await conn.writeFile(configPath, expectedContent, { mode: SYSCTL_CONFIG_MODE })
        } else {
          const result = await conn.exec(`rm -f ${shellQuote(configPath)}`, EXEC_OPTS)
          if (result.code !== 0) {
            return failedCommand(`[sysctl.set: ${key}] failed to remove config file`, result)
          }
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        if (state === "present") {
          return checkPresentState(conn, { configPath, expectedContent, key, value })
        }

        const fileExists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
        return fileExists.code === 0 ? NEEDS_APPLY : "ok"
      },
      name: state === "present" ? `sysctl.set: ${key}=${value}` : `sysctl.set: absent ${key}`,
    }
  },
}
