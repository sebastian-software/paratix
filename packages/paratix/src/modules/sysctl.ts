import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SYSCTL_DIR = "/etc/sysctl.d"

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

/**
 * Modules for managing kernel parameters via sysctl on the remote host.
 */
export const sysctl = {
  /**
   * Set a sysctl kernel parameter and persist it across reboots.
   *
   * The live value is applied immediately via `sysctl -w` and a configuration
   * file is written to `/etc/sysctl.d/99-paratix-<sanitized-key>.conf` for
   * persistence.
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
    const state = options?.state ?? "present"
    const configPath = `${SYSCTL_DIR}/99-paratix-${sanitizeKey(key)}.conf`
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
          await conn.writeFile(configPath, expectedContent)
        } else {
          await conn.exec(`rm -f ${shellQuote(configPath)}`, EXEC_OPTS)
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        if (state === "present") {
          const result = await conn.exec(`sysctl -n ${shellQuote(key)}`, EXEC_OPTS)
          const currentValue = result.stdout.trim()
          if (currentValue !== value) return NEEDS_APPLY

          const configExists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
          if (configExists.code !== 0) return NEEDS_APPLY

          const fileContent = await conn.readFile(configPath)
          return fileContent.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
        }

        const fileExists = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
        return fileExists.code === 0 ? NEEDS_APPLY : "ok"
      },
      name: state === "present" ? `sysctl.set: ${key}=${value}` : `sysctl.set: absent ${key}`,
    }
  },
}
