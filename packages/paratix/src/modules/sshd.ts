import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const DEFAULT_SSH_PORT = 22
const SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

// prettier-ignore
const REGEXP_SPECIAL = new Set(["?", ".", "(", ")", "[", "]", "{", "}", "*", "\\", "^", "+", "|", "$"])

function escapeRegExp(s: string): string {
  let result = ""
  for (const ch of s) {
    result += REGEXP_SPECIAL.has(ch) ? `\\${ch}` : ch
  }
  return result
}

async function validateSshdConfig(ssh: SshConnection, originalConfig: string): Promise<void> {
  const result = await ssh.exec("sshd -t", { ignoreExitCode: true, silent: true })
  if (result.code !== 0) {
    await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig)
    throw new Error(
      `sshd config validation failed (sshd -t), rolled back to previous config:\n${result.stderr}`
    )
  }
}

async function applySshdSetting(ssh: SshConnection, key: string, value: string): Promise<void> {
  const content = await ssh.readFile(SSHD_CONFIG_PATH)
  // eslint-disable-next-line security/detect-non-literal-regexp
  const pattern = new RegExp(`^${escapeRegExp(key)}\\s.*`, "gmv")
  const replaced = content.replace(pattern, `${key} ${value}`)

  let newContent: string
  if (replaced !== content) {
    newContent = replaced
    // eslint-disable-next-line security/detect-non-literal-regexp
  } else if (new RegExp(`^${escapeRegExp(key)}\\s`, "mv").test(content)) {
    newContent = content
  } else {
    newContent = content.endsWith("\n")
      ? `${content}${key} ${value}\n`
      : `${content}\n${key} ${value}\n`
  }

  await ssh.writeFile(SSHD_CONFIG_PATH, newContent)
}

/**
 * Modules for managing the OpenSSH daemon configuration (`/etc/ssh/sshd_config`).
 * All methods restart or reload `sshd` after applying changes.
 */
export const sshd = {
  /**
   * Apply one or more key-value settings to `sshd_config`.
   * Existing directives are updated in-place; missing directives are appended.
   *
   * @param settings - A map of sshd_config directive names to their desired values
   *   (e.g. `{ PasswordAuthentication: "no" }`).
   * @returns A Module that applies the sshd configuration settings.
   */
  config(settings: Record<string, string>): Module {
    const settingNames = Object.keys(settings).join(", ")
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)

        for (const [key, value] of Object.entries(settings)) {
          // eslint-disable-next-line no-await-in-loop
          await applySshdSetting(ssh, key, value)
        }

        await validateSshdConfig(ssh, originalConfig)

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(SSHD_CONFIG_PATH)
        for (const [key, value] of Object.entries(settings)) {
          // eslint-disable-next-line security/detect-non-literal-regexp
          const pattern = new RegExp(`^${escapeRegExp(key)}\\s+${escapeRegExp(value)}$`, "mv")
          if (!pattern.test(content)) {
            return NEEDS_APPLY
          }
        }
        return "ok"
      },
      name: `sshd.config: ${settingNames}`,
    }
  },

  /**
   * Set the SSH daemon listen port.
   * Updates the `Port` directive in `sshd_config` and restarts `sshd`.
   * The new port is exported as `sshd.port` in the module result meta so
   * the runner can reconnect on the updated port.
   *
   * @param targetPort - The port number sshd should listen on.
   * @returns A Module that sets the sshd listen port.
   */
  port(targetPort: number): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
        await applySshdSetting(ssh, "Port", String(targetPort))
        await validateSshdConfig(ssh, originalConfig)
        await ssh.exec("systemctl restart sshd", { silent: true })

        return {
          meta: { "sshd.port": targetPort },
          status: "changed",
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(SSHD_CONFIG_PATH)
        // eslint-disable-next-line security/detect-non-literal-regexp
        const pattern = new RegExp(`^Port\\s+${String(targetPort)}$`, "mv")
        if (pattern.test(content)) return "ok"
        // When no Port directive exists, sshd defaults to port 22
        if (targetPort === DEFAULT_SSH_PORT && !/^Port\s/mv.test(content)) return "ok"
        return NEEDS_APPLY
      },
      name: `sshd.port: ${targetPort}`,
    }
  },
}
