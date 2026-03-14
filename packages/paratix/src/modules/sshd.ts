import { shellQuote } from "../ssh.js"
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

async function applySshdSetting(ssh: SshConnection, key: string, value: string): Promise<void> {
  const content = await ssh.readFile(SSHD_CONFIG_PATH)
  // eslint-disable-next-line security/detect-non-literal-regexp
  const pattern = new RegExp(`^${escapeRegExp(key)}\\s.*`, "mv")
  let newContent: string

  if (pattern.test(content)) {
    newContent = content.replace(pattern, `${key} ${value}`)
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

        for (const [key, value] of Object.entries(settings)) {
          // eslint-disable-next-line no-await-in-loop
          await applySshdSetting(ssh, key, value)
        }

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

        // Check if Port line exists
        const hasPort = await ssh.test(`grep -qE '^Port\\s' ${SSHD_CONFIG_PATH}`)

        if (hasPort) {
          await ssh.exec(`sed -i 's/^Port\\s.*/Port ${String(targetPort)}/' ${SSHD_CONFIG_PATH}`, {
            silent: true,
          })
        } else {
          const portLine = `Port ${String(targetPort)}`
          await ssh.exec(`printf '%s\\n' ${shellQuote(portLine)} >> ${SSHD_CONFIG_PATH}`, {
            silent: true,
          })
        }

        // Restart sshd
        await ssh.exec("systemctl restart sshd", { silent: true })

        return {
          meta: { "sshd.port": targetPort },
          status: "changed",
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const currentPort = await ssh.output(
          `grep -E '^Port\\s' ${SSHD_CONFIG_PATH} || echo 'Port 22'`
        )
        const port = Number(currentPort.replace(/^Port\s+/v, "").trim()) || DEFAULT_SSH_PORT
        return port === targetPort ? "ok" : NEEDS_APPLY
      },
      name: `sshd.port: ${targetPort}`,
    }
  },
}
