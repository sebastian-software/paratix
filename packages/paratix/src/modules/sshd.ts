import { sshdPortMeta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"

const DEFAULT_SSH_PORT = 22
const SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
const SYSTEMCTL = "systemctl"

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
    // Intentional: unguarded write — restoring the original config is more
    // important than concurrency safety during a failed validation rollback.
    await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig)
    throw new Error(
      `sshd config validation failed (sshd -t), rolled back to previous config:\n${result.stderr}`
    )
  }
}

async function reloadSshd(ssh: SshConnection): Promise<ModuleResult> {
  const result = await ssh.exec(`${SYSTEMCTL} reload sshd`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? { status: "changed" }
    : failedCommand("[sshd.config] systemctl reload sshd failed", result)
}

function applySshdSettingToContent(content: string, key: string, value: string): string {
  // eslint-disable-next-line security/detect-non-literal-regexp
  const pattern = new RegExp(`^${escapeRegExp(key)}\\s.*`, "gmv")
  const replaced = content.replace(pattern, `${key} ${value}`)

  if (replaced !== content) {
    return replaced
  }
  // eslint-disable-next-line security/detect-non-literal-regexp
  if (new RegExp(`^${escapeRegExp(key)}\\s`, "mv").test(content)) {
    return content
  }
  return content.endsWith("\n") ? `${content}${key} ${value}\n` : `${content}\n${key} ${value}\n`
}

function isRestartDisconnect(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return (
    message.includes("SSH connection closed") ||
    message.includes("ECONNRESET") ||
    message.includes("Connection reset")
  )
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
        if (!ssh) return failed(`[sshd.config: ${settingNames}] SSH connection is required`)

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)

        let newContent = originalConfig
        for (const [key, value] of Object.entries(settings)) {
          newContent = applySshdSettingToContent(newContent, key, value)
        }

        const didChange = newContent !== originalConfig
        if (didChange) {
          await guardedWriteFile(ssh, {
            newContent,
            originalContent: originalConfig,
            remotePath: SSHD_CONFIG_PATH,
          })
        }

        await validateSshdConfig(ssh, originalConfig)

        if (!didChange) {
          return { status: "ok" }
        }

        return reloadSshd(ssh)
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
        if (!ssh) return failed(`[sshd.port: ${targetPort}] SSH connection is required`)

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
        const newContent = applySshdSettingToContent(originalConfig, "Port", String(targetPort))
        if (newContent === originalConfig) {
          return { status: "ok" }
        }

        await guardedWriteFile(ssh, {
          newContent,
          originalContent: originalConfig,
          remotePath: SSHD_CONFIG_PATH,
        })
        await validateSshdConfig(ssh, originalConfig)
        ssh.addPort(targetPort)
        try {
          await ssh.exec("systemctl restart sshd", { silent: true })
        } catch (error) {
          if (!isRestartDisconnect(error)) {
            ssh.removePort(targetPort)
          }
          throw error
        }

        return {
          meta: [sshdPortMeta(targetPort)],
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
