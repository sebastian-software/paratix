import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { detectPackageManager, isPackageInstalled } from "./package.js"

const UFW = "ufw"

/**
 * Modules for managing the UFW (Uncomplicated Firewall) on Debian/Ubuntu hosts.
 */
export const ufw = {
  /**
   * Ensure UFW is inactive. If UFW is not installed, this is treated as already satisfied.
   *
   * @returns A Module that ensures UFW is disabled.
   */
  disabled(): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[ufw.disabled] SSH connection is required")
        const pm = await detectPackageManager(ssh)
        if (pm == null || !(await isPackageInstalled(ssh, pm, UFW))) {
          return { status: "ok" }
        }

        const result = await ssh.exec(`${UFW} --force disable`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand("[ufw.disabled] ufw disable failed", result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const pm = await detectPackageManager(ssh)
        if (pm == null || !(await isPackageInstalled(ssh, pm, UFW))) {
          return "ok"
        }

        const status = await ssh.output(`${UFW} status`)
        return status.includes("Status: inactive") ? "ok" : NEEDS_APPLY
      },
      name: "ufw.disabled",
    }
  },

  /**
   * Ensure UFW is active. Enables the firewall non-interactively if not already running.
   *
   * @returns A Module that ensures UFW is enabled.
   */
  enabled(): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[ufw.enabled] SSH connection is required")
        const result = await ssh.exec(`echo 'y' | ${UFW} enable`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand("[ufw.enabled] ufw enable failed", result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const status = await ssh.output(`${UFW} status`)
        return status.includes("Status: active") ? "ok" : NEEDS_APPLY
      },
      name: "ufw.enabled",
    }
  },

  /**
   * Add an allow or deny rule for one or more ports.
   * The check phase reads `ufw status` and verifies the expected rule is present.
   *
   * @param action - Whether to `"allow"` or `"deny"` traffic on the given ports.
   * @param ports - A single port number or an array of port numbers.
   * @returns A Module that manages UFW rules.
   */
  rule(action: "allow" | "deny", ports: number | number[]): Module {
    const portList = Array.isArray(ports) ? ports : [ports]
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh)
          return failed(`[ufw.rule: ${action} ${portList.join(",")}] SSH connection is required`)

        for (const port of portList) {
          // eslint-disable-next-line no-await-in-loop
          const result = await ssh.exec(
            `${UFW} ${shellQuote(action)} ${shellQuote(String(port))}`,
            { ignoreExitCode: true, silent: true }
          )
          if (result.code !== 0) {
            return failedCommand(
              `[ufw.rule: ${action} ${portList.join(",")}] ufw ${action} failed for port ${String(port)}`,
              result
            )
          }
        }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const status = await ssh.output(`${UFW} status`)
        for (const port of portList) {
          const expectedAction = action === "allow" ? "ALLOW" : "DENY"
          // Anchor the port at the line start and require a whitespace boundary
          // after the optional /tcp or /udp suffix so port 22 does not match
          // 5022, 1022, 2222 etc.
          // eslint-disable-next-line security/detect-non-literal-regexp
          const pattern = new RegExp(`^${port}(?:/(?:tcp|udp))?\\s+${expectedAction}\\b`, "mv")
          if (!pattern.test(status)) {
            return NEEDS_APPLY
          }
        }
        return "ok"
      },
      name: `ufw.rule: ${action} ${portList.join(",")}`,
    }
  },
}
