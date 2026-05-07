import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { detectPackageManager, isPackageInstalled } from "./package.js"

const UFW = "ufw"

async function allowCurrentSshPort(ssh: SshConnection): Promise<ModuleResult | null> {
  const { port } = ssh.getConnectionInfo()
  if (!isValidTcpPort(port)) {
    return failed(`[ufw.enabled] current SSH port is invalid: ${String(port)}`)
  }
  const result = await ssh.exec(`${UFW} allow ${shellQuote(String(port))}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? null
    : failedCommand(`[ufw.enabled] ufw allow failed for current SSH port ${String(port)}`, result)
}

function hasProtocolAgnosticRule(status: string, port: number, action: "ALLOW" | "DENY"): boolean {
  // Match only the protocol-agnostic form `<port> ACTION`. Protocol-specific
  // entries like `22/tcp ALLOW`, opposite actions, and similar ports must not
  // satisfy the rule.
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}\\s+${action}\\b`, "mv").test(status)
}

function hasProtocolAgnosticIpv6Rule(
  status: string,
  port: number,
  action: "ALLOW" | "DENY"
): boolean {
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}\\s+\\(v6\\)\\s+${action}\\b`, "mv").test(status)
}

function statusIncludesIpv6Rules(status: string): boolean {
  return status.includes("(v6)")
}

function ufwRuleApplyChanged(stdout: string): boolean {
  const lines = stdout
    .split(/\r?\n/v)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  if (lines.length === 0) return true
  return lines.some((line) => !line.startsWith("Skipping adding existing rule"))
}

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
        const allowResult = await allowCurrentSshPort(ssh)
        if (allowResult !== null) return allowResult
        // R-0000064: use the officially supported `--force` flag for
        // non-interactive enable instead of piping `y` into stdin. Mirrors
        // the call shape used by ufw.disabled.apply and avoids relying on
        // the wording of the Y/N prompt or the TTY-detection heuristic in
        // ufw.
        const result = await ssh.exec(`${UFW} --force enable`, {
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
        if (!status.includes("Status: active")) return NEEDS_APPLY

        const { port } = ssh.getConnectionInfo()
        if (!isValidTcpPort(port)) return NEEDS_APPLY

        if (!hasProtocolAgnosticRule(status, port, "ALLOW")) return NEEDS_APPLY
        if (
          statusIncludesIpv6Rules(status) &&
          !hasProtocolAgnosticIpv6Rule(status, port, "ALLOW")
        ) {
          return NEEDS_APPLY
        }
        return "ok"
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
    // R-0000118: validate ports up front so callers fail fast on invalid
    // numbers rather than only discovering the problem at apply time when
    // ufw rejects the rule. Mirrors the validation pattern used in
    // sshd.port and serverDefinitionValidation.collectPortsErrors.
    for (const port of portList) {
      if (!isValidTcpPort(port)) {
        throw new Error(`ufw.rule requires integer ports between 1 and 65535, got ${String(port)}`)
      }
    }
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh)
          return failed(`[ufw.rule: ${action} ${portList.join(",")}] SSH connection is required`)

        let anyChanged = false
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
          // R-0000076/R-0000114: ufw prints "Skipping adding existing rule"
          // per address family. Treat the command as a no-op only when all
          // emitted family lines are skips; a mixed skip/add output still
          // means one family was repaired.
          if (ufwRuleApplyChanged(result.stdout)) {
            anyChanged = true
          }
        }

        return { status: anyChanged ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const status = await ssh.output(`${UFW} status`)
        const requireIpv6Rule = statusIncludesIpv6Rules(status)
        for (const port of portList) {
          const expectedAction = action === "allow" ? "ALLOW" : "DENY"
          // R-0000118: match only the protocol-agnostic form `<port> ACTION`.
          // The caller asked for `ufw <action> <port>` (no /tcp or /udp
          // suffix), which adds rules for both protocols. Accepting a
          // protocol-specific entry like `22/tcp ALLOW` here would hide a
          // drift where only one protocol is configured and apply would
          // therefore add a second, parametrically different rule.
          // Anchor the port at the line start and require a whitespace
          // boundary so port 22 does not match 5022, 1022, 2222 etc.
          if (!hasProtocolAgnosticRule(status, port, expectedAction)) {
            return NEEDS_APPLY
          }
          if (requireIpv6Rule && !hasProtocolAgnosticIpv6Rule(status, port, expectedAction)) {
            return NEEDS_APPLY
          }
        }
        return "ok"
      },
      name: `ufw.rule: ${action} ${portList.join(",")}`,
    }
  },
}
