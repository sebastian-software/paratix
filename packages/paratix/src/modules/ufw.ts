import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { detectPackageManager, isPackageInstalled } from "./package.js"
import {
  applyUfwRulePortsForApply,
  checkInactiveUfwRulePort,
  checkUfwRulePort,
  readUfwRuleStatusForApply,
  readUfwShowAdded,
  rejectWhenDenyingCurrentSshPort,
  rejectWhenDenyingLiveSshdPort,
  type UfwRuleAction,
  type UfwRuleKeyword,
} from "./ufwRuleHelpers.js"
import {
  classifyUfwStatusTcpAccess,
  hasProtocolAgnosticIpv6Rule,
  hasProtocolAgnosticRule,
  hasTcpIpv6Rule,
  hasTcpRule,
  readUfwStatus,
  statusIncludesIpv6Rules,
  statusReportsActive,
} from "./ufwStatus.js"

const UFW = "ufw"

function hasProtocolAgnosticDenyRule(status: string, port: number): boolean {
  const ipv6Rules = statusIncludesIpv6Rules(status)
  return (
    hasProtocolAgnosticRule(status, port, "DENY") ||
    (ipv6Rules && hasProtocolAgnosticIpv6Rule(status, port, "DENY"))
  )
}

function currentSshPortNeedsAllowRule(status: string, port: number): boolean {
  const ipv6Rules = statusIncludesIpv6Rules(status)
  if (classifyUfwStatusTcpAccess(status, port) === "blocked") return true
  if (!hasProtocolAgnosticRule(status, port, "ALLOW")) return true
  return ipv6Rules && !hasProtocolAgnosticIpv6Rule(status, port, "ALLOW")
}

async function deleteDenyRulesForCurrentSshPort(
  ssh: SshConnection,
  status: string,
  port: number
): Promise<ModuleResult | null> {
  const ipv6Rules = statusIncludesIpv6Rules(status)
  const denyRulePorts: string[] = []
  if (hasProtocolAgnosticDenyRule(status, port)) denyRulePorts.push(String(port))
  if (hasTcpRule(status, port, "DENY") || (ipv6Rules && hasTcpIpv6Rule(status, port, "DENY"))) {
    denyRulePorts.push(`${String(port)}/tcp`)
  }
  for (const rulePort of denyRulePorts) {
    // eslint-disable-next-line no-await-in-loop -- keep ufw mutations sequential to avoid firewall lock races
    const result = await ssh.exec(`${UFW} delete ${shellQuote("deny")} ${shellQuote(rulePort)}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (result.code !== 0) {
      return failedCommand(
        `[ufw.enabled] ufw delete deny failed for current SSH port ${String(port)}`,
        result
      )
    }
  }
  return null
}

async function allowCurrentSshPort(ssh: SshConnection): Promise<ModuleResult | null> {
  const { port } = ssh.getConnectionInfo()
  if (!isValidTcpPort(port)) {
    return failed(`[ufw.enabled] current SSH port is invalid: ${String(port)}`)
  }
  const status = await readUfwStatus(ssh)
  if (status != null) {
    const deleteFailure = await deleteDenyRulesForCurrentSshPort(ssh, status, port)
    if (deleteFailure !== null) return deleteFailure
  }
  const result = await ssh.exec(`${UFW} allow ${shellQuote(String(port))}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? null
    : failedCommand(`[ufw.enabled] ufw allow failed for current SSH port ${String(port)}`, result)
}

async function checkInactiveUfwRule(parameters: {
  action: UfwRuleAction
  portList: number[]
  ssh: SshConnection
}): Promise<"needs-apply" | "ok"> {
  const { action, portList, ssh } = parameters
  process.stderr.write(
    `Warning: [ufw.rule: ${action} ${portList.join(",")}] ufw is inactive; ` +
      "rules are saved but not enforced until ufw.enabled() runs. " +
      "Verifying rule presence via `ufw show added`.\n"
  )
  const addedOutput = await readUfwShowAdded(ssh)
  for (const port of portList) {
    const portResult = checkInactiveUfwRulePort({ action, addedOutput, port })
    if (portResult === NEEDS_APPLY) return NEEDS_APPLY
  }
  return "ok"
}

function checkActiveUfwRule(parameters: {
  expectedAction: UfwRuleKeyword
  oppositeKeyword: UfwRuleKeyword
  portList: number[]
  requireIpv6Rule: boolean
  status: string
}): "needs-apply" | "ok" {
  const { expectedAction, oppositeKeyword, portList, requireIpv6Rule, status } = parameters
  for (const port of portList) {
    const portResult = checkUfwRulePort({
      expectedAction,
      oppositeKeyword,
      port,
      requireIpv6Rule,
      status,
    })
    if (portResult === NEEDS_APPLY) return NEEDS_APPLY
  }
  return "ok"
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
        if (pm == null || !(await isPackageInstalled(ssh, pm, UFW))) return { status: "ok" }
        // R-0000489: skip the disable when ufw is already inactive.
        const status = await readUfwStatus(ssh)
        if (status?.includes("Status: inactive")) return { status: "ok" }
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

        // R-0000251: tolerate hosts where `ufw status` exits non-zero or the
        // binary disappeared between the package-installed probe and the
        // status read. `readUfwStatus` returns `null` in that case, which we
        // treat as "the disabled state is satisfied" so the check does not
        // throw an unstructured SSH error.
        const status = await readUfwStatus(ssh)
        if (status == null) return "ok"
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
        // R-0000251: when ufw is not installed or `ufw status` exits non-zero,
        // `readUfwStatus` returns `null`. Treat that as `needs-apply` (apply
        // installs/enables ufw) instead of throwing an unstructured SSH
        // error from `ssh.output`.
        const status = await readUfwStatus(ssh)
        if (status == null) return NEEDS_APPLY
        if (!status.includes("Status: active")) return NEEDS_APPLY

        const { port } = ssh.getConnectionInfo()
        if (!isValidTcpPort(port)) return NEEDS_APPLY

        if (currentSshPortNeedsAllowRule(status, port)) return NEEDS_APPLY
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
    const oppositeAction: UfwRuleAction = action === "allow" ? "deny" : "allow"
    const expectedAction: UfwRuleKeyword = action === "allow" ? "ALLOW" : "DENY"
    const oppositeKeyword: UfwRuleKeyword = action === "allow" ? "DENY" : "ALLOW"
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh)
          return failed(`[ufw.rule: ${action} ${portList.join(",")}] SSH connection is required`)

        const lockoutFailure = rejectWhenDenyingCurrentSshPort({ action, portList, ssh })
        if (lockoutFailure !== null) return lockoutFailure
        // R-0000615: also probe live sshd listeners before applying a deny.
        // The static check above only protects the SshConfig ports; this
        // catches additional active listeners (e.g. a maintenance port, a
        // socket-activated systemd listener, or a previous sshd.port apply
        // that has not yet been picked up by SshConfig).
        const liveSshdFailure = await rejectWhenDenyingLiveSshdPort({ action, portList, ssh })
        if (liveSshdFailure !== null) return liveSshdFailure

        const statusOutcome = await readUfwRuleStatusForApply(ssh, { action, portList })
        if ("failure" in statusOutcome) return statusOutcome.failure
        return applyUfwRulePortsForApply({
          action,
          oppositeAction,
          oppositeKeyword,
          portList,
          ssh,
          status: statusOutcome.status,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        // R-0000281: tolerate hosts where `ufw status` exits non-zero or the
        // binary is missing. `readUfwStatus` returns `null` in that case;
        // treat that as drift so apply runs (apply will surface the missing
        // binary as a structured failure instead of an unstructured SSH
        // error).
        const status = await readUfwStatus(ssh)
        if (status == null) return NEEDS_APPLY
        // R-0000555: when ufw is inactive the rules table is absent, so the
        // protocol-agnostic match against `ufw status` always returns
        // NEEDS_APPLY and apply would loop forever. Fall back to
        // `ufw show added`, which lists queued rules even while ufw is
        // disabled, and warn the operator that `ufw.enabled` is missing.
        if (!statusReportsActive(status)) {
          return checkInactiveUfwRule({ action, portList, ssh })
        }
        return checkActiveUfwRule({
          expectedAction,
          oppositeKeyword,
          portList,
          requireIpv6Rule: statusIncludesIpv6Rules(status),
          status,
        })
      },
      name: `ufw.rule: ${action} ${portList.join(",")}`,
    }
  },
}
