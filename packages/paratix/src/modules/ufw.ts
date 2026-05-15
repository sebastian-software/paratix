import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { detectPackageManager, isPackageInstalled } from "./package.js"
import {
  classifyUfwStatusTcpAccess,
  hasProtocolAgnosticIpv6Rule,
  hasProtocolAgnosticRule,
  hasTcpIpv6Rule,
  hasTcpRule,
  readUfwStatus,
  statusIncludesIpv6Rules,
  tcpRelevantRuleDeletePorts,
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

function ufwRuleApplyChanged(stdout: string): boolean {
  const lines = stdout
    .split(/\r?\n/v)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  if (lines.length === 0) return true
  return lines.some((line) => !line.startsWith("Skipping adding existing rule"))
}

type UfwRuleAction = "allow" | "deny"
type UfwRuleKeyword = "ALLOW" | "DENY"

// Apply phase helper for `ufw.rule`: when a contradictory `allow`/`deny`
// rule for the port still exists, delete it before adding the desired
// rule. Returns a `ModuleResult` only on failure; otherwise reports
// whether the delete actually changed the firewall.
async function deleteOppositeRule(input: {
  action: UfwRuleAction
  ipv6Rules: boolean
  oppositeAction: UfwRuleAction
  oppositeKeyword: UfwRuleKeyword
  port: number
  portList: number[]
  ssh: SshConnection
  status: string
}): Promise<{ changed: boolean; failure: ModuleResult | null }> {
  const { action, ipv6Rules, oppositeAction, oppositeKeyword, port, portList, ssh, status } = input
  const deleteRulePorts = tcpRelevantRuleDeletePorts({
    action: oppositeKeyword,
    includeIpv6: ipv6Rules,
    port,
    status,
  })
  if (deleteRulePorts.length === 0) return { changed: false, failure: null }
  for (const rulePort of deleteRulePorts) {
    // eslint-disable-next-line no-await-in-loop -- keep ufw mutations sequential to avoid firewall lock races
    const deleteResult = await ssh.exec(
      `${UFW} delete ${shellQuote(oppositeAction)} ${shellQuote(rulePort)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (deleteResult.code !== 0) {
      return {
        changed: false,
        failure: failedCommand(
          `[ufw.rule: ${action} ${portList.join(",")}] ufw delete ${oppositeAction} failed for port ${rulePort}`,
          deleteResult
        ),
      }
    }
  }
  return { changed: true, failure: null }
}

// R-0000282: refuse to deny the port the runner is currently connected on.
// `applyUfwRulePort` deletes the contradictory `allow` entry before adding the
// `deny`, which on the live SSH port would immediately lock out the runner.
// Mirrors the lockout guard in `sshd.port` (`ufwBlocksPortFailure`).
function rejectWhenDenyingCurrentSshPort(input: {
  action: UfwRuleAction
  portList: number[]
  ssh: SshConnection
}): ModuleResult | null {
  const { action, portList, ssh } = input
  if (action !== "deny") return null
  const { port: currentSshPort } = ssh.getConnectionInfo()
  if (!portList.includes(currentSshPort)) return null
  return failed(
    `[ufw.rule: ${action} ${portList.join(",")}] refuses to deny current SSH port ` +
      `${String(currentSshPort)}; would lock the runner out`
  )
}

async function applyUfwRulePort(input: {
  action: UfwRuleAction
  ipv6Rules: boolean
  oppositeAction: UfwRuleAction
  oppositeKeyword: UfwRuleKeyword
  port: number
  portList: number[]
  ssh: SshConnection
  status: string
}): Promise<{ changed: boolean; failure: ModuleResult | null }> {
  const { action, port, portList, ssh } = input
  const deleteOutcome = await deleteOppositeRule(input)
  if (deleteOutcome.failure) return deleteOutcome

  const result = await ssh.exec(`${UFW} ${shellQuote(action)} ${shellQuote(String(port))}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) {
    return {
      changed: false,
      failure: failedCommand(
        `[ufw.rule: ${action} ${portList.join(",")}] ufw ${action} failed for port ${String(port)}`,
        result
      ),
    }
  }
  // R-0000076/R-0000114: ufw prints "Skipping adding existing rule"
  // per address family. Treat the command as a no-op only when all
  // emitted family lines are skips; a mixed skip/add output still
  // means one family was repaired.
  return { changed: deleteOutcome.changed || ufwRuleApplyChanged(result.stdout), failure: null }
}

function checkUfwRulePort(input: {
  expectedAction: UfwRuleKeyword
  oppositeKeyword: UfwRuleKeyword
  port: number
  requireIpv6Rule: boolean
  status: string
}): "needs-apply" | "ok" {
  const { expectedAction, oppositeKeyword, port, requireIpv6Rule, status } = input
  // R-0000118: match only the protocol-agnostic form `<port> ACTION`.
  // The caller asked for `ufw <action> <port>` (no /tcp or /udp
  // suffix), which adds rules for both protocols. Accepting a
  // protocol-specific entry like `22/tcp ALLOW` here would hide a
  // drift where only one protocol is configured and apply would
  // therefore add a second, parametrically different rule.
  // Anchor the port at the line start and require a whitespace
  // boundary so port 22 does not match 5022, 1022, 2222 etc.
  if (!hasProtocolAgnosticRule(status, port, expectedAction)) return NEEDS_APPLY
  if (requireIpv6Rule && !hasProtocolAgnosticIpv6Rule(status, port, expectedAction)) {
    return NEEDS_APPLY
  }
  // R-0000174: contradictory leftover rules are drift even when the desired rule is
  // also present. ufw evaluates rules in order, so the older opposite
  // entry can shadow the new one. Force apply to remove it.
  if (
    tcpRelevantRuleDeletePorts({
      action: oppositeKeyword,
      includeIpv6: requireIpv6Rule,
      port,
      status,
    }).length > 0
  ) {
    return NEEDS_APPLY
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

        // R-0000281: route through `readUfwStatus` (the same guard that
        // `ufw.disabled`/`ufw.enabled` use) so a missing or unreachable ufw
        // binary surfaces as a structured failure instead of an unstructured
        // SSH error from `ssh.output`. Adding rules requires ufw to be
        // installed; treat `null` as a hard failure for apply.
        // R-0000174: read status once up front so we can drop a contradictory
        // predecessor rule before adding the desired one. ufw evaluates rules
        // in order, so a stale `allow` left in place when switching to `deny`
        // (or vice versa) can shadow the new rule. Probing the status first
        // lets us avoid issuing `ufw delete` for ports with no contradictory
        // entry, which keeps the apply quiet on steady state.
        const status = await readUfwStatus(ssh)
        if (status == null) {
          return failed(
            `[ufw.rule: ${action} ${portList.join(",")}] ufw is not installed; install ufw before adding rules`
          )
        }
        const ipv6Rules = statusIncludesIpv6Rules(status)

        let anyChanged = false
        for (const port of portList) {
          // eslint-disable-next-line no-await-in-loop
          const outcome = await applyUfwRulePort({
            action,
            ipv6Rules,
            oppositeAction,
            oppositeKeyword,
            port,
            portList,
            ssh,
            status,
          })
          if (outcome.failure) return outcome.failure
          if (outcome.changed) anyChanged = true
        }

        return { status: anyChanged ? "changed" : "ok" }
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
        for (const port of portList) {
          const portResult = checkUfwRulePort({
            expectedAction,
            oppositeKeyword,
            port,
            requireIpv6Rule: statusIncludesIpv6Rules(status),
            status,
          })
          if (portResult === NEEDS_APPLY) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `ufw.rule: ${action} ${portList.join(",")}`,
    }
  },
}
