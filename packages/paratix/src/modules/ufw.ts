import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { detectPackageManager, isPackageInstalled } from "./package.js"
import {
  hasProtocolAgnosticIpv6Rule,
  hasProtocolAgnosticRule,
  statusIncludesIpv6Rules,
} from "./ufwStatus.js"

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

function hasOppositeRule(input: {
  ipv6Rules: boolean
  oppositeKeyword: UfwRuleKeyword
  port: number
  status: string
}): boolean {
  const { ipv6Rules, oppositeKeyword, port, status } = input
  if (hasProtocolAgnosticRule(status, port, oppositeKeyword)) return true
  return ipv6Rules && hasProtocolAgnosticIpv6Rule(status, port, oppositeKeyword)
}

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
  if (!hasOppositeRule({ ipv6Rules, oppositeKeyword, port, status })) {
    return { changed: false, failure: null }
  }
  // ufw does not expose a separate IPv6 delete; deleting the
  // protocol-agnostic opposite rule clears both families. The same
  // command therefore covers the IPv4-only and IPv6-only variants of the
  // contradictory entry.
  const deleteResult = await ssh.exec(
    `${UFW} delete ${shellQuote(oppositeAction)} ${shellQuote(String(port))}`,
    { ignoreExitCode: true, silent: true }
  )
  if (deleteResult.code !== 0) {
    return {
      changed: false,
      failure: failedCommand(
        `[ufw.rule: ${action} ${portList.join(",")}] ufw delete ${oppositeAction} failed for port ${String(port)}`,
        deleteResult
      ),
    }
  }
  return { changed: true, failure: null }
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
  // R-0000174: a contradictory leftover rule (`allow` when we want
  // `deny`, or vice versa) is drift even when the desired rule is
  // also present. ufw evaluates rules in order, so the older opposite
  // entry can shadow the new one. Force apply to remove it.
  if (hasOppositeRule({ ipv6Rules: requireIpv6Rule, oppositeKeyword, port, status })) {
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
    const oppositeAction: UfwRuleAction = action === "allow" ? "deny" : "allow"
    const expectedAction: UfwRuleKeyword = action === "allow" ? "ALLOW" : "DENY"
    const oppositeKeyword: UfwRuleKeyword = action === "allow" ? "DENY" : "ALLOW"
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh)
          return failed(`[ufw.rule: ${action} ${portList.join(",")}] SSH connection is required`)

        // R-0000174: read status once up front so we can drop a contradictory
        // predecessor rule before adding the desired one. ufw evaluates rules
        // in order, so a stale `allow` left in place when switching to `deny`
        // (or vice versa) can shadow the new rule. Probing the status first
        // lets us avoid issuing `ufw delete` for ports with no contradictory
        // entry, which keeps the apply quiet on steady state.
        const status = await ssh.output(`${UFW} status`)
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

        const status = await ssh.output(`${UFW} status`)
        const requireIpv6Rule = statusIncludesIpv6Rules(status)
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
      },
      name: `ufw.rule: ${action} ${portList.join(",")}`,
    }
  },
}
