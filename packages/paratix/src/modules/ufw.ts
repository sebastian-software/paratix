import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { withMutexLock } from "./moduleHelpers.js"
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
  readUfwStatusDetailed,
  statusIncludesIpv6Rules,
  statusReportsActive,
} from "./ufwStatus.js"

const UFW = "ufw"
// R-0000783: serialise the allow + reverify + enable critical section under
// a dedicated mutex name. The lock prevents two paratix runners on the same
// host from interleaving `ufw allow $sshPort` and `ufw --force enable`,
// which could otherwise race a competing `ufw delete allow` insertion
// between the reverify probe and the enable command and lock the runner
// out. External processes (manual `ufw` invocations, other configuration
// management tools) still bypass this lock; the residual race window is
// documented in `ufw.enabled.apply` so operators can reason about it.
const UFW_ENABLE_LOCK_NAME = "ufw-enable-mutex"

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

// R-0000653: lockout guard between `ufw allow ${port}` and `ufw --force
// enable`. Re-read `ufw status` and confirm the current SSH port is
// `allowed` according to `classifyUfwStatusTcpAccess`. A `blocked`
// classification means a concurrent process re-inserted a contradictory
// deny rule (or our allow did not land); fail before flipping ufw active
// so the runner does not lock itself out. An `inactive` classification is
// expected when the firewall is still off — the enable that follows is
// the activating step and there is no race window with already-enforced
// rules. An `unknown`/`null` status (transient `ufw status` failure) is
// also treated as fail-closed because we cannot prove the rule landed.
async function reverifyCurrentSshAllowedBeforeEnable(
  ssh: SshConnection
): Promise<ModuleResult | null> {
  const { port } = ssh.getConnectionInfo()
  if (!isValidTcpPort(port)) {
    return failed(`[ufw.enabled] current SSH port is invalid: ${String(port)}`)
  }
  const status = await readUfwStatus(ssh)
  if (status == null) {
    return failed(
      `[ufw.enabled] could not re-read ufw status before enable; refusing to enable ` +
        `to avoid locking out the current SSH port ${String(port)}`
    )
  }
  const access = classifyUfwStatusTcpAccess(status, port)
  if (access === "allowed" || access === "inactive") return null
  return failed(
    `[ufw.enabled] re-verification before enable: current SSH port ${String(port)} ` +
      `is not allowed (classification: ${access}); a concurrent deny rule may have ` +
      "been inserted, refusing to enable to avoid locking the runner out"
  )
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

        // R-0000775: distinguish "ufw missing" from "ufw unreadable". The
        // previous implementation routed both through `readUfwStatus`, which
        // returns `null` in either case and was conservatively treated as
        // satisfied. That hid genuine drift on hosts where `ufw` was installed
        // but `ufw status` exited non-zero (e.g. permission denied, transient
        // race). Use `readUfwStatusDetailed` so a missing binary keeps the
        // historical "satisfied" outcome while an unreadable status triggers
        // `needs-apply` and forces apply to re-run.
        const detailed = await readUfwStatusDetailed(ssh)
        if (detailed.kind === "missing") return "ok"
        if (detailed.kind === "unreadable") return NEEDS_APPLY
        return detailed.status.includes("Status: inactive") ? "ok" : NEEDS_APPLY
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
        // R-0000783: serialise allow + reverify + enable under a dedicated
        // mutex so two paratix runners on the same host cannot interleave
        // their critical sections. The lock closes the in-process race
        // window between `ufw allow ${sshPort}`, the reverify status read,
        // and `ufw --force enable`. External callers (manual `ufw delete`,
        // other configuration tools) are not subject to the lock — their
        // residual race window is unavoidable from inside paratix and the
        // reverify step at line 229 below remains the last line of
        // defence against an externally-inserted deny rule landing right
        // before enable.
        const mutexResult = await withMutexLock<ModuleResult>(ssh, {
          failureMessage: "[ufw.enabled]",
          lockName: UFW_ENABLE_LOCK_NAME,
          async section(): Promise<ModuleResult> {
            const allowResult = await allowCurrentSshPort(ssh)
            if (allowResult !== null) return allowResult
            // R-0000653: a concurrent process could insert a `deny` rule for
            // the active SSH port between the initial `ufw status` read in
            // `allowCurrentSshPort` and the `ufw allow` that follows. ufw
            // evaluates rules in insertion order, so a deny appended after
            // we deleted the older ones (or before our allow) would survive
            // `--force enable` and lock the runner out. Re-read the status
            // and abort before enable when the SSH port is not reachable
            // through the rule set.
            const reverifyFailure = await reverifyCurrentSshAllowedBeforeEnable(ssh)
            if (reverifyFailure !== null) return reverifyFailure
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
        })
        return mutexResult.kind === "ok" ? mutexResult.value : mutexResult.failure
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
