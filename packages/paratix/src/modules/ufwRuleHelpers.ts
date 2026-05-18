import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { liveSshdPortMatches, LiveSshdPortProbeError } from "./sshdPortLivenessProbe.js"
import {
  hasProtocolAgnosticIpv6Rule,
  hasProtocolAgnosticRule,
  readUfwStatusDetailed,
  statusIncludesIpv6Rules,
  tcpRelevantRuleDeletePorts,
} from "./ufwStatus.js"

const UFW = "ufw"

export type UfwRuleAction = "allow" | "deny"
export type UfwRuleKeyword = "ALLOW" | "DENY"

function ufwRuleApplyChanged(stdout: string): boolean {
  const lines = stdout
    .split(/\r?\n/v)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  if (lines.length === 0) return true
  return lines.some((line) => !line.startsWith("Skipping adding existing rule"))
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
// R-0000543: also refuse to deny any port that ssh.ports is configured to
// reconnect through. A reconnect attempt after sshd.port or a network blip
// would otherwise pick a port that ufw now blocks and lose the session
// permanently.
export function rejectWhenDenyingCurrentSshPort(input: {
  action: UfwRuleAction
  portList: number[]
  ssh: SshConnection
}): ModuleResult | null {
  const { action, portList, ssh } = input
  if (action !== "deny") return null
  const { configuredPorts, port: currentSshPort } = ssh.getConnectionInfo()
  // R-0000820: refuse to build the `protectedPorts` set when the live SSH
  // port reported by the connection is not a valid TCP port. A bogus value
  // (NaN, Infinity, fractional, out of range) would silently make the
  // lockout guard match nothing and let a deny rule on the live SSH port
  // through. Surface the inconsistency as a structured failure so the
  // operator can fix the connection metadata before retrying.
  if (!isValidTcpPort(currentSshPort)) {
    return failed(
      `[ufw.rule: ${action} ${portList.join(",")}] refuses to evaluate SSH lockout protection: ` +
        `current SSH port ${JSON.stringify(currentSshPort)} is not a valid TCP port`
    )
  }
  const protectedPorts = new Set<number>([currentSshPort, ...configuredPorts])
  const conflictingPorts = portList.filter((port) => protectedPorts.has(port))
  if (conflictingPorts.length === 0) return null
  return failed(
    `[ufw.rule: ${action} ${portList.join(",")}] refuses to deny SSH reconnect port(s) ` +
      `${conflictingPorts.join(",")} ` +
      `(current: ${String(currentSshPort)}, configured: ${configuredPorts.join(",")}); ` +
      "would lock the runner out"
  )
}

// R-0000615: the static `rejectWhenDenyingCurrentSshPort` check only protects
// the SshConfig-declared ports. A live sshd bound to an additional port (for
// example because a previous run set `sshd.port` to a different value, an
// admin restarted sshd on a maintenance port, or socket-activation listeners
// span multiple ports) would still be silently denied. Probe `ss -ltn` for an
// active listener on each candidate port immediately before the deny is
// applied and refuse the rule if any of them is currently serving traffic.
//
// R-0000625: route the probe through the shared
// `liveSshdPortMatches`/`LiveSshdPortProbeError` pair in
// `sshdPortLivenessProbe.ts` instead of duplicating the `ss` parser. The
// duplicate previously treated *every* non-zero `ss` exit as "no listener"
// (fail-open) and would therefore silently allow a deny on the live SSH
// port whenever `ss` was missing or returned a permission denied. The
// shared helper distinguishes "no listener yet" (continue) from "hard
// environmental failure" (`LiveSshdPortProbeError`, surface as a structured
// failure) so the R-0000615 lockout guard cannot be bypassed by an absent
// or unprivileged `ss` binary on the target host.
export async function rejectWhenDenyingLiveSshdPort(input: {
  action: UfwRuleAction
  portList: number[]
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { action, portList, ssh } = input
  if (action !== "deny") return null
  const conflictingPorts: number[] = []
  const tag = `ufw.rule: ${action} ${portList.join(",")}`
  for (const port of portList) {
    try {
      // eslint-disable-next-line no-await-in-loop -- probe ports sequentially; each call hits ss on the remote host
      const matched = await liveSshdPortMatches(ssh, { tag, targetPort: port })
      if (matched) conflictingPorts.push(port)
    } catch (error) {
      if (error instanceof LiveSshdPortProbeError) {
        // R-0000625: a missing `ss` binary or a permission denial would
        // otherwise let the deny through (the old duplicate parser
        // returned `false` on every non-zero exit). Surface the
        // environmental failure as a structured module error so the
        // lockout guard from R-0000615 keeps its teeth.
        return failed(error.message)
      }
      throw error
    }
  }
  if (conflictingPorts.length === 0) return null
  return failed(
    `[ufw.rule: ${action} ${portList.join(",")}] refuses to deny port(s) ` +
      `${conflictingPorts.join(",")} ` +
      "currently served by a live sshd listener; would lock the runner out"
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
// R-0000551: use the detailed reader so a permission denied on
// `ufw status` is not misreported as "ufw is not installed".
export async function readUfwRuleStatusForApply(
  ssh: SshConnection,
  parameters: { action: UfwRuleAction; portList: number[] }
): Promise<{ failure: ModuleResult } | { status: string }> {
  const { action, portList } = parameters
  const statusRead = await readUfwStatusDetailed(ssh)
  if (statusRead.kind === "missing") {
    return {
      failure: failed(
        `[ufw.rule: ${action} ${portList.join(",")}] ufw is not installed; install ufw before adding rules`
      ),
    }
  }
  if (statusRead.kind === "unreadable") {
    return {
      failure: failed(
        `[ufw.rule: ${action} ${portList.join(",")}] could not read ufw status ` +
          `(ufw binary present but \`ufw status\` failed): ${statusRead.detail}`
      ),
    }
  }
  return { status: statusRead.status }
}

export async function applyUfwRulePortsForApply(input: {
  action: UfwRuleAction
  oppositeAction: UfwRuleAction
  oppositeKeyword: UfwRuleKeyword
  portList: number[]
  ssh: SshConnection
  status: string
}): Promise<ModuleResult> {
  const { action, oppositeAction, oppositeKeyword, portList, ssh, status } = input
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
}

// R-0000555: when ufw is inactive the rules table is missing from
// `ufw status`. `ufw show added` lists rules that have been queued but are
// not yet enforced, which lets the check distinguish "rule was added but ufw
// is disabled" from "rule does not exist at all".
export async function readUfwShowAdded(ssh: SshConnection): Promise<null | string> {
  try {
    return await ssh.output(`${UFW} show added`)
  } catch {
    return null
  }
}

// R-0000654: defense-in-depth port validation before regex interpolation.
// `ufw.rule` already validates ports via `isValidTcpPort` at construction
// time, but a future caller could still pass NaN, Infinity, a fractional
// or out-of-range value into the helper. NaN/Infinity stringify into the
// regex and break the match; a negative or fractional value would build
// a surprising pattern. Reject anything outside [1, 65535] before
// interpolation as a fail-fast guard.
const TCP_PORT_MIN = 1
const TCP_PORT_MAX = 65_535

function assertTcpPortForRegex(port: number): void {
  if (!Number.isInteger(port) || port < TCP_PORT_MIN || port > TCP_PORT_MAX) {
    throw new Error(
      `ufw rule port ${JSON.stringify(port)} is invalid; expected integer in [${String(TCP_PORT_MIN)}, ${String(TCP_PORT_MAX)}]`
    )
  }
}

function hasAddedUfwRule(output: string, action: UfwRuleAction, port: number): boolean {
  assertTcpPortForRegex(port)
  // `ufw show added` emits commands like `ufw allow 22` or `ufw deny 22/tcp`.
  // Match the action keyword followed by the bare port (protocol-agnostic) at
  // a word boundary so port 22 does not match 5022 or 22000.
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`\\b${action}\\s+${port}(?:\\b|/)`, "v").test(output)
}

export function checkInactiveUfwRulePort(input: {
  action: UfwRuleAction
  addedOutput: null | string
  port: number
}): "needs-apply" | "ok" {
  const { action, addedOutput, port } = input
  if (addedOutput == null) return NEEDS_APPLY
  return hasAddedUfwRule(addedOutput, action, port) ? "ok" : NEEDS_APPLY
}

export function checkUfwRulePort(input: {
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
