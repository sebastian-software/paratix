import type { SshConnection } from "../types.js"

const UFW = "ufw"

// R-0000654: defense-in-depth port validation before regex interpolation.
// Callers are already expected to validate ports via `isValidTcpPort`
// (e.g. `ufw.rule` rejects out-of-range values at construction time), but
// a future caller could still pass NaN, Infinity, a non-integer, or a
// value outside [1, 65535]. NaN/Infinity stringify to "NaN" / "Infinity"
// inside the regex and break the match; a negative number or fractional
// value would produce a broken or surprisingly permissive pattern. This
// in-helper assertion is a fail-fast belt-and-braces guard rather than
// the primary validation layer.
const TCP_PORT_MIN = 1
const TCP_PORT_MAX = 65_535

function assertTcpPortForRegex(port: number): void {
  if (!Number.isInteger(port) || port < TCP_PORT_MIN || port > TCP_PORT_MAX) {
    throw new Error(
      `ufw status port ${JSON.stringify(port)} is invalid; expected integer in [${String(TCP_PORT_MIN)}, ${String(TCP_PORT_MAX)}]`
    )
  }
}

/**
 * Match only the protocol-agnostic form `<port> ACTION`. Protocol-specific
 * entries like `22/tcp ALLOW`, opposite actions, and similar ports must not
 * satisfy the rule.
 *
 * @param status - The captured `ufw status` output.
 * @param port - The port number to look for at the start of a rule line.
 * @param action - The expected ufw action keyword.
 * @returns `true` when a matching protocol-agnostic line is present.
 */
export function hasProtocolAgnosticRule(
  status: string,
  port: number,
  action: "ALLOW" | "DENY"
): boolean {
  assertTcpPortForRegex(port)
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}\\s+${action}\\b`, "mv").test(status)
}

/**
 * Match the IPv6 variant `<port> (v6) ACTION` reported by ufw when IPv6 is
 * enabled.
 *
 * @param status - The captured `ufw status` output.
 * @param port - The port number to look for.
 * @param action - The expected ufw action keyword.
 * @returns `true` when a matching IPv6 rule line is present.
 */
export function hasProtocolAgnosticIpv6Rule(
  status: string,
  port: number,
  action: "ALLOW" | "DENY"
): boolean {
  assertTcpPortForRegex(port)
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}\\s+\\(v6\\)\\s+${action}\\b`, "mv").test(status)
}

/**
 * Match the TCP-specific form `<port>/tcp ACTION`.
 *
 * @param status - The captured `ufw status` output.
 * @param port - The port number to look for at the start of a rule line.
 * @param action - The expected ufw action keyword.
 * @returns `true` when a matching TCP-specific line is present.
 */
export function hasTcpRule(status: string, port: number, action: "ALLOW" | "DENY"): boolean {
  assertTcpPortForRegex(port)
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}/tcp\\s+${action}\\b`, "mv").test(status)
}

/**
 * Match the IPv6 TCP-specific form `<port>/tcp (v6) ACTION`.
 *
 * @param status - The captured `ufw status` output.
 * @param port - The port number to look for at the start of a rule line.
 * @param action - The expected ufw action keyword.
 * @returns `true` when a matching IPv6 TCP-specific line is present.
 */
export function hasTcpIpv6Rule(status: string, port: number, action: "ALLOW" | "DENY"): boolean {
  assertTcpPortForRegex(port)
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}/tcp\\s+\\(v6\\)\\s+${action}\\b`, "mv").test(status)
}

export function tcpRelevantRuleDeletePorts(input: {
  action: "ALLOW" | "DENY"
  includeIpv6: boolean
  port: number
  status: string
}): string[] {
  const { action, includeIpv6, port, status } = input
  const rulePorts = new Set<string>()
  if (hasProtocolAgnosticRule(status, port, action)) rulePorts.add(String(port))
  if (includeIpv6 && hasProtocolAgnosticIpv6Rule(status, port, action)) rulePorts.add(String(port))
  if (hasTcpRule(status, port, action)) rulePorts.add(`${String(port)}/tcp`)
  if (includeIpv6 && hasTcpIpv6Rule(status, port, action)) rulePorts.add(`${String(port)}/tcp`)
  return [...rulePorts]
}

/**
 * @param status - The captured `ufw status` output.
 * @returns `true` when the output reports any IPv6 rules.
 */
export function statusIncludesIpv6Rules(status: string): boolean {
  return status.includes("(v6)")
}

/**
 * @param status - The captured `ufw status` output.
 * @returns `true` when the output reports `Status: active`.
 */
export function statusReportsActive(status: string): boolean {
  return status.includes("Status: active")
}

/**
 * Tagged result returned by {@link readUfwStatusDetailed}. Distinguishes the
 * three relevant outcomes so callers can produce accurate diagnostics:
 *
 *   `ok` — `ufw status` returned and the trimmed output is in `status`.
 *   `missing` — `ufw` is not on PATH (binary not installed).
 *   `unreadable` — `ufw` exists but `ufw status` failed (typically a
 *     permission error or a transient race). The original error message is
 *     preserved in `detail` for surfacing to the operator.
 */
export type UfwStatusReadResult =
  { detail: string; kind: "unreadable" } | { kind: "missing" } | { kind: "ok"; status: string }

// R-0000551: probe `ufw` separately from `ufw status` so the two failure modes
// can be distinguished. `ssh.test` returns a plain boolean; checking
// `command -v ufw` keeps the probe portable across shells.
async function isUfwInstalled(ssh: SshConnection): Promise<boolean> {
  try {
    return await ssh.test(`command -v ${UFW}`)
  } catch {
    // If even the probe blows up (network glitch, sudo failure), assume the
    // binary is present and let the actual `ufw status` call surface the real
    // error — better to over-report the unreadable path than to misclassify
    // the host as not having ufw installed.
    return true
  }
}

/**
 * Read `ufw status` and classify the result. Unlike {@link readUfwStatus} the
 * caller can tell whether `ufw` is missing entirely versus simply unreadable
 * (permission denied, transient race, etc.).
 *
 * @param ssh - The remote SSH connection.
 * @returns The classified read result.
 */
export async function readUfwStatusDetailed(ssh: SshConnection): Promise<UfwStatusReadResult> {
  const installed = await isUfwInstalled(ssh)
  if (!installed) return { kind: "missing" }
  try {
    const status = await ssh.output(`${UFW} status`)
    return { kind: "ok", status }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return { detail, kind: "unreadable" }
  }
}

/**
 * Read `ufw status` once. Returns the captured output when ufw is installed
 * and reachable, or `null` when the command is not available (typical when
 * ufw is not installed). Callers can treat `null` as "no firewall guard
 * required" without a separate package-installed probe.
 *
 * Uses `ssh.output` so callers can rely on the same code path that the
 * `ufw.disabled.check` module uses; failures (such as a missing `ufw` binary
 * or a non-zero exit) are reported as `null` instead of bubbling up.
 *
 * Prefer {@link readUfwStatusDetailed} when the caller needs to distinguish
 * "ufw is not installed" from "ufw is installed but unreadable".
 *
 * @param ssh - The remote SSH connection.
 * @returns The trimmed `ufw status` output, or `null` when ufw is unavailable.
 */
export async function readUfwStatus(ssh: SshConnection): Promise<null | string> {
  const detailed = await readUfwStatusDetailed(ssh)
  return detailed.kind === "ok" ? detailed.status : null
}

type UfwAccess = "allowed" | "blocked" | "inactive"
type UfwAccessProbe = "unknown" | UfwAccess

function hasTcpRelevantDenyRule(status: string, targetPort: number): boolean {
  const ipv6Rules = statusIncludesIpv6Rules(status)
  return (
    hasProtocolAgnosticRule(status, targetPort, "DENY") ||
    hasTcpRule(status, targetPort, "DENY") ||
    (ipv6Rules &&
      (hasProtocolAgnosticIpv6Rule(status, targetPort, "DENY") ||
        hasTcpIpv6Rule(status, targetPort, "DENY")))
  )
}

function hasTcpRelevantAllowRule(status: string, targetPort: number): boolean {
  return (
    hasProtocolAgnosticRule(status, targetPort, "ALLOW") || hasTcpRule(status, targetPort, "ALLOW")
  )
}

function hasTcpRelevantIpv6AllowRule(status: string, targetPort: number): boolean {
  return (
    hasProtocolAgnosticIpv6Rule(status, targetPort, "ALLOW") ||
    hasTcpIpv6Rule(status, targetPort, "ALLOW")
  )
}

/**
 * Classify whether a captured UFW status allows SSH/TCP traffic to
 * `targetPort`. TCP-specific entries count for reachability; explicit DENY
 * entries win over ALLOW entries.
 *
 * @param status - The captured `ufw status` output.
 * @param targetPort - The SSH/TCP port whose reachability should be classified.
 * @returns The current access classification for `targetPort`.
 */
export function classifyUfwStatusTcpAccess(status: string, targetPort: number): UfwAccess {
  if (!statusReportsActive(status)) return "inactive"
  if (hasTcpRelevantDenyRule(status, targetPort)) return "blocked"
  if (!hasTcpRelevantAllowRule(status, targetPort)) return "blocked"
  if (statusIncludesIpv6Rules(status) && !hasTcpRelevantIpv6AllowRule(status, targetPort)) {
    return "blocked"
  }
  return "allowed"
}

/**
 * Decide whether the live UFW configuration would let traffic reach
 * `targetPort`. Returns:
 * - `"inactive"` when ufw is not installed or not currently enabled.
 * - `"allowed"` when ufw is active and an ALLOW rule reaches `targetPort`
 *   over TCP (including the IPv6 variant when IPv6 rules are reported).
 * - `"blocked"` when ufw is active but no such ALLOW rule exists, or when a
 *   TCP-relevant DENY rule for `targetPort` is present.
 *
 * @param ssh - The remote SSH connection.
 * @param targetPort - The port whose reachability should be classified.
 * @returns The current access classification for `targetPort`.
 */
export async function classifyUfwAccess(
  ssh: SshConnection,
  targetPort: number
): Promise<"allowed" | "blocked" | "inactive"> {
  const status = await readUfwStatus(ssh)
  if (status == null) return "inactive"
  return classifyUfwStatusTcpAccess(status, targetPort)
}

/**
 * Decide whether the live UFW configuration would let traffic reach
 * `targetPort`, preserving an unreadable status as `"unknown"` for callers
 * that must fail closed instead of treating it like an inactive firewall.
 *
 * Routes through {@link readUfwStatusDetailed} so the two failure modes can
 * be distinguished:
 *   - `missing` (ufw binary not installed) → `"inactive"` — no firewall is
 *     enforcing rules, so the lockout-guard does not need to fire.
 *   - `unreadable` (ufw installed but `ufw status` failed, typically a
 *     permission error or transient race) → `"unknown"` — caller must
 *     fail closed because we cannot confirm the rule state.
 *   - `ok` → classify the captured status via
 *     {@link classifyUfwStatusTcpAccess}.
 *
 * R-0000627: previously this collapsed both `missing` and `unreadable` to
 * `null` via {@link readUfwStatus}, which forced `sshd.port` to hard-fail
 * with `unknownUfwStatusFailure` on every host without ufw installed.
 *
 * @param ssh - The remote SSH connection.
 * @param targetPort - The port whose reachability should be classified.
 * @returns The current access classification for `targetPort`, or
 *   `"unknown"` when `ufw status` cannot be read.
 */
export async function classifyUfwAccessOrUnknown(
  ssh: SshConnection,
  targetPort: number
): Promise<UfwAccessProbe> {
  const statusRead = await readUfwStatusDetailed(ssh)
  if (statusRead.kind === "missing") return "inactive"
  if (statusRead.kind === "unreadable") return "unknown"
  return classifyUfwStatusTcpAccess(statusRead.status, targetPort)
}
