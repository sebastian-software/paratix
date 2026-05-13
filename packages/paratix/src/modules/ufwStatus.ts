import type { SshConnection } from "../types.js"

const UFW = "ufw"

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
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(`^${port}\\s+\\(v6\\)\\s+${action}\\b`, "mv").test(status)
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
 * Read `ufw status` once. Returns the captured output when ufw is installed
 * and reachable, or `null` when the command is not available (typical when
 * ufw is not installed). Callers can treat `null` as "no firewall guard
 * required" without a separate package-installed probe.
 *
 * Uses `ssh.output` so callers can rely on the same code path that the
 * `ufw.disabled.check` module uses; failures (such as a missing `ufw` binary
 * or a non-zero exit) are reported as `null` instead of bubbling up.
 *
 * @param ssh - The remote SSH connection.
 * @returns The trimmed `ufw status` output, or `null` when ufw is unavailable.
 */
export async function readUfwStatus(ssh: SshConnection): Promise<null | string> {
  try {
    return await ssh.output(`${UFW} status`)
  } catch {
    return null
  }
}

/**
 * Decide whether the live UFW configuration would let traffic reach
 * `targetPort`. Returns:
 * - `"inactive"` when ufw is not installed or not currently enabled.
 * - `"allowed"` when ufw is active and a protocol-agnostic ALLOW rule for
 *   `targetPort` is present (including the IPv6 variant when IPv6 rules are
 *   reported).
 * - `"blocked"` when ufw is active but no such ALLOW rule exists, or when a
 *   contradictory DENY rule for `targetPort` is present.
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
  if (!statusReportsActive(status)) return "inactive"
  if (hasProtocolAgnosticRule(status, targetPort, "DENY")) return "blocked"
  if (statusIncludesIpv6Rules(status) && hasProtocolAgnosticIpv6Rule(status, targetPort, "DENY")) {
    return "blocked"
  }
  if (!hasProtocolAgnosticRule(status, targetPort, "ALLOW")) return "blocked"
  if (
    statusIncludesIpv6Rules(status) &&
    !hasProtocolAgnosticIpv6Rule(status, targetPort, "ALLOW")
  ) {
    return "blocked"
  }
  return "allowed"
}
