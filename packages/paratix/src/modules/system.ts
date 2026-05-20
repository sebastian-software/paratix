import { environmentToMetaEntries, meta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  buildRebootMetaEntriesWithTimeout,
  type ResolveHostCallback,
} from "./resolveHostTimeout.js"

/**
 * Options for the reboot module.
 */
export type RebootOptions = {
  /**
   * Optional async function to resolve the new host address after a reboot.
   * Useful when the server's IP address may change (e.g. DHCP or cloud environments).
   *
   * R-0000575: the callback receives an `AbortSignal` that fires when the
   * configured timeout elapses. Honoring the signal lets DNS/cloud lookups
   * abort their in-flight work promptly.
   */
  resolveHost?: ResolveHostCallback
  /**
   * Wall-clock timeout (ms) applied to {@link RebootOptions.resolveHost}.
   * Defaults to 30 seconds. Mirrors R-0000243 in
   * {@link import("./releaseUpgrade.js")} so a stuck resolver cannot stall
   * the runner indefinitely.
   */
  resolveHostTimeoutMs?: number
}

/**
 * Detect SSH transport disconnects that originate from the remote host
 * tearing down the connection (for example when `shutdown -r now` causes the
 * sshd process to exit before the exec callback completes). Mirrors the
 * heuristic used in {@link import("./sshd.js")} so the reboot path treats a
 * disconnect mid-exec as a successful trigger instead of a hard failure.
 *
 * @param error - The error caught from `ssh.exec`.
 * @returns `true` if the error looks like a reboot-induced disconnect.
 */
function isRebootDisconnect(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return (
    message.includes("SSH connection closed") ||
    message.includes("ECONNRESET") ||
    message.includes("Connection reset")
  )
}

/**
 * Issue `shutdown -r now` and translate the various error shapes into either
 * `null` (reboot triggered, with or without disconnect) or a failure result.
 *
 * @param ssh - The active SSH connection.
 * @returns `null` on success, a {@link ModuleResult} with `status: "failed"` otherwise.
 */
async function triggerReboot(ssh: SshConnection): Promise<ModuleResult | null> {
  try {
    const result = await ssh.exec("shutdown -r now", { ignoreExitCode: true, silent: true })
    if (result.code !== 0) {
      return failedCommand("[system.reboot] shutdown -r now failed", result)
    }
  } catch (error) {
    // Many systems tear down the SSH session before the exec callback
    // returns with exit code 0, surfacing as an SSH disconnect error in
    // ssh2. Treat such disconnects as a successful reboot trigger so the
    // runner still receives the system.reboot meta and can reconnect.
    if (!isRebootDisconnect(error)) {
      const message = error instanceof Error ? error.message : String(error)
      return failed(`[system.reboot] shutdown -r now failed\n${message}`)
    }
  }
  return null
}

/**
 * Build the meta entries emitted on a successful reboot trigger.
 *
 * Always emits `system.reboot`; additionally emits `system.host` if the
 * caller supplied a `resolveHost` option. Resolver failures are returned as a
 * module failure so reconnect drift is visible to the operator.
 *
 * @param options - The reboot options (specifically `resolveHost`).
 * @returns The module result with reboot meta, or a failure result.
 */
async function buildRebootMetaEntries(options: RebootOptions): Promise<ModuleResult> {
  // R-0000243: bound the resolver with a wall-clock timeout so a hanging
  // DNS/cloud lookup surfaces as a `failed` result instead of stalling the
  // playbook forever.
  const result = await buildRebootMetaEntriesWithTimeout({
    failurePrefix: "[system.reboot]",
    resolveHost: options.resolveHost,
    timeoutMs: options.resolveHostTimeoutMs,
  })

  if (!Array.isArray(result)) return result
  return { meta: result, status: "changed" }
}

/**
 * Parse the contents of /etc/os-release into a key-value record.
 *
 * @param content - The raw file content.
 * @returns A record of key-value pairs.
 */
function parseOsRelease(content: string): Partial<Record<string, string>> {
  const result: Record<string, string> = {}
  for (const rawLine of content.split("\n")) {
    // R-0000857: strip a trailing CR so files with CRLF line endings
    // (e.g. /etc/os-release authored on Windows or downloaded over a
    // misconfigured transport) do not leak a stray "\r" into the parsed
    // value. The previous `replaceAll(/^"|"$/gv, "")` also stripped the
    // surrounding quotes asymmetrically — turning `value"` into `value` —
    // which silently accepted malformed entries. Only strip the quotes
    // when the value is symmetrically quoted (starts and ends with `"`).
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine
    const eqIndex = line.indexOf("=")
    if (eqIndex === -1) continue
    const key = line.slice(0, eqIndex)
    const rawValue = line.slice(eqIndex + 1)
    const value =
      rawValue.length >= 2 && rawValue.startsWith('"') && rawValue.endsWith('"')
        ? rawValue.slice(1, -1)
        : rawValue
    result[key] = value
  }
  return result
}

// R-0000781: the inet pattern accepts any `\d+` per octet, so values like
// `999.0.0.10` would match the regex and slip past the `startsWith("10.")`
// prefix check (the literal string starts with "10."). Validate each octet
// is ≤ 255 before reporting the IP so downstream consumers (env vars, meta
// entries) cannot see a syntactically invalid address.
const IPV4_OCTET_MAX_LENGTH = 3
const IPV4_OCTET_MAX_VALUE = 255

function isValidIpv4Octets(ip: string): boolean {
  return ip.split(".").every((octet) => {
    if (octet.length === 0 || octet.length > IPV4_OCTET_MAX_LENGTH) return false
    const numeric = Number(octet)
    return Number.isInteger(numeric) && numeric >= 0 && numeric <= IPV4_OCTET_MAX_VALUE
  })
}

/**
 * Find the first RFC-1918 private IP address in `ip -4 addr` output.
 *
 * @param output - The raw output of `ip -4 addr`.
 * @returns The first private IP found, or `undefined`.
 */
function findPrivateIp(output: string): string | undefined {
  const inetPattern = /inet\s+(?<addr>\d+\.\d+\.\d+\.\d+)/gv
  let match
  while ((match = inetPattern.exec(output)) !== null) {
    const ip = match.groups?.addr
    if (ip == null) continue
    if (!isValidIpv4Octets(ip)) continue
    if (
      ip.startsWith("10.") ||
      ip.startsWith("192.168.") ||
      /^172\.(?:1[6-9]|2\d|3[01])\./v.test(ip)
    ) {
      return ip
    }
  }
  return undefined
}

const FACTS_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/**
 * Execute a command and return its stdout, or `null` on failure.
 *
 * @param ssh - Active SSH connection.
 * @param cmd - The command to execute.
 * @returns The raw stdout or `null` on non-zero exit.
 */
async function execFact(ssh: SshConnection, cmd: string): Promise<null | string> {
  const result = await ssh.exec(cmd, FACTS_EXEC_OPTS)
  return result.code === 0 ? result.stdout : null
}

/**
 * Run all fact commands and return an array of raw outputs in order, or `null`
 * if any command fails.
 *
 * @param ssh - Active SSH connection.
 * @returns The raw outputs array or `null` on failure.
 */
async function runFactCommands(ssh: SshConnection): Promise<null | string[]> {
  const commands = [
    "cat /etc/os-release",
    "uname -m",
    "hostname",
    "uname -r",
    "free -m",
    "nproc",
    "ip -4 route get 1.1.1.1",
    "ip -4 addr",
    "df -m /",
  ]

  const results: string[] = []
  for (const cmd of commands) {
    // eslint-disable-next-line no-await-in-loop
    const output = await execFact(ssh, cmd)
    if (output === null) return null
    results.push(output)
  }

  return results
}

/**
 * Extract the total RAM in MB from `free -m` output.
 *
 * @param freeOutput - Raw output of `free -m`.
 * @returns The total RAM string or empty string.
 */
function parseRamTotal(freeOutput: string): string {
  const memLine = freeOutput.split("\n").find((line) => line.startsWith("Mem:"))
  return memLine?.trim().split(/\s+/v)[1] ?? ""
}

/**
 * Extract the root disk size in MB from `df -m /` output.
 *
 * @param dfOutput - Raw output of `df -m /`.
 * @returns The disk size string or empty string.
 */
function parseDiskRoot(dfOutput: string): string {
  const dataLine = dfOutput.split("\n")[1] ?? ""
  return dataLine.trim().split(/\s+/v)[1] ?? ""
}

/**
 * Extract the public IP from `ip -4 route get` output.
 *
 * @param routeOutput - Raw output of `ip -4 route get 1.1.1.1`.
 * @returns The public IP string or empty string.
 */
function parsePublicIp(routeOutput: string): string {
  const sourceMatch = /src\s+(?<addr>\d+\.\d+\.\d+\.\d+)/v.exec(routeOutput)
  // R-0000856: the regex accepts any `\d+` per octet, so kernel output
  // (or a spoofed mock) containing values like `999.0.0.10` would slip
  // through into `system.ip.public`. Validate each octet is ≤ 255 with
  // the shared helper before reporting; on mismatch report an empty
  // string so downstream consumers (env vars, meta entries) never see a
  // syntactically invalid address.
  const candidate = sourceMatch?.groups?.addr ?? ""
  if (candidate.length === 0) return ""
  return isValidIpv4Octets(candidate) ? candidate : ""
}

/**
 * Parse raw fact command outputs into a meta record.
 *
 * @param outputs - The 9 raw command outputs in order.
 * @returns A record of system fact meta keys.
 */
function parseFacts(outputs: string[]): Record<string, string> {
  const osInfo = parseOsRelease(outputs[0])

  return {
    "system.arch": outputs[1].trim(),
    "system.cpu.cores": outputs[5].trim(),
    "system.disk.root": parseDiskRoot(outputs[8]),
    "system.hostname": outputs[2].trim(),
    "system.ip.private": findPrivateIp(outputs[7]) ?? "",
    "system.ip.public": parsePublicIp(outputs[6]),
    "system.kernel": outputs[3].trim(),
    "system.os": osInfo.ID ?? "",
    "system.os.codename": osInfo.VERSION_CODENAME ?? "",
    "system.os.version": osInfo.VERSION_ID ?? "",
    "system.ram.total": parseRamTotal(outputs[4]),
  }
}

/**
 * Modules for managing system-level operations.
 */
export const system = {
  /**
   * Collect system facts (OS, architecture, hostname, kernel, RAM, CPU, IPs, disk).
   * Always applies because it is informational and should always report.
   *
   * All gathered values are emitted as `system.*` meta keys.
   *
   * @returns A Module that collects system facts.
   */
  facts(): Module {
    return {
      _dryRunMetaProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[system.facts] SSH connection is required")

        const outputs = await runFactCommands(ssh)
        if (outputs === null) return failed("[system.facts] failed to collect system facts")

        return { meta: environmentToMetaEntries(parseFacts(outputs)), status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "system.facts",
    }
  },

  /**
   * Reboot the remote system via `shutdown -r now`.
   * Always applies because a reboot is an imperative action.
   *
   * When `resolveHost` is provided, the resolved address is emitted as
   * `system.host` meta so the runner can update the SSH connection.
   * The `system.reboot` meta signal is always set to `"true"`.
   *
   * @param options - Optional settings including a host resolver.
   * @returns A Module that reboots the system.
   */
  reboot(options: RebootOptions = {}): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[system.reboot] SSH connection is required")

        const failure = await triggerReboot(ssh)
        if (failure !== null) return failure

        return buildRebootMetaEntries(options)
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "system.reboot",
    }
  },

  /**
   * Read the system uptime in seconds from `/proc/uptime`.
   * Always applies because it is informational and should always report.
   *
   * The uptime value is emitted as `system.uptime` meta.
   *
   * @returns A Module that reads the system uptime.
   */
  uptime(): Module {
    return {
      _dryRunMetaProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[system.uptime] SSH connection is required")

        // Use exec with ignoreExitCode so a missing or unreadable /proc/uptime
        // surfaces as a `failed` module result instead of an unhandled
        // exception thrown out of `ssh.output`.
        const result = await ssh.exec("awk '{print int($1)}' /proc/uptime", {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return failedCommand("[system.uptime] failed to read /proc/uptime", result)
        }
        const seconds = result.stdout.trim()
        if (seconds.length === 0) {
          return failed("[system.uptime] /proc/uptime returned empty output")
        }

        return { meta: [meta.env("system.uptime", seconds)], status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "system.uptime",
    }
  },
}
