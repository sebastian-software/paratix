import { environmentToMetaEntries, meta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import {
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"

/**
 * Options for the reboot module.
 */
export type RebootOptions = {
  /**
   * Optional async function to resolve the new host address after a reboot.
   * Useful when the server's IP address may change (e.g. DHCP or cloud environments).
   */
  resolveHost?: () => Promise<string>
}

/**
 * Parse the contents of /etc/os-release into a key-value record.
 *
 * @param content - The raw file content.
 * @returns A record of key-value pairs.
 */
function parseOsRelease(content: string): Partial<Record<string, string>> {
  const result: Record<string, string> = {}
  for (const line of content.split("\n")) {
    const eqIndex = line.indexOf("=")
    if (eqIndex === -1) continue
    const key = line.slice(0, eqIndex)
    const value = line.slice(eqIndex + 1).replaceAll(/^"|"$/gv, "")
    result[key] = value
  }
  return result
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
  return sourceMatch?.groups?.addr ?? ""
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

        try {
          const result = await ssh.exec("shutdown -r now", { ignoreExitCode: true, silent: true })
          if (result.code !== 0) {
            return failedCommand("[system.reboot] shutdown -r now failed", result)
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          return failed(`[system.reboot] shutdown -r now failed\n${message}`)
        }

        const entries: ModuleMetaEntry[] = [meta.systemReboot()]

        if (options.resolveHost != null) {
          try {
            const newHost = await options.resolveHost()
            entries.push(meta.systemHost(newHost))
          } catch {
            // resolveHost failed — reconnect will use current host
          }
        }

        return { meta: entries, status: "changed" }
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

        const seconds = await ssh.output("awk '{print int($1)}' /proc/uptime")

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
