/* eslint-disable max-lines */
import { failed } from "../moduleFailure.js"
import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { shellQuote } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  buildCurlHeaderFlags,
  buildWaitForName,
  buildWaitForTestCommand,
  checkHttpCondition,
  delay,
  type HttpCheckParameters,
  type WaitForOptions,
} from "./netHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const HOSTS_FILE = "/etc/hosts"
const HOSTS_FILE_MODE = "0644"
const NET_CONFIG_FILE_MODE = "0644"
const NETWORKCTL_RELOAD = "networkctl reload"
const DEFAULT_POLL_INTERVAL_MS = 2000
const DEFAULT_POLL_TIMEOUT_MS = 60_000
const DEFAULT_EXPECTED_STATUS = 200

/**
 * Sanitize a destination string for use in a filename.
 * Replaces `/` and `:` with dashes and strips leading dashes.
 *
 * @param value - The string to sanitize.
 * @returns The sanitized filename-safe string.
 */
function sanitizeForFilename(value: string): string {
  return value.replaceAll("/", "-").replaceAll(":", "-").replace(/^-+/v, "")
}

/**
 * Build the expected hosts line for an IP and its hostnames.
 *
 * @param ip - The IP address.
 * @param hostnames - The hostnames to associate.
 * @returns The formatted hosts line.
 */
function buildHostsLine(ip: string, hostnames: string[]): string {
  return `${ip} ${hostnames.join(" ")}`
}

/**
 * Generate the content of a resolv.conf file.
 *
 * @param nameservers - List of nameserver addresses.
 * @param search - Optional list of search domains.
 * @returns The resolv.conf file content.
 */
function buildResolvConfig(nameservers: string[], search?: string[]): string {
  const lines: string[] = []
  if (search && search.length > 0) {
    lines.push(`search ${search.join(" ")}`)
  }
  for (const ns of nameservers) {
    lines.push(`nameserver ${ns}`)
  }
  return `${lines.join("\n")}\n`
}

/**
 * Generate a systemd-networkd drop-in for a static route.
 *
 * @param destination - The route destination CIDR.
 * @param gateway - The gateway IP address.
 * @param device - Optional network device name.
 * @returns The drop-in file content.
 */
function buildRouteDropin(destination: string, gateway: string, device?: string): string {
  const lines = [
    "[Match]",
    `Name=${device ?? "*"}`,
    "",
    "[Route]",
    `Destination=${destination}`,
    `Gateway=${gateway}`,
  ]
  return `${lines.join("\n")}\n`
}

/** Interface configuration options shared by Netplan and networkd builders. */
type InterfaceOptions = {
  addresses?: string[]
  dhcp?: boolean
  gateway?: string
  nameservers?: string[]
}

/**
 * Generate a Netplan YAML configuration for a network interface.
 *
 * @param name - The network interface name.
 * @param options - The interface configuration.
 * @returns The Netplan YAML file content.
 */
function buildNetplanYaml(name: string, options: InterfaceOptions): string {
  const lines: string[] = [
    "network:",
    "  version: 2",
    "  ethernets:",
    `    ${name}:`,
    `      dhcp4: ${options.dhcp === true ? "true" : "false"}`,
  ]
  if (options.addresses && options.addresses.length > 0) {
    lines.push("      addresses:")
    for (const addr of options.addresses) {
      lines.push(`        - ${addr}`)
    }
  }
  appendNetplanGateway(lines, options.gateway)
  appendNetplanNameservers(lines, options.nameservers)
  return `${lines.join("\n")}\n`
}

/**
 * Append gateway route lines to a Netplan config.
 *
 * @param lines - The lines array to append to.
 * @param gateway - Optional gateway address.
 */
function appendNetplanGateway(lines: string[], gateway?: string): void {
  if (gateway !== undefined && gateway !== "") {
    lines.push("      routes:")
    lines.push("        - to: default")
    lines.push(`          via: ${gateway}`)
  }
}

/**
 * Append nameserver lines to a Netplan config.
 *
 * @param lines - The lines array to append to.
 * @param nameservers - Optional list of nameserver addresses.
 */
function appendNetplanNameservers(lines: string[], nameservers?: string[]): void {
  if (nameservers && nameservers.length > 0) {
    lines.push("      nameservers:")
    lines.push("        addresses:")
    for (const ns of nameservers) {
      lines.push(`          - ${ns}`)
    }
  }
}

/**
 * Generate a systemd-networkd configuration for a network interface.
 *
 * @param name - The network interface name.
 * @param options - The interface configuration.
 * @returns The networkd .network file content.
 */
function buildNetworkdConfig(name: string, options: InterfaceOptions): string {
  const lines: string[] = [
    "[Match]",
    `Name=${name}`,
    "",
    "[Network]",
    `DHCP=${options.dhcp === true ? "yes" : "no"}`,
  ]
  appendNetworkdEntries(lines, options)
  return `${lines.join("\n")}\n`
}

/**
 * Append Address, DNS, and Route entries to a networkd config.
 *
 * @param lines - The lines array to append to.
 * @param options - The interface configuration.
 */
function appendNetworkdEntries(lines: string[], options: InterfaceOptions): void {
  if (options.addresses) {
    for (const addr of options.addresses) {
      lines.push(`Address=${addr}`)
    }
  }
  if (options.nameservers) {
    for (const ns of options.nameservers) {
      lines.push(`DNS=${ns}`)
    }
  }
  if (options.gateway !== undefined && options.gateway !== "") {
    lines.push("")
    lines.push("[Route]")
    lines.push(`Gateway=${options.gateway}`)
  }
}

/**
 * Modules for managing network configuration on the remote host.
 */
export const net = {
  /**
   * Manage entries in /etc/hosts.
   *
   * @param ip - The IP address for the hosts entry.
   * @param hostnames - One or more hostnames to associate with the IP.
   * @param options - Optional settings.
   * @param options.state - Whether the entry should be "present" (default) or "absent".
   * @returns A Module that manages the hosts entry.
   */
  hosts(ip: string, hostnames: string[], options?: { state?: "absent" | "present" }): Module {
    const state = options?.state ?? "present"
    const expectedLine = buildHostsLine(ip, hostnames)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(`[net.hosts: ${ip} ${hostnames.join(" ")}] SSH connection is required`)
        }

        const content = await conn.readFile(HOSTS_FILE)
        const lines = content.split("\n")

        if (state === "present") {
          const alreadyPresent = lines.some((line) => line.trim() === expectedLine)
          if (alreadyPresent) return { status: "ok" }
          const suffix = content.endsWith("\n") ? "" : "\n"
          const newContent = `${content}${suffix}${expectedLine}\n`
          await guardedWriteFile(conn, {
            mode: HOSTS_FILE_MODE,
            newContent,
            originalContent: content,
            remotePath: HOSTS_FILE,
          })
        } else {
          const newContent = lines.filter((line) => line.trim() !== expectedLine).join("\n")
          await guardedWriteFile(conn, {
            mode: HOSTS_FILE_MODE,
            newContent,
            originalContent: content,
            remotePath: HOSTS_FILE,
          })
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const content = await conn.readFile(HOSTS_FILE)
        const lines = content.split("\n")
        const found = lines.some((line) => line.trim() === expectedLine)

        if (state === "present") {
          return found ? "ok" : NEEDS_APPLY
        }
        return found ? NEEDS_APPLY : "ok"
      },
      name: `net.hosts: ${ip} ${hostnames.join(" ")}`,
    }
  },

  /**
   * Configure a network interface via Netplan (when available) or systemd-networkd.
   *
   * @param name - The interface name (e.g. "eth0").
   * @param options - Network configuration options.
   * @returns A Module that manages the interface configuration.
   */
  interface(name: string, options: InterfaceOptions): Module {
    const netplanPath = `/etc/netplan/60-paratix-${name}.yaml`
    const networkdPath = `/etc/systemd/network/60-paratix-${name}.network`

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[net.interface: ${name}] SSH connection is required`)

        const useNetplan = await conn.test("test -d '/etc/netplan'")

        if (useNetplan) {
          const content = buildNetplanYaml(name, options)
          await conn.writeFile(netplanPath, content, { mode: NET_CONFIG_FILE_MODE })
          await conn.exec("netplan apply", EXEC_OPTS)
        } else {
          const content = buildNetworkdConfig(name, options)
          await conn.writeFile(networkdPath, content, { mode: NET_CONFIG_FILE_MODE })
          await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const useNetplan = await conn.test("test -d '/etc/netplan'")
        const configPath = useNetplan ? netplanPath : networkdPath
        const expectedContent = useNetplan
          ? buildNetplanYaml(name, options)
          : buildNetworkdConfig(name, options)

        const existsResult = await conn.exec(`test -f ${shellQuote(configPath)}`, EXEC_OPTS)
        if (existsResult.code !== 0) return NEEDS_APPLY

        const currentContent = await conn.readFile(configPath)
        return currentContent.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
      },
      name: `net.interface: ${name}`,
    }
  },

  /**
   * Check that an HTTP endpoint returns the expected status code and/or body.
   *
   * @param url - The URL to request.
   * @param options - Optional request settings.
   * @param options.body - Expected string in the response body.
   * @param options.headers - Additional HTTP headers.
   * @param options.method - HTTP method (default: `"GET"`).
   * @param options.status - Expected HTTP status code (default: `200`).
   * @returns A Module that checks the HTTP endpoint.
   */
  request(
    url: string,
    options?: { body?: string; headers?: Record<string, string>; method?: string; status?: number }
  ): Module {
    const method = options?.method ?? "GET"
    const parameters: HttpCheckParameters = {
      expectedBody: options?.body,
      expectedStatus: options?.status ?? DEFAULT_EXPECTED_STATUS,
      headerFlags: buildCurlHeaderFlags(options?.headers ?? {}),
      methodFlag: method === "GET" ? "" : `-X ${shellQuote(method)} `,
      url,
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[net.request: ${method} ${url}] SSH connection is required`)

        const ok = await checkHttpCondition(conn, parameters)
        return ok
          ? { status: "ok" }
          : failed(`[net.request: ${method} ${url}] HTTP request did not match expectations`)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const ok = await checkHttpCondition(conn, parameters)
        return ok ? "ok" : NEEDS_APPLY
      },
      name: `net.request: ${method} ${url}`,
    }
  },

  /**
   * Manage /etc/resolv.conf (nameservers and search domains).
   *
   * @param options - Resolver configuration.
   * @param options.nameservers - List of nameserver IP addresses.
   * @param options.search - Optional list of DNS search domains.
   * @returns A Module that manages /etc/resolv.conf.
   */
  resolv(options: { nameservers: string[]; search?: string[] }): Module {
    const expectedContent = buildResolvConfig(options.nameservers, options.search)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed("[net.resolv] SSH connection is required")

        // Atomic mv-replace via writeFile overwrites both regular files and symlinks,
        // so we never destroy /etc/resolv.conf before the replacement content is in place.
        // A failed writeFile leaves the previous file (or symlink) intact, which keeps the
        // host's resolver configuration usable.
        await conn.writeFile("/etc/resolv.conf", expectedContent, { mode: NET_CONFIG_FILE_MODE })

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const content = await conn.readFile("/etc/resolv.conf")
        return content.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
      },
      name: `net.resolv: nameservers ${options.nameservers.join(",")}`,
    }
  },

  /**
   * Manage persistent static routes via `ip route` and a systemd-networkd drop-in.
   *
   * @param destination - The route destination (e.g. "10.0.0.0/24").
   * @param gateway - The gateway IP address.
   * @param options - Optional settings.
   * @param options.device - The network device to use (e.g. "eth0").
   * @param options.state - Whether the route should be "present" (default) or "absent".
   * @returns A Module that manages the static route.
   */
  route(
    destination: string,
    gateway: string,
    options?: { device?: string; state?: "absent" | "present" }
  ): Module {
    const state = options?.state ?? "present"
    const device = options?.device
    const sanitized = sanitizeForFilename(destination)
    const dropinPath = `/etc/systemd/network/50-paratix-route-${sanitized}.network`

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(
            `[net.route: ${state} ${destination} via ${gateway}] SSH connection is required`
          )
        }

        if (state === "present") {
          const devicePart =
            device !== undefined && device !== "" ? ` dev ${shellQuote(device)}` : ""
          await conn.exec(
            `ip route replace ${shellQuote(destination)} via ${shellQuote(gateway)}${devicePart}`,
            EXEC_OPTS
          )
          const dropinContent = buildRouteDropin(destination, gateway, device)
          await conn.writeFile(dropinPath, dropinContent, { mode: NET_CONFIG_FILE_MODE })
          await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
        } else {
          await conn.exec(`ip route del ${shellQuote(destination)}`, EXEC_OPTS)
          await conn.exec(`rm -f ${shellQuote(dropinPath)}`, EXEC_OPTS)
          await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const result = await conn.exec(`ip route show ${shellQuote(destination)}`, EXEC_OPTS)
        const output = result.stdout.trim()
        const hasRoute = output.includes(`via ${gateway}`)

        if (state === "present") {
          return hasRoute ? "ok" : NEEDS_APPLY
        }
        return hasRoute ? NEEDS_APPLY : "ok"
      },
      name: `net.route: ${state} ${destination} via ${gateway}`,
    }
  },

  /**
   * Wait for a condition to become true on the remote host.
   *
   * @param options - Wait condition and timing options.
   * @returns A Module that waits for the condition.
   */
  waitFor(options: WaitForOptions): Module {
    const interval = options.interval ?? DEFAULT_POLL_INTERVAL_MS
    const timeout = options.timeout ?? DEFAULT_POLL_TIMEOUT_MS
    const host = options.host ?? "127.0.0.1"
    const testCommand = buildWaitForTestCommand(options, host)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[${buildWaitForName(options)}] SSH connection is required`)

        // R-0000052: hook into the runner abort signal so SIGINT/SIGTERM
        // unblocks the polling loop within the next iteration tick instead
        // of running until the configured timeout. The same abort signal is
        // observed by the `pause` builtin (R-0000027); both share the
        // process-scoped holder in runnerAbortSignal.ts.
        const abortSignal = getRunnerAbortSignal()
        const isAborted = (): boolean => abortSignal?.aborted === true
        const abortFailure = (): ModuleResult =>
          failed(
            `[${buildWaitForName(options)}] aborted by shutdown signal before condition was met`
          )

        const start = Date.now()
        while (Date.now() - start < timeout) {
          if (isAborted()) return abortFailure()
          // eslint-disable-next-line no-await-in-loop
          const success = await conn.test(testCommand)
          if (success) return { status: "changed" }
          if (isAborted()) return abortFailure()
          try {
            // eslint-disable-next-line no-await-in-loop
            await delay(interval, abortSignal)
          } catch {
            return abortFailure()
          }
        }

        return failed(`[${buildWaitForName(options)}] condition was not met within ${timeout}ms`)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const success = await conn.test(testCommand)
        return success ? "ok" : NEEDS_APPLY
      },
      name: buildWaitForName(options),
    }
  },
}
