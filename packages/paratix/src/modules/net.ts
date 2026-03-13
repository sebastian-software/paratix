import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const HOSTS_FILE = "/etc/hosts"
const NETWORKCTL_RELOAD = "networkctl reload"

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
        if (!conn) return { status: "failed" }

        const content = await conn.readFile(HOSTS_FILE)
        const lines = content.split("\n")

        if (state === "present") {
          const alreadyPresent = lines.some((line) => line.trim() === expectedLine)
          if (alreadyPresent) return { status: "ok" }
          const newContent = content.endsWith("\n")
            ? `${content}${expectedLine}\n`
            : `${content}\n${expectedLine}\n`
          await conn.writeFile(HOSTS_FILE, newContent)
        } else {
          const filtered = lines.filter((line) => line.trim() !== expectedLine)
          await conn.writeFile(HOSTS_FILE, filtered.join("\n"))
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
   * Auto-detects whether Netplan is in use by checking for /etc/netplan/.
   * When Netplan is detected, a YAML config is written; otherwise a
   * systemd-networkd .network file is written.
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
        if (!conn) return { status: "failed" }

        const useNetplan = await conn.test("test -d '/etc/netplan'")

        if (useNetplan) {
          const content = buildNetplanYaml(name, options)
          await conn.writeFile(netplanPath, content)
          await conn.exec("netplan apply", EXEC_OPTS)
        } else {
          const content = buildNetworkdConfig(name, options)
          await conn.writeFile(networkdPath, content)
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
   * Manage /etc/resolv.conf (nameservers and search domains).
   *
   * Removes any existing symlink (e.g. from systemd-resolved) before writing
   * the file directly.
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
        if (!conn) return { status: "failed" }

        await conn.exec("rm -f /etc/resolv.conf", EXEC_OPTS)
        await conn.writeFile("/etc/resolv.conf", expectedContent)

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
   * The route is applied immediately via `ip route replace` and persisted as a
   * systemd-networkd .network file so it survives reboots.
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
        if (!conn) return { status: "failed" }

        if (state === "present") {
          const devicePart =
            device !== undefined && device !== "" ? ` dev ${shellQuote(device)}` : ""
          await conn.exec(
            `ip route replace ${shellQuote(destination)} via ${shellQuote(gateway)}${devicePart}`,
            EXEC_OPTS
          )
          const dropinContent = buildRouteDropin(destination, gateway, device)
          await conn.writeFile(dropinPath, dropinContent)
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
}
