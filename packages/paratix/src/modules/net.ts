/* eslint-disable max-lines */
import { failed, failedCommand } from "../moduleFailure.js"
import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { withRegisteredSecrets } from "../secretSink.js"
import { shellQuote } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  buildHttpCheckParameters,
  buildWaitForName,
  buildWaitForTestCommand,
  checkHttpCondition,
  delay,
  type HttpCheckParameters,
  validateHttpUrl,
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

function validateSingleLineNetworkValue(label: string, value: string): void {
  if (value.includes("\r") || value.includes("\n")) {
    throw new Error(`[net] invalid ${label}: value must not contain CR or LF`)
  }
}

function validateSingleLineNetworkValues(label: string, values?: string[]): void {
  for (const value of values ?? []) {
    validateSingleLineNetworkValue(label, value)
  }
}

function validateInterfaceOptions(options: InterfaceOptions): void {
  validateSingleLineNetworkValues("interface address", options.addresses)
  validateSingleLineNetworkValues("interface nameserver", options.nameservers)
  if (options.gateway != null) validateSingleLineNetworkValue("interface gateway", options.gateway)
}

function validateResolvOptions(options: { nameservers: string[]; search?: string[] }): void {
  validateSingleLineNetworkValues("resolv nameserver", options.nameservers)
  validateSingleLineNetworkValues("resolv search domain", options.search)
}

function validateRouteOptions(parameters: {
  destination: string
  device?: string
  gateway: string
}): void {
  validateSingleLineNetworkValue("route destination", parameters.destination)
  validateSingleLineNetworkValue("route gateway", parameters.gateway)
  if (parameters.device != null) validateSingleLineNetworkValue("route device", parameters.device)
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
 * R-0000101: parse a non-comment hosts file line into its IP token and the
 * set of hostnames after it. Comment-only lines and blank lines return
 * `undefined` so the caller can preserve them verbatim.
 *
 * @param line - A single line from /etc/hosts.
 * @returns The parsed IP and hostname tokens, or `undefined` for blanks
 *   and comment lines.
 */
function parseHostsLine(line: string): { hostnames: string[]; ip: string } | undefined {
  const trimmed = line.trim()
  if (trimmed === "" || trimmed.startsWith("#")) return undefined
  const tokens = trimmed.split(/\s+/v)
  const [ip, ...hostnames] = tokens
  // `tokens` is non-empty here because `trimmed` is non-empty and `split`
  // always yields at least one element, so `ip` is a string. Empty-string
  // protection guards against pathological inputs.
  if (ip === "") return undefined
  return { hostnames, ip }
}

/**
 * R-0000101: determine whether two hostname token lists describe the same
 * set of hostnames, ignoring order and duplicate entries. This lets
 * `state: "absent"` match `192.168.1.1 host1 host2` against a desired
 * `192.168.1.1 host2 host1` without requiring byte-identical lines.
 *
 * @param actual - Hostname tokens parsed from the file.
 * @param expected - Desired hostnames.
 * @returns `true` when both sets are equal.
 */
function hostnameSetsEqual(actual: string[], expected: string[]): boolean {
  if (actual.length === 0 || expected.length === 0) return false
  const a = new Set(actual)
  const b = new Set(expected)
  if (a.size !== b.size) return false
  for (const name of a) {
    if (!b.has(name)) return false
  }
  return true
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

async function interfaceLiveStateMatches(
  conn: SshConnection,
  name: string,
  options: InterfaceOptions
): Promise<boolean> {
  if ((options.addresses?.length ?? 0) === 0 && (options.gateway ?? "") === "") return true
  if (!(await liveInterfaceExists(conn, name))) return false
  if (!(await interfaceAddressesMatch(conn, name, options.addresses))) return false
  return interfaceGatewayMatches(conn, name, options.gateway)
}

async function liveInterfaceExists(conn: SshConnection, name: string): Promise<boolean> {
  const link = await conn.exec(`ip link show dev ${shellQuote(name)}`, EXEC_OPTS)
  return link.code === 0
}

async function interfaceAddressesMatch(
  conn: SshConnection,
  name: string,
  expected?: string[]
): Promise<boolean> {
  if ((expected?.length ?? 0) === 0) return true
  const addresses = await conn.exec(`ip -o addr show dev ${shellQuote(name)}`, EXEC_OPTS)
  if (addresses.code !== 0) return false
  for (const address of expected ?? []) {
    if (!addresses.stdout.includes(address)) return false
  }
  return true
}

async function interfaceGatewayMatches(
  conn: SshConnection,
  name: string,
  gateway?: string
): Promise<boolean> {
  if ((gateway ?? "") === "") return true
  const defaultRoute = await conn.exec(`ip route show default dev ${shellQuote(name)}`, EXEC_OPTS)
  return defaultRoute.code === 0 && defaultRoute.stdout.includes(`via ${gateway}`)
}

/** Parameters for the net.route check helper. */
type RouteCheckParameters = {
  destination: string
  device?: string
  dropinPath: string
  gateway: string
  state: "absent" | "present"
}

type RouteParameters = Omit<RouteCheckParameters, "state">

/**
 * Run the live-route check against the remote host.
 *
 * @param conn - The SSH connection.
 * @param parameters - The route destination, gateway and optional device.
 * @param parameters.destination - The route destination CIDR.
 * @param parameters.device - Optional expected route device.
 * @param parameters.gateway - The expected gateway address.
 * @returns `true` when the live route matches the expected gateway and device.
 */
async function hasLiveRoute(
  conn: SshConnection,
  parameters: { destination: string; device?: string; gateway: string }
): Promise<boolean> {
  const { destination, device, gateway } = parameters
  const result = await conn.exec(`ip route show ${shellQuote(destination)}`, EXEC_OPTS)
  const output = result.stdout.trim()
  if (!output.includes(`via ${gateway}`)) return false
  return device == null || output.includes(` dev ${device}`)
}

/**
 * Test whether the systemd-networkd drop-in for a route is currently on disk.
 *
 * @param conn - The SSH connection.
 * @param dropinPath - The absolute drop-in file path.
 * @returns `true` when the drop-in exists.
 */
async function routeDropinExists(conn: SshConnection, dropinPath: string): Promise<boolean> {
  const result = await conn.exec(`test -f ${shellQuote(dropinPath)}`, EXEC_OPTS)
  return result.code === 0
}

/**
 * R-0000061: validate the persistent systemd-networkd drop-in alongside the
 * live route — analogous to `mount.present.check` after R-0000049 — so that
 * drift in either layer triggers `needs-apply`.
 *
 * @param conn - The SSH connection.
 * @param parameters - Desired route values plus drop-in path.
 * @returns `"ok"` when both layers match the desired state, otherwise
 *   `"needs-apply"`.
 */
async function checkRouteState(
  conn: SshConnection,
  parameters: RouteCheckParameters
): Promise<"needs-apply" | "ok"> {
  const { destination, device, dropinPath, gateway, state } = parameters
  const live = await hasLiveRoute(conn, { destination, device, gateway })
  const dropinPresent = await routeDropinExists(conn, dropinPath)

  if (state === "present") {
    if (!live) return NEEDS_APPLY
    if (!dropinPresent) return NEEDS_APPLY
    const expected = buildRouteDropin(destination, gateway, device)
    const current = await conn.readFile(dropinPath)
    return current.trim() === expected.trim() ? "ok" : NEEDS_APPLY
  }

  // absent: neither the live route nor the drop-in may remain — a lingering
  // drop-in would re-create the route on the next reboot.
  if (live) return NEEDS_APPLY
  return dropinPresent ? NEEDS_APPLY : "ok"
}

async function applyPresentRoute(
  conn: SshConnection,
  parameters: RouteParameters
): Promise<ModuleResult | null> {
  const { destination, device, dropinPath, gateway } = parameters
  const devicePart = device !== undefined && device !== "" ? ` dev ${shellQuote(device)}` : ""
  const routeResult = await conn.exec(
    `ip route replace ${shellQuote(destination)} via ${shellQuote(gateway)}${devicePart}`,
    EXEC_OPTS
  )
  if (routeResult.code !== 0) {
    return failedCommand(`[net.route: ${destination}] ip route replace failed`, routeResult)
  }
  const dropinContent = buildRouteDropin(destination, gateway, device)
  await conn.writeFile(dropinPath, dropinContent, { mode: NET_CONFIG_FILE_MODE })
  return null
}

async function applyAbsentRoute(
  conn: SshConnection,
  parameters: RouteParameters
): Promise<ModuleResult | null> {
  const { destination, device, dropinPath, gateway } = parameters
  if (await hasLiveRoute(conn, { destination, device, gateway })) {
    const routeResult = await conn.exec(`ip route del ${shellQuote(destination)}`, EXEC_OPTS)
    if (routeResult.code !== 0) {
      return failedCommand(`[net.route: ${destination}] ip route del failed`, routeResult)
    }
  }
  const removeResult = await conn.exec(`rm -f ${shellQuote(dropinPath)}`, EXEC_OPTS)
  if (removeResult.code !== 0) {
    return failedCommand(`[net.route: ${destination}] drop-in removal failed`, removeResult)
  }
  return null
}

async function applyRouteState(
  conn: SshConnection,
  parameters: RouteCheckParameters
): Promise<ModuleResult> {
  const failure =
    parameters.state === "present"
      ? await applyPresentRoute(conn, parameters)
      : await applyAbsentRoute(conn, parameters)
  if (failure != null) return failure
  const reloadResult = await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
  if (reloadResult.code !== 0) {
    return failedCommand(
      `[net.route: ${parameters.destination}] networkctl reload failed`,
      reloadResult
    )
  }
  return { status: "changed" }
}

/** Shared parameters for the net.hosts apply/check helpers. */
type HostsStateParameters = {
  expectedLine: string
  isSameIpLine: (line: string) => boolean
  matchesAbsentTarget: (line: string) => boolean
  state: "absent" | "present"
}

/** Snapshot of /etc/hosts content used by the apply helpers. */
type HostsFileSnapshot = {
  content: string
  lines: string[]
}

/**
 * Apply the `state: "present"` reconciliation for /etc/hosts.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cached hosts state context.
 * @param snapshot - The current /etc/hosts content and its lines.
 * @returns The module result for the apply operation.
 */
async function applyHostsPresent(
  conn: SshConnection,
  parameters: HostsStateParameters,
  snapshot: HostsFileSnapshot
): Promise<ModuleResult> {
  const { expectedLine, isSameIpLine } = parameters
  const { content, lines } = snapshot
  // The file is already canonical when there is exactly one line for
  // this IP and it matches the desired byte sequence. Otherwise we
  // strip every line whose first token equals `ip` and append the
  // expected line, which collapses duplicates and replaces stale
  // entries (e.g. `192.168.1.1 host1` -> `192.168.1.1 host2`).
  const sameIpLines = lines.filter((line) => isSameIpLine(line))
  const alreadyCanonical = sameIpLines.length === 1 && sameIpLines[0]?.trim() === expectedLine
  if (alreadyCanonical) return { status: "ok" }

  const filtered = lines.filter((line) => !isSameIpLine(line))
  // Drop a single trailing blank introduced by `split("\n")` so we
  // do not accumulate empty lines on every replacement.
  if (filtered.length > 0 && filtered.at(-1) === "") filtered.pop()
  filtered.push(expectedLine)
  const newContent = `${filtered.join("\n")}\n`
  await guardedWriteFile(conn, {
    mode: HOSTS_FILE_MODE,
    newContent,
    originalContent: content,
    remotePath: HOSTS_FILE,
  })
  return { status: "changed" }
}

/**
 * Apply the `state: "absent"` reconciliation for /etc/hosts.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cached hosts state context.
 * @param snapshot - The current /etc/hosts content and its lines.
 * @returns The module result for the apply operation.
 */
async function applyHostsAbsent(
  conn: SshConnection,
  parameters: HostsStateParameters,
  snapshot: HostsFileSnapshot
): Promise<ModuleResult> {
  const { matchesAbsentTarget } = parameters
  const { content, lines } = snapshot
  const alreadyAbsent = !lines.some((line) => matchesAbsentTarget(line))
  if (alreadyAbsent) return { status: "ok" }
  const newContent = lines.filter((line) => !matchesAbsentTarget(line)).join("\n")
  await guardedWriteFile(conn, {
    mode: HOSTS_FILE_MODE,
    newContent,
    originalContent: content,
    remotePath: HOSTS_FILE,
  })
  return { status: "changed" }
}

/**
 * Apply the desired /etc/hosts entry for the given parameters.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cached hosts state context.
 * @returns The module result for the apply operation.
 */
async function applyHostsState(
  conn: SshConnection,
  parameters: HostsStateParameters
): Promise<ModuleResult> {
  const content = await conn.readFile(HOSTS_FILE)
  const snapshot: HostsFileSnapshot = { content, lines: content.split("\n") }
  return parameters.state === "present"
    ? applyHostsPresent(conn, parameters, snapshot)
    : applyHostsAbsent(conn, parameters, snapshot)
}

/**
 * Determine whether the current /etc/hosts content already matches the
 * desired hosts entry.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cached hosts state context.
 * @returns `"ok"` when the file matches, otherwise `"needs-apply"`.
 */
async function checkHostsState(
  conn: SshConnection,
  parameters: HostsStateParameters
): Promise<"needs-apply" | "ok"> {
  const { expectedLine, isSameIpLine, matchesAbsentTarget, state } = parameters
  const content = await conn.readFile(HOSTS_FILE)
  const lines = content.split("\n")

  if (state === "present") {
    // Drift if there is more than one entry for this IP or if the
    // single entry does not match the desired byte sequence — both
    // would be reconciled by apply.
    const sameIpLines = lines.filter((line) => isSameIpLine(line))
    if (sameIpLines.length === 1 && sameIpLines[0]?.trim() === expectedLine) return "ok"
    return NEEDS_APPLY
  }

  const found = lines.some((line) => matchesAbsentTarget(line))
  return found ? NEEDS_APPLY : "ok"
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

    // R-0000101: a hosts line for the same IP with a different hostname set
    // collides with the desired entry. `state: "present"` must therefore
    // replace any line whose IP token matches `ip` instead of leaving the
    // stale line in place, and `state: "absent"` must match tolerantly across
    // whitespace and hostname order.
    const isSameIpLine = (line: string): boolean => {
      const parsed = parseHostsLine(line)
      return parsed?.ip === ip
    }
    const matchesAbsentTarget = (line: string): boolean => {
      const parsed = parseHostsLine(line)
      if (parsed?.ip !== ip) return false
      return hostnameSetsEqual(parsed.hostnames, hostnames)
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(`[net.hosts: ${ip} ${hostnames.join(" ")}] SSH connection is required`)
        }
        return applyHostsState(conn, {
          expectedLine,
          isSameIpLine,
          matchesAbsentTarget,
          state,
        })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY
        return checkHostsState(conn, {
          expectedLine,
          isSameIpLine,
          matchesAbsentTarget,
          state,
        })
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
    // R-0000100: validate the interface name against path-traversal payloads.
    // The name is interpolated into the Netplan/networkd file paths below, so
    // any value containing `/`, `..`, or shell metacharacters could escape the
    // intended directory and overwrite arbitrary files. The regex enforces a
    // POSIX-compatible interface-name shape (alphanumeric start, then word
    // characters plus dot and dash).
    if (!/^[A-Za-z0-9][\w.\-]*$/v.test(name)) {
      throw new Error(
        `[net.interface] invalid interface name: ${JSON.stringify(name)} ` +
          `— must match /^[A-Za-z0-9][\\w.\\-]*$/`
      )
    }
    validateInterfaceOptions(options)
    const netplanPath = `/etc/netplan/60-paratix-${name}.yaml`
    const networkdPath = `/etc/systemd/network/60-paratix-${name}.network`

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[net.interface: ${name}] SSH connection is required`)

        const useNetplan = await conn.test("test -d '/etc/netplan'")

        if (useNetplan) {
          const content = buildNetplanYaml(name, options)
          await conn.writeFile(netplanPath, content, { mode: NET_CONFIG_FILE_MODE })
          const result = await conn.exec("netplan apply", EXEC_OPTS)
          if (result.code !== 0) {
            return failedCommand(`[net.interface: ${name}] netplan apply failed`, result)
          }
        } else {
          const content = buildNetworkdConfig(name, options)
          await conn.writeFile(networkdPath, content, { mode: NET_CONFIG_FILE_MODE })
          const result = await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
          if (result.code !== 0) {
            return failedCommand(`[net.interface: ${name}] networkctl reload failed`, result)
          }
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
        if (currentContent.trim() !== expectedContent.trim()) return NEEDS_APPLY

        return (await interfaceLiveStateMatches(conn, name, options)) ? "ok" : NEEDS_APPLY
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
    validateHttpUrl(url, { allowHttp: true })
    const method = options?.method ?? "GET"
    const parameters: HttpCheckParameters = buildHttpCheckParameters({
      body: options?.body,
      headers: options?.headers,
      method,
      status: options?.status ?? DEFAULT_EXPECTED_STATUS,
      url,
    })
    const displayUrl = parameters.displayUrl

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn)
          return failed(`[net.request: ${method} ${displayUrl}] SSH connection is required`)

        // Register Authorization header values and any signed-URL secrets so
        // a CommandError raised from inside checkHttpCondition is masked
        // when its stderr reaches printCommandFailure.
        return withRegisteredSecrets(parameters.secrets, async () => {
          const ok = await checkHttpCondition(conn, parameters)
          return ok
            ? { status: "ok" }
            : failed(
                `[net.request: ${method} ${displayUrl}] HTTP request did not match expectations`
              )
        })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        return withRegisteredSecrets(parameters.secrets, async () => {
          const ok = await checkHttpCondition(conn, parameters)
          return ok ? "ok" : NEEDS_APPLY
        })
      },
      name: `net.request: ${method} ${displayUrl}`,
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
    validateResolvOptions(options)
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
    validateRouteOptions({ destination, device, gateway })
    const sanitized = sanitizeForFilename(destination)
    const dropinPath = `/etc/systemd/network/50-paratix-route-${sanitized}.network`

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(
            `[net.route: ${state} ${destination} via ${gateway}] SSH connection is required`
          )
        }

        return applyRouteState(conn, { destination, device, dropinPath, gateway, state })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY
        return checkRouteState(conn, { destination, device, dropinPath, gateway, state })
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
