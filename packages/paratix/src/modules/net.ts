/* eslint-disable max-lines */
import { isIP } from "node:net"

import { failed, failedCommand } from "../moduleFailure.js"
import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { withRegisteredSecrets } from "../secretSink.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  hasSensitiveHeaders,
  hasSensitiveQueryParameters,
  redactUrlForDisplay,
} from "./curlHelpers.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag, withMutexLock } from "./moduleHelpers.js"
import {
  buildHttpCheckParameters,
  buildWaitForName,
  buildWaitForTestCommand,
  checkHttpCondition,
  delay,
  type HttpCheckParameters,
  validateHttpUrl,
  validateWaitForHost,
  type WaitForOptions,
} from "./netHelpers.js"
import { isSymlink } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const HOSTS_FILE = "/etc/hosts"
const HOSTS_FILE_MODE = "0644"
// Lock identifier serializing read-modify-write on /etc/hosts across
// concurrent Paratix runs sharing this remote host.
const HOSTS_FILE_MUTEX = "etc-hosts-mutex"
const NET_CONFIG_FILE_MODE = "0644"
const NETWORKCTL_RELOAD = "networkctl reload"
const MS_PER_SECOND = 1000
const DEFAULT_POLL_INTERVAL_MS = 2000
const DEFAULT_POLL_TIMEOUT_MS = 60_000
const DEFAULT_EXPECTED_STATUS = 200
const NET_RELOAD_HASH_LENGTH = 16
const MAX_HOSTNAME_LENGTH = 253
const MAX_HOSTNAME_LABEL_LENGTH = 63
const HOSTNAME_LABEL_CHARS_PATTERN = /^[a-z0-9\x2d]+$/iv
const HOSTNAME_LABEL_EDGE_PATTERN = /^[a-z0-9]$/iv

function validateWaitForTimingOption(label: string, value: number): void {
  if (Number.isFinite(value) && value > 0) return
  throw new Error(`[net.waitFor] invalid ${label}: value must be a finite positive number`)
}

function getRemainingWaitForMs(start: number, timeout: number): number {
  return Math.max(0, timeout - (Date.now() - start))
}

function getWaitForPortProbeTimeoutSeconds(remainingMs: number): number {
  return Math.max(1, Math.ceil(remainingMs / MS_PER_SECOND))
}

async function runWaitForProbe(parameters: {
  conn: SshConnection
  host: string
  options: WaitForOptions
  remainingMs: number
}): Promise<boolean> {
  const command = buildWaitForTestCommand(
    parameters.options,
    parameters.host,
    getWaitForPortProbeTimeoutSeconds(parameters.remainingMs)
  )
  const result = await parameters.conn.exec(command, {
    ignoreExitCode: true,
    silent: true,
    timeout: parameters.remainingMs,
  })
  return result.code === 0
}

async function waitForNextPoll(parameters: {
  abortSignal?: AbortSignal
  interval: number
  remainingMs: number
}): Promise<"aborted" | "continue" | "timeout"> {
  const delayMs = Math.min(parameters.interval, parameters.remainingMs)
  if (delayMs <= 0) return "timeout"
  try {
    await delay(delayMs, parameters.abortSignal)
    return "continue"
  } catch {
    return "aborted"
  }
}

function isWaitForAborted(abortSignal?: AbortSignal): boolean {
  return abortSignal?.aborted === true
}

async function runWaitForPoll(parameters: {
  abortSignal?: AbortSignal
  conn: SshConnection
  host: string
  interval: number
  options: WaitForOptions
  remainingMs: number
}): Promise<"aborted" | "continue" | "ok" | "timeout"> {
  if (parameters.remainingMs <= 0) return "timeout"
  if (isWaitForAborted(parameters.abortSignal)) return "aborted"
  if (await runWaitForProbe(parameters)) return "ok"
  if (isWaitForAborted(parameters.abortSignal)) return "aborted"
  return waitForNextPoll(parameters)
}

async function waitForCondition(parameters: {
  conn: SshConnection
  host: string
  interval: number
  options: WaitForOptions
  timeout: number
}): Promise<"aborted" | "ok" | "timeout"> {
  const abortSignal = getRunnerAbortSignal()
  const start = Date.now()
  for (;;) {
    const remainingMs = getRemainingWaitForMs(start, parameters.timeout)
    // eslint-disable-next-line no-await-in-loop
    const waitResult = await runWaitForPoll({ ...parameters, abortSignal, remainingMs })
    if (waitResult !== "continue") return waitResult
  }
}

function waitForAbortFailure(options: WaitForOptions): ModuleResult {
  return failed(
    `[${buildWaitForName(options)}] aborted by shutdown signal before condition was met`
  )
}

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
  if (options.nameservers.length === 0) {
    throw new Error("[net.resolv] invalid nameservers: at least one nameserver is required")
  }
  for (const nameserver of options.nameservers) {
    if (isIP(nameserver) === 0) {
      throw new Error("[net.resolv] invalid nameserver: value must be a valid IPv4 or IPv6 address")
    }
  }
  for (const domain of options.search ?? []) {
    validateResolvSearchDomain(domain)
  }
}

function validateResolvSearchDomain(domain: string): void {
  if (domain === "" || /\s/v.test(domain)) {
    throw new Error("[net.resolv] invalid search domain: value must be a non-empty single token")
  }
  if (domain.length > MAX_HOSTNAME_LENGTH) {
    throw new Error("[net.resolv] invalid search domain: value is too long")
  }
  const labels = domain.split(".")
  if (labels.some((label) => !isValidHostnameLabel(label))) {
    throw new Error("[net.resolv] invalid search domain: value must be a valid DNS domain")
  }
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

function validateHostsToken(label: string, value: string): void {
  if (value === "" || /\s/v.test(value)) {
    throw new Error(`[net.hosts] invalid ${label}: value must be a non-empty single token`)
  }
}

function isValidHostnameLabel(label: string): boolean {
  if (label === "" || label.length > MAX_HOSTNAME_LABEL_LENGTH) return false
  if (!HOSTNAME_LABEL_CHARS_PATTERN.test(label)) return false
  const first = label.at(0)
  const last = label.at(-1)
  return (
    first !== undefined &&
    last !== undefined &&
    HOSTNAME_LABEL_EDGE_PATTERN.test(first) &&
    HOSTNAME_LABEL_EDGE_PATTERN.test(last)
  )
}

function validateHostsHostname(hostname: string): void {
  validateHostsToken("hostname", hostname)
  if (hostname.length > MAX_HOSTNAME_LENGTH) {
    throw new Error("[net.hosts] invalid hostname: value is too long")
  }
  const labels = hostname.split(".")
  if (labels.some((label) => !isValidHostnameLabel(label))) {
    throw new Error("[net.hosts] invalid hostname: value must be a valid hostname")
  }
}

function validateHostsOptions(ip: string, hostnames: string[]): void {
  validateHostsToken("IP address", ip)
  if (isIP(ip) === 0) {
    throw new Error("[net.hosts] invalid IP address: value must be a valid IPv4 or IPv6 address")
  }
  if (hostnames.length === 0) {
    throw new Error("[net.hosts] invalid hostnames: at least one hostname is required")
  }
  for (const hostname of hostnames) {
    validateHostsHostname(hostname)
  }
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

function mergeHostnames(existing: string[], desired: string[]): string[] {
  const merged: string[] = []
  const seen = new Set<string>()
  for (const hostname of [...existing, ...desired]) {
    if (seen.has(hostname)) continue
    seen.add(hostname)
    merged.push(hostname)
  }
  return merged
}

function buildMergedHostsLine(
  lines: string[],
  parameters: Pick<HostsStateParameters, "desiredHostnames" | "expectedLine" | "isSameIpLine">
): string {
  const existingHostnames = lines.flatMap((line) => {
    if (!parameters.isSameIpLine(line)) return []
    return parseHostsLine(line)?.hostnames ?? []
  })
  if (existingHostnames.length === 0) return parameters.expectedLine
  const [ip] = parameters.expectedLine.split(" ")
  return buildHostsLine(ip, mergeHostnames(existingHostnames, parameters.desiredHostnames))
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

type InterfaceConfigSnapshot = {
  existed: boolean
  path: string
  previousContent: string
}

async function captureInterfaceConfigSnapshot(
  conn: SshConnection,
  path: string
): Promise<InterfaceConfigSnapshot> {
  const existed = await conn.test(`test -f ${shellQuote(path)}`)
  return {
    existed,
    path,
    previousContent: existed ? await conn.readFile(path) : "",
  }
}

async function rollbackInterfaceConfig(
  conn: SshConnection,
  snapshot: InterfaceConfigSnapshot
): Promise<ModuleResult | null> {
  if (snapshot.existed) {
    try {
      await conn.writeFile(snapshot.path, snapshot.previousContent, { mode: NET_CONFIG_FILE_MODE })
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : String(error)
      return failed(
        `[net.interface] rollback restore failed for ${snapshot.path}; network configuration was not restored: ${reason}`
      )
    }
    return null
  }

  const result = await conn.exec(`rm -f ${shellQuote(snapshot.path)}`, EXEC_OPTS)
  return result.code === 0
    ? null
    : failedCommand(`[net.interface] rollback removal failed for ${snapshot.path}`, result)
}

async function writeAndApplyInterfaceConfig(parameters: {
  applyCommand: string
  content: string
  failureMessage: string
  path: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  // R-0000277: refuse to write through an existing symlink. The atomic
  // `mv`-replace inside `ssh.writeFile` already breaks symlinks at the
  // finalize step, but a vorgelagerter Guard surfaces a clearer error to
  // the operator and matches the defense-in-depth pattern in compose.ts,
  // apt.ts and aptKeyHelpers.ts.
  if (await isSymlink(parameters.ssh, parameters.path)) {
    return failed(
      `[net.interface: ${parameters.path}] refuses to write through symlink at the destination path`
    )
  }
  const snapshot = await captureInterfaceConfigSnapshot(parameters.ssh, parameters.path)
  await parameters.ssh.writeFile(parameters.path, parameters.content, {
    mode: NET_CONFIG_FILE_MODE,
  })
  const result = await parameters.ssh.exec(parameters.applyCommand, EXEC_OPTS)
  if (result.code === 0) return { status: "changed" }

  const rollbackFailure = await rollbackInterfaceConfig(parameters.ssh, snapshot)
  if (rollbackFailure != null) return rollbackFailure

  // Restoring the file is not enough: the live network state still reflects
  // the failed apply attempt. Re-run the apply command so the kernel/netplan
  // configuration matches the restored on-disk state. If this re-apply also
  // fails, surface a clear divergence message so operators know the live
  // state diverges from the restored configuration file.
  const reApply = await parameters.ssh.exec(parameters.applyCommand, EXEC_OPTS)
  if (reApply.code !== 0) {
    return failedCommand(
      `${parameters.failureMessage}; rollback restored the configuration file but re-applying the previous configuration also failed — live network state diverges from on-disk configuration`,
      reApply
    )
  }
  return failedCommand(parameters.failureMessage, result)
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
  const liveAddresses = parseInterfaceAddressTokens(addresses.stdout)
  for (const address of expected ?? []) {
    if (!liveAddresses.has(address)) return false
  }
  return true
}

function parseInterfaceAddressTokens(output: string): Set<string> {
  const result = new Set<string>()
  for (const line of output.split(/\r?\n/v)) {
    const tokens = line.trim().split(/\s+/v)
    for (const family of ["inet", "inet6"]) {
      const familyIndex = tokens.indexOf(family)
      if (familyIndex === -1 || familyIndex + 1 >= tokens.length) continue
      result.add(tokens[familyIndex + 1])
    }
  }
  return result
}

async function interfaceGatewayMatches(
  conn: SshConnection,
  name: string,
  gateway = ""
): Promise<boolean> {
  if (gateway === "") return true
  const defaultRoute = await conn.exec(`ip route show default dev ${shellQuote(name)}`, EXEC_OPTS)
  return defaultRoute.code === 0 && defaultRouteGatewayMatches(defaultRoute.stdout, gateway)
}

function defaultRouteGatewayMatches(output: string, gateway: string): boolean {
  return output.split(/\r?\n/v).some((line) => {
    const tokens = line.trim().split(/\s+/v)
    return tokens[0] === "default" && routeTokenValueMatches(tokens, "via", gateway)
  })
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

function buildRouteReloadFlag(parameters: RouteParameters): {
  flagName: string
  flagPrefix: string
} {
  const routeKey = `${parameters.destination}\n${parameters.gateway}\n${parameters.device ?? ""}`
  const routeHash = sha256String(routeKey).slice(0, NET_RELOAD_HASH_LENGTH)
  const flagPrefix = `net-route-${routeHash}-`
  const dropinHash = sha256String(
    buildRouteDropin(parameters.destination, parameters.gateway, parameters.device)
  ).slice(0, NET_RELOAD_HASH_LENGTH)
  return {
    flagName: `${flagPrefix}${dropinHash}`,
    flagPrefix,
  }
}

/**
 * Test whether a tokenized `ip route` line contains an exact keyword value.
 *
 * @param tokens - Whitespace-split route line tokens.
 * @param keyword - The route keyword to find, such as `via` or `dev`.
 * @param expected - The exact token expected after the keyword.
 * @returns `true` when the keyword is followed by the exact expected value.
 */
function routeTokenValueMatches(tokens: string[], keyword: string, expected: string): boolean {
  const index = tokens.indexOf(keyword)
  return index !== -1 && tokens[index + 1] === expected
}

/**
 * Test whether one `ip route show` output line matches the desired route.
 *
 * @param line - A single `ip route show` output line.
 * @param parameters - The expected route destination, gateway and device.
 * @param parameters.destination - The expected destination token.
 * @param parameters.device - Optional expected device token.
 * @param parameters.gateway - The expected gateway token.
 * @returns `true` when destination, gateway and optional device match exactly.
 */
function routeLineMatches(
  line: string,
  parameters: { destination: string; device?: string; gateway: string }
): boolean {
  const tokens = line.trim().split(/\s+/v)
  if (tokens[0] !== parameters.destination) return false
  if (!routeTokenValueMatches(tokens, "via", parameters.gateway)) return false
  return parameters.device == null || routeTokenValueMatches(tokens, "dev", parameters.device)
}

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
  const result = await conn.exec(`ip route show ${shellQuote(parameters.destination)}`, EXEC_OPTS)
  if (result.code !== 0) return false
  return result.stdout
    .split(/\r?\n/v)
    .some((line) => line.trim() !== "" && routeLineMatches(line, parameters))
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

async function routeDropinMatchesExpected(
  conn: SshConnection,
  parameters: RouteParameters
): Promise<boolean> {
  if (!(await routeDropinExists(conn, parameters.dropinPath))) return false
  const expected = buildRouteDropin(parameters.destination, parameters.gateway, parameters.device)
  const current = await conn.readFile(parameters.dropinPath)
  return current.trim() === expected.trim()
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
    return checkPresentRouteState(
      conn,
      { destination, device, dropinPath, gateway },
      {
        dropinPresent,
        live,
      }
    )
  }

  // absent: neither the live route nor this module's own drop-in may remain.
  // A drop-in at the same path with different content is foreign state and
  // must not be treated as ours to delete.
  if (live) return NEEDS_APPLY
  if (!dropinPresent) return "ok"
  return (await routeDropinMatchesExpected(conn, { destination, device, dropinPath, gateway }))
    ? NEEDS_APPLY
    : "ok"
}

async function checkPresentRouteState(
  conn: SshConnection,
  parameters: RouteParameters,
  state: { dropinPresent: boolean; live: boolean }
): Promise<"needs-apply" | "ok"> {
  if (!state.live) return NEEDS_APPLY
  if (!state.dropinPresent) return NEEDS_APPLY
  const expected = buildRouteDropin(parameters.destination, parameters.gateway, parameters.device)
  const current = await conn.readFile(parameters.dropinPath)
  if (current.trim() !== expected.trim()) return NEEDS_APPLY
  const reloadFlag = buildRouteReloadFlag(parameters)
  return (await hasFlag(conn, reloadFlag.flagName)) ? "ok" : NEEDS_APPLY
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
  // R-0000277: defense-in-depth — refuse a symlinked dropin path before the
  // atomic write would silently break it. compose/apt/aptKeyHelpers use the
  // same guard for predictable system paths.
  if (await isSymlink(conn, dropinPath)) {
    return failed(`[net.route: ${destination}] refuses to write through symlink at ${dropinPath}`)
  }
  const dropinContent = buildRouteDropin(destination, gateway, device)
  try {
    await conn.writeFile(dropinPath, dropinContent, { mode: NET_CONFIG_FILE_MODE })
  } catch (error: unknown) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(
      `[net.route: ${destination}] persistent drop-in write failed after ip route replace; live route may now differ from persistent configuration: ${reason}`
    )
  }
  return null
}

/** Result of an apply step that may or may not have mutated host state. */
type RouteApplyOutcome =
  | { changed: boolean; failure: null }
  | { changed: false; failure: ModuleResult }

async function applyAbsentRoute(
  conn: SshConnection,
  parameters: RouteParameters
): Promise<RouteApplyOutcome> {
  const { destination, device, dropinPath, gateway } = parameters
  let changed = false
  if (await hasLiveRoute(conn, { destination, device, gateway })) {
    const devicePart = device !== undefined && device !== "" ? ` dev ${shellQuote(device)}` : ""
    const routeResult = await conn.exec(
      `ip route del ${shellQuote(destination)} via ${shellQuote(gateway)}${devicePart}`,
      EXEC_OPTS
    )
    if (routeResult.code !== 0) {
      return {
        changed: false,
        failure: failedCommand(`[net.route: ${destination}] ip route del failed`, routeResult),
      }
    }
    changed = true
  }
  if (await routeDropinMatchesExpected(conn, parameters)) {
    const removeResult = await conn.exec(`rm -f ${shellQuote(dropinPath)}`, EXEC_OPTS)
    if (removeResult.code !== 0) {
      return {
        changed: false,
        failure: failedCommand(`[net.route: ${destination}] drop-in removal failed`, removeResult),
      }
    }
    changed = true
  }
  return { changed, failure: null }
}

async function reloadNetworkctlForRoute(
  conn: SshConnection,
  destination: string
): Promise<ModuleResult | null> {
  const reloadResult = await conn.exec(NETWORKCTL_RELOAD, EXEC_OPTS)
  if (reloadResult.code !== 0) {
    return failedCommand(`[net.route: ${destination}] networkctl reload failed`, reloadResult)
  }
  return null
}

async function applyPresentRouteState(
  conn: SshConnection,
  parameters: RouteCheckParameters
): Promise<ModuleResult> {
  const failure = await applyPresentRoute(conn, parameters)
  if (failure != null) return failure
  const reloadFailure = await reloadNetworkctlForRoute(conn, parameters.destination)
  if (reloadFailure != null) return reloadFailure
  const reloadFlag = buildRouteReloadFlag(parameters)
  // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC) through
  // the failedCommand path rather than letting the helper throw after a
  // successful networkctl reload.
  const flagFailure = await setVersionedFlag(conn, reloadFlag.flagName, reloadFlag.flagPrefix)
  if (flagFailure) return flagFailure
  return { status: "changed" }
}

async function applyAbsentRouteState(
  conn: SshConnection,
  parameters: RouteCheckParameters
): Promise<ModuleResult> {
  // R-0000219: skip networkctl reload entirely when applyAbsentRoute is a
  // no-op (live route absent and no matching drop-in) so the module reports
  // `ok` instead of falsely signalling `changed`.
  const outcome = await applyAbsentRoute(conn, parameters)
  if (outcome.failure != null) return outcome.failure
  if (!outcome.changed) return { status: "ok" }
  const reloadFailure = await reloadNetworkctlForRoute(conn, parameters.destination)
  if (reloadFailure != null) return reloadFailure
  return { status: "changed" }
}

async function applyRouteState(
  conn: SshConnection,
  parameters: RouteCheckParameters
): Promise<ModuleResult> {
  return parameters.state === "present"
    ? applyPresentRouteState(conn, parameters)
    : applyAbsentRouteState(conn, parameters)
}

/** Shared parameters for the net.hosts apply/check helpers. */
type HostsStateParameters = {
  desiredHostnames: string[]
  expectedLine: string
  isSameIpLine: (line: string) => boolean
  matchesAbsentTarget: (line: string) => boolean
  state: "absent" | "present"
}

/** Snapshot of /etc/hosts content used by the apply helpers. */
type HostsFileSnapshot = {
  content: string
  existed: boolean
  lines: string[]
}

async function captureHostsFileSnapshot(conn: SshConnection): Promise<HostsFileSnapshot> {
  const existed = await conn.exists(HOSTS_FILE)
  const content = existed ? await conn.readFile(HOSTS_FILE) : ""
  return { content, existed, lines: content.split("\n") }
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
  const { isSameIpLine } = parameters
  const { content, existed, lines } = snapshot
  const mergedLine = buildMergedHostsLine(lines, parameters)
  if (!existed) {
    await conn.writeFile(HOSTS_FILE, `${mergedLine}\n`, { mode: HOSTS_FILE_MODE })
    return { status: "changed" }
  }
  // The file is canonical when all same-IP hostnames are consolidated
  // into one stable line. Foreign hostnames already associated with the
  // IP are preserved and desired hostnames are appended if missing.
  const sameIpLines = lines.filter((line) => isSameIpLine(line))
  const alreadyCanonical = sameIpLines.length === 1 && sameIpLines[0]?.trim() === mergedLine
  if (alreadyCanonical) return { status: "ok" }

  const filtered = lines.filter((line) => !isSameIpLine(line))
  // Drop a single trailing blank introduced by `split("\n")` so we
  // do not accumulate empty lines on every replacement.
  if (filtered.length > 0 && filtered.at(-1) === "") filtered.pop()
  filtered.push(mergedLine)
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
  const { content, existed, lines } = snapshot
  if (!existed) return { status: "ok" }
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
  // R-0000169: read-modify-write on /etc/hosts must be serialized so
  // concurrent Paratix runs (or other processes) cannot lose updates between
  // the read and the write. The mutex lock — combined with the re-read inside
  // `guardedWriteFile` — turns the sequence into a critical section that
  // either succeeds atomically or aborts cleanly on an external modification.
  try {
    return await withMutexLock(conn, {
      lockName: HOSTS_FILE_MUTEX,
      async section() {
        const snapshot = await captureHostsFileSnapshot(conn)
        return parameters.state === "present"
          ? applyHostsPresent(conn, parameters, snapshot)
          : applyHostsAbsent(conn, parameters, snapshot)
      },
    })
  } catch (error) {
    return failed(`[net.hosts] aborted: ${error instanceof Error ? error.message : String(error)}`)
  }
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
  const { isSameIpLine, matchesAbsentTarget, state } = parameters
  // R-0000275: a missing /etc/hosts (fresh container/chroot) is a
  // needs-apply situation rather than a phase-level throw. The apply path
  // ensures the file exists, so check defers instead of escalating ENOENT.
  if (!(await conn.exists(HOSTS_FILE))) return NEEDS_APPLY
  const content = await conn.readFile(HOSTS_FILE)
  const lines = content.split("\n")

  if (state === "present") {
    // Drift if there is more than one entry for this IP or if the
    // single entry is not the stable merged representation that apply
    // would write.
    const sameIpLines = lines.filter((line) => isSameIpLine(line))
    if (
      sameIpLines.length === 1 &&
      sameIpLines[0]?.trim() === buildMergedHostsLine(lines, parameters)
    ) {
      return "ok"
    }
    return NEEDS_APPLY
  }

  const found = lines.some((line) => matchesAbsentTarget(line))
  return found ? NEEDS_APPLY : "ok"
}

/**
 * Reject combinations that would transmit credentials in cleartext: any URL
 * using `http://` together with a sensitive header (Authorization, Cookie,
 * X-Api-Key, …). Operators who knowingly target a local mock or a TLS-fronted
 * proxy can opt back in by passing `allowInsecureHttpHeaders: true`.
 *
 * @param url - The already-validated request URL.
 * @param headers - Optional header map supplied by the caller.
 * @param allowInsecureHttpHeaders - When `true`, suppress the rejection.
 */
function rejectSensitiveHeadersOverHttp(
  url: string,
  headers: Record<string, string> | undefined,
  allowInsecureHttpHeaders: boolean | undefined
): void {
  if (allowInsecureHttpHeaders === true) return
  if (headers === undefined || !hasSensitiveHeaders(headers)) return
  // The URL was already validated by validateHttpUrl, so parsing cannot fail
  // in practice; we still wrap it defensively to avoid leaking parse errors.
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return
  }
  if (parsed.protocol !== "http:") return
  throw new Error(
    "[net.request] refusing to send sensitive headers (Authorization, Cookie, X-Api-Key, …) over plaintext http; switch to https or pass allowInsecureHttpHeaders: true to opt in"
  )
}

function urlHasCredentials(url: URL): boolean {
  return url.username.length > 0 || url.password.length > 0
}

/**
 * Reject plaintext HTTP requests whose URL itself carries credentials. Unlike
 * header-based credentials, these values cannot be made safe with curl stdin:
 * they are still transmitted over the network without TLS.
 *
 * @param url - The already-validated request URL.
 */
function rejectSensitiveUrlSecretsOverHttp(url: string): void {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return
  }
  if (parsed.protocol !== "http:") return
  if (!urlHasCredentials(parsed) && !hasSensitiveQueryParameters(parsed)) return

  throw new Error(
    `[net.request] refusing to send sensitive URL credentials or query parameters over plaintext http: ${redactUrlForDisplay(parsed)}; switch to https`
  )
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
    validateHostsOptions(ip, hostnames)

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
          desiredHostnames: hostnames,
          expectedLine,
          isSameIpLine,
          matchesAbsentTarget,
          state,
        })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY
        return checkHostsState(conn, {
          desiredHostnames: hostnames,
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
          const netplanContent = buildNetplanYaml(name, options)
          return writeAndApplyInterfaceConfig({
            applyCommand: "netplan apply",
            content: netplanContent,
            failureMessage: `[net.interface: ${name}] netplan apply failed`,
            path: netplanPath,
            ssh: conn,
          })
        }
        const networkdContent = buildNetworkdConfig(name, options)
        return writeAndApplyInterfaceConfig({
          applyCommand: NETWORKCTL_RELOAD,
          content: networkdContent,
          failureMessage: `[net.interface: ${name}] networkctl reload failed`,
          path: networkdPath,
          ssh: conn,
        })
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
   * @param options.allowInsecureHttpHeaders - When `true`, allow sending sensitive headers (e.g. `Authorization`, `Cookie`) over plaintext `http://`. Default `false` rejects such combinations to prevent credential leakage.
   * @param options.body - Expected string in the response body.
   * @param options.headers - Additional HTTP headers.
   * @param options.method - HTTP method (default: `"GET"`).
   * @param options.status - Expected HTTP status code (default: `200`).
   * @returns A Module that checks the HTTP endpoint.
   */
  request(
    url: string,
    options?: {
      allowInsecureHttpHeaders?: boolean
      body?: string
      headers?: Record<string, string>
      method?: string
      status?: number
    }
  ): Module {
    validateHttpUrl(url, { allowHttp: true })
    rejectSensitiveHeadersOverHttp(url, options?.headers, options?.allowInsecureHttpHeaders)
    rejectSensitiveUrlSecretsOverHttp(url)
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

    const resolvPath = "/etc/resolv.conf"
    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed("[net.resolv] SSH connection is required")

        // R-0000222: on systemd-resolved hosts /etc/resolv.conf is a managed
        // symlink (e.g. -> /run/systemd/resolve/stub-resolv.conf). Writing
        // through it would either replace the upstream stub or, depending on
        // writeFile's atomic-rename semantics, race with systemd-resolved.
        // Refuse the write up-front and require an operator decision (e.g.
        // disable systemd-resolved, switch to net.dns).
        if (await isSymlink(conn, resolvPath)) {
          return failed(
            `[net.resolv] ${resolvPath} is a symlink (typically managed by systemd-resolved); refuse to overwrite without operator opt-in`
          )
        }

        // writeFile uses atomic mv-replace, so a failed write leaves the
        // previous file intact and the host's resolver configuration usable.
        await conn.writeFile(resolvPath, expectedContent, { mode: NET_CONFIG_FILE_MODE })

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        // R-0000275: a missing resolv file (fresh container, host without
        // systemd-resolved) is a needs-apply situation, not a phase-level
        // throw. The apply path below writes the file, so check should defer
        // rather than escalate readFile's ENOENT into a Paratix run failure.
        if (!(await conn.exists(resolvPath))) return NEEDS_APPLY

        const content = await conn.readFile(resolvPath)
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
    validateWaitForTimingOption("interval", interval)
    validateWaitForTimingOption("timeout", timeout)
    const host = options.host ?? "127.0.0.1"
    validateWaitForHost(host)
    if (options.port != null && !isValidTcpPort(options.port)) {
      throw new Error("[net.waitFor] invalid port: value must be an integer between 1 and 65535")
    }
    const testCommand = buildWaitForTestCommand(options, host)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[${buildWaitForName(options)}] SSH connection is required`)

        // R-0000052: hook into the runner abort signal so SIGINT/SIGTERM
        // unblocks the polling loop within the next iteration tick instead
        // of running until the configured timeout. The same abort signal is
        // observed by the `pause` builtin (R-0000027); both share the
        // process-scoped holder in runnerAbortSignal.ts.
        const result = await waitForCondition({ conn, host, interval, options, timeout })
        if (result === "ok") return { status: "changed" }
        if (result === "aborted") return waitForAbortFailure(options)
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
