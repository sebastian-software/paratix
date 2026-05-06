type QuadletAutoUpdate = "local" | "registry"
type QuadletHealthOnFailure = "kill" | "none" | "restart" | "stop"
type QuadletPullPolicy = "always" | "missing" | "never" | "newer"
type QuadletRestartPolicy =
  | "always"
  | "no"
  | "on-abnormal"
  | "on-abort"
  | "on-failure"
  | "on-success"
  | "on-watchdog"

export type QuadletContainerOptions = {
  addCapability?: string[]
  addDevice?: string[]
  annotation?: Record<string, string>
  autoUpdate?: QuadletAutoUpdate
  containerName?: string
  description?: string
  dns?: string[]
  dnsOption?: string[]
  dnsSearch?: string[]
  dropCapability?: string[]
  entrypoint?: string[]
  environment?: Record<string, string>
  environmentFiles?: string[]
  exec?: string[]
  exposeHostPort?: string[]
  groupAdd?: string[]
  healthCmd?: string
  healthInterval?: string
  healthOnFailure?: QuadletHealthOnFailure
  healthRetries?: number
  healthStartPeriod?: string
  healthTimeout?: string
  hostName?: string
  image: string
  ip?: string
  ip6?: string
  label?: Record<string, string>
  logDriver?: string
  mask?: string[]
  mount?: string[]
  name: string
  networks?: string[]
  noNewPrivileges?: boolean
  notify?: boolean
  podmanArgs?: string[]
  publishPorts?: string[]
  pull?: QuadletPullPolicy
  readOnly?: boolean
  restart?: QuadletRestartPolicy
  runInit?: boolean
  seccompProfile?: string
  secret?: string[]
  securityLabelDisable?: boolean
  securityLabelType?: string
  stopTimeout?: number
  sysctl?: Record<string, string>
  timeoutStartSec?: number
  timeoutStopSec?: number
  timezone?: string
  tmpfs?: string[]
  ulimit?: string[]
  unmask?: string[]
  user?: string
  userNs?: string
  volumes?: string[]
  wantedBy?: string
  workingDir?: string
}

export type QuadletImageUpdateOptions = {
  authFile?: string
  image: string
  name: string
  serviceName?: string
}

const CONTAINERS_SYSTEMD_DIRECTORY = "/etc/containers/systemd"
const QUADLET_ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/v
const QUADLET_SAFE_ENVIRONMENT_VALUE_PATTERN = /^[A-Za-z0-9_@%+=:,\x2e\/\-]*$/v
const QUADLET_PULL_CHANGED_OUTPUT_PATTERNS = [
  "Copying blob",
  "Copying config",
  "Downloaded newer image",
  "Pulling fs layer",
  "Storing signatures",
  "Writing manifest",
] as const

function sanitizeQuadletValue(value: string): string {
  return value.replaceAll(/[\n\r]/gv, "")
}

function renderQuadletLine(key: string, value: string): string {
  return `${key}=${sanitizeQuadletValue(value)}`
}

function renderQuadletRepeated(key: string, values: string[]): string[] {
  return values.map((value) => renderQuadletLine(key, value))
}

function renderQuadletKeyValue(key: string, record: Record<string, string>): string[] {
  return Object.entries(record)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([k, v]) => renderQuadletLine(key, `${k}=${v}`))
}

function maybeRenderQuadletLine(key: string, value: null | string | undefined): null | string {
  if (value == null || value === "") return null
  return renderQuadletLine(key, value)
}

function maybeRenderQuadletBool(key: string, value: boolean | undefined): null | string {
  if (value == null) return null
  return renderQuadletLine(key, String(value))
}

function maybeRenderQuadletNumber(key: string, value: number | undefined): null | string {
  if (value == null) return null
  return renderQuadletLine(key, String(value))
}

function compactQuadletLines(lines: Array<null | string>): string[] {
  return lines.filter((line): line is string => line != null)
}

export function renderQuadletSection(name: string, lines: string[]): string {
  return [`[${name}]`, ...lines, ""].join("\n")
}

function buildQuadletIdentityLines(options: QuadletContainerOptions): Array<null | string> {
  return [
    renderQuadletLine("Image", options.image),
    maybeRenderQuadletLine("ContainerName", options.containerName),
    maybeRenderQuadletLine("AutoUpdate", options.autoUpdate),
    maybeRenderQuadletLine("Pull", options.pull),
    maybeRenderQuadletLine("Entrypoint", options.entrypoint?.join(" ")),
    maybeRenderQuadletLine("Exec", options.exec?.join(" ")),
    maybeRenderQuadletLine("WorkingDir", options.workingDir),
    maybeRenderQuadletLine("User", options.user),
    maybeRenderQuadletLine("UserNS", options.userNs),
  ]
}

function buildQuadletNetworkLines(options: QuadletContainerOptions): Array<null | string> {
  return [
    maybeRenderQuadletLine("HostName", options.hostName),
    ...renderQuadletRepeated("Network", options.networks ?? []),
    ...renderQuadletRepeated("DNS", options.dns ?? []),
    ...renderQuadletRepeated("DNSOption", options.dnsOption ?? []),
    ...renderQuadletRepeated("DNSSearch", options.dnsSearch ?? []),
    maybeRenderQuadletLine("IP", options.ip),
    maybeRenderQuadletLine("IP6", options.ip6),
  ]
}

function buildQuadletSecurityLines(options: QuadletContainerOptions): Array<null | string> {
  return [
    ...renderQuadletRepeated("AddCapability", options.addCapability ?? []),
    ...renderQuadletRepeated("DropCapability", options.dropCapability ?? []),
    maybeRenderQuadletBool("SecurityLabelDisable", options.securityLabelDisable),
    maybeRenderQuadletLine("SecurityLabelType", options.securityLabelType),
    maybeRenderQuadletLine("SeccompProfile", options.seccompProfile),
    maybeRenderQuadletBool("NoNewPrivileges", options.noNewPrivileges),
    maybeRenderQuadletBool("ReadOnly", options.readOnly),
  ]
}

function buildQuadletRuntimeLines(options: QuadletContainerOptions): Array<null | string> {
  return [
    maybeRenderQuadletBool("Notify", options.notify),
    maybeRenderQuadletBool("RunInit", options.runInit),
    maybeRenderQuadletLine("LogDriver", options.logDriver),
    maybeRenderQuadletLine("Timezone", options.timezone),
    maybeRenderQuadletNumber("StopTimeout", options.stopTimeout),
  ]
}

function buildQuadletStorageLines(options: QuadletContainerOptions): string[] {
  return [
    ...renderQuadletRepeated("PublishPort", options.publishPorts ?? []),
    ...renderQuadletRepeated("ExposeHostPort", options.exposeHostPort ?? []),
    ...renderQuadletRepeated("Volume", options.volumes ?? []),
    ...renderQuadletRepeated("Mount", options.mount ?? []),
    ...renderQuadletRepeated("Tmpfs", options.tmpfs ?? []),
    ...renderQuadletRepeated("AddDevice", options.addDevice ?? []),
  ]
}

function buildQuadletMetadataLines(options: QuadletContainerOptions): string[] {
  return [
    ...renderQuadletRepeated("Secret", options.secret ?? []),
    ...renderQuadletEnvironment(options.environment ?? {}),
    ...renderQuadletRepeated("EnvironmentFile", options.environmentFiles ?? []),
    ...renderQuadletKeyValue("Label", options.label ?? {}),
    ...renderQuadletKeyValue("Annotation", options.annotation ?? {}),
  ]
}

function renderQuadletEnvironment(environment: Record<string, string>): string[] {
  return Object.entries(environment)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => renderQuadletEnvironmentLine(key, value))
}

function assertQuadletEnvironmentKey(key: string): void {
  if (!QUADLET_ENVIRONMENT_KEY_PATTERN.test(key)) {
    throw new Error(`quadlet.container environment key is invalid: ${JSON.stringify(key)}`)
  }
}

function quoteQuadletEnvironmentValue(value: string): string {
  if (/[\n\r]/v.test(value)) {
    throw new Error("quadlet.container environment values must not contain newlines")
  }
  if (QUADLET_SAFE_ENVIRONMENT_VALUE_PATTERN.test(value)) return value
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`
}

function renderQuadletEnvironmentLine(key: string, value: string): string {
  assertQuadletEnvironmentKey(key)
  return renderQuadletLine("Environment", `${key}=${quoteQuadletEnvironmentValue(value)}`)
}

function buildQuadletTuningLines(options: QuadletContainerOptions): string[] {
  return [
    ...renderQuadletKeyValue("Sysctl", options.sysctl ?? {}),
    ...renderQuadletRepeated("Ulimit", options.ulimit ?? []),
    ...renderQuadletRepeated("GroupAdd", options.groupAdd ?? []),
    ...renderQuadletRepeated("Mask", options.mask ?? []),
    ...renderQuadletRepeated("Unmask", options.unmask ?? []),
  ]
}

function buildQuadletHealthcheckLines(options: QuadletContainerOptions): string[] {
  if (options.healthCmd == null) return []
  return compactQuadletLines([
    renderQuadletLine("HealthCmd", options.healthCmd),
    maybeRenderQuadletLine("HealthInterval", options.healthInterval),
    maybeRenderQuadletLine("HealthTimeout", options.healthTimeout),
    maybeRenderQuadletNumber("HealthRetries", options.healthRetries),
    maybeRenderQuadletLine("HealthStartPeriod", options.healthStartPeriod),
    maybeRenderQuadletLine("HealthOnFailure", options.healthOnFailure),
  ])
}

export function buildQuadletContainerLines(options: QuadletContainerOptions): string[] {
  return compactQuadletLines([
    ...buildQuadletIdentityLines(options),
    ...buildQuadletNetworkLines(options),
    ...buildQuadletSecurityLines(options),
    ...buildQuadletRuntimeLines(options),
    ...renderQuadletRepeated("PodmanArgs", options.podmanArgs ?? []),
    ...buildQuadletStorageLines(options),
    ...buildQuadletMetadataLines(options),
    ...buildQuadletTuningLines(options),
    ...buildQuadletHealthcheckLines(options),
  ])
}

export function buildQuadletServiceLines(options: QuadletContainerOptions): string[] {
  return compactQuadletLines([
    maybeRenderQuadletLine("Restart", options.restart),
    maybeRenderQuadletNumber("TimeoutStartSec", options.timeoutStartSec),
    maybeRenderQuadletNumber("TimeoutStopSec", options.timeoutStopSec),
  ])
}

export function buildQuadletUnitSection(options: QuadletContainerOptions): string {
  return renderQuadletSection("Unit", [
    renderQuadletLine("Description", options.description ?? `Podman container: ${options.name}`),
    "Wants=network-online.target",
    "After=network-online.target",
  ])
}

export function buildQuadletInstallSection(options: QuadletContainerOptions): string {
  return renderQuadletSection("Install", [
    renderQuadletLine("WantedBy", options.wantedBy ?? "multi-user.target"),
  ])
}

export function buildQuadletImagePullCommand(options: QuadletImageUpdateOptions): string {
  const authFileFlag =
    options.authFile == null ? "" : ` --authfile ${shellQuoteForQuadlet(options.authFile)}`
  return `podman pull${authFileFlag} -- ${shellQuoteForQuadlet(options.image)} 2>&1`
}

export function getQuadletContainerFilePath(name: string): string {
  return `${CONTAINERS_SYSTEMD_DIRECTORY}/${name}.container`
}

export function getQuadletContainerServiceName(options: QuadletImageUpdateOptions): string {
  return options.serviceName ?? options.name
}

export function quadletPullOutputIndicatesChange(output: string): boolean {
  return QUADLET_PULL_CHANGED_OUTPUT_PATTERNS.some((pattern) => output.includes(pattern))
}

const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v

export function validateQuadletName(name: string): void {
  if (name.startsWith("-")) {
    throw new Error(`quadlet: name must not start with '-', got: ${JSON.stringify(name)}`)
  }
  if (!UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`quadlet: name must match ${String(UNIT_NAME_PATTERN)}, got: ${name}`)
  }
}

export function validateQuadletImageValue(field: string, value: string): void {
  if (value.startsWith("-")) {
    throw new Error(`quadlet: ${field} must not start with '-', got: ${JSON.stringify(value)}`)
  }
}

function shellQuoteForQuadlet(value: string): string {
  const escapedQuote = "'\\''"
  return `'${value.replaceAll("'", escapedQuote)}'`
}
