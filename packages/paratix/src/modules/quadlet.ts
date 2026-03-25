import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const CONTAINERS_SYSTEMD_DIRECTORY = "/etc/containers/systemd"
const QUADLET_FILE_MODE = "0644"
const SYSTEMCTL = "systemctl"
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v

// cspell:ignore quadlet healthcheck

type QuadletAutoUpdate = "local" | "registry"
type QuadletRestartPolicy =
  | "always"
  | "no"
  | "on-abnormal"
  | "on-abort"
  | "on-failure"
  | "on-success"
  | "on-watchdog"

type QuadletContainerOptions = {
  autoUpdate?: QuadletAutoUpdate
  containerName?: string
  description?: string
  environment?: Record<string, string>
  environmentFiles?: string[]
  exec?: string[]
  healthCmd?: string
  healthInterval?: string
  healthRetries?: number
  healthStartPeriod?: string
  healthTimeout?: string
  image: string
  name: string
  networks?: string[]
  podmanArgs?: string[]
  publishPorts?: string[]
  restart?: QuadletRestartPolicy
  volumes?: string[]
  wantedBy?: string
}

function sanitizeQuadletValue(value: string): string {
  return value.replaceAll(/[\n\r]/gv, "")
}

function renderQuadletLine(key: string, value: string): string {
  return `${key}=${sanitizeQuadletValue(value)}`
}

function renderQuadletSection(name: string, lines: string[]): string {
  return [`[${name}]`, ...lines, ""].join("\n")
}

function validateQuadletName(name: string): void {
  if (!UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`quadlet.container: name must match ${String(UNIT_NAME_PATTERN)}, got: ${name}`)
  }
}

function renderQuadletEnvironment(environment: Record<string, string>): string[] {
  return Object.entries(environment)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => renderQuadletLine("Environment", `${key}=${value}`))
}

function renderQuadletRepeated(key: string, values: string[]): string[] {
  return values.map((value) => renderQuadletLine(key, value))
}

function maybeRenderQuadletLine(
  key: string,
  value: null | string | undefined,
  transform?: (value: string) => string
): null | string {
  if (value == null || value === "") return null
  return renderQuadletLine(key, transform == null ? value : transform(value))
}

function compactQuadletLines(lines: Array<null | string>): string[] {
  return lines.filter((line): line is string => line != null)
}

function buildQuadletUnitSection(options: QuadletContainerOptions): string {
  return renderQuadletSection("Unit", [
    renderQuadletLine("Description", options.description ?? `Podman container: ${options.name}`),
    "Wants=network-online.target",
    "After=network-online.target",
  ])
}

function buildQuadletHealthcheckLines(options: QuadletContainerOptions): string[] {
  if (options.healthCmd == null) return []
  return compactQuadletLines([
    renderQuadletLine("HealthCmd", options.healthCmd),
    maybeRenderQuadletLine("HealthInterval", options.healthInterval),
    maybeRenderQuadletLine("HealthTimeout", options.healthTimeout),
    options.healthRetries == null
      ? null
      : renderQuadletLine("HealthRetries", String(options.healthRetries)),
    maybeRenderQuadletLine("HealthStartPeriod", options.healthStartPeriod),
  ])
}

function buildQuadletContainerLines(options: QuadletContainerOptions): string[] {
  return compactQuadletLines([
    renderQuadletLine("Image", options.image),
    maybeRenderQuadletLine("ContainerName", options.containerName),
    maybeRenderQuadletLine("AutoUpdate", options.autoUpdate),
    maybeRenderQuadletLine("Exec", options.exec?.join(" ")),
    maybeRenderQuadletLine("Restart", options.restart),
    ...renderQuadletRepeated("Network", options.networks ?? []),
    ...renderQuadletRepeated("PodmanArgs", options.podmanArgs ?? []),
    ...renderQuadletRepeated("PublishPort", options.publishPorts ?? []),
    ...renderQuadletRepeated("Volume", options.volumes ?? []),
    ...renderQuadletEnvironment(options.environment ?? {}),
    ...renderQuadletRepeated("EnvironmentFile", options.environmentFiles ?? []),
    ...buildQuadletHealthcheckLines(options),
  ])
}

function buildQuadletInstallSection(options: QuadletContainerOptions): string {
  return renderQuadletSection("Install", [
    renderQuadletLine("WantedBy", options.wantedBy ?? "multi-user.target"),
  ])
}

function generateContainerQuadlet(options: QuadletContainerOptions): string {
  return [
    buildQuadletUnitSection(options),
    renderQuadletSection("Container", buildQuadletContainerLines(options)),
    buildQuadletInstallSection(options),
  ]
    .join("\n")
    .trimEnd()
}

async function createQuadletDirectory(ssh: SshConnection): Promise<ExecResultLike> {
  return ssh.exec(`mkdir -p ${shellQuote(CONTAINERS_SYSTEMD_DIRECTORY)}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

type ExecResultLike = Awaited<ReturnType<SshConnection["exec"]>>

async function applyQuadletFile(parameters: {
  content: string
  filePath: string
  name: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const mkdirResult = await createQuadletDirectory(parameters.ssh)
  if (mkdirResult.code !== 0) {
    return failedCommand(
      `[quadlet.container: ${parameters.name}] failed to create quadlet directory`,
      mkdirResult
    )
  }

  await parameters.ssh.writeFile(parameters.filePath, parameters.content, {
    mode: QUADLET_FILE_MODE,
  })

  const daemonReload = await parameters.ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  return daemonReload.code === 0
    ? { status: "changed" }
    : failedCommand(
        `[quadlet.container: ${parameters.name}] systemctl daemon-reload failed`,
        daemonReload
      )
}

async function checkQuadletFile(parameters: {
  content: string
  filePath: string
  ssh: SshConnection
}): Promise<"needs-apply" | "ok"> {
  const exists = await parameters.ssh.exists(parameters.filePath)
  if (!exists) return NEEDS_APPLY
  const remoteContent = await parameters.ssh.readFile(parameters.filePath)
  return remoteContent.trim() === parameters.content.trim() ? "ok" : NEEDS_APPLY
}

/**
 * Modules for managing Podman Quadlet definitions.
 *
 * The first V1 method writes `.container` files under `/etc/containers/systemd`
 * and reloads systemd when content changes. Resulting services can be managed
 * via the regular `service.*(...)` modules.
 */
export const quadlet = {
  /**
   * Write a Podman Quadlet `.container` definition and reload systemd when it changes.
   *
   * The resulting generated service can be controlled with `service.enabled(name)`
   * and `service.running(name)`.
   *
   * @param options - Configuration for the Quadlet container definition.
   * @param options.name - Quadlet base name without `.container`.
   * @param options.image - Container image reference.
   * @param options.description - Optional systemd unit description.
   * @param options.containerName - Optional explicit Podman container name.
   * @param options.autoUpdate - Optional Podman auto-update policy.
   * @param options.environment - Optional environment variables.
   * @param options.environmentFiles - Optional `EnvironmentFile=` entries.
   * @param options.exec - Optional command and arguments for `Exec=`.
   * @param options.healthCmd - Optional `HealthCmd=` directive. Enables the healthcheck block.
   * @param options.healthInterval - Optional `HealthInterval=` (e.g. `"1m30s"`). Requires `healthCmd`.
   * @param options.healthRetries - Optional `HealthRetries=` count. Requires `healthCmd`.
   * @param options.healthStartPeriod - Optional `HealthStartPeriod=` (e.g. `"10s"`). Requires `healthCmd`.
   * @param options.healthTimeout - Optional `HealthTimeout=` (e.g. `"5s"`). Requires `healthCmd`.
   * @param options.networks - Optional `Network=` entries.
   * @param options.podmanArgs - Optional `PodmanArgs=` entries.
   * @param options.publishPorts - Optional `PublishPort=` entries.
   * @param options.restart - Optional `Restart=` policy in the `[Container]` section.
   * @param options.volumes - Optional `Volume=` entries.
   * @param options.wantedBy - Optional install target. Defaults to `multi-user.target`.
   * @returns A Module that ensures the Quadlet file is present and up to date.
   */
  container(options: QuadletContainerOptions): Module {
    validateQuadletName(options.name)
    const filePath = `${CONTAINERS_SYSTEMD_DIRECTORY}/${options.name}.container`
    const content = generateContainerQuadlet(options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.container: ${options.name}] SSH connection is required`)
        return applyQuadletFile({ content, filePath, name: options.name, ssh })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkQuadletFile({ content, filePath, ssh })
      },
      name: `quadlet.container: ${options.name}`,
    }
  },
}
