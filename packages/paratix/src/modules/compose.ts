/* eslint-disable max-lines -- compose module intentionally keeps related lifecycle helpers together */
import { readFile } from "node:fs/promises"
import { basename } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { isRegularFileWithoutSymlink, isSymlink } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const COMPOSE_CONFIG_MODE = "0600"
const COMPOSE_CONFIG_STAGING_PREFIX = ".compose.yml.paratix-staging"
const SYSTEMD_UNIT_MODE = "0644"

type ComposeRuntime = "docker" | "podman"

function requireComposeSsh(
  ssh: null | SshConnection,
  action: string,
  projectDirectory: string
): ModuleResult | SshConnection {
  return ssh ?? failed(`[compose.${action}] SSH connection is required for ${projectDirectory}`)
}

async function requireComposeRuntime(parameters: {
  action: string
  explicitRuntime?: ComposeRuntime
  projectDirectory: string
  ssh: SshConnection
}): Promise<ComposeRuntime | ModuleResult> {
  const runtime = await getRuntime(parameters.ssh, parameters.explicitRuntime)
  return (
    runtime ??
    failed(
      `[compose.${parameters.action}] no container runtime found for ${parameters.projectDirectory}`
    )
  )
}

const COMPOSE_UP_ACTION_KEYWORDS = ["Creating", "Recreating", "Starting", "Started", "Pulling"]

/**
 * R-0000078: when every service was already running, `compose up -d`
 * emits no action keywords and the run is a true no-op. Treat that as
 * status ok so apply does not always report "changed".
 *
 * @param composeOutput - The combined stdout/stderr returned by `compose up`.
 * @returns `true` when at least one action keyword was emitted.
 */
function composeUpReportedChange(composeOutput: string): boolean {
  return COMPOSE_UP_ACTION_KEYWORDS.some((keyword) => composeOutput.includes(keyword))
}

function validateComposeUpServices(services: string[] | undefined): void {
  for (const service of services ?? []) {
    if (service === "") {
      throw new Error("compose.up services must not contain empty service names")
    }
    if (service.startsWith("-")) {
      throw new Error(`compose.up service names must not start with "-", got ${service}`)
    }
  }
}

/**
 * Detect whether `podman` or `docker` is available on the remote host.
 * Podman is preferred when both are installed.
 *
 * @param ssh - The SSH connection to the remote host.
 * @returns The first available runtime, or `null` if neither is found.
 */
async function detectRuntime(ssh: SshConnection): Promise<ComposeRuntime | null> {
  if (await ssh.test("command -v podman")) return "podman"
  if (await ssh.test("command -v docker")) return "docker"
  return null
}

/**
 * Resolve the container runtime to use, preferring the explicit override.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param explicit - An optional runtime override that skips auto-detection.
 * @returns The resolved runtime, or `null` if none could be determined.
 */
async function getRuntime(
  ssh: SshConnection,
  explicit?: ComposeRuntime
): Promise<ComposeRuntime | null> {
  return explicit ?? (await detectRuntime(ssh))
}

/**
 * Build the base `docker compose` or `podman compose` command string for a
 * given project directory.
 *
 * @param runtime - The container runtime to use.
 * @param projectDirectory - The project directory passed via `--project-directory`.
 * @returns The base compose command string, ready for subcommand concatenation.
 */
function composeCommand(runtime: ComposeRuntime, projectDirectory: string): string {
  return `${runtime} compose --project-directory ${shellQuote(projectDirectory)}`
}

function parseComposeProjectName(stdout: string, projectDirectory: string): null | string {
  try {
    const parsed: unknown = JSON.parse(stdout)
    if (typeof parsed === "object" && parsed !== null && "name" in parsed) {
      const name = parsed.name
      if (typeof name === "string" && name.trim() !== "") return name
    }
    return basename(projectDirectory)
  } catch {
    return null
  }
}

async function resolveComposeProjectName(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<null | string> {
  const result = await parameters.ssh.exec(
    `${composeCommand(parameters.runtime, parameters.projectDirectory)} config --format json`,
    EXEC_OPTS
  )
  if (result.code !== 0) return null
  return parseComposeProjectName(result.stdout, parameters.projectDirectory)
}

async function composeProjectVolumesExist(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<boolean> {
  const projectName = await resolveComposeProjectName(parameters)
  if (projectName === null) return true

  const composeProjectLabel = `label=com.docker.compose.project=${projectName}`
  const result = await parameters.ssh.exec(
    `${parameters.runtime} volume ls --filter ${shellQuote(composeProjectLabel)} -q`,
    EXEC_OPTS
  )
  if (result.code !== 0) return true
  return result.stdout.trim().length > 0
}

async function checkComposeDownNoContainers(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
  volumes?: boolean
}): Promise<"needs-apply" | "ok"> {
  if (parameters.volumes !== true) return "ok"
  return (await composeProjectVolumesExist(parameters)) ? NEEDS_APPLY : "ok"
}

async function resolveDesiredComposeContent(options: {
  content?: string
  src?: string
}): Promise<null | string> {
  if (options.src !== undefined && options.src !== "") {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path from module config, not user input
    return readFile(options.src, "utf8")
  }
  if (options.content !== undefined && options.content !== "") {
    return options.content
  }
  return null
}

/**
 * Parse the container state strings from the JSON output of `compose ps --format json`.
 *
 * Both array JSON (Docker >= 2.x) and newline-delimited JSON (older Docker / Podman)
 * are supported. Each entry is expected to have a `State` property.
 *
 * @param stdout - The raw stdout string from the `compose ps` command.
 * @returns An array of state strings (e.g. `"running"`, `"exited"`). Returns an
 *   empty array when parsing fails or the output is not in a recognised format.
 */
function parseContainerStates(stdout: string): string[] {
  try {
    const parsed: unknown = stdout.startsWith("[")
      ? JSON.parse(stdout)
      : stdout
          .split("\n")
          .filter((line) => line.trim() !== "")
          .map((line) => JSON.parse(line) as unknown)

    if (!Array.isArray(parsed)) return []

    return parsed.map((entry: unknown) => {
      if (typeof entry === "object" && entry !== null && "State" in entry) {
        const state = entry.State
        return typeof state === "string" ? state : ""
      }
      return ""
    })
  } catch {
    return []
  }
}

/**
 * Strip newline characters from a value to prevent injection in systemd unit files.
 *
 * @param value - The string to sanitize.
 * @returns The sanitized string with all newline characters removed.
 */
function sanitizeUnitValue(value: string): string {
  return value.replaceAll(/[\n\r]/gv, "")
}

function validateGeneratedSystemdUnitContent(
  content: string,
  unitFileName: string
): ModuleResult | null {
  if (content.trim() === "") {
    return failed(`[compose.systemd] generated empty unit content for ${unitFileName}`)
  }

  if (!content.includes("[Unit]") || !content.includes("[Service]")) {
    return failed(`[compose.systemd] generated invalid unit content for ${unitFileName}`)
  }

  return null
}

async function verifyNonEmptySystemdUnit(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<"empty" | "matches" | "unexpected"> {
  const writtenContent = await parameters.connection.readFile(parameters.filePath)
  if (writtenContent.trim() === "") return "empty"
  return writtenContent.trim() === parameters.content.trim() ? "matches" : "unexpected"
}

async function cleanupComposeSystemdTarget(parameters: {
  connection: SshConnection
  filePath: string
}): Promise<void> {
  await parameters.connection.exec(`rm -f ${shellQuote(parameters.filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function rewriteComposeSystemdUnitViaShell(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult | null> {
  const encodedContent = Buffer.from(parameters.content, "utf8").toString("base64")
  await cleanupComposeSystemdTarget(parameters)
  const result = await parameters.connection.exec(
    `printf '%s' ${shellQuote(encodedContent)} | base64 -d > ${shellQuote(parameters.filePath)} && chmod ${shellQuote(SYSTEMD_UNIT_MODE)} ${shellQuote(parameters.filePath)} && chown ${shellQuote("root:root")} ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[compose.systemd] shell fallback write failed for ${parameters.unitFileName}`,
      result
    )
  }

  const fallbackVerification = await verifyNonEmptySystemdUnit(parameters)
  if (fallbackVerification === "matches") return null

  await cleanupComposeSystemdTarget(parameters)
  if (fallbackVerification === "empty") {
    return failed(
      `[compose.systemd] wrote empty unit file for ${parameters.unitFileName} even after shell fallback`
    )
  }
  return failed(
    `[compose.systemd] wrote unexpected unit content for ${parameters.unitFileName} even after shell fallback`
  )
}

async function writeComposeSystemdUnitFile(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult | null> {
  // R-0000192: refuse to write through a symlinked unit path. The check path
  // already rejects symlinks via isRegularFileWithoutSymlink; without the same
  // guard here, writeFile + chown root:root would follow the link and mutate
  // an attacker-controlled target. Mirrors the apt.key (R-0000134) hardening.
  if (await isSymlink(parameters.connection, parameters.filePath)) {
    return failed(`[compose.systemd] refuses to write through symlink at ${parameters.filePath}`)
  }
  try {
    await parameters.connection.writeFile(parameters.filePath, parameters.content, {
      mode: SYSTEMD_UNIT_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[compose.systemd] atomic write failed for ${parameters.unitFileName}: ${reason}`)
  }

  const writeVerification = await verifyNonEmptySystemdUnit(parameters)
  if (writeVerification !== "matches") {
    return rewriteComposeSystemdUnitViaShell(parameters)
  }
  return null
}

async function applyComposeSystemdUnit(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult> {
  await prepareComposeSystemdTarget(parameters)
  const writeFailure = await writeComposeSystemdUnitFile(parameters)
  if (writeFailure != null) return writeFailure

  // R-0000164: writeFile sets the file mode but not its owner/group, so an
  // owner drift introduced by a previous manual `chown` would persist. The
  // shell-fallback path already runs `chown root:root`, but the happy path
  // goes through writeFile and never runs that command. Always re-set owner
  // to root:root after a successful write so check and apply stay symmetric.
  const ownerResult = await parameters.connection.exec(
    `chown ${shellQuote("root:root")} ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (ownerResult.code !== 0) {
    return failedCommand(
      `[compose.systemd] failed to set owner root:root on ${parameters.unitFileName}`,
      ownerResult
    )
  }

  const result = await parameters.connection.exec("systemctl daemon-reload", EXEC_OPTS)
  return result.code === 0
    ? { status: "changed" }
    : failedCommand(`[compose.systemd] daemon-reload failed for ${parameters.unitFileName}`, result)
}

async function checkComposeSystemdUnit(parameters: {
  detached: boolean
  explicitRuntime?: ComposeRuntime
  filePath: string
  projectDirectory: string
  serviceName: string
  ssh: SshConnection
}): Promise<"needs-apply" | "ok"> {
  const runtime = await getRuntime(parameters.ssh, parameters.explicitRuntime)
  if (!runtime) return NEEDS_APPLY

  if (!(await isRegularFileWithoutSymlink(parameters.ssh, parameters.filePath))) {
    return NEEDS_APPLY
  }

  const content = generateSystemdUnit(parameters.projectDirectory, parameters.serviceName, {
    detached: parameters.detached,
    runtime,
  })
  const remoteContent = await parameters.ssh.readFile(parameters.filePath)
  if (remoteContent.trim() !== content.trim()) return NEEDS_APPLY

  // R-0000085: detect manual mode drift (e.g. an operator ran
  // `chmod 0600 compose-app.service`): even when the content matches, the
  // apply path would re-set the mode to SYSTEMD_UNIT_MODE, so check must
  // report needs-apply to keep the run idempotent — mirroring the same
  // pattern used by createComposeConfigCheck.
  const rawMode = await parameters.ssh.output(`stat -c '%a' ${shellQuote(parameters.filePath)}`)
  const remoteMode = rawMode.trim()
  if (remoteMode !== SYSTEMD_UNIT_MODE.replace(/^0+/v, "")) return NEEDS_APPLY

  // R-0000164: detect manual owner/group drift (e.g. an operator ran
  // `chown svc:svc compose-app.service`). The apply path explicitly runs
  // `chown root:root` on the unit, so a check that ignored ownership would
  // report "ok" while apply silently kept rewriting the unit on every run.
  // A non-root owner of a system-wide unit is also a hardening regression.
  const rawOwner = await parameters.ssh.output(`stat -c '%U %G' ${shellQuote(parameters.filePath)}`)
  if (rawOwner.trim() !== "root root") return NEEDS_APPLY

  return "ok"
}

function resolveComposeSystemdIdentity(options: { name?: string; projectDirectory: string }): {
  filePath: string
  serviceName: string
  unitFileName: string
} {
  const serviceName = options.name ?? `compose-${basename(options.projectDirectory)}`
  if (serviceName.startsWith("-")) {
    throw new Error(`compose.systemd: name must not start with '-', got: ${serviceName}`)
  }
  if (!UNIT_NAME_PATTERN.test(serviceName)) {
    throw new Error(
      `compose.systemd: name must match ${String(UNIT_NAME_PATTERN)}, got: ${serviceName}`
    )
  }

  const unitFileName = `${serviceName}.service`
  return {
    filePath: `/etc/systemd/system/${unitFileName}`,
    serviceName,
    unitFileName,
  }
}

async function prepareComposeSystemdTarget(parameters: {
  connection: SshConnection
  unitFileName: string
}): Promise<void> {
  await parameters.connection.exec(`systemctl unmask -- ${shellQuote(parameters.unitFileName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

/**
 * Generate the content of a systemd service unit file that manages a compose
 * stack via `ExecStart` / `ExecStop`.
 *
 * The generated unit depends on `docker.service` when the runtime is `docker`,
 * and only on `network-online.target` for `podman`.
 *
 * @param projectDirectory - The working directory for the compose commands.
 * @param name - The human-readable service description and unit name.
 * @param options - Unit generation parameters.
 * @param options.runtime - The container runtime (`docker` or `podman`).
 * @param options.detached - Whether `compose up` should run with `-d`.
 * @returns The full systemd unit file content as a string.
 */
function generateSystemdUnit(
  projectDirectory: string,
  name: string,
  options: { detached: boolean; runtime: ComposeRuntime }
): string {
  const safeName = sanitizeUnitValue(name)
  const safeDirectory = sanitizeUnitValue(projectDirectory)
  const composeUpCommand = options.detached
    ? `/usr/bin/env ${options.runtime} compose up -d --remove-orphans`
    : `/usr/bin/env ${options.runtime} compose up --remove-orphans`
  const lines = ["[Unit]", `Description=Compose stack: ${safeName}`, "Wants=network-online.target"]

  if (options.runtime === "docker") {
    lines.push("After=network-online.target docker.service")
    lines.push("Requires=docker.service")
  } else {
    lines.push("After=network-online.target")
  }

  lines.push(
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${safeDirectory}`,
    `ExecStart=${composeUpCommand}`,
    `ExecStop=/usr/bin/env ${options.runtime} compose down`,
    "TimeoutStartSec=0",
    "StandardOutput=journal",
    "StandardError=journal",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    ""
  )

  return lines.join("\n")
}

/** Options that {@link createComposeConfigCheck} reads to compute the desired state. */
type ComposeConfigCheckOptions = {
  content?: string
  src?: string
}

/**
 * Build the `check` function for `compose.config`.
 *
 * Reports `needs-apply` when:
 * - the connection is missing
 * - `compose.yml` is missing
 * - the desired content cannot be resolved
 * - the remote content differs from the desired content
 * - the remote mode has drifted from {@link COMPOSE_CONFIG_MODE}
 *
 * @param remotePath - Path to the remote `compose.yml`.
 * @param options - The compose-config options (only `src` and `content` matter here).
 * @returns A `check` callback for the module's `Module` object.
 */
function createComposeConfigCheck(
  remotePath: string,
  options: ComposeConfigCheckOptions
): (ssh: null | SshConnection) => Promise<"needs-apply" | "ok"> {
  return async (ssh) => {
    if (!ssh) return NEEDS_APPLY

    if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) return NEEDS_APPLY

    const desiredContent = await resolveDesiredComposeContent(options)
    if (desiredContent == null) return NEEDS_APPLY

    const remoteContent = await ssh.readFile(remotePath)
    if (remoteContent.trim() !== desiredContent.trim()) return NEEDS_APPLY

    // Detect manual mode drift (e.g. an operator ran `chmod 0644 compose.yml`):
    // even when the content matches, the apply path would re-set the mode,
    // so check must report needs-apply to keep the run idempotent.
    const rawMode = await ssh.output(`stat -c '%a' ${shellQuote(remotePath)}`)
    const remoteMode = rawMode.trim()
    return remoteMode === COMPOSE_CONFIG_MODE.replace(/^0+/v, "") ? "ok" : NEEDS_APPLY
  }
}

/**
 * Write the new compose.yml content to a staging path, leaving the active
 * `compose.yml` untouched until validation succeeds. Either `options.src`
 * (uploaded) or `options.content` (string) is used; the caller has already
 * verified that exactly one is provided.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param stagingPath - Temporary destination for the new compose content.
 * @param options - Source/content options identical to {@link compose.config}.
 * @param options.content - Inline string content to write.
 * @param options.src - Local file path to upload.
 */
async function writeComposeStagingFile(
  ssh: SshConnection,
  stagingPath: string,
  options: { content?: string; src?: string }
): Promise<void> {
  if (options.src !== undefined && options.src !== "") {
    // Always pass an explicit { mode } to uploadFile so the resulting
    // compose.yml mode is independent of the uploadFile temp default.
    await ssh.uploadFile(options.src, stagingPath, { mode: COMPOSE_CONFIG_MODE })
    return
  }
  if (options.content !== undefined && options.content !== "") {
    await ssh.writeFile(stagingPath, options.content, { mode: COMPOSE_CONFIG_MODE })
  }
}

async function validateStagedComposeFile(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
  stagingPath: string
}): Promise<ModuleResult | null> {
  const { projectDirectory, runtime, ssh, stagingPath } = parameters
  // R-0000228: validate against the staging file with -f so a parallel
  // compose invocation reading <projectDirectory>/compose.yml never sees
  // a half-written or unvalidated revision.
  const validate = await ssh.exec(
    `${composeCommand(runtime, projectDirectory)} -f ${shellQuote(stagingPath)} config --quiet`,
    EXEC_OPTS
  )
  if (validate.code === 0) return null
  return failedCommand(`[compose.config] validation failed for ${projectDirectory}`, validate)
}

async function activateStagedComposeFile(
  ssh: SshConnection,
  stagingPath: string,
  remotePath: string
): Promise<ModuleResult | null> {
  // R-0000228: atomic rename so the active compose.yml flips from prior
  // to validated content in one syscall. mv -T refuses to descend into
  // an existing directory at remotePath, mirroring the safety we already
  // require for download.url destinations.
  const move = await ssh.exec(
    `mv -T ${shellQuote(stagingPath)} ${shellQuote(remotePath)}`,
    EXEC_OPTS
  )
  if (move.code === 0) return null
  return failedCommand(`[compose.config] failed to activate validated compose file`, move)
}

async function removeComposeStagingFile(ssh: SshConnection, stagingPath: string): Promise<void> {
  await ssh.exec(`rm -f ${shellQuote(stagingPath)}`, EXEC_OPTS)
}

async function createComposeStagingPath(parameters: {
  projectDirectory: string
  ssh: SshConnection
}): Promise<string> {
  const template = `${parameters.projectDirectory}/${COMPOSE_CONFIG_STAGING_PREFIX}.XXXXXX`
  const stagingPath = await parameters.ssh.output(`mktemp ${shellQuote(template)}`)
  return validateMktempPath(parameters.projectDirectory, stagingPath, COMPOSE_CONFIG_STAGING_PREFIX)
}

async function applyComposeConfig(parameters: {
  options: { content?: string; src?: string }
  projectDirectory: string
  remotePath: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, projectDirectory, remotePath, runtime, ssh } = parameters
  const stagingPath = await createComposeStagingPath({ projectDirectory, ssh })

  // R-0000228: write into a staging file (not into compose.yml). The active
  // compose.yml is only replaced after validation succeeds, so a parallel
  // `compose up` cannot pick up an unvalidated config. The staging file is
  // also unique per apply and cleaned up if validation or anything else throws.
  try {
    await writeComposeStagingFile(ssh, stagingPath, options)
    const validationFailure = await validateStagedComposeFile({
      projectDirectory,
      runtime,
      ssh,
      stagingPath,
    })
    if (validationFailure != null) return validationFailure
    const activationFailure = await activateStagedComposeFile(ssh, stagingPath, remotePath)
    if (activationFailure != null) return activationFailure
  } finally {
    await removeComposeStagingFile(ssh, stagingPath)
  }

  return { status: "changed" }
}

/**
 * Modules for managing Docker Compose / Podman Compose stacks on a remote host.
 *
 * All methods auto-detect the container runtime (`docker` or `podman`) unless
 * an explicit `runtime` option is provided.
 */
export const compose = {
  /**
   * Ensure a compose-file is present at `<projectDirectory>/compose.yml`.
   *
   * Provide either `src` (a local file path to upload) or `content` (a string
   * to write). The check phase compares the remote file content with the
   * desired content and skips the apply if they match.
   *
   * @param options - Configuration for the compose file.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.src - Local file path to upload as `compose.yml`.
   * @param options.content - String content to write as `compose.yml`.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the compose file is present and valid.
   */
  config(options: {
    content?: string
    projectDirectory: string
    runtime?: ComposeRuntime
    src?: string
  }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options
    const remotePath = `${projectDirectory}/compose.yml`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "config", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "config",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        if (
          (options.src === undefined || options.src === "") &&
          (options.content === undefined || options.content === "")
        ) {
          return failed(`[compose.config] content or src is required for ${projectDirectory}`)
        }

        return applyComposeConfig({
          options,
          projectDirectory,
          remotePath,
          runtime,
          ssh: connection,
        })
      },
      check: createComposeConfigCheck(remotePath, options),
      name: `compose.config: ${projectDirectory}`,
    }
  },

  /**
   * Tear down all containers in the compose stack. Optionally remove volumes.
   *
   * @param options - Configuration for the down operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.volumes - When `true`, also remove named volumes.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures all containers are stopped and removed.
   */
  down(options: { projectDirectory: string; runtime?: ComposeRuntime; volumes?: boolean }): Module {
    const { projectDirectory, runtime: explicitRuntime, volumes } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "down", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "down",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const volumesFlag = volumes === true ? " --volumes" : ""
        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} down${volumesFlag}`,
          EXEC_OPTS
        )
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[compose.down] failed for ${projectDirectory}`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} ps --format json`,
          EXEC_OPTS
        )
        if (result.code !== 0) return NEEDS_APPLY

        const stdout = result.stdout.trim()
        if (stdout === "") {
          return checkComposeDownNoContainers({ projectDirectory, runtime: rt, ssh, volumes })
        }
        const states = parseContainerStates(stdout)
        if (states.length === 0 && stdout === "[]") {
          return checkComposeDownNoContainers({ projectDirectory, runtime: rt, ssh, volumes })
        }

        return NEEDS_APPLY
      },
      name: `compose.down: ${projectDirectory}`,
    }
  },

  /**
   * Pull the latest images for all services in the compose stack.
   * Signal-style: always applies since an efficient up-to-date check is not
   * feasible.
   *
   * @param options - Configuration for the pull operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that pulls the latest images.
   */
  pull(options: { projectDirectory: string; runtime?: ComposeRuntime }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "pull", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "pull",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} pull 2>&1`,
          EXEC_OPTS
        )
        if (result.code !== 0)
          return failedCommand(`[compose.pull] failed for ${projectDirectory}`, result)

        const output = result.stdout
        if (output.includes("Pulling") || output.includes("Downloaded")) {
          return { status: "changed" }
        }
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: `compose.pull: ${projectDirectory}`,
    }
  },

  /**
   * Restart all containers by running `down` followed by `up -d`.
   * Signal-style: always applies.
   *
   * @param options - Configuration for the restart operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that restarts the compose stack.
   */
  restart(options: { projectDirectory: string; runtime?: ComposeRuntime }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "restart", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "restart",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const cmd = composeCommand(runtime, projectDirectory)
        const result = await connection.exec(`${cmd} down && ${cmd} up -d`, EXEC_OPTS)
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[compose.restart] failed for ${projectDirectory}`, result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: `compose.restart: ${projectDirectory}`,
    }
  },

  /**
   * Generate and write a systemd service unit that manages the compose stack
   * via `ExecStart` / `ExecStop`.
   *
   * The service name defaults to `compose-<basename(projectDirectory)>` when not
   * explicitly provided.
   *
   * @param options - Configuration for the systemd unit.
   * @param options.detached - When true, use `compose up -d`; otherwise start attached.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.name - Optional service name (without `.service` suffix).
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the systemd unit file is present and up-to-date.
   */
  systemd(options: {
    detached?: boolean
    name?: string
    projectDirectory: string
    runtime?: ComposeRuntime
  }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options
    const detached = options.detached ?? false
    const { filePath, serviceName, unitFileName } = resolveComposeSystemdIdentity({
      name: options.name,
      projectDirectory,
    })

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "systemd", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "systemd",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const content = generateSystemdUnit(projectDirectory, serviceName, { detached, runtime })
        const validationFailure = validateGeneratedSystemdUnitContent(content, unitFileName)
        if (validationFailure != null) return validationFailure
        return applyComposeSystemdUnit({
          connection,
          content,
          filePath,
          unitFileName,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkComposeSystemdUnit({
          detached,
          explicitRuntime,
          filePath,
          projectDirectory,
          serviceName,
          ssh,
        })
      },
      name: `compose.systemd: ${unitFileName}`,
    }
  },

  /**
   * Ensure all services in the compose stack are running.
   *
   * The check phase inspects each container's state via `ps --format json`
   * and only skips when every service reports `"running"`.
   *
   * @param options - Configuration for the up operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.services - Optional list of specific services to start.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the compose stack is up.
   */
  up(options: { projectDirectory: string; runtime?: ComposeRuntime; services?: string[] }): Module {
    const { projectDirectory, runtime: explicitRuntime, services } = options
    validateComposeUpServices(services)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "up", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "up",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const serviceArguments = services?.map((s) => shellQuote(s)).join(" ") ?? ""
        const suffix = serviceArguments === "" ? "" : ` ${serviceArguments}`
        // R-0000078: redirect stderr to stdout so the action keywords that
        // compose prints on stderr ("Creating", "Recreating", "Starting",
        // "Started", "Pulling") are observable, mirroring compose.pull's
        // approach.
        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} up -d${suffix} 2>&1`,
          EXEC_OPTS
        )
        if (result.code !== 0) {
          return failedCommand(`[compose.up] failed for ${projectDirectory}`, result)
        }

        return { status: composeUpReportedChange(result.stdout) ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const serviceFilter = services?.map((s) => shellQuote(s)).join(" ") ?? ""
        const filterSuffix = serviceFilter === "" ? "" : ` ${serviceFilter}`
        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} ps --format json${filterSuffix}`,
          EXEC_OPTS
        )
        if (result.code !== 0) return NEEDS_APPLY

        const stdout = result.stdout.trim()
        if (stdout === "") return NEEDS_APPLY

        const states = parseContainerStates(stdout)
        if (states.length === 0) return NEEDS_APPLY

        return states.every((s) => s === "running") ? "ok" : NEEDS_APPLY
      },
      name: `compose.up: ${projectDirectory}`,
    }
  },
}
