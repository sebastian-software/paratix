/* eslint-disable max-lines -- compose module intentionally keeps related lifecycle helpers together */
import { readFile } from "node:fs/promises"
import { basename } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const COMPOSE_CONFIG_MODE = "0600"
const SYSTEMD_UNIT_MODE = "0644"

// cspell:ignore podman
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
        const state = (entry).State
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

async function applyComposeSystemdUnit(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult> {
  await prepareComposeSystemdTarget(parameters)
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
    const fallbackFailure = await rewriteComposeSystemdUnitViaShell(parameters)
    if (fallbackFailure != null) return fallbackFailure
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

  const exists = await parameters.ssh.exists(parameters.filePath)
  if (!exists) return NEEDS_APPLY

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
  return remoteMode === SYSTEMD_UNIT_MODE.replace(/^0+/v, "") ? "ok" : NEEDS_APPLY
}

function resolveComposeSystemdIdentity(options: { name?: string; projectDirectory: string }): {
  filePath: string
  serviceName: string
  unitFileName: string
} {
  const serviceName = options.name ?? `compose-${basename(options.projectDirectory)}`
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
  await parameters.connection.exec(`systemctl unmask ${shellQuote(parameters.unitFileName)}`, {
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

    const exists = await ssh.exists(remotePath)
    if (!exists) return NEEDS_APPLY

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
 * Snapshot of a `compose.yml` captured before {@link compose.config} writes a
 * new revision. When validation of the new revision fails, the snapshot is
 * used to restore the previous state.
 */
type PriorComposeFile = { content: string; existed: true; mode: string } | { existed: false }

/**
 * Capture the existing `compose.yml` at `remotePath` so a failed validation
 * can restore it. When the file does not exist yet, the returned state allows
 * the rollback to remove the freshly written file instead.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param remotePath - Path to `compose.yml` on the remote host.
 * @returns A snapshot describing whether the file existed and its content/mode.
 */
async function capturePriorComposeFile(
  ssh: SshConnection,
  remotePath: string
): Promise<PriorComposeFile> {
  const existed = await ssh.exists(remotePath)
  if (!existed) return { existed: false }

  const content = await ssh.readFile(remotePath)
  const rawMode = await ssh.output(`stat -c '%a' ${shellQuote(remotePath)}`)
  const trimmedMode = rawMode.trim()
  const mode = trimmedMode === "" ? COMPOSE_CONFIG_MODE : trimmedMode
  return { content, existed: true, mode }
}

/**
 * Write the new compose.yml content from either `options.src` (uploaded) or
 * `options.content` (string). Caller has already verified that exactly one is
 * provided.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param remotePath - Destination path for the compose file.
 * @param options - Source/content options identical to {@link compose.config}.
 * @param options.content - Inline string content to write.
 * @param options.src - Local file path to upload.
 */
async function writeComposeFileForValidation(
  ssh: SshConnection,
  remotePath: string,
  options: { content?: string; src?: string }
): Promise<void> {
  if (options.src !== undefined && options.src !== "") {
    // Always pass an explicit { mode } to uploadFile so the resulting
    // compose.yml mode is independent of the uploadFile temp default.
    await ssh.uploadFile(options.src, remotePath, { mode: COMPOSE_CONFIG_MODE })
    return
  }
  if (options.content !== undefined && options.content !== "") {
    await ssh.writeFile(remotePath, options.content, { mode: COMPOSE_CONFIG_MODE })
  }
}

/**
 * Restore the prior `compose.yml` after a failed validation. When the file
 * did not exist before, remove the freshly-written file instead.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param remotePath - Path to the compose file.
 * @param prior - The snapshot captured before the new content was written.
 */
async function rollbackComposeFile(
  ssh: SshConnection,
  remotePath: string,
  prior: PriorComposeFile
): Promise<void> {
  if (prior.existed) {
    await ssh.writeFile(remotePath, prior.content, { mode: prior.mode })
    return
  }
  await ssh.exec(`rm -f ${shellQuote(remotePath)}`, EXEC_OPTS)
}

async function validateWrittenComposeFile(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { projectDirectory, runtime, ssh } = parameters
  const validate = await ssh.exec(
    `${composeCommand(runtime, projectDirectory)} config --quiet`,
    EXEC_OPTS
  )
  if (validate.code === 0) return null
  return failedCommand(`[compose.config] validation failed for ${projectDirectory}`, validate)
}

async function applyComposeConfig(parameters: {
  options: { content?: string; src?: string }
  projectDirectory: string
  remotePath: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, projectDirectory, remotePath, runtime, ssh } = parameters
  const priorState = await capturePriorComposeFile(ssh, remotePath)

  let rollbackPending = true
  try {
    await writeComposeFileForValidation(ssh, remotePath, options)
    const validationFailure = await validateWrittenComposeFile({ projectDirectory, runtime, ssh })
    if (validationFailure != null) {
      rollbackPending = false
      await rollbackComposeFile(ssh, remotePath, priorState)
      return validationFailure
    }
    rollbackPending = false
  } catch (error) {
    if (rollbackPending) await rollbackComposeFile(ssh, remotePath, priorState)
    throw error
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
        if (stdout === "") return "ok"
        const states = parseContainerStates(stdout)
        if (states.length === 0 && stdout === "[]") return "ok"

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
