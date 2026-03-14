import { readFileSync } from "node:fs"
import { basename } from "node:path"

import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// cspell:ignore podman
type ComposeRuntime = "docker" | "podman"

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
        const state = (entry as { State: unknown }).State
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

/**
 * Generate the content of a systemd service unit file that manages a compose
 * stack via `ExecStart` / `ExecStop`.
 *
 * The generated unit depends on `docker.service` when the runtime is `docker`,
 * and only on `network-online.target` for `podman`.
 *
 * @param projectDirectory - The working directory for the compose commands.
 * @param name - The human-readable service description and unit name.
 * @param runtime - The container runtime (`docker` or `podman`).
 * @returns The full systemd unit file content as a string.
 */
function generateSystemdUnit(
  projectDirectory: string,
  name: string,
  runtime: ComposeRuntime
): string {
  const safeName = sanitizeUnitValue(name)
  const safeDirectory = sanitizeUnitValue(projectDirectory)
  const lines = ["[Unit]", `Description=Compose stack: ${safeName}`]

  if (runtime === "docker") {
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
    `ExecStart=/usr/bin/env ${runtime} compose up -d`,
    `ExecStop=/usr/bin/env ${runtime} compose down`,
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    ""
  )

  return lines.join("\n")
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
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        if (options.src !== undefined && options.src !== "") {
          await ssh.uploadFile(options.src, remotePath)
        } else if (options.content !== undefined && options.content !== "") {
          await ssh.writeFile(remotePath, options.content)
        } else {
          return { status: "failed" }
        }

        const validate = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} config --quiet`,
          EXEC_OPTS
        )
        if (validate.code !== 0) return { status: "failed" }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const exists = await ssh.exists(remotePath)
        if (!exists) return NEEDS_APPLY

        let desiredContent: string
        if (options.src !== undefined && options.src !== "") {
          // eslint-disable-next-line security/detect-non-literal-fs-filename -- path from module config, not user input
          desiredContent = readFileSync(options.src, "utf8")
        } else if (options.content !== undefined && options.content !== "") {
          desiredContent = options.content
        } else {
          return NEEDS_APPLY
        }

        const remoteContent = await ssh.readFile(remotePath)
        return remoteContent.trim() === desiredContent.trim() ? "ok" : NEEDS_APPLY
      },
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
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        const volumesFlag = volumes === true ? " --volumes" : ""
        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} down${volumesFlag}`,
          EXEC_OPTS
        )
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} ps --format json`,
          EXEC_OPTS
        )
        if (result.code !== 0) return "ok"

        const stdout = result.stdout.trim()
        if (stdout === "") return "ok"

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
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} pull 2>&1`,
          EXEC_OPTS
        )
        if (result.code !== 0) return { status: "failed" }

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
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        const cmd = composeCommand(rt, projectDirectory)
        const result = await ssh.exec(`${cmd} down && ${cmd} up -d`, EXEC_OPTS)
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.name - Optional service name (without `.service` suffix).
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the systemd unit file is present and up-to-date.
   */
  systemd(options: { name?: string; projectDirectory: string; runtime?: ComposeRuntime }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options
    const serviceName = options.name ?? `compose-${basename(projectDirectory)}`
    const unitFileName = `${serviceName}.service`
    const filePath = `/etc/systemd/system/${unitFileName}`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        const content = generateSystemdUnit(projectDirectory, serviceName, rt)
        await ssh.writeFile(filePath, content)

        const result = await ssh.exec("systemctl daemon-reload", EXEC_OPTS)
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const exists = await ssh.exists(filePath)
        if (!exists) return NEEDS_APPLY

        const content = generateSystemdUnit(projectDirectory, serviceName, rt)
        const remoteContent = await ssh.readFile(filePath)
        return remoteContent.trim() === content.trim() ? "ok" : NEEDS_APPLY
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
        if (!ssh) return { status: "failed" }

        const rt = await getRuntime(ssh, explicitRuntime)
        if (!rt) return { status: "failed" }

        const serviceArguments = services?.map((s) => shellQuote(s)).join(" ") ?? ""
        const suffix = serviceArguments === "" ? "" : ` ${serviceArguments}`
        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} up -d${suffix}`,
          EXEC_OPTS
        )
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
