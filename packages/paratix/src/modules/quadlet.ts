import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  buildQuadletContainerLines,
  buildQuadletInstallSection,
  buildQuadletServiceLines,
  buildQuadletUnitSection,
  type QuadletContainerOptions,
  renderQuadletSection,
  validateQuadletName,
} from "./quadletHelpers.js"

// cspell:ignore quadlet

const CONTAINERS_SYSTEMD_DIRECTORY = "/etc/containers/systemd"
const QUADLET_FILE_MODE = "0644"
const SYSTEMCTL = "systemctl"

function generateContainerQuadlet(options: QuadletContainerOptions): string {
  const serviceLines = buildQuadletServiceLines(options)
  const sections = [
    buildQuadletUnitSection(options),
    renderQuadletSection("Container", buildQuadletContainerLines(options)),
    ...(serviceLines.length > 0 ? [renderQuadletSection("Service", serviceLines)] : []),
    buildQuadletInstallSection(options),
  ]
  return sections.join("\n").trimEnd()
}

type ExecResultLike = Awaited<ReturnType<SshConnection["exec"]>>

async function createQuadletDirectory(ssh: SshConnection): Promise<ExecResultLike> {
  return ssh.exec(`mkdir -p ${shellQuote(CONTAINERS_SYSTEMD_DIRECTORY)}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

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
