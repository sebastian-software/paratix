import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"
import {
  buildQuadletContainerLines,
  buildQuadletImagePullCommand,
  buildQuadletInstallSection,
  buildQuadletServiceLines,
  buildQuadletUnitSection,
  getQuadletContainerFilePath,
  getQuadletContainerServiceName,
  type QuadletContainerOptions,
  type QuadletImageUpdateOptions,
  quadletPullOutputIndicatesChange,
  renderQuadletSection,
  validateQuadletImageValue,
  validateQuadletName,
} from "./quadletHelpers.js"
import {
  buildQuadletImageInspectCommand,
  formatQuadletImageIdentifierDetail,
  readQuadletImageIdentifierFromInspectOutput,
} from "./quadletImageInspectHelpers.js"

const CONTAINERS_SYSTEMD_DIRECTORY_COMMAND = "mkdir -p '/etc/containers/systemd'"
const QUADLET_FILE_MODE = "0644"
const QUADLET_RELOAD_HASH_LENGTH = 16
const SYSTEMCTL = "systemctl"

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

function buildQuadletReloadFlag(
  name: string,
  content: string
): {
  flagName: string
  flagPrefix: string
} {
  const flagPrefix = `quadlet-container-${sha256String(name).slice(0, QUADLET_RELOAD_HASH_LENGTH)}-`
  return {
    flagName: `${flagPrefix}${sha256String(content).slice(0, QUADLET_RELOAD_HASH_LENGTH)}`,
    flagPrefix,
  }
}

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

type QuadletImageUpdateParameters = {
  image: string
  inspectCommand: string
  name: string
  pullCommand: string
  serviceName: string
  ssh: SshConnection
}

async function createQuadletDirectory(ssh: SshConnection): Promise<ExecResultLike> {
  return ssh.exec(CONTAINERS_SYSTEMD_DIRECTORY_COMMAND, {
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
  if (remoteContent.trim() !== parameters.content.trim()) return NEEDS_APPLY
  const modeResult = await parameters.ssh.exec(`stat -c '%a' ${shellQuote(parameters.filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (modeResult.code !== 0) return NEEDS_APPLY
  const currentMode = modeResult.stdout.trim()
  if (currentMode === "") return NEEDS_APPLY
  return normalizeMode(currentMode) === normalizeMode(QUADLET_FILE_MODE) ? "ok" : NEEDS_APPLY
}

async function inspectQuadletImageId(parameters: {
  image: string
  inspectCommand: string
  name: string
  ssh: SshConnection
}): Promise<ModuleResult | string> {
  const inspectResult = await parameters.ssh.exec(parameters.inspectCommand, {
    ignoreExitCode: true,
    silent: true,
  })
  if (inspectResult.code !== 0) {
    return failedCommand(
      `[quadlet.updateImage: ${parameters.name}] podman image inspect failed`,
      inspectResult
    )
  }

  const imageId = readQuadletImageIdentifierFromInspectOutput(
    parameters.image,
    inspectResult.stdout
  )
  if (imageId == null) {
    return failed(
      `[quadlet.updateImage: ${parameters.name}] podman image inspect returned no digest or image ID`
    )
  }
  return imageId
}

async function restartQuadletService(parameters: {
  imageId: string
  name: string
  serviceName: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const restartResult = await parameters.ssh.exec(
    `${SYSTEMCTL} restart ${shellQuote(parameters.serviceName)}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  return restartResult.code === 0
    ? { detail: formatQuadletImageIdentifierDetail(parameters.imageId), status: "changed" }
    : failedCommand(
        `[quadlet.updateImage: ${parameters.name}] systemctl restart failed`,
        restartResult
      )
}

async function applyQuadletImageUpdate(
  parameters: QuadletImageUpdateParameters
): Promise<ModuleResult> {
  const pullResult = await parameters.ssh.exec(parameters.pullCommand, {
    ignoreExitCode: true,
    silent: true,
  })
  if (pullResult.code !== 0) {
    return failedCommand(`[quadlet.updateImage: ${parameters.name}] podman pull failed`, pullResult)
  }

  if (!quadletPullOutputIndicatesChange(pullResult.stdout)) {
    return { status: "ok" }
  }

  const imageId = await inspectQuadletImageId(parameters)
  if (typeof imageId !== "string") return imageId

  return restartQuadletService({
    imageId,
    name: parameters.name,
    serviceName: parameters.serviceName,
    ssh: parameters.ssh,
  })
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
    validateQuadletImageValue("image", options.image)
    const filePath = getQuadletContainerFilePath(options.name)
    const content = generateContainerQuadlet(options)
    const reloadFlag = buildQuadletReloadFlag(options.name, content)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.container: ${options.name}] SSH connection is required`)
        const result = await applyQuadletFile({ content, filePath, name: options.name, ssh })
        if (result.status !== "changed") return result
        await setVersionedFlag(ssh, reloadFlag.flagName, reloadFlag.flagPrefix)
        return result
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const fileResult = await checkQuadletFile({ content, filePath, ssh })
        if (fileResult !== "ok") return fileResult
        return (await hasFlag(ssh, reloadFlag.flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `quadlet.container: ${options.name}`,
    }
  },

  /**
   * Pull the latest image for a Quadlet-managed container and restart the service
   * only when the image changed.
   *
   * Accepts the same `name` and `image` fields as `quadlet.container(...)`, so a
   * shared config object can drive both deployment and targeted image refreshes.
   *
   * @param options - Image pull and restart configuration for the Quadlet service.
   * @returns A Module that updates the image and conditionally restarts the service.
   */
  updateImage(options: QuadletImageUpdateOptions): Module {
    validateQuadletName(options.name)
    if (options.serviceName != null) validateQuadletName(options.serviceName)
    validateQuadletImageValue("image", options.image)
    if (options.authFile != null) validateQuadletImageValue("authFile", options.authFile)

    const pullCommand = buildQuadletImagePullCommand(options)
    const inspectCommand = buildQuadletImageInspectCommand(options.image)
    const serviceName = getQuadletContainerServiceName(options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.updateImage: ${options.name}] SSH connection is required`)
        return applyQuadletImageUpdate({
          image: options.image,
          inspectCommand,
          name: options.name,
          pullCommand,
          serviceName,
          ssh,
        })
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Signal-style module
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: `quadlet.updateImage: ${options.name}`,
    }
  },
}
