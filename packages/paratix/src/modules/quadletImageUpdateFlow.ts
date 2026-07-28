import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { guardQuadletContainerConflict } from "./quadletConflictGuard.js"
import { quadletPullOutputIndicatesChange } from "./quadletHelpers.js"
import {
  formatQuadletImageIdentifierDetail,
  readQuadletImageIdentifierFromInspectOutput,
} from "./quadletImageInspectHelpers.js"
import { restartSystemdUnit } from "./systemctlRestart.js"

export type QuadletImageUpdateParameters = {
  containerName: string
  image: string
  inspectCommand: string
  name: string
  pullCommand: string
  serviceName: string
  ssh: SshConnection
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
  const failure = await restartSystemdUnit({
    failureMessage: `[quadlet.updateImage: ${parameters.name}] systemctl restart failed`,
    ssh: parameters.ssh,
    unit: parameters.serviceName,
  })
  return (
    failure ?? {
      detail: formatQuadletImageIdentifierDetail(parameters.imageId),
      status: "changed",
    }
  )
}

async function inspectQuadletImageIdBeforePull(
  parameters: QuadletImageUpdateParameters
): Promise<null | string> {
  // Pre-pull lookup: if the image is not present locally, the inspect call
  // exits non-zero. Treat that as "no previous ID" and rely on the post-pull
  // inspect to materialise an ID. Uses the same identifier selection as
  // {@link inspectQuadletImageId} (digest preferred, image ID fallback) so a
  // direct comparison against the post-pull result is meaningful.
  const result = await parameters.ssh.exec(parameters.inspectCommand, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return null
  return readQuadletImageIdentifierFromInspectOutput(parameters.image, result.stdout)
}

export async function applyQuadletImageUpdate(
  parameters: QuadletImageUpdateParameters
): Promise<ModuleResult> {
  // Guard before the image comparison, not only before the restart: a conflict
  // with an unchanged image would otherwise return `ok` while a foreign
  // container is the one actually running — the state a re-run does not heal.
  const conflict = await guardQuadletContainerConflict(parameters.ssh, {
    containerName: parameters.containerName,
    moduleLabel: `quadlet.updateImage: ${parameters.name}`,
    unit: parameters.serviceName,
  })
  if (conflict) return conflict

  // R-0000183: capture the local image ID before pulling so we can detect a
  // changed image regardless of podman's locale-dependent stdout strings.
  const previousImageId = await inspectQuadletImageIdBeforePull(parameters)

  const pullResult = await parameters.ssh.exec(parameters.pullCommand, {
    ignoreExitCode: true,
    silent: true,
  })
  if (pullResult.code !== 0) {
    return failedCommand(`[quadlet.updateImage: ${parameters.name}] podman pull failed`, pullResult)
  }

  const imageId = await inspectQuadletImageId(parameters)
  if (typeof imageId !== "string") return imageId

  // Either: the image was missing entirely before (previousImageId === null)
  // — pull always changes the local state — or the post-pull ID differs from
  // the pre-pull ID. Falling back to the legacy output heuristic on a tie
  // catches the (rare) case where the inspect output cannot be compared but
  // the pull output indicates a transfer happened.
  const idChanged =
    previousImageId == null ||
    previousImageId !== imageId ||
    // R-0000569: stderr is now kept separate from stdout, so feed both
    // streams to the change heuristic. podman emits progress lines on
    // either channel depending on terminal detection.
    quadletPullOutputIndicatesChange(pullResult.stdout, pullResult.stderr)
  if (!idChanged) return { status: "ok" }

  return restartQuadletService({
    imageId,
    name: parameters.name,
    serviceName: parameters.serviceName,
    ssh: parameters.ssh,
  })
}
