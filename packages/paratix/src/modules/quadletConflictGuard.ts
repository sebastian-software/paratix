import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

/**
 * Compose project labels that identify a container as owned by a Compose
 * deployment rather than by a Quadlet unit.
 *
 * This project's own `compose` module drives `docker compose` or
 * `podman compose` (see `compose.ts`), and both set one of these labels, so a
 * stack previously deployed through it is detected during a Compose-to-Quadlet
 * migration. The list is a *positive* signal only: an unknown or renamed label
 * merely means the guard stays quiet, never that it misfires.
 */
const COMPOSE_PROJECT_LABELS = ["com.docker.compose.project", "io.podman.compose.project"] as const

/** Environment variable systemd-started containers carry, holding `%n`. */
const SYSTEMD_UNIT_ENVIRONMENT_KEY = "PODMAN_SYSTEMD_UNIT"

const SERVICE_UNIT_SUFFIX = ".service"

/**
 * Separator between the label block and the environment block of the inspect
 * projection. Chosen so it cannot occur inside a label or environment value.
 */
const INSPECT_SECTION_SEPARATOR = "@@PARATIX-ENV@@"

const QUADLET_CONFLICT_INSPECT_FORMAT =
  `{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{"\\n"}}{{end}}` +
  `${INSPECT_SECTION_SEPARATOR}{{"\\n"}}` +
  `{{range .Config.Env}}{{.}}{{"\\n"}}{{end}}`

/** A foreign owner discovered on an existing container. */
export type QuadletContainerConflict = {
  /** Metadata key that proved foreign ownership. */
  marker: string
  /** Value of that key, safe to display (project name or unit name). */
  value: string
}

/**
 * Resolve the container name a Quadlet unit manages.
 *
 * Quadlet names the container `systemd-<quadlet name>` unless `ContainerName=`
 * overrides it, so the guard has to mirror that default rather than assume the
 * unit name.
 *
 * @param options - Container-name inputs.
 * @param options.containerName - Explicit container name, if configured.
 * @param options.name - Quadlet unit name.
 * @returns The container name to inspect.
 */
export function resolveQuadletContainerName(options: {
  containerName?: string
  name: string
}): string {
  return options.containerName ?? `systemd-${options.name}`
}

/**
 * Build the inspect projection that reveals a container's ownership metadata.
 *
 * @param containerName - Container to inspect.
 * @returns The `podman container inspect` command string.
 */
export function buildQuadletConflictInspectCommand(containerName: string): string {
  return `podman container inspect --format ${shellQuote(QUADLET_CONFLICT_INSPECT_FORMAT)} -- ${shellQuote(containerName)}`
}

/**
 * Normalize a unit name so `web` and `web.service` compare equal.
 *
 * @param unit - Unit name with or without the `.service` suffix.
 * @returns The suffixed form.
 */
function normalizeUnitName(unit: string): string {
  const trimmed = unit.trim()
  return trimmed.endsWith(SERVICE_UNIT_SUFFIX) ? trimmed : `${trimmed}${SERVICE_UNIT_SUFFIX}`
}

function splitInspectSections(stdout: string): { environment: string[]; labels: string[] } {
  const lines = stdout.split("\n")
  const separatorIndex = lines.indexOf(INSPECT_SECTION_SEPARATOR)
  if (separatorIndex === -1) {
    // An unexpected projection yields no marker rather than a wrong verdict.
    return { environment: [], labels: [] }
  }
  return {
    environment: lines.slice(separatorIndex + 1).filter((line) => line.length > 0),
    labels: lines.slice(0, separatorIndex).filter((line) => line.length > 0),
  }
}

function readKeyValue(entry: string): { key: string; value: string } | null {
  const separatorIndex = entry.indexOf("=")
  if (separatorIndex <= 0) return null
  return { key: entry.slice(0, separatorIndex), value: entry.slice(separatorIndex + 1) }
}

function findComposeOwner(labels: string[]): null | QuadletContainerConflict {
  for (const entry of labels) {
    const parsed = readKeyValue(entry)
    if (parsed == null) continue
    if (
      COMPOSE_PROJECT_LABELS.some((label) => label === parsed.key) &&
      parsed.value.trim().length > 0
    ) {
      return { marker: parsed.key, value: parsed.value }
    }
  }
  return null
}

function findForeignUnitOwner(
  environment: string[],
  expectedUnit: string
): null | QuadletContainerConflict {
  const expected = normalizeUnitName(expectedUnit)
  for (const entry of environment) {
    const parsed = readKeyValue(entry)
    if (parsed?.key !== SYSTEMD_UNIT_ENVIRONMENT_KEY) continue
    const owner = parsed.value.trim()
    if (owner.length === 0) continue
    // `%n` expands to the full unit name, so both sides are normalized before
    // comparison. Without this the unit's *own* container would look foreign
    // and the guard would block the very apply it exists to permit.
    if (normalizeUnitName(owner) === expected) return null
    return { marker: SYSTEMD_UNIT_ENVIRONMENT_KEY, value: owner }
  }
  return null
}

/**
 * Detect whether a container of the target name is owned by something other
 * than the target Quadlet unit.
 *
 * The check reports a conflict only on **positive** evidence of foreign
 * ownership: a Compose project label, or a `PODMAN_SYSTEMD_UNIT` naming a
 * different unit. Absence of any marker — including a container that carries no
 * ownership metadata at all — is deliberately *not* treated as evidence, so the
 * guard cannot block an apply it does not understand. That asymmetry is the
 * point: a false positive here would fail every rollout, while a false negative
 * only falls back to the journal excerpt that `restartSystemdUnit` already
 * attaches to a failed restart.
 *
 * Structural metadata is used rather than Podman's error text, per the
 * convention behind `quadletPullOutputIndicatesChange` (R-0000183): the module
 * must not depend on locale-dependent podman output.
 *
 * @param ssh - Connection to the target host.
 * @param parameters - Detection inputs.
 * @param parameters.containerName - Container to inspect.
 * @param parameters.unit - Unit that should own the container.
 * @returns The foreign owner, or `null` when there is no conflict.
 */
export async function detectQuadletContainerConflict(
  ssh: SshConnection,
  parameters: { containerName: string; unit: string }
): Promise<null | QuadletContainerConflict> {
  const result = await ssh.exec(buildQuadletConflictInspectCommand(parameters.containerName), {
    ignoreExitCode: true,
    silent: true,
  })
  // A non-zero exit is the module's established "container absent" idiom. Any
  // other probe problem also lands here and must leave the apply unchanged.
  if (result.code !== 0) return null
  const { environment, labels } = splitInspectSections(result.stdout)
  return findComposeOwner(labels) ?? findForeignUnitOwner(environment, parameters.unit)
}

/**
 * Run the conflict guard and turn a detected conflict into a failed result.
 *
 * @param ssh - Connection to the target host.
 * @param parameters - Guard inputs.
 * @param parameters.containerName - Container to inspect.
 * @param parameters.moduleLabel - Module label used in the failure message.
 * @param parameters.unit - Unit that should own the container.
 * @returns A failed ModuleResult on conflict, otherwise `null`.
 */
export async function guardQuadletContainerConflict(
  ssh: SshConnection,
  parameters: { containerName: string; moduleLabel: string; unit: string }
): Promise<ModuleResult | null> {
  const conflict = await detectQuadletContainerConflict(ssh, {
    containerName: parameters.containerName,
    unit: parameters.unit,
  })
  if (conflict == null) return null
  return failed(
    `[${parameters.moduleLabel}] container '${parameters.containerName}' already exists and is not owned by unit '${parameters.unit}' (${conflict.marker}=${conflict.value}); ` +
      `podman cannot replace it. Remove it together with its dependents (podman rm --depend ${parameters.containerName}), then run systemctl reset-failed ${parameters.unit}`
  )
}
