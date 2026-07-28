import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type Environment,
  type Module,
  type ModuleApplyOptions,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { buildUnifiedDiff } from "./diffHelpers.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"
import {
  guardQuadletContainerConflict,
  resolveQuadletContainerName,
} from "./quadletConflictGuard.js"
import { applyQuadletFile, checkQuadletFile } from "./quadletFileHelpers.js"
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
  renderQuadletSection,
} from "./quadletHelpers.js"
import { buildQuadletImageInspectCommand } from "./quadletImageInspectHelpers.js"
import { applyQuadletImageUpdate } from "./quadletImageUpdateFlow.js"
import {
  generateNetworkQuadlet,
  getQuadletNetworkFilePath,
  type QuadletNetworkOptions,
} from "./quadletNetworkHelpers.js"
import {
  validateQuadletAuthFilePath,
  validateQuadletImageValue,
  validateQuadletName,
} from "./quadletValidationHelpers.js"

const QUADLET_RELOAD_HASH_LENGTH = 16

function buildQuadletReloadFlag(
  kind: string,
  name: string,
  content: string
): {
  flagName: string
  flagPrefix: string
} {
  const flagPrefix = `quadlet-${kind}-${sha256String(name).slice(0, QUADLET_RELOAD_HASH_LENGTH)}-`
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

/**
 * Build the dry-run diff for a Quadlet unit mutation (`.container` or
 * `.network`) by comparing the remote unit file against the desired content.
 * Returns `undefined` when either side cannot be read (missing file is treated
 * as empty, but a permission error returns `undefined` so the caller falls
 * back to the generic `(dry-run)` suffix without leaking diagnostics).
 *
 * @param ssh - The SSH connection.
 * @param filePath - Absolute path of the Quadlet unit file on the remote host.
 * @param desired - The desired Quadlet unit content.
 * @returns The unified-diff text, or `undefined` when no diff can be produced.
 */
async function buildQuadletDryRunDiff(
  ssh: SshConnection,
  filePath: string,
  desired: string
): Promise<string | undefined> {
  try {
    const exists = await ssh.exists(filePath)
    const current = exists ? await ssh.readFile(filePath) : ""
    const currentLabel = exists ? filePath : `${filePath} (new file)`
    const diff = buildUnifiedDiff(current, desired, { currentLabel, desiredLabel: "desired" })
    return diff === "" ? undefined : diff
  } catch {
    return undefined
  }
}

/**
 * Read-only probe for whether a Podman network with the given name already
 * exists on the host. `podman network exists` exits 0 when present. Any
 * non-zero exit — including podman not being installed — is treated as
 * "not present / cannot determine" so callers simply omit the advisory hint
 * instead of failing the apply.
 *
 * @param ssh - The SSH connection.
 * @param name - The Podman network name (matches the unit's `NetworkName`).
 * @returns `true` only when the probe confirms the network exists.
 */
async function podmanNetworkExists(ssh: SshConnection, name: string): Promise<boolean> {
  const result = await ssh.exec(`podman network exists -- ${shellQuote(name)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
}

/**
 * Advisory hint emitted when a `quadlet.network` change lands but a network
 * with the same name is already live. Podman creates a network once; a
 * `daemon-reload` regenerates the unit but does not push changed
 * `Subnet`/`Gateway`/… onto the running network until it is removed.
 *
 * @param name - The Podman network name.
 * @returns The hint text for the module result detail.
 */
function quadletNetworkLiveHint(name: string): string {
  return `network '${name}' already exists; the running network is not recreated automatically — remove it to apply changed settings`
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
    const reloadFlag = buildQuadletReloadFlag("container", options.name, content)
    const containerName = resolveQuadletContainerName(options)
    const guardParameters = {
      containerName,
      moduleLabel: `quadlet.container: ${options.name}`,
      unit: options.name,
    }

    return {
      async _applyDryRun(
        ssh: null | SshConnection,
        _environment: Environment,
        applyOptions?: ModuleApplyOptions
      ): Promise<ModuleResult> {
        if (!ssh) return { status: "changed" }
        // `_dryRunBlocker` makes this hook run in every dry run, so the guard
        // reports a blocking conflict even without `--diff`.
        const conflict = await guardQuadletContainerConflict(ssh, guardParameters)
        if (conflict) return conflict
        // Diff production stays behind `--diff`, exactly as before the guard
        // existed: the marker above would otherwise add the diff round-trips
        // to every dry run.
        if (applyOptions?.diff === true) {
          const diff = await buildQuadletDryRunDiff(ssh, filePath, content)
          if (diff != null) return { diff, status: "changed" }
        }
        // R-0001023: the unit file content already converges, but `apply`
        // also persists a versioned reload flag that drives the next
        // `systemctl daemon-reload`. When that flag is missing the operator
        // would otherwise see no signal in `--dry-run` (without `--diff`)
        // even though apply would still trigger a reload. Surface that
        // pending side effect via `_dryRunDetail`. `hasFlag` is a read-only
        // probe (`[ -f .../flag ]`) and therefore safe in the dry-run path.
        const flagPresent = await hasFlag(ssh, reloadFlag.flagName)
        if (flagPresent) return { status: "changed" }
        return { _dryRunDetail: "(dry-run, daemon-reload pending)", status: "changed" }
      },
      // Run `_applyDryRun` in every dry run, not only under `--diff`: the guard
      // is a run blocker, and a conflict that only surfaces with `--diff` would
      // let a plain dry run look clean.
      _dryRunBlocker: true,
      _dryRunDiffProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.container: ${options.name}] SSH connection is required`)
        // Detect a foreign container before writing the unit, so a migration
        // learns about the blocker at definition time rather than at the first
        // activation through `service.enabled`.
        const conflict = await guardQuadletContainerConflict(ssh, guardParameters)
        if (conflict) return conflict
        const result = await applyQuadletFile({ content, filePath, name: options.name, ssh })
        if (result.status !== "changed") return result
        // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC)
        // through the failedCommand path; the helper no longer throws.
        const flagFailure = await setVersionedFlag(ssh, reloadFlag.flagName, reloadFlag.flagPrefix)
        if (flagFailure) return flagFailure
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
   * Write a Podman Quadlet `.network` definition and reload systemd when it changes.
   *
   * Mirrors {@link quadlet.container}: the unit is written atomically to
   * `/etc/containers/systemd/<name>.network`, symlinks are refused, and
   * `systemctl daemon-reload` runs when the content changes. Containers
   * reference the network via their existing `networks` option
   * (e.g. `networks: ["app.network"]`).
   *
   * When the change lands and a network with the same name is already live on
   * the host, the result carries an advisory detail: Podman does not recreate
   * a running network, so changed `subnet`/`gateway`/… only take effect after
   * the network is removed.
   *
   * @param options - Configuration for the Quadlet network definition.
   * @returns A Module that ensures the Quadlet `.network` file is present and up to date.
   */
  network(options: QuadletNetworkOptions): Module {
    validateQuadletName(options.name)
    const filePath = getQuadletNetworkFilePath(options.name)
    const content = generateNetworkQuadlet(options)
    const reloadFlag = buildQuadletReloadFlag("network", options.name, content)

    return {
      async _applyDryRun(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "changed" }
        const diff = await buildQuadletDryRunDiff(ssh, filePath, content)
        if (diff != null) {
          // Content actually changes: the live-network advisory is relevant
          // here (and only when a network of the same name is already live).
          const liveHint = (await podmanNetworkExists(ssh, options.name))
            ? quadletNetworkLiveHint(options.name)
            : undefined
          return liveHint == null
            ? { diff, status: "changed" }
            : { _dryRunDetail: liveHint, diff, status: "changed" }
        }
        // Content already converged; apply would only persist the reload flag
        // and re-run daemon-reload. No settings change, so no live-network
        // advisory — otherwise a flag-only re-apply would misleadingly tell the
        // operator to remove an unchanged network.
        const flagPresent = await hasFlag(ssh, reloadFlag.flagName)
        return flagPresent
          ? { status: "changed" }
          : { _dryRunDetail: "(dry-run, daemon-reload pending)", status: "changed" }
      },
      _dryRunDiffProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.network: ${options.name}] SSH connection is required`)
        // Capture whether the unit content actually changes *before* the write.
        // `applyQuadletFile` always writes and reports `changed` (so the reload
        // flag gets persisted), even on a flag-only re-apply of already-matching
        // content. The advisory must only fire on a genuine settings change.
        const contentChanges = (await buildQuadletDryRunDiff(ssh, filePath, content)) != null
        const result = await applyQuadletFile({
          content,
          filePath,
          label: "quadlet.network",
          name: options.name,
          ssh,
        })
        if (result.status !== "changed") return result
        const flagFailure = await setVersionedFlag(ssh, reloadFlag.flagName, reloadFlag.flagPrefix)
        if (flagFailure) return flagFailure
        // Advisory only: a real content change landed but a live network keeps
        // its old settings until it is removed.
        if (contentChanges && (await podmanNetworkExists(ssh, options.name))) {
          return { ...result, detail: quadletNetworkLiveHint(options.name) }
        }
        return result
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const fileResult = await checkQuadletFile({ content, filePath, ssh })
        if (fileResult !== "ok") return fileResult
        return (await hasFlag(ssh, reloadFlag.flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `quadlet.network: ${options.name}`,
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
    // R-0000537: `authFile` must point at a real on-disk credentials file;
    // use the strict validator that requires an absolute path and rejects
    // `..` traversal segments.
    if (options.authFile != null) validateQuadletAuthFilePath("authFile", options.authFile)

    const pullCommand = buildQuadletImagePullCommand(options)
    const inspectCommand = buildQuadletImageInspectCommand(options.image)
    const serviceName = getQuadletContainerServiceName(options)
    const containerName = resolveQuadletContainerName(options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[quadlet.updateImage: ${options.name}] SSH connection is required`)
        return applyQuadletImageUpdate({
          containerName,
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
