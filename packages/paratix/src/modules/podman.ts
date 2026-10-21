import type { Module } from "../types.js"
import type { PodmanLoginOptions, PodmanOptions } from "./podmanHelpers.js"

import { failed } from "../moduleFailure.js"
import { NEEDS_APPLY } from "../types.js"
import { executePodman } from "./podmanContainer.js"
import { configuration, PodmanError, resolvePodmanCredentials } from "./podmanHelpers.js"

export type { PodmanLoginOptions, PodmanOptions } from "./podmanHelpers.js"

function createModule(
  registry: string,
  options: PodmanOptions,
  source?: PodmanLoginOptions
): Module {
  const config = configuration(registry, options, source)
  return {
    async apply(ssh, env) {
      if (!ssh) return failed("podman: SSH connection is required")
      try {
        const credentials = await resolvePodmanCredentials(config, env)
        const status = await executePodman(ssh, config, { credentials, mode: "apply" })
        return { status: status === "CHANGED" ? "changed" : "ok" }
      } catch (error) {
        return failed(
          error instanceof PodmanError ? error.message : "podman: completion is unknown"
        )
      }
    },
    async check(ssh, env) {
      if (!ssh) return NEEDS_APPLY
      const credentials = await resolvePodmanCredentials(config, env)
      const status = await executePodman(ssh, config, { credentials, mode: "check" })
      return status === "OK" ? "ok" : NEEDS_APPLY
    },
    name: `podman.${config.operation}`,
  }
}

/**
 * Persistent registry authentication on native Linux with effective-root execution.
 * Requires a preloaded digest-pinned helper; rootless and SELinux Enforcing are unsupported.
 */
export const podman = {
  /**
   * Maintain local credentials, replacing the complete direct entry when they change.
   * Preserves JSON values outside that entry; a matching check does not contact the registry.
   * Use the same explicit authFile for later image pulls. No automatic retry or rollback.
   * Secret values stay out of output; the username remains visible in host Podman argv.
   * @param options - Registry, exclusive credential sources and optional paths/image.
   * @returns A registry authentication module.
   */
  login(options: PodmanLoginOptions): Module {
    return createModule(options.registry, options, { ...options })
  },
  /**
   * Remove only the complete direct entry for this registry.
   * @param registry - Registry hostname with optional port.
   * @param options - Optional persistent auth path and pinned helper image.
   * @returns A registry logout module requiring no credentials.
   */
  logout(registry: string, options: PodmanOptions = {}): Module {
    return createModule(registry, options)
  },
}
