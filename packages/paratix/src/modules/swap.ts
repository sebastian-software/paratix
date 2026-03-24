import { failed } from "../moduleFailure.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { normalizeSwapFileOptions } from "./swapFileHelpers.js"
import { applySwapFile, checkSwapFile } from "./swapHelpers.js"
import { sysctl } from "./sysctl.js"

/**
 * Modules for managing swap files and common swap-related kernel tuning.
 */
export const swap = {
  /**
   * Ensure a file-backed swap area exists, is activated, and is persisted in `/etc/fstab`.
   *
   * @param options - Configuration for the swap file.
   * @param options.mode - File mode applied to the swap file. Defaults to `0600`.
   * @param options.path - Absolute path to the swap file, e.g. `/swapfile`.
   * @param options.priority - Optional swap priority written into the fstab entry.
   * @param options.size - Desired file size as bytes or a shell-friendly size string such as `2G`.
   * @param options.state - Whether the swap file should be `present` (default) or `absent`.
   * @returns A Module that manages the swap file lifecycle.
   */
  file(options: {
    mode?: string
    path: string
    priority?: number
    size: number | string
    state?: "absent" | "present"
  }): Module {
    const normalized = normalizeSwapFileOptions(options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[swap.file: ${normalized.path}] SSH connection is required`)
        return applySwapFile(ssh, normalized)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkSwapFile(ssh, normalized)
      },
      name:
        normalized.state === "present"
          ? `swap.file: ${normalized.path} (${normalized.sizeForCommand})`
          : `swap.file: absent ${normalized.path}`,
    }
  },

  /**
   * Persist `vm.swappiness`.
   *
   * @param value - Desired swappiness value.
   * @returns A Module that manages `vm.swappiness`.
   */
  swappiness(value: number): Module {
    return sysctl.set("vm.swappiness", String(value))
  },

  /**
   * Persist `vm.vfs_cache_pressure`.
   *
   * @param value - Desired VFS cache pressure value.
   * @returns A Module that manages `vm.vfs_cache_pressure`.
   */
  vfsCachePressure(value: number): Module {
    return sysctl.set("vm.vfs_cache_pressure", String(value))
  },
}
