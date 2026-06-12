import type { NormalizedSwapFileOptions } from "./swapFileTypes.js"

import { failed } from "../moduleFailure.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { normalizeSwapFileOptions } from "./swapFileHelpers.js"
import { applySwapFile, checkSwapFile } from "./swapHelpers.js"
import { sysctl } from "./sysctl.js"

const FSTAB_PATH = "/etc/fstab"

/**
 * Locate the current `/etc/fstab` entry whose first field matches `path`.
 * Skips blank and comment lines so a hand-edited fstab with banner comments
 * does not confuse the lookup. Returns the trimmed line or `null` when no
 * matching entry exists.
 *
 * @param fstabContent - Raw contents of `/etc/fstab`.
 * @param path - Absolute path to the swap file used as the entry key.
 * @returns The trimmed matching line, or `null` when no entry is present.
 */
function findFstabSwapEntry(fstabContent: string, path: string): null | string {
  for (const line of fstabContent.split("\n")) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const fields = trimmed.split(/\s+/v)
    if (fields[0] === path) return trimmed
  }
  return null
}

/**
 * Build the dry-run diff for a `swap.file` mutation by previewing the
 * `/etc/fstab` entry change. The diff is intentionally a small one- or
 * two-line block — the operator cares about whether the persistence entry
 * appears, disappears, or changes priority, not about the full fstab
 * surrounding it.
 *
 * @param ssh - The SSH connection.
 * @param options - The normalized `swap.file` options.
 * @returns A short diff block, or `undefined` when no diff can be produced.
 */
async function buildSwapFileDryRunDiff(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<string | undefined> {
  try {
    const fstabContent = await ssh.readFile(FSTAB_PATH)
    const currentLine = findFstabSwapEntry(fstabContent, options.path)
    if (options.state === "absent") {
      return currentLine === null ? undefined : `-${currentLine}`
    }
    const desired = options.expectedFstabLine ?? ""
    if (currentLine === desired) return undefined
    const lines: string[] = []
    if (currentLine !== null) lines.push(`-${currentLine}`)
    lines.push(`+${desired}`)
    return lines.join("\n")
  } catch {
    return undefined
  }
}

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
      async _applyDryRun(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "changed" }
        const diff = await buildSwapFileDryRunDiff(ssh, normalized)
        return diff == null ? { status: "changed" } : { diff, status: "changed" }
      },
      _dryRunDiffProducer: true,
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
