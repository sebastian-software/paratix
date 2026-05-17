import type { NormalizedSwapFileOptions } from "./swapFileTypes.js"

import { failed } from "../moduleFailure.js"
import { guardedWriteFile, type ModuleResult, type SshConnection } from "../types.js"
import { withMutexLock } from "./moduleHelpers.js"

const FSTAB_PATH = "/etc/fstab"
const FSTAB_MODE = "0644"
const FSTAB_FILE_MUTEX = "etc-fstab-mutex"

// R-0000495 / R-0000648: every read of `/etc/fstab` goes through the same
// process-scoped mutex that protects writes so concurrent runs never observe
// a partially written file, and the read itself is wrapped in try/catch so a
// failing readFile surfaces as a structured `failed` ModuleResult instead of
// crashing the module.

function findFstabEntry(fstabContent: string, path: string): null | string {
  for (const line of fstabContent.split("\n")) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const fields = trimmed.split(/\s+/v)
    if (fields[0] === path) return trimmed
  }
  return null
}

function upsertFstabEntry(fstabContent: string, path: string, newLine: string): string {
  const lines = fstabContent.split("\n")
  const index = lines.findIndex((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return false
    const fields = trimmed.split(/\s+/v)
    return fields[0] === path
  })

  if (index === -1) {
    while (lines.length > 0 && lines.at(-1)?.trim() === "") {
      lines.pop()
    }
    lines.push(newLine)
  } else {
    lines[index] = newLine
  }

  return `${lines.join("\n")}\n`
}

function removeFstabEntry(fstabContent: string, path: string): string {
  const lines = fstabContent.split("\n")
  const result = lines.filter((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return true
    const fields = trimmed.split(/\s+/v)
    return fields[0] !== path
  })
  return `${result.join("\n")}\n`
}

/**
 * Update `/etc/fstab` so the swap entry for `path` matches `desiredLine`.
 *
 * When `desiredLine` is `null` the entry is removed; otherwise it is upserted.
 * Writes go through `guardedWriteFile` so the on-disk file is replaced
 * atomically only when the precondition (current content) still holds.
 *
 * @param parameters - The desired entry, the swap path, and the SSH handle.
 * @param parameters.desiredLine - The new fstab line for the swap entry, or
 *   `null` to remove the entry entirely.
 * @param parameters.path - Absolute path of the swap file the entry refers to.
 * @param parameters.ssh - SSH connection used for the read-modify-write cycle.
 * @returns `true` when fstab was modified, `false` when it was already
 *   converged, or a `failed` `ModuleResult` when the write rejected.
 */
export async function ensureSwapFstabState(parameters: {
  desiredLine: null | string
  path: string
  ssh: SshConnection
}): Promise<boolean | ModuleResult> {
  try {
    return await withMutexLock(parameters.ssh, {
      lockName: FSTAB_FILE_MUTEX,
      async section() {
        const fstabContent = await parameters.ssh.readFile(FSTAB_PATH)
        const currentEntry = findFstabEntry(fstabContent, parameters.path)

        if (parameters.desiredLine == null) {
          if (currentEntry == null) return false
          const removedContent = removeFstabEntry(fstabContent, parameters.path)
          await guardedWriteFile(parameters.ssh, {
            mode: FSTAB_MODE,
            newContent: removedContent,
            originalContent: fstabContent,
            remotePath: FSTAB_PATH,
          })
          return true
        }

        if (currentEntry === parameters.desiredLine) return false
        const updatedContent = upsertFstabEntry(
          fstabContent,
          parameters.path,
          parameters.desiredLine
        )
        await guardedWriteFile(parameters.ssh, {
          mode: FSTAB_MODE,
          newContent: updatedContent,
          originalContent: fstabContent,
          remotePath: FSTAB_PATH,
        })
        return true
      },
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[swap.file: ${parameters.path}] failed to update ${FSTAB_PATH}: ${reason}`)
  }
}

// R-0000495: read /etc/fstab under the same mutex that protects writes so
// concurrent runs never observe a partially written file.
// R-0000648: surface read failures as a structured ModuleResult instead of
// letting the underlying `ssh.readFile` reject. The withMutexLock wrapper
// still owns lock acquisition/release; only the inner readFile is allowed
// to fail soft via try/catch so the lock is always released.
async function readFstabUnderLock(ssh: SshConnection): Promise<ModuleResult | string> {
  return withMutexLock(ssh, {
    lockName: FSTAB_FILE_MUTEX,
    async section() {
      try {
        return await ssh.readFile(FSTAB_PATH)
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error)
        return failed(`[swap.file] failed to read ${FSTAB_PATH}: ${reason}`)
      }
    },
  })
}

/**
 * Check whether `/etc/fstab` already carries the desired swap entry for
 * `options.path`.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param options - The normalized swap file options (carries the expected line).
 * @returns `true` when the entry matches, `false` when it does not, or a
 *   structured failure when the fstab read fails.
 */
export async function hasSwapFstabEntry(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean | ModuleResult> {
  const fstab = await readFstabUnderLock(ssh)
  if (typeof fstab !== "string") return fstab
  return findFstabEntry(fstab, options.path) === options.expectedFstabLine
}

/**
 * Check whether `/etc/fstab` carries no entry for `path`.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param path - The swap path to look for.
 * @returns `true` when no entry references `path`, `false` when one exists,
 *   or a structured failure when the fstab read fails.
 */
export async function hasNoSwapFstabEntry(
  ssh: SshConnection,
  path: string
): Promise<boolean | ModuleResult> {
  const fstab = await readFstabUnderLock(ssh)
  if (typeof fstab !== "string") return fstab
  return findFstabEntry(fstab, path) == null
}
