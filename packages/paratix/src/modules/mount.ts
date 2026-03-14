import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const FSTAB_PATH = "/etc/fstab"
// cspell:ignore fstype mountpoint noheadings noexec nosuid nodev tmpfs umount findmnt

/**
 * Build a single fstab line from the given mount parameters.
 *
 * @param entry - The mount entry fields.
 * @param entry.fstype - The filesystem type.
 * @param entry.opts - The mount options string.
 * @param entry.path - The mountpoint path.
 * @param entry.src - The device or virtual filesystem source.
 * @returns A formatted fstab line with dump and pass fields set to `0`.
 */
function buildFstabLine(entry: {
  fstype: string
  opts: string
  path: string
  src: string
}): string {
  return `${entry.src} ${entry.path} ${entry.fstype} ${entry.opts} 0 0`
}

/**
 * Check whether a given fstab line already exists in the fstab content.
 *
 * @param fstabContent - The full contents of `/etc/fstab`.
 * @param path - The mountpoint to search for.
 * @returns The matching fstab line, or `null` if no entry exists for this mountpoint.
 */
function findFstabEntry(fstabContent: string, path: string): null | string {
  const lines = fstabContent.split("\n")
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const fields = trimmed.split(/\s+/v)
    if (fields[1] === path) return trimmed
  }
  return null
}

/**
 * Replace or append a fstab entry for the given mountpoint.
 *
 * @param fstabContent - The current full contents of `/etc/fstab`.
 * @param path - The mountpoint to match against.
 * @param newLine - The new fstab line to insert or replace with.
 * @returns The updated fstab content.
 */
function upsertFstabEntry(fstabContent: string, path: string, newLine: string): string {
  const lines = fstabContent.split("\n")
  const index = lines.findIndex((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return false
    const fields = trimmed.split(/\s+/v)
    return fields[1] === path
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

/**
 * Remove the fstab entry for the given mountpoint.
 *
 * @param fstabContent - The current full contents of `/etc/fstab`.
 * @param path - The mountpoint whose entry should be removed.
 * @returns The updated fstab content with the entry removed.
 */
function removeFstabEntry(fstabContent: string, path: string): string {
  const lines = fstabContent.split("\n")
  const result = lines.filter((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return true
    const fields = trimmed.split(/\s+/v)
    return fields[1] !== path
  })
  return `${result.join("\n")}\n`
}

/**
 * Ensure the fstab entry for a mount matches the desired line.
 * Reads, compares, and writes back only when a change is needed.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param path - The mountpoint to match against.
 * @param desiredLine - The expected fstab line.
 * @returns `true` if the fstab was updated, `false` if it already matched.
 */
async function ensureFstabEntry(
  ssh: SshConnection,
  path: string,
  desiredLine: string
): Promise<boolean> {
  const fstabContent = await ssh.readFile(FSTAB_PATH)
  const existingEntry = findFstabEntry(fstabContent, path)
  if (existingEntry === desiredLine) return false
  const newContent = upsertFstabEntry(fstabContent, path, desiredLine)
  await ssh.writeFile(FSTAB_PATH, newContent)
  return true
}

/**
 * Modules for managing filesystem mounts and `/etc/fstab` entries on a remote host.
 */
export const mount = {
  /**
   * Ensure a mountpoint is not mounted. Optionally removes the `/etc/fstab` entry.
   *
   * The check phase verifies both whether the path is currently mounted and, when
   * `persist` is `true`, whether a corresponding fstab entry exists. The apply
   * phase always returns `"changed"` even if only one of the two conditions required
   * action.
   *
   * @param options - Configuration for unmounting.
   * @param options.path - The mountpoint to unmount.
   * @param options.persist - When `true` (default), also remove the fstab entry.
   * @returns A Module that ensures the mountpoint is absent.
   */
  absent(options: { path: string; persist?: boolean }): Module {
    const { path, persist = true } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        let changed = false

        const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
        if (isMounted) {
          const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
          if (umountResult.code !== 0) return { status: "failed" }
          changed = true
        }

        if (persist) {
          const fstabContent = await ssh.readFile(FSTAB_PATH)
          const entry = findFstabEntry(fstabContent, path)
          if (entry !== null) {
            const newContent = removeFstabEntry(fstabContent, path)
            await ssh.writeFile(FSTAB_PATH, newContent)
            changed = true
          }
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
        if (isMounted) return NEEDS_APPLY

        if (persist) {
          const fstabContent = await ssh.readFile(FSTAB_PATH)
          const entry = findFstabEntry(fstabContent, path)
          if (entry !== null) return NEEDS_APPLY
        }

        return "ok"
      },
      name: `mount.absent: ${path}`,
    }
  },

  /**
   * Ensure a filesystem is mounted at the given path. Creates the mountpoint
   * directory if it does not exist. Optionally persists the mount in `/etc/fstab`.
   *
   * The check phase verifies that the mountpoint is active (via `findmnt`) and,
   * when `persist` is `true`, that the fstab entry matches the desired line
   * exactly. It does **not** compare the currently mounted source, filesystem
   * type, or options against the desired values — a remount is only triggered
   * when the mountpoint is absent entirely.
   *
   * @param options - Configuration for the mount.
   * @param options.fstype - The filesystem type (e.g. `"ext4"`, `"tmpfs"`, `"nfs"`).
   * @param options.opts - Mount options string (e.g. `"noexec,nosuid,nodev,size=512m"`).
   * @param options.path - The mountpoint path.
   * @param options.persist - When `true` (default), add or update the fstab entry.
   * @param options.src - The device or virtual filesystem source (e.g. `"tmpfs"`, `"/dev/sdb1"`).
   * @returns A Module that ensures the filesystem is mounted.
   */
  present(options: {
    fstype: string
    opts: string
    path: string
    persist?: boolean
    src: string
  }): Module {
    const { fstype, opts, path, persist = true, src } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        let changed = false

        await ssh.exec(`mkdir -p ${shellQuote(path)}`, EXEC_OPTS)

        if (persist) {
          const desiredLine = buildFstabLine({ fstype, opts, path, src })
          if (await ensureFstabEntry(ssh, path, desiredLine)) changed = true
        }

        const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
        if (!isMounted) {
          const mountResult = await ssh.exec(
            `mount -t ${shellQuote(fstype)} -o ${shellQuote(opts)} ${shellQuote(src)} ${shellQuote(path)}`,
            EXEC_OPTS
          )
          if (mountResult.code !== 0) return { status: "failed" }
          changed = true
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const findmntResult = await ssh.exec(
          `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS ${shellQuote(path)}`,
          EXEC_OPTS
        )
        if (findmntResult.code !== 0) return NEEDS_APPLY

        if (persist) {
          const fstabContent = await ssh.readFile(FSTAB_PATH)
          const desiredLine = buildFstabLine({ fstype, opts, path, src })
          const existingEntry = findFstabEntry(fstabContent, path)
          if (existingEntry !== desiredLine) return NEEDS_APPLY
        }

        return "ok"
      },
      name: `mount.present: ${path}`,
    }
  },
}
