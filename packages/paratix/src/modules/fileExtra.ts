import { readFileSync } from "node:fs"

import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { sha256String } from "./fileHelpers.js"

/** Index where the file-type field starts in `stat -c '%s %a %U %G %F %Y'` output. */
const STAT_TYPE_START_INDEX = 4

function concatFragments(fragments: string[]): string {
  return (
    fragments
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      .map((f) => readFileSync(f, "utf8"))
      .join("")
  )
}

type BlockMarkers = { begin: string; end: string; full: string }

function replaceBlock(text: string, markers: BlockMarkers): string {
  const lines = text.split("\n")
  const result: string[] = []
  let insideBlock = false
  for (const line of lines) {
    if (line.includes(markers.begin)) {
      result.push(markers.full)
      insideBlock = true
    } else if (insideBlock && line.includes(markers.end)) {
      insideBlock = false
    } else if (!insideBlock) {
      result.push(line)
    }
  }
  return result.join("\n")
}

function extractBlockContent(text: string, beginMarker: string, endMarker: string): string {
  const lines = text.split("\n")
  const blockLines: string[] = []
  let insideBlock = false
  for (const line of lines) {
    if (line.includes(beginMarker)) {
      insideBlock = true
    } else if (insideBlock && line.includes(endMarker)) {
      insideBlock = false
    } else if (insideBlock) {
      blockLines.push(line)
    }
  }
  return blockLines.join("\n")
}

/** Options for the {@link block} module. */
export type BlockOptions = {
  /** The desired content between the markers. */
  content: string
  /** Unique identifier for the managed block. Used in the marker comment lines. */
  name: string
  /** Comment prefix for the marker lines (default `"#"`). */
  prefix?: string
}

/**
 * Concatenate local fragment files and write the result to the remote host.
 * The file is only transferred when the remote SHA-256 differs from the
 * combined local fragments.
 *
 * @param remotePath - Destination path on the remote host.
 * @param fragments - Array of local file paths whose contents are concatenated.
 * @param options - Optional file attributes.
 * @param options.mode - Optional chmod mode string (e.g. `"0644"`).
 * @param options.owner - Optional chown owner string (e.g. `"www-data:www-data"`).
 * @returns A Module that assembles the fragments on the remote host.
 */
export function assemble(
  remotePath: string,
  fragments: string[],
  options?: { mode?: string; owner?: string }
): Module {
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }

      await ssh.writeFile(remotePath, concatFragments(fragments))

      if (options?.mode != null) {
        await ssh.exec(`chmod ${shellQuote(options.mode)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
      }
      if (options?.owner != null) {
        await ssh.exec(`chown ${shellQuote(options.owner)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
      }

      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const exists = await ssh.exists(remotePath)
      if (!exists) return NEEDS_APPLY

      const localHash = sha256String(concatFragments(fragments))
      const remoteHash = await ssh.sha256(remotePath)
      return remoteHash === localHash ? "ok" : NEEDS_APPLY
    },
    name: `file.assemble: ${remotePath}`,
  }
}

/**
 * Ensure a managed block of text is present in a remote file.
 * The block is delimited by marker comments of the form
 * `<prefix> BEGIN paratix: <name>` / `<prefix> END paratix: <name>`.
 * If the markers are not yet present, the block is appended to the file.
 * If the markers already exist, the content between them is replaced in place.
 *
 * @param remotePath - Path to the file on the remote host.
 * @param options - Block configuration.
 * @param options.content - The desired content between the begin and end markers.
 * @param options.name - Unique identifier for the managed block, used in the marker lines.
 * @param options.prefix - Comment prefix for the marker lines (default `"#"`).
 * @returns A Module that ensures the block is present with the correct content.
 */
export function block(remotePath: string, options: BlockOptions): Module {
  const prefix = options.prefix ?? "#"
  const beginMarker = `${prefix} BEGIN paratix: ${options.name}`
  const endMarker = `${prefix} END paratix: ${options.name}`

  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }

      const fullBlock = `${beginMarker}\n${options.content}\n${endMarker}`
      const exists = await ssh.exists(remotePath)

      if (exists) {
        const existing = await ssh.readFile(remotePath)
        const hasMarker = existing.includes(beginMarker)

        if (hasMarker) {
          const markers: BlockMarkers = { begin: beginMarker, end: endMarker, full: fullBlock }
          await ssh.writeFile(remotePath, replaceBlock(existing, markers))
        } else {
          const separator = existing.endsWith("\n") ? "" : "\n"
          await ssh.writeFile(remotePath, `${existing}${separator}${fullBlock}\n`)
        }
      } else {
        await ssh.writeFile(remotePath, `${fullBlock}\n`)
      }

      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY

      const hasMarker = await ssh.test(
        `grep -qF ${shellQuote(beginMarker)} ${shellQuote(remotePath)}`
      )
      if (!hasMarker) return NEEDS_APPLY

      const fileContent = await ssh.readFile(remotePath)
      const current = extractBlockContent(fileContent, beginMarker, endMarker)
      return current === options.content ? "ok" : NEEDS_APPLY
    },
    name: `file.block: ${remotePath} (${options.name})`,
  }
}

/**
 * Set file or directory ownership and permissions on the remote host.
 * Only the attributes specified in `options` are checked and applied.
 *
 * @param remotePath - Path to the file or directory on the remote host.
 * @param options - Attributes to enforce.
 * @param options.group - Optional group name.
 * @param options.mode - Optional chmod mode string (e.g. `"0644"`).
 * @param options.owner - Optional owner name.
 * @returns A Module that ensures the properties match.
 */
export function properties(
  remotePath: string,
  options: { group?: string; mode?: string; owner?: string }
): Module {
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }

      let changed = false

      if (options.mode != null) {
        await ssh.exec(`chmod ${shellQuote(options.mode)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
        changed = true
      }
      if (options.owner != null && options.group != null) {
        const ownerGroup = `${options.owner}:${options.group}`
        await ssh.exec(`chown ${shellQuote(ownerGroup)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
        changed = true
      } else if (options.owner != null) {
        await ssh.exec(`chown ${shellQuote(options.owner)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
        changed = true
      } else if (options.group != null) {
        // cspell:disable-next-line
        await ssh.exec(`chgrp ${shellQuote(options.group)} ${shellQuote(remotePath)}`, {
          silent: true,
        })
        changed = true
      }

      return { status: changed ? "changed" : "ok" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY

      const raw = await ssh.output(`stat -c '%a %U %G' ${shellQuote(remotePath)}`)
      const [mode, owner, group] = raw.trim().split(" ")

      if (options.mode != null && mode !== options.mode.replace(/^0+/v, "")) return NEEDS_APPLY
      if (options.owner != null && owner !== options.owner) return NEEDS_APPLY
      if (options.group != null && group !== options.group) return NEEDS_APPLY

      return "ok"
    },
    name: `file.properties: ${remotePath}`,
  }
}

/**
 * Replace all occurrences of a regex pattern in a remote file.
 * `check` uses `grep -E` to detect whether the pattern still exists in the file.
 * `apply` reads the file, performs the replacement in TypeScript and writes it back.
 *
 * @param remotePath - Path to the file on the remote host.
 * @param pattern - Extended regex pattern to match.
 * @param replacement - Replacement string.
 * @returns A Module that performs the substitution.
 */
export function replace(remotePath: string, pattern: string, replacement: string): Module {
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }

      const content = await ssh.readFile(remotePath)
      const updated = content.replaceAll(new RegExp(pattern, "gu"), replacement)
      await ssh.writeFile(remotePath, updated)

      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY

      const found = await ssh.test(`grep -qE ${shellQuote(pattern)} ${shellQuote(remotePath)}`)
      return found ? NEEDS_APPLY : "ok"
    },
    name: `file.replace: ${remotePath}`,
  }
}

/**
 * Read metadata about a remote file via `stat`.
 * This is a read-only module: `check` always reports `"needs-apply"` so the runner
 * invokes `apply`, which populates the result's `meta` map with the following keys:
 * - `file.stat.size` — file size in bytes
 * - `file.stat.mode` — octal permission bits (e.g. `"644"`)
 * - `file.stat.owner` — owning user name
 * - `file.stat.group` — owning group name
 * - `file.stat.type` — file type string (e.g. `"regular file"`, `"directory"`)
 * - `file.stat.mtime` — last modification time as a Unix timestamp string
 *
 * @param remotePath - Path to the file on the remote host.
 * @returns A Module that reads file metadata into `result.meta`.
 */
export function stat(remotePath: string): Module {
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return { status: "failed" }

      const raw = await ssh.output(`stat -c '%s %a %U %G %F %Y' ${shellQuote(remotePath)}`)
      const parts = raw.trim().split(" ")
      const [size, mode, owner, group] = parts
      const mtime = parts.at(-1)
      const type = parts.slice(STAT_TYPE_START_INDEX, -1).join(" ")

      return {
        meta: {
          "file.stat.group": group,
          "file.stat.mode": mode,
          "file.stat.mtime": mtime ?? "",
          "file.stat.owner": owner,
          "file.stat.size": size,
          "file.stat.type": type,
        },
        status: "ok",
      }
    },
    // eslint-disable-next-line @typescript-eslint/require-await
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: `file.stat: ${remotePath}`,
  }
}
