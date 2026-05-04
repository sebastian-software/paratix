import { readFile } from "node:fs/promises"
import { posix } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"
import { renderTemplate } from "../template.js"
import {
  type Environment,
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { applyDirectoryState } from "./fileDirectoryHelpers.js"
import { assemble, block, properties, replace, stat } from "./fileExtra.js"
import { hexHashesEqual, localSha256, sha256String } from "./fileHelpers.js"
import {
  applyFileMetadata,
  createMetadataModule,
  normalizeMode,
  ownershipMatches,
  readOwnership,
  resolveWriteMode,
} from "./fileMetadataHelpers.js"

export type { BlockOptions } from "./fileExtra.js"

/**
 * Default file mode applied by {@link file.copy} when the caller does not
 * specify `options.mode`. Both `apply` and `check` use this value, so
 * subsequent runs detect mode drift even on the implicit-default path.
 */
const FILE_COPY_DEFAULT_MODE = "0644"

function splitLines(content: string): string[] {
  return content.split(/\r?\n/v)
}

function findFirstMatchingLineIndex(lines: string[], pattern: RegExp): number {
  return lines.findIndex((candidateLine) => pattern.test(candidateLine))
}

function splitLinesPreservingTrailingNewline(content: string): {
  hasTrailingNewline: boolean
  lines: string[]
} {
  const hasTrailingNewline = /\r?\n$/v.test(content)
  const lines = splitLines(content)
  if (hasTrailingNewline && lines.at(-1) === "") lines.pop()
  return { hasTrailingNewline, lines }
}

function validateAbsentPath(remotePath: string): void {
  const trimmedPath = remotePath.trim()
  if (trimmedPath.length === 0) {
    throw new Error("file.absent: remotePath must not be empty")
  }

  if (!posix.isAbsolute(trimmedPath)) {
    throw new Error(`file.absent: remotePath must be an absolute path: ${remotePath}`)
  }

  if (posix.normalize(trimmedPath) === "/") {
    throw new Error(`file.absent: refusing to remove destructive path: ${remotePath}`)
  }
}

async function applyLineAppend(input: {
  line: string
  remotePath: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  // R-0000108: short-circuit when the line is already present so apply does
  // not append duplicates on direct invocation (e.g. from signal targets that
  // bypass check). Mirrors the no-op return pattern from R-0000075/77/81/88.
  const existsBeforeAppend = await input.ssh.exists(input.remotePath)
  if (existsBeforeAppend) {
    const existingContent = await input.ssh.readFile(input.remotePath)
    if (splitLines(existingContent).includes(input.line)) return { status: "ok" }
  }

  // Append line using printf to avoid shell interpretation
  await input.ssh.exec(
    `printf '%s\\n' ${shellQuote(input.line)} >> ${shellQuote(input.remotePath)}`,
    { silent: true }
  )
  return { status: "changed" }
}

async function applyLineReplace(input: {
  line: string
  match: string
  remotePath: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  // Replace the first matching full line (client-side to avoid sed escaping issues)
  const content = await input.ssh.readFile(input.remotePath)
  const { hasTrailingNewline, lines } = splitLinesPreservingTrailingNewline(content)
  // eslint-disable-next-line security/detect-non-literal-regexp
  const pattern = new RegExp(input.match, "mu")
  const matchingLineIndex = findFirstMatchingLineIndex(lines, pattern)
  if (matchingLineIndex === -1) {
    return failed(
      `[file.line: ${input.remotePath}] No line matching ${input.match} found for replacement`
    )
  }
  if (lines[matchingLineIndex] === input.line) return { status: "ok" }
  lines[matchingLineIndex] = input.line
  let newContent = lines.join("\n")
  if (hasTrailingNewline) newContent += "\n"
  const ownership = await readOwnership(input.ssh, input.remotePath)
  await guardedWriteFile(input.ssh, {
    mode: normalizeMode(ownership.mode),
    newContent,
    originalContent: content,
    remotePath: input.remotePath,
  })
  return { status: "changed" }
}

async function templateStateMatches(input: {
  options?: { mode?: string; owner?: string }
  remotePath: string
  rendered: string
  ssh: SshConnection
}): Promise<boolean> {
  const remoteHash = await input.ssh.sha256(input.remotePath)
  const localHash = sha256String(input.rendered)
  if (!hexHashesEqual(remoteHash, localHash)) return false

  return ownershipMatches(await readOwnership(input.ssh, input.remotePath), input.options)
}

/**
 * Modules for managing remote files and directories.
 *
 * Idempotency is enforced via SHA-256 checksums for file content and
 * existence checks for directories and individual lines.
 */
export const file = {
  /**
   * Ensure a remote path does not exist, removing it recursively if present.
   *
   * @param remotePath - Path to remove on the remote host.
   * @returns A Module that ensures the path is absent.
   */
  absent(remotePath: string): Module {
    validateAbsentPath(remotePath)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.absent: ${remotePath}] SSH connection is required`)
        if (!(await ssh.exists(remotePath))) return { status: "ok" }

        const result = await ssh.exec(`rm -rf ${shellQuote(remotePath)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return failedCommand(`[file.absent: ${remotePath}] rm failed`, result)
        }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`[ -e ${shellQuote(remotePath)} ]`)) ? "needs-apply" : "ok"
      },
      name: `file.absent: ${remotePath}`,
    }
  },

  assemble,

  block,

  chmod(remotePath: string, mode: string): Module {
    return createMetadataModule("chmod", remotePath, mode)
  },

  chown(remotePath: string, owner: string): Module {
    return createMetadataModule("chown", remotePath, owner)
  },

  /**
   * Upload a local file to the remote host.
   * The file is only transferred when the remote SHA-256 differs from the local one.
   *
   * @param remotePath - Destination path on the remote host.
   * @param localPath - Source path on the local filesystem.
   * @param options - Optional file attributes.
   * @param options.mode - Optional chmod mode string (e.g. `"0644"`). When omitted,
   *   the file is created with the documented default {@link FILE_COPY_DEFAULT_MODE}
   *   (`"0644"`) instead of inheriting whatever default `ssh.uploadFile` happens
   *   to choose for its temp file.
   * @param options.owner - Optional chown owner string (e.g. `"www-data:www-data"`).
   * @returns A Module that copies the file to the remote host.
   */
  copy(remotePath: string, localPath: string, options?: { mode?: string; owner?: string }): Module {
    const desiredMode = options?.mode ?? FILE_COPY_DEFAULT_MODE
    validateMode(desiredMode)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.copy: ${remotePath}] SSH connection is required`)
        // Forward the resolved mode (caller-supplied or default 0644) so the
        // remote file's permissions are predictable regardless of the
        // ssh.uploadFile temp-mode default.
        await ssh.uploadFile(localPath, remotePath, { mode: desiredMode })

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

        const remoteHash = await ssh.sha256(remotePath)
        const localHash = await localSha256(localPath)
        if (!hexHashesEqual(remoteHash, localHash)) return NEEDS_APPLY

        // Always compare the remote mode against the resolved desired mode so
        // mode drift is detected even when the caller did not pass options.mode.
        const matchOptions = { ...options, mode: desiredMode }
        const metadataMatches = ownershipMatches(await readOwnership(ssh, remotePath), matchOptions)
        return metadataMatches ? "ok" : NEEDS_APPLY
      },
      name: `file.copy: ${remotePath}`,
    }
  },

  /**
   * Ensure a remote directory exists, creating it recursively if needed.
   *
   * @param remotePath - Path of the directory to create on the remote host.
   * @param options - Optional directory attributes.
   * @param options.mode - Optional chmod mode string.
   * @param options.owner - Optional chown owner string.
   * @returns A Module that ensures the directory exists.
   */
  directory(remotePath: string, options?: { mode?: string; owner?: string }): Module {
    if (options?.mode != null) validateMode(options.mode)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.directory: ${remotePath}] SSH connection is required`)
        return applyDirectoryState({ options, remotePath, ssh })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.test(`[ -d ${shellQuote(remotePath)} ]`)
        if (!exists) return NEEDS_APPLY

        const metadataMatches = ownershipMatches(await readOwnership(ssh, remotePath), options)
        return metadataMatches ? "ok" : NEEDS_APPLY
      },
      name: `file.directory: ${remotePath}`,
    }
  },

  /**
   * Ensure a specific line is present in a remote file.
   * When `options.match` is provided, the first line matching the regex is replaced
   * with the new `line` value instead of appending.
   *
   * @param remotePath - Path to the file on the remote host.
   * @param line - The exact line content to ensure is present.
   * @param options - Optional match configuration.
   * @param options.match - A regex pattern; when matched, the line is replaced rather than appended.
   * @returns A Module that ensures the line is present.
   */
  line(remotePath: string, line: string, options?: { match?: string }): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.line: ${remotePath}] SSH connection is required`)

        if (options?.match == null) {
          return applyLineAppend({ line, remotePath, ssh })
        }

        return applyLineReplace({ line, match: options.match, remotePath, ssh })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(remotePath)
        if (!exists) return NEEDS_APPLY

        const content = await ssh.readFile(remotePath)
        const lines = splitLines(content)

        if (options?.match != null) {
          // eslint-disable-next-line security/detect-non-literal-regexp
          const matchPattern = new RegExp(options.match, "mu")
          const matchedLineIndex = findFirstMatchingLineIndex(lines, matchPattern)
          const matchedLine = matchedLineIndex === -1 ? undefined : lines[matchedLineIndex]
          return matchedLine === line ? "ok" : NEEDS_APPLY
        }

        return lines.includes(line) ? "ok" : NEEDS_APPLY
      },
      name: `file.line: ${remotePath}`,
    }
  },

  properties,

  replace,

  stat,

  /**
   * Render a local template file with env values and write the result to the remote host.
   * Uses SHA-256 comparison of the rendered output to avoid unnecessary writes.
   *
   * @param remotePath - Destination path on the remote host.
   * @param templatePath - Path to the local template file containing `{{key}}` placeholders.
   * @param options - Optional file attributes.
   * @param options.mode - Optional chmod mode string.
   * @param options.owner - Optional chown owner string.
   * @param options.strict - When `true`, every template placeholder must use an explicit modifier.
   * @returns A Module that renders and writes the template.
   */
  template(
    remotePath: string,
    templatePath: string,
    options?: { mode?: string; owner?: string; strict?: boolean }
  ): Module {
    let cachedContent: string | undefined

    async function getTemplateContent(): Promise<string> {
      // eslint-disable-next-line security/detect-non-literal-fs-filename, require-atomic-updates -- single-threaded; runner calls check() then apply() sequentially
      cachedContent ??= await readFile(templatePath, "utf8")
      return cachedContent
    }

    return {
      async apply(ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.template: ${remotePath}] SSH connection is required`)

        const templateContent = await getTemplateContent()
        const rendered = await renderTemplate(templateContent, environment, {
          strict: options?.strict,
        })
        await ssh.writeFile(remotePath, rendered, {
          mode: await resolveWriteMode(ssh, remotePath, options?.mode),
        })
        await applyFileMetadata(ssh, remotePath, options)

        return { status: "changed" }
      },
      async check(
        ssh: null | SshConnection,
        environment: Environment
      ): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(remotePath)
        if (!exists) return NEEDS_APPLY

        const templateContent = await getTemplateContent()
        const rendered = await renderTemplate(templateContent, environment, {
          strict: options?.strict,
        })
        return (await templateStateMatches({ options, remotePath, rendered, ssh }))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `file.template: ${remotePath}`,
    }
  },
}
