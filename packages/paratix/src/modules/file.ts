import { readFile } from "node:fs/promises"
import { posix } from "node:path"

import { failed } from "../moduleFailure.js"
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
import { assemble, block, properties, replace, stat } from "./fileExtra.js"
import { hexHashesEqual, localSha256, sha256String } from "./fileHelpers.js"

export type { BlockOptions } from "./fileExtra.js"

type FileOwnership = {
  group: string
  mode: string
  owner: string
}

async function readOwnership(ssh: SshConnection, remotePath: string): Promise<FileOwnership> {
  const raw = await ssh.output(`stat -c '%a %U %G' ${shellQuote(remotePath)}`)
  const [mode = "", owner = "", group = ""] = raw.trim().split(" ")
  return { group, mode, owner }
}

function ownershipMatches(
  current: FileOwnership,
  options?: { mode?: string; owner?: string }
): boolean {
  if (options?.mode != null && current.mode !== options.mode.replace(/^0+/v, "")) return false
  if (options?.owner == null) return true

  const expectsGroup = options.owner.includes(":")
  const [expectedOwner, expectedGroup = ""] = options.owner.split(":", 2)
  if (current.owner !== expectedOwner) return false
  if (expectsGroup && current.group !== expectedGroup) return false
  return true
}

function splitLines(content: string): string[] {
  return content.split(/\r?\n/v)
}

function validateAbsentPath(remotePath: string): void {
  const trimmedPath = remotePath.trim()
  if (trimmedPath.length === 0) {
    throw new Error("file.absent: remotePath must not be empty")
  }

  if (posix.normalize(trimmedPath) === "/") {
    throw new Error(`file.absent: refusing to remove destructive path: ${remotePath}`)
  }
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
        await ssh.exec(`rm -rf ${shellQuote(remotePath)}`, { silent: true })
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

  /**
   * Upload a local file to the remote host.
   * The file is only transferred when the remote SHA-256 differs from the local one.
   *
   * @param remotePath - Destination path on the remote host.
   * @param localPath - Source path on the local filesystem.
   * @param options - Optional file attributes.
   * @param options.mode - Optional chmod mode string (e.g. `"0644"`).
   * @param options.owner - Optional chown owner string (e.g. `"www-data:www-data"`).
   * @returns A Module that copies the file to the remote host.
   */
  copy(remotePath: string, localPath: string, options?: { mode?: string; owner?: string }): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.copy: ${remotePath}] SSH connection is required`)
        await ssh.uploadFile(localPath, remotePath)

        if (options?.mode != null) {
          validateMode(options.mode)
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

        const remoteHash = await ssh.sha256(remotePath)
        const localHash = await localSha256(localPath)
        if (!hexHashesEqual(remoteHash, localHash)) return NEEDS_APPLY

        const metadataMatches = ownershipMatches(await readOwnership(ssh, remotePath), options)
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[file.directory: ${remotePath}] SSH connection is required`)
        await ssh.exec(`mkdir -p ${shellQuote(remotePath)}`, { silent: true })

        if (options?.mode != null) {
          validateMode(options.mode)
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
          // Append line using printf to avoid shell interpretation
          await ssh.exec(`printf '%s\\n' ${shellQuote(line)} >> ${shellQuote(remotePath)}`, {
            silent: true,
          })
        } else {
          // Replace matching line with the new line (client-side to avoid sed escaping issues)
          const content = await ssh.readFile(remotePath)
          // eslint-disable-next-line security/detect-non-literal-regexp
          const pattern = new RegExp(options.match, "mu")
          if (!pattern.test(content)) {
            return failed(
              `[file.line: ${remotePath}] No line matching ${options.match} found for replacement`
            )
          }
          const newContent = content.replace(pattern, line)
          await guardedWriteFile(ssh, { newContent, originalContent: content, remotePath })
        }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(remotePath)
        const lines = splitLines(content)

        if (options?.match != null) {
          // eslint-disable-next-line security/detect-non-literal-regexp
          const matchPattern = new RegExp(options.match, "mu")
          const matchedLine = lines.find((candidateLine) => matchPattern.test(candidateLine))
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
        await ssh.writeFile(remotePath, rendered)

        if (options?.mode != null) {
          validateMode(options.mode)
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
