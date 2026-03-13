import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"

import { shellQuote } from "../ssh.js"
import { renderTemplate } from "../template.js"
import {
  type Environment,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"

function localSha256(filePath: string): string {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = readFileSync(filePath)
  return createHash("sha256").update(content).digest("hex")
}

function sha256String(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
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
        if (!ssh) return { status: "failed" }
        await ssh.uploadFile(localPath, remotePath)

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

        const remoteHash = await ssh.sha256(remotePath)
        const localHash = localSha256(localPath)
        return remoteHash === localHash ? "ok" : NEEDS_APPLY
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
        if (!ssh) return { status: "failed" }
        await ssh.exec(`mkdir -p ${shellQuote(remotePath)}`, { silent: true })

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
        return (await ssh.test(`[ -d ${shellQuote(remotePath)} ]`)) ? "ok" : NEEDS_APPLY
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
        if (!ssh) return { status: "failed" }

        if (options?.match == null) {
          // Append line using printf to avoid shell interpretation
          await ssh.exec(`printf '%s\\n' ${shellQuote(line)} >> ${shellQuote(remotePath)}`, {
            silent: true,
          })
        } else {
          // Replace matching line with the new line
          const escaped = line.replaceAll("/", "\\/")
          const matchEscaped = options.match.replaceAll("/", "\\/")
          await ssh.exec(`sed -i 's/${matchEscaped}/${escaped}/' ${shellQuote(remotePath)}`, {
            silent: true,
          })
        }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        if (options?.match != null) {
          const hasMatch = await ssh.test(
            `grep -qE ${shellQuote(options.match)} ${shellQuote(remotePath)}`
          )
          if (!hasMatch) return NEEDS_APPLY
          // Check if the exact line already exists
          const exactLineExists = await ssh.test(
            `grep -qF ${shellQuote(line)} ${shellQuote(remotePath)}`
          )
          return exactLineExists ? "ok" : NEEDS_APPLY
        }

        const lineExists = await ssh.test(`grep -qF ${shellQuote(line)} ${shellQuote(remotePath)}`)
        return lineExists ? "ok" : NEEDS_APPLY
      },
      name: `file.line: ${remotePath}`,
    }
  },

  /**
   * Render a local template file with env values and write the result to the remote host.
   * Uses SHA-256 comparison of the rendered output to avoid unnecessary writes.
   *
   * @param remotePath - Destination path on the remote host.
   * @param templatePath - Path to the local template file containing `{{key}}` placeholders.
   * @param options - Optional file attributes.
   * @param options.mode - Optional chmod mode string.
   * @param options.owner - Optional chown owner string.
   * @returns A Module that renders and writes the template.
   */
  template(
    remotePath: string,
    templatePath: string,
    options?: { mode?: string; owner?: string }
  ): Module {
    return {
      async apply(ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        // eslint-disable-next-line security/detect-non-literal-fs-filename
        const templateContent = readFileSync(templatePath, "utf8")
        const rendered = await renderTemplate(templateContent, environment)
        await ssh.writeFile(remotePath, rendered)

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
      async check(
        ssh: null | SshConnection,
        environment: Environment
      ): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(remotePath)
        if (!exists) return NEEDS_APPLY

        // eslint-disable-next-line security/detect-non-literal-fs-filename
        const templateContent = readFileSync(templatePath, "utf8")
        const rendered = await renderTemplate(templateContent, environment)
        const localHash = sha256String(rendered)
        const remoteHash = await ssh.sha256(remotePath)
        return remoteHash === localHash ? "ok" : NEEDS_APPLY
      },
      name: `file.template: ${remotePath}`,
    }
  },
}
