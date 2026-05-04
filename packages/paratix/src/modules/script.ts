import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const NAME_PATTERN = /^[\w.\-]+$/iv

/**
 * Allocate a per-run remote path under `/tmp` via `mktemp` so two parallel
 * applies of the same script cannot race on the same legacy deterministic
 * path. Returns either the allocated path or a failure `ModuleResult`.
 *
 * @param ssh - Active SSH connection.
 * @param name - The script name; embedded in the mktemp template.
 * @returns The allocated remote path, or a failure result when mktemp
 *   exited non-zero or returned an empty path.
 */
async function allocateRemoteScriptPath(
  ssh: SshConnection,
  name: string
): Promise<ModuleResult | string> {
  const template = `paratix-script-${name}.XXXXXX`
  const mktempResult = await ssh.exec(`mktemp -p /tmp ${shellQuote(template)}`, EXEC_OPTS)
  if (mktempResult.code !== 0) {
    return failedCommand(`[script.once: ${name}] mktemp failed`, mktempResult)
  }
  const remotePath = mktempResult.stdout.trim()
  if (remotePath.length === 0) {
    return failed(`[script.once: ${name}] mktemp returned an empty path`)
  }
  try {
    return validateMktempPath("/tmp", remotePath, `paratix-script-${name}`)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[script.once: ${name}] mktemp returned an unsafe path: ${reason}`)
  }
}

/**
 * Modules for executing scripts on the remote host.
 */
export const script = {
  /**
   * Upload and run a local script on the remote host exactly once.
   * Idempotency is tracked via a versioned flag file; bumping the version
   * causes the script to run again.
   *
   * @param name - A unique identifier for this script execution (alphanumeric, dots, hyphens, underscores).
   * @param localPath - Path to the script on the local filesystem.
   * @param options - Optional settings.
   * @param options.args - Arguments to pass to the script (each element is shell-quoted).
   * @param options.version - Version string for the flag file (default: `"1"`).
   * @returns A Module that manages the one-time script execution.
   */
  once(name: string, localPath: string, options?: { args?: string[]; version?: string }): Module {
    if (!NAME_PATTERN.test(name)) {
      throw new Error(`script.once: name must match ${String(NAME_PATTERN)}, got: ${name}`)
    }

    const version = options?.version ?? "1"
    const scriptArguments = options?.args
    const flagName = `script-${name}-${version}`
    const flagPrefix = `script-${name}-`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[script.once: ${name}] SSH connection is required`)

        // R-0000050: create a per-run remote path via `mktemp` so two
        // concurrent applies of the same script (e.g. parallel runs
        // against the same host fleet) cannot race on the same
        // `/tmp/paratix-script-<name>` file.
        const allocation = await allocateRemoteScriptPath(ssh, name)
        if (typeof allocation !== "string") return allocation
        const remotePath = allocation

        await ssh.uploadFile(localPath, remotePath)

        try {
          await ssh.exec(`chmod +x ${shellQuote(remotePath)}`, { silent: true })

          const cmd =
            scriptArguments != null && scriptArguments.length > 0
              ? `${shellQuote(remotePath)} ${scriptArguments.map((a) => shellQuote(a)).join(" ")}`
              : shellQuote(remotePath)
          const result = await ssh.exec(cmd, EXEC_OPTS)

          if (result.code !== 0) {
            return failedCommand(`[script.once: ${name}] script execution failed`, result)
          }

          await setVersionedFlag(ssh, flagName, flagPrefix)

          return { status: "changed" }
        } finally {
          // The finally block now removes the per-run path created via
          // mktemp above, never the deterministic legacy path.
          await ssh.exec(`rm -f ${shellQuote(remotePath)}`, { silent: true })
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `script.once: ${name} (v${version})`,
    }
  },
}
