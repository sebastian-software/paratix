import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const NAME_PATTERN = /^[\w.\-]+$/iv

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
    const remotePath = `/tmp/paratix-script-${name}`
    const flagPrefix = `script-${name}-`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        await ssh.uploadFile(localPath, remotePath)

        try {
          await ssh.exec(`chmod +x ${shellQuote(remotePath)}`, { silent: true })

          const cmd =
            scriptArguments != null && scriptArguments.length > 0
              ? `${shellQuote(remotePath)} ${scriptArguments.map((a) => shellQuote(a)).join(" ")}`
              : shellQuote(remotePath)
          const result = await ssh.exec(cmd, EXEC_OPTS)

          if (result.code !== 0) return { status: "failed" }

          await setVersionedFlag(ssh, flagName, flagPrefix)

          return { status: "changed" }
        } finally {
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
