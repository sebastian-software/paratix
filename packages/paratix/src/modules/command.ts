import { failed, failedCommand } from "../moduleFailure.js"
import { maskSecrets } from "../sshHelpers.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

/**
 * Modules for running arbitrary shell commands on the remote host.
 */
export const command = {
  /**
   * Run an arbitrary shell command on the remote host.
   *
   * By default the module always applies (no idempotency). Provide `options.check`
   * with a shell expression that exits `0` when the desired state is already
   * present -- in that case the command is skipped.
   *
   * @param cmd - The shell command to execute.
   * @param options - Optional configuration for the command.
   * @param options.check - An optional shell expression used as the idempotency guard.
   *   If it exits `0`, the command is considered already done.
   * @param options.name - An optional display name shown in the run output.
   * @param options.secrets - Secret values that must be redacted from command output.
   * @returns A Module that executes the shell command.
   *
   * @example
   * command.shell("curl -fsSL https://example.com/install.sh | bash", {
   *   check: "which my-tool",
   *   name: "install my-tool",
   * })
   */
  shell(cmd: string, options?: { check?: string; name?: string; secrets?: string[] }): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const moduleName = options?.name ?? "command.shell"
        if (!ssh) return failed(`[${moduleName}] SSH connection is required`)
        const secrets = options?.secrets ?? []
        const result = await ssh.exec(cmd, {
          ignoreExitCode: true,
          secrets,
          silent: true,
        })
        if (result.code !== 0) {
          return failedCommand(`[${moduleName}] command failed`, {
            ...result,
            stderr: maskSecrets(result.stderr, secrets),
            stdout: maskSecrets(result.stdout, secrets),
          })
        }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        if (options?.check == null) return NEEDS_APPLY
        return (await ssh.test(options.check)) ? "ok" : NEEDS_APPLY
      },
      name: options?.name ?? "command.shell",
    }
  },
}
