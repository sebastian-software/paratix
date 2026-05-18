import { statSync } from "node:fs"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { applyWithFlagLock, hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const NAME_PATTERN = /^[\w.\-]+$/iv

// R-0000717: cap the number of CLI arguments and the length of any single
// argument that `script.once` forwards to the remote process. The remote
// command line is built by joining `shellQuote`-d arguments with spaces,
// so unbounded counts or sizes would let a misconfigured playbook produce
// command lines that exceed kernel `ARG_MAX` on the target host and fail
// with a confusing "Argument list too long" error at execution time. Reject
// such inputs at module-construction time so the playbook author sees the
// problem up-front instead of mid-apply.
const SCRIPT_ARGS_MAX_COUNT = 1024
const SCRIPT_ARG_MAX_LENGTH = 4096

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
  // R-0000565: separate the template from the option list with `--` so a
  // future refactor that loosens the name validation cannot let the template
  // be interpreted as a `mktemp` option.
  const mktempResult = await ssh.exec(`mktemp -p /tmp -- ${shellQuote(template)}`, EXEC_OPTS)
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
 * Run a script.once apply payload: mktemp + upload + chmod + execute + flag.
 * Extracted out of the closure inside `script.once` to keep statement counts
 * inside lint limits while preserving the original failure semantics.
 *
 * @param parameters - The script execution parameters.
 * @param parameters.flagName - Versioned flag file name written on success.
 * @param parameters.flagPrefix - Flag prefix used to evict older versions.
 * @param parameters.localPath - Local path of the script to upload.
 * @param parameters.name - Logical script identifier (used in error messages).
 * @param parameters.scriptArguments - Optional CLI arguments passed to the script.
 * @param parameters.ssh - The active SSH connection.
 * @returns The module result for the apply operation.
 */
async function runScriptOnce(parameters: {
  flagName: string
  flagPrefix: string
  localPath: string
  name: string
  scriptArguments: string[] | undefined
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { flagName, flagPrefix, localPath, name, scriptArguments, ssh } = parameters
  // R-0000050: create a per-run remote path via `mktemp` so two
  // concurrent applies of the same script (e.g. parallel runs
  // against the same host fleet) cannot race on the same
  // `/tmp/paratix-script-<name>` file.
  const allocation = await allocateRemoteScriptPath(ssh, name)
  if (typeof allocation !== "string") return allocation
  const remotePath = allocation

  try {
    try {
      await ssh.uploadFile(localPath, remotePath)
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      return failed(`[script.once: ${name}] upload failed: ${reason}`)
    }
    return await runScriptOnceBody({
      flagName,
      flagPrefix,
      name,
      remotePath,
      scriptArguments,
      ssh,
    })
  } finally {
    // The finally block now removes the per-run path created via
    // mktemp above, never the deterministic legacy path. `ignoreExitCode`
    // mirrors the cleanup-rm convention used in quadlet/swap*Helpers/timer:
    // a non-zero `rm -f` (e.g. /tmp briefly read-only, SFTP transport blip)
    // must not overwrite the structured ModuleResult of a successful run.
    // R-0000565: pass `--` so the mktemp-allocated path cannot be parsed as
    // an `rm` option after a future refactor that loosens the name pattern.
    await ssh.exec(`rm -f -- ${shellQuote(remotePath)}`, { ignoreExitCode: true, silent: true })
  }
}

/**
 * Inner body of {@link runScriptOnce} after path allocation and upload.
 *
 * @param parameters - The chmod/execute/flag parameters.
 * @param parameters.flagName - Versioned flag file name written on success.
 * @param parameters.flagPrefix - Flag prefix used to evict older versions.
 * @param parameters.name - Logical script identifier (used in error messages).
 * @param parameters.remotePath - The mktemp-allocated remote path of the uploaded script.
 * @param parameters.scriptArguments - Optional CLI arguments passed to the script.
 * @param parameters.ssh - The active SSH connection.
 * @returns The module result for the apply operation.
 */
async function runScriptOnceBody(parameters: {
  flagName: string
  flagPrefix: string
  name: string
  remotePath: string
  scriptArguments: string[] | undefined
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { flagName, flagPrefix, name, remotePath, scriptArguments, ssh } = parameters
  // R-0000248: surface chmod failures as a structured `failedCommand`
  // ModuleResult instead of letting `conn.exec` throw. Without
  // `ignoreExitCode: true` a non-zero exit (e.g. chmod refused on a
  // noexec mount or stripped of write rights) would leak as an
  // unstructured SSH error.
  const chmodResult = await ssh.exec(`chmod +x ${shellQuote(remotePath)}`, EXEC_OPTS)
  if (chmodResult.code !== 0) {
    return failedCommand(`[script.once: ${name}] chmod failed`, chmodResult)
  }

  const cmd =
    scriptArguments != null && scriptArguments.length > 0
      ? `${shellQuote(remotePath)} ${scriptArguments.map((a) => shellQuote(a)).join(" ")}`
      : shellQuote(remotePath)
  const result = await ssh.exec(cmd, EXEC_OPTS)

  if (result.code !== 0) {
    return failedCommand(`[script.once: ${name}] script execution failed`, result)
  }

  // R-0000273: setVersionedFlag now returns a typed `ModuleResult |
  // null` instead of throwing on EROFS/EPERM/ENOSPC. Surface the
  // failure through the standard failedCommand path so converged work
  // remains observable.
  const flagFailure = await setVersionedFlag(ssh, flagName, flagPrefix)
  if (flagFailure) return flagFailure

  return { status: "changed" }
}

/**
 * R-0000717: verify that `localPath` resolves to a regular file at module
 * construction time. The upload itself happens during apply via SFTP and
 * would surface a stat/open error from the remote side; surfacing the
 * problem at construction time gives the playbook author a clearer signal
 * (wrong path, accidentally pointing at a directory, dangling symlink, …)
 * before any host is touched.
 *
 * Symlinks are followed deliberately: the resolved target is what would be
 * uploaded by `uploadFile`. Symlinks dangling or pointing at a non-file are
 * rejected because `statSync` either throws (ENOENT/ELOOP) or returns a
 * stat without `isFile() === true`.
 *
 * @param name - The script name; embedded in the error message.
 * @param localPath - The local path that must point at a regular file.
 * @throws {Error} when the path does not exist or is not a regular file.
 */
function assertScriptLocalPathIsFile(name: string, localPath: string): void {
  let stats
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- playbook-controlled path; validated to refer to a regular file before upload
    stats = statSync(localPath)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(
      `script.once: ${name} cannot read local script ${JSON.stringify(localPath)}: ${reason}`,
      { cause: error }
    )
  }
  if (!stats.isFile()) {
    throw new Error(
      `script.once: ${name} expected a regular file at ${JSON.stringify(localPath)}, got a non-file entry`
    )
  }
}

/**
 * R-0000717: enforce a bounded list of CLI arguments. Both the count and
 * the per-argument length are capped so the assembled command line cannot
 * be silently inflated to a size that exceeds the kernel's `ARG_MAX`.
 *
 * @param name - The script name; embedded in the error message.
 * @param scriptArguments - The optional `args` array from the caller.
 * @throws {Error} when the array is too long or a single argument exceeds
 *   the per-argument byte cap.
 */
function assertScriptArgumentsWithinLimits(
  name: string,
  scriptArguments: string[] | undefined
): void {
  if (scriptArguments == null) return
  if (scriptArguments.length > SCRIPT_ARGS_MAX_COUNT) {
    throw new Error(
      `script.once: ${name} args must contain at most ${String(SCRIPT_ARGS_MAX_COUNT)} entries, got ${String(scriptArguments.length)}`
    )
  }
  for (const [index, argument] of scriptArguments.entries()) {
    if (argument.length > SCRIPT_ARG_MAX_LENGTH) {
      throw new Error(
        `script.once: ${name} args[${String(index)}] exceeds maximum length of ${String(SCRIPT_ARG_MAX_LENGTH)} characters, got ${String(argument.length)}`
      )
    }
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

    // R-0000717: validate the local script path and the argument list at
    // construction time so misconfigured playbooks fail fast instead of
    // failing mid-apply with opaque upload or "Argument list too long"
    // errors from the remote shell.
    assertScriptLocalPathIsFile(name, localPath)
    assertScriptArgumentsWithinLimits(name, options?.args)

    const version = options?.version ?? "1"
    const scriptArguments = options?.args
    const flagName = `script-${name}-${version}`
    const flagPrefix = `script-${name}-`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[script.once: ${name}] SSH connection is required`)

        return applyWithFlagLock(ssh, {
          async apply() {
            return runScriptOnce({
              flagName,
              flagPrefix,
              localPath,
              name,
              scriptArguments,
              ssh,
            })
          },
          flagName,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `script.once: ${name} (v${version})`,
    }
  },
}
