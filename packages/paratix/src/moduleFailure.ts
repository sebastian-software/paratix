import type { ExecResult, ModuleResult } from "./types.js"

import { CommandError, maskSecrets } from "./sshHelpers.js"

/**
 * Return the first non-empty, trimmed line of `text`, or `null` when every
 * line is blank. Shared across the module layer so command-output summaries
 * (`failedCommand`, apt rollback diagnostics, …) pick their first meaningful
 * line identically.
 *
 * @param text - Multi-line command output to scan.
 * @returns The first non-empty trimmed line, or `null` when none exists.
 */
export function firstNonEmptyLine(text: string): null | string {
  for (const line of text.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.length > 0) return trimmed
  }
  return null
}

export function failed(message: string): ModuleResult {
  return { error: new Error(message), status: "failed" }
}

/**
 * Build a `failed` ModuleResult from an `ExecResult`. When `secrets` is
 * provided, every secret variant is masked in the rendered error message and
 * in the stored stdout/stderr so the hash, signed URL, or token never leaks
 * through `failedCommand`'s output. Callers that already pass `secrets` to
 * `ssh.exec` should forward the same list here so the failure path stays
 * symmetric with the success path.
 *
 * @param message - Human-readable summary of the failure context.
 * @param result - The non-zero `ExecResult` returned by `ssh.exec` (typically
 *   captured via `ignoreExitCode: true`).
 * @param secrets - Optional list of secret strings to mask in the rendered
 *   error message and the captured stdout/stderr.
 * @returns A failed ModuleResult whose error is a {@link CommandError}.
 */
export function failedCommand(
  message: string,
  result: ExecResult,
  secrets?: string[]
): ModuleResult {
  const stderr =
    secrets != null && secrets.length > 0 ? maskSecrets(result.stderr, secrets) : result.stderr
  const stdout =
    secrets != null && secrets.length > 0 ? maskSecrets(result.stdout, secrets) : result.stdout
  const detail = firstNonEmptyLine(stderr) ?? firstNonEmptyLine(stdout)
  const summary = `${message} (exit code ${String(result.code)})`
  const errorMessage = detail == null ? summary : `${summary}\n${detail}`
  return {
    error: new CommandError(errorMessage, stdout, stderr),
    status: "failed",
  }
}

export async function withRollbackFailure(
  failure: ModuleResult,
  rollback: () => Promise<void>,
  fallbackMessage = "operation failed"
): Promise<ModuleResult> {
  try {
    await rollback()
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`${failure.error?.message ?? fallbackMessage}\nrollback failed: ${reason}`)
  }
  return failure
}
