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

/**
 * Maximum number of leading output lines carried in a failure message.
 *
 * A single line used to be the whole budget, which silently dropped the second
 * line of multi-line diagnostics -- systemd, for instance, puts the actionable
 * `See "journalctl -xeu <unit>"` hint on the line after its summary. Keep the
 * budget small so `--verbose` stays the place for the full output.
 */
const DETAIL_LINE_LIMIT = 3
/** Byte ceiling for the carried output lines, independent of the line limit. */
const DETAIL_BYTE_LIMIT = 600
/** Appended when the line or byte budget dropped part of the output. */
const DETAIL_TRUNCATION_MARKER = "… (output truncated)"

/**
 * Return the leading non-empty, trimmed lines of `text` within the line and
 * byte budget, or `null` when every line is blank.
 *
 * A first line that exceeds the byte budget on its own is truncated rather than
 * dropped: it carries the primary cause and is more useful cut short than
 * missing.
 *
 * @param text - Multi-line command output to summarize.
 * @returns The bounded detail block, or `null` when every line is blank.
 */
/**
 * Join the kept lines and flag that output was dropped.
 *
 * @param lines - The lines that fit inside the budget.
 * @returns The joined lines followed by the truncation marker.
 */
function withTruncationMarker(lines: string[]): string {
  return `${lines.join("\n")}\n${DETAIL_TRUNCATION_MARKER}`
}

function boundedOutputDetail(text: string): null | string {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  if (lines.length === 0) return null
  const [first] = lines
  if (first.length > DETAIL_BYTE_LIMIT) {
    return withTruncationMarker([first.slice(0, DETAIL_BYTE_LIMIT)])
  }

  const kept: string[] = []
  let remaining = DETAIL_BYTE_LIMIT
  for (const line of lines.slice(0, DETAIL_LINE_LIMIT)) {
    if (line.length > remaining) return withTruncationMarker(kept)
    kept.push(line)
    remaining -= line.length + 1
  }
  return kept.length < lines.length ? withTruncationMarker(kept) : kept.join("\n")
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
/**
 * Build a `failed` ModuleResult from an `ExecResult`.
 *
 * Delegates to {@link failedCommandWithDiagnostic} without an extra diagnostic
 * block; see there for the masking and budget rules.
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
  return failedCommandWithDiagnostic({ diagnostic: null, message, result, secrets })
}

/**
 * Build a `failed` ModuleResult from an `ExecResult`, appending an extra
 * diagnostic block after the command's own output lines.
 *
 * This is the single assembly point for command failure messages;
 * {@link failedCommand} delegates here without a diagnostic. Use it when the
 * failing command's own output does not name the cause and a follow-up probe
 * supplied it -- for example a journal excerpt for a failed `systemctl restart`,
 * where the actual container-engine error only exists in the journal.
 *
 * The diagnostic is expected to be pre-bounded by its producer. It is masked
 * with the same `secrets` list as stdout/stderr, so a caller that forwards its
 * secrets keeps the failure path symmetric with the success path.
 *
 * @param parameters - Failure inputs.
 * @param parameters.diagnostic - Pre-bounded extra diagnostic block, or `null`.
 * @param parameters.message - Human-readable summary of the failure context.
 * @param parameters.result - The non-zero `ExecResult` returned by `ssh.exec`.
 * @param parameters.secrets - Optional secret strings to mask in the rendered
 *   message, the diagnostic, and the captured stdout/stderr.
 * @returns A failed ModuleResult whose error is a {@link CommandError}.
 */
export function failedCommandWithDiagnostic(parameters: {
  diagnostic: null | string
  message: string
  result: ExecResult
  secrets?: string[]
}): ModuleResult {
  const { diagnostic, message, result, secrets } = parameters
  const mask = (text: string): string =>
    secrets != null && secrets.length > 0 ? maskSecrets(text, secrets) : text
  const stderr = mask(result.stderr)
  const stdout = mask(result.stdout)
  const detail = boundedOutputDetail(stderr) ?? boundedOutputDetail(stdout)
  const summary = `${message} (exit code ${String(result.code)})`
  const errorMessage = [summary, detail, diagnostic == null ? null : mask(diagnostic)]
    .filter((part) => part != null && part.length > 0)
    .join("\n")
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
