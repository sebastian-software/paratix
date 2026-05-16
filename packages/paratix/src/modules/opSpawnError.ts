/**
 * R-0000589: error subclass that carries the captured stdout / stderr from a
 * failed `op` invocation so the resolve failure path can fold those buffers
 * into the `secrets` list passed to `maskSecrets`. Defense-in-depth: a
 * partial stdout (for example a half-printed secret value) that leaked into
 * a higher-level error message can then still be redacted.
 *
 * Extracted from `op.ts` to keep that module within the project max-lines
 * cap.
 */
export class OpSpawnError extends Error {
  public readonly opStderr: string
  public readonly opStdout: string

  public constructor(message: string, parameters: { stderr?: string; stdout?: string } = {}) {
    super(message)
    this.name = "OpSpawnError"
    this.opStderr = parameters.stderr ?? ""
    this.opStdout = parameters.stdout ?? ""
  }
}

/**
 * Split each captured stream into non-empty lines so a multi-line stdout
 * buffer contributes individual masking candidates without ever exposing the
 * full text as a single secret token.
 *
 * R-0000602: split on every line-ending variant (`\r\n`, lone `\n`, lone
 * `\r`) so a Windows-style CR-LF or a classic CR-only stream does not leave
 * stray `\r` bytes on the returned tokens. A trailing `\r` would slip past
 * the downstream `maskSecrets` comparison (which uses exact substring
 * matching) and effectively widen the masking blind spot.
 *
 * The returned strings are *masking candidates*, not literal secrets — they
 * may contain non-secret diagnostic chatter from the `op` CLI. Callers feed
 * them into `maskSecrets` so any value that happens to coincide with one of
 * these lines is redacted from user-visible error messages.
 *
 * @param error - A caught error potentially of type {@link OpSpawnError}.
 * @returns Per-line masking candidates from stdout/stderr, or an empty list
 *   when the error is not an {@link OpSpawnError}.
 */
export function collectOpFailureOutputs(error: unknown): string[] {
  if (!(error instanceof OpSpawnError)) return []
  const lines: string[] = []
  for (const stream of [error.opStdout, error.opStderr]) {
    if (stream.length === 0) continue
    for (const rawLine of stream.split(/\r\n|\n|\r/v)) {
      const trimmed = rawLine.trim()
      if (trimmed.length > 0) lines.push(trimmed)
    }
  }
  return lines
}
