/**
 * R-0000189: dedicated error type that signals a deterministic CLI exit. A
 * synchronous `process.exit` call from inside an interactive prompt skips
 * any in-flight cleanup (raw-mode reset, cursor visibility), which leaves
 * the operator's terminal unusable. Throwing instead lets `main()` (or any
 * other top-level driver) run cleanup and assign `process.exitCode` before
 * the process exits naturally.
 *
 * Lives in its own module so low-level helpers (e.g. scaffoldConfig prompts)
 * can reuse it without forming a circular dependency with cliValidation.
 */
export class CliExitError extends Error {
  public readonly cliMessage: string
  public readonly exitCode: number

  public constructor(message: string, exitCode = 1) {
    super(message)
    this.name = "CliExitError"
    this.cliMessage = message
    this.exitCode = exitCode
  }
}
