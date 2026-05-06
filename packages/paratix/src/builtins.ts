import {
  createCommandGuard,
  createFilesystemGuard,
  createPackageGuard,
} from "./conditionalGuards.js"
import { createConditionalModule } from "./conditionalModules.js"
import { failed } from "./moduleFailure.js"
import { getRunnerAbortSignal, setRunnerAbortSignal } from "./runnerAbortSignal.js"
import {
  type Environment,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

/**
 * Backward-compatible wrapper for {@link setRunnerAbortSignal}.
 *
 * R-0000027 introduced this function for the {@link pause} builtin; R-0000052
 * generalized the underlying holder so polling modules (e.g. `net.waitFor`)
 * can observe the same abort signal. The export is preserved so external
 * callers and tests that already imported `setPauseAbortSignal` continue to
 * work; new code should call {@link setRunnerAbortSignal} directly.
 *
 * @param signal - The abort signal whose `abort` event cancels active waits.
 */
export function setPauseAbortSignal(signal: AbortSignal | undefined): void {
  setRunnerAbortSignal(signal)
}

/**
 * Fail the run if a condition on the current env is not satisfied.
 *
 * The check phase evaluates the condition; if it returns `false`, apply
 * marks the module as failed, which aborts the parent recipe.
 *
 * @param condition - A predicate receiving the current env at run time.
 * @param message - Human-readable description shown in the run output.
 * @returns A Module that asserts the condition.
 *
 * @example
 * assert(env => !!env["APP_SECRET"], "APP_SECRET must be set")
 */
export function assert(condition: (environment: Environment) => boolean, message: string): Module {
  return {
    _dryRunBlocker: true,
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply(_ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
      if (condition(environment)) {
        return { status: "ok" }
      }
      return failed(`[assert] ${message}`)
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check(
      _ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      return condition(environment) ? "ok" : NEEDS_APPLY
    },
    name: `assert: ${message}`,
  }
}

/**
 * Print a static debug message to the console during the apply phase.
 * Always runs (never skipped by the check phase).
 *
 * @param message - The message to print, prefixed with `[debug]`.
 * @returns A Module that prints a debug message.
 */
export function debug(message: string): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply(): Promise<ModuleResult> {
      console.log(`  [debug] ${message}`)
      return { status: "ok" }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: `debug: ${message}`,
  }
}

/**
 * Unconditionally abort the run with a failed status and an error message.
 * Useful as a sentinel at the end of a conditional branch.
 *
 * @param message - The message to print, prefixed with `[fail]`.
 * @returns A Module that fails the run.
 */
export function fail(message: string): Module {
  return {
    _dryRunBlocker: true,
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply(): Promise<ModuleResult> {
      return failed(`[fail] ${message}`)
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: `fail: ${message}`,
  }
}

/**
 * Coerce an unknown abort reason into an `Error` instance.
 *
 * Falls back to `"pause aborted"` when the reason is `undefined`/`null`,
 * preserves any thrown `Error`, and wraps anything else with a string
 * representation that does not depend on `Object.prototype.toString`.
 *
 * @param reason - The {@link AbortSignal.reason}, if any.
 * @returns An `Error` with a meaningful message.
 */
function normalizePauseAbortReason(reason: unknown): Error {
  if (reason instanceof Error) return reason
  if (reason === undefined || reason === null) return new Error("pause aborted")
  if (typeof reason === "string") return new Error(reason)
  return new Error("pause aborted")
}

/**
 * Wait for the operator to press Enter, observing an optional abort signal.
 *
 * Cleans up the stdin `data` listener and the abort listener regardless of
 * which one fires first, mirroring the cancellation semantics of
 * {@link import("./terminal.js").promptTerminal}.
 *
 * @param abortSignal - Optional signal that, when aborted, rejects the wait.
 * @returns A promise that resolves on Enter or rejects on abort.
 */
async function waitForEnterOrAbort(abortSignal: AbortSignal | undefined): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false

    const onData = (chunk: unknown): void => {
      const input = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk)
      if (!input.includes("\n") && !input.includes("\r")) return
      if (settled) return
      settled = true
      cleanup()
      process.stdin.pause()
      resolve()
    }

    const onAbort = (): void => {
      if (settled) return
      settled = true
      cleanup()
      process.stdin.pause()
      reject(normalizePauseAbortReason(abortSignal?.reason))
    }

    function cleanup(): void {
      process.stdin.removeListener("data", onData)
      abortSignal?.removeEventListener("abort", onAbort)
    }

    if (abortSignal?.aborted === true) {
      onAbort()
      return
    }

    process.stdin.on("data", onData)
    abortSignal?.addEventListener("abort", onAbort, { once: true })
  })
}

/**
 * Pause execution and wait for the operator to press Enter.
 * Useful for interactive confirmation during a run.
 *
 * Honors the runner's prompt abort signal: a SIGINT during the pause cancels
 * the wait, removes the stdin `data` listener, and rejects the apply promise
 * with the signal's abort reason.
 *
 * @param message - Prompt shown to the operator. Defaults to `"Press enter to continue..."`.
 * @returns A Module that pauses execution.
 */
export function pause(message?: string): Module {
  return {
    async apply(): Promise<ModuleResult> {
      const promptText = message ?? "Press enter to continue..."
      process.stdout.write(`  [pause] ${promptText} `)

      await waitForEnterOrAbort(getRunnerAbortSignal())

      return { status: "ok" }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: message == null ? "pause" : `pause: ${message}`,
  }
}

function isFirstRunEnabled(environment: Environment): boolean {
  return environment.PARATIX_FIRST_RUN === "true" || environment.FIRST_RUN === true
}

/**
 * Built-ins related to the explicit first-run bootstrap stage.
 */
export const firstRun = {
  /**
   * Stop the current run successfully when Paratix was invoked with `--first-run`.
   * Useful as an explicit stage boundary in scaffolded playbooks.
   *
   * @param message - Optional note shown in the module name.
   * @returns A local module that stops the run only during first-run execution.
   */
  stop(message?: string): Module {
    const moduleName = message == null ? "firstRun.stop" : `firstRun.stop: ${message}`

    return {
      _dryRunBlocker: true,
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply(_ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
        if (!isFirstRunEnabled(environment)) {
          return { status: "ok" }
        }

        return {
          _dryRunDetail: "(first-run stop)",
          _stopRun: true,
          status: "ok",
        }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(
        _ssh: null | SshConnection,
        environment: Environment
      ): Promise<"needs-apply" | "ok"> {
        return isFirstRunEnabled(environment) ? NEEDS_APPLY : "ok"
      },
      local: true,
      name: moduleName,
    }
  },
}

/**
 * Built-ins for explicit signal checkpoints.
 */
export const signals = {
  /**
   * Flush all currently pending signals for the active scope.
   * Signals remain scope-local:
   * - in a recipe, this flushes that recipe's signals
   * - at top level, this flushes `server(...).signals`
   *
   * @param message - Optional note shown in the module name.
   * @returns A local control module that requests an immediate signal flush.
   */
  flush(message?: string): Module {
    const moduleName = message == null ? "signals.flush" : `signals.flush: ${message}`

    return {
      _dryRunBlocker: true,
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply(): Promise<ModuleResult> {
        return {
          _dryRunDetail: "(dry-run, pending signals not executed)",
          _flushSignals: true,
          status: "ok",
        }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      local: true,
      name: moduleName,
    }
  },
}

/**
 * Run one or more modules only when a runtime condition is met.
 * When the condition is `false`, the whole group is skipped without running
 * any child checks or applies.
 *
 * @param condition - A predicate evaluated against the current env at run time.
 * @param modules - One or more modules to run when the condition is `true`.
 * @returns A Module that conditionally runs the inner modules.
 *
 * @example
 * when(env => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban"))
 */
function baseWhen(condition: (environment: Environment) => boolean, ...modules: Module[]): Module {
  return createConditionalModule({
    condition: (_ssh, environment) => condition(environment),
    modules,
    name: `when: conditional (${modules.length} modules)`,
  })
}

type WhenFunction = {
  commandExists: (commandName: string, ...modules: Module[]) => Module
  commandMissing: (commandName: string, ...modules: Module[]) => Module
  fileExists: (path: string, ...modules: Module[]) => Module
  fileMissing: (path: string, ...modules: Module[]) => Module
  packageAbsent: (packageName: string, ...modules: Module[]) => Module
  packageInstalled: (packageName: string, ...modules: Module[]) => Module
  pathExists: (path: string, ...modules: Module[]) => Module
  pathMissing: (path: string, ...modules: Module[]) => Module
  socketExists: (path: string, ...modules: Module[]) => Module
  socketMissing: (path: string, ...modules: Module[]) => Module
  symlinkExists: (path: string, ...modules: Module[]) => Module
  symlinkMissing: (path: string, ...modules: Module[]) => Module
} & typeof baseWhen

export const when: WhenFunction = Object.assign(baseWhen, {
  commandExists: (commandName: string, ...modules: Module[]) =>
    createCommandGuard(commandName, false, modules),
  commandMissing: (commandName: string, ...modules: Module[]) =>
    createCommandGuard(commandName, true, modules),
  fileExists: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: false, modules, path, testFlag: "-f" }),
  fileMissing: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: true, modules, path, testFlag: "-f" }),
  packageAbsent: (packageName: string, ...modules: Module[]) =>
    createPackageGuard(packageName, true, modules),
  packageInstalled: (packageName: string, ...modules: Module[]) =>
    createPackageGuard(packageName, false, modules),
  pathExists: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: false, modules, path, testFlag: "-d" }),
  pathMissing: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: true, modules, path, testFlag: "-d" }),
  socketExists: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: false, modules, path, testFlag: "-S" }),
  socketMissing: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: true, modules, path, testFlag: "-S" }),
  symlinkExists: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: false, modules, path, testFlag: "-L" }),
  symlinkMissing: (path: string, ...modules: Module[]) =>
    createFilesystemGuard({ invert: true, modules, path, testFlag: "-L" }),
})
