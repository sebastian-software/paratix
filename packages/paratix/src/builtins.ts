import { mergeEnvironmentFromMeta } from "./meta.js"
import { failed } from "./moduleFailure.js"
import {
  type Environment,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

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
 * Pause execution and wait for the operator to press Enter.
 * Useful for interactive confirmation during a run.
 *
 * @param message - Prompt shown to the operator. Defaults to `"Press enter to continue..."`.
 * @returns A Module that pauses execution.
 */
export function pause(message?: string): Module {
  return {
    async apply(): Promise<ModuleResult> {
      const promptText = message ?? "Press enter to continue..."
      process.stdout.write(`  [pause] ${promptText} `)

      await new Promise<void>((resolve) => {
        process.stdin.once("data", () => {
          process.stdin.pause()
          resolve()
        })
      })

      return { status: "ok" }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: message == null ? "pause" : `pause: ${message}`,
  }
}

async function applyConditionalModules(
  ssh: null | SshConnection,
  environment: Environment,
  modules: Module[]
): Promise<ModuleResult> {
  let aggregatedStatus: "changed" | "ok" | "skipped" = "ok"
  let currentEnvironment = { ...environment }
  const aggregatedMeta: ModuleMetaEntry[] = []

  for (const currentModule of modules) {
    // eslint-disable-next-line no-await-in-loop
    const checkResult = await currentModule.check(ssh, currentEnvironment)
    if (checkResult === "ok") continue

    // eslint-disable-next-line no-await-in-loop
    const result = await currentModule.apply(ssh, currentEnvironment)
    if (result.status === "failed") return result
    if (result.meta != null) aggregatedMeta.push(...result.meta)
    // eslint-disable-next-line no-await-in-loop -- downstream env must see each module's meta in order
    currentEnvironment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
    if (result.status === "changed") aggregatedStatus = "changed"
  }

  return {
    meta: aggregatedMeta.length === 0 ? undefined : aggregatedMeta,
    status: aggregatedStatus,
  }
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
export function when(
  condition: (environment: Environment) => boolean,
  ...modules: Module[]
): Module {
  return {
    async apply(ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
      if (!condition(environment)) {
        return { status: "skipped" }
      }
      return applyConditionalModules(ssh, environment, modules)
    },
    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      if (!condition(environment)) {
        return "ok"
      }
      // Defensive copy so inner modules can mutate the env without affecting
      // the caller's object (see Bug #13 regression tests).
      const currentEnvironment = { ...environment }
      for (const currentModule of modules) {
        // eslint-disable-next-line no-await-in-loop
        const result = await currentModule.check(ssh, currentEnvironment)
        if (result === NEEDS_APPLY) {
          return NEEDS_APPLY
        }
      }
      return "ok"
    },
    name: `when: conditional (${modules.length} modules)`,
  }
}
