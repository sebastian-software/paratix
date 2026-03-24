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

async function applyConditionalModules(parameters: {
  dryRun?: boolean
  environment: Environment
  modules: Module[]
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun = false, modules, ssh } = parameters
  let state = createConditionalApplyState(parameters.environment)

  for (const currentModule of modules) {
    // eslint-disable-next-line no-await-in-loop
    const checkResult = await currentModule.check(ssh, state.environment)
    if (checkResult === "ok") continue

    if (!shouldExecuteConditionalApply(currentModule, dryRun)) {
      state = markConditionalApplyChanged(state)
      continue
    }

    // eslint-disable-next-line no-await-in-loop -- conditional modules must preserve ordered env propagation
    const result = await executeConditionalApply({
      dryRun,
      environment: state.environment,
      module: currentModule,
      ssh,
    })
    if (result.status === "failed") return result
    // eslint-disable-next-line no-await-in-loop -- downstream env must see each module's meta in order
    state = await mergeConditionalApplyState(state, result)
    if (state.stopRun === true) break
  }

  return {
    _flushSignals: state.flushSignals,
    _stopRun: state.stopRun,
    meta: state.meta.length === 0 ? undefined : state.meta,
    status: state.status,
  }
}

function shouldExecuteConditionalApply(module: Module, dryRun: boolean): boolean {
  if (!dryRun) return true
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

type ConditionalApplyState = {
  environment: Environment
  flushSignals?: true
  meta: ModuleMetaEntry[]
  status: "changed" | "ok" | "skipped"
  stopRun?: true
}

function createConditionalApplyState(environment: Environment): ConditionalApplyState {
  return { environment: { ...environment }, meta: [], status: "ok" }
}

function markConditionalApplyChanged(state: ConditionalApplyState): ConditionalApplyState {
  return { ...state, status: "changed" }
}

async function executeConditionalApply(parameters: {
  dryRun: boolean
  environment: Environment
  module: Module
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun, environment, module, ssh } = parameters
  if (dryRun && module._applyDryRun != null) {
    return module._applyDryRun(ssh, environment)
  }
  return module.apply(ssh, environment)
}

function whenNeedsDryRunApply(modules: Module[]): boolean {
  return modules.some((module) => shouldExecuteConditionalDryRun(module))
}

function shouldExecuteConditionalDryRun(module: Module): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

async function mergeConditionalApplyState(
  state: ConditionalApplyState,
  result: ModuleResult
): Promise<ConditionalApplyState> {
  const environment = await mergeEnvironmentFromMeta(state.environment, result.meta)
  return {
    environment,
    flushSignals: result._flushSignals === true ? true : state.flushSignals,
    meta: result.meta == null ? state.meta : [...state.meta, ...result.meta],
    status: result.status === "changed" ? "changed" : state.status,
    stopRun: result._stopRun === true ? true : state.stopRun,
  }
}

function createWhenDryRunApply(
  condition: (environment: Environment) => boolean,
  modules: Module[],
  needsDryRunApply: boolean
): ((ssh: null | SshConnection, environment: Environment) => Promise<ModuleResult>) | undefined {
  if (!needsDryRunApply) return undefined
  return async (ssh: null | SshConnection, environment: Environment) => {
    if (!condition(environment)) {
      return { status: "skipped" as const }
    }
    return applyConditionalModules({ dryRun: true, environment, modules, ssh })
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
  const needsDryRunApply = whenNeedsDryRunApply(modules)
  const applyDryRun = createWhenDryRunApply(condition, modules, needsDryRunApply)
  return {
    ...(modules.some((module) => module._dryRunBlocker === true)
      ? { _dryRunBlocker: true as const }
      : {}),
    ...(modules.some((module) => module._dryRunMetaProducer === true)
      ? { _dryRunMetaProducer: true as const }
      : {}),
    ...(applyDryRun == null ? {} : { _applyDryRun: applyDryRun }),
    async apply(ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
      if (!condition(environment)) {
        return { status: "skipped" }
      }
      return applyConditionalModules({ environment, modules, ssh })
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
