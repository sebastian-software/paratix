/* eslint-disable max-lines -- recipe orchestration intentionally stays co-located */
import { isEnvironmentMetaEntry, mergeEnvironmentFromMeta } from "./meta.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  printRecipeModuleResult,
  startModuleSpinner,
  withRecipeOutputScope,
} from "./output.js"
import { runSignalModules, type SignalHooks } from "./signalOrchestration.js"
import { CommandError } from "./sshHelpers.js"
import {
  type Environment,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  type ModuleStatus,
  NEEDS_APPLY,
  type OrchestrationStep,
  type SshConnection,
} from "./types.js"

/**
 * Internal representation of a recipe module.
 * The `_isRecipe` flag lets the runner distinguish recipes from leaf modules.
 * @internal
 */
export type RecipeModule = {
  _isRecipe: true
  _modules: Module[]
  _signals?: Module[]
  apply: (
    ssh: null | SshConnection,
    environment: Environment,
    options?: {
      onChildStep?: (step: OrchestrationStep) => Promise<void>
      onSignalStep?: (step: OrchestrationStep) => Promise<void>
      shutdownSignal?: () => NodeJS.Signals | null
      signalHooks?: SignalHooks
      verbose?: boolean
    }
  ) => Promise<ModuleResult>
} & Module

type RecipeState = {
  env: Environment
  meta?: ModuleMetaEntry[]
  signalsPending: boolean
  status: Exclude<ModuleStatus, "skipped">
  stopRun?: true
}

type ExecuteModulesParameters = {
  environment: Environment
  onChildStep?: (step: OrchestrationStep) => Promise<void>
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => NodeJS.Signals | null
  signalHooks?: SignalHooks
  signals?: Module[]
  verbose?: boolean
}

type RecipeLoopStepResult =
  | { kind: "break"; state: RecipeState }
  | { kind: "continue"; state: RecipeState }

const INTERRUPTED_BEFORE_APPLY = Symbol("recipe-interrupted-before-apply")

function isRecipeModuleLike(module: Module): boolean {
  return (module as { _isRecipe?: boolean } & Module)._isRecipe === true
}

function printRecipeChildResult(module: Module, result: ModuleResult): void {
  if (isRecipeModuleLike(module)) {
    printRecipeModuleResult(module.name, result.status)
    return
  }

  printModuleResult(module.name, result.status)
}

function applyRecipeStepToState(
  state: RecipeState,
  step: OrchestrationStep,
  preserveControlPlaneMeta: boolean
): RecipeState {
  let stepMeta: ModuleMetaEntry[] | undefined
  if (step.meta == null) {
    stepMeta = undefined
  } else if (preserveControlPlaneMeta) {
    stepMeta = step.meta
  } else {
    stepMeta = step.meta.filter(isEnvironmentMetaEntry)
  }
  const nextMeta = stepMeta == null ? (state.meta ?? []) : [...(state.meta ?? []), ...stepMeta]
  let nextStatus = state.status
  if (step.status === "failed") nextStatus = "failed"
  else if (step.status === "changed") nextStatus = "changed"

  return {
    env: step.env,
    meta: nextMeta,
    signalsPending: step.status === "changed" ? true : state.signalsPending,
    status: nextStatus,
    stopRun: step._stopRun === true ? true : state.stopRun,
  }
}

/**
 * Recipes run their own check→apply loop, separate from the runner's
 * `runModuleLoop` in runner.ts.  This is intentional: recipes execute as a
 * single nested module inside the runner, so SSH-lifecycle concerns
 * (port-change reconnects, reboot handling), shutdown-signal guards,
 * dry-run mode and stats tracking are the runner's responsibility and
 * must not be duplicated here.
 *
 * @param parameters - Parameters for executing one child module.
 * @param parameters.targetModule - The module to check and conditionally apply.
 * @param parameters.ssh - Active SSH connection, or `null` for local modules.
 * @param parameters.currentEnvironment - Environment values available to the module.
 * @param parameters.shutdownSignal - Optional shutdown getter used to suppress new apply steps.
 * @param parameters.verbose - Whether verbose command diagnostics should be printed.
 * @returns The updated environment and status, or `null` if the module was already ok.
 */
async function executeOneModule(parameters: {
  currentEnvironment: Environment
  shutdownSignal?: () => NodeJS.Signals | null
  ssh: null | SshConnection
  targetModule: Module
  verbose?: boolean
}): Promise<null | OrchestrationStep | typeof INTERRUPTED_BEFORE_APPLY> {
  const { currentEnvironment, ssh, targetModule } = parameters
  const verbose = parameters.verbose ?? false
  const connection = targetModule.local === true ? null : ssh
  const checkResult = await checkRecipeChild(targetModule, connection, currentEnvironment)

  if (checkResult === "ok") {
    printModuleResult(targetModule.name, "ok")
    return null
  }

  if ((parameters.shutdownSignal?.() ?? null) != null) {
    return INTERRUPTED_BEFORE_APPLY
  }

  const result = await targetModule.apply(connection, currentEnvironment)
  printRecipeChildResult(targetModule, result)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }

  const environment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
  return {
    _flushSignals: result._flushSignals,
    _stopRun: result._stopRun,
    env: environment,
    meta: result.meta,
    status: result.status,
  }
}

async function checkRecipeChild(
  targetModule: Module,
  connection: null | SshConnection,
  currentEnvironment: Environment
): Promise<"needs-apply" | "ok"> {
  startModuleSpinner(targetModule.name)
  return targetModule.check(connection, currentEnvironment)
}

async function applyExecutedRecipeStep(parameters: {
  onChildStep?: (step: OrchestrationStep) => Promise<void>
  preserveControlPlaneMeta: boolean
  state: RecipeState
  step: null | OrchestrationStep | typeof INTERRUPTED_BEFORE_APPLY
}): Promise<null | RecipeState> {
  if (parameters.step == null) return parameters.state
  if (parameters.step === INTERRUPTED_BEFORE_APPLY) return null

  if (parameters.onChildStep != null) {
    await parameters.onChildStep(parameters.step)
  }

  return applyRecipeStepToState(
    parameters.state,
    parameters.step,
    parameters.preserveControlPlaneMeta
  )
}

function failedRecipeState(environment: Environment): RecipeState {
  return {
    env: environment,
    meta: undefined,
    signalsPending: false,
    status: "failed",
  }
}

function annotateRecipeChildError(moduleName: string, error: unknown): Error {
  const prefix = `[${moduleName}] `
  if (error instanceof CommandError) {
    return new CommandError(`${prefix}${error.message}`, error.fullStdout, error.fullStderr)
  }
  if (error instanceof Error) {
    return new Error(`${prefix}${error.message}`)
  }
  return new Error(`${prefix}${String(error)}`)
}

type RecipeChildExecution =
  | { kind: "failed"; state: RecipeState }
  | {
      kind: "step"
      step: null | OrchestrationStep | typeof INTERRUPTED_BEFORE_APPLY
    }

async function executeRecipeChildStep(parameters: {
  currentEnvironment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  targetModule: Module
  verbose: boolean
}): Promise<RecipeChildExecution> {
  try {
    return { kind: "step", step: await executeOneModule(parameters) }
  } catch (error) {
    if (parameters.shutdownSignal() != null) {
      return { kind: "step", step: INTERRUPTED_BEFORE_APPLY }
    }
    printModuleResult(parameters.targetModule.name, "failed")
    printCommandFailure(error, parameters.verbose)
    return { kind: "failed", state: failedRecipeState(parameters.currentEnvironment) }
  }
}

async function processRecipeStep(parameters: {
  onChildStep?: (step: OrchestrationStep) => Promise<void>
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  preserveControlPlaneMeta: boolean
  shutdownSignal: () => NodeJS.Signals | null
  signalHooks?: SignalHooks
  signals?: Module[]
  ssh: null | SshConnection
  state: RecipeState
  step: RecipeChildExecution
  verbose: boolean
}): Promise<RecipeLoopStepResult> {
  if (parameters.step.kind === "failed") {
    return { kind: "break", state: parameters.step.state }
  }

  const nextState = await applyExecutedRecipeStep({
    onChildStep: parameters.onChildStep,
    preserveControlPlaneMeta: parameters.preserveControlPlaneMeta,
    state: parameters.state,
    step: parameters.step.step,
  })
  if (nextState == null) {
    return { kind: "break", state: parameters.state }
  }

  let state = nextState
  if (shouldFlushRecipeSignals(parameters.step.step, state, parameters.signals)) {
    const signalStatus = await flushPendingRecipeSignals({
      environment: state.env,
      onSignalStep: parameters.onSignalStep,
      shutdownSignal: parameters.shutdownSignal,
      signalHooks: parameters.signalHooks,
      signals: parameters.signals,
      ssh: parameters.ssh,
      verbose: parameters.verbose,
    })
    state = applyRecipeSignalStatus(state, signalStatus)
  }

  if (state.status === "failed" || state.stopRun === true) {
    return { kind: "break", state }
  }

  return { kind: "continue", state }
}

async function executeModules(
  modules: Module[],
  ssh: null | SshConnection,
  parameters: ExecuteModulesParameters
): Promise<RecipeState> {
  const onChildStep = parameters.onChildStep
  const preserveControlPlaneMeta = onChildStep == null
  const shutdownSignal = parameters.shutdownSignal ?? (() => null)
  const verbose = parameters.verbose ?? false
  let state: RecipeState = {
    env: { ...parameters.environment },
    meta: undefined,
    signalsPending: false,
    status: "ok",
  }

  for (const currentModule of modules) {
    if (shutdownSignal() != null) break
    // eslint-disable-next-line no-await-in-loop
    const step = await executeRecipeChildStep({
      currentEnvironment: state.env,
      shutdownSignal,
      ssh,
      targetModule: currentModule,
      verbose,
    })
    // eslint-disable-next-line no-await-in-loop
    const processedStep = await processRecipeStep({
      onChildStep,
      onSignalStep: parameters.onSignalStep,
      preserveControlPlaneMeta,
      shutdownSignal,
      signalHooks: parameters.signalHooks,
      signals: parameters.signals,
      ssh,
      state,
      step,
      verbose,
    })
    state = processedStep.state
    if (processedStep.kind === "break") return state
  }

  return state
}

async function triggerSignals(parameters: {
  environment: Environment
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => NodeJS.Signals | null
  signalHooks?: SignalHooks
  signals: Module[]
  ssh: null | SshConnection
  verbose?: boolean
}): Promise<"changed" | "failed"> {
  return runSignalModules({
    environment: parameters.environment,
    hooks: parameters.signalHooks,
    onSignalStep: parameters.onSignalStep,
    shutdownSignal: parameters.shutdownSignal,
    signals: parameters.signals,
    ssh: parameters.ssh,
    verbose: parameters.verbose,
  })
}

function shouldFlushRecipeSignals(
  step: null | OrchestrationStep | typeof INTERRUPTED_BEFORE_APPLY,
  state: RecipeState,
  signals?: Module[]
): signals is Module[] {
  return (
    step != null &&
    step !== INTERRUPTED_BEFORE_APPLY &&
    step._flushSignals === true &&
    state.signalsPending &&
    signals != null
  )
}

function applyRecipeSignalStatus(
  state: RecipeState,
  signalStatus: "changed" | "failed"
): RecipeState {
  return {
    ...state,
    signalsPending: false,
    status: signalStatus === "failed" ? "failed" : state.status,
  }
}

async function flushPendingRecipeSignals(parameters: {
  environment: Environment
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => NodeJS.Signals | null
  signalHooks?: SignalHooks
  signals: Module[]
  ssh: null | SshConnection
  verbose?: boolean
}): Promise<"changed" | "failed"> {
  return triggerSignals(parameters)
}

async function applyRecipe(parameters: {
  environment: Environment
  modules: Module[]
  name: string
  options?: {
    onChildStep?: (step: OrchestrationStep) => Promise<void>
    onSignalStep?: (step: OrchestrationStep) => Promise<void>
    shutdownSignal?: () => NodeJS.Signals | null
    signalHooks?: SignalHooks
    verbose?: boolean
  }
  signals?: Module[]
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  return withRecipeOutputScope(async () => {
    const shutdownSignal = parameters.options?.shutdownSignal
    const verbose = parameters.options?.verbose ?? false
    printRecipeHeader(parameters.name)
    const state = await executeModules(parameters.modules, parameters.ssh, {
      environment: parameters.environment,
      onChildStep: parameters.options?.onChildStep,
      onSignalStep: parameters.options?.onSignalStep,
      shutdownSignal,
      signalHooks: parameters.options?.signalHooks,
      signals: parameters.signals,
      verbose,
    })

    if (shouldRunRecipeSignalsAtEnd(state, parameters.signals)) {
      state.status = await triggerSignals({
        environment: state.env,
        onSignalStep: parameters.options?.onSignalStep,
        shutdownSignal,
        signalHooks: parameters.options?.signalHooks,
        signals: parameters.signals,
        ssh: parameters.ssh,
        verbose,
      })
    }

    return {
      _stopRun: state.stopRun,
      meta: state.meta,
      status: state.status,
    }
  })
}

function shouldRunRecipeSignalsAtEnd(state: RecipeState, signals?: Module[]): signals is Module[] {
  return state.signalsPending && state.status === "changed" && signals != null
}

/**
 * Group a list of modules into a named, self-contained recipe.
 *
 * The recipe runs each child module in order, short-circuits on the first
 * failure, and propagates `meta` env values from one module to all subsequent
 * ones. If any child reports `"changed"`, the optional `signals` are triggered
 * at the end of the run.
 *
 * @param name - Display name shown in the run output header.
 * @param modules - Ordered list of modules to execute.
 * @param options - Optional recipe configuration.
 * @param options.signals - Modules to fire when at least one child changed state.
 * @returns A RecipeModule that groups the child modules.
 *
 * @example
 * export const nginxRecipe = recipe("nginx", [
 *   apt.installed("nginx"),
 *   file.template("/etc/nginx/nginx.conf", "./files/nginx.conf.tmpl"),
 *   service.enabled("nginx"),
 * ], {
 *   signals: [service.reload("nginx")],
 * });
 */
export function recipe(
  name: string,
  modules: Module[],
  options?: { signals?: Module[] }
): RecipeModule {
  return {
    _isRecipe: true,
    _modules: modules,
    _signals: options?.signals,
    async apply(
      ssh: null | SshConnection,
      environment: Environment,
      parameters?: {
        onChildStep?: (step: OrchestrationStep) => Promise<void>
        onSignalStep?: (step: OrchestrationStep) => Promise<void>
        shutdownSignal?: () => NodeJS.Signals | null
        signalHooks?: SignalHooks
        verbose?: boolean
      }
    ): Promise<ModuleResult> {
      return applyRecipe({
        environment,
        modules,
        name,
        options: parameters,
        signals: options?.signals,
        ssh,
      })
    },

    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      // Each child receives the original environment — no meta propagation,
      // because check() never calls apply() and therefore produces no meta.
      for (const childModule of modules) {
        const connection = childModule.local === true ? null : ssh
        let result: "needs-apply" | "ok"
        try {
          // eslint-disable-next-line no-await-in-loop
          result = await childModule.check(connection, environment)
        } catch (error) {
          throw annotateRecipeChildError(childModule.name, error)
        }
        if (result === NEEDS_APPLY) return NEEDS_APPLY
      }
      return "ok"
    },

    name,
  }
}
