import { createNullPrototypeEnvironment } from "./environment.js"
import { isEnvironmentMetaEntry, mergeEnvironmentFromMeta } from "./meta.js"
import {
  type Environment,
  type Module,
  type ModuleApplyOptions,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

type ConditionalApplyState = {
  environment: Environment
  flushSignals?: true
  meta: ModuleMetaEntry[]
  status: "changed" | "ok" | "skipped"
  stopRun?: true
}

type ConditionalApplyStepResult =
  | { kind: "break"; state: ConditionalApplyState }
  | { kind: "continue"; state: ConditionalApplyState }
  | { kind: "failed"; result: ModuleResult }

function createConditionalApplyState(environment: Environment): ConditionalApplyState {
  // R-0000087: preserve the null-prototype guarantee that
  // R-0000069/R-0000070/R-0000074 establish for the runner-level
  // environment. Plain object spread (`{ ...environment }`) would create a
  // map with `Object.prototype`, exposing the first child module of every
  // when(...) guard to a polluted-fähige environment. Mirror the
  // recipe.ts:302 / meta.ts:214 approach.
  return {
    environment: Object.assign(createNullPrototypeEnvironment(), environment),
    meta: [],
    status: "ok",
  }
}

function markConditionalApplyChanged(state: ConditionalApplyState): ConditionalApplyState {
  return { ...state, status: "changed" }
}

async function executeConditionalApply(parameters: {
  dryRun: boolean
  environment: Environment
  module: Module
  onChildStep?: ModuleApplyOptions["onChildStep"]
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun, environment, module, ssh } = parameters
  if (dryRun && module._applyDryRun != null) {
    return module._applyDryRun(ssh, environment, {
      shutdownSignal: parameters.shutdownSignal,
    })
  }
  if (module._supportsChildStepHook === true) {
    return module.apply(ssh, environment, {
      onChildStep: parameters.onChildStep,
      shutdownSignal: parameters.shutdownSignal,
    })
  }
  return module.apply(ssh, environment)
}

function shouldExecuteConditionalApply(module: Module, dryRun: boolean): boolean {
  if (!dryRun) return true
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

function getConditionalChildConnection(
  module: Module,
  ssh: null | SshConnection
): null | SshConnection {
  return module.local === true ? null : ssh
}

async function mergeConditionalApplyState(
  preserveControlPlaneMeta: boolean,
  state: ConditionalApplyState,
  result: ModuleResult
): Promise<ConditionalApplyState> {
  const environment = await mergeEnvironmentFromMeta(state.environment, result.meta)
  const resultMeta =
    result.meta == null || preserveControlPlaneMeta
      ? result.meta
      : result.meta.filter(isEnvironmentMetaEntry)
  return {
    environment,
    flushSignals: result._flushSignals === true ? true : state.flushSignals,
    meta: resultMeta == null ? state.meta : [...state.meta, ...resultMeta],
    status: result.status === "changed" ? "changed" : state.status,
    stopRun: result._stopRun === true ? true : state.stopRun,
  }
}

async function notifyConditionalChildStep(parameters: {
  environment: Environment
  onChildStep?: ModuleApplyOptions["onChildStep"]
  result: ModuleResult
}): Promise<void> {
  if (parameters.onChildStep == null) return
  await parameters.onChildStep({
    _flushSignals: parameters.result._flushSignals,
    _stopRun: parameters.result._stopRun,
    env: parameters.environment,
    meta: parameters.result.meta,
    status: parameters.result.status,
  })
}

async function processConditionalApplyResult(parameters: {
  onChildStep?: ModuleApplyOptions["onChildStep"]
  preserveControlPlaneMeta: boolean
  result: ModuleResult
  state: ConditionalApplyState
}): Promise<ConditionalApplyState> {
  const state = await mergeConditionalApplyState(
    parameters.preserveControlPlaneMeta,
    parameters.state,
    parameters.result
  )
  await notifyConditionalChildStep({
    environment: state.environment,
    onChildStep: parameters.onChildStep,
    result: parameters.result,
  })
  return state
}

async function applyConditionalModules(parameters: {
  dryRun?: boolean
  environment: Environment
  modules: Module[]
  onChildStep?: ModuleApplyOptions["onChildStep"]
  shutdownSignal?: ModuleApplyOptions["shutdownSignal"]
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun = false, modules, ssh } = parameters
  const preserveControlPlaneMeta = parameters.onChildStep == null
  const shutdownSignal = parameters.shutdownSignal ?? (() => null)
  let state = createConditionalApplyState(parameters.environment)

  for (const currentModule of modules) {
    // eslint-disable-next-line no-await-in-loop
    const step = await applyConditionalModuleStep({
      currentModule,
      dryRun,
      onChildStep: parameters.onChildStep,
      preserveControlPlaneMeta,
      shutdownSignal,
      ssh,
      state,
    })
    if (step.kind === "failed") return step.result
    state = step.state
    if (step.kind === "break") break
  }

  return {
    _flushSignals: state.flushSignals,
    _stopRun: state.stopRun,
    meta: state.meta.length === 0 ? undefined : state.meta,
    status: state.status,
  }
}

async function applyConditionalModuleStep(parameters: {
  currentModule: Module
  dryRun: boolean
  onChildStep?: ModuleApplyOptions["onChildStep"]
  preserveControlPlaneMeta: boolean
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  state: ConditionalApplyState
}): Promise<ConditionalApplyStepResult> {
  if (parameters.shutdownSignal() != null) {
    return { kind: "break", state: parameters.state }
  }
  const connection = getConditionalChildConnection(parameters.currentModule, parameters.ssh)
  const checkResult = await parameters.currentModule.check(connection, parameters.state.environment)
  if (checkResult === "ok") return { kind: "continue", state: parameters.state }
  if (parameters.shutdownSignal() != null) return { kind: "break", state: parameters.state }
  if (!shouldExecuteConditionalApply(parameters.currentModule, parameters.dryRun)) {
    return { kind: "continue", state: markConditionalApplyChanged(parameters.state) }
  }
  const result = await executeConditionalApply({
    dryRun: parameters.dryRun,
    environment: parameters.state.environment,
    module: parameters.currentModule,
    onChildStep: parameters.onChildStep,
    shutdownSignal: parameters.shutdownSignal,
    ssh: connection,
  })
  if (result.status === "failed") return { kind: "failed", result }
  const state = await processConditionalApplyResult({
    onChildStep: parameters.onChildStep,
    preserveControlPlaneMeta: parameters.preserveControlPlaneMeta,
    result,
    state: parameters.state,
  })
  return { kind: state.stopRun === true ? "break" : "continue", state }
}

function shouldExecuteConditionalDryRun(module: Module): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

function whenNeedsDryRunApply(modules: Module[]): boolean {
  return modules.some((module) => shouldExecuteConditionalDryRun(module))
}

async function checkConditionalModules(
  modules: Module[],
  ssh: null | SshConnection,
  environment: Environment
): Promise<"needs-apply" | "ok"> {
  // R-0000087: same null-prototype preservation as createConditionalApplyState
  // for the check-side traversal of when(...) guards.
  const currentEnvironment = Object.assign(createNullPrototypeEnvironment(), environment)
  for (const currentModule of modules) {
    const connection = getConditionalChildConnection(currentModule, ssh)
    // eslint-disable-next-line no-await-in-loop
    const result = await currentModule.check(connection, currentEnvironment)
    if (result === NEEDS_APPLY) {
      return NEEDS_APPLY
    }
  }
  return "ok"
}

type Condition = (ssh: null | SshConnection, environment: Environment) => boolean | Promise<boolean>

function createWhenDryRunApply(
  condition: Condition,
  modules: Module[],
  needsDryRunApply: boolean
): Module["_applyDryRun"] | undefined {
  if (!needsDryRunApply) return undefined
  return async (
    ssh: null | SshConnection,
    environment: Environment,
    options?: ModuleApplyOptions
  ) => {
    if (!(await condition(ssh, environment))) {
      return { status: "skipped" as const }
    }
    return applyConditionalModules({
      dryRun: true,
      environment,
      modules,
      shutdownSignal: options?.shutdownSignal,
      ssh,
    })
  }
}

export function createConditionalModule(parameters: {
  condition: Condition
  modules: Module[]
  name: string
}): Module {
  const needsDryRunApply = whenNeedsDryRunApply(parameters.modules)
  const applyDryRun = createWhenDryRunApply(
    parameters.condition,
    parameters.modules,
    needsDryRunApply
  )

  return {
    _supportsChildStepHook: true as const,
    ...(parameters.modules.some((module) => module._dryRunBlocker === true)
      ? { _dryRunBlocker: true as const }
      : {}),
    ...(parameters.modules.some((module) => module._dryRunMetaProducer === true)
      ? { _dryRunMetaProducer: true as const }
      : {}),
    ...(applyDryRun == null ? {} : { _applyDryRun: applyDryRun }),
    async apply(
      ssh: null | SshConnection,
      environment: Environment,
      options?: ModuleApplyOptions
    ): Promise<ModuleResult> {
      if (!(await parameters.condition(ssh, environment))) {
        return { status: "skipped" }
      }
      return applyConditionalModules({
        environment,
        modules: parameters.modules,
        onChildStep: options?.onChildStep,
        shutdownSignal: options?.shutdownSignal,
        ssh,
      })
    },
    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      if (!(await parameters.condition(ssh, environment))) {
        return "ok"
      }
      return checkConditionalModules(parameters.modules, ssh, environment)
    },
    name: parameters.name,
  }
}
