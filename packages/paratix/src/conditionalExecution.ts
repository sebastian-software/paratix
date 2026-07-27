import type { DryRunStepResult } from "./dryRunRecipe.js"
import type {
  Environment,
  Module,
  ModuleApplyOptions,
  ModuleMetaEntry,
  ModuleResult,
  SshConnection,
} from "./types.js"

import { executeDryRunChildModule } from "./dryRunRecipe.js"
import { createNullPrototypeEnvironment } from "./environment.js"
import { isEnvironmentMetaEntry, mergeEnvironmentFromMeta } from "./meta.js"
import {
  printModuleResult,
  printRecipeHeader,
  startModuleSpinner,
  withRecipeOutputScope,
} from "./output.js"

type ConditionalApplyState = {
  environment: Environment
  flushSignals?: true
  meta: ModuleMetaEntry[]
  status: "changed" | "ok" | "skipped"
  stopRun?: true
}

/**
 * Everything a single child step needs besides the child module itself and the
 * accumulated state. Bundled so the step functions keep a single parameter
 * object and the loop stays readable.
 */
type ConditionalRunContext = {
  diff: boolean
  dryRun: boolean
  onChildStep?: ModuleApplyOptions["onChildStep"]
  preserveControlPlaneMeta: boolean
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  verbose: boolean
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

/**
 * Pick the connection a guarded child sees: a `local` child never receives the
 * block's SSH connection.
 *
 * @param module - The guarded child module.
 * @param ssh - The block's own connection, or `null`.
 * @returns The connection to hand to the child.
 */
export function getConditionalChildConnection(
  module: Module,
  ssh: null | SshConnection
): null | SshConnection {
  return module.local === true ? null : ssh
}

async function executeConditionalApply(parameters: {
  connection: null | SshConnection
  context: ConditionalRunContext
  currentModule: Module
  environment: Environment
}): Promise<ModuleResult> {
  const { connection, context, currentModule, environment } = parameters
  if (currentModule._supportsChildStepHook === true) {
    return currentModule.apply(connection, environment, {
      onChildStep: context.onChildStep,
      shutdownSignal: context.shutdownSignal,
    })
  }
  return currentModule.apply(connection, environment)
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

/**
 * Run a guarded block and itemize it exactly like a recipe.
 *
 * The block opens its own output scope, prints its `[name]` header and one
 * result line per child. Its own closing line is *not* printed here: for a
 * nested block `recipe.executeOneModule` prints it, for a top-level one
 * `runner.runRegularModule` does — the same split `applyRecipe` uses.
 *
 * @param parameters - Everything the block needs for one run.
 * @param parameters.diff - Whether `--diff` was requested (dry run only).
 * @param parameters.dryRun - Whether this is a dry run.
 * @param parameters.environment - Environment the block inherited.
 * @param parameters.modules - The guarded child modules.
 * @param parameters.name - Display name of the block, used for the header.
 * @param parameters.onChildStep - Control-plane hook of the surrounding runner.
 * @param parameters.shutdownSignal - Getter for the pending shutdown signal.
 * @param parameters.ssh - SSH connection, or `null` for a local block.
 * @param parameters.verbose - Whether verbose command diagnostics are printed.
 * @returns The block's aggregated result.
 */
export async function applyConditionalModules(parameters: {
  diff?: boolean
  dryRun?: boolean
  environment: Environment
  modules: Module[]
  name: string
  onChildStep?: ModuleApplyOptions["onChildStep"]
  shutdownSignal?: ModuleApplyOptions["shutdownSignal"]
  ssh: null | SshConnection
  verbose?: boolean
}): Promise<ModuleResult> {
  return withRecipeOutputScope(async () => {
    printRecipeHeader(parameters.name)
    return runConditionalModuleLoop(parameters)
  })
}

async function runConditionalModuleLoop(parameters: {
  diff?: boolean
  dryRun?: boolean
  environment: Environment
  modules: Module[]
  onChildStep?: ModuleApplyOptions["onChildStep"]
  shutdownSignal?: ModuleApplyOptions["shutdownSignal"]
  ssh: null | SshConnection
  verbose?: boolean
}): Promise<ModuleResult> {
  const context: ConditionalRunContext = {
    diff: parameters.diff ?? false,
    dryRun: parameters.dryRun ?? false,
    onChildStep: parameters.onChildStep,
    preserveControlPlaneMeta: parameters.onChildStep == null,
    shutdownSignal: parameters.shutdownSignal ?? (() => null),
    ssh: parameters.ssh,
    verbose: parameters.verbose ?? false,
  }
  let state = createConditionalApplyState(parameters.environment)

  for (const currentModule of parameters.modules) {
    // eslint-disable-next-line no-await-in-loop
    const step = await applyConditionalModuleStep({ context, currentModule, state })
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

/**
 * Execute one guarded child. The block keeps a single dual-mode loop; only the
 * per-child work differs between an apply and a dry run.
 *
 * @param parameters - Context, child module and accumulated block state.
 * @param parameters.context - Shared per-run context.
 * @param parameters.currentModule - The guarded child to run.
 * @param parameters.state - Result accumulated by the preceding children.
 * @returns Whether the loop continues, breaks, or the block failed.
 */
async function applyConditionalModuleStep(parameters: {
  context: ConditionalRunContext
  currentModule: Module
  state: ConditionalApplyState
}): Promise<ConditionalApplyStepResult> {
  if (parameters.context.shutdownSignal() != null) {
    return { kind: "break", state: parameters.state }
  }
  if (parameters.context.dryRun) return applyConditionalDryRunStep(parameters)
  return applyConditionalApplyStep(parameters)
}

async function applyConditionalApplyStep(parameters: {
  context: ConditionalRunContext
  currentModule: Module
  state: ConditionalApplyState
}): Promise<ConditionalApplyStepResult> {
  const { context, currentModule, state } = parameters
  const connection = getConditionalChildConnection(currentModule, context.ssh)
  // Capture the child's own start before check() so a composite child (a
  // nested recipe or a nested when(...) block) reports its total runtime
  // instead of losing the shared start-time slot to its last grandchild.
  const startedAt = Date.now()
  startModuleSpinner(currentModule.name)
  const checkResult = await currentModule.check(connection, state.environment)
  if (checkResult === "ok") {
    printModuleResult(currentModule.name, "ok", undefined, undefined, startedAt)
    return { kind: "continue", state }
  }
  if (context.shutdownSignal() != null) return { kind: "break", state }
  const result = await executeConditionalApply({
    connection,
    context,
    currentModule,
    environment: state.environment,
  })
  printModuleResult(currentModule.name, result.status, result.detail, undefined, startedAt)
  // A failed child keeps its `error` on the way out: the surrounding runner or
  // recipe renders the block's own closing line and prints the diagnostics
  // exactly once, so this loop deliberately does not call printCommandFailure.
  if (result.status === "failed") return { kind: "failed", result }
  const nextState = await processConditionalApplyResult({
    onChildStep: context.onChildStep,
    preserveControlPlaneMeta: context.preserveControlPlaneMeta,
    result,
    state,
  })
  return { kind: nextState.stopRun === true ? "break" : "continue", state: nextState }
}

async function applyConditionalDryRunStep(parameters: {
  context: ConditionalRunContext
  currentModule: Module
  state: ConditionalApplyState
}): Promise<ConditionalApplyStepResult> {
  const { context, currentModule, state } = parameters
  // Shared with the recipe dry-run loop so both containers descend into and
  // gate their children identically; see executeDryRunChildModule.
  const step = await executeDryRunChildModule({
    childModule: currentModule,
    diff: context.diff,
    environment: state.environment,
    shutdownSignal: context.shutdownSignal,
    ssh: context.ssh,
    verbose: context.verbose,
  })
  if (step.status === "failed") {
    // The descent already printed the child's result line *and* its command
    // diagnostics. Passing `error` on would make the caller print the very
    // same failure a second time under the block's closing line.
    return { kind: "failed", result: { meta: step.meta, status: "failed" } }
  }
  return {
    kind: step.shouldBreak ? "break" : "continue",
    state: mergeConditionalDryRunStep(state, step),
  }
}

/**
 * Fold a shared dry-run step result into the block's accumulator.
 *
 * A dry run never carries an `onChildStep` hook — `_applyDryRun` has no such
 * option — so control-plane meta is always preserved here and the
 * `preserveControlPlaneMeta` filter of the apply path has no counterpart.
 *
 * @param state - The accumulated block state.
 * @param step - The finished child step.
 * @returns The updated block state.
 */
function mergeConditionalDryRunStep(
  state: ConditionalApplyState,
  step: DryRunStepResult
): ConditionalApplyState {
  return {
    ...state,
    environment: step.env,
    meta: step.meta == null ? state.meta : [...state.meta, ...step.meta],
    status: step.status === "changed" ? "changed" : state.status,
    stopRun: step.stopRun === true ? true : state.stopRun,
  }
}
