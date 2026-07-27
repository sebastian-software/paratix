import type { RecipeModule } from "./recipe.js"
import type { Environment, Module, ModuleMetaEntry, ModuleStatus, SshConnection } from "./types.js"

import { shouldExecuteApplyDuringDryRun } from "./dryRunDispatch.js"
import { mergeEnvironmentFromMeta } from "./meta.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  startModuleSpinner,
  withRecipeOutputScope,
} from "./output.js"
import { isRecipe } from "./recipeGuard.js"

/**
 * Outcome of a single dry-run step: the environment the next sibling sees, the
 * meta it produced, and the control-plane flags that end the enclosing loop.
 *
 * Exported because `conditionalModules.ts` folds the very same step result into
 * its own accumulator — see {@link executeDryRunChildModule}.
 */
export type DryRunStepResult = {
  env: Environment
  meta?: ModuleMetaEntry[]
  shouldBreak: boolean
  status?: ModuleStatus
  stopRun?: true
}

function interruptedDryRunResult(parameters: {
  aggregatedMeta: ModuleMetaEntry[]
  aggregatedStatus: "changed" | "ok"
  currentEnvironment: Environment
}): DryRunStepResult {
  return {
    env: parameters.currentEnvironment,
    meta: parameters.aggregatedMeta.length === 0 ? undefined : parameters.aggregatedMeta,
    shouldBreak: true,
    status: parameters.aggregatedStatus === "changed" ? "changed" : undefined,
  }
}

async function executeDryRunBlockingModule(parameters: {
  childModule: Module
  connection: null | SshConnection
  diff: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  verbose: boolean
}): Promise<DryRunStepResult> {
  const { childModule, connection, diff, environment, verbose } = parameters
  if (parameters.shutdownSignal() != null) return { env: environment, shouldBreak: true }
  startModuleSpinner(childModule.name)
  const result =
    childModule._applyDryRun == null
      ? await childModule.apply(connection, environment)
      : await childModule._applyDryRun(connection, environment, {
          // `diff` and `verbose` matter to container modules (a `when(...)`
          // block) that itemize their own children: without them the container
          // would render its subtree with `--diff` disabled and swallow the
          // verbose command diagnostics of a failing grandchild.
          diff,
          shutdownSignal: parameters.shutdownSignal,
          verbose,
        })
  const nextEnvironment =
    result.meta == null ? environment : await mergeEnvironmentFromMeta(environment, result.meta)
  const diffOutput = diff ? result.diff : undefined
  printModuleResult(
    childModule.name,
    result.status,
    result._dryRunDetail ?? "(dry-run)",
    diffOutput
  )
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
  return {
    env: nextEnvironment,
    meta: result.meta,
    shouldBreak: result.status === "failed" || result._stopRun === true,
    status: result.status,
    stopRun: result._stopRun,
  }
}

/**
 * Decide whether a finished descent was cut short by a shutdown signal.
 *
 * `interruptedDryRunResult` and the shutdown guards in
 * {@link executeDryRunChildModule} all leave the loop with `shouldBreak` set
 * while a signal is pending, and none of them printed a result line for the
 * work they abandoned. The enclosing recipe must stay silent for the same
 * reason (see the invariant documented in `output.ts`).
 *
 * @param result - The step result returned by the descent.
 * @param shutdownSignal - Getter for the pending shutdown signal.
 * @returns `true` when the descent was interrupted rather than completed.
 */
function wasDryRunDescentInterrupted(
  result: DryRunStepResult,
  shutdownSignal: () => NodeJS.Signals | null
): boolean {
  return result.shouldBreak && shutdownSignal() != null
}

/**
 * Render a nested recipe exactly like a top-level one.
 *
 * Itemization is a property of *being a recipe*, not of the module kinds a
 * recipe happens to contain: the descent is unconditional, so a recipe of plain
 * package/service steps prints its `[name]` header plus one line per child
 * instead of collapsing into a single anonymous `changed (dry-run)` row. The
 * per-module `shouldExecuteApplyDuringDryRun` gate still applies one level
 * down, so `--diff` handling, blockers and meta producers are unchanged.
 *
 * @param parameters - Descent parameters.
 * @param parameters.childRecipe - The nested recipe to itemize.
 * @param parameters.connection - SSH connection, or `null` for local recipes.
 * @param parameters.diff - Whether `--diff` was requested.
 * @param parameters.environment - Environment visible to the nested recipe.
 * @param parameters.shutdownSignal - Getter for the pending shutdown signal.
 * @param parameters.verbose - Whether verbose command diagnostics are printed.
 * @returns The nested recipe's aggregated step result.
 */
async function executeDryRunChildRecipe(parameters: {
  childRecipe: RecipeModule
  connection: null | SshConnection
  diff: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  verbose: boolean
}): Promise<DryRunStepResult> {
  // Measure the recipe's own runtime here: each child result line consumes and
  // clears the shared start-time slot in output.ts, so the closing line has to
  // carry its own measurement rather than the last child's.
  const startedAt = Date.now()
  const result = await dryRunRecipeModule({
    environment: parameters.environment,
    options: { diff: parameters.diff, verbose: parameters.verbose },
    recipeModule: parameters.childRecipe,
    shutdownSignal: parameters.shutdownSignal,
    ssh: parameters.connection,
  })
  const { status } = result
  // An interrupted descent carries no meaningful aggregate — `status` may even
  // be undefined — and must not print a closing line at all.
  if (status != null && !wasDryRunDescentInterrupted(result, parameters.shutdownSignal)) {
    printModuleResult(parameters.childRecipe.name, status, "(dry-run)", undefined, startedAt)
  }
  // A failed child already emitted its own printCommandFailure inside the
  // descent, so the aggregate is passed through untouched. dryRunRecipeModule
  // returns the inner-merged environment and the aggregated meta, so the parent
  // accumulator needs no extra mergeEnvironmentFromMeta on this path.
  return result
}

/**
 * Run one child of a container during a dry run and print its result line.
 *
 * This is the single place that encodes the per-child dry-run decision:
 *
 * - a recipe child is descended into unconditionally, because itemization is a
 *   property of *being a container*, not of the module kinds it happens to
 *   hold;
 * - every other child runs its `check()` and only dispatches `_applyDryRun`
 *   (or `apply` as the fallback) when {@link shouldExecuteApplyDuringDryRun}
 *   allows it — otherwise it renders as a passive `ok` / `changed (dry-run)`.
 *
 * Both dry-run containers consume this function: the recipe loop below and the
 * `when(...)` loop in `conditionalModules.ts`. Keeping a private copy per
 * container is exactly how the itemization gaps of issues #160 and #163 arose,
 * so new container kinds must call this instead of re-deriving the decision.
 *
 * @param parameters - Step parameters.
 * @param parameters.childModule - The child to check and conditionally dispatch.
 * @param parameters.diff - Whether `--diff` was requested.
 * @param parameters.environment - Environment visible to the child.
 * @param parameters.shutdownSignal - Getter for the pending shutdown signal.
 * @param parameters.ssh - SSH connection of the enclosing container.
 * @param parameters.verbose - Whether verbose command diagnostics are printed.
 * @returns The child's step result for the enclosing accumulator.
 */
export async function executeDryRunChildModule(parameters: {
  childModule: Module
  diff: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  verbose: boolean
}): Promise<DryRunStepResult> {
  const { childModule, diff, environment, ssh, verbose } = parameters
  if (parameters.shutdownSignal() != null) return { env: environment, shouldBreak: true }
  const connection = childModule.local === true ? null : ssh
  if (isRecipe(childModule)) {
    // Deliberately no recipe-level check() here: the descent itemizes every
    // child, and each child runs its own check().
    return executeDryRunChildRecipe({
      childRecipe: childModule,
      connection,
      diff,
      environment,
      shutdownSignal: parameters.shutdownSignal,
      verbose,
    })
  }
  startModuleSpinner(childModule.name)
  const checkResult = await childModule.check(connection, environment)
  if (parameters.shutdownSignal() != null) return { env: environment, shouldBreak: true }
  if (checkResult !== "ok" && shouldExecuteApplyDuringDryRun(childModule, diff)) {
    return executeDryRunBlockingModule({
      childModule,
      connection,
      diff,
      environment,
      shutdownSignal: parameters.shutdownSignal,
      verbose,
    })
  }
  const status = checkResult === "ok" ? "ok" : "changed"
  const suffix = checkResult === "ok" ? undefined : "(dry-run)"
  printModuleResult(childModule.name, status, suffix)
  return { env: environment, shouldBreak: false, status }
}

type DryRunRecipeAccumulator = {
  aggregatedMeta: ModuleMetaEntry[]
  aggregatedStatus: "changed" | "ok"
  currentEnvironment: Environment
}

function applyDryRunChildResult(
  accumulator: DryRunRecipeAccumulator,
  result: DryRunStepResult
): DryRunRecipeAccumulator {
  return {
    aggregatedMeta:
      result.meta == null
        ? accumulator.aggregatedMeta
        : [...accumulator.aggregatedMeta, ...result.meta],
    aggregatedStatus: result.status === "changed" ? "changed" : accumulator.aggregatedStatus,
    currentEnvironment: result.env,
  }
}

async function runDryRunChildLoop(parameters: {
  accumulator: DryRunRecipeAccumulator
  diff: boolean
  recipeModule: RecipeModule
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  verbose: boolean
}): Promise<DryRunRecipeAccumulator | DryRunStepResult> {
  let accumulator = parameters.accumulator
  for (const childModule of parameters.recipeModule._modules) {
    if (parameters.shutdownSignal() != null) {
      return interruptedDryRunResult({
        aggregatedMeta: accumulator.aggregatedMeta,
        aggregatedStatus: accumulator.aggregatedStatus,
        currentEnvironment: accumulator.currentEnvironment,
      })
    }
    // eslint-disable-next-line no-await-in-loop
    const result = await executeDryRunChildModule({
      childModule,
      diff: parameters.diff,
      environment: accumulator.currentEnvironment,
      shutdownSignal: parameters.shutdownSignal,
      ssh: parameters.ssh,
      verbose: parameters.verbose,
    })
    if (result.shouldBreak) return result
    accumulator = applyDryRunChildResult(accumulator, result)
  }
  return accumulator
}

export async function dryRunRecipeModule(parameters: {
  environment: Environment
  options?: {
    diff?: boolean
    verbose?: boolean
  }
  recipeModule: RecipeModule
  shutdownSignal?: () => NodeJS.Signals | null
  ssh: null | SshConnection
}): Promise<DryRunStepResult> {
  return withRecipeOutputScope(async () => {
    const { environment, recipeModule, ssh } = parameters
    printRecipeHeader(recipeModule.name)
    const shutdownSignal = parameters.shutdownSignal ?? (() => null)
    const loopResult = await runDryRunChildLoop({
      accumulator: {
        aggregatedMeta: [],
        aggregatedStatus: "ok",
        currentEnvironment: environment,
      },
      diff: parameters.options?.diff ?? false,
      recipeModule,
      shutdownSignal,
      ssh,
      verbose: parameters.options?.verbose ?? false,
    })
    if ("shouldBreak" in loopResult) return loopResult
    return {
      env: loopResult.currentEnvironment,
      meta: loopResult.aggregatedMeta.length === 0 ? undefined : loopResult.aggregatedMeta,
      shouldBreak: false,
      status: loopResult.aggregatedStatus,
    }
  })
}
