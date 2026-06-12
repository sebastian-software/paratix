import type { RecipeModule } from "./recipe.js"
import type { Environment, ModuleMetaEntry, ModuleStatus, SshConnection } from "./types.js"

import { shouldExecuteApplyDuringDryRun } from "./dryRunDispatch.js"
import { mergeEnvironmentFromMeta } from "./meta.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  startModuleSpinner,
  withRecipeOutputScope,
} from "./output.js"

type StepResult = {
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
}): StepResult {
  return {
    env: parameters.currentEnvironment,
    meta: parameters.aggregatedMeta.length === 0 ? undefined : parameters.aggregatedMeta,
    shouldBreak: true,
    status: parameters.aggregatedStatus === "changed" ? "changed" : undefined,
  }
}

async function executeDryRunBlockingModule(parameters: {
  childModule: RecipeModule["_modules"][number]
  connection: null | SshConnection
  diff: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  verbose: boolean
}): Promise<StepResult> {
  const { childModule, connection, diff, environment, verbose } = parameters
  if (parameters.shutdownSignal() != null) return { env: environment, shouldBreak: true }
  startModuleSpinner(childModule.name)
  const result =
    childModule._applyDryRun == null
      ? await childModule.apply(connection, environment)
      : await childModule._applyDryRun(connection, environment, {
          shutdownSignal: parameters.shutdownSignal,
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

async function executeDryRunChildModule(parameters: {
  childModule: RecipeModule["_modules"][number]
  diff: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  ssh: null | SshConnection
  verbose: boolean
}): Promise<StepResult> {
  const { childModule, diff, environment, ssh, verbose } = parameters
  if (parameters.shutdownSignal() != null) return { env: environment, shouldBreak: true }
  const connection = childModule.local === true ? null : ssh
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
  result: StepResult
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
}): Promise<DryRunRecipeAccumulator | StepResult> {
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
}): Promise<StepResult> {
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
