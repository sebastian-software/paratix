import type { RecipeModule } from "./recipe.js"
import type { SshConnectionImpl } from "./ssh.js"
import type { Environment, ModuleStatus } from "./types.js"

import { mergeEnvironmentFromMeta } from "./meta.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  startModuleSpinner,
  withRecipeOutputScope,
} from "./output.js"

type StepResult = { env: Environment; shouldBreak: boolean; status?: ModuleStatus; stopRun?: true }

function shouldExecuteApplyDuringDryRun(module: RecipeModule["_modules"][number]): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

async function executeDryRunBlockingModule(parameters: {
  childModule: RecipeModule["_modules"][number]
  connection: null | SshConnectionImpl
  environment: Environment
  verbose: boolean
}): Promise<StepResult> {
  const { childModule, connection, environment, verbose } = parameters
  startModuleSpinner(childModule.name)
  const result =
    childModule._applyDryRun == null
      ? await childModule.apply(connection, environment)
      : await childModule._applyDryRun(connection, environment)
  const nextEnvironment =
    result.meta == null ? environment : await mergeEnvironmentFromMeta(environment, result.meta)
  printModuleResult(childModule.name, result.status, result._dryRunDetail ?? "(dry-run)")
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
  return {
    env: nextEnvironment,
    shouldBreak: result.status === "failed" || result._stopRun === true,
    status: result.status,
    stopRun: result._stopRun,
  }
}

async function executeDryRunChildModule(parameters: {
  childModule: RecipeModule["_modules"][number]
  environment: Environment
  ssh: SshConnectionImpl
  verbose: boolean
}): Promise<StepResult> {
  const { childModule, environment, ssh, verbose } = parameters
  const connection = childModule.local === true ? null : ssh
  startModuleSpinner(childModule.name)
  const checkResult = await childModule.check(connection, environment)
  if (checkResult !== "ok" && shouldExecuteApplyDuringDryRun(childModule)) {
    return executeDryRunBlockingModule({ childModule, connection, environment, verbose })
  }
  const status = checkResult === "ok" ? "ok" : "changed"
  const suffix = checkResult === "ok" ? undefined : "(dry-run)"
  printModuleResult(childModule.name, status, suffix)
  return { env: environment, shouldBreak: false, status }
}

export async function dryRunRecipeModule(parameters: {
  environment: Environment
  options?: {
    verbose?: boolean
  }
  recipeModule: RecipeModule
  ssh: SshConnectionImpl
}): Promise<StepResult> {
  return withRecipeOutputScope(async () => {
    const { environment, recipeModule, ssh } = parameters
    printRecipeHeader(recipeModule.name)
    let aggregatedStatus: "changed" | "ok" = "ok"
    let currentEnvironment = environment
    const verbose = parameters.options?.verbose ?? false

    for (const childModule of recipeModule._modules) {
      // eslint-disable-next-line no-await-in-loop
      const result = await executeDryRunChildModule({
        childModule,
        environment: currentEnvironment,
        ssh,
        verbose,
      })
      if (result.shouldBreak) return result
      currentEnvironment = result.env
      if (result.status === "changed") aggregatedStatus = "changed"
    }

    return { env: currentEnvironment, shouldBreak: false, status: aggregatedStatus }
  })
}
