import type { RecipeModule } from "./recipe.js"
import type { SshConnectionImpl } from "./ssh.js"
import type { Environment, ModuleStatus } from "./types.js"

import { mergeEnvironmentFromMeta } from "./meta.js"
import { printCommandFailure, printModuleResult, printRecipeHeader } from "./output.js"

type StepResult = { env: Environment; shouldBreak: boolean; status?: ModuleStatus }

function shouldExecuteApplyDuringDryRun(module: RecipeModule["_modules"][number]): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

async function executeDryRunBlockingModule(
  childModule: RecipeModule["_modules"][number],
  connection: null | SshConnectionImpl,
  environment: Environment
): Promise<StepResult> {
  const result =
    childModule._applyDryRun == null
      ? await childModule.apply(connection, environment)
      : await childModule._applyDryRun(connection, environment)
  const nextEnvironment =
    result.meta == null ? environment : await mergeEnvironmentFromMeta(environment, result.meta)
  printModuleResult(childModule.name, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, false)
  }
  return { env: nextEnvironment, shouldBreak: result.status === "failed", status: result.status }
}

async function executeDryRunChildModule(
  childModule: RecipeModule["_modules"][number],
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  const connection = childModule.local === true ? null : ssh
  const checkResult = await childModule.check(connection, environment)
  if (checkResult !== "ok" && shouldExecuteApplyDuringDryRun(childModule)) {
    return executeDryRunBlockingModule(childModule, connection, environment)
  }
  const status = checkResult === "ok" ? "ok" : "changed"
  const suffix = checkResult === "ok" ? undefined : "(dry-run)"
  printModuleResult(childModule.name, status, suffix)
  return { env: environment, shouldBreak: false, status }
}

export async function dryRunRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  printRecipeHeader(recipeModule.name)
  let aggregatedStatus: "changed" | "ok" = "ok"
  let currentEnvironment = environment

  for (const childModule of recipeModule._modules) {
    // eslint-disable-next-line no-await-in-loop
    const result = await executeDryRunChildModule(childModule, currentEnvironment, ssh)
    if (result.shouldBreak) return result
    currentEnvironment = result.env
    if (result.status === "changed") aggregatedStatus = "changed"
  }

  return { env: currentEnvironment, shouldBreak: false, status: aggregatedStatus }
}
