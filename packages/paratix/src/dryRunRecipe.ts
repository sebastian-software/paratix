import type { RecipeModule } from "./recipe.js"
import type { SshConnectionImpl } from "./ssh.js"
import type { Environment, ModuleStatus } from "./types.js"

import { printCommandFailure, printModuleResult, printRecipeHeader } from "./output.js"

type StepResult = { env: Environment; shouldBreak: boolean; status?: ModuleStatus }

function isDryRunBlockingModule(module: RecipeModule["_modules"][number]): boolean {
  return module._dryRunBlocker === true
}

async function executeDryRunBlockingModule(
  childModule: RecipeModule["_modules"][number],
  connection: null | SshConnectionImpl,
  environment: Environment
): Promise<StepResult> {
  const result = await childModule.apply(connection, environment)
  printModuleResult(childModule.name, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, false)
  }
  return { env: environment, shouldBreak: result.status === "failed", status: result.status }
}

async function executeDryRunChildModule(
  childModule: RecipeModule["_modules"][number],
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  const connection = childModule.local === true ? null : ssh
  const checkResult = await childModule.check(connection, environment)
  if (checkResult !== "ok" && isDryRunBlockingModule(childModule)) {
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

  for (const childModule of recipeModule._modules) {
    // eslint-disable-next-line no-await-in-loop
    const result = await executeDryRunChildModule(childModule, environment, ssh)
    if (result.shouldBreak) return result
    if (result.status === "changed") aggregatedStatus = "changed"
  }

  return { env: environment, shouldBreak: false, status: aggregatedStatus }
}
