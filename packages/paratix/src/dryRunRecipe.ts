import type { RecipeModule } from "./recipe.js"
import type { SshConnectionImpl } from "./ssh.js"
import type { Environment, ModuleStatus } from "./types.js"

import { printModuleResult, printRecipeHeader } from "./output.js"

type StepResult = { env: Environment; shouldBreak: boolean; status?: ModuleStatus }

export async function dryRunRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  printRecipeHeader(recipeModule.name)
  let aggregatedStatus: "changed" | "ok" = "ok"

  for (const childModule of recipeModule._modules) {
    const connection = childModule.local === true ? null : ssh
    // eslint-disable-next-line no-await-in-loop
    const checkResult = await childModule.check(connection, environment)
    const status = checkResult === "ok" ? "ok" : "changed"
    const suffix = checkResult === "ok" ? undefined : "(dry-run)"
    printModuleResult(childModule.name, status, suffix)
    if (status === "changed") aggregatedStatus = "changed"
  }

  return { env: environment, shouldBreak: false, status: aggregatedStatus }
}
