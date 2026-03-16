import type { RecipeModule } from "./recipe.js"
import type { Environment } from "./types.js"

import { printModuleResult, printRecipeHeader } from "./output.js"
import type { SshConnectionImpl } from "./ssh.js"

type StepResult = { env: Environment; shouldBreak: boolean; status?: string }

export async function dryRunRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  printRecipeHeader(recipeModule.name)
  let aggregatedStatus: "changed" | "ok" = "ok"

  for (const childModule of recipeModule._modules) {
    // eslint-disable-next-line no-await-in-loop
    const checkResult = await childModule.check(ssh, environment)
    const status = checkResult === "ok" ? "ok" : "changed"
    const suffix = checkResult === "ok" ? undefined : "(dry-run)"
    printModuleResult(childModule.name, status, suffix)
    if (status === "changed") aggregatedStatus = "changed"
  }

  return { env: environment, shouldBreak: false, status: aggregatedStatus }
}
