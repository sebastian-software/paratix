import type { RecipeModule } from "./recipe.js"
import type { Module } from "./types.js"

/**
 * Central type guard that narrows a {@link Module} to a {@link RecipeModule}
 * through the internal `kind` discriminator.
 *
 * This is the single source of truth for the recipe/leaf-module distinction;
 * the runner, the module filter and the dry-run paths all consume it instead of
 * repeating an unsafe structural cast on an ad-hoc marker. It is re-exported
 * from `recipe.ts`, which is where every consumer outside `dryRunRecipe.ts`
 * imports it from.
 *
 * The guard lives in its own module rather than in `recipe.ts` so that
 * `dryRunRecipe.ts` can import it as a *value* without creating a runtime
 * import cycle: `recipe.ts` already imports `dryRunRecipeModule` from
 * `dryRunRecipe.ts`, and the only edge back to `recipe.ts` from here is the
 * type-only import above, which is erased at build time.
 *
 * @param module - The module to inspect.
 * @returns `true` when `module` is a recipe exposing child `_modules`.
 */
export function isRecipe(module: Module): module is RecipeModule {
  return module.kind === "recipe"
}
