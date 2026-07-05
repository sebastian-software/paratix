import type { RecipeModule } from "./recipe.js"
import type { Module, ModuleResult } from "./types.js"

import { recipe } from "./recipe.js"
import { NEEDS_APPLY } from "./types.js"

/**
 * Detail shown next to the `skipped` status of a filtered-out node during a
 * dry-run. Without a `_dryRunDetail` the runner would fall back to the generic
 * `(dry-run)` suffix; this makes clear why the node reports `skipped`.
 */
const SKIP_DRY_RUN_DETAIL = "filtered out"

/**
 * Narrow a {@link Module} to a {@link RecipeModule}.
 *
 * A local `_isRecipe` check is used on purpose instead of importing the
 * `isRecipe` helper from `runner.ts`: it keeps `moduleFilter.ts` free of a
 * dependency on the runner and avoids an import cycle, while relying on the
 * same discriminator the runner and recipe modules already expose.
 *
 * @param module - The module to inspect.
 * @returns `true` when `module` is a recipe that exposes child `_modules`.
 */
function isRecipeModule(module: Module): module is RecipeModule {
  return (module as { _isRecipe?: boolean } & Module)._isRecipe === true
}

/**
 * Split, trim, and de-duplicate the raw `--filter` values collected by the CLI.
 *
 * Each raw value may itself be a comma-separated list (`"a,b"`), and the option
 * may be repeated (`--filter a --filter b`), so both forms are flattened into a
 * single ordered list. Empty and whitespace-only entries are dropped;
 * duplicates are removed while preserving first-seen order.
 *
 * @param rawValues - The accumulated raw option values from Commander.
 * @returns The normalized, de-duplicated list of filter names.
 */
export function parseFilterNames(rawValues: string[]): string[] {
  const names: string[] = []
  const seen = new Set<string>()
  for (const rawValue of rawValues) {
    for (const part of rawValue.split(",")) {
      const name = part.trim()
      if (name === "" || seen.has(name)) continue
      seen.add(name)
      names.push(name)
    }
  }
  return names
}

/**
 * Collect the names of every node in `modules`, descending recursively into
 * recipe children. Used to validate that each requested filter name actually
 * matches a node before the run connects.
 *
 * @param modules - The top-level module list to walk.
 * @returns A set containing every recipe and leaf-module name in the tree.
 */
export function collectModuleNames(modules: Module[]): Set<string> {
  const names = new Set<string>()
  const visit = (module: Module): void => {
    names.add(module.name)
    if (isRecipeModule(module)) {
      for (const child of module._modules) visit(child)
    }
  }
  for (const module of modules) visit(module)
  return names
}

/**
 * Determine whether `module` itself or any of its descendants matches the
 * filter. Drives the decision to descend into an otherwise unselected recipe.
 *
 * @param module - The node to inspect.
 * @param filter - The set of requested filter names.
 * @returns `true` when the node or a descendant is named in `filter`.
 */
export function subtreeHasFilterMatch(module: Module, filter: ReadonlySet<string>): boolean {
  if (filter.has(module.name)) return true
  if (isRecipeModule(module)) {
    return module._modules.some((child) => subtreeHasFilterMatch(child, filter))
  }
  return false
}

/**
 * Build a synthetic module that renders as `skipped` without any side effect.
 *
 * `check()` returns {@link NEEDS_APPLY} on purpose so that a rebuilt "descend"
 * recipe containing skip modules never short-circuits on an aggregate `ok`
 * check and always renders its children (including the skip lines). The
 * `_dryRunBlocker` marker plus `_applyDryRun` make the node report `skipped`
 * during a dry-run instead of the default `changed (dry-run)`.
 *
 * @param name - The display name of the node being skipped.
 * @returns A module that prints a single `skipped` row and mutates nothing.
 */
export function createSkipModule(name: string): Module {
  return {
    async _applyDryRun(): Promise<ModuleResult> {
      await Promise.resolve()
      return { _dryRunDetail: SKIP_DRY_RUN_DETAIL, status: "skipped" }
    },
    _dryRunBlocker: true,
    async apply(): Promise<ModuleResult> {
      await Promise.resolve()
      return { status: "skipped" }
    },
    async check(): Promise<"needs-apply" | "ok"> {
      await Promise.resolve()
      return NEEDS_APPLY
    },
    local: true,
    name,
  }
}

/**
 * Map a single node according to the selection rule, given whether an ancestor
 * was already selected.
 *
 * - Selected (ancestor selected or own name matches) → keep the node unchanged
 *   so its whole subtree runs.
 * - Not selected but a recipe with a matching descendant → rebuild the recipe
 *   from filtered children so the run descends into it. The original signals
 *   are preserved; the dry-run markers are re-derived by {@link recipe} from
 *   the filtered children.
 * - Otherwise → replace the node with a skip module.
 *
 * @param module - The node to transform.
 * @param filter - The set of requested filter names.
 * @param ancestorSelected - Whether a parent node was already selected.
 * @returns The original node, a rebuilt descend recipe, or a skip module.
 */
function filterNode(
  module: Module,
  filter: ReadonlySet<string>,
  ancestorSelected: boolean
): Module {
  const selfSelected = ancestorSelected || filter.has(module.name)
  if (selfSelected) return module

  if (isRecipeModule(module) && subtreeHasFilterMatch(module, filter)) {
    const filteredChildren = module._modules.map((child) => filterNode(child, filter, false))
    return recipe(module.name, filteredChildren, { signals: module._signals })
  }

  return createSkipModule(module.name)
}

/**
 * Transform a top-level module list into a filtered list: selected subtrees are
 * kept by reference, partially matched recipes are rebuilt from filtered
 * children, and every other node is replaced by a skip module.
 *
 * The input modules are never mutated; a new array with the same length is
 * returned so the top-level `run` array is never emptied by filtering.
 *
 * @param modules - The original top-level module list.
 * @param filter - The set of requested filter names.
 * @returns A new module list with skips and descend recipes applied.
 */
export function applyModuleFilter(modules: Module[], filter: ReadonlySet<string>): Module[] {
  return modules.map((module) => filterNode(module, filter, false))
}
