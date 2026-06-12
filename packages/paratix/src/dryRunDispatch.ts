import type { Module } from "./types.js"

/**
 * Decide whether the dry-run runner should execute a module's `_applyDryRun`
 * hook in addition to its `check()`.
 *
 * The decision is shared between the top-level runner loop
 * (`runner.runRegularModule`) and the recipe-scoped runner
 * (`dryRunRecipe.executeDryRunChildModule`). Centralizing it here keeps the
 * two paths in lockstep: a future marker tweak only needs one edit.
 *
 * Semantics:
 * - Modules marked as `_dryRunBlocker` (e.g. the first-run-stop module) or
 *   `_dryRunMetaProducer` (modules that emit downstream-visible meta even
 *   in dry-run mode) always run their `_applyDryRun` / `apply` so the
 *   blocker fires and meta keeps propagating.
 * - `_dryRunDiffProducer` modules only run their `_applyDryRun` when the
 *   user passed `--diff` (`diffEnabled === true`). Without `--diff`, the
 *   dry-run keeps its pre-existing behaviour and pays no extra remote
 *   round-trip.
 * - Modules that ship a custom `_applyDryRun` without any of the markers
 *   above keep the legacy behaviour: their hook always runs (e.g. the
 *   sshd module's config validation has to run regardless of `--diff`).
 *
 * @param module - The candidate module.
 * @param diffEnabled - Whether the user passed `--diff` on the CLI.
 * @returns `true` when the runner should dispatch `_applyDryRun` (or
 *   `apply` as the fallback path) instead of treating the module as a
 *   passive `changed (dry-run)` result.
 */
export function shouldExecuteApplyDuringDryRun(module: Module, diffEnabled: boolean): boolean {
  if (module._dryRunBlocker === true || module._dryRunMetaProducer === true) return true
  if (diffEnabled && module._dryRunDiffProducer === true && module._applyDryRun != null) return true
  return module._applyDryRun != null && module._dryRunDiffProducer !== true
}
