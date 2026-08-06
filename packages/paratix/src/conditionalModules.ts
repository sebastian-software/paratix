import { applyConditionalModules, getConditionalChildConnection } from "./conditionalExecution.js"
import { createNullPrototypeEnvironment } from "./environment.js"
import { hasSecretPrewarmCarriers, prewarmSecrets } from "./secretPrewarm.js"
import {
  type Environment,
  type Module,
  type ModuleApplyOptions,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

async function checkConditionalModules(
  modules: Module[],
  ssh: null | SshConnection,
  environment: Environment
): Promise<"needs-apply" | "ok"> {
  // R-0000087: same null-prototype preservation as createConditionalApplyState
  // for the check-side traversal of when(...) guards.
  const currentEnvironment = Object.assign(createNullPrototypeEnvironment(), environment)
  for (const currentModule of modules) {
    const connection = getConditionalChildConnection(currentModule, ssh)
    // eslint-disable-next-line no-await-in-loop
    const result = await currentModule.check(connection, currentEnvironment)
    if (result === NEEDS_APPLY) {
      return NEEDS_APPLY
    }
  }
  return "ok"
}

type Condition = (ssh: null | SshConnection, environment: Environment) => boolean | Promise<boolean>

/**
 * Build a conditional ("when") module that runs its children only while the
 * guard condition holds.
 *
 * The module always exposes `_applyDryRun`. Unlike a recipe, a guarded block is
 * not reachable through `isRecipe`, so its caller decides via
 * `shouldExecuteApplyDuringDryRun` whether to descend at all — a block without
 * the hook would collapse into a single anonymous `changed (dry-run)` line and
 * never reach its own output layer.
 *
 * @param parameters - Guard condition, guarded modules and display name.
 * @param parameters.condition - Guard predicate evaluated at run time.
 * @param parameters.modules - The guarded child modules.
 * @param parameters.name - Display name shown in the run output.
 * @returns A module that conditionally runs and itemizes the inner modules.
 */
export function createConditionalModule(parameters: {
  condition: Condition
  modules: Module[]
  name: string
}): Module {
  // Memo for the guard result of the current run.
  //
  // Rendering a false guard as `skipped` requires reaching `apply`, so `check`
  // has to report NEEDS_APPLY for it. Guard conditions are remote (`ssh.test`;
  // `when.packageInstalled` additionally runs package-manager detection plus a
  // package query), so re-evaluating the condition inside `apply` would double
  // the remote round trips of every false guard in a run.
  //
  // `check` therefore writes its freshly evaluated result here on *every*
  // invocation and `apply` reads it. All three call paths — recipe's
  // `executeOneModule`, the runner's `runRegularModule` and
  // `applyConditionalApplyStep` — evaluate `check` immediately before `apply`,
  // so the memo always describes the current run and can never survive into a
  // later one. A throwing condition propagates out of `check` and writes
  // nothing. The apply side never writes, so a direct `apply()` without a
  // preceding `check()` keeps evaluating the condition itself.
  let checkedCondition: boolean | undefined

  const evaluateConditionForCheck = async (
    ssh: null | SshConnection,
    environment: Environment
  ): Promise<boolean> => {
    const result = await parameters.condition(ssh, environment)
    checkedCondition = result
    return result
  }

  const readConditionForApply = async (
    ssh: null | SshConnection,
    environment: Environment
  ): Promise<boolean> => {
    if (checkedCondition != null) return checkedCondition
    return parameters.condition(ssh, environment)
  }

  const conditionalModule: Module = {
    async _applyDryRun(
      ssh: null | SshConnection,
      environment: Environment,
      options?: ModuleApplyOptions
    ): Promise<ModuleResult> {
      if (!(await readConditionForApply(ssh, environment))) {
        return { status: "skipped" }
      }
      return applyConditionalModules({
        diff: options?.diff,
        dryRun: true,
        environment,
        modules: parameters.modules,
        name: parameters.name,
        shutdownSignal: options?.shutdownSignal,
        ssh,
        verbose: options?.verbose,
      })
    },
    _supportsChildStepHook: true as const,
    async apply(
      ssh: null | SshConnection,
      environment: Environment,
      options?: ModuleApplyOptions
    ): Promise<ModuleResult> {
      if (!(await readConditionForApply(ssh, environment))) {
        return { status: "skipped" }
      }
      return applyConditionalModules({
        environment,
        modules: parameters.modules,
        name: parameters.name,
        onChildStep: options?.onChildStep,
        shutdownSignal: options?.shutdownSignal,
        ssh,
      })
    },
    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      if (!(await evaluateConditionForCheck(ssh, environment))) {
        // NEEDS_APPLY, not "ok": the run has to reach apply() so the block
        // renders a single `skipped` line and the summary counts it as a skip
        // instead of silently reporting it as already ok.
        return NEEDS_APPLY
      }
      return checkConditionalModules(parameters.modules, ssh, environment)
    },
    name: parameters.name,
  }

  // The hook is attached only when the guarded children can actually contribute
  // a secret. The child list is fixed at construction time, so the question is
  // answered once, here — not per run.
  //
  // Attaching it unconditionally would turn every `when(...)` into a secret
  // carrier: a playbook without a single secret module would print the
  // "resolving secrets" status line before a run that never calls a provider,
  // and `--filter` would warn about lost secrets that never existed. A nested
  // `when(...)` composes correctly because the inner block is built before the
  // outer one and therefore already carries (or lacks) its own hook.
  if (hasSecretPrewarmCarriers(parameters.modules)) {
    conditionalModule._prewarmSecrets = async (): Promise<void> => {
      // The guarded children stay encapsulated in this closure, so the runner's
      // tree walk cannot reach them; the block delegates on their behalf
      // instead of exposing a public `_modules` surface for guarded blocks.
      //
      // The guard condition is deliberately NOT evaluated here: it is answered
      // remotely and no connection exists yet at this point in the run. A
      // secret inside a branch whose condition later turns out to be `false` is
      // therefore resolved although nobody consumes it — the accepted price for
      // the guarantee that no provider prompt can appear mid-run.
      await prewarmSecrets(parameters.modules)
    }
  }

  return conditionalModule
}
