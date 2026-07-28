import type {
  Environment,
  Module,
  ModuleStatus,
  OrchestrationStep,
  SshConnection,
} from "./types.js"

import { assertValidModuleMetaEntries, mergeEnvironmentFromMeta } from "./meta.js"
import { printCommandFailure, printModuleResult, startModuleSpinner } from "./output.js"

export type SignalHooks = {
  onSignalFinished?: (status: ModuleStatus) => void
  onSignalStarted?: () => void
}

export type SignalRunStatus = "changed" | "failed"

type SignalRunParameters = {
  environment: Environment
  hooks?: SignalHooks
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => NodeJS.Signals | null
  signals: Module[]
  ssh: null | SshConnection
  verbose?: boolean
}

function handleSignalResult(parameters: {
  hooks?: SignalHooks
  result: Awaited<ReturnType<Module["apply"]>>
  signalName: string
  verbose: boolean
}): SignalRunStatus {
  const { hooks, result, signalName, verbose } = parameters
  printModuleResult(`signal: ${signalName}`, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
  hooks?.onSignalFinished?.(result.status)
  return result.status === "failed" ? "failed" : "changed"
}

function handleSignalFailure(parameters: {
  error: unknown
  hooks?: SignalHooks
  signalName: string
  verbose: boolean
}): SignalRunStatus {
  const { error, hooks, signalName, verbose } = parameters
  printModuleResult(`signal: ${signalName}`, "failed")
  printCommandFailure(error, verbose)
  hooks?.onSignalFinished?.("failed")
  return "failed"
}

async function applySignalMeta(parameters: {
  currentEnvironment: Environment
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  result: Awaited<ReturnType<Module["apply"]>>
}): Promise<Environment> {
  assertValidModuleMetaEntries(parameters.result.meta)
  const nextEnvironment =
    parameters.result.status === "failed"
      ? parameters.currentEnvironment
      : await mergeEnvironmentFromMeta(parameters.currentEnvironment, parameters.result.meta)
  await parameters.onSignalStep?.({
    env: nextEnvironment,
    meta: parameters.result.meta,
    status: parameters.result.status,
  })
  return nextEnvironment
}

async function runOneSignal(parameters: {
  currentEnvironment: Environment
  hooks?: SignalHooks
  onSignalStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => NodeJS.Signals | null
  signal: Module
  ssh: null | SshConnection
  verbose: boolean
}): Promise<{ nextEnvironment: Environment; status: SignalRunStatus }> {
  const connection = parameters.signal.local === true ? null : parameters.ssh
  startModuleSpinner(`signal: ${parameters.signal.name}`)
  const result =
    parameters.shutdownSignal == null
      ? await parameters.signal.apply(connection, parameters.currentEnvironment)
      : await parameters.signal.apply(connection, parameters.currentEnvironment, {
          shutdownSignal: parameters.shutdownSignal,
        })
  const nextEnvironment = await applySignalMeta({
    currentEnvironment: parameters.currentEnvironment,
    onSignalStep: parameters.onSignalStep,
    result,
  })
  return {
    nextEnvironment,
    status: handleSignalResult({
      hooks: parameters.hooks,
      result,
      signalName: parameters.signal.name,
      verbose: parameters.verbose,
    }),
  }
}

/**
 * Run a signal list, stopping at the first failed signal.
 *
 * A failed signal aborts the remaining signals of *this* list, the same way a
 * failed child aborts the remaining steps of a recipe. Continuing here used to
 * turn a single failed step into an inconsistent host: when one container of a
 * Quadlet stack could not be replaced, its siblings were still recreated, which
 * left the stack split across the old and the new state and did not heal on a
 * re-run.
 *
 * The abort is scoped to this list. Whether the enclosing recipe or run also
 * stops is decided by their existing post-list handling, so a separate signal
 * list is not suppressed from here.
 *
 * @param parameters - The signal list plus its environment, connection, hooks
 *   and shutdown probe.
 * @returns `"failed"` when any signal failed, otherwise `"changed"`.
 */
export async function runSignalModules(parameters: SignalRunParameters): Promise<SignalRunStatus> {
  const getShutdownSignal = parameters.shutdownSignal ?? (() => null)
  const verbose = parameters.verbose ?? false
  let currentEnvironment = parameters.environment

  for (const signal of parameters.signals) {
    if (getShutdownSignal() != null) break
    parameters.hooks?.onSignalStarted?.()
    try {
      // eslint-disable-next-line no-await-in-loop
      const signalStep = await runOneSignal({
        currentEnvironment,
        hooks: parameters.hooks,
        onSignalStep: parameters.onSignalStep,
        shutdownSignal: parameters.shutdownSignal,
        signal,
        ssh: parameters.ssh,
        verbose,
      })
      currentEnvironment = signalStep.nextEnvironment
      if (signalStep.status === "failed") return "failed"
    } catch (error) {
      return handleSignalFailure({
        error,
        hooks: parameters.hooks,
        signalName: signal.name,
        verbose,
      })
    }
  }

  return "changed"
}
