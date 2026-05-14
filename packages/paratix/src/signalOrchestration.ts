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

export async function runSignalModules(parameters: SignalRunParameters): Promise<SignalRunStatus> {
  const getShutdownSignal = parameters.shutdownSignal ?? (() => null)
  const verbose = parameters.verbose ?? false
  let currentEnvironment = parameters.environment
  let status: SignalRunStatus = "changed"

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
      if (signalStep.status === "failed") status = "failed"
    } catch (error) {
      status = handleSignalFailure({
        error,
        hooks: parameters.hooks,
        signalName: signal.name,
        verbose,
      })
    }
  }

  return status
}
