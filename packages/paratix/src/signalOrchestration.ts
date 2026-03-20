import type { Environment, Module, ModuleStatus, SshConnection } from "./types.js"

import { printCommandFailure, printModuleResult } from "./output.js"

export type SignalHooks = {
  onSignalFinished?: (status: ModuleStatus) => void
  onSignalStarted?: () => void
}

export type SignalRunStatus = "changed" | "failed"

type SignalRunParameters = {
  environment: Environment
  hooks?: SignalHooks
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

export async function runSignalModules(parameters: SignalRunParameters): Promise<SignalRunStatus> {
  const getShutdownSignal = parameters.shutdownSignal ?? (() => null)
  const verbose = parameters.verbose ?? false
  let status: SignalRunStatus = "changed"

  for (const signal of parameters.signals) {
    if (getShutdownSignal() != null) break
    parameters.hooks?.onSignalStarted?.()
    try {
      const connection = signal.local === true ? null : parameters.ssh
      // eslint-disable-next-line no-await-in-loop
      const result = await signal.apply(connection, parameters.environment)
      const signalStatus = handleSignalResult({
        hooks: parameters.hooks,
        result,
        signalName: signal.name,
        verbose,
      })
      if (signalStatus === "failed") status = "failed"
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
