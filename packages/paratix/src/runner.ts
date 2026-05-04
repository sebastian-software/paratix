/* eslint-disable max-lines -- central runner orchestration stays intentionally co-located */
import type { RecipeModule } from "./recipe.js"
import type {
  Environment,
  Module,
  ModuleResult,
  ModuleStatus,
  OrchestrationStep,
  ServerDefinition,
} from "./types.js"

import { dryRunRecipeModule } from "./dryRunRecipe.js"
import { loadDotEnvironment, mergeEnvironment } from "./environment.js"
import {
  assertValidModuleMetaEntries,
  isSshdPortMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
} from "./meta.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  printRunContext,
  printSummary,
  startModuleSpinner,
  stopLiveModuleOutput,
} from "./output.js"
import { setRunnerAbortSignal } from "./runnerAbortSignal.js"
import { resolveExitCode, signalExitCode } from "./runnerHelpers.js"
import { clearRegisteredSecrets } from "./secretSink.js"
import { getSignalBus, type SignalName } from "./signalBus.js"
import { runSignalModules, type SignalRunStatus } from "./signalOrchestration.js"
import { SshConnectionImpl } from "./ssh.js"

/** Holds the shutdown listener, SSH setter, and getter for the first received signal. */
type ShutdownState = {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  promptAbortSignal: AbortSignal
  setSsh: (connection: SshConnectionImpl) => void
  shutdownSignal: () => NodeJS.Signals | null
}

/**
 * Registers shutdown handlers.
 * @returns The listener state and first-signal getter.
 */
function setupShutdownHandlers(): ShutdownState {
  let receivedSignal: NodeJS.Signals | null = null
  let ssh: null | SshConnectionImpl = null
  const promptAbortController = new AbortController()

  const handleShutdownSignal = (signal: NodeJS.Signals): void => {
    if (receivedSignal != null) {
      // eslint-disable-next-line node/no-process-exit
      process.exit(signalExitCode(signal))
    }
    receivedSignal = signal
    promptAbortController.abort(new Error(`Terminal prompt interrupted by ${signal}`))
    stopLiveModuleOutput(true)
    console.error(`\nReceived ${signal}, shutting down…`)
    ssh?.disconnect()
  }

  getSignalBus().on("SIGINT", handleShutdownSignal as (signal: SignalName) => void)
  getSignalBus().on("SIGTERM", handleShutdownSignal as (signal: SignalName) => void)

  return {
    handleShutdownSignal,
    promptAbortSignal: promptAbortController.signal,
    setSsh: (connection: SshConnectionImpl) => {
      ssh = connection
    },
    shutdownSignal: () => receivedSignal,
  }
}

export type RunOptions = {
  /** When `true`, modules report what would change without applying anything. Defaults to `false`. */
  dryRun?: boolean
  /** Path to a `.env` file whose variables are merged into the run environment. */
  envFile?: string
  /** Additional environment variables that override values from `envFile` and the server definition. */
  envOverrides?: Environment
  /** Custom reconnect timeout in milliseconds passed to SSH, overriding the config default. */
  reconnectTimeout?: number
  /** When `true`, failed commands print full stdout/stderr in addition to the summary error. */
  verbose?: boolean
}

class RunStats {
  public changed = 0
  public failed = 0
  public ok = 0
  public signals = 0
  public skipped = 0

  public incrementSignals(): void {
    this.signals++
  }

  public update(status: ModuleStatus): void {
    switch (status) {
      case "changed": {
        this.changed++
        break
      }
      case "failed": {
        this.failed++
        break
      }
      case "ok": {
        this.ok++
        break
      }
      case "skipped": {
        this.skipped++
        break
      }
    }
  }
}

type StepResult = {
  env: Environment
  flushSignals?: true
  shouldBreak: boolean
  status?: ModuleStatus
  stopRun?: true
}

function interruptedStepResult(environment: Environment): StepResult {
  return { env: environment, shouldBreak: true }
}

function shouldBreakAfterResult(result: Pick<ModuleResult, "_stopRun" | "status">): boolean {
  return result.status === "failed" || result._stopRun === true
}

function interruptedBeforeApply(
  environment: Environment,
  shutdownSignal: () => NodeJS.Signals | null
): StepResult | undefined {
  if (shutdownSignal() == null) return undefined
  return interruptedStepResult(environment)
}

async function applyCheckedModule(parameters: {
  currentEnvironment: Environment
  dryRun?: boolean
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}): Promise<StepResult> {
  const interrupted = interruptedBeforeApply(
    parameters.currentEnvironment,
    parameters.shutdownSignal
  )
  if (interrupted != null) return interrupted

  return applyModule({
    currentEnvironment: parameters.currentEnvironment,
    dryRun: parameters.dryRun,
    ssh: parameters.ssh,
    targetModule: parameters.targetModule,
    verbose: parameters.verbose,
  })
}

function shouldExecuteApplyDuringDryRun(module: Module): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

function handleCaughtStepError(parameters: {
  environment: Environment
  error: unknown
  moduleName: string
  shutdownSignal: () => NodeJS.Signals | null
  verbose: boolean
}): StepResult {
  if (parameters.shutdownSignal() != null) {
    return interruptedStepResult(parameters.environment)
  }
  printModuleResult(parameters.moduleName, "failed")
  printCommandFailure(parameters.error, parameters.verbose)
  return { env: parameters.environment, shouldBreak: true, status: "failed" }
}

function isRecipe(target: Module): target is RecipeModule {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- RecipeModule uses _isRecipe as discriminator
  return "_isRecipe" in target && (target as RecipeModule)._isRecipe
}

function addSshdPorts(ssh: SshConnectionImpl, metaEntries: ModuleResult["meta"]): number[] {
  const portEntries = metaEntries?.filter((entry) => isSshdPortMetaEntry(entry)) ?? []
  const addedPorts: number[] = []
  for (const portEntry of portEntries) {
    if (ssh.addPort(portEntry.port)) {
      addedPorts.push(portEntry.port)
    }
  }
  return addedPorts
}

function hasSshdPortMeta(metaEntries: ModuleResult["meta"]): boolean {
  return metaEntries?.some((entry) => isSshdPortMetaEntry(entry)) ?? false
}

async function initializeEnvironment(
  options: RunOptions,
  definition: ServerDefinition
): Promise<Environment> {
  const dotEnvironment =
    options.envFile == null ? undefined : await loadDotEnvironment(options.envFile)
  return mergeEnvironment({}, dotEnvironment, definition.env, options.envOverrides)
}

async function handlePortChange(
  ssh: SshConnectionImpl,
  metaEntries: ModuleResult["meta"]
): Promise<void> {
  if (!hasSshdPortMeta(metaEntries)) return
  const addedPorts = addSshdPorts(ssh, metaEntries)

  // Skip reconnect when a reboot is pending — the reboot handler will
  // reconnect on all registered ports (including the newly added ones).
  if (metaEntries?.some((entry) => isSystemRebootMetaEntry(entry)) ?? false) return

  try {
    await ssh.reconnect()
  } catch (error) {
    // Roll back the optimistic addPort calls so the failed ports do not stick
    // in runtime.ports for any subsequent reuse of the connection. Mirrors
    // the rollback behavior in modules/sshd.ts:applySshdPort.
    for (const port of addedPorts) ssh.removePort(port)
    const portList = addedPorts.join(", ")
    console.error(
      `Failed to reconnect on port(s) ${portList} after port change: ${String(error)}. ` +
        `Verify that port(s) ${portList} are allowed by the server's firewall rules.`
    )
    throw error
  }
}

async function handleReboot(
  ssh: SshConnectionImpl,
  metaEntries: ModuleResult["meta"]
): Promise<void> {
  if (!(metaEntries?.some((entry) => isSystemRebootMetaEntry(entry)) ?? false)) return

  const hostEntry = metaEntries?.find((entry) => isSystemHostMetaEntry(entry))
  if (hostEntry != null) {
    ssh.updateHost(hostEntry.host)
  }

  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(`Failed to reconnect after reboot: ${String(error)}`)
    throw error
  }
}

async function applyRunnerControlPlaneMeta(
  ssh: SshConnectionImpl,
  step: Pick<OrchestrationStep, "meta">
): Promise<void> {
  if (step.meta == null) return
  assertValidModuleMetaEntries(step.meta)
  await handlePortChange(ssh, step.meta)
  await handleReboot(ssh, step.meta)
}

async function handleMetaAndBuildResult(
  ssh: SshConnectionImpl,
  environment: Environment,
  result: ModuleResult
): Promise<StepResult> {
  let currentEnvironment = environment

  if (result.meta != null) {
    currentEnvironment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
    await applyRunnerControlPlaneMeta(ssh, { meta: result.meta })
  }

  return {
    env: currentEnvironment,
    flushSignals: result._flushSignals,
    shouldBreak: shouldBreakAfterResult(result),
    status: result.status,
    stopRun: result._stopRun,
  }
}

// eslint-disable-next-line max-params -- verbose and dryRun flags need to be threaded through
async function runDryRunRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl,
  verbose: boolean
): Promise<StepResult> {
  return dryRunRecipeModule({
    environment,
    options: { verbose },
    recipeModule,
    ssh,
  })
}

// eslint-disable-next-line max-params -- verbose and dryRun flags need to be threaded through
async function runRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl,
  stats: RunStats,
  verbose: boolean,
  dryRun: boolean,
  shutdownSignal: () => NodeJS.Signals | null
): Promise<StepResult> {
  try {
    if (dryRun) return await runDryRunRecipeModule(recipeModule, environment, ssh, verbose)

    // check() iterates all child modules; apply() checks them again internally via executeModules().
    startModuleSpinner(recipeModule.name)
    const checkResult = await recipeModule.check(ssh, environment)
    if (checkResult === "ok") {
      printModuleResult(recipeModule.name, "ok")
      return { env: environment, shouldBreak: false, status: "ok" }
    }

    const result = await recipeModule.apply(ssh, environment, {
      onChildStep: async (step) => {
        await applyRunnerControlPlaneMeta(ssh, step)
      },
      onSignalStep: async (step) => {
        await applyRunnerControlPlaneMeta(ssh, step)
      },
      shutdownSignal,
      signalHooks: {
        onSignalFinished: (status: ModuleStatus) => {
          stats.update(status)
        },
        onSignalStarted: () => {
          stats.incrementSignals()
        },
      },
      verbose,
    })
    return await handleMetaAndBuildResult(ssh, environment, result)
  } catch (error) {
    return handleCaughtStepError({
      environment,
      error,
      moduleName: recipeModule.name,
      shutdownSignal,
      verbose,
    })
  }
}

async function applyModule(parameters: {
  currentEnvironment: Environment
  dryRun?: boolean
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}): Promise<StepResult> {
  const { currentEnvironment, dryRun = false, ssh, targetModule, verbose } = parameters
  const connection = targetModule.local === true ? null : ssh
  const result =
    dryRun && targetModule._applyDryRun != null
      ? await targetModule._applyDryRun(connection, currentEnvironment)
      : await targetModule.apply(connection, currentEnvironment)
  const stepResult = await handleMetaAndBuildResult(ssh, currentEnvironment, result)
  const detail = dryRun ? (result._dryRunDetail ?? "(dry-run)") : result.detail
  printModuleResult(targetModule.name, result.status, detail)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
  return stepResult
}

async function checkRegularModule(parameters: {
  env: Environment
  ssh: SshConnectionImpl
  targetModule: Module
}): Promise<"needs-apply" | "ok"> {
  const { env, ssh, targetModule } = parameters
  const connection = targetModule.local === true ? null : ssh
  startModuleSpinner(targetModule.name)
  return targetModule.check(connection, env)
}

function buildDryRunChangedResult(environment: Environment): StepResult {
  return { env: environment, shouldBreak: false, status: "changed" }
}

type RegularModuleArguments = {
  dryRun: boolean
  env: Environment
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}

async function runRegularModule(parameters: RegularModuleArguments): Promise<StepResult> {
  const { dryRun, env, ssh, targetModule, verbose } = parameters
  const shutdownSignal = parameters.shutdownSignal

  try {
    const checkResult = await checkRegularModule({ env, ssh, targetModule })

    if (checkResult === "ok") {
      printModuleResult(targetModule.name, "ok")
      return { env, shouldBreak: false, status: "ok" }
    }

    if (dryRun) {
      if (shouldExecuteApplyDuringDryRun(targetModule)) {
        return await applyCheckedModule({
          currentEnvironment: env,
          dryRun: true,
          shutdownSignal,
          ssh,
          targetModule,
          verbose,
        })
      }
      printModuleResult(targetModule.name, "changed", "(dry-run)")
      return buildDryRunChangedResult(env)
    }

    return await applyCheckedModule({
      currentEnvironment: env,
      dryRun: false,
      shutdownSignal,
      ssh,
      targetModule,
      verbose,
    })
  } catch (error) {
    return handleCaughtStepError({
      environment: env,
      error,
      moduleName: targetModule.name,
      shutdownSignal,
      verbose,
    })
  }
}

type LoopArguments = {
  definitionSignals?: Module[]
  dryRun: boolean
  env: Environment
  modules: Module[]
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

type ModuleLoopState = {
  currentEnvironment: Environment
  signalsPending: boolean
  stopRun?: true
}

function updateLoopSignalState(input: {
  currentSignalsPending: boolean
  result: StepResult
  stats: RunStats
}): boolean {
  if (input.result.status == null) return input.currentSignalsPending
  input.stats.update(input.result.status)
  return input.result.status === "changed" ? true : input.currentSignalsPending
}

function shouldFlushTopLevelSignals(input: {
  definitionSignals?: Module[]
  dryRun: boolean
  shutdownSignal: () => NodeJS.Signals | null
  signalsPending: boolean
  stats: RunStats
  stepResult: StepResult
}): input is {
  definitionSignals: Module[]
  dryRun: boolean
  shutdownSignal: () => NodeJS.Signals | null
  signalsPending: boolean
  stats: RunStats
  stepResult: { flushSignals: true } & StepResult
} {
  return (
    input.stepResult.flushSignals === true &&
    !input.dryRun &&
    input.shutdownSignal() == null &&
    input.signalsPending &&
    input.stats.failed === 0 &&
    input.definitionSignals != null
  )
}

async function flushPendingTopLevelSignals(input: {
  currentEnvironment: Environment
  definitionSignals: Module[]
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<SignalRunStatus> {
  return runSignals({
    env: input.currentEnvironment,
    shutdownSignal: input.shutdownSignal,
    signals: input.definitionSignals,
    ssh: input.ssh,
    stats: input.stats,
    verbose: input.verbose,
  })
}

function applyLoopResultToState(
  state: ModuleLoopState,
  result: StepResult,
  stats: RunStats
): ModuleLoopState {
  return {
    currentEnvironment: result.env,
    signalsPending: updateLoopSignalState({
      currentSignalsPending: state.signalsPending,
      result,
      stats,
    }),
    stopRun: result.stopRun === true ? true : state.stopRun,
  }
}

async function flushTopLevelSignalsIfRequested(parameters: {
  definitionSignals?: Module[]
  dryRun: boolean
  loopState: ModuleLoopState
  result: StepResult
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<{ nextSignalsPending: boolean; outcome: "break" | "continue" }> {
  if (
    !shouldFlushTopLevelSignals({
      definitionSignals: parameters.definitionSignals,
      dryRun: parameters.dryRun,
      shutdownSignal: parameters.shutdownSignal,
      signalsPending: parameters.loopState.signalsPending,
      stats: parameters.stats,
      stepResult: parameters.result,
    })
  ) {
    return { nextSignalsPending: parameters.loopState.signalsPending, outcome: "continue" }
  }
  const definitionSignals = parameters.definitionSignals
  if (definitionSignals == null) {
    return { nextSignalsPending: parameters.loopState.signalsPending, outcome: "continue" }
  }

  const signalStatus = await flushPendingTopLevelSignals({
    currentEnvironment: parameters.loopState.currentEnvironment,
    definitionSignals,
    shutdownSignal: parameters.shutdownSignal,
    ssh: parameters.ssh,
    stats: parameters.stats,
    verbose: parameters.verbose,
  })
  return {
    nextSignalsPending: false,
    outcome: signalStatus === "failed" ? "break" : "continue",
  }
}

async function createModuleStepPromise(parameters: {
  currentEnvironment: Environment
  currentModule: Module
  dryRun: boolean
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<StepResult> {
  const { currentEnvironment, currentModule, dryRun, shutdownSignal, ssh, stats, verbose } =
    parameters

  return isRecipe(currentModule)
    ? runRecipeModule(
        currentModule,
        currentEnvironment,
        ssh,
        stats,
        verbose,
        dryRun,
        shutdownSignal
      )
    : runRegularModule({
        dryRun,
        env: currentEnvironment,
        shutdownSignal,
        ssh,
        targetModule: currentModule,
        verbose,
      })
}

async function runModuleLoop(parameters: LoopArguments): Promise<{
  env: Environment
  signalsPending: boolean
  stopRun?: true
}> {
  const { definitionSignals, dryRun, modules, shutdownSignal, ssh, stats, verbose } = parameters
  const loopState: ModuleLoopState = {
    currentEnvironment: parameters.env,
    signalsPending: false,
    stopRun: undefined,
  }

  for (const currentModule of modules) {
    // A module already running when the signal arrived completes normally
    // and its result is still counted in stats before the loop exits here.
    if (shutdownSignal() != null) break
    const stepPromise = createModuleStepPromise({
      currentEnvironment: loopState.currentEnvironment,
      currentModule,
      dryRun,
      shutdownSignal,
      ssh,
      stats,
      verbose,
    })

    // eslint-disable-next-line no-await-in-loop
    const result = await stepPromise

    Object.assign(loopState, applyLoopResultToState(loopState, result, stats))
    // eslint-disable-next-line no-await-in-loop
    const flushResult = await flushTopLevelSignalsIfRequested({
      definitionSignals,
      dryRun,
      loopState,
      result,
      shutdownSignal,
      ssh,
      stats,
      verbose,
    })
    loopState.signalsPending = flushResult.nextSignalsPending
    if (flushResult.outcome === "break") break
    if (result.shouldBreak) break
  }

  return {
    env: loopState.currentEnvironment,
    signalsPending: loopState.signalsPending,
    stopRun: loopState.stopRun,
  }
}

type SignalArguments = {
  env: Environment
  shutdownSignal: () => NodeJS.Signals | null
  signals: Module[]
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function runSignals(parameters: SignalArguments): Promise<SignalRunStatus> {
  const { env, shutdownSignal, signals, ssh, stats, verbose } = parameters
  return runSignalModules({
    environment: env,
    hooks: {
      onSignalFinished: (status: ModuleStatus) => {
        stats.update(status)
      },
      onSignalStarted: () => {
        stats.incrementSignals()
      },
    },
    onSignalStep: async (step) => {
      await applyRunnerControlPlaneMeta(ssh, step)
    },
    shutdownSignal,
    signals,
    ssh,
    verbose,
  })
}

function throwIfShutdownRequested(shutdownSignal: () => NodeJS.Signals | null): void {
  const signal = shutdownSignal()
  if (signal == null) return
  throw new Error(`Bootstrap interrupted by ${signal}`)
}

async function connectAndRegister(parameters: {
  definition: ServerDefinition
  options: RunOptions
  promptAbortSignal: AbortSignal
  setSsh: (c: SshConnectionImpl) => void
  shutdownSignal: () => NodeJS.Signals | null
}): Promise<SshConnectionImpl> {
  const { definition, options, promptAbortSignal, setSsh, shutdownSignal } = parameters
  const sshConfig = {
    ...definition.ssh,
    ports: [...definition.ssh.ports],
    ...(options.reconnectTimeout == null ? {} : { reconnectTimeout: options.reconnectTimeout }),
  }
  const ssh = new SshConnectionImpl(definition.host, sshConfig)
  setSsh(ssh)
  throwIfShutdownRequested(shutdownSignal)
  await ssh.connect({ abortSignal: promptAbortSignal })
  throwIfShutdownRequested(shutdownSignal)
  return ssh
}

type ExecuteRunArguments = {
  definition: ServerDefinition
  dryRun: boolean
  environment: Environment
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function executeRun(parameters: ExecuteRunArguments): Promise<void> {
  const { definition, dryRun, environment, shutdownSignal, ssh, stats, verbose } = parameters

  printRecipeHeader(definition.name)
  const loopResult = await runModuleLoop({
    definitionSignals: definition.signals,
    dryRun,
    env: environment,
    modules: definition.run,
    shutdownSignal,
    ssh,
    stats,
    verbose,
  })
  const finalEnvironment = loopResult.env

  if (
    !dryRun &&
    shutdownSignal() == null &&
    loopResult.signalsPending &&
    stats.failed === 0 &&
    definition.signals != null
  )
    await runSignals({
      env: finalEnvironment,
      shutdownSignal,
      signals: definition.signals,
      ssh,
      stats,
      verbose,
    })

  printSummary(stats)
}

function rethrowIfNotShutdown(error: unknown, shutdownSignal: () => NodeJS.Signals | null): void {
  if (shutdownSignal() == null) throw error
}

/**
 * Tear down per-run resources: shutdown signal listeners, the runner abort
 * signal, the process-scoped secret sink, and the ssh connection. R-0000041:
 * `clearRegisteredSecrets` ensures op resolved values, sudo/user passwords,
 * and download URL tokens never bleed into a subsequent invocation that
 * shares the same Node process (e.g. tests, daemonized CLI).
 *
 * @param parameters - Cleanup context.
 * @param parameters.handleShutdownSignal - Listener installed for SIGINT/SIGTERM.
 * @param parameters.ssh - The SSH connection that may need disconnecting.
 */
function teardownPlaybookResources(parameters: {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  ssh: SshConnectionImpl | undefined
}): void {
  stopLiveModuleOutput(true)
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    getSignalBus().off(signal, parameters.handleShutdownSignal as (signal: SignalName) => void)
  setRunnerAbortSignal(undefined)
  clearRegisteredSecrets()
  parameters.ssh?.disconnect()
}

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  const { dryRun = false, verbose = false } = options
  const environment = await initializeEnvironment(options, definition)
  const { handleShutdownSignal, promptAbortSignal, setSsh, shutdownSignal } =
    setupShutdownHandlers()
  setRunnerAbortSignal(promptAbortSignal)
  const stats = new RunStats()
  let ssh: SshConnectionImpl | undefined

  printRunContext({
    dryRun,
    host: definition.host,
    name: definition.name,
    ports: definition.ssh.ports,
  })

  // No catch block: connect errors propagate to cli.ts, which prints them and exits with code 2.
  try {
    ssh = await connectAndRegister({
      definition,
      options,
      promptAbortSignal,
      setSsh,
      shutdownSignal,
    })
    await executeRun({ definition, dryRun, environment, shutdownSignal, ssh, stats, verbose })
  } catch (error) {
    rethrowIfNotShutdown(error, shutdownSignal)
  } finally {
    teardownPlaybookResources({ handleShutdownSignal, ssh })
  }

  resolveExitCode(shutdownSignal(), stats)
}
