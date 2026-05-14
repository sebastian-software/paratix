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
import { validateServerDefinition } from "./server.js"
import { getSignalBus } from "./signalBus.js"
import { runSignalModules, type SignalRunStatus } from "./signalOrchestration.js"
import { SshConnectionImpl } from "./ssh.js"

/** Holds the shutdown listener, SSH setter, and getter for the first received signal. */
type ShutdownState = {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  promptAbortSignal: AbortSignal
  setSsh: (connection: SshConnectionImpl) => void
  /**
   * R-0000203: AbortSignal that fires the instant SIGINT/SIGTERM is observed,
   * so cooperative waits like {@link sleepRespectingShutdown} can return early
   * without polling.
   */
  shutdownAbortSignal: AbortSignal
  shutdownSignal: () => NodeJS.Signals | null
}

/** ASCII ESC byte (0x1B) used to start ANSI/VT100 control sequences. */
const ASCII_ESC = 0x1b

/**
 * ANSI escape sequence "ESC [ ? 25 h" that re-enables the terminal cursor
 * after a spinner or prompt may have hidden it via "[?25l".
 */
const ANSI_SHOW_CURSOR = `${String.fromCharCode(ASCII_ESC)}[?25h`

/**
 * Best-effort terminal/secret cleanup performed before `process.exit` on a
 * second SIGINT/SIGTERM. Each step is wrapped in a try/catch so a failure in
 * one step never prevents the others from running.
 */
function performShutdownBestEffortCleanup(): void {
  try {
    stopLiveModuleOutput(true)
  } catch {
    // ignore: cleanup is best-effort
  }
  try {
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false)
    }
  } catch {
    // ignore: not all streams support raw mode
  }
  try {
    process.stdout.write(ANSI_SHOW_CURSOR)
  } catch {
    // ignore: stdout may already be closed
  }
  try {
    clearRegisteredSecrets()
  } catch {
    // ignore: secret sink should never throw, but guard defensively
  }
}

/**
 * Registers shutdown handlers.
 * @returns The listener state and first-signal getter.
 */
function setupShutdownHandlers(): ShutdownState {
  let receivedSignal: NodeJS.Signals | null = null
  let ssh: null | SshConnectionImpl = null
  const promptAbortController = new AbortController()
  // R-0000203: dedicated controller for cooperative waits (e.g. the reboot
  // grace sleep). Abort fires synchronously when SIGINT/SIGTERM arrives, so
  // active sleeps end immediately instead of running their full duration.
  const shutdownAbortController = new AbortController()

  const handleShutdownSignal = (signal: NodeJS.Signals): void => {
    if (receivedSignal != null) {
      // A second signal forces a hard exit. Run best-effort cleanup first so
      // the terminal is not left in raw mode / cursor hidden, and so the
      // secret sink does not retain registered values.
      performShutdownBestEffortCleanup()
      // eslint-disable-next-line node/no-process-exit
      process.exit(signalExitCode(signal))
    }
    receivedSignal = signal
    promptAbortController.abort(new Error(`Terminal prompt interrupted by ${signal}`))
    shutdownAbortController.abort(new Error(`Runner sleep interrupted by ${signal}`))
    stopLiveModuleOutput(true)
    console.error(`\nReceived ${signal}, shutting down…`)
    // R-0000257: defer ssh.disconnect() to a microtask. The signal handler
    // runs synchronously inside Node's signal dispatch and disconnect ->
    // disconnectTransport iterates pendingRejects, which calls reject
    // handlers that may reentrantly invoke ssh2 stream internals. ssh2
    // assumes coherent event-loop tick lifetimes and reentrant stream
    // access is a known crash source. Returning to the next microtask
    // first lets the signal handler complete cleanly and lets ssh2
    // process any in-flight events before teardown begins.
    const sshToDisconnect = ssh
    queueMicrotask(() => {
      sshToDisconnect?.disconnect()
    })
  }

  getSignalBus().on("SIGINT", handleShutdownSignal)
  getSignalBus().on("SIGTERM", handleShutdownSignal)

  return {
    handleShutdownSignal,
    promptAbortSignal: promptAbortController.signal,
    setSsh(connection: SshConnectionImpl) {
      ssh = connection
    },
    shutdownAbortSignal: shutdownAbortController.signal,
    shutdownSignal: () => receivedSignal,
  }
}

/**
 * Exposed for tests to observe the second-signal cleanup path without
 * spawning a real process.
 */
export const __testing = {
  performShutdownBestEffortCleanup,
}

export type RunOptions = {
  /** When `true`, modules report what would change without applying anything. Defaults to `false`. */
  dryRun?: boolean
  /** Path to a `.env` file whose variables are merged into the run environment. */
  envFile?: string
  /** Additional environment variables that override values from `envFile` and the server definition. */
  envOverrides?: Environment
  /**
   * Initial grace period (in seconds) the runner waits before the first
   * reconnect attempt after a `system.reboot` meta. Defaults to
   * {@link DEFAULT_REBOOT_GRACE_SECONDS}. The wait does not consume any of
   * the configured `maxReconnectAttempts` budget.
   */
  rebootGraceSeconds?: number
  /** Custom reconnect timeout in milliseconds passed to SSH, overriding the config default. */
  reconnectTimeout?: number
  /** When `true`, failed commands print full stdout/stderr in addition to the summary error. */
  verbose?: boolean
}

/** Default grace period before reconnecting after a reboot. */
export const DEFAULT_REBOOT_GRACE_SECONDS = 15
const REBOOT_GRACE_SECONDS_TO_MS = 1000

/**
 * Process-scoped holder for the configured reboot grace period. Set once per
 * `runPlaybook` invocation and cleared in teardown so a subsequent run
 * starts from defaults.
 */
let rebootGraceMs: number = DEFAULT_REBOOT_GRACE_SECONDS * REBOOT_GRACE_SECONDS_TO_MS

/**
 * Process-scoped getter for the runner's shutdown signal so the reboot
 * grace sleep can return early when SIGINT/SIGTERM arrives without
 * threading the getter through every call site of
 * {@link applyRunnerControlPlaneMeta}.
 *
 * @returns The active shutdown signal, or `null` when no shutdown is in progress.
 */
let rebootShutdownSignal: () => NodeJS.Signals | null = () => null

/**
 * R-0000203: process-scoped {@link AbortSignal} mirroring the runner's
 * shutdown handler. Set during {@link initializeRunPlaybookContext} and
 * cleared in {@link resetRebootGrace} so the reboot grace sleep can break
 * out of the timer the moment SIGINT/SIGTERM arrives.
 */
let rebootAbortSignal: AbortSignal | undefined

function setRebootGraceFromOptions(options: RunOptions): void {
  const seconds = options.rebootGraceSeconds ?? DEFAULT_REBOOT_GRACE_SECONDS
  rebootGraceMs = Math.max(0, seconds) * REBOOT_GRACE_SECONDS_TO_MS
}

function resetRebootGrace(): void {
  rebootGraceMs = DEFAULT_REBOOT_GRACE_SECONDS * REBOOT_GRACE_SECONDS_TO_MS
  rebootShutdownSignal = () => null
  rebootAbortSignal = undefined
}

/**
 * Sleep helper that respects the runner's shutdown signal: returns early
 * (without throwing) if a shutdown is in progress so the caller can react.
 *
 * R-0000203: subscribes to a {@link AbortSignal} that fires the moment the
 * shutdown handler observes SIGINT/SIGTERM, so an in-flight sleep ends
 * immediately instead of running its full duration. Without the abort, the
 * reboot reconnect would idle through the entire grace period after the
 * operator pressed Ctrl-C.
 *
 * @param durationMs - The maximum sleep duration in milliseconds.
 * @param shutdownSignal - Getter that returns the active shutdown signal, or `null`.
 * @param abortSignal - Optional `AbortSignal` that ends the sleep early.
 */
async function sleepRespectingShutdown(
  durationMs: number,
  shutdownSignal: () => NodeJS.Signals | null,
  abortSignal?: AbortSignal
): Promise<void> {
  if (durationMs <= 0) return
  if (shutdownSignal() != null) return
  if (abortSignal?.aborted === true) return
  await new Promise<void>((resolve) => {
    const handleAbort = (): void => {
      clearTimeout(timer)
      cleanup()
      resolve()
    }
    const cleanup = (): void => {
      abortSignal?.removeEventListener("abort", handleAbort)
    }
    const timer = setTimeout(() => {
      cleanup()
      resolve()
    }, durationMs)
    // Avoid keeping the event loop alive solely for this sleep.
    if (typeof timer.unref === "function") timer.unref()
    abortSignal?.addEventListener("abort", handleAbort, { once: true })
  })
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
    shutdownSignal: parameters.shutdownSignal,
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

function hasSystemRebootMeta(metaEntries: ModuleResult["meta"]): boolean {
  return metaEntries?.some((entry) => isSystemRebootMetaEntry(entry)) ?? false
}

function isConnectedToReportedSshdPort(
  ssh: SshConnectionImpl,
  metaEntries: ModuleResult["meta"]
): boolean {
  const connectedPort = ssh.getConnectionInfo().port
  return (
    connectedPort > 0 &&
    (metaEntries?.some((entry) => isSshdPortMetaEntry(entry) && entry.port === connectedPort) ??
      false)
  )
}

function shouldSkipPortChangeReconnect(
  ssh: SshConnectionImpl,
  metaEntries: ModuleResult["meta"]
): boolean {
  return hasSystemRebootMeta(metaEntries) || isConnectedToReportedSshdPort(ssh, metaEntries)
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
  if (shouldSkipPortChangeReconnect(ssh, metaEntries)) return

  try {
    await ssh.reconnect()
  } catch (error) {
    // R-0000207: distinguish reconnect-failure from a post-connect failure
    // (e.g. host-key persist, sudo probe). If the SSH client is still
    // attached to a port, the reconnect itself succeeded and the new ports
    // are reachable — keep them registered so subsequent reuse works. Only
    // roll back when no port actually held a connection. Mirrors the
    // rollback behavior in modules/sshd.ts:applySshdPort.
    const connectedPort = ssh.getConnectionInfo().port
    const reconnectSucceeded = connectedPort > 0
    if (!reconnectSucceeded) {
      for (const port of addedPorts) ssh.removePort(port)
    }
    const portList = addedPorts.join(", ")
    const diagnostic = reconnectSucceeded
      ? `Reconnect on port(s) ${portList} succeeded but a follow-up step failed: ${String(error)}.`
      : `Failed to reconnect on port(s) ${portList} after port change: ${String(error)}. ` +
        `Verify that port(s) ${portList} are allowed by the server's firewall rules.`
    console.error(diagnostic)
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

  // Wait an initial grace period before the first reconnect so attempts
  // during shutdown/boot do not waste the maxReconnectAttempts budget. The
  // wait short-circuits when a shutdown signal arrives — both via the
  // synchronous shutdown getter (already set when this is reached) and via
  // the AbortSignal that fires on a fresh SIGINT/SIGTERM mid-sleep.
  await sleepRespectingShutdown(rebootGraceMs, rebootShutdownSignal, rebootAbortSignal)

  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(`Failed to reconnect after reboot: ${String(error)}`)
    throw error
  }
}

async function applyRunnerControlPlaneMeta(
  ssh: SshConnectionImpl,
  step: Pick<OrchestrationStep, "meta" | "status">
): Promise<void> {
  if (step.status === "failed") return
  if (step.meta == null) return
  assertValidModuleMetaEntries(step.meta)
  await handlePortChange(ssh, step.meta)
  await handleReboot(ssh, step.meta)
}

async function handleMetaAndBuildResult(parameters: {
  dryRun?: boolean
  environment: Environment
  result: ModuleResult
  ssh: SshConnectionImpl
}): Promise<StepResult> {
  const { dryRun, environment, result, ssh } = parameters
  let currentEnvironment = environment

  if (result.meta != null) {
    currentEnvironment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
    if (dryRun !== true) {
      await applyRunnerControlPlaneMeta(ssh, { meta: result.meta, status: result.status })
    }
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
  shutdownSignal: () => NodeJS.Signals | null,
  verbose: boolean
): Promise<StepResult> {
  return dryRunRecipeModule({
    environment,
    options: { verbose },
    recipeModule,
    shutdownSignal,
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
    if (dryRun) {
      return await runDryRunRecipeModule(recipeModule, environment, ssh, shutdownSignal, verbose)
    }

    // check() iterates all child modules; apply() checks them again internally via executeModules().
    startModuleSpinner(recipeModule.name)
    const checkResult = await recipeModule.check(ssh, environment)
    if (checkResult === "ok") {
      printModuleResult(recipeModule.name, "ok")
      return { env: environment, shouldBreak: false, status: "ok" }
    }

    const result = await recipeModule.apply(ssh, environment, {
      async onChildStep(step) {
        await applyRunnerControlPlaneMeta(ssh, step)
      },
      async onSignalStep(step) {
        await applyRunnerControlPlaneMeta(ssh, step)
      },
      shutdownSignal,
      signalHooks: {
        onSignalFinished(status: ModuleStatus) {
          stats.update(status)
        },
        onSignalStarted() {
          stats.incrementSignals()
        },
      },
      verbose,
    })
    return await handleMetaAndBuildResult({ environment, result, ssh })
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
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}): Promise<StepResult> {
  const { currentEnvironment, dryRun = false, ssh, targetModule, verbose } = parameters
  const connection = targetModule.local === true ? null : ssh
  let result: ModuleResult
  if (dryRun && targetModule._applyDryRun != null) {
    result = await targetModule._applyDryRun(connection, currentEnvironment, {
      shutdownSignal: parameters.shutdownSignal,
    })
  } else if (targetModule._supportsChildStepHook === true) {
    result = await targetModule.apply(connection, currentEnvironment, {
      async onChildStep(step) {
        await applyRunnerControlPlaneMeta(ssh, step)
      },
      shutdownSignal: parameters.shutdownSignal,
    })
  } else {
    result = await targetModule.apply(connection, currentEnvironment)
  }
  const stepResult = await handleMetaAndBuildResult({
    dryRun,
    environment: currentEnvironment,
    result,
    ssh,
  })
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
      onSignalFinished(status: ModuleStatus) {
        stats.update(status)
      },
      onSignalStarted() {
        stats.incrementSignals()
      },
    },
    async onSignalStep(step) {
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
    getSignalBus().off(signal, parameters.handleShutdownSignal)
  setRunnerAbortSignal(undefined)
  clearRegisteredSecrets()
  // Restore the default reboot grace so a subsequent run starts from a known
  // baseline instead of inheriting the previous run's value.
  resetRebootGrace()
  parameters.ssh?.disconnect()
}

function initializeRunPlaybookContext(options: RunOptions): {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  promptAbortSignal: AbortSignal
  setSsh: (connection: SshConnectionImpl) => void
  shutdownSignal: () => NodeJS.Signals | null
} {
  const { handleShutdownSignal, promptAbortSignal, setSsh, shutdownAbortSignal, shutdownSignal } =
    setupShutdownHandlers()
  setRunnerAbortSignal(promptAbortSignal)
  setRebootGraceFromOptions(options)
  // Expose the shutdown getter so the reboot grace sleep can return early
  // when SIGINT/SIGTERM arrives mid-grace.
  rebootShutdownSignal = shutdownSignal
  // R-0000203: also expose the AbortSignal so an in-flight grace sleep ends
  // synchronously the moment the shutdown handler aborts it, instead of
  // running its full duration.
  rebootAbortSignal = shutdownAbortSignal
  return { handleShutdownSignal, promptAbortSignal, setSsh, shutdownSignal }
}

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  validateServerDefinition(definition, { allowEmptyRun: true })
  const { dryRun = false, verbose = false } = options
  const environment = await initializeEnvironment(options, definition)
  const { handleShutdownSignal, promptAbortSignal, setSsh, shutdownSignal } =
    initializeRunPlaybookContext(options)
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
      setSsh(connection) {
        ssh = connection
        setSsh(connection)
      },
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
