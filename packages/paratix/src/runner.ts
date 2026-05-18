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
import { withRunnerAbortSignal } from "./runnerAbortSignal.js"
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
      // R-0000694: synchronously destroy the ssh2 client before exiting.
      // The first SIGINT queued `ssh.disconnect()` as a microtask
      // (R-0000257) so ssh2 stream internals had a coherent tick to
      // drain. The second SIGINT may arrive before that microtask has
      // run, so any in-flight ssh2 callback would die mid-flight on
      // `process.exit`. Calling `forceDestroy()` here tears down the
      // underlying socket inside the current tick — fully synchronous, no
      // microtask required — so no ssh2 state is left dangling.
      ssh?.forceDestroy()
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
 * Per-`runPlaybook` reboot grace state. Bundling the grace duration, the
 * shutdown getter, and the abort signal in a single context keeps the
 * state out of module scope so concurrent runs cannot race on shared
 * mutable values. The context is created in
 * {@link initializeRunPlaybookContext} and threaded through every call
 * site that may schedule a reboot grace sleep (mirroring how
 * {@link ShutdownState} already flows through the runner).
 */
type RebootGraceContext = {
  // R-0000788: typed as a required `AbortSignal` because the only sleep that
  // consumes this context (`sleepRespectingShutdown`) now requires the
  // signal as well. Callers must thread a real shutdown-aware abort source
  // through; passing `undefined` would silently downgrade to a plain timer.
  abortSignal: AbortSignal
  graceMs: number
  shutdownSignal: () => NodeJS.Signals | null
}

function createRebootGraceContext(
  options: RunOptions,
  shutdownSignal: () => NodeJS.Signals | null,
  abortSignal: AbortSignal
): RebootGraceContext {
  const seconds = options.rebootGraceSeconds ?? DEFAULT_REBOOT_GRACE_SECONDS
  return {
    abortSignal,
    graceMs: Math.max(0, seconds) * REBOOT_GRACE_SECONDS_TO_MS,
    shutdownSignal,
  }
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
 * @param abortSignal - `AbortSignal` that ends the sleep early. Required so
 *   every caller threads a shutdown-aware abort source through; a plain
 *   `setTimeout`-style sleep that ignores Ctrl-C is intentionally not
 *   supported here.
 */
async function sleepRespectingShutdown(
  durationMs: number,
  shutdownSignal: () => NodeJS.Signals | null,
  abortSignal: AbortSignal
): Promise<void> {
  if (durationMs <= 0) return
  if (shutdownSignal() != null) return
  if (abortSignal.aborted) return
  await new Promise<void>((resolve) => {
    const handleAbort = (): void => {
      clearTimeout(timer)
      cleanup()
      resolve()
    }
    const cleanup = (): void => {
      abortSignal.removeEventListener("abort", handleAbort)
    }
    const timer = setTimeout(() => {
      cleanup()
      resolve()
    }, durationMs)
    // Avoid keeping the event loop alive solely for this sleep.
    if (typeof timer.unref === "function") timer.unref()
    abortSignal.addEventListener("abort", handleAbort, { once: true })
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
  rebootGrace: RebootGraceContext
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
    rebootGrace: parameters.rebootGrace,
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
  metaEntries: ModuleResult["meta"],
  rebootGrace: RebootGraceContext
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
  await sleepRespectingShutdown(
    rebootGrace.graceMs,
    rebootGrace.shutdownSignal,
    rebootGrace.abortSignal
  )

  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(`Failed to reconnect after reboot: ${String(error)}`)
    throw error
  }
}

async function applyRunnerControlPlaneMeta(
  ssh: SshConnectionImpl,
  step: Pick<OrchestrationStep, "meta" | "status">,
  rebootGrace: RebootGraceContext
): Promise<void> {
  if (step.status === "failed") return
  if (step.meta == null) return
  assertValidModuleMetaEntries(step.meta)
  await handlePortChange(ssh, step.meta)
  await handleReboot(ssh, step.meta, rebootGrace)
}

async function handleMetaAndBuildResult(parameters: {
  dryRun?: boolean
  environment: Environment
  rebootGrace: RebootGraceContext
  result: ModuleResult
  ssh: SshConnectionImpl
}): Promise<StepResult> {
  const { dryRun, environment, rebootGrace, result, ssh } = parameters
  let currentEnvironment = environment

  if (result.meta != null) {
    currentEnvironment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
    if (dryRun !== true) {
      await applyRunnerControlPlaneMeta(
        ssh,
        { meta: result.meta, status: result.status },
        rebootGrace
      )
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

async function runDryRunRecipeModule(parameters: {
  environment: Environment
  recipeModule: RecipeModule
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  verbose: boolean
}): Promise<StepResult> {
  return dryRunRecipeModule({
    environment: parameters.environment,
    options: { verbose: parameters.verbose },
    recipeModule: parameters.recipeModule,
    shutdownSignal: parameters.shutdownSignal,
    ssh: parameters.ssh,
  })
}

async function runRecipeModule(parameters: {
  dryRun: boolean
  environment: Environment
  rebootGrace: RebootGraceContext
  recipeModule: RecipeModule
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<StepResult> {
  const { dryRun, environment, rebootGrace, recipeModule, shutdownSignal, ssh, stats, verbose } =
    parameters
  try {
    if (dryRun) {
      return await runDryRunRecipeModule({
        environment,
        recipeModule,
        shutdownSignal,
        ssh,
        verbose,
      })
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
        await applyRunnerControlPlaneMeta(ssh, step, rebootGrace)
      },
      async onSignalStep(step) {
        await applyRunnerControlPlaneMeta(ssh, step, rebootGrace)
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
    return await handleMetaAndBuildResult({ environment, rebootGrace, result, ssh })
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}): Promise<StepResult> {
  const { currentEnvironment, dryRun = false, rebootGrace, ssh, targetModule, verbose } = parameters
  const connection = targetModule.local === true ? null : ssh
  let result: ModuleResult
  if (dryRun && targetModule._applyDryRun != null) {
    result = await targetModule._applyDryRun(connection, currentEnvironment, {
      shutdownSignal: parameters.shutdownSignal,
    })
  } else if (targetModule._supportsChildStepHook === true) {
    result = await targetModule.apply(connection, currentEnvironment, {
      async onChildStep(step) {
        await applyRunnerControlPlaneMeta(ssh, step, rebootGrace)
      },
      shutdownSignal: parameters.shutdownSignal,
    })
  } else {
    result = await targetModule.apply(connection, currentEnvironment)
  }
  const stepResult = await handleMetaAndBuildResult({
    dryRun,
    environment: currentEnvironment,
    rebootGrace,
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}

async function runRegularModule(parameters: RegularModuleArguments): Promise<StepResult> {
  const { dryRun, env, rebootGrace, ssh, targetModule, verbose } = parameters
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
          rebootGrace,
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
      rebootGrace,
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
  rebootGrace: RebootGraceContext
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<SignalRunStatus> {
  return runSignals({
    env: input.currentEnvironment,
    rebootGrace: input.rebootGrace,
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
  rebootGrace: RebootGraceContext
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
    rebootGrace: parameters.rebootGrace,
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}): Promise<StepResult> {
  const {
    currentEnvironment,
    currentModule,
    dryRun,
    rebootGrace,
    shutdownSignal,
    ssh,
    stats,
    verbose,
  } = parameters

  return isRecipe(currentModule)
    ? runRecipeModule({
        dryRun,
        environment: currentEnvironment,
        rebootGrace,
        recipeModule: currentModule,
        shutdownSignal,
        ssh,
        stats,
        verbose,
      })
    : runRegularModule({
        dryRun,
        env: currentEnvironment,
        rebootGrace,
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
  const { definitionSignals, dryRun, modules, rebootGrace, shutdownSignal, ssh, stats, verbose } =
    parameters
  // R-0000842: hold loop state in a single `let` binding and reassign
  // wholesale each iteration. The previous code created the value as
  // `const` and used `Object.assign(loopState, applyLoopResultToState(...))`
  // to mutate the binding in place. Reassigning a plain object is easier to
  // reason about — it makes the per-iteration transition explicit and
  // avoids the fragile contract that `applyLoopResultToState` must return a
  // payload that fully describes every field on `ModuleLoopState`.
  let loopState: ModuleLoopState = {
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
      rebootGrace,
      shutdownSignal,
      ssh,
      stats,
      verbose,
    })

    // eslint-disable-next-line no-await-in-loop
    const result = await stepPromise

    loopState = applyLoopResultToState(loopState, result, stats)
    // eslint-disable-next-line no-await-in-loop
    const flushResult = await flushTopLevelSignalsIfRequested({
      definitionSignals,
      dryRun,
      loopState,
      rebootGrace,
      result,
      shutdownSignal,
      ssh,
      stats,
      verbose,
    })
    loopState = { ...loopState, signalsPending: flushResult.nextSignalsPending }
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  signals: Module[]
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function runSignals(parameters: SignalArguments): Promise<SignalRunStatus> {
  const { env, rebootGrace, shutdownSignal, signals, ssh, stats, verbose } = parameters
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
      await applyRunnerControlPlaneMeta(ssh, step, rebootGrace)
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
  rebootGrace: RebootGraceContext
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function executeRun(parameters: ExecuteRunArguments): Promise<void> {
  const { definition, dryRun, environment, rebootGrace, shutdownSignal, ssh, stats, verbose } =
    parameters

  printRecipeHeader(definition.name)
  const loopResult = await runModuleLoop({
    definitionSignals: definition.signals,
    dryRun,
    env: environment,
    modules: definition.run,
    rebootGrace,
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
      rebootGrace,
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
 * signal, and the ssh connection.
 *
 * R-0000518: the process-scoped secret sink is NOT cleared here. The sink in
 * `secretSink.ts` is reference-counted via `withRegisteredSecrets` /
 * `registerSecret` / `unregisterSecret`: every module that
 * registers a secret also releases it through `try/finally`, so the sink
 * drains on its own once each scope closes. Calling
 * `clearRegisteredSecrets()` unconditionally on teardown would wipe secrets
 * belonging to a concurrent `runPlaybook` invocation that shares the same
 * Node process — a parallel run would lose its redaction context the moment
 * the first run finishes. R-0000041's original goal (no bleed across runs)
 * is preserved by the reference-counting protocol itself.
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
  // R-0000743: the abort signal lives inside the AsyncLocalStorage scope
  // installed by `withRunnerAbortSignal` in `runPlaybook`. The scope ends
  // automatically once the wrapped body returns, so no explicit clear is
  // needed here and a parallel run is no longer affected.
  parameters.ssh?.disconnect()
}

function initializeRunPlaybookContext(options: RunOptions): {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  promptAbortSignal: AbortSignal
  rebootGrace: RebootGraceContext
  setSsh: (connection: SshConnectionImpl) => void
  shutdownSignal: () => NodeJS.Signals | null
} {
  const { handleShutdownSignal, promptAbortSignal, setSsh, shutdownAbortSignal, shutdownSignal } =
    setupShutdownHandlers()
  // R-0000743: the abort signal is no longer installed eagerly into a
  // module-global slot. `runPlaybook` wraps its body in
  // `withRunnerAbortSignal(promptAbortSignal, …)` so the signal lives inside
  // an AsyncLocalStorage scope and parallel runs never observe each other.
  // R-0000203: scope the reboot grace state (duration, shutdown getter, abort
  // signal) to this invocation so concurrent `runPlaybook` calls cannot race
  // on shared mutable values.
  const rebootGrace = createRebootGraceContext(options, shutdownSignal, shutdownAbortSignal)
  return { handleShutdownSignal, promptAbortSignal, rebootGrace, setSsh, shutdownSignal }
}

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  validateServerDefinition(definition, { allowEmptyRun: true })
  const { dryRun = false, verbose = false } = options
  const environment = await initializeEnvironment(options, definition)
  const { handleShutdownSignal, promptAbortSignal, rebootGrace, setSsh, shutdownSignal } =
    initializeRunPlaybookContext(options)
  const stats = new RunStats()

  // R-0000743: wrap the entire playbook lifecycle (connect, executeRun,
  // teardown, exit-code resolution) in the per-run AsyncLocalStorage scope
  // so every async branch that the run spawns observes its own abort signal
  // and a parallel `runPlaybook` invocation never overwrites it.
  await withRunnerAbortSignal(promptAbortSignal, async () => {
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
      await executeRun({
        definition,
        dryRun,
        environment,
        rebootGrace,
        shutdownSignal,
        ssh,
        stats,
        verbose,
      })
    } catch (error) {
      rethrowIfNotShutdown(error, shutdownSignal)
    } finally {
      teardownPlaybookResources({ handleShutdownSignal, ssh })
    }

    resolveExitCode(shutdownSignal(), stats)
  })
}
