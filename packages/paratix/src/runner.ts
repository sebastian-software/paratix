import type { RecipeModule } from "./recipe.js"
import type { Environment, Module, ModuleResult, ServerDefinition } from "./types.js"

import { dryRunRecipeModule } from "./dryRunRecipe.js"
import { loadDotEnvironment, mergeEnvironment } from "./environment.js"
import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  printSummary,
} from "./output.js"
import { SshConnectionImpl } from "./ssh.js"

const SIGNAL_EXIT_BASE = 128
const SIGTERM_NUMBER = 15
const SIGINT_NUMBER = 2

/**
 * Returns the conventional exit code for a termination signal.
 * Follows the POSIX convention of 128 + signal number.
 *
 * @param signal - The received signal (`SIGTERM` or `SIGINT`).
 * @returns The exit code to use when the process is terminated by `signal`.
 */
function signalExitCode(signal: NodeJS.Signals): number {
  return SIGNAL_EXIT_BASE + (signal === "SIGTERM" ? SIGTERM_NUMBER : SIGINT_NUMBER)
}

/**
 * Holds the shutdown handler and a getter for the signal that triggered it.
 *
 * - `handleShutdownSignal` — the listener registered on `SIGINT`/`SIGTERM`.
 *   A second signal while shutdown is already in progress causes an immediate exit.
 * - `shutdownSignal` — returns the first signal received, or `null` if no signal
 *   has been received yet.
 */
type ShutdownState = {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
  setSsh: (connection: SshConnectionImpl) => void
  shutdownSignal: () => NodeJS.Signals | null
}

/**
 * Registers `SIGINT` and `SIGTERM` handlers that perform a graceful SSH
 * shutdown on the first signal. A second signal triggers an immediate exit
 * with the appropriate signal exit code.
 *
 * The SSH connection is not required at registration time — call `setSsh`
 * once the connection is established so the handler can disconnect it.
 *
 * @returns A {@link ShutdownState} containing the registered handler, a
 *   `setSsh` setter for the SSH connection, and a getter that returns the
 *   first received signal.
 */
function setupShutdownHandlers(): ShutdownState {
  let receivedSignal: NodeJS.Signals | null = null
  let ssh: null | SshConnectionImpl = null

  const handleShutdownSignal = (signal: NodeJS.Signals): void => {
    if (receivedSignal != null) {
      // eslint-disable-next-line node/no-process-exit
      process.exit(signalExitCode(signal))
    }
    receivedSignal = signal
    console.error(`\nReceived ${signal}, shutting down…`)
    ssh?.disconnect()
  }

  process.on("SIGINT", handleShutdownSignal)
  process.on("SIGTERM", handleShutdownSignal)

  return {
    handleShutdownSignal,
    setSsh: (connection: SshConnectionImpl) => {
      ssh = connection
    },
    shutdownSignal: () => receivedSignal,
  }
}

/**
 * Options controlling the behavior of a {@link runPlaybook} run.
 */
export type RunOptions = {
  /**
   * When `true`, modules report what would change without applying anything.
   * Defaults to `false`.
   */
  dryRun?: boolean
  /** Path to a `.env` file whose variables are merged into the run environment. */
  envFile?: string
  /** Additional environment variables that override values from `envFile` and the server definition. */
  envOverrides?: Environment
  /**
   * Custom reconnect timeout in milliseconds passed to the SSH connection.
   * Falls back to the default defined in the SSH configuration when omitted.
   */
  reconnectTimeout?: number
  /**
   * When `true`, the full (untruncated) stdout and stderr of a failed command
   * are printed in addition to the summary error message.
   * Defaults to `false`.
   */
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

  public update(status: string): void {
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
      default: {
        break
      }
    }
  }
}

type StepResult = { env: Environment; shouldBreak: boolean; status?: string }

function isRecipe(target: Module): target is RecipeModule {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- RecipeModule uses _isRecipe as discriminator
  return "_isRecipe" in target && (target as RecipeModule)._isRecipe
}

async function initializeEnvironment(
  options: RunOptions,
  definition: ServerDefinition
): Promise<Environment> {
  const dotEnvironment =
    options.envFile == null ? undefined : await loadDotEnvironment(options.envFile)
  return mergeEnvironment({}, dotEnvironment, definition.env, options.envOverrides)
}

async function handlePortChange(ssh: SshConnectionImpl, meta: Environment): Promise<void> {
  const portValue = meta["sshd.port"]
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- portValue may be undefined at runtime
  if (portValue == null) return

  const newPort = Number(portValue)
  ssh.addPort(newPort)
  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(`Failed to reconnect after port change: ${String(error)}`)
    throw error
  }
}

async function handleReboot(ssh: SshConnectionImpl, meta: Environment): Promise<void> {
  const reboot = meta["system.reboot"]
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- meta values may be undefined at runtime
  if (reboot == null) return

  const newHost = meta["system.host"]
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- meta values may be undefined at runtime
  if (newHost != null) {
    ssh.updateHost(String(newHost))
  }

  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(`Failed to reconnect after reboot: ${String(error)}`)
    throw error
  }
}

async function handleMetaAndBuildResult(
  ssh: SshConnectionImpl,
  environment: Environment,
  result: ModuleResult
): Promise<StepResult> {
  let currentEnvironment = environment

  if (result.meta != null) {
    currentEnvironment = mergeEnvironment(currentEnvironment, result.meta)
    await handlePortChange(ssh, result.meta)
    await handleReboot(ssh, result.meta)
  }

  return {
    env: currentEnvironment,
    shouldBreak: result.status === "failed",
    status: result.status,
  }
}

// eslint-disable-next-line max-params -- verbose and dryRun flags need to be threaded through
async function runRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl,
  verbose: boolean,
  dryRun: boolean
): Promise<StepResult> {
  try {
    if (dryRun) return await dryRunRecipeModule(recipeModule, environment, ssh)

    const checkResult = await recipeModule.check(ssh, environment)
    if (checkResult === "ok") {
      printModuleResult(recipeModule.name, "ok")
      return { env: environment, shouldBreak: false, status: "ok" }
    }

    const result = await recipeModule.apply(ssh, environment)
    return await handleMetaAndBuildResult(ssh, environment, result)
  } catch (error) {
    printModuleResult(recipeModule.name, "failed")
    printCommandFailure(error, verbose)
    return { env: environment, shouldBreak: true, status: "failed" }
  }
}

async function applyModule(
  targetModule: Module,
  currentEnvironment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  const connection = targetModule.local === true ? null : ssh
  const result = await targetModule.apply(connection, currentEnvironment)
  printModuleResult(targetModule.name, result.status)
  return handleMetaAndBuildResult(ssh, currentEnvironment, result)
}

type RegularModuleArguments = {
  dryRun: boolean
  env: Environment
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}

async function runRegularModule(parameters: RegularModuleArguments): Promise<StepResult> {
  const { dryRun, env, ssh, targetModule, verbose } = parameters

  try {
    const connection = targetModule.local === true ? null : ssh
    const checkResult = await targetModule.check(connection, env)

    if (checkResult === "ok") {
      printModuleResult(targetModule.name, "ok")
      return { env, shouldBreak: false, status: "ok" }
    }

    if (dryRun) {
      printModuleResult(targetModule.name, "changed", "(dry-run)")
      return { env, shouldBreak: false, status: "changed" }
    }

    return await applyModule(targetModule, env, ssh)
  } catch (error) {
    printModuleResult(targetModule.name, "failed")
    printCommandFailure(error, verbose)
    return { env, shouldBreak: true, status: "failed" }
  }
}

type LoopArguments = {
  dryRun: boolean
  env: Environment
  modules: Module[]
  shutdownSignal: () => NodeJS.Signals | null
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function runModuleLoop(parameters: LoopArguments): Promise<Environment> {
  const { dryRun, modules, shutdownSignal, ssh, stats, verbose } = parameters
  let currentEnvironment = parameters.env

  for (const currentModule of modules) {
    // A module already running when the signal arrived completes normally
    // and its result is still counted in stats before the loop exits here.
    if (shutdownSignal() != null) break
    const stepPromise = isRecipe(currentModule)
      ? runRecipeModule(currentModule, currentEnvironment, ssh, verbose, dryRun)
      : runRegularModule({
          dryRun,
          env: currentEnvironment,
          ssh,
          targetModule: currentModule,
          verbose,
        })

    // eslint-disable-next-line no-await-in-loop
    const result = await stepPromise

    currentEnvironment = result.env
    if (result.status != null) stats.update(result.status)
    if (result.shouldBreak) break
  }

  return currentEnvironment
}

type SignalArguments = {
  env: Environment
  signals: Module[]
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function runSignals(parameters: SignalArguments): Promise<void> {
  const { env, signals, ssh, stats, verbose } = parameters

  for (const signal of signals) {
    try {
      const connection = signal.local === true ? null : ssh
      // eslint-disable-next-line no-await-in-loop
      const result = await signal.apply(connection, env)
      printModuleResult(`signal: ${signal.name}`, result.status)
      stats.incrementSignals()
    } catch (error) {
      printModuleResult(`signal: ${signal.name}`, "failed")
      printCommandFailure(error, verbose)
    }
  }
}

/**
 * Sets `process.exitCode` based on the run outcome.
 * A received shutdown signal takes precedence over module failures.
 *
 * @param shutdownSignal - The signal that interrupted the run, or `null` if the
 *   run completed normally.
 * @param stats - Accumulated run statistics used to detect module failures.
 */
function resolveExitCode(shutdownSignal: NodeJS.Signals | null, stats: RunStats): void {
  if (shutdownSignal != null) {
    process.exitCode = signalExitCode(shutdownSignal)
  } else if (stats.failed > 0) {
    process.exitCode = 1
  }
}

async function connectAndRegister(
  definition: ServerDefinition,
  options: RunOptions,
  setSsh: (c: SshConnectionImpl) => void
): Promise<SshConnectionImpl> {
  const sshConfig =
    options.reconnectTimeout == null
      ? definition.ssh
      : { ...definition.ssh, reconnectTimeout: options.reconnectTimeout }
  const ssh = new SshConnectionImpl(definition.host, sshConfig)
  await ssh.connect()
  await ssh.probeSudo()
  setSsh(ssh)
  return ssh
}

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  const { dryRun = false, verbose = false } = options
  const environment = await initializeEnvironment(options, definition)
  const { handleShutdownSignal, setSsh, shutdownSignal } = setupShutdownHandlers()
  const stats = new RunStats()
  let ssh: SshConnectionImpl | undefined

  // No catch block — connect errors propagate to the CLI handler in cli.ts
  // which prints the error and exits with code 2.
  try {
    ssh = await connectAndRegister(definition, options, setSsh)
    printRecipeHeader(definition.name)
    const finalEnvironment = await runModuleLoop({
      dryRun,
      env: environment,
      modules: definition.run,
      shutdownSignal,
      ssh,
      stats,
      verbose,
    })

    if (shutdownSignal() == null && stats.changed > 0 && definition.signals != null) {
      await runSignals({ env: finalEnvironment, signals: definition.signals, ssh, stats, verbose })
    }

    printSummary(stats)
  } finally {
    for (const signal of ["SIGINT", "SIGTERM"] as const)
      process.removeListener(signal, handleShutdownSignal)
    ssh?.disconnect()
  }

  resolveExitCode(shutdownSignal(), stats)
}
