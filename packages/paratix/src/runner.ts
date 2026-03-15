import type { RecipeModule } from "./recipe.js"
import type { Environment, Module, ModuleResult, ServerDefinition } from "./types.js"

import { loadDotEnvironment, mergeEnvironment } from "./environment.js"
import { printError, printModuleResult, printRecipeHeader, printSummary } from "./output.js"
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

export type RunOptions = {
  dryRun?: boolean
  envFile?: string
  envOverrides?: Environment
  reconnectTimeout?: number
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

function initializeEnvironment(options: RunOptions, definition: ServerDefinition): Environment {
  let environment: Environment = {}

  if (options.envFile != null) {
    environment = mergeEnvironment(environment, loadDotEnvironment(options.envFile))
  }
  if (options.envOverrides != null) {
    environment = mergeEnvironment(environment, options.envOverrides)
  }
  if (definition.env != null) {
    environment = mergeEnvironment(environment, definition.env)
  }

  return environment
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

async function runRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  try {
    const result = await recipeModule.apply(ssh, environment)
    return await handleMetaAndBuildResult(ssh, environment, result)
  } catch (error) {
    printError("", String(error))
    return { env: environment, shouldBreak: true, status: "failed" }
  }
}

async function applyModule(
  targetModule: Module,
  currentEnvironment: Environment,
  ssh: SshConnectionImpl
): Promise<StepResult> {
  const result = await targetModule.apply(ssh, currentEnvironment)
  printModuleResult(targetModule.name, result.status)
  return handleMetaAndBuildResult(ssh, currentEnvironment, result)
}

type RegularModuleArguments = {
  dryRun: boolean
  env: Environment
  ssh: SshConnectionImpl
  targetModule: Module
}

async function runRegularModule(parameters: RegularModuleArguments): Promise<StepResult> {
  const { dryRun, env, ssh, targetModule } = parameters

  try {
    const checkResult = await targetModule.check(ssh, env)

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
    printError("", String(error))
    return { env, shouldBreak: true, status: "failed" }
  }
}

type LoopArguments = {
  dryRun: boolean
  env: Environment
  modules: Module[]
  ssh: SshConnectionImpl
  stats: RunStats
}

async function runModuleLoop(parameters: LoopArguments): Promise<Environment> {
  const { dryRun, modules, ssh, stats } = parameters
  let currentEnvironment = parameters.env

  for (const currentModule of modules) {
    const stepPromise = isRecipe(currentModule)
      ? runRecipeModule(currentModule, currentEnvironment, ssh)
      : runRegularModule({ dryRun, env: currentEnvironment, ssh, targetModule: currentModule })

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
}

async function runSignals(parameters: SignalArguments): Promise<void> {
  const { env, signals, ssh, stats } = parameters

  for (const signal of signals) {
    try {
      // eslint-disable-next-line no-await-in-loop
      const result = await signal.apply(ssh, env)
      printModuleResult(`signal: ${signal.name}`, result.status)
      stats.incrementSignals()
    } catch (error) {
      printModuleResult(`signal: ${signal.name}`, "failed")
      printError("", String(error))
    }
  }
}

/**
 * Creates an SSH connection for the given server definition, applies any
 * `reconnectTimeout` override from `options`, and probes for sudo access.
 *
 * @param definition - The server definition containing host and SSH config.
 * @param options - Run options; `reconnectTimeout` overrides the value in
 *   `definition.ssh` when provided.
 * @returns A connected and sudo-probed {@link SshConnectionImpl}.
 */
async function createSshConnection(
  definition: ServerDefinition,
  options: RunOptions
): Promise<SshConnectionImpl> {
  const sshConfig =
    options.reconnectTimeout == null
      ? definition.ssh
      : { ...definition.ssh, reconnectTimeout: options.reconnectTimeout }
  const ssh = new SshConnectionImpl(definition.host, sshConfig)
  await ssh.connect()
  await ssh.probeSudo()
  return ssh
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

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  const environment = initializeEnvironment(options, definition)
  const { handleShutdownSignal, setSsh, shutdownSignal } = setupShutdownHandlers()
  const ssh = await createSshConnection(definition, options)
  setSsh(ssh)
  const stats = new RunStats()

  try {
    printRecipeHeader(definition.name)
    const finalEnvironment = await runModuleLoop({
      dryRun: options.dryRun ?? false,
      env: environment,
      modules: definition.run,
      ssh,
      stats,
    })

    if (shutdownSignal() == null && stats.changed > 0 && definition.signals != null) {
      await runSignals({ env: finalEnvironment, signals: definition.signals, ssh, stats })
    }

    printSummary(stats)
  } finally {
    process.removeListener("SIGINT", handleShutdownSignal)
    process.removeListener("SIGTERM", handleShutdownSignal)
    // Idempotent: may already have been called by the shutdown signal handler
    ssh.disconnect()
  }

  resolveExitCode(shutdownSignal(), stats)
}
