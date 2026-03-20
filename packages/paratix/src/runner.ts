/* eslint-disable max-lines -- central runner orchestration stays intentionally co-located */
import type { RecipeModule } from "./recipe.js"
import type { Environment, Module, ModuleResult, ModuleStatus, ServerDefinition } from "./types.js"

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
  printSummary,
} from "./output.js"
import { resolveExitCode, signalExitCode } from "./runnerHelpers.js"
import { SshConnectionImpl } from "./ssh.js"

/** Holds the shutdown listener, SSH setter, and getter for the first received signal. */
type ShutdownState = {
  handleShutdownSignal: (signal: NodeJS.Signals) => void
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

type StepResult = { env: Environment; shouldBreak: boolean; status?: ModuleStatus }

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

function hasRebootMeta(result: ModuleResult): boolean {
  return result.meta?.some(isSystemRebootMetaEntry) ?? false
}

async function handlePortChange(ssh: SshConnectionImpl, result: ModuleResult): Promise<void> {
  const portEntry = result.meta?.find(isSshdPortMetaEntry)
  if (portEntry == null) return

  const newPort = portEntry.port
  ssh.addPort(newPort)

  // Skip reconnect when a reboot is pending — the reboot handler will
  // reconnect on all registered ports (including the newly added one).
  if (hasRebootMeta(result)) return

  try {
    await ssh.reconnect()
  } catch (error) {
    console.error(
      `Failed to reconnect on port ${newPort} after port change: ${String(error)}. ` +
        `Verify that port ${newPort} is allowed by the server's firewall rules.`
    )
    throw error
  }
}

async function handleReboot(ssh: SshConnectionImpl, result: ModuleResult): Promise<void> {
  if (!hasRebootMeta(result)) return

  const hostEntry = result.meta?.find(isSystemHostMetaEntry)
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

async function handleMetaAndBuildResult(
  ssh: SshConnectionImpl,
  environment: Environment,
  result: ModuleResult
): Promise<StepResult> {
  let currentEnvironment = environment

  if (result.meta != null) {
    assertValidModuleMetaEntries(result.meta)
    currentEnvironment = await mergeEnvironmentFromMeta(currentEnvironment, result.meta)
    await handlePortChange(ssh, result)
    await handleReboot(ssh, result)
  }

  return { env: currentEnvironment, shouldBreak: result.status === "failed", status: result.status }
}

// eslint-disable-next-line max-params -- verbose and dryRun flags need to be threaded through
async function runRecipeModule(
  recipeModule: RecipeModule,
  environment: Environment,
  ssh: SshConnectionImpl,
  verbose: boolean,
  dryRun: boolean,
  shutdownSignal: () => NodeJS.Signals | null
): Promise<StepResult> {
  try {
    if (dryRun) return await dryRunRecipeModule(recipeModule, environment, ssh)

    // check() iterates all child modules; apply() checks them again internally via executeModules().
    const checkResult = await recipeModule.check(ssh, environment)
    if (checkResult === "ok") {
      printRecipeHeader(recipeModule.name)
      printModuleResult(recipeModule.name, "ok")
      return { env: environment, shouldBreak: false, status: "ok" }
    }

    const result = await recipeModule.apply(ssh, environment, { shutdownSignal, verbose })
    return await handleMetaAndBuildResult(ssh, environment, result)
  } catch (error) {
    printModuleResult(recipeModule.name, "failed")
    printCommandFailure(error, verbose)
    return { env: environment, shouldBreak: true, status: "failed" }
  }
}

async function applyModule(parameters: {
  currentEnvironment: Environment
  ssh: SshConnectionImpl
  targetModule: Module
  verbose: boolean
}): Promise<StepResult> {
  const { currentEnvironment, ssh, targetModule, verbose } = parameters
  const connection = targetModule.local === true ? null : ssh
  const result = await targetModule.apply(connection, currentEnvironment)
  printModuleResult(targetModule.name, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
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

    return await applyModule({
      currentEnvironment: env,
      ssh,
      targetModule,
      verbose,
    })
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
      ? runRecipeModule(currentModule, currentEnvironment, ssh, verbose, dryRun, shutdownSignal)
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
  shutdownSignal: () => NodeJS.Signals | null
  signals: Module[]
  ssh: SshConnectionImpl
  stats: RunStats
  verbose: boolean
}

async function runSignals(parameters: SignalArguments): Promise<void> {
  const { env, shutdownSignal, signals, ssh, stats, verbose } = parameters

  for (const signal of signals) {
    if (shutdownSignal() != null) break
    stats.incrementSignals()
    try {
      const connection = signal.local === true ? null : ssh
      // eslint-disable-next-line no-await-in-loop
      const result = await signal.apply(connection, env)
      printModuleResult(`signal: ${signal.name}`, result.status)
      if (result.status === "failed" && result.error != null) {
        printCommandFailure(result.error, verbose)
      }
      stats.update(result.status)
    } catch (error) {
      printModuleResult(`signal: ${signal.name}`, "failed")
      printCommandFailure(error, verbose)
      stats.update("failed")
    }
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
  setSsh(ssh)
  await ssh.connect()
  await ssh.probeSudo()
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
  const finalEnvironment = await runModuleLoop({
    dryRun,
    env: environment,
    modules: definition.run,
    shutdownSignal,
    ssh,
    stats,
    verbose,
  })

  if (shutdownSignal() == null && stats.changed > 0 && definition.signals != null)
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

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  const { dryRun = false, verbose = false } = options
  const environment = await initializeEnvironment(options, definition)
  const { handleShutdownSignal, setSsh, shutdownSignal } = setupShutdownHandlers()
  const stats = new RunStats()
  let ssh: SshConnectionImpl | undefined

  // No catch block: connect errors propagate to cli.ts, which prints them and exits with code 2.
  try {
    ssh = await connectAndRegister(definition, options, setSsh)
    await executeRun({ definition, dryRun, environment, shutdownSignal, ssh, stats, verbose })
  } catch (error) {
    rethrowIfNotShutdown(error, shutdownSignal)
  } finally {
    for (const signal of ["SIGINT", "SIGTERM"] as const)
      process.removeListener(signal, handleShutdownSignal)
    ssh?.disconnect()
  }

  resolveExitCode(shutdownSignal(), stats)
}
