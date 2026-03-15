import type { RecipeModule } from "./recipe.js"
import type { Environment, Module, ModuleResult, ServerDefinition } from "./types.js"

import { loadDotEnvironment, mergeEnvironment } from "./environment.js"
import { printError, printModuleResult, printRecipeHeader, printSummary } from "./output.js"
import { SshConnectionImpl } from "./ssh.js"

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
  const result = await recipeModule.apply(ssh, environment)
  return handleMetaAndBuildResult(ssh, environment, result)
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

export async function runPlaybook(
  definition: ServerDefinition,
  options: RunOptions = {}
): Promise<void> {
  const environment = initializeEnvironment(options, definition)
  const sshConfig =
    options.reconnectTimeout == null
      ? definition.ssh
      : { ...definition.ssh, reconnectTimeout: options.reconnectTimeout }
  const ssh = new SshConnectionImpl(definition.host, sshConfig)
  await ssh.connect()
  await ssh.probeSudo()

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

    if (stats.changed > 0 && definition.signals != null) {
      await runSignals({ env: finalEnvironment, signals: definition.signals, ssh, stats })
    }

    printSummary(stats)
  } finally {
    ssh.disconnect()
  }

  if (stats.failed > 0) {
    process.exitCode = 1
  }
}
