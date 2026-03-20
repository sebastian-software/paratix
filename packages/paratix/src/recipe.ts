import { mergeEnvironment } from "./environment.js"
import { printCommandFailure, printModuleResult, printRecipeHeader } from "./output.js"
import {
  type Environment,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

/**
 * Internal representation of a recipe module.
 * The `_isRecipe` flag lets the runner distinguish recipes from leaf modules.
 * @internal
 */
export type RecipeModule = {
  _isRecipe: true
  _modules: Module[]
  _signals?: Module[]
  apply: (
    ssh: null | SshConnection,
    environment: Environment,
    options?: {
      shutdownSignal?: () => NodeJS.Signals | null
      verbose?: boolean
    }
  ) => Promise<ModuleResult>
} & Module

type RecipeState = {
  env: Environment
  status: "changed" | "failed" | "ok"
}

/**
 * Recipes run their own check→apply loop, separate from the runner's
 * `runModuleLoop` in runner.ts.  This is intentional: recipes execute as a
 * single nested module inside the runner, so SSH-lifecycle concerns
 * (port-change reconnects, reboot handling), shutdown-signal guards,
 * dry-run mode and stats tracking are the runner's responsibility and
 * must not be duplicated here.
 *
 * @param targetModule - The module to check and conditionally apply.
 * @param ssh - Active SSH connection, or `null` for local modules.
 * @param currentEnvironment - Environment values available to the module.
 * @returns The updated environment and status, or `null` if the module was already ok.
 */
async function executeOneModule(
  targetModule: Module,
  ssh: null | SshConnection,
  currentEnvironment: Environment
): Promise<{ env: Environment; status: string } | null> {
  const connection = targetModule.local === true ? null : ssh
  const checkResult = await targetModule.check(connection, currentEnvironment)

  if (checkResult === "ok") {
    printModuleResult(targetModule.name, "ok")
    return null
  }

  const result = await targetModule.apply(connection, currentEnvironment)
  printModuleResult(targetModule.name, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, false)
  }

  const environment =
    result.meta == null ? currentEnvironment : mergeEnvironment(currentEnvironment, result.meta)
  return { env: environment, status: result.status }
}

async function executeModules(
  modules: Module[],
  ssh: null | SshConnection,
  parameters: {
    environment: Environment
    shutdownSignal?: () => NodeJS.Signals | null
  }
): Promise<RecipeState> {
  const shutdownSignal = parameters.shutdownSignal ?? (() => null)
  let aggregatedStatus: "changed" | "failed" | "ok" = "ok"
  let currentEnvironment = { ...parameters.environment }

  for (const currentModule of modules) {
    if (shutdownSignal() != null) break
    // eslint-disable-next-line no-await-in-loop
    const step = await executeOneModule(currentModule, ssh, currentEnvironment)
    if (step == null) continue

    if (step.status === "failed") {
      return { env: step.env, status: "failed" }
    }
    currentEnvironment = step.env
    if (step.status === "changed") aggregatedStatus = "changed"
  }

  return { env: currentEnvironment, status: aggregatedStatus }
}

function handleSignalResultWithVerbosity(
  name: string,
  result: ModuleResult,
  verbose: boolean
): "changed" | "failed" {
  printModuleResult(`signal: ${name}`, result.status)
  if (result.status === "failed" && result.error != null) {
    printCommandFailure(result.error, verbose)
  }
  return result.status === "failed" ? "failed" : "changed"
}

async function triggerSignals(parameters: {
  environment: Environment
  shutdownSignal?: () => NodeJS.Signals | null
  signals: Module[]
  ssh: null | SshConnection
  verbose?: boolean
}): Promise<"changed" | "failed"> {
  const getShutdownSignal = parameters.shutdownSignal ?? (() => null)
  const verbose = parameters.verbose ?? false
  let status: "changed" | "failed" = "changed"

  for (const signal of parameters.signals) {
    if (getShutdownSignal() != null) break
    try {
      const connection = signal.local === true ? null : parameters.ssh
      // eslint-disable-next-line no-await-in-loop
      const result = await signal.apply(connection, parameters.environment)
      status = handleSignalResultWithVerbosity(signal.name, result, verbose)
    } catch (error) {
      printModuleResult(`signal: ${signal.name}`, "failed")
      printCommandFailure(error, verbose)
      status = "failed"
    }
  }

  return status
}

function extractMeta(
  environment: Environment,
  nextEnvironment: Environment
): Environment | undefined {
  const meta: Environment = {}
  let hasMeta = false
  for (const key of Object.keys(nextEnvironment)) {
    if (!(key in environment) || nextEnvironment[key] !== environment[key]) {
      meta[key] = nextEnvironment[key]
      hasMeta = true
    }
  }
  return hasMeta ? meta : undefined
}

async function applyRecipe(parameters: {
  environment: Environment
  modules: Module[]
  name: string
  options?: {
    shutdownSignal?: () => NodeJS.Signals | null
    verbose?: boolean
  }
  signals?: Module[]
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const shutdownSignal = parameters.options?.shutdownSignal
  const verbose = parameters.options?.verbose ?? false
  printRecipeHeader(parameters.name)
  const state = await executeModules(parameters.modules, parameters.ssh, {
    environment: parameters.environment,
    shutdownSignal,
  })

  if (state.status === "changed" && parameters.signals) {
    state.status = await triggerSignals({
      environment: state.env,
      shutdownSignal,
      signals: parameters.signals,
      ssh: parameters.ssh,
      verbose,
    })
  }

  return {
    meta: extractMeta(parameters.environment, state.env),
    status: state.status,
  }
}

/**
 * Group a list of modules into a named, self-contained recipe.
 *
 * The recipe runs each child module in order, short-circuits on the first
 * failure, and propagates `meta` env values from one module to all subsequent
 * ones. If any child reports `"changed"`, the optional `signals` are triggered
 * at the end of the run.
 *
 * @param name - Display name shown in the run output header.
 * @param modules - Ordered list of modules to execute.
 * @param options - Optional recipe configuration.
 * @param options.signals - Modules to fire when at least one child changed state.
 * @returns A RecipeModule that groups the child modules.
 *
 * @example
 * export const nginxRecipe = recipe("nginx", [
 *   apt.installed("nginx"),
 *   file.template("/etc/nginx/nginx.conf", "./files/nginx.conf.tmpl"),
 *   service.enabled("nginx"),
 * ], {
 *   signals: [service.reload("nginx")],
 * });
 */
export function recipe(
  name: string,
  modules: Module[],
  options?: { signals?: Module[] }
): RecipeModule {
  return {
    _isRecipe: true,
    _modules: modules,
    _signals: options?.signals,
    async apply(
      ssh: null | SshConnection,
      environment: Environment,
      parameters?: {
        shutdownSignal?: () => NodeJS.Signals | null
        verbose?: boolean
      }
    ): Promise<ModuleResult> {
      return applyRecipe({
        environment,
        modules,
        name,
        options: parameters,
        signals: options?.signals,
        ssh,
      })
    },

    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      // Each child receives the original environment — no meta propagation,
      // because check() never calls apply() and therefore produces no meta.
      for (const childModule of modules) {
        const connection = childModule.local === true ? null : ssh
        // eslint-disable-next-line no-await-in-loop
        const result = await childModule.check(connection, environment)
        if (result === NEEDS_APPLY) return NEEDS_APPLY
      }
      return "ok"
    },

    name,
  }
}
