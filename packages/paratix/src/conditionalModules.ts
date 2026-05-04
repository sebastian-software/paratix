import { createNullPrototypeEnvironment } from "./environment.js"
import { mergeEnvironmentFromMeta } from "./meta.js"
import { detectPackageManager, isPackageInstalled } from "./modules/package.js"
import { shellQuote } from "./ssh.js"
import {
  type Environment,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "./types.js"

type ConditionalApplyState = {
  environment: Environment
  flushSignals?: true
  meta: ModuleMetaEntry[]
  status: "changed" | "ok" | "skipped"
  stopRun?: true
}

function createConditionalApplyState(environment: Environment): ConditionalApplyState {
  // R-0000087: preserve the null-prototype guarantee that
  // R-0000069/R-0000070/R-0000074 establish for the runner-level
  // environment. Plain object spread (`{ ...environment }`) would create a
  // map with `Object.prototype`, exposing the first child module of every
  // when(...) guard to a polluted-fähige environment. Mirror the
  // recipe.ts:302 / meta.ts:214 approach.
  return {
    environment: Object.assign(createNullPrototypeEnvironment(), environment),
    meta: [],
    status: "ok",
  }
}

function markConditionalApplyChanged(state: ConditionalApplyState): ConditionalApplyState {
  return { ...state, status: "changed" }
}

async function executeConditionalApply(parameters: {
  dryRun: boolean
  environment: Environment
  module: Module
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun, environment, module, ssh } = parameters
  if (dryRun && module._applyDryRun != null) {
    return module._applyDryRun(ssh, environment)
  }
  return module.apply(ssh, environment)
}

function shouldExecuteConditionalApply(module: Module, dryRun: boolean): boolean {
  if (!dryRun) return true
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

function getConditionalChildConnection(
  module: Module,
  ssh: null | SshConnection
): null | SshConnection {
  return module.local === true ? null : ssh
}

async function mergeConditionalApplyState(
  state: ConditionalApplyState,
  result: ModuleResult
): Promise<ConditionalApplyState> {
  const environment = await mergeEnvironmentFromMeta(state.environment, result.meta)
  return {
    environment,
    flushSignals: result._flushSignals === true ? true : state.flushSignals,
    meta: result.meta == null ? state.meta : [...state.meta, ...result.meta],
    status: result.status === "changed" ? "changed" : state.status,
    stopRun: result._stopRun === true ? true : state.stopRun,
  }
}

async function applyConditionalModules(parameters: {
  dryRun?: boolean
  environment: Environment
  modules: Module[]
  ssh: null | SshConnection
}): Promise<ModuleResult> {
  const { dryRun = false, modules, ssh } = parameters
  let state = createConditionalApplyState(parameters.environment)

  for (const currentModule of modules) {
    const connection = getConditionalChildConnection(currentModule, ssh)
    // eslint-disable-next-line no-await-in-loop
    const checkResult = await currentModule.check(connection, state.environment)
    if (checkResult === "ok") continue

    if (!shouldExecuteConditionalApply(currentModule, dryRun)) {
      state = markConditionalApplyChanged(state)
      continue
    }

    // eslint-disable-next-line no-await-in-loop -- conditional modules must preserve ordered env propagation
    const result = await executeConditionalApply({
      dryRun,
      environment: state.environment,
      module: currentModule,
      ssh: connection,
    })
    if (result.status === "failed") return result
    // eslint-disable-next-line no-await-in-loop -- downstream env must see each module's meta in order
    state = await mergeConditionalApplyState(state, result)
    if (state.stopRun === true) break
  }

  return {
    _flushSignals: state.flushSignals,
    _stopRun: state.stopRun,
    meta: state.meta.length === 0 ? undefined : state.meta,
    status: state.status,
  }
}

function shouldExecuteConditionalDryRun(module: Module): boolean {
  return (
    module._applyDryRun != null ||
    module._dryRunBlocker === true ||
    module._dryRunMetaProducer === true
  )
}

function whenNeedsDryRunApply(modules: Module[]): boolean {
  return modules.some((module) => shouldExecuteConditionalDryRun(module))
}

async function checkConditionalModules(
  modules: Module[],
  ssh: null | SshConnection,
  environment: Environment
): Promise<"needs-apply" | "ok"> {
  // R-0000087: same null-prototype preservation as createConditionalApplyState
  // for the check-side traversal of when(...) guards.
  const currentEnvironment = Object.assign(createNullPrototypeEnvironment(), environment)
  for (const currentModule of modules) {
    const connection = getConditionalChildConnection(currentModule, ssh)
    // eslint-disable-next-line no-await-in-loop
    const result = await currentModule.check(connection, currentEnvironment)
    if (result === NEEDS_APPLY) {
      return NEEDS_APPLY
    }
  }
  return "ok"
}

type Condition = (ssh: null | SshConnection, environment: Environment) => boolean | Promise<boolean>

function createWhenDryRunApply(
  condition: Condition,
  modules: Module[],
  needsDryRunApply: boolean
): ((ssh: null | SshConnection, environment: Environment) => Promise<ModuleResult>) | undefined {
  if (!needsDryRunApply) return undefined
  return async (ssh: null | SshConnection, environment: Environment) => {
    if (!(await condition(ssh, environment))) {
      return { status: "skipped" as const }
    }
    return applyConditionalModules({ dryRun: true, environment, modules, ssh })
  }
}

export function createConditionalModule(parameters: {
  condition: Condition
  modules: Module[]
  name: string
}): Module {
  const needsDryRunApply = whenNeedsDryRunApply(parameters.modules)
  const applyDryRun = createWhenDryRunApply(
    parameters.condition,
    parameters.modules,
    needsDryRunApply
  )

  return {
    ...(parameters.modules.some((module) => module._dryRunBlocker === true)
      ? { _dryRunBlocker: true as const }
      : {}),
    ...(parameters.modules.some((module) => module._dryRunMetaProducer === true)
      ? { _dryRunMetaProducer: true as const }
      : {}),
    ...(applyDryRun == null ? {} : { _applyDryRun: applyDryRun }),
    async apply(ssh: null | SshConnection, environment: Environment): Promise<ModuleResult> {
      if (!(await parameters.condition(ssh, environment))) {
        return { status: "skipped" }
      }
      return applyConditionalModules({ environment, modules: parameters.modules, ssh })
    },
    async check(
      ssh: null | SshConnection,
      environment: Environment
    ): Promise<"needs-apply" | "ok"> {
      if (!(await parameters.condition(ssh, environment))) {
        return "ok"
      }
      return checkConditionalModules(parameters.modules, ssh, environment)
    },
    name: parameters.name,
  }
}

function filesystemTypeName(testFlag: "-d" | "-f" | "-L" | "-S"): string {
  switch (testFlag) {
    case "-d": {
      return "path"
    }
    case "-f": {
      return "file"
    }
    case "-L": {
      return "symlink"
    }
    case "-S": {
      return "socket"
    }
  }
}

export function createFilesystemGuard(parameters: {
  invert: boolean
  modules: Module[]
  path: string
  testFlag: "-d" | "-f" | "-L" | "-S"
}): Module {
  const typeName = filesystemTypeName(parameters.testFlag)
  return createConditionalModule({
    condition: async (ssh) => {
      if (ssh == null) return false
      const exists = await ssh.test(`test ${parameters.testFlag} ${shellQuote(parameters.path)}`)
      return parameters.invert ? !exists : exists
    },
    modules: parameters.modules,
    name: `when.${typeName}${parameters.invert ? "Missing" : "Exists"}: ${parameters.path}`,
  })
}

export function createCommandGuard(
  commandName: string,
  invert: boolean,
  modules: Module[]
): Module {
  return createConditionalModule({
    condition: async (ssh) => {
      if (ssh == null) return false
      const exists = await ssh.test(`command -v ${shellQuote(commandName)} >/dev/null 2>&1`)
      return invert ? !exists : exists
    },
    modules,
    name: `when.command${invert ? "Missing" : "Exists"}: ${commandName}`,
  })
}

export function createPackageGuard(
  packageName: string,
  invert: boolean,
  modules: Module[]
): Module {
  return createConditionalModule({
    condition: async (ssh) => {
      if (ssh == null) return false
      const pm = await detectPackageManager(ssh)
      if (pm == null) return false
      const installed = await isPackageInstalled(ssh, pm, packageName)
      return invert ? !installed : installed
    },
    modules,
    name: `when.package${invert ? "Absent" : "Installed"}: ${packageName}`,
  })
}
