export { assert, debug, fail, firstRun, pause, signals, when } from "./builtins.js"
export { resolveEnvironment } from "./environment.js"
// R-0000695: public helper that returns the async-local first-run flag.
// Playbooks can call it while their top-level module is imported and the
// server definition is created. Module check/apply runs after this context
// ends, and the CLI does not expose the flag through `process.env`.
// R-0000729: imported from the dedicated `firstRunContext` module instead
// of `cli.ts` so the library bundle does not transitively pull `cli.ts`
// (and its `import.meta.url` direct-run guard) which broke esbuild chunk
// splitting for the published package entries.
export { isFirstRun } from "./firstRunContext.js"
export {
  assertValidModuleMetaEntries,
  assertValidModuleMetaEntry,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
  sshdPortMeta,
  systemHostMeta,
  systemRebootMeta,
} from "./meta.js"
export { failed, failedCommand, failedCommandWithDiagnostic } from "./moduleFailure.js"
export {
  apt,
  archive,
  buildKeyValueDiff,
  buildUnifiedDiff,
  command,
  compose,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  net,
  op,
  package,
  quadlet,
  releaseUpgrade,
  restartSystemdUnit,
  rsync,
  script,
  service,
  ssh,
  sshd,
  swap,
  sysctl,
  system,
  systemd,
  timer,
  ufw,
  user,
} from "./modules/index.js"
export type { UnifiedDiffOptions } from "./modules/index.js"
export { recipe } from "./recipe.js"
/**
 * Paratix — public API entry point.
 *
 * Re-exports the core APIs needed to define servers, recipes, and modules.
 * Import built-in modules from the dedicated `paratix/modules` entry point:
 *
 * @example
 * import { server, recipe } from "paratix";
 * import { apt, file, service } from "paratix/modules";
 */
export { server } from "./server.js"
export { shellQuote } from "./ssh.js"
export { NEEDS_APPLY } from "./types.js"
export type {
  Environment,
  EnvironmentMetaEntry,
  EnvironmentValue,
  ExecOptions,
  ExecResult,
  MetaEnvironmentValue,
  Module,
  ModuleMetaEntry,
  ModuleResult,
  ServerDefinition,
  ShutdownSignal,
  SshConfig,
  SshConnection,
  SshdPortMetaEntry,
  SystemHostMetaEntry,
  SystemRebootMetaEntry,
} from "./types.js"
