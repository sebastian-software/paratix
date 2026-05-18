export { assert, debug, fail, firstRun, pause, signals, when } from "./builtins.js"
export { resolveEnvironment } from "./environment.js"
// R-0000695: public helper that returns the async-local first-run flag.
// Playbooks should call this from `init`/`apply`/`check` rather than
// reading `process.env.PARATIX_FIRST_RUN`, which the CLI no longer mutates.
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
export { failed, failedCommand } from "./moduleFailure.js"
export {
  apt,
  archive,
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
export { recipe } from "./recipe.js"
/**
 * Paratix — public API entry point.
 *
 * Re-exports all symbols needed to define servers, recipes, and modules.
 * Import from this module in your server definition files:
 *
 * @example
 * import { server, recipe, apt, file, service } from "paratix";
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
