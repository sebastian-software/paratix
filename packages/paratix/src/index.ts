export { assert, debug, fail, firstRun, pause, signals, when } from "./builtins.js"
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
  releaseUpgrade,
  rsync,
  script,
  service,
  ssh,
  sshd,
  sysctl,
  system,
  systemd,
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
  SshConfig,
  SshConnection,
  SshdPortMetaEntry,
  SystemHostMetaEntry,
  SystemRebootMetaEntry,
} from "./types.js"
