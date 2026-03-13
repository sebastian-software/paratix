export { assert, debug, fail, pause, when } from "./builtins.js"
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
  Env,
  Environment,
  EnvironmentValue,
  EnvValue,
  ExecOptions,
  ExecResult,
  Module,
  ModuleResult,
  ServerDefinition,
  SshConfig,
  SshConnection,
} from "./types.js"
