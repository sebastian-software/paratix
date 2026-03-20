import type { ServerDefinition } from "./types.js"

import { validateSshConfig } from "./serverDefinitionValidation.js"

/**
 * Define a server and validate its configuration at construction time.
 *
 * This is a thin identity function whose only purpose is to provide
 * type-safe validation with descriptive error messages before the runner
 * ever attempts an SSH connection.
 *
 * @param config - The server definition to validate and return.
 * @returns The validated server definition.
 * @throws {Error} When any required field is missing or empty.
 *
 * @example
 * export default server({
 *   name: "web-01",
 *   host: "10.0.0.1",
 *   ssh: { user: "root", ports: [22], privateKey: "~/.ssh/id_ed25519" }, // "~" is expanded
 *   run: [apt.installed("nginx")],
 * });
 */
export function server(config: ServerDefinition): ServerDefinition {
  if (config.host.length === 0) {
    throw new Error("ServerDefinition: host is required")
  }
  if (config.name.length === 0) {
    throw new Error("ServerDefinition: name is required")
  }
  validateSshConfig(config.ssh)
  if (config.run.length === 0) {
    throw new Error("ServerDefinition: run must contain at least one module")
  }

  return config
}
