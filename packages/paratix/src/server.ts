import type { ServerDefinition } from "./types.js"

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
 *   ssh: { user: "root", ports: [22], privateKey: "~/.ssh/id_ed25519" },
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
  if (config.ssh.ports.length === 0) {
    throw new Error("ServerDefinition: ssh.ports must not be empty")
  }
  if (config.ssh.privateKey?.length === 0) {
    throw new Error("ServerDefinition: ssh.privateKey must not be an empty string")
  }
  if (config.ssh.user.length === 0) {
    throw new Error("ServerDefinition: ssh.user is required")
  }
  if (config.run.length === 0) {
    throw new Error("ServerDefinition: run must contain at least one module")
  }

  return config
}
