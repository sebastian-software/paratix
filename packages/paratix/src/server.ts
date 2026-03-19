import type { ServerDefinition, SshConfig } from "./types.js"

const VALID_HOST_KEY_MODES = ["accept-new", "no", "yes"]

function ensureOptionalSshStringIsNotEmpty(value: string | undefined, label: string): void {
  if (value?.length === 0) {
    throw new Error(`ServerDefinition: ${label} must not be an empty string`)
  }
}

/**
 * Validate SSH-specific fields of a server definition.
 *
 * @param ssh - The SSH config to validate.
 */
function validateSshConfig(ssh: SshConfig): void {
  if (ssh.ports.length === 0) {
    throw new Error("ServerDefinition: ssh.ports must not be empty")
  }
  if (ssh.privateKey?.length === 0) {
    throw new Error("ServerDefinition: ssh.privateKey must not be an empty string")
  }
  if (ssh.user.length === 0) {
    throw new Error("ServerDefinition: ssh.user is required")
  }
  ensureOptionalSshStringIsNotEmpty(ssh.expectedHostFingerprint, "ssh.expectedHostFingerprint")
  ensureOptionalSshStringIsNotEmpty(ssh.expectedHostPublicKey, "ssh.expectedHostPublicKey")
  if (
    ssh.strictHostKeyChecking != null &&
    !VALID_HOST_KEY_MODES.includes(ssh.strictHostKeyChecking)
  ) {
    throw new Error(
      `ServerDefinition: ssh.strictHostKeyChecking must be one of ${VALID_HOST_KEY_MODES.join(", ")}`
    )
  }
}

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
  validateSshConfig(config.ssh)
  if (config.run.length === 0) {
    throw new Error("ServerDefinition: run must contain at least one module")
  }

  return config
}
