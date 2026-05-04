import type { ServerDefinition } from "./types.js"

import { validateSshConfig } from "./serverDefinitionValidation.js"

function isModuleLike(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.name === "string" &&
    candidate.name.length > 0 &&
    typeof candidate.check === "function" &&
    typeof candidate.apply === "function"
  )
}

function validateModuleList(
  modules: unknown,
  property: "run" | "signals",
  options?: { requireNonEmpty?: boolean }
): void {
  if (!Array.isArray(modules)) {
    throw new Error(`ServerDefinition: ${property} must be an array of modules`)
  }
  if (options?.requireNonEmpty === true && modules.length === 0) {
    throw new Error("ServerDefinition: run must contain at least one module")
  }
  for (const [index, module] of modules.entries()) {
    if (!isModuleLike(module)) {
      throw new Error(
        `ServerDefinition: ${property}[${index}] must be a module with name, check, and apply`
      )
    }
  }
}

export function validateServerDefinition(
  config: ServerDefinition,
  options?: { allowEmptyRun?: boolean }
): void {
  if (config.host.length === 0) {
    throw new Error("ServerDefinition: host is required")
  }
  if (config.name.length === 0) {
    throw new Error("ServerDefinition: name is required")
  }
  validateSshConfig(config.ssh)
  validateModuleList(config.run, "run", { requireNonEmpty: options?.allowEmptyRun !== true })
  if (config.signals !== undefined) validateModuleList(config.signals, "signals")
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
 *   ssh: { user: "root", ports: [22], privateKey: "~/.ssh/id_ed25519" }, // "~" is expanded
 *   run: [apt.installed("nginx")],
 * });
 */
export function server(config: ServerDefinition): ServerDefinition {
  validateServerDefinition(config)
  return config
}
