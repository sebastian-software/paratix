import type { SshConfig } from "./types.js"

const STRICT_HOST_KEY_ERROR = `Invalid property 'ssh.strictHostKeyChecking' (expected "accept-new", "no", or "yes")`
const MAX_TCP_PORT = 65_535

type NumberValidationOptions = {
  integer?: boolean
  positive?: boolean
}

function describeType(value: unknown): string {
  return value === null ? "null" : typeof value
}

function isHostKeyMode(value: string): boolean {
  return value === "accept-new" || value === "no" || value === "yes"
}

function isRecord(value: object): value is Record<string, unknown> {
  return Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null
}

function collectOptionalBooleanErrors(
  object: Record<string, unknown>,
  key: string,
  errors: string[]
): void {
  if (!(key in object) || object[key] == null) return
  if (typeof object[key] !== "boolean") {
    errors.push(
      `Invalid property 'ssh.${key}' (expected boolean, got ${describeType(object[key])})`
    )
  }
}

function collectOptionalNumberErrors(parameters: {
  errors: string[]
  key: string
  object: Record<string, unknown>
  options?: NumberValidationOptions
}): void {
  const { errors, key, object, options } = parameters
  if (!(key in object) || object[key] == null) return
  const value = object[key]
  const validatedNumber = validateNumberValue(value)
  if (validatedNumber == null) {
    errors.push(`Invalid property 'ssh.${key}' (expected number, got ${describeType(value)})`)
    return
  }
  if (options?.integer === true && !Number.isInteger(validatedNumber)) {
    errors.push(`Property 'ssh.${key}' must be an integer`)
    return
  }
  if (options?.positive === true && validatedNumber <= 0) {
    errors.push(`Property 'ssh.${key}' must be greater than 0`)
  }
}

function validateNumberValue(value: unknown): null | number {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

export function isValidTcpPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_TCP_PORT
}

function collectOptionalStringErrors(
  object: Record<string, unknown>,
  key: string,
  errors: string[]
): void {
  if (!(key in object) || object[key] == null) return
  if (typeof object[key] !== "string") {
    errors.push(`Invalid property 'ssh.${key}' (expected string, got ${describeType(object[key])})`)
    return
  }
  if (object[key].length === 0) {
    errors.push(`Property 'ssh.${key}' must not be an empty string`)
  }
}

function collectPortsErrors(ssh: Record<string, unknown>, errors: string[]): void {
  if (!("ports" in ssh)) {
    errors.push("Missing property 'ssh.ports' (expected array)")
    return
  }
  if (!Array.isArray(ssh.ports)) {
    errors.push(`Invalid property 'ssh.ports' (expected array, got ${describeType(ssh.ports)})`)
    return
  }
  if (ssh.ports.length === 0) {
    errors.push("Property 'ssh.ports' must not be empty")
    return
  }
  for (const [index, port] of ssh.ports.entries()) {
    if (!isValidTcpPort(port)) {
      errors.push(`Property 'ssh.ports[${index}]' must be an integer between 1 and 65535`)
    }
  }
}

function collectRequiredUserErrors(ssh: Record<string, unknown>, errors: string[]): void {
  if (!("user" in ssh)) {
    errors.push("Missing property 'ssh.user' (expected string)")
    return
  }
  if (typeof ssh.user !== "string") {
    errors.push(`Invalid property 'ssh.user' (expected string, got ${describeType(ssh.user)})`)
    return
  }
  if (ssh.user.length === 0) {
    errors.push("Property 'ssh.user' must not be an empty string")
  }
}

function collectStrictHostKeyCheckingErrors(ssh: Record<string, unknown>, errors: string[]): void {
  if (!("strictHostKeyChecking" in ssh) || ssh.strictHostKeyChecking == null) return
  if (typeof ssh.strictHostKeyChecking !== "string" || !isHostKeyMode(ssh.strictHostKeyChecking)) {
    errors.push(STRICT_HOST_KEY_ERROR)
  }
}

function collectOptionalSshFieldErrors(ssh: Record<string, unknown>, errors: string[]): void {
  collectOptionalStringErrors(ssh, "privateKey", errors)
  collectOptionalStringErrors(ssh, "expectedHostFingerprint", errors)
  collectOptionalStringErrors(ssh, "expectedHostPublicKey", errors)
  collectOptionalBooleanErrors(ssh, "agentForward", errors)
  collectOptionalBooleanErrors(ssh, "passwordFallback", errors)
  collectOptionalNumberErrors({
    errors,
    key: "reconnectTimeout",
    object: ssh,
    options: { positive: true },
  })
  collectOptionalNumberErrors({
    errors,
    key: "maxReconnectAttempts",
    object: ssh,
    options: { integer: true, positive: true },
  })
  collectStrictHostKeyCheckingErrors(ssh, errors)
}

export function collectSshConfigErrors(value: unknown): string[] {
  const errors: string[] = []
  if (value === null) {
    errors.push("Invalid property 'ssh' (expected object, got null)")
    return errors
  }
  if (typeof value !== "object") {
    errors.push(`Invalid property 'ssh' (expected object, got ${describeType(value)})`)
    return errors
  }
  if (!isRecord(value)) {
    errors.push("Invalid property 'ssh' (expected object, got object)")
    return errors
  }
  const ssh = value
  collectPortsErrors(ssh, errors)
  collectRequiredUserErrors(ssh, errors)
  collectOptionalSshFieldErrors(ssh, errors)
  return errors
}

function normalizeServerDefinitionSshError(error: string): string {
  const mappedErrors: Record<string, string> = {
    "Missing property 'ssh.user' (expected string)": "ssh.user is required",
    "Property 'ssh.expectedHostFingerprint' must not be an empty string":
      "ssh.expectedHostFingerprint must not be an empty string",
    "Property 'ssh.expectedHostPublicKey' must not be an empty string":
      "ssh.expectedHostPublicKey must not be an empty string",
    "Property 'ssh.ports' must not be empty": "ssh.ports must not be empty",
    "Property 'ssh.privateKey' must not be an empty string":
      "ssh.privateKey must not be an empty string",
    "Property 'ssh.user' must not be an empty string": "ssh.user is required",
    [STRICT_HOST_KEY_ERROR]: "ssh.strictHostKeyChecking must be one of accept-new, no, yes",
  }
  return mappedErrors[error] ?? error
}

export function validateSshConfig(ssh: SshConfig): void {
  const errors = collectSshConfigErrors(ssh)
  if (errors.length === 0) return
  throw new Error(`ServerDefinition: ${normalizeServerDefinitionSshError(errors[0])}`)
}
