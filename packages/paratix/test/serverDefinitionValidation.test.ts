import { describe, expect, it } from "vitest"

import type { SshConfig } from "../src/types.js"

import {
  collectSshConfigErrors,
  isValidTcpPort,
  validateSshConfig,
} from "../src/serverDefinitionValidation.js"

function baseSsh(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { ports: [22], user: "root", ...overrides }
}

describe("isValidTcpPort", () => {
  it("accepts integers within the valid TCP range", () => {
    expect(isValidTcpPort(1)).toBe(true)
    expect(isValidTcpPort(22)).toBe(true)
    expect(isValidTcpPort(65_535)).toBe(true)
  })

  it("rejects out-of-range, non-integer, and non-number values", () => {
    expect(isValidTcpPort(0)).toBe(false)
    expect(isValidTcpPort(65_536)).toBe(false)
    expect(isValidTcpPort(22.5)).toBe(false)
    expect(isValidTcpPort("22")).toBe(false)
    expect(isValidTcpPort(Number.NaN)).toBe(false)
    expect(isValidTcpPort(null)).toBe(false)
  })
})

describe("collectSshConfigErrors", () => {
  it("returns no errors for a minimal valid config", () => {
    expect(collectSshConfigErrors(baseSsh())).toStrictEqual([])
  })

  it("accepts a fully populated valid config", () => {
    const ssh = baseSsh({
      agentForward: true,
      expectedHostFingerprint: "SHA256:abc",
      maxReconnectAttempts: 3,
      passwordFallback: false,
      privateKey: "KEY",
      reconnectTimeout: 1000,
      strictHostKeyChecking: "accept-new",
      sudoPassword: "pw",
    })
    expect(collectSshConfigErrors(ssh)).toStrictEqual([])
  })

  it("reports null and non-object roots", () => {
    expect(collectSshConfigErrors(null)).toStrictEqual([
      "Invalid property 'ssh' (expected object, got null)",
    ])
    expect(collectSshConfigErrors("nope")).toStrictEqual([
      "Invalid property 'ssh' (expected object, got string)",
    ])
  })

  it("rejects non-plain-object roots such as arrays", () => {
    expect(collectSshConfigErrors([])).toStrictEqual([
      "Invalid property 'ssh' (expected object, got object)",
    ])
  })

  it("validates the ports property", () => {
    expect(collectSshConfigErrors({ user: "root" })).toContain(
      "Missing property 'ssh.ports' (expected array)"
    )
    expect(collectSshConfigErrors({ ports: 22, user: "root" })).toContain(
      "Invalid property 'ssh.ports' (expected array, got number)"
    )
    expect(collectSshConfigErrors({ ports: [], user: "root" })).toContain(
      "Property 'ssh.ports' must not be empty"
    )
    expect(collectSshConfigErrors({ ports: [0], user: "root" })).toContain(
      "Property 'ssh.ports[0]' must be an integer between 1 and 65535"
    )
  })

  it("validates the required user property", () => {
    expect(collectSshConfigErrors({ ports: [22] })).toContain(
      "Missing property 'ssh.user' (expected string)"
    )
    expect(collectSshConfigErrors({ ports: [22], user: 5 })).toContain(
      "Invalid property 'ssh.user' (expected string, got number)"
    )
    expect(collectSshConfigErrors({ ports: [22], user: "" })).toContain(
      "Property 'ssh.user' must not be an empty string"
    )
  })

  it("validates optional string fields", () => {
    expect(collectSshConfigErrors(baseSsh({ privateKey: "" }))).toContain(
      "Property 'ssh.privateKey' must not be an empty string"
    )
    expect(collectSshConfigErrors(baseSsh({ sudoPassword: 5 }))).toContain(
      "Invalid property 'ssh.sudoPassword' (expected string, got number)"
    )
    expect(collectSshConfigErrors(baseSsh({ privateKey: null }))).toStrictEqual([])
  })

  it("validates optional boolean fields", () => {
    expect(collectSshConfigErrors(baseSsh({ agentForward: "yes" }))).toContain(
      "Invalid property 'ssh.agentForward' (expected boolean, got string)"
    )
    expect(collectSshConfigErrors(baseSsh({ passwordFallback: null }))).toStrictEqual([])
  })

  it("validates optional number fields with integer and positivity rules", () => {
    expect(collectSshConfigErrors(baseSsh({ reconnectTimeout: "1000" }))).toContain(
      "Invalid property 'ssh.reconnectTimeout' (expected number, got string)"
    )
    expect(collectSshConfigErrors(baseSsh({ reconnectTimeout: 0 }))).toContain(
      "Property 'ssh.reconnectTimeout' must be greater than 0"
    )
    expect(collectSshConfigErrors(baseSsh({ maxReconnectAttempts: 1.5 }))).toContain(
      "Property 'ssh.maxReconnectAttempts' must be an integer"
    )
    expect(collectSshConfigErrors(baseSsh({ maxReconnectAttempts: -1 }))).toContain(
      "Property 'ssh.maxReconnectAttempts' must be greater than 0"
    )
    expect(
      collectSshConfigErrors(baseSsh({ reconnectTimeout: Number.POSITIVE_INFINITY }))
    ).toContain("Invalid property 'ssh.reconnectTimeout' (expected number, got number)")
  })

  it("validates strictHostKeyChecking against the allowed modes", () => {
    expect(collectSshConfigErrors(baseSsh({ strictHostKeyChecking: "maybe" }))).toContain(
      `Invalid property 'ssh.strictHostKeyChecking' (expected "accept-new", "no", or "yes")`
    )
    expect(collectSshConfigErrors(baseSsh({ strictHostKeyChecking: 1 }))).toContain(
      `Invalid property 'ssh.strictHostKeyChecking' (expected "accept-new", "no", or "yes")`
    )
    expect(collectSshConfigErrors(baseSsh({ strictHostKeyChecking: "yes" }))).toStrictEqual([])
    expect(collectSshConfigErrors(baseSsh({ strictHostKeyChecking: null }))).toStrictEqual([])
  })

  it("rejects a malformed expectedHostPublicKey", () => {
    const errors = collectSshConfigErrors(baseSsh({ expectedHostPublicKey: "not-a-real-key" }))
    expect(
      errors.some((error) => error.startsWith("Invalid property 'ssh.expectedHostPublicKey'"))
    ).toBe(true)
  })
})

describe("validateSshConfig", () => {
  it("does not throw for a valid config", () => {
    const validSsh: SshConfig = { ports: [22], user: "root" }
    expect(() => {
      validateSshConfig(validSsh)
    }).not.toThrow()
  })

  it("throws with a normalized message for a missing user", () => {
    expect(() => {
      validateSshConfig({ ports: [22] } as unknown as SshConfig)
    }).toThrow("ServerDefinition: ssh.user is required")
  })

  it("throws with a normalized message for an invalid strictHostKeyChecking", () => {
    expect(() => {
      validateSshConfig(baseSsh({ strictHostKeyChecking: "maybe" }) as unknown as SshConfig)
    }).toThrow("ServerDefinition: ssh.strictHostKeyChecking must be one of accept-new, no, yes")
  })

  it("passes through unmapped errors verbatim after the prefix", () => {
    expect(() => {
      validateSshConfig({ ports: [0], user: "root" })
    }).toThrow("ServerDefinition: Property 'ssh.ports[0]' must be an integer between 1 and 65535")
  })
})
