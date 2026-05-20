import { describe, expect, it, vi } from "vitest"

import { server } from "../src/server.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const validModule = {
  apply: vi.fn().mockResolvedValue({ status: "ok" }),
  check: vi.fn().mockResolvedValue("ok"),
  name: "noop",
}

const validSsh = { ports: [22], privateKey: "/home/user/.ssh/id_ed25519", user: "root" }

function validConfig(overrides: Record<string, unknown> = {}) {
  return {
    host: "example.com",
    name: "web-01",
    run: [validModule],
    ssh: validSsh,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// server() validation
// ---------------------------------------------------------------------------

describe("server", () => {
  it("returns the config unchanged for a valid definition", () => {
    const config = validConfig()
    const result = server(config)
    expect(result).toBe(config)
  })

  it("throws when host is empty", () => {
    expect(() => server(validConfig({ host: "" }) as Parameters<typeof server>[0])).toThrow(
      "ServerDefinition: host is required"
    )
  })

  it.each(["*.example.com", "host?.example.com", "!host.example.com", "host,alias"])(
    "throws when host contains an OpenSSH known_hosts metacharacter (%s)",
    (host) => {
      expect(() => server(validConfig({ host }) as Parameters<typeof server>[0])).toThrow(
        "ServerDefinition: host must not contain OpenSSH known_hosts pattern metacharacters"
      )
    }
  )

  it.each([
    ["bad host", "whitespace"],
    ["bad\nhost", "control characters"],
  ])("throws when host contains %s", (host, message) => {
    expect(() => server(validConfig({ host }) as Parameters<typeof server>[0])).toThrow(
      `ServerDefinition: host must not contain ${message}`
    )
  })

  it("accepts an IPv6 host literal", () => {
    expect(() =>
      server(validConfig({ host: "2001:db8::1" }) as Parameters<typeof server>[0])
    ).not.toThrow()
  })

  it("throws when name is empty", () => {
    expect(() => server(validConfig({ name: "" }) as Parameters<typeof server>[0])).toThrow(
      "ServerDefinition: name is required"
    )
  })

  it("throws when run is empty", () => {
    expect(() => server(validConfig({ run: [] }) as Parameters<typeof server>[0])).toThrow(
      "ServerDefinition: run must contain at least one module"
    )
  })

  it("throws when signals is not an array in an untyped JS playbook", () => {
    expect(() =>
      server(validConfig({ signals: validModule }) as unknown as Parameters<typeof server>[0])
    ).toThrow("ServerDefinition: signals must be an array of modules")
  })

  it("throws when signals contains a malformed module in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          signals: [{ ...validModule, name: "" }],
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: signals[0] must be a module with name, check, and apply")
  })

  it("throws when ssh.ports is empty", () => {
    expect(() =>
      server(validConfig({ ssh: { ...validSsh, ports: [] } }) as Parameters<typeof server>[0])
    ).toThrow("ServerDefinition: ssh.ports must not be empty")
  })

  it("throws when ssh.ports contains zero in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, ports: [0] },
        }) as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: Property 'ssh.ports[0]' must be an integer between 1 and 65535")
  })

  it("throws when ssh.ports contains 65536 in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, ports: [65_536] },
        }) as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: Property 'ssh.ports[0]' must be an integer between 1 and 65535")
  })

  it("throws when ssh.ports contains a string in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, ports: ["22"] },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: Property 'ssh.ports[0]' must be an integer between 1 and 65535")
  })

  it("throws when ssh.user is empty", () => {
    expect(() =>
      server(validConfig({ ssh: { ...validSsh, user: "" } }) as Parameters<typeof server>[0])
    ).toThrow("ServerDefinition: ssh.user is required")
  })

  it("throws when ssh.privateKey is an empty string", () => {
    expect(() =>
      server(validConfig({ ssh: { ...validSsh, privateKey: "" } }) as Parameters<typeof server>[0])
    ).toThrow("ServerDefinition: ssh.privateKey must not be an empty string")
  })

  it("throws when ssh.agentForward is not a boolean in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, agentForward: "yes" },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow(
      "ServerDefinition: Invalid property 'ssh.agentForward' (expected boolean, got string)"
    )
  })

  it("throws when ssh.passwordFallback is not a boolean in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, passwordFallback: "no" },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow(
      "ServerDefinition: Invalid property 'ssh.passwordFallback' (expected boolean, got string)"
    )
  })

  it("throws when ssh.sudoPassword is not a string in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, sudoPassword: 123 },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: Invalid property 'ssh.sudoPassword' (expected string, got number)")
  })

  it("throws when ssh.reconnectTimeout is not a number in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, reconnectTimeout: "5000" },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow(
      "ServerDefinition: Invalid property 'ssh.reconnectTimeout' (expected number, got string)"
    )
  })

  it("throws when ssh.maxReconnectAttempts is not an integer in an untyped JS playbook", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, maxReconnectAttempts: 1.5 },
        }) as unknown as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: Property 'ssh.maxReconnectAttempts' must be an integer")
  })

  // ---------------------------------------------------------------------------
  // validateSshConfig: strictHostKeyChecking
  // ---------------------------------------------------------------------------

  it("accepts strictHostKeyChecking 'accept-new'", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: "accept-new" },
        }) as Parameters<typeof server>[0]
      )
    ).not.toThrow()
  })

  it("accepts strictHostKeyChecking 'no'", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: "no" },
        }) as Parameters<typeof server>[0]
      )
    ).not.toThrow()
  })

  it("accepts strictHostKeyChecking 'yes'", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: "yes" },
        }) as Parameters<typeof server>[0]
      )
    ).not.toThrow()
  })

  it("accepts undefined strictHostKeyChecking (optional field)", () => {
    expect(() => server(validConfig() as Parameters<typeof server>[0])).not.toThrow()
  })

  it("accepts expectedHostFingerprint and expectedHostPublicKey", () => {
    expect(() =>
      server(
        validConfig({
          ssh: {
            ...validSsh,
            expectedHostFingerprint: "SHA256:trusted-fingerprint",
            expectedHostPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItrusted",
          },
        }) as Parameters<typeof server>[0]
      )
    ).not.toThrow()
  })

  it("throws when expectedHostFingerprint is an empty string", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, expectedHostFingerprint: "" },
        }) as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: ssh.expectedHostFingerprint must not be an empty string")
  })

  it("accepts null strictHostKeyChecking (treated as absent)", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: null },
        }) as Parameters<typeof server>[0]
      )
    ).not.toThrow()
  })

  it("throws when strictHostKeyChecking has an invalid string value", () => {
    expect(() =>
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: "always" },
        }) as Parameters<typeof server>[0]
      )
    ).toThrow("ServerDefinition: ssh.strictHostKeyChecking must be one of accept-new, no, yes")
  })

  it("error message for invalid strictHostKeyChecking lists all valid options", () => {
    let message = ""
    try {
      server(
        validConfig({
          ssh: { ...validSsh, strictHostKeyChecking: "bad-value" },
        })
      )
    } catch (error) {
      message = (error as Error).message
    }
    expect(message).toContain("accept-new")
    expect(message).toContain("no")
    expect(message).toContain("yes")
  })
})
