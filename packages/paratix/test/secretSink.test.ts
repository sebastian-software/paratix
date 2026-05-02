import { afterEach, describe, expect, it } from "vitest"

import { printCommandFailure } from "../src/output.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  maskRegisteredSecrets,
  registerSecret,
  unregisterSecret,
  withRegisteredSecrets,
} from "../src/secretSink.js"
import { CommandError } from "../src/sshHelpers.js"

const REDACTED = "[REDACTED]"

describe("secretSink — registration", () => {
  afterEach(() => {
    clearRegisteredSecrets()
  })
  it("masks registered secrets in subsequent text", () => {
    registerSecret("super-secret-token-XYZ123")
    expect(maskRegisteredSecrets("API call failed: super-secret-token-XYZ123 expired")).toBe(
      `API call failed: ${REDACTED} expired`
    )
  })

  it("returns input unchanged when no secrets are registered", () => {
    expect(maskRegisteredSecrets("nothing-to-mask here")).toBe("nothing-to-mask here")
  })

  it("ignores empty registrations so the redaction marker does not replace every byte", () => {
    registerSecret("")
    expect(getRegisteredSecrets()).toStrictEqual([])
    expect(maskRegisteredSecrets("hello world")).toBe("hello world")
  })

  it("reference-counts duplicate registrations so a single unregister keeps the secret active", () => {
    registerSecret("dup-secret")
    registerSecret("dup-secret")
    unregisterSecret("dup-secret")
    expect(maskRegisteredSecrets("see dup-secret leak")).toBe(`see ${REDACTED} leak`)
    unregisterSecret("dup-secret")
    expect(maskRegisteredSecrets("see dup-secret leak")).toBe("see dup-secret leak")
  })

  it("unregisterSecret on an unknown value is a no-op", () => {
    expect(() => {
      unregisterSecret("never-seen")
    }).not.toThrow()
  })

  it("clearRegisteredSecrets drops every entry", () => {
    registerSecret("alpha")
    registerSecret("beta")
    clearRegisteredSecrets()
    expect(getRegisteredSecrets()).toStrictEqual([])
  })
})

describe("withRegisteredSecrets", () => {
  afterEach(() => {
    clearRegisteredSecrets()
  })
  it("registers and unregisters secrets around the body", async () => {
    let observedDuringBody: string[] = []
    await withRegisteredSecrets(["one", "two"], async () => {
      observedDuringBody = getRegisteredSecrets()
      await Promise.resolve()
    })

    expect(new Set(observedDuringBody)).toStrictEqual(new Set(["one", "two"]))
    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("releases secrets even when the body throws", async () => {
    await expect(
      withRegisteredSecrets(["alpha"], async () => {
        await Promise.resolve()
        throw new Error("boom")
      })
    ).rejects.toThrow("boom")

    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("ignores empty strings without affecting the unregister bookkeeping", async () => {
    await withRegisteredSecrets(["", "value"], async () => {
      await Promise.resolve()
      expect(getRegisteredSecrets()).toStrictEqual(["value"])
    })
    expect(getRegisteredSecrets()).toStrictEqual([])
  })
})

describe("printCommandFailure — secret redaction (R-0000041)", () => {
  afterEach(() => {
    clearRegisteredSecrets()
  })
  it("redacts registered secrets in non-CommandError messages written to stderr", () => {
    registerSecret("plain-error-secret-XYZ")
    const calls: unknown[][] = []
    const originalError = console.error
    console.error = (...args: unknown[]): void => {
      calls.push(args)
    }
    try {
      printCommandFailure(new Error("Something failed: plain-error-secret-XYZ leaked"), false)
    } finally {
      console.error = originalError
    }
    const allOutput = calls.map((args) => args.map(String).join(" ")).join("\n")
    expect(calls.length).toBeGreaterThan(0)
    expect(allOutput).not.toContain("plain-error-secret-XYZ")
    expect(allOutput).toContain(REDACTED)
  })

  it("redacts registered secrets in verbose stack traces", () => {
    registerSecret("stack-trace-secret-ABC")
    const error = new Error("Detailed failure")
    error.stack = `Error: Detailed failure\n    at someFn (/file.ts:1) // stack-trace-secret-ABC inside`

    const calls: unknown[][] = []
    const originalError = console.error
    console.error = (...args: unknown[]): void => {
      calls.push(args)
    }
    try {
      printCommandFailure(error, true)
    } finally {
      console.error = originalError
    }
    const allOutput = calls.map((args) => args.map(String).join(" ")).join("\n")
    expect(calls.length).toBeGreaterThan(0)
    expect(allOutput).not.toContain("stack-trace-secret-ABC")
    expect(allOutput).toContain(REDACTED)
  })

  it("redacts registered secrets in CommandError verbose output", () => {
    registerSecret("commanderror-secret-DEF")
    const error = new CommandError(
      "Command failed",
      "stdout containing commanderror-secret-DEF",
      "stderr containing commanderror-secret-DEF"
    )

    const calls: unknown[][] = []
    const originalError = console.error
    console.error = (...args: unknown[]): void => {
      calls.push(args)
    }
    try {
      printCommandFailure(error, true)
    } finally {
      console.error = originalError
    }
    const allOutput = calls.map((args) => args.map(String).join(" ")).join("\n")
    expect(calls.length).toBeGreaterThan(0)
    expect(allOutput).not.toContain("commanderror-secret-DEF")
    expect(allOutput).toContain(REDACTED)
  })
})
