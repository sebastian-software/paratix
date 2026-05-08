import { afterEach, describe, expect, it, vi } from "vitest"

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

  it("rejects registrations that already contain the redaction placeholder", () => {
    expect(() => {
      registerSecret(`token-${REDACTED}-value`)
    }).toThrow("redaction placeholder")

    expect(getRegisteredSecrets()).toStrictEqual([])
    expect(maskRegisteredSecrets(`token-${REDACTED}-value`)).toBe(`token-${REDACTED}-value`)
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

  it("masks scoped secrets on errors before unregistering", async () => {
    await expect(
      withRegisteredSecrets(["alpha"], async () => {
        await Promise.resolve()
        throw new Error("boom alpha")
      })
    ).rejects.toThrow("boom [REDACTED]")

    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("masks scoped secrets on primitive error causes before unregistering", async () => {
    await expect(
      withRegisteredSecrets(["primitive-cause-secret"], async () => {
        await Promise.resolve()
        throw Object.assign(new Error("boom"), { cause: "primitive-cause-secret" })
      })
    ).rejects.toHaveProperty("cause", REDACTED)

    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("masks scoped secrets on failed module results before unregistering", async () => {
    const result = await withRegisteredSecrets(["alpha"], async () => {
      await Promise.resolve()
      return {
        error: new CommandError("failed alpha", "stdout alpha", "stderr alpha"),
        status: "failed" as const,
      }
    })

    expect(result.error.message).toBe("failed [REDACTED]")
    expect(result.error).toBeInstanceOf(CommandError)
    expect((result.error as CommandError | undefined)?.fullStdout).toBe("stdout [REDACTED]")
    expect((result.error as CommandError | undefined)?.fullStderr).toBe("stderr [REDACTED]")
    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("ignores empty strings without affecting the unregister bookkeeping", async () => {
    await withRegisteredSecrets(["", "value"], async () => {
      await Promise.resolve()
      expect(getRegisteredSecrets()).toStrictEqual(["value"])
    })
    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("validates all scoped secrets before mutating the global sink", async () => {
    await expect(
      withRegisteredSecrets(["alpha", `token-${REDACTED}-value`], async () => {
        await Promise.resolve()
      })
    ).rejects.toThrow("redaction placeholder")

    expect(getRegisteredSecrets()).toStrictEqual([])
    expect(maskRegisteredSecrets("alpha")).toBe("alpha")
  })

  it("releases already-registered secrets when registration is interrupted (R-0000195)", async () => {
    // Regression: the register loop must run inside the same try/finally as
    // the body so a throw between two registrations releases everything.
    // Force a throw mid-registration by spying on Map.prototype.set and
    // failing the second call.
    // eslint-disable-next-line @typescript-eslint/unbound-method -- bound to Map instance via call() below
    const originalSet = Map.prototype.set
    const setSpy = vi
      .spyOn(Map.prototype, "set")
      .mockImplementationOnce(function mockedSet(this: Map<unknown, unknown>, key, value) {
        return originalSet.call(this, key, value)
      })
      .mockImplementationOnce(() => {
        throw new Error("simulated register failure")
      })

    await expect(
      withRegisteredSecrets(["alpha", "beta"], async () => {
        await Promise.resolve()
      })
    ).rejects.toThrow("simulated register failure")

    setSpy.mockRestore()

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

  it("redacts registered secrets in verbose error causes", () => {
    registerSecret("cause-secret-GHI")
    const cause = new Error("Nested failure")
    cause.stack = "Error: Nested failure\n    at nested (/file.ts:1) // cause-secret-GHI inside"
    const error = Object.assign(new Error("Outer failure"), { cause })

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
    expect(allOutput).not.toContain("cause-secret-GHI")
    expect(allOutput).toContain(REDACTED)
  })

  it("redacts registered secrets in verbose non-error causes", () => {
    registerSecret("primitive-cause-secret-JKL")
    const error = Object.assign(new Error("Outer failure"), {
      cause: "primitive-cause-secret-JKL",
    })

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
    expect(allOutput).not.toContain("primitive-cause-secret-JKL")
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
