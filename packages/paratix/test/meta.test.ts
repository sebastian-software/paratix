import { describe, expect, it } from "vitest"

import { resolveEnvironment } from "../src/environment.js"
import {
  assertValidModuleMetaEntry,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
} from "../src/meta.js"

describe("meta builders and guards", () => {
  it("builds and narrows a string env entry", () => {
    const entry = meta.env("APP_NAME", "paratix")

    expect(isEnvironmentMetaEntry(entry)).toBe(true)
    expect(isStringEnvironmentMetaEntry(entry)).toBe(true)
    expect(isNumberEnvironmentMetaEntry(entry)).toBe(false)
    expect(isBooleanEnvironmentMetaEntry(entry)).toBe(false)
    expect(isLazyEnvironmentMetaEntry(entry)).toBe(true)
  })

  it("builds and narrows number and boolean env entries", () => {
    const numberEntry = meta.env("APP_PORT", 3000)
    const booleanEntry = meta.env("FEATURE_ENABLED", true)

    expect(isNumberEnvironmentMetaEntry(numberEntry)).toBe(true)
    expect(isBooleanEnvironmentMetaEntry(booleanEntry)).toBe(true)
  })

  it("builds and narrows lazy env entries", () => {
    const entry = meta.env("OTP", () => "123456")

    expect(isLazyEnvironmentMetaEntry(entry)).toBe(true)
  })

  it("builds and narrows control-plane entries", () => {
    const portEntry = meta.sshdPort(2222)
    const hostEntry = meta.systemHost("10.0.0.42")
    const rebootEntry = meta.systemReboot()

    expect(isSshdPortMetaEntry(portEntry)).toBe(true)
    expect(isSystemHostMetaEntry(hostEntry)).toBe(true)
    expect(isSystemRebootMetaEntry(rebootEntry)).toBe(true)
  })
})

describe("mergeEnvironmentFromMeta", () => {
  it("merges string, number, boolean, and lazy env entries into the runtime environment", async () => {
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("APP_NAME", "paratix"),
      meta.env("APP_PORT", 3000),
      meta.env("FEATURE_ENABLED", true),
      meta.env("OTP", () => "654321"),
    ])

    await expect(resolveEnvironment(environment, "APP_NAME")).resolves.toBe("paratix")
    await expect(resolveEnvironment(environment, "APP_PORT")).resolves.toBe(3000)
    await expect(resolveEnvironment(environment, "FEATURE_ENABLED")).resolves.toBe(true)
    await expect(resolveEnvironment(environment, "OTP")).resolves.toBe("654321")
  })

  it("ignores control-plane entries when materializing the runtime environment", async () => {
    const environment = await mergeEnvironmentFromMeta({ EXISTING: "value" }, [
      meta.sshdPort(2222),
      meta.systemHost("10.0.0.42"),
      meta.systemReboot(),
    ])

    expect(environment).toStrictEqual({ EXISTING: "value" })
  })
})

describe("meta runtime validation", () => {
  it("accepts valid built-in entries", () => {
    expect(() => {
      assertValidModuleMetaEntry(meta.env("APP_NAME", "paratix"))
    }).not.toThrow()
    expect(() => {
      assertValidModuleMetaEntry(meta.sshdPort(2222))
    }).not.toThrow()
    expect(() => {
      assertValidModuleMetaEntry(meta.systemHost("10.0.0.42"))
    }).not.toThrow()
    expect(() => {
      assertValidModuleMetaEntry(meta.systemReboot())
    }).not.toThrow()
  })

  it("rejects malformed entries", () => {
    expect(() => {
      assertValidModuleMetaEntry({ kind: "sshd.port", port: "2222" } as unknown)
    }).toThrow("Invalid sshd.port meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ host: "", kind: "system.host" } as unknown)
    }).toThrow("Invalid system.host meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ kind: "env", name: "", value: "x" } as unknown)
    }).toThrow("Invalid env meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ kind: "mystery" } as unknown)
    }).toThrow("Invalid meta entry kind")
  })
})
