import { describe, expect, it, vi } from "vitest"

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

  it("accepts lazy number and boolean env entries without an explicit valueType", async () => {
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("LAZY_PORT", () => 3000),
      meta.env("LAZY_FEATURE_ENABLED", () => true),
    ])

    await expect(resolveEnvironment(environment, "LAZY_PORT")).resolves.toBe(3000)
    await expect(resolveEnvironment(environment, "LAZY_FEATURE_ENABLED")).resolves.toBe(true)
  })

  it("ignores control-plane entries when materializing the runtime environment", async () => {
    const environment = await mergeEnvironmentFromMeta({ EXISTING: "value" }, [
      meta.sshdPort(2222),
      meta.systemHost("10.0.0.42"),
      meta.systemReboot(),
    ])

    expect({ ...environment }).toStrictEqual({ EXISTING: "value" })
  })

  it("does not expose Object.prototype methods as lazy resolvers when entry name is toString", async () => {
    // R-0000074: a meta entry whose name shadows Object.prototype.toString
    // must override the prototype method only when the entry is explicitly
    // set. Crucially, accessing other prototype-only keys must not return
    // an inherited resolver, because the merged environment is
    // null-prototype.
    const environment = await mergeEnvironmentFromMeta({}, [meta.env("toString", "shadow")])

    // The explicitly set entry resolves to the user-supplied value, not the
    // inherited Object.prototype.toString.
    await expect(resolveEnvironment(environment, "toString")).resolves.toBe("shadow")

    // The merged environment must have a null prototype so prototype-only
    // keys (e.g. hasOwnProperty, valueOf) are not inherited as resolvers.
    expect(Object.getPrototypeOf(environment)).toBeNull()
  })

  it("memoizes lazy env entries so each entry resolves at most once across multiple accesses", async () => {
    let resolveCalls = 0
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("CACHED_TOKEN", () => {
        resolveCalls += 1
        return `value-${String(resolveCalls)}`
      }),
    ])

    const first = await resolveEnvironment(environment, "CACHED_TOKEN")
    const second = await resolveEnvironment(environment, "CACHED_TOKEN")
    const third = await resolveEnvironment(environment, "CACHED_TOKEN")

    expect(first).toBe("value-1")
    expect(second).toBe("value-1")
    expect(third).toBe("value-1")
    expect(resolveCalls).toBe(1)
  })

  it("coalesces concurrent accesses to the same env entry into a single resolve invocation", async () => {
    let resolveCalls = 0
    const deferred: { release: (value: string) => void } = {
      release() {
        throw new Error("release called before initialization")
      },
    }
    const pending = new Promise<string>((resolve) => {
      deferred.release = resolve
    })
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("CONCURRENT_TOKEN", async () => {
        resolveCalls += 1
        return pending
      }),
    ])

    const first = resolveEnvironment(environment, "CONCURRENT_TOKEN")
    const second = resolveEnvironment(environment, "CONCURRENT_TOKEN")
    deferred.release("shared-value")

    await expect(first).resolves.toBe("shared-value")
    await expect(second).resolves.toBe("shared-value")
    expect(resolveCalls).toBe(1)
  })

  it("retries after a rejected resolve so transient failures do not poison the cache", async () => {
    const resolver = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("transient"))
      .mockResolvedValueOnce("recovered")
    const environment = await mergeEnvironmentFromMeta({}, [meta.env("RETRY_TOKEN", resolver)])

    await expect(resolveEnvironment(environment, "RETRY_TOKEN")).rejects.toThrow("transient")
    await expect(resolveEnvironment(environment, "RETRY_TOKEN")).resolves.toBe("recovered")
    expect(resolver).toHaveBeenCalledTimes(2)
  })

  it("rejects meta entries whose name is a reserved JavaScript identifier", async () => {
    await expect(mergeEnvironmentFromMeta({}, [meta.env("__proto__", "evil")])).rejects.toThrow(
      /Forbidden env meta entry name/v
    )
    await expect(mergeEnvironmentFromMeta({}, [meta.env("constructor", "evil")])).rejects.toThrow(
      /Forbidden env meta entry name/v
    )
    await expect(mergeEnvironmentFromMeta({}, [meta.env("prototype", "evil")])).rejects.toThrow(
      /Forbidden env meta entry name/v
    )
  })

  // R-0000264: a provider that drifts away from its declared valueType (e.g.
  // a 1Password CLI that suddenly returns a number for a "string"-typed key,
  // or a misconfigured resolver that yields null/an object) must fail fast
  // at the boundary. Without runtime validation the unexpected typeof would
  // propagate through resolveEnvironment into downstream modules and
  // template rendering.
  it("rejects a resolved value whose typeof differs from the declared valueType", async () => {
    // Provider promises a string (the explicit valueType) but resolves to a
    // number — the boundary must surface a TypeError that names the entry,
    // expected type, and actual typeof so operators can locate the drift.
    // The declared valueType "string" is the contract; the inferred runtime
    // value (42) must be rejected even though TypeScript's structural typing
    // accepts `() => number` for MetaEnvironmentValue.
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("DRIFT_KEY", () => 42, "string"),
    ])

    await expect(resolveEnvironment(environment, "DRIFT_KEY")).rejects.toThrow(TypeError)
    await expect(resolveEnvironment(environment, "DRIFT_KEY")).rejects.toThrow(/"DRIFT_KEY"/v)
    await expect(resolveEnvironment(environment, "DRIFT_KEY")).rejects.toThrow(/typeof number/v)
    await expect(resolveEnvironment(environment, "DRIFT_KEY")).rejects.toThrow(/expected string/v)
  })

  it("rejects lazy number and boolean values when an incompatible valueType was explicit", async () => {
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("NUMBER_DRIFT", () => 42, "string"),
      meta.env("BOOLEAN_DRIFT", () => true, "number"),
    ])

    await expect(resolveEnvironment(environment, "NUMBER_DRIFT")).rejects.toThrow(
      /typeof number, expected string/v
    )
    await expect(resolveEnvironment(environment, "BOOLEAN_DRIFT")).rejects.toThrow(
      /typeof boolean, expected number/v
    )
  })

  it("does not poison the resolver cache when valueType validation fails", async () => {
    // First call drifts to a number, second call returns the declared
    // string. The cache must drop the rejected promise so the retry
    // surfaces the corrected value instead of replaying the TypeError.
    const resolver = vi
      .fn<() => Promise<boolean | number | string>>()
      .mockResolvedValueOnce(42)
      .mockResolvedValueOnce("ok")
    const environment = await mergeEnvironmentFromMeta({}, [
      meta.env("RECOVERED_KEY", resolver, "string"),
    ])

    await expect(resolveEnvironment(environment, "RECOVERED_KEY")).rejects.toThrow(TypeError)
    await expect(resolveEnvironment(environment, "RECOVERED_KEY")).resolves.toBe("ok")
    expect(resolver).toHaveBeenCalledTimes(2)
  })

  it("rejects a resolved value of typeof object even when the declared type is string", async () => {
    // The MetaEnvironmentValue union does not include null, but providers can
    // misbehave at runtime; the boundary must catch that drift too. Constructing
    // the EnvironmentMetaEntry directly (instead of going through meta.env)
    // lets the test target the runtime path without TypeScript narrowing the
    // input.
    const driftingResolver = vi
      .fn<() => Promise<boolean | number | string>>()
      // The mock returns null even though the resolver type forbids it; this
      // is the exact runtime drift the boundary check must reject.
      .mockResolvedValue(null as unknown as string)
    const environment = await mergeEnvironmentFromMeta({}, [
      { kind: "env", name: "NULL_DRIFT", resolve: driftingResolver, valueType: "string" },
    ])

    await expect(resolveEnvironment(environment, "NULL_DRIFT")).rejects.toThrow(TypeError)
    await expect(resolveEnvironment(environment, "NULL_DRIFT")).rejects.toThrow(/typeof object/v)
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
      assertValidModuleMetaEntry({ kind: "sshd.port", port: "2222" })
    }).toThrow("Invalid sshd.port meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ host: "", kind: "system.host" })
    }).toThrow("Invalid system.host meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ kind: "env", name: "", value: "x" })
    }).toThrow("Invalid env meta entry")
    expect(() => {
      assertValidModuleMetaEntry({ kind: "mystery" })
    }).toThrow("Invalid meta entry kind")
  })
})
