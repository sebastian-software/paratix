import { describe, expect, it, vi } from "vitest"

import type { EnvironmentMetaEntry } from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import {
  assertValidModuleMetaEntry,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  isEnvironmentMetaEntry,
  isLazyEnvironmentMetaEntry,
  isStringEnvironmentMetaEntry,
  mergeEnvironmentFromMeta,
} from "../src/meta.js"

function perAccess(resolve: EnvironmentMetaEntry["resolve"]): EnvironmentMetaEntry {
  return { ...environmentMeta("CODE", resolve, "string"), resolution: "per-access" }
}

describe("per-access environment resolution", () => {
  it("retains lazy policy through repeated merges, a roundtrip, a diff, and a default outer wrapper", async () => {
    const resolve = vi
      .fn<EnvironmentMetaEntry["resolve"]>()
      .mockResolvedValueOnce("first")
      .mockResolvedValueOnce("second")
      .mockResolvedValueOnce("third")
    const original = await mergeEnvironmentFromMeta({}, [perAccess(resolve)])
    const roundtripEntries = environmentToMetaEntries(original)
    expect(roundtripEntries).toStrictEqual([expect.objectContaining({ resolution: "per-access" })])
    const roundtrip = await mergeEnvironmentFromMeta({}, roundtripEntries)
    const diff = diffEnvironmentToMetaEntries({}, roundtrip)
    expect(diff).toStrictEqual([expect.objectContaining({ resolution: "per-access" })])
    const derived = await mergeEnvironmentFromMeta({}, diff)
    const entry = environmentMeta("CODE", derived.CODE)
    delete entry.resolution
    const outer = await mergeEnvironmentFromMeta({}, [entry])
    expect(resolve).not.toHaveBeenCalled()
    await expect(resolveEnvironment(outer, "CODE")).resolves.toBe("first")
    await expect(resolveEnvironment(outer, "CODE")).resolves.toBe("second")
    await expect(resolveEnvironment(original, "CODE")).resolves.toBe("third")
    expect(resolve).toHaveBeenCalledTimes(3)
  })

  it("shares an open original resolver with a roundtrip environment but never its completed value", async () => {
    const pending = Promise.withResolvers<string>()
    const resolve = vi
      .fn<EnvironmentMetaEntry["resolve"]>()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce("next")
    const original = await mergeEnvironmentFromMeta({}, [perAccess(resolve)])
    const derived = await mergeEnvironmentFromMeta({}, environmentToMetaEntries(original))
    const first = resolveEnvironment(original, "CODE")
    const second = resolveEnvironment(derived, "CODE")
    await vi.waitFor(() => {
      expect(resolve).toHaveBeenCalledOnce()
    })
    pending.resolve("shared")
    await expect(Promise.all([first, second])).resolves.toStrictEqual(["shared", "shared"])
    await expect(resolveEnvironment(derived, "CODE")).resolves.toBe("next")
    expect(resolve).toHaveBeenCalledTimes(2)
  })

  it("shares a failed pending request, then retries instead of keeping the error", async () => {
    const pending = Promise.withResolvers<string>()
    const resolve = vi
      .fn<EnvironmentMetaEntry["resolve"]>()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce("recovered")
    const env = await mergeEnvironmentFromMeta({}, [perAccess(resolve)])
    const reads = Promise.allSettled([
      resolveEnvironment(env, "CODE"),
      resolveEnvironment(env, "CODE"),
    ])
    await vi.waitFor(() => {
      expect(resolve).toHaveBeenCalledOnce()
    })
    pending.reject(new Error("cancelled"))
    expect(await reads).toStrictEqual([
      expect.objectContaining({ status: "rejected" }),
      expect.objectContaining({ status: "rejected" }),
    ])
    await expect(resolveEnvironment(env, "CODE")).resolves.toBe("recovered")
    expect(resolve).toHaveBeenCalledTimes(2)
  })

  it("does not cache synchronous failures", async () => {
    const resolve = vi
      .fn<EnvironmentMetaEntry["resolve"]>()
      .mockImplementationOnce(() => {
        throw new Error("sync failure")
      })
      .mockResolvedValueOnce("recovered")
    const env = await mergeEnvironmentFromMeta({}, [perAccess(resolve)])
    await expect(resolveEnvironment(env, "CODE")).rejects.toThrow("sync failure")
    await expect(resolveEnvironment(env, "CODE")).resolves.toBe("recovered")
  })

  it.each([undefined, "per-access"] as const)(
    "retains type checking and retry behavior with policy=%s",
    async (resolution) => {
      const resolve = vi
        .fn<EnvironmentMetaEntry["resolve"]>()
        .mockResolvedValueOnce(123)
        .mockResolvedValueOnce(null as never)
        .mockResolvedValueOnce("valid")
      const entry = { ...environmentMeta("CODE", resolve, "string"), resolution }
      const env = await mergeEnvironmentFromMeta({}, [entry])
      await expect(resolveEnvironment(env, "CODE")).rejects.toThrow("expected string")
      await expect(resolveEnvironment(env, "CODE")).rejects.toThrow(
        "expected boolean, number, or string"
      )
      await expect(resolveEnvironment(env, "CODE")).resolves.toBe("valid")
      expect(isEnvironmentMetaEntry(entry)).toBe(true)
      expect(isLazyEnvironmentMetaEntry(entry)).toBe(true)
      expect(isStringEnvironmentMetaEntry(entry)).toBe(true)
    }
  )

  it("keeps ordinary successful entries memoized", async () => {
    const resolve = vi
      .fn<EnvironmentMetaEntry["resolve"]>()
      .mockResolvedValueOnce("original")
      .mockResolvedValueOnce("changed")
    const env = await mergeEnvironmentFromMeta({}, [environmentMeta("VALUE", resolve)])
    const roundtrip = await mergeEnvironmentFromMeta({}, environmentToMetaEntries(env))
    await expect(resolveEnvironment(env, "VALUE")).resolves.toBe("original")
    await expect(resolveEnvironment(roundtrip, "VALUE")).resolves.toBe("original")
    expect(resolve).toHaveBeenCalledOnce()
  })

  it("rejects an invalid explicit policy at assertion and merge boundaries without executing it", async () => {
    const resolve = vi.fn<EnvironmentMetaEntry["resolve"]>()
    const entry = { ...environmentMeta("VALUE", resolve), resolution: "forever" } as never
    expect(() => {
      assertValidModuleMetaEntry(entry)
    }).toThrow("resolution")
    await expect(mergeEnvironmentFromMeta({}, [entry])).rejects.toThrow("resolution")
    expect(resolve).not.toHaveBeenCalled()
  })
})
