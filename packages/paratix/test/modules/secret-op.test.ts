import { spawn } from "node:child_process"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { op } from "../../src/modules/op.js"
import { secret } from "../../src/modules/secret.js"
import { withSecretPrewarmScope } from "../../src/secretPrewarm.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  withRunScopedSecrets,
} from "../../src/secretSink.js"
import * as totp from "../../src/totp.js"
import { createMockSpawnChild } from "../helpers/runnerMocks.js"

vi.mock("node:child_process", () => ({ spawn: vi.fn() }))
const spawnMock = vi.mocked(spawn)
const seed = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=8"

function captureError(operation: () => unknown): unknown {
  try {
    operation()
  } catch (error) {
    return error
  }
  throw new Error("Expected the invalid configuration to fail")
}

describe("secret contract test context", () => {
  beforeEach(() => {
    spawnMock.mockReset().mockImplementation(() => createMockSpawnChild(`${seed}\n`) as never)
    clearRegisteredSecrets()
  })
  afterEach(() => {
    vi.restoreAllMocks()
    clearRegisteredSecrets()
  })

  describe("1Password secret facade contracts", () => {
    it("passes reference bytes unchanged and shares early reads across both APIs and facades", async () => {
      const reference = "op://Vault With Spaces/Item/abc123?attr=value&other=a%20b"
      spawnMock.mockImplementation(() => createMockSpawnChild("  field-value \r\n") as never)
      await withSecretPrewarmScope(async () => {
        const modules = [
          secret.provider("1password").resolve({ FIRST: reference }),
          op.resolve({ SECOND: reference }),
          secret.provider("1password").resolve({ THIRD: reference }),
        ]
        for (const module of modules) {
          // eslint-disable-next-line no-await-in-loop -- The next consumer must observe the first consumer cache entry.
          await module._prewarmSecrets?.()
          // eslint-disable-next-line no-await-in-loop, prefer-spread -- Sequential lifecycle calls test shared cache reuse.
          const result = await module.apply(null, {})
          // eslint-disable-next-line no-await-in-loop -- Meta belongs to the current lifecycle call.
          const env = await mergeEnvironmentFromMeta({}, result.meta)
          // eslint-disable-next-line no-await-in-loop -- Observe each consumer before continuing.
          await expect(resolveEnvironment(env, Object.keys(env)[0])).resolves.toBe("  field-value ")
        }
        expect(spawnMock).toHaveBeenCalledOnce()
        expect(spawnMock.mock.calls[0].slice(0, 2)).toStrictEqual(["op", ["read", "--", reference]])
      })
      expect(getRegisteredSecrets()).toStrictEqual([])
    })

    it.each(["", "?attribute=value", "?attr=value"])(
      "validates free-field seeds early and computes codes at access time: %s",
      async (query) => {
        const generate = vi.spyOn(totp, "generateTotpCode")
        const reference = `op://Vault With Spaces/Item/custom field${query}`
        const marker = { kind: "totp" as const, reference }
        const bindings = { CODE: marker }
        const module = secret.provider("1password").resolve(bindings)
        marker.reference = "op://changed/item/field?attribute=otp"
        bindings.CODE = { kind: "totp", reference: "op://changed/item/other" }
        await withSecretPrewarmScope(async () => {
          await module._prewarmSecrets?.()
          expect(generate).not.toHaveBeenCalled()
          // eslint-disable-next-line prefer-spread -- Sequential lifecycle calls test shared cache reuse.
          const result = await module.apply(null, {})

          const env = await mergeEnvironmentFromMeta({}, result.meta)
          expect(generate).not.toHaveBeenCalled()
          vi.spyOn(Date, "now").mockReturnValue(59_000)

          await expect(resolveEnvironment(env, "CODE")).resolves.toBe("94287082")
          vi.mocked(Date.now).mockReturnValue(1_111_111_109_000)

          await expect(resolveEnvironment(env, "CODE")).resolves.toBe("07081804")
          expect(spawnMock).toHaveBeenCalledOnce()
          expect(spawnMock.mock.calls[0][1]).toStrictEqual(["read", "--", reference])
          expect(generate).toHaveBeenCalledTimes(2)
        })
      }
    )

    it.each(["attribute", "attr"])(
      "reads %s=otp only when used, bypassing an identical early cache entry",
      async (alias) => {
        const reference = `op://Vault/Item/field-id?${alias}=otp`
        const module = secret.provider("1password").resolve({ CODE: secret.totp(reference) })
        spawnMock
          .mockImplementationOnce(() => createMockSpawnChild("cached-ordinary-value\n") as never)
          .mockImplementationOnce(() => createMockSpawnChild("001234\n") as never)
          .mockImplementationOnce(() => createMockSpawnChild("009876\r\n") as never)
        await withSecretPrewarmScope(async () => {
          await module._prewarmSecrets?.()
          expect(spawnMock).not.toHaveBeenCalled()
          // eslint-disable-next-line prefer-spread -- Module.apply is a lifecycle method.
          await op.resolve({ RAW: reference }).apply(null, {})
          // eslint-disable-next-line prefer-spread -- Sequential lifecycle calls test shared cache reuse.
          const result = await module.apply(null, {})

          const env = await mergeEnvironmentFromMeta({}, result.meta)
          expect(spawnMock).toHaveBeenCalledOnce()

          await expect(resolveEnvironment(env, "CODE")).resolves.toBe("001234")

          await expect(resolveEnvironment(env, "CODE")).resolves.toBe("009876")
          expect(spawnMock).toHaveBeenCalledTimes(3)
          for (const call of spawnMock.mock.calls)
            expect(call.slice(0, 2)).toStrictEqual(["op", ["read", "--", reference]])
        })
      }
    )

    it.each([
      "?attr=otp&attribute=value",
      "?attr=value&attr=value",
      "?attribute=type",
      "?attr=id",
      "?attribute=purpose",
    ])("rejects ambiguous or non-code selectors before I/O: %s", (query) => {
      const reference = `op://private-vault/private-item/field${query}`
      expect(() => secret.provider("1password").resolve({ CODE: secret.totp(reference) })).toThrow(
        Error
      )
      const error = captureError(() =>
        secret.provider("1password").resolve({ CODE: secret.totp(reference) })
      )
      expect(String(error)).not.toContain("private-")
      expect(spawnMock).not.toHaveBeenCalled()
    })

    it.each(["marked", "regular"] as const)(
      "keeps base and trimmed seed normalization independent of first consumer: %s",
      async (first) => {
        const reference = "op://Vault/Item/free field"
        const raw = `  ${seed}  `
        spawnMock.mockImplementation(() => createMockSpawnChild(`${raw}\n`) as never)
        const facade = secret.provider("1password")
        const regular = facade.resolve({ RAW: reference })
        const marked = facade.resolve({ CODE: secret.totp(reference) })
        await withSecretPrewarmScope(async () => {
          const modules = { marked, regular }
          await modules[first]._prewarmSecrets?.()
          expect(getRegisteredSecrets()).toStrictEqual([])
          await withRunScopedSecrets(async () => {
            // eslint-disable-next-line prefer-spread -- Module.apply is a lifecycle method.
            const result = await regular.apply(null, {})

            await expect(
              resolveEnvironment(await mergeEnvironmentFromMeta({}, result.meta), "RAW")
            ).resolves.toBe(raw)
            // eslint-disable-next-line prefer-spread -- Module.apply is a lifecycle method.
            const codes = await marked.apply(null, {})

            await expect(
              resolveEnvironment(await mergeEnvironmentFromMeta({}, codes.meta), "CODE")
            ).resolves.toMatch(/^\d{8}$/v)
            expect(getRegisteredSecrets()).toContain(raw)
            expect(getRegisteredSecrets()).toContain(seed)
          })
          expect(spawnMock).toHaveBeenCalledOnce()
        })
        expect(getRegisteredSecrets()).toStrictEqual([])
      }
    )

    it.each([
      "not-a-uri",
      "otpauth://hotp/Test?secret=AAAA",
      "otpauth://totp/Test?secret=not!base32",
      "otpauth://totp/Test?secret=AAAA&period=0",
    ])(
      "rejects an invalid marked seed before a consumer without generating a code: %s",
      async (invalid) => {
        spawnMock.mockImplementation(() => createMockSpawnChild(`${invalid}\n`) as never)
        const generate = vi.spyOn(totp, "generateTotpCode")
        const module = secret
          .provider("1password")
          .resolve({ CODE: secret.totp("op://Vault/Item/field") })
        await expect(module._prewarmSecrets?.()).rejects.toThrow(Error)
        expect(generate).not.toHaveBeenCalled()
        expect(getRegisteredSecrets()).toStrictEqual([])
      }
    )
  })
})
