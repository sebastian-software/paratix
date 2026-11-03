/* oxlint-disable vitest/no-conditional-in-test -- Table-driven cases explicitly select fixture inputs and expected outcomes; every case runs its assertions. */
import { inspect } from "node:util"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { SecretResolver } from "../src/modules/secret.js"

import { assertSecretHandle, withDeferredSecret } from "../src/modules/deferredSecret.js"
import * as providerProcess from "../src/modules/opSpawnRunner.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import {
  hasSecretPrewarmCarriers,
  prewarmSecrets,
  withSecretPrewarmScope,
} from "../src/secretPrewarm.js"
import { maskRegisteredSecrets, withRunScopedSecrets } from "../src/secretSink.js"
import * as terminal from "../src/terminal.js"

const REFERENCE = "op://private-test-vault/private-item/private-field"
const FIRST = "marked-first-deferred-password"
const SECOND = "marked-second-deferred-password"
const CA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"

async function consume(value: string): Promise<string> {
  await Promise.resolve()
  return value
}

async function run<T>(body: () => Promise<T>): Promise<T> {
  return withRunScopedSecrets(async () => withSecretPrewarmScope(body))
}

describe("provider-bound deferred credential lifecycle", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })
  it("prompts manually only on use with a safe consumer label rather than the private source or caller labels", async () => {
    const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
    const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")
    const prompt = vi.spyOn(terminal, "promptTerminal").mockResolvedValue(FIRST)
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
    try {
      const handle = secret
        .provider("manual", { labels: { "SSH certificate signer": REFERENCE } })
        .deferred(REFERENCE)
      expect(prompt).not.toHaveBeenCalled()
      expect(await run(async () => withDeferredSecret(handle, consume))).toBe(FIRST)
      expect(prompt).toHaveBeenCalledExactlyOnceWith("SSH certificate signer: ", true, {
        abortSignal: undefined,
      })
      expect(inspect(prompt.mock.calls)).not.toContain(REFERENCE)
    } finally {
      if (stdinTty === undefined) Reflect.deleteProperty(process.stdin, "isTTY")
      else Object.defineProperty(process.stdin, "isTTY", stdinTty)
      if (stderrTty === undefined) Reflect.deleteProperty(process.stderr, "isTTY")
      else Object.defineProperty(process.stderr, "isTTY", stderrTty)
    }
  })

  it("creates no provider access, prewarm carrier or environment metadata at construction/check/dry-run", async () => {
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    const handle = secret.provider("1password").deferred(REFERENCE)
    const signer = ssh.signer.stepCa({
      caPublicKey: CA,
      caUrl: "https://ca.invalid",
      password: handle,
      provisioner: "fixture",
      root: "/tmp/public-test-root.pem",
    })
    const sign = vi.fn(signer.sign)
    const module = ssh.hostCertificate({ principals: ["host.test"], signer: { ...signer, sign } })
    expect(hasSecretPrewarmCarriers([module])).toBe(false)
    await prewarmSecrets([module])
    expect(await module.check(null, {})).toBe("needs-apply")
    const dry = await module._applyDryRun?.(null, {})
    expect(dry?.status).toBe("failed")
    expect(dry).not.toHaveProperty("meta")
    expect(module).not.toHaveProperty("_dryRunMetaProducer")
    expect(inspect(module, { depth: null })).not.toContain(REFERENCE)
    expect(provider).not.toHaveBeenCalled()
    expect(sign).not.toHaveBeenCalled()
  })

  it("rejects stolen brands, copied descriptors, deserialized and forged handles without reference disclosure", async () => {
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    const handle = secret.provider("1password").deferred(REFERENCE)
    const copies: unknown[] = [
      {},
      null,
      REFERENCE,
      { ...handle },
      Object.create(Object.getPrototypeOf(handle), Object.getOwnPropertyDescriptors(handle)),
      JSON.parse("{}"),
    ]
    for (const copy of copies) {
      expect(() => {
        assertSecretHandle(copy)
      }).toThrow("provider-bound")
      // Exercise the real resolver gate as well as the standalone predicate.
      // eslint-disable-next-line no-await-in-loop -- Each forged identity must fail independently before any provider access.
      await expect(
        // @ts-expect-error Runtime protection must reject values that bypass the public nominal type.
        withDeferredSecret(copy, async () => {
          await Promise.resolve()
          return "unreachable"
        })
      ).rejects.toThrow("provider-bound")
    }
    expect(Object.isFrozen(handle)).toBe(true)
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- Intentionally exercise runtime stringification of the opaque nominal type.
    expect(String(handle)).toBe("SecretHandle [redacted]")
    expect(inspect(handle)).toBe("SecretHandle [redacted]")
    expect(inspect(handle, { customInspect: false, depth: null, showHidden: true })).not.toContain(
      REFERENCE
    )
    expect(() => JSON.stringify({ handle })).toThrow("cannot be serialized")
    expect(() => structuredClone(handle)).toThrow("could not be cloned")
    expect(provider).not.toHaveBeenCalled()
  })

  it("deduplicates concurrent handles from one provider instance and masks through the whole run", async () => {
    const provider = vi.spyOn(providerProcess, "spawnWithInput").mockResolvedValue(FIRST)
    const resolver = secret.provider("1password")
    const handles = [resolver.deferred(REFERENCE), resolver.deferred(REFERENCE)]
    await run(async () => {
      expect(
        await Promise.all(handles.map(async (handle) => withDeferredSecret(handle, consume)))
      ).toStrictEqual([FIRST, FIRST])
      expect(provider).toHaveBeenCalledTimes(1)
      expect(maskRegisteredSecrets(`diagnostic ${FIRST}`)).not.toContain(FIRST)
      await Promise.resolve()
      expect(maskRegisteredSecrets(FIRST)).not.toContain(FIRST)
    })
    expect(maskRegisteredSecrets(FIRST)).toBe(FIRST)
  })

  it("binds identical references to distinct provider instances rather than sharing another provider's credential", async () => {
    const provider = vi
      .spyOn(providerProcess, "spawnWithInput")
      .mockResolvedValueOnce(FIRST)
      .mockResolvedValueOnce(SECOND)
    const first = secret.provider("1password").deferred(REFERENCE)
    const second = secret.provider("1password").deferred(REFERENCE)
    await run(async () => {
      expect(await withDeferredSecret(first, consume)).toBe(FIRST)
      expect(await withDeferredSecret(second, consume)).toBe(SECOND)
      expect(await withDeferredSecret(first, consume)).toBe(FIRST)
      expect(provider).toHaveBeenCalledTimes(2)
    })
  })

  it("retains neither resolved credentials nor promises when the same handle enters a new run", async () => {
    const provider = vi
      .spyOn(providerProcess, "spawnWithInput")
      .mockResolvedValueOnce(FIRST)
      .mockResolvedValueOnce(SECOND)
    const handle = secret.provider("1password").deferred(REFERENCE)
    expect(await run(async () => withDeferredSecret(handle, consume))).toBe(FIRST)
    expect(await run(async () => withDeferredSecret(handle, consume))).toBe(SECOND)
    expect(provider).toHaveBeenCalledTimes(2)
    expect(inspect(handle, { customInspect: false, depth: null, showHidden: true })).not.toContain(
      FIRST
    )
    expect(maskRegisteredSecrets(SECOND)).toBe(SECOND)
  })

  it("isolates simultaneous run caches even while an earlier credential request is unresolved", async () => {
    let completeFirst: (value: string) => void = vi.fn<(value: string) => void>()
    const provider = vi
      .spyOn(providerProcess, "spawnWithInput")
      .mockImplementationOnce(
        async () =>
          new Promise<string>((resolve) => {
            completeFirst = resolve
          })
      )
      .mockResolvedValueOnce(SECOND)
    const handle = secret.provider("1password").deferred(REFERENCE)
    const first = run(async () => withDeferredSecret(handle, consume))
    const second = run(async () => withDeferredSecret(handle, consume))
    expect(await second).toBe(SECOND)
    completeFirst(FIRST)
    expect(await first).toBe(FIRST)
    expect(provider).toHaveBeenCalledTimes(2)
  })

  it("discards raw provider and consumer errors including causes, then resolves freshly on a later run", async () => {
    const provider = vi
      .spyOn(providerProcess, "spawnWithInput")
      .mockRejectedValueOnce(new Error(`${REFERENCE} ${FIRST}`, { cause: new Error(SECOND) }))
      .mockResolvedValueOnce(SECOND)
    const handle = secret.provider("1password").deferred(REFERENCE)
    const failure = await run(async () =>
      withDeferredSecret(handle, async () => {
        await Promise.resolve()
        return "unreachable"
      })
    ).catch((error: unknown) => error)
    expect(inspect(failure, { depth: null })).not.toContain(REFERENCE)
    expect(inspect(failure, { depth: null })).not.toContain(FIRST)
    expect(inspect(failure, { depth: null })).not.toContain(SECOND)
    expect(failure).not.toHaveProperty("cause")
    await run(async () => {
      const consumerFailure = await withDeferredSecret(handle, async () => {
        await Promise.resolve()
        throw new Error(SECOND, { cause: new Error(REFERENCE) })
      }).catch((error: unknown) => error)
      expect(inspect(consumerFailure, { depth: null })).not.toContain(SECOND)
      expect(inspect(consumerFailure, { depth: null })).not.toContain(REFERENCE)
      expect(maskRegisteredSecrets(SECOND)).not.toContain(SECOND)
    })
    expect(maskRegisteredSecrets(SECOND)).toBe(SECOND)
    expect(provider).toHaveBeenCalledTimes(2)
  })

  it("keeps existing resolve-only dependency injection valid without requiring deferred support", async () => {
    const resolve = vi.fn(() => ({
      async apply() {
        await Promise.resolve()
        return { status: "ok" as const }
      },
      async check() {
        await Promise.resolve()
        return "ok" as const
      },
      name: "injected secret resolver",
    }))
    const injected: SecretResolver = { resolve }
    const module = injected.resolve({ password: REFERENCE })
    // eslint-disable-next-line prefer-spread -- Module.apply is a lifecycle method.
    expect(await module.apply(null, {})).toStrictEqual({ status: "ok" })
    expect(resolve).toHaveBeenCalledExactlyOnceWith({ password: REFERENCE })
  })
})
