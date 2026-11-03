import { inspect } from "node:util"

import type { SecretRequest } from "./secretResolution.js"

import { resolveCachedSecret } from "../secretPrewarm.js"
import { registerRunScopedSecret, withRunScopedSecrets } from "../secretSink.js"

const brand: unique symbol = Symbol("SecretHandle")

/** An opaque provider-bound reference; only its originating registry can resolve it. */
export type SecretHandle = { readonly [brand]: true }

type Entry = { key: symbol; request: SecretRequest }
const handles = new WeakMap<object, Entry>()

/**
 * Creates no provider work and stores no decrypted values or promises.
 * @internal
 * @param request - Provider-bound request retained without resolving it.
 * @param key - Run-cache identity shared by this provider binding.
 * @returns A nominal, immutable secret handle.
 */
export function createSecretHandle(request: SecretRequest, key: symbol): SecretHandle {
  const handle = Object.freeze({
    [brand]: true as const,
    [inspect.custom]: () => "SecretHandle [redacted]",
    // eslint-disable-next-line @typescript-eslint/naming-convention -- standard JSON serialization hook
    toJSON(): never {
      throw new TypeError("SecretHandle cannot be serialized")
    },
    toString: () => "SecretHandle [redacted]",
  })
  handles.set(handle, { key, request })
  return handle
}

/**
 * Reject copies, JSON reconstructions and values from foreign registries.
 * @internal
 * @param value - Value whose registry membership must be verified.
 */
export function assertSecretHandle(value: unknown): asserts value is SecretHandle {
  if (typeof value !== "object" || value === null || !handles.has(value)) {
    throw new TypeError("A provider-bound SecretHandle is required")
  }
}

/**
 * Call only after a confirmed signing need; no environment/prewarm registration.
 * @internal
 * @param handle - The original provider-bound handle.
 * @param consume - Signer operation receiving the resolved credential.
 * @returns The consumer result, with provider failures translated at the boundary.
 */
export async function withDeferredSecret<T>(
  handle: SecretHandle,
  consume: (value: string) => Promise<T>
): Promise<T> {
  assertSecretHandle(handle)
  const entry = handles.get(handle)
  if (entry === undefined) throw new TypeError("Invalid SecretHandle")
  return withRunScopedSecrets(async () => {
    try {
      const value = await resolveCachedSecret(entry.key, async () => {
        const loaded = await entry.request.early?.load()
        const result = loaded ?? (await entry.request.resolve?.())
        if (typeof result !== "string") throw new Error("Missing secret resolver")
        registerRunScopedSecret(result)
        return result
      })
      registerRunScopedSecret(value)
      return await consume(value)
    } catch {
      // Provider exceptions can contain references, values, stdout and causes. None escape.
      throw new Error("Deferred signer credential resolution or use failed")
    }
  })
}
