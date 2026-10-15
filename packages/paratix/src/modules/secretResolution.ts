import type { EnvironmentMetaEntry, Module, ModuleResult } from "../types.js"

import { environmentMeta } from "../meta.js"
import { failed } from "../moduleFailure.js"
import { resolveCachedSecret } from "../secretPrewarm.js"
import { registerRunScopedSecret, withRunScopedSecrets } from "../secretSink.js"
import { buildSecretFailure, type SecretFailurePolicy } from "./secretFailureMasking.js"

/** A prepared provider request; only the shared lifecycle owns cache and scopes. */
export type SecretRequest = {
  early?: { cacheKey: string | symbol; load: () => Promise<string> }
  name: string
  prepare?: (value: string) => string
  reference: string
  resolution?: "per-access"
  resolve?: (value?: string) => Promise<string> | string
  validate?: (value: string) => void
}

type SecretModuleOptions = {
  failure: SecretFailurePolicy
  /** Preserve the empty legacy op.resolve module's hook. */
  forcePrewarm?: boolean
  name: string
  requests: SecretRequest[]
}

type ObservedValue = { raw: string; value: string }

function observe(value: string, values: string[]): void {
  if (value.length === 0) return
  values.push(value)
  // Registration happens at first observation and again on cache hits. The
  // surrounding re-entrant scope releases every registration on all paths.
  registerRunScopedSecret(value)
}

async function loadEarly(
  request: SecretRequest,
  values: string[]
): Promise<ObservedValue | undefined> {
  if (request.early == null) return undefined
  const { cacheKey, load } = request.early
  const raw = await resolveCachedSecret(cacheKey, async () => {
    const loaded = await load()
    observe(loaded, values)
    return loaded
  })
  observe(raw, values)
  // The cache holds the provider's base normalization. Seed trimming and
  // validation happen afterwards so mixed ordinary/seed consumers agree.
  const value = request.prepare?.(raw) ?? raw
  if (value !== raw) observe(value, values)
  request.validate?.(value)
  return { raw, value }
}

function failureCandidates(
  options: SecretModuleOptions,
  values: string[],
  error: unknown
): string[] {
  return [
    ...options.requests.map((request) => request.reference),
    ...values,
    ...(options.failure.collectCandidates?.(error) ?? []),
  ]
}

function createLazyResolver(
  request: SecretRequest,
  loaded: ObservedValue | undefined,
  context: { options: SecretModuleOptions; values: string[] }
): () => Promise<string> {
  const { options } = context
  // A new closure belongs to each apply, never to the facade or run cache.
  return async () =>
    withRunScopedSecrets(async () => {
      // Retain apply's known ordinary values for diagnostics, never a completed
      // code. Each access keeps its own newly observed values only locally.
      const values = [...context.values]
      try {
        if (loaded != null) {
          observe(loaded.raw, values)
          if (loaded.value !== loaded.raw) observe(loaded.value, values)
        }
        const value = await request.resolve?.(loaded?.value)
        if (value === undefined) throw new Error("Secret request has no resolver")
        observe(value, values)
        return value
      } catch (error) {
        // Lazy calls can outlive apply's own scope, so sanitize before this
        // independent bracket releases its registrations (including short codes).
        throw buildSecretFailure(error, failureCandidates(options, values, error), options.failure)
      }
    })
}

async function prewarm(options: SecretModuleOptions): Promise<void> {
  await withRunScopedSecrets(async () => {
    const values: string[] = []
    try {
      for (const request of options.requests) {
        // eslint-disable-next-line no-await-in-loop -- interactive providers must remain sequential
        await loadEarly(request, values)
      }
    } catch (error) {
      throw buildSecretFailure(error, failureCandidates(options, values, error), options.failure)
    }
  })
}

async function apply(options: SecretModuleOptions): Promise<ModuleResult> {
  return withRunScopedSecrets(async () => {
    const values: string[] = []
    try {
      const entries: EnvironmentMetaEntry[] = []
      for (const request of options.requests) {
        // eslint-disable-next-line no-await-in-loop -- preserve provider interaction order
        const loaded = await loadEarly(request, values)
        const value =
          request.resolve == null
            ? (loaded?.value ?? "")
            : createLazyResolver(request, loaded, { options, values })
        const entry = environmentMeta(request.name, value)
        if (request.resolution != null) entry.resolution = request.resolution
        entries.push(entry)
      }
      return { meta: entries, status: "ok" }
    } catch (error) {
      const sanitized = buildSecretFailure(
        error,
        failureCandidates(options, values, error),
        options.failure
      )
      return failed(sanitized.message)
    }
  })
}

/**
 * Build the single local-module lifecycle shared by all secret entry points.
 * @param options - Prepared requests, display metadata, and failure policy.
 * @returns A local secret-producing module.
 */
export function createSecretModule(options: SecretModuleOptions): Module {
  return {
    _dryRunMetaProducer: true,
    ...(options.forcePrewarm === true || options.requests.some((request) => request.early != null)
      ? { _prewarmSecrets: async () => prewarm(options) }
      : {}),
    apply: async () => apply(options),
    // eslint-disable-next-line @typescript-eslint/require-await
    async check(): Promise<"needs-apply" | "ok"> {
      return "needs-apply"
    },
    local: true,
    name: options.name,
  }
}
