import type { Module } from "../types.js"

import { ENVIRONMENT_FORBIDDEN_KEYS } from "../environment.js"
import {
  createManualRequestFactory,
  type ManualSecretProviderOptions,
} from "./manualSecretProvider.js"
import { opFailurePolicy } from "./opFailureMasking.js"
import { orderOpRequests, prepareOpRequest } from "./opReferenceResolution.js"
import { createSecretModule, type SecretRequest } from "./secretResolution.js"

export type { ManualSecretProviderOptions } from "./manualSecretProvider.js"

/** Explicitly request a fresh code whenever the environment value is accessed. */
export type SecretTotpInput = Readonly<{ kind: "totp"; reference: string }>
export type SecretInput = SecretTotpInput | string
export type SecretProvider = "1password" | "manual"

/** Provider-independent interface suitable for recipe dependency injection. */
export type SecretResolver = {
  resolve: (bindings: Readonly<Record<string, SecretInput>>) => Module
}

type Binding = { markedTotp: boolean; name: string; reference: string }

function isMap(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function validateName(name: string): void {
  if (
    name.length === 0 ||
    ENVIRONMENT_FORBIDDEN_KEYS.has(name) ||
    !name.split(".").every((segment) => /^[A-Za-z_]\w*$/v.test(segment))
  ) {
    throw new TypeError("Invalid secret environment name")
  }
}

function copyBindings(bindings: unknown): Binding[] {
  if (!isMap(bindings)) throw new TypeError("Secret bindings must be a map")
  const entries = Object.entries(bindings)
  if (entries.length === 0) throw new TypeError("Secret bindings must not be empty")
  return entries.map(([name, input]) => {
    validateName(name)
    if (typeof input === "string") return { markedTotp: false, name, reference: input }
    if (
      !isMap(input) ||
      input.kind !== "totp" ||
      typeof input.reference !== "string" ||
      Object.keys(input).some((key) => key !== "kind" && key !== "reference")
    ) {
      throw new TypeError("Secret input must be a string or TOTP descriptor")
    }
    return { markedTotp: true, name, reference: input.reference }
  })
}

function copyLabels(options: unknown): ReadonlyMap<string, string> {
  const labels = new Map<string, string>()
  if (options === undefined) return labels
  if (!isMap(options) || Object.keys(options).some((key) => key !== "labels")) {
    throw new TypeError("Invalid manual secret provider options")
  }
  if (options.labels === undefined) return labels
  if (!isMap(options.labels)) throw new TypeError("Manual secret labels must be a map")
  for (const [name, label] of Object.entries(options.labels)) {
    if (typeof label !== "string") throw new TypeError("Manual secret labels must be strings")
    labels.set(name, label)
  }
  return labels
}

function provider(name: "manual", options?: ManualSecretProviderOptions): SecretResolver
function provider(name: SecretProvider): SecretResolver
function provider(name: unknown, options?: ManualSecretProviderOptions): SecretResolver {
  if (name !== "manual" && name !== "1password") throw new TypeError("Unknown secret provider")
  if (name === "1password" && options !== undefined) {
    throw new TypeError("1Password secret provider does not accept options")
  }
  const prepareManual = createManualRequestFactory(copyLabels(options))
  return Object.freeze({
    resolve(bindings: Readonly<Record<string, SecretInput>>): Module {
      const copied = copyBindings(bindings)
      const requests: SecretRequest[] = copied.map(
        ({ markedTotp, name: bindingName, reference }) =>
          name === "manual"
            ? prepareManual(bindingName, reference, markedTotp)
            : prepareOpRequest(bindingName, reference, markedTotp)
      )
      return createSecretModule({
        failure:
          name === "1password" ? opFailurePolicy : { prefix: "Failed to resolve manual secrets" },
        name: `secret.resolve: ${copied.map((binding) => binding.name).join(", ")}`,
        requests: name === "1password" ? orderOpRequests(requests) : requests,
      })
    },
  })
}

/** Built-in facade for local manual and 1Password secret resolution. */
export const secret = Object.freeze({
  provider,
  totp(reference: string): SecretTotpInput {
    if (typeof reference !== "string") throw new TypeError("TOTP reference must be a string")
    return Object.freeze({ kind: "totp", reference })
  },
})
