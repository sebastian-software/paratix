import type { Module } from "../types.js"

import { opFailurePolicy } from "./opFailureMasking.js"
import { orderOpRequests, prepareOpRequest, validateReferences } from "./opReferenceResolution.js"
import { createSecretModule } from "./secretResolution.js"

/**
 * Modules for resolving secrets from 1Password on the local controller.
 */
export const op = {
  /**
   * Resolve 1Password secret references into environment values.
   *
   * Regular references are resolved via `op read`.
   * References ending in `/one-time-password` or `/otp` are resolved individually
   * via `op read` and returned as lazy functions. Calling a returned meta
   * resolver directly computes a fresh TOTP code; merging it into an environment
   * retains the legacy memoization of its first successful result. The new
   * per-access policy requires the explicit `secret.totp` marker in the secret
   * facade and is not enabled by this compatibility entry point.
   *
   * This module runs locally (`local: true`) and never touches the remote host.
   * `check` always returns `"needs-apply"` so the runner executes `apply`
   * unconditionally and propagates the resolved meta values.
   * If any CLI call fails the module returns `{ status: "failed", error }`.
   *
   * Inside a `runPlaybook` run every reference is already read at the very
   * start of the run, before the SSH connect, so the 1Password interaction
   * (biometric unlock, `op signin`) happens immediately and only once. `apply`
   * then runs at its own position in `run`, serves its values from the
   * run-scoped cache without another CLI call, and emits the same meta as
   * before. A failure during that up-front phase aborts the run before any
   * connection is opened, instead of surfacing as a failed module later on.
   * Outside a run — a direct `op.resolve(...).apply(...)` call — there is no
   * cache and the references are resolved on the spot, exactly as before.
   *
   * @param references - A map of logical names to 1Password secret references
   *   (e.g. `op://vault/item/field`). References ending in `/one-time-password`
   *   or `/otp` are treated as TOTP sources.
   * @returns A Module that resolves the references and emits them as meta values.
   *
   * @example
   * ```ts
   * op.resolve({
   *   DB_PASSWORD: "op://prod/database/password",
   *   API_TOKEN:   "op://prod/api/credential",
   *   MFA_CODE:    "op://prod/authenticator/one-time-password",
   * })
   * ```
   */
  resolve(references: Record<string, string>): Module {
    validateReferences(references)
    const requests = Object.entries(references).map(([name, reference]) =>
      prepareOpRequest(name, reference)
    )
    return createSecretModule({
      failure: opFailurePolicy,
      forcePrewarm: true,
      name: `op.resolve: ${Object.keys(references).join(", ")}`,
      requests: orderOpRequests(requests),
    })
  },
}
