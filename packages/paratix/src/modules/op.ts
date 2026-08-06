import { type ChildProcess, spawn } from "node:child_process"

import type { Environment, Module, ModuleResult } from "../types.js"

import { environmentToMetaEntries } from "../meta.js"
import { failed } from "../moduleFailure.js"
import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { resolveCachedSecret } from "../secretPrewarm.js"
import {
  hasActiveRunScopedSecretScope,
  registerRunScopedSecret,
  withRunScopedSecrets,
} from "../secretSink.js"
import { generateTotpCode } from "../totp.js"
import { buildOpFailureDetail, buildPrewarmFailure, maskOpText } from "./opFailureMasking.js"
import {
  type BoundedOutputCapture,
  createBoundedOutputCapture,
  OP_OUTPUT_CAPTURE_LIMIT_BYTES,
} from "./opOutputCapture.js"
import { collectOpFailureOutputs, OpSpawnError } from "./opSpawnError.js"
import { attachSpawnLifecycle, killChildEscalating } from "./opSpawnLifecycle.js"

/**
 * Default upper bound for a single `op` CLI invocation. The 1Password helper
 * can deadlock on a biometric prompt or a stale agent socket; we kill the
 * child after this many milliseconds rather than hanging the runner. R-0000220.
 */
const DEFAULT_OP_TIMEOUT_MILLISECONDS = 60_000

const OP_INSTALL_HINT =
  "Install it from https://1password.com/downloads/command-line/ and ensure it is on PATH."

const OP_SIGNIN_HINT = "Run 'op signin' first to authenticate the current shell session."

const OP_AUTH_PATTERNS = [
  /not\s+signed\s+in/iv,
  /not\s+authorized/iv,
  /authentication\s+required/iv,
  /session\s+expired/iv,
  /session\s+invalid/iv,
]

function isAuthFailure(stderr: string): boolean {
  return OP_AUTH_PATTERNS.some((pattern) => pattern.test(stderr))
}

function describeSpawnError(command: string, error: unknown): Error {
  if (error instanceof Error && (error as NodeJS.ErrnoException).code === "ENOENT") {
    return new Error(`${command} CLI is not installed or not on PATH. ${OP_INSTALL_HINT}`)
  }
  return error instanceof Error ? error : new Error(String(error))
}

/** Options for {@link spawnWithInput}; extracted to keep the parameter count <= 3. */
type SpawnWithInputOptions = {
  /**
   * Optional override for the per-call timeout. Defaults to
   * {@link DEFAULT_OP_TIMEOUT_MILLISECONDS}; pass a non-positive value to
   * disable the timer.
   */
  timeoutMs?: number
}

/**
 * Spawn a command, write `input` to its stdin, and collect stdout.
 *
 * The child is bound to the runner abort signal returned by
 * {@link getRunnerAbortSignal}: when the runner observes SIGINT/SIGTERM the
 * spawned process is killed (SIGTERM → SIGKILL) instead of hanging on a
 * blocked `op` CLI (e.g. waiting on a biometric prompt). A configurable
 * timeout (default {@link DEFAULT_OP_TIMEOUT_MILLISECONDS}) bounds individual
 * invocations to keep the runner responsive even when no abort arrives. R-0000220.
 *
 * @param command - The executable to run.
 * @param commandArguments - Arguments for the command.
 * @param spawnOptions - Optional behaviour overrides (input, timeout).
 * @returns The stdout output as a string.
 */
/** Mutable IO state captured while a child is running. */
type SpawnIoState = { stderr: BoundedOutputCapture; stdout: BoundedOutputCapture }

/** Initial no-op detach used until {@link attachSpawnLifecycle} replaces it. */
const NOOP_DETACH = (): void => {
  /* placeholder until attachSpawnLifecycle wires the real detach */
}

/**
 * Wire stdout, stderr, error and close handlers onto a spawned child so the
 * helper resolves on success and rejects with a contextual error on failure.
 *
 * @param parameters - Wiring inputs.
 * @param parameters.child - The spawned child process.
 * @param parameters.command - The executable name used in error messages.
 * @param parameters.io - Mutable IO accumulator that captures stdout / stderr.
 * @param parameters.rejectOnce - Reject closure invoked on error / non-zero exit.
 * @param parameters.resolveOnce - Resolve closure invoked when the child exits 0.
 */
function attachSpawnIoHandlers(parameters: {
  child: ChildProcess
  command: string
  io: SpawnIoState
  rejectOnce: (error: Error) => void
  resolveOnce: (output: string) => void
}): void {
  const { child, command, io, rejectOnce, resolveOnce } = parameters
  child.stdout?.on("data", (chunk: Buffer) => {
    io.stdout.append(chunk)
  })
  child.stderr?.on("data", (chunk: Buffer) => {
    io.stderr.append(chunk)
  })
  child.on("error", (error) => {
    rejectOnce(describeSpawnError(command, error))
  })
  child.on("close", (code) => {
    if (code === 0) {
      if (io.stdout.exceededLimit()) {
        rejectOnce(
          new Error(
            `${command} stdout exceeded ${String(
              OP_OUTPUT_CAPTURE_LIMIT_BYTES
            )} bytes; refusing to return a truncated secret`
          )
        )
        return
      }
      resolveOnce(io.stdout.text())
      return
    }
    const stderr = io.stderr.text()
    const stdoutText = io.stdout.text()
    const hint = isAuthFailure(stderr) ? ` ${OP_SIGNIN_HINT}` : ""
    // R-0000589: attach the captured streams to the rejection so the
    // resolve failure path can fold them into the maskSecrets call.
    rejectOnce(
      new OpSpawnError(`${command} exited with code ${String(code)}: ${stderr}${hint}`, {
        stderr,
        stdout: stdoutText,
      })
    )
  })
  child.stdin?.once("error", (error) => {
    // R-0000711: mirror the synchronous failure paths in `feedStdinOrFail`
    // (R-0000573/R-0000641/R-0000678) — an async stdin `error` event (e.g. a
    // late EPIPE after the pipe was wired up) settles the promise via
    // `rejectOnce` but otherwise leaves the underlying ChildProcess running.
    // Send SIGTERM with SIGKILL escalation first so no orphaned op CLI
    // process outlives the rejected promise.
    killChildEscalating(child)
    rejectOnce(describeSpawnError(command, error))
  })
}

function feedStdinOrFail(parameters: {
  child: ChildProcess
  command: string
  input: string
  rejectOnce: (error: Error) => void
}): void {
  const { child, command, input, rejectOnce } = parameters
  // R-0000573: when the child exits before its stdin pipe is wired up
  // (e.g. spawn raced a SIGKILL or the binary refused exec) `child.stdin`
  // is null. The previous `child.stdin?.end(input)` would then silently
  // no-op and the promise would hang because neither `error` nor `close`
  // had fired yet. Surface the failure explicitly instead.
  if (child.stdin == null) {
    // R-0000641: without an active stdin pipe `rejectOnce` settles the
    // promise but leaves the underlying ChildProcess running. Trigger
    // SIGTERM with SIGKILL escalation so no orphaned 1Password CLI process
    // can hang past this function.
    killChildEscalating(child)
    rejectOnce(new Error(`${command} spawn failed: stdin unavailable`))
    return
  }
  try {
    child.stdin.end(input)
  } catch (error) {
    // R-0000678: mirror the null-stdin path above — if `stdin.end()` throws
    // synchronously (e.g. EPIPE) `rejectOnce` settles the promise but
    // leaves the underlying ChildProcess running. Send SIGTERM with
    // SIGKILL escalation first so no orphaned op CLI process outlives
    // the rejected promise.
    killChildEscalating(child)
    rejectOnce(describeSpawnError(command, error))
  }
}

async function spawnWithInput(
  command: string,
  commandArguments: string[],
  spawnOptions: { input: string } & SpawnWithInputOptions
): Promise<string> {
  const { input } = spawnOptions
  const timeoutMs = spawnOptions.timeoutMs ?? DEFAULT_OP_TIMEOUT_MILLISECONDS
  if (getRunnerAbortSignal()?.aborted === true) {
    throw new Error(`${command} aborted before spawn — runner shutdown in progress`)
  }
  return new Promise<string>((resolve, reject) => {
    const child: ChildProcess = spawn(command, commandArguments, {
      stdio: ["pipe", "pipe", "pipe"],
    })
    let settled = false
    const io: SpawnIoState = {
      stderr: createBoundedOutputCapture("stderr"),
      stdout: createBoundedOutputCapture("stdout"),
    }
    let detachLifecycle: () => void = NOOP_DETACH
    const rejectOnce = (error: Error): void => {
      if (settled) return
      settled = true
      detachLifecycle()
      reject(error)
    }
    const resolveOnce = (output: string): void => {
      if (settled) return
      settled = true
      detachLifecycle()
      resolve(output)
    }
    attachSpawnIoHandlers({ child, command, io, rejectOnce, resolveOnce })
    detachLifecycle = attachSpawnLifecycle({ child, command, rejectOnce, timeoutMs })
    feedStdinOrFail({ child, command, input, rejectOnce })
  })
}

const OTP_SUFFIX_PATTERN = /\/(?:one-time-password|otp)$/iv

const REFERENCE_PREFIX = "op://"

/**
 * Validate that all reference values start with `op://`.
 *
 * @param references - Map of logical names to 1Password references.
 * @throws {Error} If any reference does not start with `op://`.
 */
function validateReferences(references: Record<string, string>): void {
  for (const [name, reference] of Object.entries(references)) {
    if (!reference.startsWith(REFERENCE_PREFIX)) {
      throw new Error(
        `Invalid 1Password reference for "${name}": must start with "${REFERENCE_PREFIX}"`
      )
    }
  }
}

/**
 * Split references into regular secrets and OTP references.
 *
 * @param references - Map of logical names to 1Password references.
 * @returns A tuple of [regularEntries, otpEntries].
 */
function splitReferences(
  references: Record<string, string>
): [Record<string, string>, Record<string, string>] {
  const regularEntries: Record<string, string> = {}
  const otpEntries: Record<string, string> = {}

  for (const [name, reference] of Object.entries(references)) {
    if (OTP_SUFFIX_PATTERN.test(reference)) {
      otpEntries[name] = reference
    } else {
      regularEntries[name] = reference
    }
  }

  return [regularEntries, otpEntries]
}

function stripTrailingCliNewline(value: string): string {
  return value.replace(/\r?\n$/v, "")
}

/**
 * Read a single 1Password reference, routed through the run-scoped prewarm
 * cache so each reference costs exactly one `op read` per run — no matter how
 * many `op.resolve` modules name it, and no matter whether the prewarm phase or
 * the module's own `apply()` asks first.
 *
 * `normalize` post-processes the raw CLI stdout, and the **normalized** value —
 * not the raw stdout — is what gets cached and registered. That distinction is
 * load-bearing: the secret sink masks exactly the string it was handed, so a
 * raw value registered with its trailing newline would leave the trimmed value
 * that actually reaches the output unmasked.
 *
 * R-0000165 / R-0000850: the loader registers the value with the secret sink at
 * the moment it is first observed, so the window between the up-front phase and
 * the module's own execution is covered too. An empty value is cached and passed
 * on like any other but never registered.
 *
 * Every *observation* registers as well, not just the load. The loader runs once
 * per reference and run, so its registration is only as long-lived as whichever
 * `withRunScopedSecrets` bracket happened to be active back then. A cache hit
 * that re-registers inside the caller's own bracket makes each consumer
 * self-supporting again — exactly the property `apply()` had before the cache
 * existed — instead of depending on an ordering of scopes that nothing enforces.
 * The registration is reference-counted, so the extra registration is released
 * exactly as often as it was taken; the scope guard follows the precedent of the
 * TOTP closure below and keeps a registration without a scope (which nothing
 * would ever release) from happening.
 *
 * @param reference - The `op://` reference to read.
 * @param normalize - Post-processing applied to the raw CLI stdout.
 * @returns The normalized value, served from cache once the reference was read.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function readReference(
  reference: string,
  normalize: (stdout: string) => string
): Promise<string> {
  const value = await resolveCachedSecret(reference, async () => {
    const stdout = await spawnWithInput("op", ["read", "--", reference], { input: "" })
    const loaded = normalize(stdout)
    if (loaded.length > 0) registerRunScopedSecret(loaded)
    return loaded
  })
  if (value.length > 0 && hasActiveRunScopedSecretScope()) registerRunScopedSecret(value)
  return value
}

/**
 * Read a regular (non-OTP) reference: the secret value with the trailing
 * newline the CLI appends removed.
 *
 * @param reference - The `op://` reference to read.
 * @returns The resolved secret value.
 */
async function readSecretValue(reference: string): Promise<string> {
  return readReference(reference, stripTrailingCliNewline)
}

/**
 * Read an OTP reference: the `otpauth://` seed URI, trimmed. Only the seed is
 * read here — the TOTP code itself stays lazy, see {@link resolveOtpReferences}.
 *
 * `splitReferences` assigns every reference to exactly one of the two branches
 * by its suffix, so a single reference can never be cached under both
 * normalizations.
 *
 * @param reference - The `op://` reference to read.
 * @returns The resolved `otpauth://` URI.
 */
async function readOtpauthUri(reference: string): Promise<string> {
  return readReference(reference, (stdout) => stripTrailingCliNewline(stdout).trim())
}

/**
 * Resolve regular (non-OTP) 1Password references via `op read`.
 *
 * @param entries - Map of logical names to 1Password references.
 * @param leakedValues - Mutable sink that captures every resolved value. The
 *   caller uses it to feed `maskSecrets` on failure paths so any value that
 *   leaks into stderr or a stack trace is still redacted.
 * @returns Resolved key-value pairs.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveRegularReferences(
  entries: Record<string, string>,
  leakedValues: string[]
): Promise<Record<string, string>> {
  const result: Record<string, string> = {}

  for (const [name, reference] of Object.entries(entries)) {
    // eslint-disable-next-line no-await-in-loop
    const value = await readSecretValue(reference)
    if (value.length > 0) {
      leakedValues.push(value)
    }
    result[name] = value
  }

  return result
}

/**
 * Resolve OTP 1Password references into lazy TOTP code generators.
 *
 * Each reference is resolved exactly once via `op read` to obtain the
 * `otpauth://totp/...` URI, then wrapped in a lazy function so the
 * time-based TOTP **code** is recomputed on every access.
 *
 * Note: only the TOTP code rotates per call — the underlying seed (the
 * `secret=` parameter of the otpauth URI) is captured by the returned
 * closure and is NOT refetched. A seed rotation in 1Password during a
 * running playbook is therefore not observable until the next `runPlaybook`
 * invocation re-resolves the reference. This is a deliberate design
 * decision: resolving the seed on every access would invoke `op read`
 * (and potentially a 1Password authentication pop-up / biometric prompt)
 * for every module evaluation, which is unacceptable for both performance
 * and interactive UX. Use a fresh playbook run when a seed has been
 * rotated.
 *
 * @param entries - Map of logical names to OTP 1Password references.
 * @param leakedValues - Mutable sink that captures every resolved otpauth URI.
 *   The caller uses it to feed `maskSecrets` on failure paths so the
 *   `secret=` parameter in the URI is redacted from any user-visible output.
 * @returns Map of logical names to lazy functions that compute a fresh TOTP
 *   code (from the captured seed) on every call.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveOtpReferences(
  entries: Record<string, string>,
  leakedValues: string[]
): Promise<Environment> {
  const result: Environment = {}

  for (const [name, reference] of Object.entries(entries)) {
    // R-0000165: the otpauth URI is registered in the secret sink the moment it
    // is first observed — inside `readReference` — so an exception thrown later
    // (e.g. from a follow-up op invocation or from generateTotpCode) cannot
    // leak the URI's `secret=` parameter through stack traces or shared error
    // renderers.
    //
    // R-0000576: that registration still happens BEFORE the closure below is
    // defined, because the awaited read completes first. A third-party catch
    // site that stringifies the thrown error therefore never sees the raw URI
    // before the sink masks it.
    // eslint-disable-next-line no-await-in-loop
    const otpauthUri = await readOtpauthUri(reference)
    if (otpauthUri.length > 0) {
      leakedValues.push(otpauthUri)
    }
    result[name] = () => {
      // R-0000576: the captured `otpauthUri` is closed over and would show
      // up in V8 stack traces if `generateTotpCode` throws synchronously.
      // Rethrow a sanitized Error whose message contains only the logical
      // reference name; the original error is kept in `cause` so callers
      // who carefully render `cause` keep diagnostic detail, while the
      // top-level message stays free of the secret.
      try {
        const code = generateTotpCode(otpauthUri)
        if (hasActiveRunScopedSecretScope()) {
          registerRunScopedSecret(code)
        }
        return code
      } catch (error) {
        throw new Error(`Failed to generate TOTP code for ${JSON.stringify(name)}`, {
          cause: error,
        })
      }
    }
  }

  return result
}

/**
 * Resolve every reference of one `op.resolve` module into the run-scoped cache,
 * before the run connects.
 *
 * Resolution is sequential (as it is in `apply()`): parallel `op read` calls
 * would stack several biometric prompts on top of each other. The resolved
 * values are only warmed here — the lazy TOTP closure belongs to the module and
 * is built in `apply()`, not in the cache.
 *
 * @param references - Map of logical names to 1Password references.
 * @throws {Error} A fully redacted error when a reference cannot be resolved.
 */
async function prewarmReferences(references: Record<string, string>): Promise<void> {
  // Mirrors the `leakedValues` list of `apply()`: every value observed here
  // feeds the masking of a failure raised later in this phase. The list that
  // `apply()` builds locally is not reachable from here.
  const resolvedValues: string[] = []
  try {
    const [regularEntries, otpEntries] = splitReferences(references)
    for (const reference of Object.values(regularEntries)) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design, see the doc comment above
      const value = await readSecretValue(reference)
      if (value.length > 0) resolvedValues.push(value)
    }
    for (const reference of Object.values(otpEntries)) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design, see the doc comment above
      const otpauthUri = await readOtpauthUri(reference)
      if (otpauthUri.length > 0) resolvedValues.push(otpauthUri)
    }
  } catch (error) {
    throw buildPrewarmFailure(error, [
      ...Object.values(references),
      ...resolvedValues,
      // R-0000589: fold the per-line captured stdout/stderr of the failing op
      // invocation into the masking candidates, exactly as the apply() path does.
      ...collectOpFailureOutputs(error),
    ])
  }
}

/**
 * Modules for resolving secrets from 1Password on the local controller.
 */
export const op = {
  /**
   * Resolve 1Password secret references into environment values.
   *
   * Regular references are resolved via `op read`.
   * References ending in `/one-time-password` or `/otp` are resolved individually
   * via `op read` and returned as lazy functions that compute a fresh TOTP code
   * on each call.
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

    return {
      _dryRunMetaProducer: true,
      async _prewarmSecrets(): Promise<void> {
        // The hook opens its own run-scoped secret bracket, just like `apply()`
        // does. Inside the runner the helper is re-entrant and this costs
        // nothing, but it makes the hook self-supporting: on a direct call
        // without a surrounding run scope, `registerRunScopedSecret` increments
        // the process-wide count unconditionally and only *then* returns when
        // there is no store (`secretSink.ts`), and no regular path ever releases
        // it again (R-0000518). Without this bracket a direct call would leak
        // its registrations process-wide.
        await withRunScopedSecrets(async () => {
          await prewarmReferences(references)
        })
      },
      async apply(): Promise<ModuleResult> {
        return withRunScopedSecrets(async () => {
          // Track every secret we observe locally (resolved values + otpauth
          // URIs) so the failure path can mask them from stderr and stack
          // traces, not just the op:// reference strings the caller supplied.
          const leakedValues: string[] = []
          try {
            const [regularEntries, otpEntries] = splitReferences(references)
            // R-0000041 / R-0000850: `resolveRegularReferences` and
            // `resolveOtpReferences` read through `readReference`, which
            // registers every resolved value with the process-scoped secret
            // sink as soon as it observes it — in this run that may already
            // have happened during the prewarm phase. We deliberately do not
            // re-register here — keeping that single loader as the source of
            // truth for secret registration avoids the risk of the sites
            // drifting apart (e.g. when a future helper learns to register a
            // derived value but the post-loop block is overlooked).
            const resolvedRegular = await resolveRegularReferences(regularEntries, leakedValues)
            const resolvedOtp = await resolveOtpReferences(otpEntries, leakedValues)

            return {
              meta: environmentToMetaEntries({ ...resolvedRegular, ...resolvedOtp }),
              status: "ok",
            }
          } catch (error) {
            const rawDetail = buildOpFailureDetail(error)
            // R-0000589: also feed the per-line captured stdout/stderr of the
            // failing op invocation into the secret list. A partial stdout
            // buffer (e.g. half a secret value) that ended up embedded in the
            // error message is then redacted as defense-in-depth.
            const secrets = [
              ...Object.values(references),
              ...leakedValues,
              ...collectOpFailureOutputs(error),
            ]
            const detail = maskOpText(rawDetail, secrets)
            // R-0000850: every value that ended up in `leakedValues` was already
            // registered with the secret sink by the helpers above (see
            // `resolveRegularReferences` / `resolveOtpReferences`). We rely on
            // that single registration site so the resolve flow has one — and
            // only one — canonical place that owns secret registration.
            return failed(`Failed to resolve 1Password references: ${detail}`)
          }
        })
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return "needs-apply"
      },
      local: true,
      name: `op.resolve: ${Object.keys(references).join(", ")}`,
    }
  },
}
