import { type ChildProcess, spawn } from "node:child_process"

import type { Environment, Module, ModuleResult } from "../types.js"

import { environmentToMetaEntries } from "../meta.js"
import { failed } from "../moduleFailure.js"
import { registerSecret } from "../secretSink.js"
import { maskSecrets } from "../sshHelpers.js"
import { generateTotpCode } from "../totp.js"

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

/**
 * Build a single-string failure detail from a caught error so a later
 * `maskSecrets` pass can redact any resolved values that happened to leak
 * into the error message (typically via captured stderr from the op CLI).
 *
 * @param error - The thrown error caught from the op CLI invocation.
 * @returns The detail string (message or `String(value)` fallback) to mask and surface.
 */
function buildOpFailureDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function describeSpawnError(command: string, error: unknown): Error {
  if (error instanceof Error && (error as NodeJS.ErrnoException).code === "ENOENT") {
    return new Error(`${command} CLI is not installed or not on PATH. ${OP_INSTALL_HINT}`)
  }
  return error instanceof Error ? error : new Error(String(error))
}

/**
 * Spawn a command, write `input` to its stdin, and collect stdout.
 *
 * @param command - The executable to run.
 * @param commandArguments - Arguments for the command.
 * @param input - Data to write to stdin before closing it.
 * @returns The stdout output as a string.
 */
async function spawnWithInput(
  command: string,
  commandArguments: string[],
  input: string
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const child: ChildProcess = spawn(command, commandArguments, {
      stdio: ["pipe", "pipe", "pipe"],
    })
    let settled = false
    let stdout = ""
    let stderr = ""

    const rejectOnce = (error: Error): void => {
      if (settled) return
      settled = true
      reject(error)
    }

    const resolveOnce = (output: string): void => {
      if (settled) return
      settled = true
      resolve(output)
    }

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString()
    })
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString()
    })
    child.on("error", (error) => {
      rejectOnce(describeSpawnError(command, error))
    })
    child.on("close", (code) => {
      if (code === 0) {
        resolveOnce(stdout)
        return
      }
      const hint = isAuthFailure(stderr) ? ` ${OP_SIGNIN_HINT}` : ""
      rejectOnce(new Error(`${command} exited with code ${String(code)}: ${stderr}${hint}`))
    })
    child.stdin?.once("error", (error) => {
      rejectOnce(describeSpawnError(command, error))
    })

    try {
      child.stdin?.end(input)
    } catch (error) {
      rejectOnce(describeSpawnError(command, error))
    }
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
    const stdout = await spawnWithInput("op", ["read", reference], "")
    const value = stripTrailingCliNewline(stdout)
    if (value.length > 0) {
      leakedValues.push(value)
      // R-0000165: register the resolved secret in the process-scoped sink
      // immediately. Without this, a later failure (e.g. an OTP resolve
      // crash, op CLI timeout, unhandled rejection) before the caller's
      // post-loop registration would let the value leak through stack
      // traces and shared logger trap output in plaintext.
      registerSecret(value)
    }
    result[name] = value
  }

  return result
}

/**
 * Resolve OTP 1Password references into lazy TOTP code generators.
 *
 * Each reference is resolved immediately via `op read` to obtain the
 * `otpauth://totp/...` URI, then wrapped in a lazy function so the TOTP
 * code is computed fresh on every access.
 *
 * @param entries - Map of logical names to OTP 1Password references.
 * @param leakedValues - Mutable sink that captures every resolved otpauth URI.
 *   The caller uses it to feed `maskSecrets` on failure paths so the
 *   `secret=` parameter in the URI is redacted from any user-visible output.
 * @returns Map of logical names to lazy functions that compute fresh TOTP codes.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveOtpReferences(
  entries: Record<string, string>,
  leakedValues: string[]
): Promise<Environment> {
  const result: Environment = {}

  for (const [name, reference] of Object.entries(entries)) {
    // eslint-disable-next-line no-await-in-loop
    const stdout = await spawnWithInput("op", ["read", reference], "")

    const otpauthUri = stripTrailingCliNewline(stdout).trim()
    if (otpauthUri.length > 0) {
      leakedValues.push(otpauthUri)
      // R-0000165: register the otpauth URI in the secret sink as soon as
      // it is resolved so an exception thrown later (e.g. from a follow-up
      // op invocation or from generateTotpCode) cannot leak the URI's
      // `secret=` parameter through stack traces or shared error renderers.
      registerSecret(otpauthUri)
    }
    result[name] = () => {
      const code = generateTotpCode(otpauthUri)
      registerSecret(code)
      return code
    }
  }

  return result
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
      async apply(): Promise<ModuleResult> {
        // Track every secret we observe locally (resolved values + otpauth
        // URIs) so the failure path can mask them from stderr and stack
        // traces, not just the op:// reference strings the caller supplied.
        const leakedValues: string[] = []
        try {
          const [regularEntries, otpEntries] = splitReferences(references)
          const resolvedRegular = await resolveRegularReferences(regularEntries, leakedValues)
          const resolvedOtp = await resolveOtpReferences(otpEntries, leakedValues)

          // R-0000041: register the resolved values in the process-scoped
          // secret sink so any subsequent generic Error / stack trace that
          // reaches printCommandFailure gets the values redacted, even when
          // the rendering call site is not aware of these secrets.
          for (const value of leakedValues) registerSecret(value)
          for (const resolvedValue of Object.values(resolvedRegular)) {
            if (typeof resolvedValue === "string") registerSecret(resolvedValue)
          }

          return {
            meta: environmentToMetaEntries({ ...resolvedRegular, ...resolvedOtp }),
            status: "ok",
          }
        } catch (error) {
          const rawDetail = buildOpFailureDetail(error)
          const secrets = [...Object.values(references), ...leakedValues]
          const detail = maskSecrets(rawDetail, secrets)
          // Register the leaked values for the duration of the run so the
          // shared stderr renderers redact them if the failure bubbles up
          // through unrelated catch sites.
          for (const value of leakedValues) registerSecret(value)
          return failed(`Failed to resolve 1Password references: ${detail}`)
        }
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
