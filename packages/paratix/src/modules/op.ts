import { type ChildProcess, spawn } from "node:child_process"

import type { Environment, Module, ModuleResult } from "../types.js"

import { generateTotpCode } from "../totp.js"

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
    let stdout = ""
    let stderr = ""

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString()
    })
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString()
    })
    child.on("error", reject)
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout)
      } else {
        reject(new Error(`${command} exited with code ${String(code)}: ${stderr}`))
      }
    })

    child.stdin?.end(input)
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

/**
 * Resolve regular (non-OTP) 1Password references in bulk via `op inject`.
 *
 * @param entries - Map of logical names to 1Password references.
 * @returns Resolved key-value pairs.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveRegularReferences(
  entries: Record<string, string>
): Promise<Record<string, string>> {
  if (Object.keys(entries).length === 0) return {}

  const stdout = await spawnWithInput("op", ["inject"], JSON.stringify(entries))

  const parsed: unknown = JSON.parse(stdout)

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("op inject returned unexpected non-object JSON")
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- validated: non-null, non-array object
  const record = parsed as Record<string, unknown>
  if (!Object.values(record).every((v) => typeof v === "string")) {
    throw new Error("op inject returned object with non-string values")
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- all values validated as strings above
  return record as Record<string, string>
}

/**
 * Resolve OTP 1Password references into lazy TOTP code generators.
 *
 * Each reference is resolved immediately via `op read` to obtain the
 * `otpauth://totp/...` URI, then wrapped in a lazy function so the TOTP
 * code is computed fresh on every access.
 *
 * @param entries - Map of logical names to OTP 1Password references.
 * @returns Map of logical names to lazy functions that compute fresh TOTP codes.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveOtpReferences(entries: Record<string, string>): Promise<Environment> {
  const result: Environment = {}

  for (const [name, reference] of Object.entries(entries)) {
    // eslint-disable-next-line no-await-in-loop
    const stdout = await spawnWithInput("op", ["read", reference], "")

    const otpauthUri = stdout.trim()
    result[name] = () => generateTotpCode(otpauthUri)
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
   * Regular references are resolved in bulk via `op inject`.
   * References ending in `/one-time-password` or `/otp` are resolved individually
   * via `op read` and returned as lazy functions that compute a fresh TOTP code
   * on each call.
   *
   * This module runs locally (`local: true`) and never touches the remote host.
   * `check` always returns `"ok"` — secrets are resolved unconditionally in `apply`.
   * If any CLI call fails the module returns `{ status: "failed" }`.
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
      async apply(): Promise<ModuleResult> {
        try {
          const [regularEntries, otpEntries] = splitReferences(references)
          const resolvedRegular = await resolveRegularReferences(regularEntries)
          const resolvedOtp = await resolveOtpReferences(otpEntries)

          return { meta: { ...resolvedRegular, ...resolvedOtp }, status: "ok" }
        } catch (error) {
          console.error(String(error))
          return { status: "failed" }
        }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return "ok"
      },
      local: true,
      name: `op.resolve: ${Object.keys(references).join(", ")}`,
    }
  },
}
