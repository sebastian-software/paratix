import { createHash, timingSafeEqual } from "node:crypto"
import { createReadStream } from "node:fs"

import type { ModuleResult } from "../types.js"

import { failed } from "../moduleFailure.js"

/**
 * R-0000674: hard cap on the regex pattern length accepted by modules that
 * compile user-supplied regular expressions (`file.replace`, `file.line`).
 * Real-world playbook patterns easily fit into a few dozen characters; any
 * pattern far longer than this is almost certainly attacker-influenced input
 * (e.g. an unsanitized template variable) and would let a malicious actor
 * trigger pathological RegExp compilation. Rejecting oversized patterns
 * upfront keeps the failure deterministic and the error message readable.
 */
export const FILE_USER_REGEX_MAX_PATTERN_LENGTH = 1024

/**
 * R-0000674: compile a user-provided pattern once and wrap the `RegExp`
 * constructor in try/catch so a malformed pattern surfaces as a structured
 * `ModuleResult` failure instead of an uncaught `SyntaxError` propagating out
 * of `apply`/`check`. Originally introduced for `file.replace` (R-0000639) and
 * extracted here so `file.line({match})` gains the same length cap and
 * try/catch wrapper.
 *
 * @param errorPrefix - Module-specific prefix included in the failure message
 *   (e.g. `[file.replace: /etc/foo]`).
 * @param pattern - Raw pattern string from the playbook.
 * @param flags - RegExp flags forwarded to the `RegExp` constructor.
 * @returns Either the compiled `RegExp` or a `failed` {@link ModuleResult}.
 */
export function compileUserRegex(
  errorPrefix: string,
  pattern: string,
  flags: string
): ModuleResult | RegExp {
  if (pattern.length > FILE_USER_REGEX_MAX_PATTERN_LENGTH) {
    return failed(
      `${errorPrefix} pattern exceeds maximum length of ${String(FILE_USER_REGEX_MAX_PATTERN_LENGTH)} characters: got ${String(pattern.length)}`
    )
  }
  try {
    // eslint-disable-next-line security/detect-non-literal-regexp -- pattern from module config, not user input
    return new RegExp(pattern, flags)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`${errorPrefix} invalid regex pattern: ${reason}`)
  }
}

/**
 * Constant-time comparison of two hex-encoded hashes.
 *
 * @param a - First hex-encoded hash (or `null` when unavailable).
 * @param b - Second hex-encoded hash.
 * @returns `true` when both hashes are equal.
 */
export function hexHashesEqual(a: null | string, b: string): boolean {
  if (a == null) return false
  const bufA = Buffer.from(a, "hex")
  const bufB = Buffer.from(b, "hex")
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB)
}

export async function localSha256(filePath: string): Promise<string> {
  const hash = createHash("sha256")
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const stream = createReadStream(filePath) as AsyncIterable<Buffer>
  for await (const chunk of stream) {
    hash.update(chunk)
  }
  return hash.digest("hex")
}

export function sha256String(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}
