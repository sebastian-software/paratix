import { createHash, timingSafeEqual } from "node:crypto"
import { createReadStream } from "node:fs"

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
