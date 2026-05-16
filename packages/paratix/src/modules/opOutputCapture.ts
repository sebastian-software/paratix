const BYTES_PER_KIB = 1024
const OP_OUTPUT_CAPTURE_LIMIT_KIB = 64
/**
 * Minimum length of a secret prefix that {@link maskKnownSecretPrefixes} will
 * redact when the full secret is not present verbatim in the captured op
 * output. Set high enough that:
 *
 * - 6-digit TOTP codes never leak two trailing digits (would otherwise reveal
 *   ~7 bits of entropy per failure).
 * - Base64 tokens with a fixed `eyJ`-style header still have at least the
 *   first half of their unique tail covered before the prefix matcher
 *   declines to redact.
 *
 * R-0000588: bumped from 4 to 8. A second defence layer that also masks
 * sensitive suffixes could be added later; this value covers the prefix
 * direction only.
 */
const MIN_MASKED_SECRET_PREFIX_LENGTH = 8

export const OP_OUTPUT_CAPTURE_LIMIT_BYTES = OP_OUTPUT_CAPTURE_LIMIT_KIB * BYTES_PER_KIB

export type BoundedOutputCapture = {
  append: (chunk: Buffer) => void
  exceededLimit: () => boolean
  text: () => string
}

export function createBoundedOutputCapture(streamName: "stderr" | "stdout"): BoundedOutputCapture {
  const truncationMarker = `[paratix] op ${streamName} truncated`
  const chunks: Buffer[] = []
  let capturedBytes = 0
  let exceeded = false

  return {
    append(chunk: Buffer): void {
      const remainingBytes = OP_OUTPUT_CAPTURE_LIMIT_BYTES - capturedBytes
      if (remainingBytes > 0) {
        const capturedChunk =
          chunk.byteLength <= remainingBytes ? chunk : chunk.subarray(0, remainingBytes)
        chunks.push(capturedChunk)
        capturedBytes += capturedChunk.byteLength
      }
      if (chunk.byteLength > remainingBytes) exceeded = true
    },
    exceededLimit(): boolean {
      return exceeded
    },
    text(): string {
      const output = Buffer.concat(chunks, capturedBytes).toString("utf8")
      if (!exceeded) return output
      return `${output}\n${truncationMarker} after ${String(OP_OUTPUT_CAPTURE_LIMIT_BYTES)} bytes\n`
    },
  }
}

export function maskKnownSecretPrefixes(detail: string, secrets: string[]): string {
  let maskedDetail = detail
  for (const secret of secrets) {
    if (secret.length < MIN_MASKED_SECRET_PREFIX_LENGTH || maskedDetail.includes(secret)) continue
    const maxPrefixLength = Math.min(secret.length - 1, maskedDetail.length)
    for (let length = maxPrefixLength; length >= MIN_MASKED_SECRET_PREFIX_LENGTH; length -= 1) {
      const prefix = secret.slice(0, length)
      if (!maskedDetail.includes(prefix)) continue
      maskedDetail = maskedDetail.split(prefix).join("[REDACTED]")
      break
    }
  }
  return maskedDetail
}
