const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v

export function validateQuadletName(name: string): void {
  if (name.startsWith("-")) {
    throw new Error(`quadlet: name must not start with '-', got: ${JSON.stringify(name)}`)
  }
  if (!UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`quadlet: name must match ${String(UNIT_NAME_PATTERN)}, got: ${name}`)
  }
}

// OCI references are practically much shorter than 512 chars; capping here
// hardens systemd unit parsing and shell construction against pathological
// inputs.
const QUADLET_IMAGE_VALUE_MAX_LENGTH = 512
// Permitted characters: ASCII letters/digits, _ . : @ / -. Rejects
// whitespace, NUL, newlines and other control codes.
const QUADLET_IMAGE_VALUE_PATTERN = /^[\w.:@\-\/]+$/v

export function validateQuadletImageValue(field: string, value: string): void {
  if (value.length === 0) throw new Error(`quadlet: ${field} must not be empty`)
  if (value.length > QUADLET_IMAGE_VALUE_MAX_LENGTH) {
    throw new Error(
      `quadlet: ${field} must not exceed ${String(QUADLET_IMAGE_VALUE_MAX_LENGTH)} characters, got: ${String(value.length)}`
    )
  }
  if (value.startsWith("-")) {
    throw new Error(`quadlet: ${field} must not start with '-', got: ${JSON.stringify(value)}`)
  }
  if (!QUADLET_IMAGE_VALUE_PATTERN.test(value)) {
    throw new Error(
      `quadlet: ${field} must match ${String(QUADLET_IMAGE_VALUE_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
  // R-0000537: even though the regex above forbids most shell-significant
  // characters, the `/`-permitting character class still matches `..` and
  // `foo/../bar`. Splitting on `/` and rejecting any `..` segment closes
  // the path-traversal corner cases the surrounding pattern allowed
  // through.
  for (const segment of value.split("/")) {
    if (segment === "..") {
      throw new Error(
        `quadlet: ${field} must not contain '..' path segments, got: ${JSON.stringify(value)}`
      )
    }
  }
}

/**
 * R-0000537: the auth-file path passed via `--authfile` must point to a real
 * file on disk. Re-using `validateQuadletImageValue` for that purpose was
 * permissive: it allowed relative paths and accepted `..` segments. This
 * strict variant enforces an absolute path and rejects any traversal
 * segment, while keeping the same length cap and leading-dash rejection.
 *
 * @param field - Logical name used in the error message (e.g. `"authFile"`).
 * @param value - The auth-file path to validate.
 */
export function validateQuadletAuthFilePath(field: string, value: string): void {
  if (value.length === 0) throw new Error(`quadlet: ${field} must not be empty`)
  if (value.length > QUADLET_IMAGE_VALUE_MAX_LENGTH) {
    throw new Error(
      `quadlet: ${field} must not exceed ${String(QUADLET_IMAGE_VALUE_MAX_LENGTH)} characters, got: ${String(value.length)}`
    )
  }
  if (value.startsWith("-")) {
    throw new Error(`quadlet: ${field} must not start with '-', got: ${JSON.stringify(value)}`)
  }
  if (!value.startsWith("/")) {
    throw new Error(
      `quadlet: ${field} must be an absolute path starting with '/', got: ${JSON.stringify(value)}`
    )
  }
  if (!QUADLET_IMAGE_VALUE_PATTERN.test(value)) {
    throw new Error(
      `quadlet: ${field} must match ${String(QUADLET_IMAGE_VALUE_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
  for (const segment of value.split("/")) {
    if (segment === "..") {
      throw new Error(
        `quadlet: ${field} must not contain '..' path segments, got: ${JSON.stringify(value)}`
      )
    }
  }
}
