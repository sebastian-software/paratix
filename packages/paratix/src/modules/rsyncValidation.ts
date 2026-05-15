const RSYNC_PATH_CONTROL_BOUNDARY = 0x20
const RSYNC_PATH_DEL_CODE_POINT = 0x7f
const STRICT_HOST_KEY_CHECKING_VALUES = new Set(["accept-new", "no", "off", "yes"])

export function validateStrictHostKeyChecking(value: unknown): void {
  if (value == null) return
  if (typeof value === "string" && STRICT_HOST_KEY_CHECKING_VALUES.has(value)) return

  throw new Error(
    '[rsync.sync] strictHostKeyChecking must be one of "accept-new", "no", "off", or "yes"'
  )
}

/**
 * R-0000179: reject `src`/`dest` values that contain ASCII control characters.
 *
 * `dest` is interpolated into the rsync remote spec passed over SSH; embedded
 * newlines or NUL bytes can perturb the rsync handshake or downstream shell
 * tooling. Reject defensively rather than try to escape.
 *
 * @param value - The path to validate.
 * @param field - The argument name used in the error message.
 */
export function validateRsyncPath(value: string, field: "dest" | "src"): void {
  if (value.length === 0) {
    throw new Error(`[rsync.sync] ${field} must not be empty`)
  }
  for (let index = 0; index < value.length; index++) {
    const code = value.codePointAt(index)
    if (code === undefined) continue
    if (code < RSYNC_PATH_CONTROL_BOUNDARY || code === RSYNC_PATH_DEL_CODE_POINT) {
      throw new Error(
        `[rsync.sync] ${field} must not contain ASCII control characters (NUL, newline, tab, ...)`
      )
    }
  }
}

/**
 * R-0000536: reject rsync filter patterns that contain ASCII control characters.
 *
 * `--include`/`--exclude` patterns flow into rsync's filter-rule parser as
 * separate argv entries. rsync itself however accepts multi-line filter rules
 * inside merge files and shares its rule-parsing code across forms; embedded
 * newlines (`\n`), carriage returns or NUL bytes in user-supplied patterns
 * are a strong code smell and have historically led to additional, unintended
 * rules being injected — particularly dangerous when paired with `--delete`.
 *
 * Mirrors the control-character whitelist used by `validateRsyncPath`.
 *
 * @param value - The filter pattern to validate.
 * @param field - The argument name (`"include"` or `"exclude"`) used in the
 *   error message.
 */
export function validateRsyncFilterPattern(value: string, field: "exclude" | "include"): void {
  if (value.length === 0) {
    throw new Error(`[rsync.sync] ${field} pattern must not be empty`)
  }
  for (let index = 0; index < value.length; index++) {
    const code = value.codePointAt(index)
    if (code === undefined) continue
    if (code < RSYNC_PATH_CONTROL_BOUNDARY || code === RSYNC_PATH_DEL_CODE_POINT) {
      throw new Error(
        `[rsync.sync] ${field} pattern must not contain ASCII control characters (NUL, newline, tab, ...)`
      )
    }
  }
}
