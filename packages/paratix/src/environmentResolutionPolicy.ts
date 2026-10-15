import type { EnvironmentMetaEntry } from "./types.js"

type MetaValueType = EnvironmentMetaEntry["valueType"]

export const PER_ACCESS_RESOLUTION = "per-access"

const ENVIRONMENT_RESOLUTION_POLICY = Symbol.for("paratix.environment.resolution")

/**
 * Recognize generated resolvers even across separately bundled package copies.
 *
 * @param value - The environment value to inspect without invoking it.
 * @returns Whether the value carries the per-access resolution policy.
 */
export function hasPerAccessResolution(value: unknown): boolean {
  return (
    typeof value === "function" &&
    ENVIRONMENT_RESOLUTION_POLICY in value &&
    value[ENVIRONMENT_RESOLUTION_POLICY] === PER_ACCESS_RESOLUTION
  )
}

/**
 * Mark only a generated wrapper, leaving the caller's resolver untouched.
 *
 * @param resolver - The generated wrapper to mark.
 * @returns The same wrapper with a non-enumerable policy marker.
 */
export function markPerAccessResolution<TResolver extends () => Promise<boolean | number | string>>(
  resolver: TResolver
): TResolver {
  Object.defineProperty(resolver, ENVIRONMENT_RESOLUTION_POLICY, { value: PER_ACCESS_RESOLUTION })
  return resolver
}

function isMetaValueType(value: string): value is MetaValueType {
  return value === "boolean" || value === "number" || value === "string"
}

export function validateResolvedMetaValue(parameters: {
  actualType: string
  declaredValueType: MetaValueType
  enforceDeclaredValueType: boolean
  entryKey: string
}): void {
  const { actualType, declaredValueType, enforceDeclaredValueType, entryKey } = parameters
  if (!isMetaValueType(actualType)) {
    throw new TypeError(
      `Env meta entry ${JSON.stringify(entryKey)} resolved to typeof ${actualType}, expected boolean, number, or string`
    )
  }
  if (enforceDeclaredValueType && actualType !== declaredValueType) {
    throw new TypeError(
      `Env meta entry ${JSON.stringify(entryKey)} resolved to typeof ${actualType}, expected ${declaredValueType}`
    )
  }
}

export function createPerAccessEnvironmentResolver(
  entry: EnvironmentMetaEntry
): () => Promise<boolean | number | string> {
  let pendingResolution: null | Promise<boolean | number | string> = null
  const declaredValueType = entry.valueType
  const enforceDeclaredValueType = entry.valueTypeExplicit !== false
  const entryKey = entry.name
  return markPerAccessResolution(async () => {
    if (pendingResolution != null) return pendingResolution
    // Defer invocation until the pending promise is stored, including sync failures.
    pendingResolution = Promise.resolve()
      .then(async () => entry.resolve())
      .then((resolved) => {
        validateResolvedMetaValue({
          actualType: typeof resolved,
          declaredValueType,
          enforceDeclaredValueType,
          entryKey,
        })
        return resolved
      })
      .finally(() => {
        pendingResolution = null
      })
    return pendingResolution
  })
}
