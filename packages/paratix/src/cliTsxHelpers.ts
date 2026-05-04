/**
 * Extract the module specifier from common Node.js module-not-found messages.
 *
 * @param message - Error message produced by Node's module loader.
 * @returns The missing specifier, or null when the message shape is unknown.
 */
function extractMissingModuleSpecifier(message: string): null | string {
  const packageMatch = /Cannot find package ['"](?<specifier>[^'"]+)['"]/v.exec(message)
  if (packageMatch?.groups?.specifier != null) return packageMatch.groups.specifier

  const moduleMatch = /Cannot find module ['"](?<specifier>[^'"]+)['"]/v.exec(message)
  if (moduleMatch?.groups?.specifier != null) return moduleMatch.groups.specifier

  return null
}

function isTsxLoaderSpecifier(specifier: string): boolean {
  const normalized = specifier.replaceAll("\\", "/")
  return (
    normalized === "tsx" ||
    normalized === "tsx/esm/api" ||
    normalized.endsWith("/tsx/esm/api")
  )
}

/**
 * Detect whether an import failure means the optional tsx loader itself is
 * missing, rather than a transitive dependency or another loader error.
 *
 * @param error - The error caught while importing `tsx/esm/api`.
 * @returns True when the missing specifier is `tsx` or `tsx/esm/api`.
 */
export function isMissingTsxDependencyError(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const code = "code" in error ? error.code : undefined
  if (code !== "ERR_MODULE_NOT_FOUND" && code !== "MODULE_NOT_FOUND") return false
  const specifier = extractMissingModuleSpecifier(error.message)
  return specifier != null && isTsxLoaderSpecifier(specifier)
}
