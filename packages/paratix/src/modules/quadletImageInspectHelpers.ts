function shellQuoteForQuadletImageInspect(value: string): string {
  const escapedQuote = "'\\''"
  return `'${value.replaceAll("'", escapedQuote)}'`
}

export function buildQuadletImageInspectCommand(image: string): string {
  return `podman image inspect -- ${shellQuoteForQuadletImageInspect(image)}`
}

export function formatQuadletImageIdentifierDetail(imageIdentifier: string): string {
  return `(${imageIdentifier})`
}

export function readQuadletImageIdentifierFromInspectOutput(
  image: string,
  output: string
): null | string {
  const parsed = parseQuadletImageInspectOutput(output)
  if (parsed == null) return null

  const repoDigest = findQuadletRepoDigest(image, parsed.repoDigests)
  return repoDigest ?? parsed.id
}

function findQuadletRepoDigest(image: string, repoDigests: string[]): null | string {
  const repository = getQuadletImageRepository(image)
  for (const repoDigest of repoDigests) {
    const separatorIndex = repoDigest.indexOf("@")
    if (separatorIndex === -1) continue
    const repo = repoDigest.slice(0, separatorIndex)
    const digest = repoDigest.slice(separatorIndex + 1)
    if (repo === repository && digest.length > 0) return digest
  }
  return null
}

function getQuadletImageRepository(image: string): string {
  const digestSeparatorIndex = image.indexOf("@")
  if (digestSeparatorIndex !== -1) return image.slice(0, digestSeparatorIndex)

  const lastSlashIndex = image.lastIndexOf("/")
  const lastColonIndex = image.lastIndexOf(":")
  return lastColonIndex > lastSlashIndex ? image.slice(0, lastColonIndex) : image
}

function parseQuadletImageInspectOutput(output: string): {
  id: null | string
  repoDigests: string[]
} | null {
  try {
    const parsed = JSON.parse(output) as unknown
    if (!Array.isArray(parsed) || parsed.length === 0) return null
    const [firstEntry] = parsed as unknown[]
    if (!isQuadletInspectEntry(firstEntry)) return null
    const repoDigests = Array.isArray(firstEntry.RepoDigests) ? firstEntry.RepoDigests : []
    return {
      id: typeof firstEntry.Id === "string" && firstEntry.Id.length > 0 ? firstEntry.Id : null,
      repoDigests: repoDigests.filter(
        (entry): entry is string => typeof entry === "string" && entry.length > 0
      ),
    }
  } catch {
    return null
  }
}

function isQuadletInspectEntry(value: unknown): value is { Id?: unknown; RepoDigests?: unknown[] } {
  return value != null && typeof value === "object"
}
