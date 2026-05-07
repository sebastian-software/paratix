function shellQuoteForQuadletImageInspect(value: string): string {
  const escapedQuote = "'\\''"
  return `'${value.replaceAll("'", escapedQuote)}'`
}

// R-0000176: ask podman for a deterministic, line-oriented projection that
// stays small even for images with multi-megabyte manifests. The first line
// is the image ID, every subsequent line is one RepoDigest entry.
const QUADLET_INSPECT_FORMAT = "{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}"

export function buildQuadletImageInspectCommand(image: string): string {
  const quotedImage = shellQuoteForQuadletImageInspect(image)
  return `podman image inspect --format '${QUADLET_INSPECT_FORMAT}' -- ${quotedImage}`
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
  // The format string emits the image ID on the first line and one
  // RepoDigest per following line. Empty lines (e.g. trailing newline,
  // image without RepoDigests) are ignored.
  const lines = output.split("\n").filter((line) => line.length > 0)
  if (lines.length === 0) return null
  const [first, ...rest] = lines
  return {
    id: first.length > 0 ? first : null,
    repoDigests: rest,
  }
}
