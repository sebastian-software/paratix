import { escapeCliControlCharacters } from "./cliFormat.js"

export function logAdminPublicKeyRealpath(parameters: {
  isLeafSymlink: boolean
  realPath: string
  resolvedPath: string
}): void {
  const escapedRealPath = escapeCliControlCharacters(parameters.realPath)
  const escapedResolvedPath = escapeCliControlCharacters(parameters.resolvedPath)
  if (parameters.isLeafSymlink) {
    console.log(
      `Reading public key from ${escapedRealPath} (symlink target of ${escapedResolvedPath}).`
    )
    return
  }
  console.log(
    `Reading public key from ${escapedRealPath} (resolved via ancestor symlink of ${escapedResolvedPath}).`
  )
}
