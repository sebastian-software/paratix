import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"

export function localSha256(filePath: string): string {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = readFileSync(filePath)
  return createHash("sha256").update(content).digest("hex")
}

export function sha256String(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}
