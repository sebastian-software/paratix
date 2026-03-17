import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"

export async function localSha256(filePath: string): Promise<string> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = await readFile(filePath)
  return createHash("sha256").update(content).digest("hex")
}

export function sha256String(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}
