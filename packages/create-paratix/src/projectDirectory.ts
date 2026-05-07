import { mkdirSync } from "node:fs"

import { formatCliValue } from "./cliFormat.js"
import { exitWithMessage } from "./cliValidation.js"

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && typeof error.code === "string"
}

export function createProjectDirectoryAtomically(
  projectDirectory: string,
  normalizedProjectName: string
): void {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    mkdirSync(projectDirectory, { recursive: false })
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      exitWithMessage(`Error: Directory ${formatCliValue(normalizedProjectName)} already exists.`)
    }
    throw error
  }
}
