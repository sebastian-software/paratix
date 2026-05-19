import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmdirSync,
  type Stats,
} from "node:fs"
import { dirname, join } from "node:path"

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

export type StagedProjectDirectory = {
  projectDirectory: string
  projectDirectoryIdentity: ProjectDirectoryIdentity
  stagingDirectory: string
}

export type ProjectDirectoryIdentity = {
  dev: Stats["dev"]
  ino: Stats["ino"]
}

function exitWithDirectoryAlreadyExists(normalizedProjectName: string): never {
  exitWithMessage(`Error: Directory ${formatCliValue(normalizedProjectName)} already exists.`)
  throw new Error(`Error: Directory ${formatCliValue(normalizedProjectName)} already exists.`)
}

function readProjectDirectoryIdentity(projectDirectory: string): ProjectDirectoryIdentity {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const stats = lstatSync(projectDirectory)
  return { dev: stats.dev, ino: stats.ino }
}

export function createStagedProjectDirectory(
  projectDirectory: string,
  normalizedProjectName: string
): StagedProjectDirectory {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    mkdirSync(projectDirectory, { recursive: false })
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      exitWithDirectoryAlreadyExists(normalizedProjectName)
    }
    throw error
  }

  const projectDirectoryIdentity = readProjectDirectoryIdentity(projectDirectory)
  const stagingParentDirectory = dirname(projectDirectory)
  const stagingPrefix = join(stagingParentDirectory, `.${normalizedProjectName}-staging-`)

  try {
    return {
      projectDirectory,
      projectDirectoryIdentity,
      stagingDirectory: mkdtempSync(stagingPrefix),
    }
  } catch (error: unknown) {
    removeReservedProjectDirectoryIfEmpty({ projectDirectory, projectDirectoryIdentity })
    throw error
  }
}

function assertReservedProjectDirectory(
  { projectDirectory, projectDirectoryIdentity }: StagedProjectDirectory,
  normalizedProjectName: string
): void {
  if (!isSameProjectDirectoryIdentity(projectDirectory, projectDirectoryIdentity)) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (readdirSync(projectDirectory).length > 0) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }
}

function publishStagedProjectDirectory({
  projectDirectory,
  stagingDirectory,
}: StagedProjectDirectory): void {
  const publishedEntries: string[] = []
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const entries = readdirSync(stagingDirectory)
  try {
    for (const entry of entries) {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      renameSync(join(stagingDirectory, entry), join(projectDirectory, entry))
      publishedEntries.push(entry)
    }
  } catch (error: unknown) {
    for (const entry of publishedEntries.toReversed()) {
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        renameSync(join(projectDirectory, entry), join(stagingDirectory, entry))
      } catch {
        // Preserve the original publish failure; cleanup in the caller still
        // removes any staging content that could not be restored.
      }
    }
    throw error
  }
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  rmdirSync(stagingDirectory)
}

export function finalizeStagedProjectDirectory(
  stagedProjectDirectory: StagedProjectDirectory,
  normalizedProjectName: string
): ProjectDirectoryIdentity {
  try {
    assertReservedProjectDirectory(stagedProjectDirectory, normalizedProjectName)
    publishStagedProjectDirectory(stagedProjectDirectory)
  } catch (error: unknown) {
    const errorCode = isErrnoException(error) ? error.code : undefined
    if (errorCode === "EEXIST" || errorCode === "ENOTEMPTY") {
      exitWithDirectoryAlreadyExists(normalizedProjectName)
    }

    throw error
  }

  return readProjectDirectoryIdentity(stagedProjectDirectory.projectDirectory)
}

export function isSameProjectDirectoryIdentity(
  projectDirectory: string,
  identity: ProjectDirectoryIdentity
): boolean {
  try {
    const currentIdentity = readProjectDirectoryIdentity(projectDirectory)
    return currentIdentity.dev === identity.dev && currentIdentity.ino === identity.ino
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "ENOENT") {
      return false
    }

    throw error
  }
}

export function removeReservedProjectDirectoryIfEmpty({
  projectDirectory,
  projectDirectoryIdentity,
}: Pick<StagedProjectDirectory, "projectDirectory" | "projectDirectoryIdentity">): void {
  if (!isSameProjectDirectoryIdentity(projectDirectory, projectDirectoryIdentity)) {
    return
  }

  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    rmdirSync(projectDirectory)
  } catch (error: unknown) {
    const errorCode = isErrnoException(error) ? error.code : undefined
    if (errorCode === "ENOENT" || errorCode === "ENOTEMPTY") {
      return
    }

    throw error
  }
}
