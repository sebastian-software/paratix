import { lstatSync, mkdirSync, mkdtempSync, renameSync, type Stats } from "node:fs"
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
  stagingDirectory: string
}

export type ProjectDirectoryIdentity = {
  dev: Stats["dev"]
  ino: Stats["ino"]
}

function projectDirectoryExists(projectDirectory: string): boolean {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    lstatSync(projectDirectory)
    return true
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "ENOENT") {
      return false
    }

    throw error
  }
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
  if (projectDirectoryExists(projectDirectory)) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  const stagingParentDirectory = dirname(projectDirectory)
  const stagingPrefix = join(stagingParentDirectory, `.${normalizedProjectName}-staging-`)

  return {
    projectDirectory,
    stagingDirectory: mkdtempSync(stagingPrefix),
  }
}

export function finalizeStagedProjectDirectory(
  { projectDirectory, stagingDirectory }: StagedProjectDirectory,
  normalizedProjectName: string
): ProjectDirectoryIdentity {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    renameSync(stagingDirectory, projectDirectory)
  } catch (error: unknown) {
    const errorCode = isErrnoException(error) ? error.code : undefined
    if (errorCode === "EEXIST" || errorCode === "ENOTEMPTY") {
      exitWithDirectoryAlreadyExists(normalizedProjectName)
    }

    throw error
  }

  return readProjectDirectoryIdentity(projectDirectory)
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
