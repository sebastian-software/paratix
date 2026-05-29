import { randomBytes } from "node:crypto"
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmdirSync,
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs"
import { dirname, join } from "node:path"

import { formatCliValue } from "./cliFormat.js"
import { exitWithMessage } from "./cliValidation.js"

// Sentinel filename written into the reserved project directory so we can
// detect a replacement even when the inode is recycled by the OS — Linux
// tmpfs/ext4 will happily hand a freshly removed inode back to the next
// `mkdirSync`, defeating a plain dev/ino identity check.
const RESERVATION_SENTINEL_PREFIX = ".paratix-reservation-"
const RESERVATION_SENTINEL_TOKEN_BYTES = 16

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
  reservationSentinel: string
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

function reserveProjectDirectoryWithSentinel(
  projectDirectory: string,
  normalizedProjectName: string
): string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    mkdirSync(projectDirectory, { recursive: false })
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      exitWithDirectoryAlreadyExists(normalizedProjectName)
    }
    throw error
  }

  const reservationSentinel = `${RESERVATION_SENTINEL_PREFIX}${randomBytes(
    RESERVATION_SENTINEL_TOKEN_BYTES
  ).toString("hex")}`
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(join(projectDirectory, reservationSentinel), "")
  } catch (error: unknown) {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    rmdirSync(projectDirectory)
    throw error
  }

  return reservationSentinel
}

export function createStagedProjectDirectory(
  projectDirectory: string,
  normalizedProjectName: string
): StagedProjectDirectory {
  const reservationSentinel = reserveProjectDirectoryWithSentinel(
    projectDirectory,
    normalizedProjectName
  )
  const projectDirectoryIdentity = readProjectDirectoryIdentity(projectDirectory)
  const stagingParentDirectory = dirname(projectDirectory)
  const stagingPrefix = join(stagingParentDirectory, `.${normalizedProjectName}-staging-`)

  try {
    return {
      projectDirectory,
      projectDirectoryIdentity,
      reservationSentinel,
      stagingDirectory: mkdtempSync(stagingPrefix),
    }
  } catch (error: unknown) {
    removeReservedProjectDirectoryIfEmpty({
      projectDirectory,
      projectDirectoryIdentity,
      reservationSentinel,
    })
    throw error
  }
}

function assertReservedProjectDirectory(
  { projectDirectory, projectDirectoryIdentity, reservationSentinel }: StagedProjectDirectory,
  normalizedProjectName: string
): void {
  if (!isSameProjectDirectoryIdentity(projectDirectory, projectDirectoryIdentity)) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (!existsSync(join(projectDirectory, reservationSentinel))) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const foreignEntries = readdirSync(projectDirectory).filter(
    (name) => name !== reservationSentinel
  )
  if (foreignEntries.length > 0) {
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }
}

function createQuarantinePath(parentDirectory: string, normalizedProjectName: string): string {
  const quarantineDirectory = mkdtempSync(
    join(parentDirectory, `.${normalizedProjectName}-quarantine-`)
  )
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  rmdirSync(quarantineDirectory)
  return quarantineDirectory
}

function restoreQuarantinedDirectory(quarantineDirectory: string, projectDirectory: string): void {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    renameSync(quarantineDirectory, projectDirectory)
  } catch {
    // Preserve the original publish or cleanup failure. The quarantined path is
    // intentionally left in place if the requested project path was replaced.
  }
}

function quarantineReservedProjectDirectory(
  {
    projectDirectory,
    projectDirectoryIdentity,
    reservationSentinel,
  }: Pick<
    StagedProjectDirectory,
    "projectDirectory" | "projectDirectoryIdentity" | "reservationSentinel"
  >,
  normalizedProjectName: string
): string {
  const quarantineDirectory = createQuarantinePath(dirname(projectDirectory), normalizedProjectName)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  renameSync(projectDirectory, quarantineDirectory)

  if (!isSameProjectDirectoryIdentity(quarantineDirectory, projectDirectoryIdentity)) {
    restoreQuarantinedDirectory(quarantineDirectory, projectDirectory)
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (!existsSync(join(quarantineDirectory, reservationSentinel))) {
    restoreQuarantinedDirectory(quarantineDirectory, projectDirectory)
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const foreignEntries = readdirSync(quarantineDirectory).filter(
    (name) => name !== reservationSentinel
  )
  if (foreignEntries.length > 0) {
    restoreQuarantinedDirectory(quarantineDirectory, projectDirectory)
    exitWithDirectoryAlreadyExists(normalizedProjectName)
  }

  return quarantineDirectory
}

function publishStagedProjectDirectory(
  stagedProjectDirectory: StagedProjectDirectory,
  normalizedProjectName: string
): void {
  const { projectDirectory, reservationSentinel, stagingDirectory } = stagedProjectDirectory
  const quarantineDirectory = quarantineReservedProjectDirectory(
    stagedProjectDirectory,
    normalizedProjectName
  )
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    renameSync(stagingDirectory, projectDirectory)
  } catch (error: unknown) {
    restoreQuarantinedDirectory(quarantineDirectory, projectDirectory)
    throw error
  }

  // Publish succeeded — the quarantine still holds the reservation
  // sentinel. Drop the sentinel so the quarantine becomes empty and can
  // be removed cleanly.
  rmSync(join(quarantineDirectory, reservationSentinel), { force: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  rmdirSync(quarantineDirectory)
}

export function finalizeStagedProjectDirectory(
  stagedProjectDirectory: StagedProjectDirectory,
  normalizedProjectName: string
): ProjectDirectoryIdentity {
  try {
    assertReservedProjectDirectory(stagedProjectDirectory, normalizedProjectName)
    publishStagedProjectDirectory(stagedProjectDirectory, normalizedProjectName)
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

function readForeignReservationEntries(
  projectDirectory: string,
  reservationSentinel: string
): null | string[] {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return readdirSync(projectDirectory).filter((name) => name !== reservationSentinel)
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "ENOENT") {
      return null
    }
    throw error
  }
}

export function removeReservedProjectDirectoryIfEmpty({
  projectDirectory,
  projectDirectoryIdentity,
  reservationSentinel,
}: Pick<
  StagedProjectDirectory,
  "projectDirectory" | "projectDirectoryIdentity" | "reservationSentinel"
>): void {
  if (!isSameProjectDirectoryIdentity(projectDirectory, projectDirectoryIdentity)) {
    return
  }

  const foreignEntries = readForeignReservationEntries(projectDirectory, reservationSentinel)
  if (foreignEntries === null || foreignEntries.length > 0) {
    return
  }

  try {
    rmSync(join(projectDirectory, reservationSentinel), { force: true })
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

export function removePublishedProjectDirectory(
  projectDirectory: string,
  projectDirectoryIdentity: ProjectDirectoryIdentity,
  normalizedProjectName: string
): void {
  const quarantineDirectory = createQuarantinePath(dirname(projectDirectory), normalizedProjectName)
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    renameSync(projectDirectory, quarantineDirectory)
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "ENOENT") {
      return
    }

    throw error
  }

  if (!isSameProjectDirectoryIdentity(quarantineDirectory, projectDirectoryIdentity)) {
    restoreQuarantinedDirectory(quarantineDirectory, projectDirectory)
    return
  }

  rmSync(quarantineDirectory, { force: true, recursive: true })
}
