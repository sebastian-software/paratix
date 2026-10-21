import { constants } from "node:fs"
import { type FileHandle, open } from "node:fs/promises"

import type { Environment, ExecResult } from "../types.js"

import { resolveEnvironment } from "../environment.js"
import {
  PODMAN_PROTOCOL_BASE_CODE,
  PODMAN_TOKEN_LIMIT,
  type PodmanConfiguration,
  type PodmanCredentials,
  PodmanError,
} from "./podmanTypes.js"
import { validateToken, validateUsername } from "./podmanValidation.js"

const TOKEN_READ_MARGIN = 3
const FILE_MODE_MASK = 0o7777
const TOKEN_FILE_MODE = 0o400
const CRLF_LENGTH = 2

async function readBoundedToken(file: FileHandle): Promise<Buffer> {
  const buffer = Buffer.alloc(PODMAN_TOKEN_LIMIT + TOKEN_READ_MARGIN)
  let total = 0
  while (total < buffer.length) {
    // eslint-disable-next-line no-await-in-loop -- Each descriptor read advances the bounded buffer.
    const { bytesRead } = await file.read(buffer, total, buffer.length - total, total)
    if (bytesRead === 0) break
    total += bytesRead
  }
  return buffer.subarray(0, total)
}

async function readControllerToken(path: string): Promise<string> {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Validated explicit credential path; descriptor flags reject symlink and special-file blocking.
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    try {
      const stat = await file.stat()
      if (
        !stat.isFile() ||
        (stat.mode & FILE_MODE_MASK) !== TOKEN_FILE_MODE ||
        stat.uid !== process.geteuid?.() ||
        stat.size > PODMAN_TOKEN_LIMIT + CRLF_LENGTH
      )
        throw new PodmanError("invalid controller token file")
      const buffer = await readBoundedToken(file)
      let token = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer)
      if (token.endsWith("\r\n")) token = token.slice(0, -CRLF_LENGTH)
      else if (token.endsWith("\n")) token = token.slice(0, -1)
      validateToken(token)
      return token
    } finally {
      await file.close()
    }
  } catch {
    throw new PodmanError("controller token file is unavailable or invalid")
  }
}

export async function resolvePodmanCredentials(
  config: PodmanConfiguration,
  env: Environment
): Promise<PodmanCredentials> {
  const source = config.source
  if (!source) return {}
  try {
    const username = source.username ?? (await resolveEnvironment(env, source.usernameEnv))
    validateUsername(username)
    if (source.passwordFileLocation === "target") return { username }
    const password =
      source.passwordEnv === undefined
        ? await readControllerToken(source.passwordFile)
        : await resolveEnvironment(env, source.passwordEnv)
    validateToken(password)
    return { password, username }
  } catch {
    throw new PodmanError("credential resolution failed")
  }
}

export const PODMAN_STATUSES = [
  "OK",
  "NEEDS_APPLY",
  "CHANGED",
  "IMAGE_MISSING",
  "UNSAFE_PATH",
  "SELINUX",
  "HELPER_FAILED",
  "HOST_FAILED",
  "CONFLICT",
  "UNKNOWN",
] as const
export type PodmanStatus = (typeof PODMAN_STATUSES)[number]
export function parsePodmanStatus(result: ExecResult): PodmanStatus {
  const status = PODMAN_STATUSES.find(
    (_status, index) => result.code === index + PODMAN_PROTOCOL_BASE_CODE
  )
  if (status !== undefined && result.stdout === "" && result.stderr === "") return status
  throw new PodmanError("invalid remote status; completion is unknown")
}

export { PODMAN_AUTH_FILE, PODMAN_HELPER_IMAGE, PodmanError } from "./podmanTypes.js"

export type {
  PodmanConfiguration,
  PodmanCredentials,
  PodmanLoginOptions,
  PodmanOptions,
} from "./podmanTypes.js"
export {
  configuration,
  normalizeRegistry,
  validatePodmanPath,
  validateToken,
  validateUsername,
} from "./podmanValidation.js"
