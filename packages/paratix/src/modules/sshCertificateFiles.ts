import { createHash } from "node:crypto"
import { posix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

const OPTIONS = { ignoreExitCode: true, silent: true } as const
const WRITE_BITS = 0o022
const ROOT_READ_BIT = 0o400
const REGULAR_MODE = "644 0 0"

export class CertificateFileError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "CertificateFileError"
  }
}

export type CertificateFileState = { hash: string; metadata: string } | null
export type CertificateFile = {
  content?: string
  original: CertificateFileState
  path: string
  preserve?: boolean
}

export function parentPaths(path: string): string[] {
  const parents: string[] = []
  let parent = posix.dirname(path)
  while (parent !== "/") {
    parents.unshift(parent)
    parent = posix.dirname(parent)
  }
  return ["/", ...parents]
}

export async function certificateCommand(ssh: SshConnection, command: string): Promise<string> {
  const result = await ssh.exec(command, OPTIONS)
  if (result.code !== 0) {
    throw new CertificateFileError(
      result.stderr.trim() || result.stdout.trim() || `Command failed: ${command}`
    )
  }
  return result.stdout.trim()
}

async function certificateMetadata(ssh: SshConnection, path: string): Promise<string> {
  return certificateCommand(ssh, `stat -c '%a %u %g' -- ${shellQuote(path)}`)
}

function safeRootMetadata(metadata: string, rootReadable: boolean): boolean {
  const [mode, uid] = metadata.split(" ")
  if (!/^[0-7]{3,4}$/v.test(mode) || uid !== "0") return false
  const bits = Number.parseInt(mode, 8)
  return (bits & WRITE_BITS) === 0 && (!rootReadable || (bits & ROOT_READ_BIT) !== 0)
}

export async function inspectCertificateFile(
  ssh: SshConnection,
  path: string,
  options: { preserve?: boolean; user?: string } = {}
): Promise<CertificateFileState> {
  // Every ancestor must be protected before subsequent path operations. The
  // only actors able to replace these directories are already privileged.
  for (const parent of parentPaths(path)) {
    // eslint-disable-next-line no-await-in-loop -- parent validation proceeds from root to leaf
    await inspectCertificateParent(ssh, parent, options.user)
  }
  const quoted = shellQuote(path)
  if (await ssh.test(`[ -L ${quoted} ]`))
    throw new CertificateFileError(`Symlink file rejected: ${path}`)
  if (!(await ssh.test(`[ -e ${quoted} ]`))) return null
  if (!(await ssh.test(`[ -f ${quoted} ]`)))
    throw new CertificateFileError(`Regular file required: ${path}`)
  const metadata = await certificateMetadata(ssh, path)

  if (options.preserve && !safeRootMetadata(metadata, true)) {
    throw new CertificateFileError(
      `Revocation file must be root-owned, root-readable and not group/other-writable: ${path}`
    )
  }
  const hash = await ssh.sha256(path)
  // eslint-disable-next-line security/detect-possible-timing-attacks -- null denotes a missing file, not a secret comparison
  if (hash === null) throw new CertificateFileError(`File disappeared during preflight: ${path}`)
  return { hash, metadata }
}

async function inspectCertificateParent(
  ssh: SshConnection,
  path: string,
  user?: string
): Promise<void> {
  const quoted = shellQuote(path)
  if (await ssh.test(`[ -L ${quoted} ]`))
    throw new CertificateFileError(`Symlink parent rejected: ${path}`)
  if (!(await ssh.test(`[ -e ${quoted} ]`))) return
  if (!(await ssh.test(`[ -d ${quoted} ]`)))
    throw new CertificateFileError(`Parent must be a directory: ${path}`)
  if (!safeRootMetadata(await certificateMetadata(ssh, path), false)) {
    throw new CertificateFileError(
      `Existing parent must be root-owned without group/other write access: ${path}`
    )
  }
  const traversalTest = `test -x ${quoted}`
  if (
    user !== undefined &&
    !(await ssh.test(`su -s /bin/sh -c ${shellQuote(traversalTest)} ${shellQuote(user)}`))
  ) {
    throw new CertificateFileError(
      `Principal parent is not traversable under login user ${user}: ${path}`
    )
  }
}

export function contentHash(content: string): string {
  return createHash("sha256").update(content).digest("hex")
}

export function certificateFileMatches(file: CertificateFile): boolean {
  if (file.preserve && file.original !== null) return true
  if (file.content === undefined) return file.original === null
  return (
    file.original?.hash === contentHash(file.content) && file.original.metadata === REGULAR_MODE
  )
}

export function sameState(left: CertificateFileState, right: CertificateFileState): boolean {
  return left === null
    ? right === null
    : right !== null && left.hash === right.hash && left.metadata === right.metadata
}
