import { createHash } from "node:crypto"
import { posix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { withMutexLock } from "./moduleHelpers.js"
import { parentPaths } from "./sshCertificateFiles.js"

const OPTIONS = { ignoreExitCode: true, silent: true } as const
const TEMP_PREFIX = ".paratix-known-hosts"
const READ_STATUS_LENGTH = "\n0".length

export class KnownHostsFileError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = "KnownHostsFileError"
  }
}

export type KnownHostsTarget = {
  home: string
  knownHostsPath: string
  sshDirectoryPath: string
}
export type KnownHostsOwner = { group: string; user: string }
export type KnownHostsSnapshot = {
  content: string
  directory: null | string
  file: null | string
}

export async function knownHostsCommand(ssh: SshConnection, command: string): Promise<string> {
  const result = await ssh.exec(command, OPTIONS)
  if (result.code !== 0) {
    throw new KnownHostsFileError(result.stderr.trim() || "known_hosts command failed")
  }
  return result.stdout
}

export function knownHostsTarget(home: string): KnownHostsTarget {
  if (
    home === "/" ||
    !home.startsWith("/") ||
    /[\p{Cc}\p{Cf}:]/v.test(home) ||
    posix.normalize(home) !== home
  ) {
    throw new KnownHostsFileError("failed to resolve a safe home directory")
  }
  return { home, knownHostsPath: `${home}/.ssh/known_hosts`, sshDirectoryPath: `${home}/.ssh` }
}

/**
 * Reject aliases before choosing a lock name, including aliases above a missing .ssh.
 *
 * @param ssh - The active target connection.
 * @param target - Normalized absolute home and known_hosts paths.
 */
export async function confirmKnownHostsTarget(
  ssh: SshConnection,
  target: KnownHostsTarget
): Promise<void> {
  const guards = parentPaths(target.knownHostsPath)
    .map((path) => {
      const quoted = shellQuote(path)
      return `[ ! -L ${quoted} ] && { [ ! -e ${quoted} ] || [ -d ${quoted} ]; } || { echo 'known_hosts parent must be a real directory' >&2; exit 1; }`
    })
    .join("\n")
  const actual = await knownHostsCommand(
    ssh,
    `${guards}\nreadlink -m -- ${shellQuote(target.knownHostsPath)}`
  )
  if (actual.trim() !== target.knownHostsPath) {
    throw new KnownHostsFileError("known_hosts target has an ambiguous physical path")
  }
}

export async function withKnownHostsLock(
  ssh: SshConnection,
  target: KnownHostsTarget,
  parameters: { name: string; section: () => Promise<ModuleResult> }
): Promise<ModuleResult> {
  const { name, section } = parameters
  await confirmKnownHostsTarget(ssh, target)
  const digest = createHash("sha256").update(target.knownHostsPath).digest("hex")
  const result = await withMutexLock(ssh, {
    failureMessage: `[${name}] known_hosts transaction failed`,
    lockName: `ssh-known-hosts-${digest}`,
    async section() {
      await confirmKnownHostsTarget(ssh, target)
      return section()
    },
  })
  return result.kind === "failed" ? result.failure : result.value
}

function pathGuard(path: string, directory: boolean): string {
  const quoted = shellQuote(path)
  const test = directory ? "-d" : "-f"
  return `[ ! -L ${quoted} ] && { [ ! -e ${quoted} ] || [ ${test} ${quoted} ]; } || { echo '${directory ? ".ssh must be a real directory" : "known_hosts must be a regular file, not a symlink"}' >&2; exit 1; }`
}

function directoryMetadataCommand(path: string): string {
  return `stat -c '%d:%i %a %U %G' -- ${shellQuote(path)}`
}

function readWithStatus(path: string): string {
  return `{ if dd if=${shellQuote(path)} iflag=nofollow,nonblock status=none; then printf '\\n0'; else printf '\\n1'; fi; }`
}

function checkedContentHash(content: string): string {
  return createHash("sha256")
    .update(Buffer.from(`${content}\n0`, "latin1"))
    .digest("hex")
}

function metadataCommand(path: string): string {
  return `stat -c '%d:%i:%s:%y:%z %a %U %G' -- ${shellQuote(path)}`
}

/**
 * The data open itself uses O_NOFOLLOW; before/after snapshots detect observable replacement.
 *
 * @param ssh - The active target connection.
 * @param target - Canonical paths to inspect without changing the filesystem.
 * @returns The original raw bytes and directory/file identity and metadata.
 */
export async function inspectKnownHosts(
  ssh: SshConnection,
  target: KnownHostsTarget
): Promise<KnownHostsSnapshot> {
  await confirmKnownHostsTarget(ssh, target)
  const directory = shellQuote(target.sshDirectoryPath)
  const file = shellQuote(target.knownHostsPath)
  const result = await knownHostsCommand(
    ssh,
    `set -e
${pathGuard(target.sshDirectoryPath, true)}
${pathGuard(target.knownHostsPath, false)}
directory_before=missing
if [ -e ${directory} ]; then directory_before=$(${directoryMetadataCommand(target.sshDirectoryPath)}); fi
printf '%s\\n' "$directory_before"
if [ -e ${file} ]; then
  before=$(${metadataCommand(target.knownHostsPath)})
  printf '%s\\n' "$before"
  ${readWithStatus(target.knownHostsPath)} | base64 -w 0
  after=$(${metadataCommand(target.knownHostsPath)})
  [ "$before" = "$after" ] && [ ! -L ${file} ] || { echo 'known_hosts changed during read' >&2; exit 1; }
else printf 'missing\\n'; fi
directory_after=missing
if [ -e ${directory} ]; then directory_after=$(${directoryMetadataCommand(target.sshDirectoryPath)}); fi
[ ! -L ${directory} ] && [ "$directory_before" = "$directory_after" ] || { echo '.ssh changed during read' >&2; exit 1; }`
  )
  const [directoryState, fileState, encoded = ""] = result.split("\n")
  const decoded = Buffer.from(encoded, "base64").toString("latin1")
  if (fileState !== "missing" && !decoded.endsWith("\n0")) {
    throw new KnownHostsFileError("failed to read known_hosts without following symlinks")
  }
  return {
    content: fileState === "missing" ? "" : decoded.slice(0, -READ_STATUS_LENGTH),
    directory: directoryState === "missing" ? null : directoryState,
    file: fileState === "missing" ? null : fileState,
  }
}

export function knownHostsMetadataMatches(
  snapshot: KnownHostsSnapshot,
  owner: KnownHostsOwner
): boolean {
  return (
    snapshot.directory?.endsWith(` 700 ${owner.user} ${owner.group}`) === true &&
    snapshot.file?.endsWith(` 600 ${owner.user} ${owner.group}`) === true
  )
}

function sameSnapshot(left: KnownHostsSnapshot, right: KnownHostsSnapshot): boolean {
  return (
    left.content === right.content && left.directory === right.directory && left.file === right.file
  )
}

async function prepareKnownHostsDirectory(
  ssh: SshConnection,
  target: KnownHostsTarget,
  parameters: { original: KnownHostsSnapshot; owner: KnownHostsOwner }
): Promise<void> {
  const { original, owner } = parameters
  const directory = shellQuote(target.sshDirectoryPath)
  const expected = original.directory?.split(" ")[0].split(":").slice(0, 2).join(":")
  await confirmKnownHostsTarget(ssh, target)
  await knownHostsCommand(
    ssh,
    `set -e
${pathGuard(target.sshDirectoryPath, true)}
${expected === undefined ? `[ ! -e ${directory} ] || { echo '.ssh appeared during prepare' >&2; exit 1; }; mkdir -- ${directory}` : `[ "$(stat -c '%d:%i' -- ${directory})" = ${shellQuote(expected)} ] || { echo '.ssh changed before prepare' >&2; exit 1; }`}
identity=$(stat -c '%d:%i' -- ${directory})
[ ! -L ${directory} ] && chmod 700 -- ${directory}
[ ! -L ${directory} ] && chown -h -- ${shellQuote(`${owner.user}:${owner.group}`)} ${directory}
[ ! -L ${directory} ] && [ "$identity" = "$(stat -c '%d:%i' -- ${directory})" ] || { echo '.ssh changed during prepare' >&2; exit 1; }`
  )
}

function snapshotGuard(target: KnownHostsTarget, snapshot: KnownHostsSnapshot): string {
  const file = shellQuote(target.knownHostsPath)
  const directory = shellQuote(target.sshDirectoryPath)
  const fileGuard =
    snapshot.file === null
      ? `[ ! -e ${file} ] && [ ! -L ${file} ]`
      : `[ "$(${metadataCommand(target.knownHostsPath)})" = ${shellQuote(snapshot.file)} ] && [ "$( ${readWithStatus(target.knownHostsPath)} | sha256sum | cut -d' ' -f1)" = ${shellQuote(checkedContentHash(snapshot.content))} ]`
  return `${pathGuard(target.sshDirectoryPath, true)}
[ "$(${directoryMetadataCommand(target.sshDirectoryPath)})" = ${shellQuote(snapshot.directory ?? "")} ] || { echo '.ssh changed before publication' >&2; exit 1; }
${pathGuard(target.knownHostsPath, false)}
${fileGuard} || { echo 'known_hosts changed before publication' >&2; exit 1; }
[ -d ${directory} ]`
}

/**
 * Stage and publish on the target filesystem; a failed rename retains the original hardlink.
 *
 * @param ssh - The active target connection.
 * @param parameters - The protected target, snapshot and desired content and ownership.
 * @param parameters.content - Desired raw bytes represented as a Latin-1 string.
 * @param parameters.name - Module name used in structured failure messages.
 * @param parameters.original - The snapshot that must still match before staging.
 * @param parameters.owner - The target user and actual primary group.
 * @param parameters.target - Canonical paths protected by the shared file lock.
 * @returns A changed result after verification or a structured failure.
 */
export async function writeKnownHosts(
  ssh: SshConnection,
  parameters: {
    content: string
    name: string
    original: KnownHostsSnapshot
    owner: KnownHostsOwner
    target: KnownHostsTarget
  }
): Promise<ModuleResult> {
  const { content, name, original, owner, target } = parameters
  let temporary: string | undefined
  try {
    if (!sameSnapshot(original, await inspectKnownHosts(ssh, target)))
      throw new KnownHostsFileError("known_hosts changed before staging")
    await prepareKnownHostsDirectory(ssh, target, { original, owner })
    const prepared = await inspectKnownHosts(ssh, target)
    // Directory chmod/chown is intentional; the original file must still be unchanged.
    if (prepared.file !== original.file || prepared.content !== original.content) {
      throw new KnownHostsFileError("known_hosts changed during directory preparation")
    }
    temporary = await allocateKnownHostsTemporary(ssh, target)
    await stageKnownHosts(ssh, { content, owner, temporary })
    await publishKnownHosts(ssh, { content, owner, snapshot: prepared, target, temporary })
    return { status: "changed" }
  } catch (error) {
    return failed(`[${name}] ${error instanceof Error ? error.message : String(error)}`)
  } finally {
    if (temporary !== undefined) {
      await ssh.exec(`rm -f -- ${shellQuote(temporary)}`, OPTIONS)
    }
  }
}

async function allocateKnownHostsTemporary(
  ssh: SshConnection,
  target: KnownHostsTarget
): Promise<string> {
  const output = await knownHostsCommand(
    ssh,
    `mktemp -p ${shellQuote(target.sshDirectoryPath)} -- '${TEMP_PREFIX}.XXXXXX'`
  )
  return validateMktempPath(target.sshDirectoryPath, output.trim(), TEMP_PREFIX)
}

async function stageKnownHosts(
  ssh: SshConnection,
  parameters: { content: string; owner: KnownHostsOwner; temporary: string }
): Promise<void> {
  const { content, owner, temporary } = parameters
  const quoted = shellQuote(temporary)
  await knownHostsCommand(
    ssh,
    `set -e
[ ! -L ${quoted} ] && [ -f ${quoted} ]
identity=$(stat -c '%d:%i' -- ${quoted})
printf '%s' ${shellQuote(Buffer.from(content, "latin1").toString("base64"))} | base64 -d | dd of=${quoted} oflag=nofollow status=none
[ ! -L ${quoted} ] && chmod 600 -- ${quoted}
[ ! -L ${quoted} ] && chown -h -- ${shellQuote(`${owner.user}:${owner.group}`)} ${quoted}
[ ! -L ${quoted} ] && [ "$identity" = "$(stat -c '%d:%i' -- ${quoted})" ]`
  )
}

async function publishKnownHosts(
  ssh: SshConnection,
  parameters: {
    content: string
    owner: KnownHostsOwner
    snapshot: KnownHostsSnapshot
    target: KnownHostsTarget
    temporary: string
  }
): Promise<void> {
  const { content, owner, snapshot, target, temporary } = parameters
  const file = shellQuote(target.knownHostsPath)
  const staged = shellQuote(temporary)
  const backup = shellQuote(`${temporary}.backup`)
  await confirmKnownHostsTarget(ssh, target)
  await knownHostsCommand(
    ssh,
    `set -e
${snapshotGuard(target, snapshot)}
[ ! -L ${staged} ] && [ -f ${staged} ]
[ "$(stat -c '%a %U %G' -- ${staged})" = ${shellQuote(`600 ${owner.user} ${owner.group}`)} ]
[ "$( ${readWithStatus(temporary)} | sha256sum | cut -d' ' -f1)" = ${shellQuote(checkedContentHash(content))} ]
${snapshot.file === null ? ":" : `ln -P -- ${file} ${backup}`}
if ! mv -T -- ${staged} ${file}; then
  ${snapshot.file === null ? ":" : `[ ! -L ${backup} ] && mv -T -- ${backup} ${file} || { echo 'known_hosts backup restore failed' >&2; exit 1; }`}
  echo 'known_hosts publication failed' >&2; exit 1
fi
rm -f -- ${backup}`
  )
  const actual = await inspectKnownHosts(ssh, target)
  if (actual.content !== content || !knownHostsMetadataMatches(actual, owner)) {
    throw new KnownHostsFileError("known_hosts content or metadata changed after publication")
  }
}
