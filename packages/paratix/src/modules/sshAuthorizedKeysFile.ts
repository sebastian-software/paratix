/**
 * Remote read and staging primitives for `ssh.authorizedKeys`.
 *
 * The existing file is transferred as base64 so its exact bytes reach the
 * controller (no UTF-8 replacement and no secret masking of stdout content),
 * and it is never echoed in failure output because option values such as
 * `command` or `environment` may carry sensitive data. The new content goes
 * back the same way: its base64 text is written through SFTP and decoded on
 * the host, so every byte of lines the module does not own is preserved.
 *
 * `~/.ssh` belongs to the target user, who can rename, replace or link any
 * entry in it between two remote commands. The base64 payload is therefore
 * written into a private `mktemp -d` directory under `/tmp` that only the
 * privileged connection user can enter, never into `~/.ssh`. The staged file
 * itself has to stay in `~/.ssh` (same filesystem, so the final rename is
 * atomic); every privileged step on it first checks that it is still a
 * regular, single-link file owned by the staging uid and never follows a
 * symlink.
 */
import { createHash } from "node:crypto"

import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote, validateMktempPath } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import { isStrictBase64 } from "./sshPublicKeyValidation.js"

const READ_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const READ_STATUS_SUFFIX = "\n0"
const PRESENT_MARKER = "present\n"
const MISSING_MARKER = "missing\n"
const STAGING_FILE_MODE = "0600"
// Prefix of the private directory under `/tmp` that receives the base64 payload.
const PAYLOAD_DIRECTORY_PREFIX = "paratix-authorized-keys-payload"
const PAYLOAD_DIRECTORY_TEMPLATE = `${PAYLOAD_DIRECTORY_PREFIX}.XXXXXX`
// Name of the file inside that directory that carries the base64 text.
const PAYLOAD_FILE_NAME = "payload.base64"
const STAGED_FILE_REFUSAL =
  "authorized_keys staging file must be a regular single-link file owned by the staging user"
// `stat -c %a` of the staged file that the final replace may publish.
const STAGED_FILE_OCTAL_MODE = "600"
const STAGED_FILE_MODE_REFUSAL =
  "authorized_keys staging file must have mode 600; a default ACL on ~/.ssh may override the umask"

/** Result of reading `authorized_keys`; `content` is Latin-1, `null` when the file is missing. */
export type AuthorizedKeysRead =
  { content: null | string; kind: "read" } | { kind: "failed"; result: ExecResult }

/**
 * R-0000617: read through `dd ... iflag=nofollow` so open(2) uses
 * `O_NOFOLLOW`. A plain read would leave a TOCTOU window between the
 * `[ ! -L ]` probe and the open where an attacker with write access to
 * `~/.ssh` could swap the file for a symlink and redirect the read into an
 * arbitrary location; `dd iflag=nofollow` fails with ELOOP instead. The
 * trailing status line distinguishes a failed read from an empty file,
 * because the pipeline exit status is the one of the consumer.
 *
 * @param quotedPath - The shell-quoted path to read.
 * @returns A shell fragment printing the file bytes followed by `\n0` or `\n1`.
 */
function noFollowReadWithStatus(quotedPath: string): string {
  return `{ if dd if=${quotedPath} iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; }`
}

/**
 * SHA-256 of content plus the success status suffix, matching what
 * `noFollowReadWithStatus(...) | sha256sum` prints for an unchanged file.
 *
 * @param content - Latin-1 content.
 * @returns The lowercase hex digest.
 */
function checkedContentDigest(content: string): string {
  return createHash("sha256")
    .update(Buffer.from(`${content}${READ_STATUS_SUFFIX}`, "latin1"))
    .digest("hex")
}

/**
 * Build the read-only command used by check, dry-run and apply. It refuses a
 * symlinked `~/.ssh` as well as a symlinked `authorized_keys`, so no read
 * follows a link the target user controls.
 *
 * @param parameters - Paths to read.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.sshDirectoryPath - Absolute `~/.ssh` path.
 * @returns A shell script printing `missing` or `present` plus base64 content.
 */
export function authorizedKeysReadCommand(parameters: {
  authorizedKeysPath: string
  sshDirectoryPath: string
}): string {
  const keys = shellQuote(parameters.authorizedKeysPath)
  const directory = shellQuote(parameters.sshDirectoryPath)
  return `set -e
[ ! -L ${directory} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
[ ! -L ${keys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
if [ -e ${keys} ]; then
  [ -f ${keys} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  printf 'present\\n'
  ${noFollowReadWithStatus(keys)} | base64 -w 0
else
  printf 'missing\\n'
fi`
}

function parseReadOutput(stdout: string): { content: null | string } | null {
  if (stdout === MISSING_MARKER) return { content: null }
  if (stdout.endsWith(CAPTURE_TRUNCATION_MARKER) || !stdout.startsWith(PRESENT_MARKER)) return null
  const encoded = stdout.slice(PRESENT_MARKER.length)
  if (!isStrictBase64(encoded)) return null
  const decoded = Buffer.from(encoded, "base64").toString("latin1")
  if (!decoded.endsWith(READ_STATUS_SUFFIX)) return null
  return { content: decoded.slice(0, -READ_STATUS_SUFFIX.length) }
}

/**
 * Read `authorized_keys` without following symlinks.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Paths to read.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.sshDirectoryPath - Absolute `~/.ssh` path.
 * @returns The content, or a failed result whose stdout is redacted.
 */
export async function readAuthorizedKeys(
  conn: SshConnection,
  parameters: { authorizedKeysPath: string; sshDirectoryPath: string }
): Promise<AuthorizedKeysRead> {
  const result = await conn.exec(authorizedKeysReadCommand(parameters), READ_EXEC_OPTS)
  if (result.code !== 0) return { kind: "failed", result: { ...result, stdout: "" } }
  const parsed = parseReadOutput(result.stdout)
  if (parsed === null) {
    return {
      kind: "failed",
      result: {
        code: 1,
        stderr: "failed to read authorized_keys without following symlinks",
        stdout: "",
      },
    }
  }
  return { content: parsed.content, kind: "read" }
}

/**
 * Path of the file that carries the base64 text of the staged content.
 *
 * @param payloadDirectory - The validated private payload directory under `/tmp`.
 * @returns The payload path inside it.
 */
export function authorizedKeysStagingPayloadPath(payloadDirectory: string): string {
  return `${payloadDirectory}/${PAYLOAD_FILE_NAME}`
}

/**
 * Shell statement that aborts unless the staged file in `~/.ssh` is still the
 * file the privileged connection created: not a symlink, a regular file, one
 * hard link and owned by the uid that runs the script. The target user owns
 * `~/.ssh` and could otherwise swap the entry for a symlink, or (with
 * `fs.protected_hardlinks=0`) for a hard link to a file such as
 * `/etc/shadow`, between two remote commands. `stat` without `-L` reports the
 * entry itself, and a hard link always raises the link count above one.
 *
 * @param temporaryPath - The validated staging path inside the canonical `~/.ssh`.
 * @returns A single shell statement without a trailing newline.
 */
export function authorizedKeysStagedFileGuard(temporaryPath: string): string {
  const staged = shellQuote(temporaryPath)
  return `[ ! -L ${staged} ] && [ -f ${staged} ] && [ "$(stat -c '%u %h' -- ${staged})" = "$(id -u) 1" ] || { echo '${STAGED_FILE_REFUSAL}' >&2; exit 1; }`
}

/**
 * Shell statement that aborts unless the staged file has mode 600. The decode
 * creates it under `umask 077`, but a default ACL on `~/.ssh` overrides the
 * umask, so the new inode can come out as 0640 or 0660. The mode has to be
 * right before the final replace publishes the file: the replace only checks
 * the live file after `mv -T`, when the backup is already gone, and a
 * symlink-following `chmod` on a path in the user-owned `~/.ssh` is not an
 * option. Run it only after {@link authorizedKeysStagedFileGuard}, so `stat`
 * without `-L` reports the regular file itself and not a symlink.
 *
 * @param temporaryPath - The validated staging path inside the canonical `~/.ssh`.
 * @returns A single shell statement without a trailing newline.
 */
export function authorizedKeysStagedFileModeGuard(temporaryPath: string): string {
  return `[ "$(stat -c '%a' -- ${shellQuote(temporaryPath)})" = ${STAGED_FILE_OCTAL_MODE} ] || { echo '${STAGED_FILE_MODE_REFUSAL}' >&2; exit 1; }`
}

/**
 * Build the command that decodes the transferred base64 payload into the
 * staging file and verifies the staged bytes. After the ownership and link
 * guard the reserved entry is removed and recreated by `dd` with
 * `conv=excl` (`O_CREAT | O_EXCL`) and `oflag=nofollow` under `umask 077`:
 * the write can only create a new 0600 inode and never opens a symlink or a
 * hard link the target user put in place after the guard. A name claimed in
 * that window makes `dd` fail instead. The last statement confirms mode 600,
 * because a default ACL on `~/.ssh` overrides the umask.
 *
 * @param parameters - Paths and the staged content.
 * @param parameters.content - The staged content as Latin-1 string.
 * @param parameters.payloadDirectory - The validated private payload directory.
 * @param parameters.temporaryPath - The validated mktemp staging path.
 * @returns The decode and verification shell script.
 */
export function authorizedKeysStageDecodeCommand(parameters: {
  content: string
  payloadDirectory: string
  temporaryPath: string
}): string {
  const { content, payloadDirectory, temporaryPath } = parameters
  const staged = shellQuote(temporaryPath)
  const payload = shellQuote(authorizedKeysStagingPayloadPath(payloadDirectory))
  return `set -e
umask 077
[ ! -L ${payload} ] && [ -f ${payload} ] || { echo 'authorized_keys staging payload must be a regular file' >&2; exit 1; }
${authorizedKeysStagedFileGuard(temporaryPath)}
rm -f -- ${staged}
dd if=${payload} iflag=nofollow status=none | base64 -d | dd of=${staged} oflag=nofollow conv=excl status=none
rm -f -- ${payload}
staged_hash=$(${noFollowReadWithStatus(staged)} | sha256sum | cut -d' ' -f1)
[ "$staged_hash" = ${shellQuote(checkedContentDigest(content))} ] || { echo 'authorized_keys staging file does not match the computed content' >&2; exit 1; }
${authorizedKeysStagedFileModeGuard(temporaryPath)}`
}

/**
 * Allocate the private payload directory. `mktemp -d` creates it with mode
 * 0700 for the uid that runs the command, so with a privileged connection no
 * other user can enter, swap or link anything inside it; `/tmp` is sticky,
 * so the directory itself cannot be renamed by another user either.
 *
 * @param conn - The active SSH connection.
 * @returns The validated directory, or a failure description.
 */
async function createPayloadDirectory(
  conn: SshConnection
): Promise<{ directory: string } | { message: string; result?: ExecResult }> {
  const created = await conn.exec(
    `mktemp -d -p /tmp -- ${shellQuote(PAYLOAD_DIRECTORY_TEMPLATE)}`,
    READ_EXEC_OPTS
  )
  if (created.code !== 0) {
    return { message: "failed to create the authorized_keys payload directory", result: created }
  }
  try {
    return {
      directory: validateMktempPath("/tmp", created.stdout.trim(), PAYLOAD_DIRECTORY_PREFIX),
    }
  } catch (error) {
    return { message: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * Transfer the base64 payload into the payload directory and decode it into
 * the staging file.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Paths and content.
 * @param parameters.content - The new content as Latin-1 string.
 * @param parameters.payloadDirectory - The validated private payload directory.
 * @param parameters.temporaryPath - The validated staging path inside the canonical `~/.ssh`.
 * @returns `null` on success, otherwise a failure description or the failed decode result.
 */
async function stageThroughPayloadDirectory(
  conn: SshConnection,
  parameters: { content: string; payloadDirectory: string; temporaryPath: string }
): Promise<{ message: string; result?: ExecResult } | null> {
  const { content, payloadDirectory, temporaryPath } = parameters
  const payload = Buffer.from(content, "latin1").toString("base64")
  try {
    await conn.writeFile(authorizedKeysStagingPayloadPath(payloadDirectory), payload, {
      mode: STAGING_FILE_MODE,
    })
  } catch (error) {
    return {
      message: `failed to stage authorized_keys rewrite: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
  const decode = await conn.exec(
    authorizedKeysStageDecodeCommand({ content, payloadDirectory, temporaryPath }),
    READ_EXEC_OPTS
  )
  if (decode.code !== 0) {
    return { message: "failed to stage authorized_keys rewrite", result: decode }
  }
  return null
}

/**
 * Write the computed content into the mktemp staging file. The base64 text of
 * the exact bytes goes through the connection's SFTP `writeFile` into the
 * private payload directory and is decoded on the host, so the content never
 * appears on a remote command line (sudo logs, process listings), the write
 * needs no stdin (it works with a sudo password), and bytes that are not
 * valid UTF-8 survive unchanged. The payload directory is removed on every
 * path.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Staging path and content.
 * @param parameters.content - The new content as Latin-1 string.
 * @param parameters.temporaryPath - The validated staging path inside the canonical `~/.ssh`.
 * @returns `null` on success, otherwise a failure description or the failed decode result.
 */
export async function writeAuthorizedKeysStagingFile(
  conn: SshConnection,
  parameters: { content: string; temporaryPath: string }
): Promise<{ message: string; result?: ExecResult } | null> {
  const { content, temporaryPath } = parameters
  const created = await createPayloadDirectory(conn)
  if (!("directory" in created)) return created
  const payloadDirectory = created.directory
  try {
    return await stageThroughPayloadDirectory(conn, { content, payloadDirectory, temporaryPath })
  } finally {
    // R-0000565: `--` so the directory cannot be parsed as an `rm` option.
    await conn.exec(`rm -rf -- ${shellQuote(payloadDirectory)}`, READ_EXEC_OPTS)
  }
}

/**
 * Shell lines for the final replace script that confirm the live file still
 * holds the content the rewrite was computed from. They run in the same
 * script directly before the backup link and the rename, so a concurrent
 * modification since the read is reported instead of being overwritten.
 *
 * @param parameters - Path and analyzed content.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.original - The analyzed content, or `null` when the file was missing.
 * @returns Shell lines indented for the replace block, without a trailing newline.
 */
export function authorizedKeysUnchangedGuard(parameters: {
  authorizedKeysPath: string
  original: null | string
}): string {
  const { authorizedKeysPath, original } = parameters
  const keys = shellQuote(authorizedKeysPath)
  if (original === null) {
    return `  [ ! -e ${keys} ] && [ ! -L ${keys} ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }`
  }
  return `  [ -f ${keys} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  current_authorized_keys_hash=$(${noFollowReadWithStatus(keys)} | sha256sum | cut -d' ' -f1) || exit $?
  [ "$current_authorized_keys_hash" = ${shellQuote(checkedContentDigest(original))} ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }`
}

/**
 * Shell lines for the final replace script that confirm, after the rename,
 * that the live file holds exactly the computed content. The expected value
 * is the digest of the content itself (the one the decode already verified),
 * embedded as a literal, not a hash of whatever is at the staging name, and
 * the live file is read with `O_NOFOLLOW`. Only the digest reaches the
 * command line, never the content. A mismatch removes the backup link and
 * fails the replace.
 *
 * @param parameters - Paths and the computed content.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.backupPath - Absolute path of the hardlink backup.
 * @param parameters.content - The computed content as Latin-1 string.
 * @returns Shell lines indented for the replace block, without a trailing newline.
 */
export function authorizedKeysReplacedContentGuard(parameters: {
  authorizedKeysPath: string
  backupPath: string
  content: string
}): string {
  const { authorizedKeysPath, backupPath, content } = parameters
  const keys = shellQuote(authorizedKeysPath)
  const backup = shellQuote(backupPath)
  return `  authorized_keys_hash=$(${noFollowReadWithStatus(keys)} | sha256sum | cut -d' ' -f1) || { rm -f -- ${backup}; exit 1; }
  [ "$authorized_keys_hash" = ${shellQuote(checkedContentDigest(content))} ] || { rm -f -- ${backup}; echo 'authorized_keys content changed during replace' >&2; exit 1; }`
}
