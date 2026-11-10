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
 * privileged connection user can enter, never into `~/.ssh`. Root decodes it
 * and pipes the bytes into a script that runs as the target user (see
 * `sshAuthorizedKeysAccount.ts`), enters the verified `~/.ssh` and writes
 * the staged file through a relative name. Reads run the same way, so root
 * never opens a name inside `~/.ssh`. The staged file itself has to stay in
 * `~/.ssh` (same filesystem, so the final rename is atomic); every step on it
 * first checks that it is still a regular, single-link file owned by the
 * target user and never follows a symlink.
 */
import { createHash } from "node:crypto"

import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote, validateMktempPath } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import {
  asAuthorizedKeysUser,
  asAuthorizedKeysUserReadingPipe,
  AUTHORIZED_KEYS_OWNER_REFUSAL,
  type AuthorizedKeysAccount,
  enterSshDirectoryLines,
  enterVerifiedSshDirectoryLines,
  rootInspectSshDirectoryLines,
  SSH_DIRECTORY_OWNER_REFUSAL,
  SSH_DIRECTORY_SYMLINK_REFUSAL,
} from "./sshAuthorizedKeysAccount.js"
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
const READ_FAILURE = "failed to read authorized_keys without following symlinks"
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
  return `{ if command -p dd if=${quotedPath} iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; }`
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

// Relative name of the managed file inside the verified `~/.ssh`.
const KEYS = "./authorized_keys"

/**
 * Lines that print `missing`, or `present` plus the base64 content of
 * `./authorized_keys` in the current directory. They refuse a symlinked or
 * non-regular `authorized_keys` and read the relative name with `O_NOFOLLOW`.
 */
const READ_KEYS_LINES = `[ ! -L ${KEYS} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
if [ -e ${KEYS} ]; then
  [ -f ${KEYS} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  printf 'present\\n'
  ${noFollowReadWithStatus(KEYS)} | command -p base64 -w 0
else
  printf 'missing\\n'
fi`

/**
 * User-side read script. `$1` is the canonical `~/.ssh`, `$2` the target
 * uid. It enters the directory again by its physical path (so a swap at any
 * moment is caught), refuses a `~/.ssh` the target user does not own and an
 * `authorized_keys` owned by someone else (for example root after
 * `sudo tee -a`), which the user could neither verify nor back up during the
 * replace, and reads only the relative name. It runs as the target user, so
 * even a hard link to a foreign file only reads what that user may read.
 */
const READ_SCRIPT = `set -e
${enterSshDirectoryLines()}
[ "$(stat -c '%u' .)" = "$2" ] || { echo '${SSH_DIRECTORY_OWNER_REFUSAL}' >&2; exit 1; }
if [ -f ${KEYS} ] && [ ! -L ${KEYS} ]; then
  [ "$(stat -c '%u' ${KEYS})" = "$2" ] || { echo '${AUTHORIZED_KEYS_OWNER_REFUSAL}' >&2; exit 1; }
fi
${READ_KEYS_LINES}`

/**
 * Build the read-only command used by check, dry-run and apply. Root tests
 * whether `~/.ssh` exists, enters and classifies it (see
 * `rootInspectSshDirectoryLines`) and then reads in one of two ways:
 *
 * - a `~/.ssh` that root owns, that nobody else may write and that holds only
 *   ssh files (for example one an earlier root bootstrap created with mode
 *   0700) is read by root in the verified working directory: its entries are
 *   not user-controlled, and the target user may not even be able to enter
 *   it; any other root-owned `~/.ssh` is refused;
 * - a `~/.ssh` of the target user is read by {@link READ_SCRIPT} as that user.
 *
 * A missing directory reads as `missing`; a symlinked one is refused.
 *
 * @param account - The resolved target account with an existing home.
 * @param account.expectedSshDirectory - The canonical `~/.ssh`.
 * @returns A command printing `missing` or `present` plus base64 content.
 */
export function authorizedKeysReadCommand(
  account: { expectedSshDirectory: string } & AuthorizedKeysAccount
): string {
  const { expectedSshDirectory } = account
  const expected = shellQuote(expectedSshDirectory)
  return `set -e
exec </dev/null
cd /
if [ ! -e ${expected} ] && [ ! -L ${expected} ]; then
  printf 'missing\\n'
  exit 0
fi
[ ! -L ${expected} ] || { echo '${SSH_DIRECTORY_SYMLINK_REFUSAL}' >&2; exit 1; }
${rootInspectSshDirectoryLines(account, expectedSshDirectory)}
if [ "$ssh_directory_owner" != ${shellQuote(account.uid)} ]; then
${READ_KEYS_LINES}
else
  cd /
  ${asAuthorizedKeysUser(account, READ_SCRIPT, [expectedSshDirectory, account.uid])}
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
 * Read `authorized_keys` as the target user without following symlinks. A
 * missing home directory reads as a missing file.
 *
 * @param conn - The active SSH connection.
 * @param account - The resolved target account.
 * @returns The content, or a failed result whose stdout is redacted.
 */
export async function readAuthorizedKeys(
  conn: SshConnection,
  account: AuthorizedKeysAccount
): Promise<AuthorizedKeysRead> {
  const { expectedSshDirectory } = account
  if (expectedSshDirectory === null) return { content: null, kind: "read" }
  const result = await conn.exec(
    authorizedKeysReadCommand({ ...account, expectedSshDirectory }),
    READ_EXEC_OPTS
  )
  if (result.code !== 0) return { kind: "failed", result: { ...result, stdout: "" } }
  const parsed = parseReadOutput(result.stdout)
  if (parsed === null) {
    // The trailing status reports a failed `dd`; its stderr (for example a
    // permission error) names the cause and never contains file content.
    const detail = result.stderr.trim()
    return {
      kind: "failed",
      result: {
        code: 1,
        stderr: [READ_FAILURE, detail].filter((line) => line.length > 0).join("\n"),
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

// Shell word that names the staged file inside the verified `~/.ssh`; the
// scripts set `staged=./$3` from the validated mktemp name.
const STAGED = '"$staged"'

/**
 * Shell statement that aborts unless the staged file in `~/.ssh` is still the
 * file the target user's `mktemp` created: not a symlink, a regular file, one
 * hard link and owned by the uid that runs the script. The scripts already
 * run as the target user, so a swapped entry cannot gain anything beyond that
 * user's own rights; the guard still refuses a symlink, or (with
 * `fs.protected_hardlinks=0`) a hard link to a file such as `/etc/shadow`,
 * swapped in between two remote commands, so the replace never publishes
 * foreign content. `stat` without `-L` reports the entry itself, and a hard
 * link always raises the link count above one.
 *
 * @returns A single shell statement without a trailing newline.
 */
export function authorizedKeysStagedFileGuard(): string {
  return `[ ! -L ${STAGED} ] && [ -f ${STAGED} ] && [ "$(stat -c '%u %h' -- ${STAGED})" = "$(id -u) 1" ] || { echo '${STAGED_FILE_REFUSAL}' >&2; exit 1; }`
}

/**
 * Shell statement that aborts unless the staged file has mode 600. The decode
 * creates it under `umask 077`, but a default ACL on `~/.ssh` overrides the
 * umask, so the new inode can come out as 0640 or 0660. The mode has to be
 * right before the final replace publishes the file: the replace only checks
 * the live file after `mv -T`, when the backup is already gone. Run it only
 * after {@link authorizedKeysStagedFileGuard}, so `stat` without `-L` reports
 * the regular file itself and not a symlink.
 *
 * @returns A single shell statement without a trailing newline.
 */
export function authorizedKeysStagedFileModeGuard(): string {
  return `[ "$(stat -c '%a' -- ${STAGED})" = ${STAGED_FILE_OCTAL_MODE} ] || { echo '${STAGED_FILE_MODE_REFUSAL}' >&2; exit 1; }`
}

/**
 * User-side stage script. `$1`/`$2` are the canonical `~/.ssh` and its
 * identity, `$3` the validated staging name and `$4` the expected digest; the
 * decoded bytes arrive on stdin. After the ownership and link guard the
 * reserved entry is removed and recreated by `dd` with `conv=excl`
 * (`O_CREAT | O_EXCL`) and `oflag=nofollow` under `umask 077`: the write can
 * only create a new 0600 inode and never opens a symlink or a hard link put
 * in place after the guard. A name claimed in that window makes `dd` fail
 * instead. A truncated or corrupt stdin fails the digest comparison. The last
 * statement confirms mode 600, because a default ACL on `~/.ssh` overrides
 * the umask.
 */
const STAGE_SCRIPT = `set -e
umask 077
${enterVerifiedSshDirectoryLines()}
staged=./$3
${authorizedKeysStagedFileGuard()}
rm -f -- ${STAGED}
dd of=${STAGED} oflag=nofollow conv=excl status=none
staged_hash=$(${noFollowReadWithStatus(STAGED)} | sha256sum | cut -d' ' -f1)
[ "$staged_hash" = "$4" ] || { echo 'authorized_keys staging file does not match the computed content' >&2; exit 1; }
${authorizedKeysStagedFileModeGuard()}`

/**
 * Build the command that decodes the transferred base64 payload as root, out
 * of the private payload directory, and pipes the bytes into the
 * {@link STAGE_SCRIPT} running as the target user. Content never appears on a
 * command line; only the digest does.
 *
 * @param parameters - Account, identity, staged name, payload and content.
 * @param parameters.account - The resolved target account.
 * @param parameters.content - The staged content as Latin-1 string.
 * @param parameters.expectedSshDirectory - The canonical `~/.ssh`.
 * @param parameters.identity - The `device:inode owner` identity of `~/.ssh`.
 * @param parameters.payloadDirectory - The validated private payload directory.
 * @param parameters.stagedName - The validated staging name inside `~/.ssh`.
 * @returns The decode and verification command.
 */
export function authorizedKeysStageDecodeCommand(parameters: {
  account: AuthorizedKeysAccount
  content: string
  expectedSshDirectory: string
  identity: string
  payloadDirectory: string
  stagedName: string
}): string {
  const { account, content, expectedSshDirectory, identity, payloadDirectory, stagedName } =
    parameters
  const payload = shellQuote(authorizedKeysStagingPayloadPath(payloadDirectory))
  const stage = asAuthorizedKeysUserReadingPipe(account, STAGE_SCRIPT, [
    expectedSshDirectory,
    identity,
    stagedName,
    checkedContentDigest(content),
  ])
  // Root's own stdin is replaced first, so the pipe into the stage script
  // carries the decoded payload and nothing else.
  return `set -e
exec </dev/null
cd /
[ ! -L ${payload} ] && [ -f ${payload} ] || { echo 'authorized_keys staging payload must be a regular file' >&2; exit 1; }
command -p base64 -d < ${payload} | { ${stage}; }`
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

type StagingTarget = {
  account: AuthorizedKeysAccount
  content: string
  expectedSshDirectory: string
  identity: string
  stagedName: string
}

/**
 * Transfer the base64 payload into the payload directory and decode it into
 * the staging file.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Staging target and the payload directory.
 * @returns `null` on success, otherwise a failure description or the failed decode result.
 */
async function stageThroughPayloadDirectory(
  conn: SshConnection,
  parameters: { payloadDirectory: string } & StagingTarget
): Promise<{ message: string; result?: ExecResult } | null> {
  const { content, payloadDirectory } = parameters
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
  const decode = await conn.exec(authorizedKeysStageDecodeCommand(parameters), READ_EXEC_OPTS)
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
 * needs no stdin from the controller (it works with a sudo password), and
 * bytes that are not valid UTF-8 survive unchanged. The payload directory is
 * removed by root on every path.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Account, verified `~/.ssh`, staging name and content.
 * @param parameters.account - The resolved target account.
 * @param parameters.content - The new content as Latin-1 string.
 * @param parameters.expectedSshDirectory - The canonical `~/.ssh`.
 * @param parameters.identity - The `device:inode owner` identity of `~/.ssh`.
 * @param parameters.stagedName - The validated staging name inside `~/.ssh`.
 * @returns `null` on success, otherwise a failure description or the failed decode result.
 */
export async function writeAuthorizedKeysStagingFile(
  conn: SshConnection,
  parameters: StagingTarget
): Promise<{ message: string; result?: ExecResult } | null> {
  const created = await createPayloadDirectory(conn)
  if (!("directory" in created)) return created
  const payloadDirectory = created.directory
  try {
    return await stageThroughPayloadDirectory(conn, { ...parameters, payloadDirectory })
  } finally {
    // R-0000565: `--` so the directory cannot be parsed as an `rm` option.
    await conn.exec(`rm -rf -- ${shellQuote(payloadDirectory)}`, READ_EXEC_OPTS)
  }
}

/**
 * Value of the replace script's original-digest argument when the file was
 * missing at the read; a hex digest never equals it.
 */
export const AUTHORIZED_KEYS_MISSING_ORIGINAL = "missing"

/**
 * Digest argument for the replace script's unchanged check.
 *
 * @param original - The analyzed content, or `null` when the file was missing.
 * @returns The digest of `original`, or {@link AUTHORIZED_KEYS_MISSING_ORIGINAL}.
 */
export function authorizedKeysOriginalDigest(original: null | string): string {
  return original === null ? AUTHORIZED_KEYS_MISSING_ORIGINAL : checkedContentDigest(original)
}

/**
 * Digest argument for the replace script's post-replace check.
 *
 * @param content - The computed content as Latin-1 string.
 * @returns The digest of `content` plus the read status suffix.
 */
export function authorizedKeysContentDigest(content: string): string {
  return checkedContentDigest(content)
}

/**
 * Shell lines for the final replace script that confirm the live file still
 * holds the content the rewrite was computed from: `$4` is its digest, or
 * {@link AUTHORIZED_KEYS_MISSING_ORIGINAL} when the file was missing. They
 * run in the same script directly before the backup link and the rename, so
 * a concurrent modification since the read is reported instead of being
 * overwritten.
 *
 * @returns Shell lines without a trailing newline.
 */
export function authorizedKeysUnchangedGuard(): string {
  return `if [ "$4" = ${AUTHORIZED_KEYS_MISSING_ORIGINAL} ]; then
  [ ! -e ${KEYS} ] && [ ! -L ${KEYS} ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }
else
  [ -f ${KEYS} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  current_authorized_keys_hash=$(${noFollowReadWithStatus(KEYS)} | sha256sum | cut -d' ' -f1) || exit $?
  [ "$current_authorized_keys_hash" = "$4" ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }
fi`
}

/**
 * Shell lines for the final replace script that confirm, after the rename,
 * that the live file holds exactly the computed content. `$5` is the digest
 * of the content itself (the one the decode already verified), passed as a
 * literal, not a hash of whatever is at the staging name, and the live file
 * is read with `O_NOFOLLOW`. Only the digest reaches the command line, never
 * the content. A mismatch removes the backup link and fails the replace.
 *
 * @param backup - Shell word naming the hardlink backup.
 * @returns Shell lines without a trailing newline.
 */
export function authorizedKeysReplacedContentGuard(backup: string): string {
  return `authorized_keys_hash=$(${noFollowReadWithStatus(KEYS)} | sha256sum | cut -d' ' -f1) || { rm -f -- ${backup}; exit 1; }
[ "$authorized_keys_hash" = "$5" ] || { rm -f -- ${backup}; echo 'authorized_keys content changed during replace' >&2; exit 1; }`
}
