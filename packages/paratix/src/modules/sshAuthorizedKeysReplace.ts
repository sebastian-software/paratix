/**
 * Prepare, staging-name, replace and cleanup steps of the `ssh.authorizedKeys`
 * rewrite. Every step enters the canonical `~/.ssh` with `cd -P`, verifies
 * its physical path and, after the prepare step, its `device:inode owner`
 * identity, and then works only with relative names (see
 * `sshAuthorizedKeysAccount.ts`). All steps run as the target user, except
 * the root repair of a root-owned `~/.ssh` in the prepare step.
 */
import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import {
  asAuthorizedKeysUser,
  type AuthorizedKeysAccount,
  authorizedKeysUserCommand,
  enterSshDirectoryLines,
  enterVerifiedSshDirectoryLines,
  HOME_DIRECTORY_ENTER_REFUSAL,
  parseSshDirectoryIdentity,
  rootInspectSshDirectoryLines,
  SSH_DIRECTORY_OWNER_REFUSAL,
} from "./sshAuthorizedKeysAccount.js"
import {
  authorizedKeysContentDigest,
  authorizedKeysOriginalDigest,
  authorizedKeysReplacedContentGuard,
  authorizedKeysStagedFileGuard,
  authorizedKeysStagedFileModeGuard,
  authorizedKeysUnchangedGuard,
} from "./sshAuthorizedKeysFile.js"

const MUTATION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000181: prefix used by `mktemp` for the in-flight authorized_keys
// rewrite. The leading dot keeps the temp file hidden from typical glob
// expansions. `mktemp` runs inside the verified `~/.ssh` and prints a
// relative name, which must match the prefix plus the random suffix exactly.
const AUTHORIZED_KEYS_TEMPORARY_PREFIX = ".paratix-authorized-keys"
const STAGED_NAME_PATTERN = /^\.paratix-authorized-keys\.[A-Za-z0-9]+$/v
const BACKUP = "./authorized_keys.paratix-backup"
const SSH_DIRECTORY_SUFFIX = "/.ssh"

/** A verified `~/.ssh`: the canonical path and the identity captured by the prepare step. */
export type VerifiedSshDirectory = {
  account: AuthorizedKeysAccount
  expectedSshDirectory: string
  identity: string
}

/**
 * User-side prepare script. `$1` is the canonical `~/.ssh`, `$2`/`$3` the
 * numeric uid and gid. A missing `~/.ssh` is created by the target user with
 * mode 0700, so nothing is ever created through a name in the user-owned
 * home by root; an existing entry, even a symlink, is left alone and the
 * checks that follow refuse anything that is not the real directory. After
 * `cd -P` and the `pwd -P` check, the script confirms the owner and resets
 * mode and group with `chmod 700 .` and `chown -h uid:gid .`, which act on the
 * verified working directory itself, never on a name that can be swapped.
 * `pwd -P` is checked again afterwards, so a rename during the update is
 * reported, and the script prints the `device:inode owner` identity that
 * every later step compares against (R-0000887 compared only device and
 * inode around a root-side `chmod`/`chown` of the path itself).
 */
const PREPARE_SCRIPT = `set -e
[ -e "$1" ] || [ -L "$1" ] || mkdir -m 700 -- "$1"
${enterSshDirectoryLines()}
[ "$(stat -c '%u' .)" = "$2" ] || { echo '${SSH_DIRECTORY_OWNER_REFUSAL}' >&2; exit 1; }
chmod 700 .
chown -h -- "$2:$3" .
[ "$(pwd -P)" = "$1" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
stat -c '%d:%i %u' .`

/**
 * User-side probe that the target user can enter its canonical home, run
 * before root changes anything, so a home the user cannot search (for
 * example on NFS with `root_squash`) fails with its own message.
 */
const HOME_PROBE_SCRIPT = `cd -P -- "$1" || { echo '${HOME_DIRECTORY_ENTER_REFUSAL}' >&2; exit 1; }`

/**
 * Build the prepare command. First the target user proves it can enter the
 * home. An existing `~/.ssh` that the target user does not own (typically
 * one an earlier root or sudo bootstrap created) is then repaired by root:
 * root enters and classifies it (see `rootInspectSshDirectoryLines`), so
 * only a root-owned directory that nobody else may write and that holds only
 * ssh files gets this far, then runs `chmod 700 .` and `chown -h uid:gid .`
 * on the verified working directory, never on a name, and re-checks path and
 * owner.
 *
 * While that directory is still root-owned and writable by nobody else, its
 * entries are root-controlled, so root first hands its root-owned,
 * single-link regular `authorized_keys` (checked by the inspection) to the
 * target user (0600); otherwise the user could neither read it for the
 * unchanged check nor hard-link it as the backup. Root touches no other
 * entry. The {@link PREPARE_SCRIPT} then runs as the target user as for any
 * other directory.
 *
 * @param parameters - Account and canonical `~/.ssh`.
 * @param parameters.account - The resolved target account.
 * @param parameters.expectedSshDirectory - The canonical `~/.ssh`.
 * @returns A command that prints the directory identity.
 */
export function authorizedKeysPrepareCommand(parameters: {
  account: AuthorizedKeysAccount
  expectedSshDirectory: string
}): string {
  const { account, expectedSshDirectory } = parameters
  const expected = shellQuote(expectedSshDirectory)
  const uid = shellQuote(account.uid)
  const owner = shellQuote(`${account.uid}:${account.gid}`)
  const home = expectedSshDirectory.slice(0, -SSH_DIRECTORY_SUFFIX.length)
  return `set -e
exec </dev/null
cd /
${asAuthorizedKeysUser(account, HOME_PROBE_SCRIPT, [home])}
if [ -e ${expected} ] || [ -L ${expected} ]; then
${rootInspectSshDirectoryLines(account, expectedSshDirectory)}
if [ "$ssh_directory_owner" != ${uid} ]; then
if [ ! -L ./authorized_keys ] && [ -f ./authorized_keys ]; then
  command -p chown -h -- ${owner} ./authorized_keys
  command -p chmod 600 ./authorized_keys
fi
command -p chmod 700 . && command -p chown -h -- ${owner} .
[ "$(pwd -P)" = ${expected} ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
[ "$(command -p stat -c '%u' .)" = ${uid} ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
fi
cd /
fi
${asAuthorizedKeysUser(account, PREPARE_SCRIPT, [expectedSshDirectory, account.uid, account.gid])}`
}

/**
 * Prepare `~/.ssh` and capture its identity.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Account and canonical `~/.ssh`.
 * @param parameters.account - The resolved target account.
 * @param parameters.expectedSshDirectory - The canonical `~/.ssh`.
 * @returns The verified directory, or a failure description.
 */
export async function prepareAuthorizedKeysDirectory(
  conn: SshConnection,
  parameters: { account: AuthorizedKeysAccount; expectedSshDirectory: string }
): Promise<{ message: string; result?: ExecResult } | { verified: VerifiedSshDirectory }> {
  const result = await conn.exec(authorizedKeysPrepareCommand(parameters), MUTATION_EXEC_OPTS)
  if (result.code !== 0) return { message: "failed to prepare .ssh directory", result }
  const identity = parseSshDirectoryIdentity(result.stdout, parameters.account.uid)
  if (identity === null) return { message: "failed to verify the prepared .ssh directory" }
  return { verified: { ...parameters, identity } }
}

/**
 * User-side `mktemp` inside the verified `~/.ssh`. R-0000565: the template
 * follows `--`, so it can never be parsed as an option.
 */
const MKTEMP_TEMPLATE = shellQuote(`${AUTHORIZED_KEYS_TEMPORARY_PREFIX}.XXXXXX`)
const MKTEMP_SCRIPT = `set -e
${enterVerifiedSshDirectoryLines()}
mktemp -- ${MKTEMP_TEMPLATE}`

/**
 * Build the command that reserves the staging name.
 *
 * @param verified - The verified `~/.ssh`.
 * @returns A command that prints the relative name of a new 0600 file of the target user.
 */
export function authorizedKeysMktempCommand(verified: VerifiedSshDirectory): string {
  return authorizedKeysUserCommand(verified.account, MKTEMP_SCRIPT, [
    verified.expectedSshDirectory,
    verified.identity,
  ])
}

/**
 * R-0000181: allocate the temporary file for the authorized_keys rewrite
 * inside the user's `~/.ssh` directory, on the same filesystem as the
 * destination. The earlier `/run/paratix` (tmpfs) location forced `mv -T`
 * into a cross-filesystem copy+unlink, breaking atomicity; on NFS with
 * `root_squash` it could even fail outright.
 *
 * The target user's `mktemp` creates the file as a 0600 file of that user
 * and prints its relative name; any other output is rejected.
 *
 * @param conn - The active SSH connection.
 * @param verified - The verified `~/.ssh`.
 * @returns The validated relative staging name.
 */
export async function createAuthorizedKeysStagingName(
  conn: SshConnection,
  verified: VerifiedSshDirectory
): Promise<{ message: string; result?: ExecResult } | { stagedName: string }> {
  const result = await conn.exec(authorizedKeysMktempCommand(verified), MUTATION_EXEC_OPTS)
  if (result.code !== 0) return { message: "failed to create the staging file", result }
  const stagedName = result.stdout.endsWith("\n") ? result.stdout.slice(0, -1) : result.stdout
  if (!STAGED_NAME_PATTERN.test(stagedName)) {
    return { message: `Unexpected mktemp output: ${stagedName}` }
  }
  return { stagedName }
}

// R-0000285: harden the final rename against a symlink race. The plain
// `mv -T` previously overwrote the target unconditionally; an attacker who
// could win the race between the `[ ! -L ]` probe and the move could
// redirect the write through a malicious symlink. We now (1) reject
// symlinks up front, (2) keep a hardlink backup of the existing regular
// file in the same directory so the original `authorized_keys` content is
// recoverable even if the rename fails, and (3) run `mv -T --` so the
// rename(2) call atomically replaces the destination (regular file) in a
// single step instead of going through a `rm + mv` window during which the
// user has no authorized_keys at all. The combined `--` end-of-options
// markers guard against pathological names beginning with `-`.
//
// R-0000610: the previous `rm -f -- $auth_keys; mv -T -n -- $tmp
// $auth_keys` sequence could leave the user without any authorized_keys
// (and thus locked out) when `rm` succeeded but the subsequent `mv -T -n`
// failed — e.g. because the destination reappeared as a symlink in the
// race window, or because the rename hit ENOSPC/ENOMEM. We now keep a
// hardlink under `<authorized_keys>.paratix-backup` for the duration of
// the rename. If `mv` fails, we restore the backup back to
// `authorized_keys` via a second atomic rename; if it succeeds, we delete
// the backup at the end of the shell block. The hardlink lives on the
// same filesystem and the same directory as the destination, so both
// renames remain atomic.
//
// R-0000622: the hardlink backup uses `ln -P --` (no-deref) so a
// last-instant symlink race between the `[ ! -L ]` probe and the `ln`
// cannot turn the backup into a hardlink that points at an
// attacker-controlled target outside `~/.ssh`. Plain `ln` (without `-P`)
// would follow a symbolic link at the source side and create a hardlink
// to its resolution. As a defence-in-depth, the `[ ! -L ]` guard is
// repeated immediately before the `ln` call so the race window between the
// earlier guard and the link operation is collapsed to a single shell
// statement.
//
// The whole script runs as the target user inside the verified `~/.ssh` and
// addresses every file by a relative name, so neither a rename of `~/.ssh`
// nor a link inside it can make the replace touch anything outside the
// user's own rights. `$1`/`$2` are the canonical `~/.ssh` and its identity,
// `$3` the staging name, `$4` the digest of the read content (or `missing`),
// `$5` the digest of the computed content, and `$6`/`$7` the expected
// `stat -c '%a %U %G %F'` of the directory and of the published file.
//
// The staged file was created by the user's `mktemp` and `dd` under
// `umask 077`, so it already is a 0600 file of the user and the user's
// primary group; no `chmod` or `chown` on it is needed. The script first
// re-checks that it is still a regular, single-link file owned by the user,
// and a default ACL on `~/.ssh` overrides the umask, so it confirms mode 600
// right after that guard: a wrong mode fails before anything is published,
// instead of after `mv -T` when the backup is already removed.
//
// The check that the live file still holds the content the rewrite was
// computed from runs in this same script, directly before the backup link
// and the rename, so the window for an unnoticed concurrent edit is as small
// as the shell allows. The post-replace check compares the live file, read
// with `O_NOFOLLOW`, with the literal digest of the computed content, which
// the decode already verified against the staged bytes; it is not a
// `sha256sum` of the staging name, and only the digest reaches the command
// line.
const REPLACE_SCRIPT = `${enterVerifiedSshDirectoryLines()}
staged=./$3
${authorizedKeysStagedFileGuard()}
${authorizedKeysStagedFileModeGuard()}
ssh_directory_state=$(stat -c '%a %U %G %F' .) || exit $?
[ "$ssh_directory_state" = "$6" ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }
[ ! -L ./authorized_keys ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
rm -f -- ${BACKUP}
backup_created=0
${authorizedKeysUnchangedGuard()}
if [ -e ./authorized_keys ]; then
  [ -f ./authorized_keys ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  [ ! -L ./authorized_keys ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  ln -P -- ./authorized_keys ${BACKUP} || { echo 'failed to create authorized_keys backup hardlink' >&2; exit 1; }
  backup_created=1
fi
[ ! -L ./authorized_keys ] || { rm -f -- ${BACKUP}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
if ! mv -T -- "$staged" ./authorized_keys; then
  if [ "$backup_created" = 1 ]; then
    mv -T -- ${BACKUP} ./authorized_keys || echo "authorized_keys backup restore failed; backup is at $1/authorized_keys.paratix-backup" >&2
  fi
  echo 'authorized_keys replace failed' >&2
  exit 1
fi
[ ! -e "$staged" ] || { rm -f -- ${BACKUP}; echo 'authorized_keys replace did not consume temporary file' >&2; exit 1; }
[ ! -L ./authorized_keys ] || { rm -f -- ${BACKUP}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
[ -f ./authorized_keys ] || { rm -f -- ${BACKUP}; echo 'authorized_keys must be a regular file' >&2; exit 1; }
authorized_keys_state=$(stat -c '%a %U %G %F' ./authorized_keys) || { rm -f -- ${BACKUP}; exit 1; }
[ "$authorized_keys_state" = "$7" ] || { rm -f -- ${BACKUP}; echo 'authorized_keys metadata changed during replace' >&2; exit 1; }
${authorizedKeysReplacedContentGuard(BACKUP)}
rm -f -- ${BACKUP}`

/**
 * Build the final replace command.
 *
 * @param parameters - Verified directory, staging name, contents and owner.
 * @param parameters.content - The computed content as Latin-1 string.
 * @param parameters.original - The read content, or `null` when the file was missing.
 * @param parameters.primaryGroup - The user's primary group name.
 * @param parameters.stagedName - The validated staging name.
 * @param parameters.verified - The verified `~/.ssh`.
 * @returns A command that publishes the staged file as the target user.
 */
export function authorizedKeysReplaceCommand(parameters: {
  content: string
  original: null | string
  primaryGroup: string
  stagedName: string
  verified: VerifiedSshDirectory
}): string {
  const { content, original, primaryGroup, stagedName, verified } = parameters
  // R-0000065: compare against the user and the user's resolved primary
  // group instead of `${user}:${user}`, so hosts where the primary group is
  // not equal to the username (e.g. `deploy:users`, `www-data:www-data`) do
  // not end in a drift loop.
  const { user } = verified.account
  return authorizedKeysUserCommand(verified.account, REPLACE_SCRIPT, [
    verified.expectedSshDirectory,
    verified.identity,
    stagedName,
    authorizedKeysOriginalDigest(original),
    authorizedKeysContentDigest(content),
    `700 ${user} ${primaryGroup} directory`,
    `600 ${user} ${primaryGroup} regular file`,
  ])
}

/**
 * User-side cleanup of the staging name inside the verified `~/.ssh`. When
 * `~/.ssh` no longer verifies, nothing is removed: root never deletes a name
 * in a directory it cannot vouch for. The hardlink backup is not removed
 * here; the replace removes it on every path except a failed restore, where
 * it holds the only copy of the previous file.
 */
const CLEANUP_SCRIPT = `${enterVerifiedSshDirectoryLines()}
rm -f -- "./$3"`

/**
 * Build the cleanup command for the staging name.
 *
 * @param verified - The verified `~/.ssh`.
 * @param stagedName - The validated staging name.
 * @returns A command that removes the staging name as the target user.
 */
export function authorizedKeysCleanupCommand(
  verified: VerifiedSshDirectory,
  stagedName: string
): string {
  return authorizedKeysUserCommand(verified.account, CLEANUP_SCRIPT, [
    verified.expectedSshDirectory,
    verified.identity,
    stagedName,
  ])
}
