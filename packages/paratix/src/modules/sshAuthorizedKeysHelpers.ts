/* eslint-disable max-lines -- authorized_keys flow keeps related apply, check, and rewrite helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  type AuthorizedKeysContentPlan,
  type AuthorizedKeysTarget,
  planAuthorizedKeysContent,
} from "./sshAuthorizedKeysContent.js"
import {
  authorizedKeysReplacedContentGuard,
  authorizedKeysStagedFileGuard,
  authorizedKeysStagedFileModeGuard,
  authorizedKeysUnchangedGuard,
  readAuthorizedKeys,
  writeAuthorizedKeysStagingFile,
} from "./sshAuthorizedKeysFile.js"

const MUTATION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000181: prefix used by `mktemp` for the in-flight authorized_keys
// rewrite. The leading dot keeps the temp file hidden from typical
// glob expansions; the validateMktempPath check rejects any output that
// does not start with `<home>/.ssh/.paratix-authorized-keys.`.
const AUTHORIZED_KEYS_TEMPORARY_PREFIX = ".paratix-authorized-keys"
const SSH_DIRECTORY_SUFFIX = "/.ssh"
const AUTHORIZED_KEYS_FILE_NAME = "authorized_keys"

function isSafeAuthorizedKeysHome(home: string): boolean {
  return (
    home.length > 0 &&
    home.startsWith("/") &&
    home !== "/" &&
    !home.includes(":") &&
    !home.includes("\r") &&
    !home.includes("\n")
  )
}

async function resolveHome(conn: SshConnection, user: string): Promise<string> {
  const home = await conn.output(`getent passwd ${shellQuote(user)} | cut -d: -f6`)
  if (!isSafeAuthorizedKeysHome(home)) {
    throw new Error(`[ssh.authorizedKeys: ${user}] failed to resolve a safe home directory`)
  }
  return home
}

/**
 * R-0000065: resolve the user's actual primary group via `id -gn` so the
 * chown calls and the `stat`-based check do not falsely overwrite the group
 * ownership of `~/.ssh` and `~/.ssh/authorized_keys` for users whose
 * primary group is not equal to the username (e.g. `deploy:users`,
 * `www-data:www-data` for nginx, or operator users in `wheel`).
 *
 * Falls back to the username when `id -gn` produces no usable output, which
 * preserves the legacy behaviour for the historically common
 * user-private-group setup.
 *
 * R-0000554: route the lookup through `conn.exec` with `ignoreExitCode` so a
 * non-zero exit from `id -gn` (e.g. when the target user does not exist on
 * the remote host) does not surface as an unstructured exception. The
 * username fallback already mirrors the user-private-group default on Linux
 * and matches the behaviour expected by callers in
 * `ensureAuthorizedKeysOwnership`.
 *
 * @param conn - The active SSH connection.
 * @param user - The target user.
 * @returns The user's primary group name.
 */
async function resolvePrimaryGroup(conn: SshConnection, user: string): Promise<string> {
  const result = await conn.exec(`id -gn ${shellQuote(user)}`, MUTATION_EXEC_OPTS)
  if (result.code !== 0) return user
  const primaryGroup = result.stdout.trim()
  if (primaryGroup.length === 0) return user
  return primaryGroup
}

function isUnsafeAuthorizedKeysHomeError(error: unknown, user: string): error is Error {
  return (
    error instanceof Error &&
    error.message === `[ssh.authorizedKeys: ${user}] failed to resolve a safe home directory`
  )
}

function isAuthorizedKeysMktempValidationError(error: unknown): error is Error {
  return (
    error instanceof Error &&
    (error.message.startsWith("Unexpected mktemp output:") ||
      error.message.startsWith("Unexpected mktemp directory:"))
  )
}

async function resolveApplyHome(
  conn: SshConnection,
  parameters: {
    state: "absent" | "present"
    user: string
  }
): Promise<{ failure: ModuleResult | null; home: null | string }> {
  const { state, user } = parameters
  try {
    return { failure: null, home: await resolveHome(conn, user) }
  } catch (error) {
    if (isUnsafeAuthorizedKeysHomeError(error, user)) {
      return state === "absent"
        ? { failure: null, home: null }
        : { failure: failed(error.message), home: null }
    }
    throw error
  }
}

/**
 * R-0000181: allocate the temporary file for the authorized_keys rewrite
 * inside the user's `~/.ssh` directory, on the same filesystem as the
 * destination. The earlier `/run/paratix` (tmpfs) location forced `mv -T`
 * into a cross-filesystem copy+unlink, breaking atomicity; on NFS with
 * `root_squash` it could even fail outright.
 *
 * The mktemp template uses the dotfile prefix so the temp file is hidden
 * from typical glob expansions, and `validateMktempPath` rejects any
 * stdout that does not match `<sshDirectory>/.paratix-authorized-keys.*`.
 *
 * @param conn - The active SSH connection.
 * @param sshDirectoryPath - Absolute path of the user's `~/.ssh` directory.
 * @returns The validated temporary file path.
 */
async function createAuthorizedKeysTemporaryPath(
  conn: SshConnection,
  sshDirectoryPath: string
): Promise<string> {
  // R-0000565: pass the staging directory via `-p` and separate the template
  // with `--` so a future refactor that loosens the prefix cannot let an
  // attacker-controlled value be interpreted as a `mktemp` option.
  const template = `${AUTHORIZED_KEYS_TEMPORARY_PREFIX}.XXXXXX`
  const temporaryPath = await conn.output(
    `mktemp -p ${shellQuote(sshDirectoryPath)} -- ${shellQuote(template)}`
  )
  return validateMktempPath(sshDirectoryPath, temporaryPath, AUTHORIZED_KEYS_TEMPORARY_PREFIX)
}

// R-0000244: mutation helpers return a `failedCommand` ModuleResult on
// non-zero exit instead of letting `conn.exec` throw an unstructured
// SSH error. Callers chain on a `null` return value.
//
// R-0000765: fuse the previously separate `.ssh`-directory preparation and
// `authorized_keys` symlink probe into a single `set -e` shell pipeline.
// The two helpers always ran back to back on the apply path, each over its
// own SSH exec round-trip. Combining them halves the round-trip cost,
// keeps the guards adjacent (so a hostile actor cannot race a symlink in
// between them), and lets `set -e` propagate the first failure verbatim
// while we still surface a single structured `failedCommand` to callers.
// The error messages emitted by each `|| { echo …; exit 1; }` clause stay
// byte-for-byte identical so log-pattern asserts in the existing test
// suite (and operator runbooks) continue to match.
/**
 * Validate the canonical `~/.ssh` path printed by the guard script.
 *
 * @param stdout - The guard script output.
 * @returns The canonical path, or `null` when the output is not a safe absolute `.ssh` path.
 */
function parseCanonicalSshDirectory(stdout: string): null | string {
  const canonical = stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout
  const isSafe =
    canonical.startsWith("/") &&
    canonical.endsWith(SSH_DIRECTORY_SUFFIX) &&
    canonical.length > SSH_DIRECTORY_SUFFIX.length &&
    !canonical.includes("\n") &&
    !canonical.includes("\r") &&
    !canonical.includes("\0")
  return isSafe ? canonical : null
}

async function ensureSshDirectoryAndAuthorizedKeysAreNotSymlinks(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<{ canonicalSshDirectoryPath: string; failure: null } | { failure: ModuleResult }> {
  const { authorizedKeysPath, primaryGroup, sshDirectoryPath, state, user } = parameters
  const directory = shellQuote(sshDirectoryPath)
  const keysPath = shellQuote(authorizedKeysPath)
  const quotedUser = shellQuote(user)
  const quotedPrimaryGroup = shellQuote(primaryGroup)

  // The pipeline below keeps the .ssh directory guards and the
  // authorized_keys symlink probe in one `set -e` script so the first failing
  // guard aborts the remainder of the script. R-0000887 also snapshots the
  // prepared directory's device+inode before chmod/chown and verifies it
  // afterwards, so a concurrent swap to another real directory is reported
  // before the authorized_keys rewrite continues.
  // The multi-line form below is byte-for-byte equivalent to the previous
  // single-line pipeline: newlines act as the same command separators that
  // `; ` did, every guard clause stays intact on its own line, and `set -e`
  // still aborts on the first failing statement.
  //
  // After the guards, the script prints the canonical `~/.ssh` path
  // (`realpath -e`). The guards above already reject a symlinked `.ssh`, so
  // the canonical path only differs when a parent component such as `/home`
  // is a symlink (for example `/home -> /data/home`). Staging and the final
  // replace use the canonical path, because the SFTP `writeFile` refuses any
  // destination whose directory resolves elsewhere. The identity comparison
  // ties the canonical path to the directory that was just prepared.
  const command = `set -e
[ ! -L ${directory} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
if [ -e ${directory} ]; then
  [ -d ${directory} ] || { echo '.ssh must be a directory' >&2; exit 1; }
else
  mkdir -p ${directory}
fi
[ -d ${directory} ] && [ ! -L ${directory} ] || { echo '.ssh must be a real directory' >&2; exit 1; }
ssh_directory_identity=$(stat -c '%d:%i' ${directory}) || exit $?
chmod 700 ${directory} && chown ${quotedUser}:${quotedPrimaryGroup} ${directory}
[ ! -L ${directory} ] && [ -d ${directory} ] || { echo '.ssh must be a real directory' >&2; exit 1; }
post_ssh_directory_identity=$(stat -c '%d:%i' ${directory}) || exit $?
[ "$post_ssh_directory_identity" = "$ssh_directory_identity" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
[ ! -L ${keysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
canonical_ssh_directory=$(command -p realpath -e -- ${directory}) || exit $?
canonical_ssh_directory_identity=$(stat -c '%d:%i' -- "$canonical_ssh_directory") || exit $?
[ "$canonical_ssh_directory_identity" = "$post_ssh_directory_identity" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
printf '%s\\n' "$canonical_ssh_directory"`

  const result = await conn.exec(command, MUTATION_EXEC_OPTS)
  if (result.code !== 0) {
    // R-0000765: differentiate the failure label based on which clause
    // emitted the error so the structured failure stays informative even
    // though both guards now share a single exec round-trip. The
    // `authorized_keys must not be a symlink` message can only come from
    // the trailing clause; everything else is .ssh-directory preparation.
    const label = result.stderr.includes("authorized_keys must not be a symlink")
      ? "authorized_keys symlink check failed"
      : "failed to prepare .ssh directory"
    return { failure: failedCommand(`[ssh.authorizedKeys: ${user} (${state})] ${label}`, result) }
  }
  const canonicalSshDirectoryPath = parseCanonicalSshDirectory(result.stdout)
  if (canonicalSshDirectoryPath === null) {
    return {
      failure: failed(
        `[ssh.authorizedKeys: ${user} (${state})] failed to resolve the canonical .ssh directory`
      ),
    }
  }
  return { canonicalSshDirectoryPath, failure: null }
}

async function authorizedKeysSecurityStateIsValid(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    primaryGroup: string
    sshDirectoryPath: string
    user: string
  }
): Promise<boolean> {
  const { authorizedKeysPath, primaryGroup, sshDirectoryPath, user } = parameters

  const isSshDirectorySymlink = await conn.test(`[ -L ${shellQuote(sshDirectoryPath)} ]`)
  if (isSshDirectorySymlink) return false

  const isAuthorizedKeysSymlink = await conn.test(`[ -L ${shellQuote(authorizedKeysPath)} ]`)
  if (isAuthorizedKeysSymlink) return false

  const sshDirectoryState = await conn.output(
    `stat -c '%a %U %G %F' ${shellQuote(sshDirectoryPath)}`
  )
  // R-0000065: compare against the user's resolved primary group (via
  // `id -gn`) so users whose primary group is not equal to the username do
  // not flap between `ok` and `needs-apply`.
  if (sshDirectoryState.trim() !== `700 ${user} ${primaryGroup} directory`) return false

  const authorizedKeysState = await conn.output(
    `stat -c '%a %U %G %F' ${shellQuote(authorizedKeysPath)}`
  )
  return authorizedKeysState.trim() === `600 ${user} ${primaryGroup} regular file`
}

/**
 * Write the computed content into the staging file and verify the staged
 * bytes before the atomic replace.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Paths, contents and labels.
 * @param parameters.content - The new content as Latin-1 string.
 * @param parameters.state - Desired state, used in failure labels.
 * @param parameters.temporaryPath - The validated staging path.
 * @param parameters.user - Target user, used in failure labels.
 * @returns `null` on success, otherwise a structured failure.
 */
async function stageAuthorizedKeysContent(
  conn: SshConnection,
  parameters: {
    content: string
    state: "absent" | "present"
    temporaryPath: string
    user: string
  }
): Promise<ModuleResult | null> {
  const { content, state, temporaryPath, user } = parameters
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  const stageFailure = await writeAuthorizedKeysStagingFile(conn, { content, temporaryPath })
  if (stageFailure === null) return null
  if (stageFailure.result === undefined) return failed(`${label} ${stageFailure.message}`)
  return failedCommand(`${label} ${stageFailure.message}`, stageFailure.result)
}

async function replaceAuthorizedKeysAtomically(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    content: string
    original: null | string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    temporaryPath: string
    user: string
  }
): Promise<ModuleResult | null> {
  const {
    authorizedKeysPath,
    content,
    original,
    primaryGroup,
    sshDirectoryPath,
    state,
    temporaryPath,
    user,
  } = parameters
  // R-0000065: chown to the user and the user's resolved primary group
  // instead of `${user}:${user}`. This preserves the existing primary group
  // on hosts where it is not equal to the username (e.g. `deploy:users`,
  // `www-data:www-data`) and prevents a drift loop where apply overwrites
  // the semantically correct group ownership only to see check go green on
  // the next run.
  const quotedTemporaryPath = shellQuote(temporaryPath)
  const quotedSshDirectoryPath = shellQuote(sshDirectoryPath)
  const quotedAuthorizedKeysPath = shellQuote(authorizedKeysPath)
  const expectedSshDirectoryState = shellQuote(`700 ${user} ${primaryGroup} directory`)
  const expectedAuthorizedKeysState = shellQuote(`600 ${user} ${primaryGroup} regular file`)

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
  // to its resolution, which on Linux can be `/etc/shadow` or any other
  // file the running uid has read access to. As a defence-in-depth, the
  // `[ ! -L ]` guard is repeated immediately before the `ln` call so the
  // race window between the earlier guard and the link operation is
  // collapsed to a single shell statement.
  //
  // Keep the expected temp-file digest and verify, in the same final shell
  // block, that the destination is the exact regular file we staged. The
  // expected digest is the one of the computed content, which the decode
  // already verified against the staged bytes, embedded as a literal; it is
  // not a `sha256sum` of the staging name (that would follow a symlink and
  // only prove equality with whatever sits there). The live file is read with
  // `O_NOFOLLOW`, and only the digest reaches the command line.
  //
  // The staged file lives in the user-owned `~/.ssh`, so the target user can
  // swap it for a symlink or a hard link after the decode. The script first
  // re-checks that it is still a regular, single-link file owned by the
  // staging uid and then uses `chown -h --`, which never follows a symlink.
  // The decode already created the file with mode 0600 (`umask 077`), so the
  // former `chmod 600`, which follows symlinks, is gone. A default ACL on
  // `~/.ssh` overrides the umask, so the script confirms mode 600 right after
  // the staged-file guard: a wrong mode fails before anything is published,
  // instead of after `mv -T` when the backup is already removed.
  //
  // The check that the live file still holds the content the rewrite was
  // computed from runs in this same script, directly before the backup link
  // and the rename, so the window for an unnoticed concurrent edit is as
  // small as the shell allows.
  const unchangedGuard = authorizedKeysUnchangedGuard({ authorizedKeysPath, original })
  const backupPath = `${authorizedKeysPath}.paratix-backup`
  const quotedBackupPath = shellQuote(backupPath)
  const replacedContentGuard = authorizedKeysReplacedContentGuard({
    authorizedKeysPath,
    backupPath,
    content,
  })
  const replace = await conn.exec(
    `${authorizedKeysStagedFileGuard(temporaryPath)}
${authorizedKeysStagedFileModeGuard(temporaryPath)}
chown -h -- ${shellQuote(user)}:${shellQuote(primaryGroup)} ${quotedTemporaryPath} && {
  [ ! -L ${quotedSshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
  [ -d ${quotedSshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }
  ssh_directory_state=$(stat -c '%a %U %G %F' ${quotedSshDirectoryPath}) || exit $?
  [ "$ssh_directory_state" = ${expectedSshDirectoryState} ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }
  [ ! -L ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  rm -f -- ${quotedBackupPath}
  backup_created=0
${unchangedGuard}
  if [ -e ${quotedAuthorizedKeysPath} ]; then
    [ -f ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
    [ ! -L ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
    ln -P -- ${quotedAuthorizedKeysPath} ${quotedBackupPath} || { echo 'failed to create authorized_keys backup hardlink' >&2; exit 1; }
    backup_created=1
  fi
  [ ! -L ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  if ! mv -T -- ${quotedTemporaryPath} ${quotedAuthorizedKeysPath}; then
    if [ "$backup_created" = 1 ]; then
      mv -T -- ${quotedBackupPath} ${quotedAuthorizedKeysPath} || echo 'authorized_keys backup restore failed; backup is at '${quotedBackupPath} >&2
    fi
    echo 'authorized_keys replace failed' >&2
    exit 1
  fi
  [ ! -e ${quotedTemporaryPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys replace did not consume temporary file' >&2; exit 1; }
  [ ! -L ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  [ -f ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must be a regular file' >&2; exit 1; }
  authorized_keys_state=$(stat -c '%a %U %G %F' ${quotedAuthorizedKeysPath}) || { rm -f -- ${quotedBackupPath}; exit 1; }
  [ "$authorized_keys_state" = ${expectedAuthorizedKeysState} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys metadata changed during replace' >&2; exit 1; }
${replacedContentGuard}
  rm -f -- ${quotedBackupPath}
}`,
    MUTATION_EXEC_OPTS
  )
  if (replace.code !== 0) {
    return failedCommand(
      `[ssh.authorizedKeys: ${user} (${state})] failed to replace authorized_keys`,
      replace
    )
  }
  return null
}

async function rewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    content: string
    original: null | string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult | null> {
  const { authorizedKeysPath, content, original, primaryGroup, sshDirectoryPath, state, user } =
    parameters
  // R-0000181: temp file lives in the same filesystem as the destination so
  // `mv -T` is atomic (single rename(2)) and so NFS root_squash hosts do not
  // hit cross-filesystem copy fallbacks.
  let temporaryPath: string
  try {
    temporaryPath = await createAuthorizedKeysTemporaryPath(conn, sshDirectoryPath)
  } catch (error) {
    if (isAuthorizedKeysMktempValidationError(error)) {
      return failed(`[ssh.authorizedKeys: ${user} (${state})] ${error.message}`)
    }
    throw error
  }

  try {
    const stageFailure = await stageAuthorizedKeysContent(conn, {
      content,
      state,
      temporaryPath,
      user,
    })
    if (stageFailure) return stageFailure

    return await replaceAuthorizedKeysAtomically(conn, {
      authorizedKeysPath,
      content,
      original,
      primaryGroup,
      sshDirectoryPath,
      state,
      temporaryPath,
      user,
    })
  } finally {
    // R-0000565: pass `--` so the staging path cannot be parsed as an `rm`
    // option after a future refactor that loosens the prefix validation.
    // The base64 payload never lives in `~/.ssh`; its private directory is
    // removed by `writeAuthorizedKeysStagingFile` itself.
    await conn.exec(`rm -f -- ${shellQuote(temporaryPath)}`, MUTATION_EXEC_OPTS)
  }
}

/**
 * Map the blocking plan outcomes to a failure. Messages name option names and
 * line numbers only, never option values or line content.
 *
 * @param plan - The content plan.
 * @param label - Module label prefix, e.g. `[ssh.authorizedKeys: alice (present)]`.
 * @returns A failed result for `conflict` and `options-guard`, otherwise `null`.
 */
function authorizedKeysPlanFailure(
  plan: AuthorizedKeysContentPlan,
  label: string
): ModuleResult | null {
  if (plan.kind === "conflict") {
    return failed(
      `${label} authorized_keys line ${plan.lineNumber} references this key but cannot be parsed; fix or remove that line manually`
    )
  }
  if (plan.kind === "options-guard") {
    return failed(
      `${label} authorized_keys already contains this key with options (${plan.optionNames.join(", ")}); pass options explicitly to replace them, or options: {} to remove them`
    )
  }
  return null
}

/**
 * Decide the result for content that needs no edit: `ok` when the file is
 * missing in the absent state or ownership and mode are valid, otherwise
 * `changed`, which tells the caller to rewrite (unchanged content resets
 * ownership and mode through the atomic replace).
 *
 * @param conn - The active SSH connection.
 * @param parameters - Paths, read content, plan and owner.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.content - The read content, or `null` when the file is missing.
 * @param parameters.plan - The content plan.
 * @param parameters.primaryGroup - The user's primary group.
 * @param parameters.sshDirectoryPath - Absolute `~/.ssh` path.
 * @param parameters.user - The target user.
 * @returns `ok` when nothing must change, otherwise `changed`.
 */
async function convergedAuthorizedKeysResult(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    content: null | string
    plan: AuthorizedKeysContentPlan
    primaryGroup: string
    sshDirectoryPath: string
    user: string
  }
): Promise<ModuleResult> {
  const { authorizedKeysPath, content, plan, primaryGroup, sshDirectoryPath, user } = parameters
  if (plan.kind !== "converged") return { status: "changed" }
  if (content === null) return { status: "ok" }
  const securityStateIsValid = await authorizedKeysSecurityStateIsValid(conn, {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    user,
  })
  return { status: securityStateIsValid ? "ok" : "changed" }
}

/**
 * Read and plan without touching the target: a blocking plan (options guard,
 * conflict) or converged content returns before `~/.ssh` metadata changes.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Paths, owner and target entry.
 * @param parameters.authorizedKeysPath - Absolute `authorized_keys` path.
 * @param parameters.primaryGroup - The user's primary group.
 * @param parameters.sshDirectoryPath - Absolute `~/.ssh` path.
 * @param parameters.target - The desired entry.
 * @param parameters.user - The target user.
 * @returns A final result, or the content to stage together with the read original.
 */
async function planAuthorizedKeysRewrite(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    primaryGroup: string
    sshDirectoryPath: string
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<{ content: string; original: null | string } | { result: ModuleResult }> {
  const {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    target,
    target: { state },
    user,
  } = parameters
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  // The read guards against a symlinked `.ssh` and `authorized_keys`; a
  // missing directory or file reads as `missing`, the normal append case.
  const read = await readAuthorizedKeys(conn, { authorizedKeysPath, sshDirectoryPath })
  if (read.kind === "failed") {
    return { result: failedCommand(`${label} failed to read authorized_keys`, read.result) }
  }

  const plan = planAuthorizedKeysContent(read.content, target)
  const planFailure = authorizedKeysPlanFailure(plan, label)
  if (planFailure) return { result: planFailure }

  const convergedResult = await convergedAuthorizedKeysResult(conn, {
    authorizedKeysPath,
    content: read.content,
    plan,
    primaryGroup,
    sshDirectoryPath,
    user,
  })
  if (convergedResult.status === "ok") return { result: convergedResult }

  // A converged content with drifted ownership or mode is rewritten unchanged
  // so the atomic replace resets ownership and permissions.
  return {
    content: plan.kind === "rewrite" ? plan.content : (read.content ?? ""),
    original: read.content,
  }
}

async function absentAuthorizedKeysPathNeedsGuard(
  conn: SshConnection,
  authorizedKeysPath: string
): Promise<boolean> {
  const quotedAuthorizedKeysPath = shellQuote(authorizedKeysPath)
  return conn.test(`[ -e ${quotedAuthorizedKeysPath} ] || [ -L ${quotedAuthorizedKeysPath} ]`)
}

export async function applyAuthorizedKeys(
  conn: null | SshConnection,
  parameters: {
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<ModuleResult> {
  const {
    target,
    target: { state },
    user,
  } = parameters
  if (!conn) {
    return failed(`[ssh.authorizedKeys: ${user} (${state})] SSH connection is required`)
  }

  const { failure: homeFailure, home } = await resolveApplyHome(conn, { state, user })
  if (homeFailure) return homeFailure
  if (home == null) return { status: "ok" }

  const sshDirectoryPath = `${home}${SSH_DIRECTORY_SUFFIX}`
  const authorizedKeysPath = `${sshDirectoryPath}/${AUTHORIZED_KEYS_FILE_NAME}`

  if (state === "absent") {
    const needsGuard = await absentAuthorizedKeysPathNeedsGuard(conn, authorizedKeysPath)
    if (!needsGuard) return { status: "ok" }
  }

  // R-0000065: resolve the primary group exactly once for the duration of
  // this apply so the directory chown, the authorized_keys chown and the
  // matching `stat` comparison all reference the same group identity.
  const primaryGroup = await resolvePrimaryGroup(conn, user)

  const planned = await planAuthorizedKeysRewrite(conn, {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    target,
    user,
  })
  if ("result" in planned) return planned.result

  return prepareAndRewriteAuthorizedKeys(conn, {
    authorizedKeysPath,
    planned,
    primaryGroup,
    sshDirectoryPath,
    state,
    user,
  })
}

/**
 * Prepare `~/.ssh` and publish the planned content through the canonical
 * `.ssh` path.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Literal paths, planned content and owner.
 * @param parameters.authorizedKeysPath - Literal `authorized_keys` path.
 * @param parameters.planned - The content to stage and the read original.
 * @param parameters.planned.content - The new content as Latin-1 string.
 * @param parameters.planned.original - The read content, or `null` when the file was missing.
 * @param parameters.primaryGroup - The user's primary group.
 * @param parameters.sshDirectoryPath - Literal `~/.ssh` path.
 * @param parameters.state - Desired state, used in failure labels.
 * @param parameters.user - The target user.
 * @returns `changed`, or a structured failure.
 */
async function prepareAndRewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    planned: { content: string; original: null | string }
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult> {
  const { authorizedKeysPath, planned, primaryGroup, sshDirectoryPath, state, user } = parameters
  // R-0000765: prepare `.ssh` and probe `authorized_keys` in a single
  // `set -e` shell pipeline instead of two sequential SSH execs. Halves the
  // round-trip cost on the apply path and keeps the two symlink guards
  // adjacent so a swap between them cannot slip past unnoticed.
  const guard = await ensureSshDirectoryAndAuthorizedKeysAreNotSymlinks(conn, {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    state,
    user,
  })
  if (guard.failure) return guard.failure

  // The live-file comparison inside the final replace covers any change
  // between the read and the replace.
  const canonicalSshDirectoryPath = guard.canonicalSshDirectoryPath
  const rewriteFailure = await rewriteAuthorizedKeys(conn, {
    authorizedKeysPath: `${canonicalSshDirectoryPath}/${AUTHORIZED_KEYS_FILE_NAME}`,
    content: planned.content,
    original: planned.original,
    primaryGroup,
    sshDirectoryPath: canonicalSshDirectoryPath,
    state,
    user,
  })
  return rewriteFailure ?? { status: "changed" }
}

function checkMissingAuthorizedKeysUser(
  error: unknown,
  user: string,
  state: "absent" | "present"
): "needs-apply" | "ok" | null {
  if (!isUnsafeAuthorizedKeysHomeError(error, user)) return null
  return state === "present" ? NEEDS_APPLY : "ok"
}

function checkResultForMissingAuthorizedKeysFiles(
  state: "absent" | "present"
): "needs-apply" | "ok" {
  return state === "present" ? NEEDS_APPLY : "ok"
}

async function resolveAuthorizedKeysCheckPaths(
  conn: SshConnection,
  user: string,
  state: "absent" | "present"
): Promise<
  | "needs-apply"
  | "ok"
  | {
      authorizedKeysPath: string
      sshDirectoryPath: string
    }
> {
  try {
    const home = await resolveHome(conn, user)
    return {
      authorizedKeysPath: `${home}${SSH_DIRECTORY_SUFFIX}/${AUTHORIZED_KEYS_FILE_NAME}`,
      sshDirectoryPath: `${home}${SSH_DIRECTORY_SUFFIX}`,
    }
  } catch (error) {
    const missingUserResult = checkMissingAuthorizedKeysUser(error, user, state)
    if (missingUserResult != null) return missingUserResult
    throw error
  }
}

async function checkAuthorizedKeysPathsExist(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    sshDirectoryPath: string
    state: "absent" | "present"
  }
): Promise<"needs-apply" | "ok" | null> {
  const { authorizedKeysPath, sshDirectoryPath, state } = parameters
  const sshDirectoryExists = await conn.exists(sshDirectoryPath)
  const authorizedKeysExists = await conn.exists(authorizedKeysPath)

  if (sshDirectoryExists && authorizedKeysExists) return null
  return checkResultForMissingAuthorizedKeysFiles(state)
}

export async function checkAuthorizedKeys(
  conn: null | SshConnection,
  parameters: {
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<"needs-apply" | "ok"> {
  const {
    target,
    target: { state },
    user,
  } = parameters
  if (!conn) return NEEDS_APPLY

  const pathResolution = await resolveAuthorizedKeysCheckPaths(conn, user, state)
  if (pathResolution === "needs-apply" || pathResolution === "ok") return pathResolution

  const { authorizedKeysPath, sshDirectoryPath } = pathResolution
  const missingPathResult = await checkAuthorizedKeysPathsExist(conn, {
    authorizedKeysPath,
    sshDirectoryPath,
    state,
  })
  if (missingPathResult != null) return missingPathResult

  // R-0000065: resolve the primary group via `id -gn` so the stat-based
  // ownership comparison matches what apply actually writes and does not
  // flap for users whose primary group differs from the username.
  const primaryGroup = await resolvePrimaryGroup(conn, user)
  const securityStateIsValid = await authorizedKeysSecurityStateIsValid(conn, {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    user,
  })
  if (!securityStateIsValid) return NEEDS_APPLY

  // R-0000044 superseded: entries are matched by key blob on a no-follow
  // read of the file, so a key body that only appears inside another entry
  // (comment, option value) is never reported as present. Unreadable content,
  // blocking conflicts and the options guard all defer to apply.
  const read = await readAuthorizedKeys(conn, { authorizedKeysPath, sshDirectoryPath })
  if (read.kind === "failed") return NEEDS_APPLY
  return planAuthorizedKeysContent(read.content, target).kind === "converged" ? "ok" : NEEDS_APPLY
}

/**
 * Read-only dry-run analysis: reports `failed` for the options guard and for
 * an unparseable line that references the key, `ok` when converged, and
 * `changed` otherwise. Never mutates the target.
 *
 * @param conn - The active SSH connection, or `null`.
 * @param parameters - Target entry and user.
 * @param parameters.target - The desired entry.
 * @param parameters.user - The target user.
 * @returns The dry-run module result.
 */
export async function dryRunAuthorizedKeys(
  conn: null | SshConnection,
  parameters: {
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<ModuleResult> {
  const {
    target,
    target: { state },
    user,
  } = parameters
  if (!conn) return { status: "changed" }

  // A user created earlier in the same run does not exist during a dry run.
  const pathResolution = await resolveAuthorizedKeysCheckPaths(conn, user, state)
  if (pathResolution === "needs-apply") return { status: "changed" }
  if (pathResolution === "ok") return { status: "ok" }

  const { authorizedKeysPath, sshDirectoryPath } = pathResolution
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  // A symlinked `.ssh` or `authorized_keys` fails the read, so dry-run
  // reports `failed` like apply would.
  const read = await readAuthorizedKeys(conn, { authorizedKeysPath, sshDirectoryPath })
  if (read.kind === "failed") {
    return failedCommand(`${label} failed to read authorized_keys`, read.result)
  }

  const plan = planAuthorizedKeysContent(read.content, target)
  const planFailure = authorizedKeysPlanFailure(plan, label)
  if (planFailure) return planFailure
  // The primary group only matters for the ownership probe of converged content.
  if (plan.kind !== "converged") return { status: "changed" }

  return convergedAuthorizedKeysResult(conn, {
    authorizedKeysPath,
    content: read.content,
    plan,
    primaryGroup: await resolvePrimaryGroup(conn, user),
    sshDirectoryPath,
    user,
  })
}
