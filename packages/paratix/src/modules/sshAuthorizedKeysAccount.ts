/**
 * Target-account resolution and privilege drop for `ssh.authorizedKeys`.
 *
 * The target user owns `$HOME` and `~/.ssh`, so between or inside any remote
 * command the user can rename or replace `~/.ssh` (for example with a symlink
 * to `/etc`) and swap entries inside it for symlinks or hard links. Path
 * components above `$HOME` are root-controlled. Every script that works
 * inside `~/.ssh` therefore:
 *
 * - runs as the target user (`setpriv`, falling back to `runuser`), so root
 *   never opens or creates a user-controlled name inside it, nor changes its
 *   mode or owner;
 * - enters the directory with `cd -P` and verifies `pwd -P` against the
 *   canonical path resolved once here (`realpath -e` of the root-controlled
 *   getent home plus `/.ssh`), and from the prepare step on also its
 *   `device:inode owner` identity, and then uses only relative names.
 *
 * The one exception is a `~/.ssh` that root owns, typically left by an
 * earlier root or sudo bootstrap. Root enters it the same way, and only when
 * nobody but root may write it and it holds nothing but ssh files does root
 * read it or hand its `authorized_keys` to the target user, because then its
 * entries are not user-controlled; root also resets mode and owner of the
 * verified directory itself (`chmod 700 .`, `chown -h uid:gid .`). A
 * `~/.ssh` owned by any other user is refused.
 *
 * These guarantees assume that every path component above `$HOME` is
 * root-controlled, so that `realpath -e` of the home and a `pwd -P` match
 * name a directory only root could have placed there or moved there.
 *
 * Every root script that launches a dropped process first runs
 * `exec </dev/null` and `cd /`, and {@link asAuthorizedKeysUser} gives that
 * process `/dev/null` (or, for the stage step, exactly the decoded payload)
 * as stdin and pipes that root reads as stdout and stderr. The dropped
 * process runs as the target user and that user could inspect it, so it must
 * never hold a descriptor of the controller channel, whose stdin can carry a
 * sudo password. Root-side tools that may run inside `~/.ssh` are invoked
 * with `command -p`, the drop tool by the absolute path the probe resolved,
 * and the user-side scripts by `/bin/sh`, so neither the working directory
 * nor a `.` in root's `PATH` can substitute a program.
 *
 * Nothing here falls back to running as root: without `setpriv` and `runuser`
 * the module fails. The prefix is empty only when the remote shell already
 * runs with the target uid (the target user is root, or a test runs as the
 * target user), where a drop would not change the identity.
 */
import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

const ACCOUNT_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SSH_DIRECTORY_SUFFIX = "/.ssh"
const ACCOUNT_LINE_PATTERN = /^(?<drop>missing|none|runuser|setpriv) (?<uid>\d+) (?<gid>\d+)$/v
const IDENTITY_PATTERN = /^\d+:\d+ (?<uid>\d+)$/v
// Absolute path of `setpriv` or `runuser`, as `command -v` prints it.
const DROP_TOOL_PATTERN = /^\/[\w.\/\-]+\/(?:runuser|setpriv)$/v

/** Message of a target host that offers neither `setpriv` nor `runuser`. */
export const AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING =
  "needs setpriv or runuser (util-linux) on the target host to act as the target user; neither was found"

/** `cd -P` into `~/.ssh` failed, for example because the user cannot enter it. */
export const SSH_DIRECTORY_ENTER_REFUSAL = "cannot enter .ssh as the target user"
/** `pwd -P` after `cd -P` differs from the canonical path. */
export const SSH_DIRECTORY_SYMLINK_REFUSAL = ".ssh must not be a symlink"
/** `~/.ssh` belongs to another user than the target user. */
export const SSH_DIRECTORY_OWNER_REFUSAL = ".ssh must be owned by the target user"
/** `~/.ssh` belongs to neither the target user nor root, so it is never repaired. */
export const SSH_DIRECTORY_FOREIGN_OWNER_REFUSAL = ".ssh must be owned by the target user or root"
/** Entries a root-owned `~/.ssh` may hold for root to read and repair it. */
export const ROOT_OWNED_SSH_DIRECTORY_ENTRIES = [
  "authorized_keys",
  "known_hosts",
  "known_hosts.old",
] as const
/** A root-owned `~/.ssh` that group or others may write is never repaired. */
export const ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL =
  "a root-owned .ssh must not be writable by group or others; fix it manually"
/** A root-owned `~/.ssh` with other entries may not be an `.ssh` directory at all. */
export const ROOT_OWNED_SSH_DIRECTORY_ENTRIES_REFUSAL =
  "a root-owned .ssh may only contain authorized_keys and known_hosts; fix it manually"
/** A root-owned `~/.ssh` whose `authorized_keys` root cannot hand over safely. */
export const ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL =
  "authorized_keys in a root-owned .ssh must be a root-owned single-link regular file; fix it manually"
/** `authorized_keys` in a user-owned `~/.ssh` belongs to another user, e.g. after `sudo tee -a`. */
export const AUTHORIZED_KEYS_OWNER_REFUSAL =
  "authorized_keys must be owned by the target user; chown it manually"
/** The target user cannot enter its home directory, e.g. NFS root_squash or a non-searchable home. */
export const HOME_DIRECTORY_ENTER_REFUSAL = "cannot enter the home directory as the target user"
/** The verified `~/.ssh` no longer has the identity captured by the prepare step. */
export const SSH_DIRECTORY_IDENTITY_REFUSAL = ".ssh directory changed during rewrite"

/**
 * The target account as resolved once per check, dry-run or apply.
 */
export type AuthorizedKeysAccount = {
  /**
   * Shell words, each followed by a space, that run the next command as the
   * target user; empty when the remote shell already runs with the target uid.
   */
  dropPrefix: string
  /** Canonical `~/.ssh` path, or `null` when the home directory does not exist. */
  expectedSshDirectory: null | string
  /** Numeric primary gid of the target user. */
  gid: string
  /** Numeric uid of the target user. */
  uid: string
  /** The target user name (already validated as a POSIX user name). */
  user: string
}

function isSafeCanonicalHome(home: string): boolean {
  return (
    home.startsWith("/") &&
    home !== "/" &&
    !home.includes(":") &&
    !home.includes("\r") &&
    !home.includes("\n") &&
    !home.includes("\0")
  )
}

/**
 * Root-side probe for the numeric ids, the canonical home and the available
 * privilege-drop tool. `realpath -e` resolves the getent home, whose
 * components are root-controlled; `$HOME` itself cannot be renamed by its
 * owner because its parent belongs to root. The tool is looked up with
 * `command -v` in root's `PATH`, which also resolves it when it runs.
 *
 * @param parameters - Getent home and target user.
 * @param parameters.home - The validated getent home directory.
 * @param parameters.user - The target user.
 * @returns The probe script; it prints `<drop> <uid> <gid>` and the canonical home (empty when missing).
 */
export function authorizedKeysAccountCommand(parameters: { home: string; user: string }): string {
  const user = shellQuote(parameters.user)
  return `set -e
exec </dev/null
cd /
target_uid=$(command -p id -u ${user})
target_gid=$(command -p id -g ${user})
canonical_home=$(command -p realpath -e -- ${shellQuote(parameters.home)} 2>/dev/null) || canonical_home=
drop_tool=
if [ "$(command -p id -u)" = "$target_uid" ]; then drop=none
elif drop_tool=$(command -v setpriv); then drop=setpriv
elif drop_tool=$(command -v runuser); then drop=runuser
else drop=missing
fi
printf '%s %s %s\\n%s\\n%s\\n' "$drop" "$target_uid" "$target_gid" "$canonical_home" "$drop_tool"`
}

function dropPrefixFor(parameters: {
  drop: string
  gid: string
  tool: string
  uid: string
  user: string
}): null | string {
  const { drop, gid, tool, uid, user } = parameters
  if (drop === "none") return tool.length === 0 ? "" : null
  // `command -v` must have resolved an absolute program path, never a
  // relative one, a builtin or a function.
  if (!DROP_TOOL_PATTERN.test(tool)) return null
  if (drop === "setpriv") {
    return `${shellQuote(tool)} --reuid=${uid} --regid=${gid} --init-groups -- `
  }
  return `${shellQuote(tool)} -u ${shellQuote(user)} -- `
}

/**
 * Split the probe output into its three lines.
 *
 * @param stdout - The probe output.
 * @returns The drop line, canonical home and tool path, or `null` for extra output.
 */
function probeLines(stdout: string): { canonicalHome: string; first: string; tool: string } | null {
  const [first = "", canonicalHome = "", tool = "", ...rest] = stdout.split("\n")
  if (rest.some((line) => line.length > 0)) return null
  return { canonicalHome, first, tool }
}

function parseAccountOutput(
  stdout: string,
  user: string
): { message: string } | AuthorizedKeysAccount | null {
  const lines = probeLines(stdout)
  const groups = lines === null ? undefined : ACCOUNT_LINE_PATTERN.exec(lines.first)?.groups
  if (lines === null || groups === undefined) return null
  const { canonicalHome, tool } = lines
  const { drop, gid, uid } = groups
  if (drop === "missing") return { message: AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING }
  if (canonicalHome.length > 0 && !isSafeCanonicalHome(canonicalHome)) return null
  const dropPrefix = dropPrefixFor({ drop, gid, tool, uid, user })
  if (dropPrefix === null) return null
  return {
    dropPrefix,
    expectedSshDirectory:
      canonicalHome.length > 0 ? `${canonicalHome}${SSH_DIRECTORY_SUFFIX}` : null,
    gid,
    uid,
    user,
  }
}

/**
 * Resolve the target account once per operation.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Getent home and target user.
 * @param parameters.home - The validated getent home directory.
 * @param parameters.user - The target user.
 * @returns The account, or a failure description with the failed probe result.
 */
export async function resolveAuthorizedKeysAccount(
  conn: SshConnection,
  parameters: { home: string; user: string }
): Promise<{ account: AuthorizedKeysAccount } | { message: string; result?: ExecResult }> {
  const result = await conn.exec(authorizedKeysAccountCommand(parameters), ACCOUNT_EXEC_OPTS)
  if (result.code !== 0) {
    return { message: "failed to resolve the target account", result }
  }
  const parsed = parseAccountOutput(result.stdout, parameters.user)
  if (parsed === null) return { message: "failed to resolve the target account" }
  if ("message" in parsed) return parsed
  return { account: parsed }
}

/**
 * Prologue of every root-side command that launches a dropped process: root
 * gives up its own stdin, which may carry a sudo password, and leaves any
 * directory the target user controls.
 */
export const AUTHORIZED_KEYS_ROOT_PROLOGUE = "exec </dev/null\ncd /\n"

/**
 * Wrap a dropped command so that it holds none of root's descriptors. The
 * dropped process runs as the target user, who may read its descriptors
 * through `/proc/<pid>/fd`: stdin is `/dev/null` unless the caller connects
 * a pipe, fds 3 to 9 are closed, and stdout and stderr are pipes that two
 * root-side `cat`s copy to root's own stdout and stderr. POSIX `sh` has no
 * `pipefail`, so the exit status travels through the command substitution on
 * fd 3. It is recorded in both branches of an `if`, because `set -e` (which
 * dash and `bash --posix` carry into the substitution) would otherwise end
 * the subshell before a status line after a failing drop; the command ends
 * with `(exit "${paratix_status:-1}")`, so callers see exactly that status,
 * or 1 if none arrived.
 *
 * The target user could keep the output pipes open, for example through a
 * process it starts from the dropped one; root then waits until the exec
 * timeout of the connection. That only delays the run that manages this
 * user's own keys and grants nothing.
 *
 * @param parameters - The drop and how its stdin is connected.
 * @param parameters.account - The resolved target account.
 * @param parameters.args - Positional arguments (`$1`, `$2`, ...).
 * @param parameters.script - The user-side shell script.
 * @param parameters.stdin - `"null"` for `/dev/null`, `"pipe"` for the caller's pipe.
 * @returns The command to run as root.
 */
function wrapDroppedCommand(parameters: {
  account: AuthorizedKeysAccount
  args: readonly string[]
  script: string
  stdin: "null" | "pipe"
}): string {
  const { account, args, script, stdin } = parameters
  const input = stdin === "pipe" ? "" : " </dev/null"
  const quotedArgs = args.map((arg) => shellQuote(arg)).join(" ")
  const dropped = `${account.dropPrefix}/bin/sh -c ${shellQuote(script)} sh ${quotedArgs}${input} 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-`
  return `{ paratix_status=$({ { if ${dropped}; then echo 0 >&3; else echo "$?" >&3; fi | command -p cat >&4; } 2>&1 | command -p cat >&5; } 3>&1); } 4>&1 5>&2; (exit "\${paratix_status:-1}")`
}

/**
 * Root-side command that runs `script` as the target user with `/bin/sh -c`
 * and stdin from `/dev/null`. The script text is constant per step; every
 * variable value travels as a shell-quoted positional argument, never as
 * content on the command line. See {@link wrapDroppedCommand} for the
 * descriptors the dropped process gets.
 *
 * @param account - The resolved target account.
 * @param script - The user-side shell script.
 * @param args - Positional arguments (`$1`, `$2`, ...).
 * @returns The command to run as root.
 */
export function asAuthorizedKeysUser(
  account: AuthorizedKeysAccount,
  script: string,
  args: readonly string[]
): string {
  return wrapDroppedCommand({ account, args, script, stdin: "null" })
}

/**
 * A complete root-side command for a step that consists of one drop: the
 * {@link AUTHORIZED_KEYS_ROOT_PROLOGUE} followed by
 * {@link asAuthorizedKeysUser}.
 *
 * @param account - The resolved target account.
 * @param script - The user-side shell script.
 * @param args - Positional arguments (`$1`, `$2`, ...).
 * @returns The command to run as root.
 */
export function authorizedKeysUserCommand(
  account: AuthorizedKeysAccount,
  script: string,
  args: readonly string[]
): string {
  return `${AUTHORIZED_KEYS_ROOT_PROLOGUE}${asAuthorizedKeysUser(account, script, args)}`
}

/**
 * Like {@link asAuthorizedKeysUser}, but the dropped process reads the pipe
 * the caller connects. Only the stage step uses it, with a pipe that carries
 * the decoded payload and nothing of root's own stdin.
 *
 * @param account - The resolved target account.
 * @param script - The user-side shell script.
 * @param args - Positional arguments (`$1`, `$2`, ...).
 * @returns The command to run as root, to be placed after `|`.
 */
export function asAuthorizedKeysUserReadingPipe(
  account: AuthorizedKeysAccount,
  script: string,
  args: readonly string[]
): string {
  return wrapDroppedCommand({ account, args, script, stdin: "pipe" })
}

/**
 * Shell lines that enter the canonical `~/.ssh` given as `$1` and verify it
 * by its physical path. After them, only relative names are used, so a later
 * rename or replacement of `~/.ssh` cannot redirect any access.
 *
 * @returns The prologue lines without a trailing newline.
 */
export function enterSshDirectoryLines(): string {
  return `cd -P -- "$1" || { echo '${SSH_DIRECTORY_ENTER_REFUSAL}' >&2; exit 1; }
[ "$(pwd -P)" = "$1" ] || { echo '${SSH_DIRECTORY_SYMLINK_REFUSAL}' >&2; exit 1; }`
}

/**
 * Shell lines that enter the canonical `~/.ssh` given as `$1` and confirm
 * that it is still the directory the prepare step verified: `$2` carries its
 * `device:inode owner` identity as a literal.
 *
 * @returns The prologue lines without a trailing newline.
 */
export function enterVerifiedSshDirectoryLines(): string {
  return `${enterSshDirectoryLines()}
[ "$(stat -c '%d:%i %u' .)" = "$2" ] || { echo '${SSH_DIRECTORY_IDENTITY_REFUSAL}' >&2; exit 1; }`
}

/**
 * Root-side lines that enter the canonical `~/.ssh` and classify it. Root
 * only changes into the directory and inspects metadata of `.` and of its
 * entry names; it opens no name. After `cd -P` and the `pwd -P` check, `.` is
 * the directory that sat at the canonical path, a child of the
 * root-controlled home. The lines set `ssh_directory_owner` and refuse:
 *
 * - a directory owned by neither the target user nor root;
 * - a root-owned directory that group or others may write (`stat -c %A`, a
 *   character test that does not depend on the shell's octal arithmetic;
 *   an ACL mask shows up in the group bits): the user could have moved such
 *   a shared directory into the home, and its entries are user-controlled;
 *   every probe is assigned first and checked, so a failing `stat` or
 *   `find` refuses instead of passing;
 * - a root-owned directory with entries other than {@link
 *   ROOT_OWNED_SSH_DIRECTORY_ENTRIES}, so another root-owned directory the
 *   user renamed to `.ssh` (for example a sudo-created `~/.cache`) is never
 *   taken over;
 * - a root-owned directory whose `authorized_keys` is not a root-owned,
 *   single-link regular file.
 *
 * Only root can change the entries of a root-owned directory nobody else may
 * write, and nobody but root can change that state while the script runs, so
 * root may read and hand over its `authorized_keys`.
 *
 * @param account - The resolved target account.
 * @param expectedSshDirectory - The canonical `~/.ssh`.
 * @returns The lines without a trailing newline.
 */
export function rootInspectSshDirectoryLines(
  account: AuthorizedKeysAccount,
  expectedSshDirectory: string
): string {
  const expected = shellQuote(expectedSshDirectory)
  const uid = shellQuote(account.uid)
  const allowed = ROOT_OWNED_SSH_DIRECTORY_ENTRIES.map((name) => `! -name ${name}`).join(" ")
  return `cd -P -- ${expected} || { echo '.ssh must be a directory' >&2; exit 1; }
[ "$(pwd -P)" = ${expected} ] || { echo '${SSH_DIRECTORY_SYMLINK_REFUSAL}' >&2; exit 1; }
ssh_directory_owner=$(command -p stat -c '%u' .) || exit 1
[ "$ssh_directory_owner" = ${uid} ] || [ "$ssh_directory_owner" = 0 ] || { echo '${SSH_DIRECTORY_FOREIGN_OWNER_REFUSAL}' >&2; exit 1; }
if [ "$ssh_directory_owner" != ${uid} ]; then
  ssh_directory_mode=$(command -p stat -c '%A' .) || exit 1
  case "$ssh_directory_mode" in
    d????????*) ;;
    *) echo '.ssh must be a directory' >&2; exit 1 ;;
  esac
  case "$ssh_directory_mode" in
    ?????w*|????????w*) echo '${ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL}' >&2; exit 1 ;;
  esac
  ssh_directory_extra=$(command -p find . -mindepth 1 -maxdepth 1 ${allowed} -print -quit) || exit 1
  [ -z "$ssh_directory_extra" ] || { echo '${ROOT_OWNED_SSH_DIRECTORY_ENTRIES_REFUSAL}' >&2; exit 1; }
  if [ -e ./authorized_keys ] || [ -L ./authorized_keys ]; then
    authorized_keys_shape=$(command -p stat -c '%u %h' ./authorized_keys) || exit 1
    [ ! -L ./authorized_keys ] && [ -f ./authorized_keys ] && [ "$authorized_keys_shape" = '0 1' ] || { echo '${ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL}' >&2; exit 1; }
  fi
fi`
}

/**
 * Validate the identity the prepare step prints for the verified `~/.ssh`.
 *
 * @param stdout - The prepare script output.
 * @param uid - The expected owner uid.
 * @returns The identity, or `null` when it is malformed or names another owner.
 */
export function parseSshDirectoryIdentity(stdout: string, uid: string): null | string {
  const identity = stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout
  return IDENTITY_PATTERN.exec(identity)?.groups?.uid === uid ? identity : null
}
