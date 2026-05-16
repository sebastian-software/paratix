/* eslint-disable max-lines -- authorized_keys flow keeps related apply, check, and rewrite helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const MUTATION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000181: prefix used by `mktemp` for the in-flight authorized_keys
// rewrite. The leading dot keeps the temp file hidden from typical
// glob expansions; the validateMktempPath check rejects any output that
// does not start with `<home>/.ssh/.paratix-authorized-keys.`.
const AUTHORIZED_KEYS_TEMPORARY_PREFIX = ".paratix-authorized-keys"

async function resolveHome(conn: SshConnection, user: string): Promise<string> {
  const home = await conn.output(`getent passwd ${shellQuote(user)} | cut -d: -f6`)
  if (home.length === 0 || home === "/") {
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
async function ensureAuthorizedKeysIsNotSymlink(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult | null> {
  const { authorizedKeysPath, state, user } = parameters
  const result = await conn.exec(
    `[ ! -L ${shellQuote(authorizedKeysPath)} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`,
    MUTATION_EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[ssh.authorizedKeys: ${user} (${state})] authorized_keys symlink check failed`,
      result
    )
  }
  return null
}

async function ensureSshDirectoryForAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult | null> {
  const { primaryGroup, sshDirectoryPath, state, user } = parameters
  const directory = shellQuote(sshDirectoryPath)

  const result = await conn.exec(
    `[ ! -L ${directory} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e ${directory} ]; then [ -d ${directory} ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p ${directory}; fi; [ -d ${directory} ] && [ ! -L ${directory} ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 ${directory} && chown ${shellQuote(user)}:${shellQuote(primaryGroup)} ${directory}`,
    MUTATION_EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[ssh.authorizedKeys: ${user} (${state})] failed to prepare .ssh directory`,
      result
    )
  }
  return null
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

async function stageAuthorizedKeysContent(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    key: string
    state: "absent" | "present"
    temporaryPath: string
    user: string
  }
): Promise<ModuleResult | null> {
  const { authorizedKeysPath, key, state, temporaryPath, user } = parameters
  const quotedAuthorizedKeysPath = shellQuote(authorizedKeysPath)
  const quotedTemporaryPath = shellQuote(temporaryPath)
  const existingAuthorizedKeysGuard = `[ ! -L ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }; [ -f ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }`
  const stage =
    state === "present"
      ? await conn.exec(
          `{ if [ -e ${quotedAuthorizedKeysPath} ]; then ${existingAuthorizedKeysGuard}; awk '1' ${quotedAuthorizedKeysPath} > ${quotedTemporaryPath} || exit $?; grep -qxF -- ${shellQuote(key)} ${quotedTemporaryPath}; grep_status=$?; if [ "$grep_status" -eq 0 ]; then :; elif [ "$grep_status" -eq 1 ]; then printf '%s\\n' ${shellQuote(key)} >> ${quotedTemporaryPath}; else exit "$grep_status"; fi; else printf '%s\\n' ${shellQuote(key)} > ${quotedTemporaryPath}; fi; }`,
          MUTATION_EXEC_OPTS
        )
      : // R-0000044: use `grep -vxF` (whole-line match) to mirror the present
        // branch's `grep -qxF` and avoid removing collateral entries whose key
        // body is a substring of the key being deleted (e.g. a key appearing
        // again with options-prefix or a different comment).
        await conn.exec(
          `{ if [ -e ${quotedAuthorizedKeysPath} ]; then ${existingAuthorizedKeysGuard}; grep -vxF -- ${shellQuote(key)} ${quotedAuthorizedKeysPath} > ${quotedTemporaryPath}; grep_status=$?; if [ "$grep_status" -eq 0 ] || [ "$grep_status" -eq 1 ]; then :; else exit "$grep_status"; fi; else : > ${quotedTemporaryPath}; fi; }`,
          MUTATION_EXEC_OPTS
        )
  if (stage.code !== 0) {
    return failedCommand(
      `[ssh.authorizedKeys: ${user} (${state})] failed to stage authorized_keys rewrite`,
      stage
    )
  }
  return null
}

async function replaceAuthorizedKeysAtomically(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    temporaryPath: string
    user: string
  }
): Promise<ModuleResult | null> {
  const { authorizedKeysPath, primaryGroup, sshDirectoryPath, state, temporaryPath, user } =
    parameters
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
  // Keep the expected temp-file digest and verify, in the same final shell
  // block, that the destination is the exact regular file we staged.
  const quotedBackupPath = shellQuote(`${authorizedKeysPath}.paratix-backup`)
  const replace = await conn.exec(
    `chmod 600 ${quotedTemporaryPath} && chown ${shellQuote(user)}:${shellQuote(primaryGroup)} ${quotedTemporaryPath} && { expected_authorized_keys_hash=$(sha256sum ${quotedTemporaryPath} | cut -d' ' -f1) || exit $?; [ ! -L ${quotedSshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; [ -d ${quotedSshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }; ssh_directory_state=$(stat -c '%a %U %G %F' ${quotedSshDirectoryPath}) || exit $?; [ "$ssh_directory_state" = ${expectedSshDirectoryState} ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }; [ ! -L ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }; rm -f -- ${quotedBackupPath}; backup_created=0; if [ -e ${quotedAuthorizedKeysPath} ]; then [ -f ${quotedAuthorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }; ln -- ${quotedAuthorizedKeysPath} ${quotedBackupPath} || { echo 'failed to create authorized_keys backup hardlink' >&2; exit 1; }; backup_created=1; fi; [ ! -L ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }; if ! mv -T -- ${quotedTemporaryPath} ${quotedAuthorizedKeysPath}; then if [ "$backup_created" = 1 ]; then mv -T -- ${quotedBackupPath} ${quotedAuthorizedKeysPath} || echo 'authorized_keys backup restore failed; backup is at '${quotedBackupPath} >&2; fi; echo 'authorized_keys replace failed' >&2; exit 1; fi; [ ! -e ${quotedTemporaryPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys replace did not consume temporary file' >&2; exit 1; }; [ ! -L ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }; [ -f ${quotedAuthorizedKeysPath} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys must be a regular file' >&2; exit 1; }; authorized_keys_state=$(stat -c '%a %U %G %F' ${quotedAuthorizedKeysPath}) || { rm -f -- ${quotedBackupPath}; exit 1; }; [ "$authorized_keys_state" = ${expectedAuthorizedKeysState} ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys metadata changed during replace' >&2; exit 1; }; authorized_keys_hash=$(sha256sum ${quotedAuthorizedKeysPath} | cut -d' ' -f1) || { rm -f -- ${quotedBackupPath}; exit 1; }; [ "$authorized_keys_hash" = "$expected_authorized_keys_hash" ] || { rm -f -- ${quotedBackupPath}; echo 'authorized_keys content changed during replace' >&2; exit 1; }; rm -f -- ${quotedBackupPath}; }`,
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
    key: string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult | null> {
  const { authorizedKeysPath, key, primaryGroup, sshDirectoryPath, state, user } = parameters
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
      authorizedKeysPath,
      key,
      state,
      temporaryPath,
      user,
    })
    if (stageFailure) return stageFailure

    return await replaceAuthorizedKeysAtomically(conn, {
      authorizedKeysPath,
      primaryGroup,
      sshDirectoryPath,
      state,
      temporaryPath,
      user,
    })
  } finally {
    // R-0000565: pass `--` so the staging path cannot be parsed as an `rm`
    // option after a future refactor that loosens the prefix validation.
    await conn.exec(`rm -f -- ${shellQuote(temporaryPath)}`, MUTATION_EXEC_OPTS)
  }
}

async function authorizedKeysApplyIsConverged(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    key: string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<boolean> {
  const { authorizedKeysPath, key, primaryGroup, sshDirectoryPath, state, user } = parameters
  const authorizedKeysExists = await conn.exists(authorizedKeysPath)
  if (!authorizedKeysExists) return state === "absent"

  const keyExists = await conn.test(
    `grep -qxF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)}`
  )
  if (state === "present" && !keyExists) return false
  if (state === "absent" && keyExists) return false

  const securityStateIsValid = await authorizedKeysSecurityStateIsValid(conn, {
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    user,
  })

  return finalizeAuthorizedKeysCheck(state, keyExists, securityStateIsValid) === "ok"
}

async function rewriteAuthorizedKeysWhenNeeded(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    key: string
    primaryGroup: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult> {
  const applyIsConverged = await authorizedKeysApplyIsConverged(conn, parameters)
  if (applyIsConverged) return { status: "ok" }

  const rewriteFailure = await rewriteAuthorizedKeys(conn, parameters)
  if (rewriteFailure) return rewriteFailure

  return { status: "changed" }
}

export async function applyAuthorizedKeys(
  conn: null | SshConnection,
  parameters: {
    key: string
    state: "absent" | "present"
    user: string
  }
): Promise<ModuleResult> {
  const { key, state, user } = parameters
  if (!conn) {
    return failed(`[ssh.authorizedKeys: ${user} (${state})] SSH connection is required`)
  }

  const { failure: homeFailure, home } = await resolveApplyHome(conn, { state, user })
  if (homeFailure) return homeFailure
  if (home == null) return { status: "ok" }

  // R-0000065: resolve the primary group exactly once for the duration of
  // this apply so the directory chown, the authorized_keys chown and the
  // matching `stat` comparison all reference the same group identity.
  const primaryGroup = await resolvePrimaryGroup(conn, user)
  const sshDirectoryPath = `${home}/.ssh`
  const authorizedKeysPath = `${home}/.ssh/authorized_keys`

  const directoryFailure = await ensureSshDirectoryForAuthorizedKeys(conn, {
    primaryGroup,
    sshDirectoryPath,
    state,
    user,
  })
  if (directoryFailure) return directoryFailure

  const symlinkFailure = await ensureAuthorizedKeysIsNotSymlink(conn, {
    authorizedKeysPath,
    state,
    user,
  })
  if (symlinkFailure) return symlinkFailure

  return rewriteAuthorizedKeysWhenNeeded(conn, {
    authorizedKeysPath,
    key,
    primaryGroup,
    sshDirectoryPath,
    state,
    user,
  })
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

function finalizeAuthorizedKeysCheck(
  state: "absent" | "present",
  keyExists: boolean,
  securityStateIsValid: boolean
): "needs-apply" | "ok" {
  if (state === "present") {
    return keyExists && securityStateIsValid ? "ok" : NEEDS_APPLY
  }
  return keyExists || !securityStateIsValid ? NEEDS_APPLY : "ok"
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
      authorizedKeysPath: `${home}/.ssh/authorized_keys`,
      sshDirectoryPath: `${home}/.ssh`,
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
    key: string
    state: "absent" | "present"
    user: string
  }
): Promise<"needs-apply" | "ok"> {
  const { key, state, user } = parameters
  if (!conn) return NEEDS_APPLY

  const pathResolution = await resolveAuthorizedKeysCheckPaths(conn, user, state)
  if (pathResolution === "needs-apply" || pathResolution === "ok") return pathResolution

  const { authorizedKeysPath, sshDirectoryPath } = pathResolution
  const authKeysPath = shellQuote(authorizedKeysPath)
  const missingPathResult = await checkAuthorizedKeysPathsExist(conn, {
    authorizedKeysPath,
    sshDirectoryPath,
    state,
  })
  if (missingPathResult != null) return missingPathResult

  // R-0000044: whole-line match so check stays consistent with the apply
  // path (which writes/removes whole lines) and never falsely reports a key
  // as present when only its body appears as a substring of another entry.
  const keyExists = await conn.test(`grep -qxF -- ${shellQuote(key)} ${authKeysPath}`)
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

  return finalizeAuthorizedKeysCheck(state, keyExists, securityStateIsValid)
}
