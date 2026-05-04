import { failed } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

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
 * @param conn - The active SSH connection.
 * @param user - The target user.
 * @returns The user's primary group name.
 */
async function resolvePrimaryGroup(conn: SshConnection, user: string): Promise<string> {
  const primaryGroup = await conn.output(`id -gn ${shellQuote(user)}`)
  if (primaryGroup.length === 0) return user
  return primaryGroup
}

function isUnsafeAuthorizedKeysHomeError(error: unknown, user: string): boolean {
  return (
    error instanceof Error &&
    error.message === `[ssh.authorizedKeys: ${user}] failed to resolve a safe home directory`
  )
}

async function resolveApplyHome(
  conn: SshConnection,
  parameters: {
    state: "absent" | "present"
    user: string
  }
): Promise<null | string> {
  const { state, user } = parameters
  try {
    return await resolveHome(conn, user)
  } catch (error) {
    if (state === "absent" && isUnsafeAuthorizedKeysHomeError(error, user)) return null
    throw error
  }
}

async function createAuthorizedKeysTemporaryPath(
  conn: SshConnection,
  sshDirectoryPath: string
): Promise<string> {
  const template = `${sshDirectoryPath}/.authorized-keys.XXXXXX`
  const temporaryPath = await conn.output(`mktemp ${shellQuote(template)}`)
  return validateMktempPath(sshDirectoryPath, temporaryPath, ".authorized-keys")
}

async function ensureAuthorizedKeysIsNotSymlink(
  conn: SshConnection,
  authorizedKeysPath: string
): Promise<void> {
  await conn.exec(
    `[ ! -L ${shellQuote(authorizedKeysPath)} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`,
    { silent: true }
  )
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
): Promise<void> {
  const { authorizedKeysPath, key, primaryGroup, sshDirectoryPath, state, user } = parameters
  const temporaryPath = await createAuthorizedKeysTemporaryPath(conn, sshDirectoryPath)

  try {
    if (state === "present") {
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then awk '1' ${shellQuote(authorizedKeysPath)}; grep -qxF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)} || printf '%s\\n' ${shellQuote(key)}; else printf '%s\\n' ${shellQuote(key)}; fi; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    } else {
      // R-0000044: use `grep -vxF` (whole-line match) to mirror the
      // present branch's `grep -qxF` and avoid removing collateral entries
      // whose key body is a substring of the key being deleted (e.g. a key
      // appearing again with options-prefix or a different comment).
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then grep -vxF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)} || true; fi; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    }

    // R-0000065: chown to the user and the user's resolved primary group
    // instead of `${user}:${user}`. This preserves the existing primary
    // group on hosts where it is not equal to the username (e.g.
    // `deploy:users`, `www-data:www-data`) and prevents a drift loop where
    // `apply` overwrites the semantically correct group ownership only to
    // see `check` go green on the next run.
    await conn.exec(
      `chmod 600 ${shellQuote(temporaryPath)} && chown ${shellQuote(user)}:${shellQuote(primaryGroup)} ${shellQuote(temporaryPath)} && mv ${shellQuote(temporaryPath)} ${shellQuote(authorizedKeysPath)} && chmod 600 ${shellQuote(authorizedKeysPath)} && chown ${shellQuote(user)}:${shellQuote(primaryGroup)} ${shellQuote(authorizedKeysPath)}`,
      { silent: true }
    )
  } finally {
    await conn.exec(`rm -f ${shellQuote(temporaryPath)}`, { silent: true })
  }
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

  const home = await resolveApplyHome(conn, { state, user })
  if (home == null) return { status: "ok" }

  // R-0000065: resolve the primary group exactly once for the duration of
  // this apply so the directory chown, the authorized_keys chown and the
  // matching `stat` comparison all reference the same group identity.
  const primaryGroup = await resolvePrimaryGroup(conn, user)
  const sshDirectoryPath = `${home}/.ssh`
  const directory = shellQuote(sshDirectoryPath)
  const authorizedKeysPath = `${home}/.ssh/authorized_keys`

  await conn.exec(
    `mkdir -p ${directory} && chmod 700 ${directory} && chown ${shellQuote(user)}:${shellQuote(primaryGroup)} ${directory}`,
    { silent: true }
  )
  await ensureAuthorizedKeysIsNotSymlink(conn, authorizedKeysPath)
  await rewriteAuthorizedKeys(conn, {
    authorizedKeysPath,
    key,
    primaryGroup,
    sshDirectoryPath,
    state,
    user,
  })

  return { status: "changed" }
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
