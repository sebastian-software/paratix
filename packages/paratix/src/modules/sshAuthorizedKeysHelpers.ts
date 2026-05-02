import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

async function resolveHome(conn: SshConnection, user: string): Promise<string> {
  const home = await conn.output(`getent passwd ${shellQuote(user)} | cut -d: -f6`)
  if (home.length === 0 || home === "/") {
    throw new Error(`[ssh.authorizedKeys: ${user}] failed to resolve a safe home directory`)
  }
  return home
}

function isUnsafeAuthorizedKeysHomeError(error: unknown, user: string): boolean {
  return (
    error instanceof Error &&
    error.message === `[ssh.authorizedKeys: ${user}] failed to resolve a safe home directory`
  )
}

async function createAuthorizedKeysTemporaryPath(
  conn: SshConnection,
  sshDirectoryPath: string
): Promise<string> {
  const template = `${sshDirectoryPath}/.authorized-keys.XXXXXX`
  return conn.output(`mktemp ${shellQuote(template)}`)
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
    sshDirectoryPath: string
    user: string
  }
): Promise<boolean> {
  const { authorizedKeysPath, sshDirectoryPath, user } = parameters

  const isAuthorizedKeysSymlink = await conn.test(`[ -L ${shellQuote(authorizedKeysPath)} ]`)
  if (isAuthorizedKeysSymlink) return false

  const sshDirectoryState = await conn.output(
    `stat -c '%a %U %G %F' ${shellQuote(sshDirectoryPath)}`
  )
  if (sshDirectoryState.trim() !== `700 ${user} ${user} directory`) return false

  const authorizedKeysState = await conn.output(
    `stat -c '%a %U %G %F' ${shellQuote(authorizedKeysPath)}`
  )
  return authorizedKeysState.trim() === `600 ${user} ${user} regular file`
}

async function rewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    key: string
    sshDirectoryPath: string
    state: "absent" | "present"
    user: string
  }
): Promise<void> {
  const { authorizedKeysPath, key, sshDirectoryPath, state, user } = parameters
  const temporaryPath = await createAuthorizedKeysTemporaryPath(conn, sshDirectoryPath)

  try {
    if (state === "present") {
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then cat ${shellQuote(authorizedKeysPath)}; grep -qxF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)} || printf '%s\\n' ${shellQuote(key)}; else printf '%s\\n' ${shellQuote(key)}; fi; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    } else {
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then grep -vF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)} || true; fi; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    }

    await conn.exec(
      `chmod 600 ${shellQuote(temporaryPath)} && chown ${shellQuote(user)}:${shellQuote(user)} ${shellQuote(temporaryPath)} && mv ${shellQuote(temporaryPath)} ${shellQuote(authorizedKeysPath)} && chmod 600 ${shellQuote(authorizedKeysPath)} && chown ${shellQuote(user)}:${shellQuote(user)} ${shellQuote(authorizedKeysPath)}`,
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

  const home = await resolveHome(conn, user)
  const sshDirectoryPath = `${home}/.ssh`
  const directory = shellQuote(sshDirectoryPath)
  const authorizedKeysPath = `${home}/.ssh/authorized_keys`

  await conn.exec(
    `mkdir -p ${directory} && chmod 700 ${directory} && chown ${shellQuote(user)}:${shellQuote(user)} ${directory}`,
    { silent: true }
  )
  await ensureAuthorizedKeysIsNotSymlink(conn, authorizedKeysPath)
  await rewriteAuthorizedKeys(conn, {
    authorizedKeysPath,
    key,
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

  const keyExists = await conn.test(`grep -qF -- ${shellQuote(key)} ${authKeysPath}`)
  const securityStateIsValid = await authorizedKeysSecurityStateIsValid(conn, {
    authorizedKeysPath,
    sshDirectoryPath,
    user,
  })

  return finalizeAuthorizedKeysCheck(state, keyExists, securityStateIsValid)
}
