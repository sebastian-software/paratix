/* eslint-disable max-lines -- authorized_keys flow keeps related apply, check, and rewrite helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ExecResult, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  type AuthorizedKeysAccount,
  resolveAuthorizedKeysAccount,
} from "./sshAuthorizedKeysAccount.js"
import {
  type AuthorizedKeysContentPlan,
  type AuthorizedKeysTarget,
  planAuthorizedKeysContent,
} from "./sshAuthorizedKeysContent.js"
import { readAuthorizedKeys, writeAuthorizedKeysStagingFile } from "./sshAuthorizedKeysFile.js"
import {
  authorizedKeysCleanupCommand,
  authorizedKeysReplaceCommand,
  createAuthorizedKeysStagingName,
  prepareAuthorizedKeysDirectory,
  type VerifiedSshDirectory,
} from "./sshAuthorizedKeysReplace.js"

const MUTATION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

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
 * Compare mode and ownership of `~/.ssh` and `authorized_keys`. These probes
 * run as root on the literal paths, but only read metadata for a comparison:
 * a swap can at most make the result `needs-apply` or `changed`, never
 * change, open or disclose anything. The content read and every mutation run
 * as the target user inside the verified directory.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Literal paths and the expected owner.
 * @param parameters.authorizedKeysPath - Literal `authorized_keys` path.
 * @param parameters.primaryGroup - The user's primary group.
 * @param parameters.sshDirectoryPath - Literal `~/.ssh` path.
 * @param parameters.user - The target user.
 * @returns Whether both have the expected mode and owner.
 */
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
 * Map a failure description of a remote step to a module result. R-0000244:
 * mutation helpers return a `failedCommand` ModuleResult on non-zero exit
 * instead of letting `conn.exec` throw an unstructured SSH error.
 *
 * @param label - Module label prefix, e.g. `[ssh.authorizedKeys: alice (present)]`.
 * @param failure - The step's failure description and optional command result.
 * @param failure.message - The failure description.
 * @param failure.result - The failed command result, when one ran.
 * @returns A structured failure.
 */
function stepFailure(
  label: string,
  failure: { message: string; result?: ExecResult }
): ModuleResult {
  if (failure.result === undefined) return failed(`${label} ${failure.message}`)
  return failedCommand(`${label} ${failure.message}`, failure.result)
}

/**
 * Resolve the target account, mapping a failure to a module result.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Getent home, label and target user.
 * @param parameters.home - The validated getent home directory.
 * @param parameters.label - Module label prefix.
 * @param parameters.user - The target user.
 * @returns The account, or a structured failure.
 */
async function resolveAccountOrFailure(
  conn: SshConnection,
  parameters: { home: string; label: string; user: string }
): Promise<{ account: AuthorizedKeysAccount } | { failure: ModuleResult }> {
  const resolved = await resolveAuthorizedKeysAccount(conn, parameters)
  if ("account" in resolved) return resolved
  return { failure: stepFailure(parameters.label, resolved) }
}

/**
 * Stage, verify and publish the computed content in the verified `~/.ssh`,
 * then remove the staging name as the target user.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Verified directory, contents, owner and label.
 * @param parameters.content - The new content as Latin-1 string.
 * @param parameters.label - Module label prefix.
 * @param parameters.original - The read content, or `null` when the file was missing.
 * @param parameters.primaryGroup - The user's primary group name.
 * @param parameters.verified - The verified `~/.ssh`.
 * @returns `null` on success, otherwise a structured failure.
 */
async function rewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    content: string
    label: string
    original: null | string
    primaryGroup: string
    verified: VerifiedSshDirectory
  }
): Promise<ModuleResult | null> {
  const { content, label, original, primaryGroup, verified } = parameters
  // R-0000181: temp file lives in the same filesystem as the destination so
  // `mv -T` is atomic (single rename(2)) and so NFS root_squash hosts do not
  // hit cross-filesystem copy fallbacks.
  const staging = await createAuthorizedKeysStagingName(conn, verified)
  if (!("stagedName" in staging)) return stepFailure(label, staging)
  const { stagedName } = staging

  try {
    const stageFailure = await writeAuthorizedKeysStagingFile(conn, {
      account: verified.account,
      content,
      expectedSshDirectory: verified.expectedSshDirectory,
      identity: verified.identity,
      stagedName,
    })
    if (stageFailure) return stepFailure(label, stageFailure)

    const replace = await conn.exec(
      authorizedKeysReplaceCommand({ content, original, primaryGroup, stagedName, verified }),
      MUTATION_EXEC_OPTS
    )
    if (replace.code !== 0)
      return failedCommand(`${label} failed to replace authorized_keys`, replace)
    return null
  } finally {
    // The staging name is removed as the target user inside the verified
    // `~/.ssh`. The base64 payload never lives in `~/.ssh`; its private
    // directory is removed by `writeAuthorizedKeysStagingFile` itself.
    await conn.exec(authorizedKeysCleanupCommand(verified, stagedName), MUTATION_EXEC_OPTS)
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
 * @param parameters - Account, paths, owner and target entry.
 * @param parameters.account - The resolved target account.
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
    account: AuthorizedKeysAccount
    authorizedKeysPath: string
    primaryGroup: string
    sshDirectoryPath: string
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<{ content: string; original: null | string } | { result: ModuleResult }> {
  const {
    account,
    authorizedKeysPath,
    primaryGroup,
    sshDirectoryPath,
    target,
    target: { state },
    user,
  } = parameters
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  // The read runs as the target user and guards against a symlinked `.ssh`
  // and `authorized_keys`; a missing directory or file reads as `missing`,
  // the normal append case.
  const read = await readAuthorizedKeys(conn, account)
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
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  if (!conn) return failed(`${label} SSH connection is required`)

  const { failure: homeFailure, home } = await resolveApplyHome(conn, { state, user })
  if (homeFailure) return homeFailure
  if (home == null) return { status: "ok" }

  const sshDirectoryPath = `${home}${SSH_DIRECTORY_SUFFIX}`
  const authorizedKeysPath = `${sshDirectoryPath}/${AUTHORIZED_KEYS_FILE_NAME}`

  if (state === "absent") {
    const needsGuard = await absentAuthorizedKeysPathNeedsGuard(conn, authorizedKeysPath)
    if (!needsGuard) return { status: "ok" }
  }

  return planAndRewriteAuthorizedKeys(conn, {
    authorizedKeysPath,
    home,
    label,
    sshDirectoryPath,
    target,
    user,
  })
}

/**
 * Resolve owner and account, read and plan, then prepare and rewrite.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Literal paths, getent home, label, target entry and user.
 * @param parameters.authorizedKeysPath - Literal `authorized_keys` path.
 * @param parameters.home - The validated getent home directory.
 * @param parameters.label - Module label prefix.
 * @param parameters.sshDirectoryPath - Literal `~/.ssh` path.
 * @param parameters.target - The desired entry.
 * @param parameters.user - The target user.
 * @returns `ok`, `changed`, or a structured failure.
 */
async function planAndRewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    home: string
    label: string
    sshDirectoryPath: string
    target: AuthorizedKeysTarget
    user: string
  }
): Promise<ModuleResult> {
  const { home, label, user } = parameters
  // R-0000065: resolve the primary group exactly once for the duration of
  // this apply so the directory chown, the authorized_keys ownership check
  // and the matching `stat` comparison all reference the same group identity.
  const primaryGroup = await resolvePrimaryGroup(conn, user)
  const resolved = await resolveAccountOrFailure(conn, { home, label, user })
  if ("failure" in resolved) return resolved.failure
  const { account } = resolved

  const planned = await planAuthorizedKeysRewrite(conn, { ...parameters, account, primaryGroup })
  if ("result" in planned) return planned.result

  return prepareAndRewriteAuthorizedKeys(conn, { account, home, label, planned, primaryGroup })
}

/**
 * Prepare `~/.ssh` and publish the planned content through the canonical
 * `.ssh` path.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Account, planned content, owner and label.
 * @param parameters.account - The resolved target account.
 * @param parameters.home - The getent home, named when it does not exist.
 * @param parameters.label - Module label prefix.
 * @param parameters.planned - The content to stage and the read original.
 * @param parameters.planned.content - The new content as Latin-1 string.
 * @param parameters.planned.original - The read content, or `null` when the file was missing.
 * @param parameters.primaryGroup - The user's primary group.
 * @returns `changed`, or a structured failure.
 */
async function prepareAndRewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    account: AuthorizedKeysAccount
    home: string
    label: string
    planned: { content: string; original: null | string }
    primaryGroup: string
  }
): Promise<ModuleResult> {
  const { account, home, label, planned, primaryGroup } = parameters
  const { expectedSshDirectory } = account
  if (expectedSshDirectory === null) {
    return failed(`${label} home directory ${home} does not exist; create it before adding keys`)
  }
  // R-0000765: preparing `.ssh` stays a single `set -e` exec. It creates a
  // missing `.ssh` as the target user, verifies the directory by its
  // physical path and captures its identity for every later step.
  const prepared = await prepareAuthorizedKeysDirectory(conn, { account, expectedSshDirectory })
  if (!("verified" in prepared)) return stepFailure(label, prepared)

  // The live-file comparison inside the final replace covers any change
  // between the read and the replace.
  const rewriteFailure = await rewriteAuthorizedKeys(conn, {
    content: planned.content,
    label,
    original: planned.original,
    primaryGroup,
    verified: prepared.verified,
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
      home: string
      sshDirectoryPath: string
    }
> {
  try {
    const home = await resolveHome(conn, user)
    return {
      authorizedKeysPath: `${home}${SSH_DIRECTORY_SUFFIX}/${AUTHORIZED_KEYS_FILE_NAME}`,
      home,
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

  const { authorizedKeysPath, home, sshDirectoryPath } = pathResolution
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
  // a missing privilege-drop tool, blocking conflicts and the options guard
  // all defer to apply.
  const resolved = await resolveAuthorizedKeysAccount(conn, { home, user })
  if (!("account" in resolved)) return NEEDS_APPLY
  const read = await readAuthorizedKeys(conn, resolved.account)
  if (read.kind === "failed") return NEEDS_APPLY
  return planAuthorizedKeysContent(read.content, target).kind === "converged" ? "ok" : NEEDS_APPLY
}

/**
 * Resolve the account and read `authorized_keys` as the target user for the
 * dry-run. A missing privilege-drop tool fails apply, so dry-run reports it
 * too; a symlinked `.ssh` or `authorized_keys` fails the read, so dry-run
 * reports `failed` like apply would.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Getent home, label and target user.
 * @param parameters.home - The validated getent home directory.
 * @param parameters.label - Module label prefix.
 * @param parameters.user - The target user.
 * @returns The read content, or a structured failure.
 */
async function readForDryRun(
  conn: SshConnection,
  parameters: { home: string; label: string; user: string }
): Promise<{ content: null | string } | { failure: ModuleResult }> {
  const resolved = await resolveAccountOrFailure(conn, parameters)
  if ("failure" in resolved) return resolved
  const read = await readAuthorizedKeys(conn, resolved.account)
  if (read.kind === "read") return { content: read.content }
  return {
    failure: failedCommand(`${parameters.label} failed to read authorized_keys`, read.result),
  }
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

  const { authorizedKeysPath, home, sshDirectoryPath } = pathResolution
  const label = `[ssh.authorizedKeys: ${user} (${state})]`
  const read = await readForDryRun(conn, { home, label, user })
  if ("failure" in read) return read.failure

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
