import { posix } from "node:path"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { hasSensitiveQueryParameters } from "./curlHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000730: `git.clone` invokes `rm -rf -- <destination>` during fallback
// cleanup when the first clone attempt fails. Without strict validation of the
// destination argument a caller could pass a path like "/", a relative path
// that resolves unexpectedly, a leading "-" that Git would interpret as an
// option, or whitespace-padded input that bypasses later checks. The pattern
// mirrors `validateAbsentPath` in file.ts: trim, reject empty, require
// absolute and normalized POSIX paths, refuse "/" outright, and reject leading
// dashes. Validation runs synchronously in the module constructor so the
// invariant is established before any async exec / rm -rf path can execute.
function validateCloneDestination(destination: string): void {
  const trimmedDestination = destination.trim()
  if (trimmedDestination.length === 0) {
    throw new Error("git.clone: destination must not be empty")
  }

  if (trimmedDestination !== destination) {
    throw new Error(`git.clone: destination must not start or end with whitespace: ${destination}`)
  }

  if (trimmedDestination.startsWith("-")) {
    throw new Error(
      `git.clone: destination must not start with '-' because Git could parse it as an option: ${destination}`
    )
  }

  if (!posix.isAbsolute(trimmedDestination)) {
    throw new Error(`git.clone: destination must be an absolute path: ${destination}`)
  }

  const normalizedDestination = posix.normalize(trimmedDestination)
  if (normalizedDestination === "/") {
    throw new Error(`git.clone: refusing to use destructive destination path: ${destination}`)
  }

  if (trimmedDestination !== normalizedDestination) {
    throw new Error(`git.clone: destination must be normalized: ${destination}`)
  }
}

function validateCloneRepo(repo: string): void {
  if (repo.startsWith("-")) {
    throw new Error(
      "git.clone repo must not start with '-' because Git could parse it as an option."
    )
  }

  let parsed: URL
  try {
    parsed = new URL(repo)
  } catch {
    return
  }

  if (
    (parsed.protocol === "http:" || parsed.protocol === "https:") &&
    (parsed.username.length > 0 || parsed.password.length > 0)
  ) {
    throw new Error(
      "git.clone repo URLs must not embed credentials. Use SSH with deploy keys or an SSH agent instead."
    )
  }

  if (
    (parsed.protocol === "http:" || parsed.protocol === "https:") &&
    hasSensitiveQueryParameters(parsed)
  ) {
    throw new Error(
      "git.clone repo URLs must not contain sensitive query parameters. Use SSH with deploy keys or an SSH agent instead."
    )
  }
}

// R-0000278: defense-in-depth — refuse refs that contain whitespace, control
// characters, backslashes, or `..` sequences in addition to the leading-`-`
// rule. shellQuote already neutralises shell metacharacters at the exec
// boundary, but newlines in a ref still corrupt `output.split("\n")` and a
// backslash can fool downstream consumers. The pattern below mirrors the
// strictness applied to apt resource names and POSIX user/group names.
// R-0000482: also reject apostrophes. `updateRepo` and `isRemoteTrackingBranch`
// build `origin/${shellQuote(reference)}` paths via concatenation, so a single
// quote inside the reference would otherwise corrupt the resulting shell token.
const CLONE_REFERENCE_DISALLOWED_PATTERN = /[\s\\']|\.\./v

function validateCloneReference(reference: string | undefined): void {
  if (reference === undefined || reference === "") return
  if (reference.startsWith("-")) {
    throw new Error(
      "git.clone ref must not start with '-' because Git could parse it as an option."
    )
  }
  if (CLONE_REFERENCE_DISALLOWED_PATTERN.test(reference)) {
    throw new Error(
      "git.clone ref must not contain whitespace, backslashes, apostrophes, or '..' sequences."
    )
  }
}

/** Parameters for a git clone or update operation. */
type GitCloneParameters = {
  /** The destination path on the remote host. */
  destination: string
  /** An optional branch, tag, or commit SHA to check out. */
  reference?: string
  /** The repository URL to clone. */
  repo: string
}

/**
 * Remove the destination directory before retrying a clone. Used after a
 * failed first-pass clone leaves the destination partially populated; without
 * this cleanup the fallback `git clone` aborts with "destination path already
 * exists". R-0000223.
 *
 * @param conn - The SSH connection to the remote host.
 * @param destination - The destination path on the remote host.
 */
async function cleanupFailedCloneDestination(
  conn: SshConnection,
  destination: string
): Promise<void> {
  await conn.exec(`rm -rf -- ${shellQuote(destination)}`, EXEC_OPTS)
}

/**
 * Run the fallback path of a referenced clone: plain `git clone` followed by
 * `git checkout <reference>`. Used after `git clone --branch <ref>` fails
 * (e.g. because the ref is a bare commit SHA). R-0000642: when the clone
 * succeeds but the checkout fails, the worktree is at the repository's
 * default branch instead of the requested reference; remove the destination
 * the apply just created so the host stays in the original state.
 *
 * @param conn - The SSH connection to the remote host.
 * @param parameters - Clone parameters including destination, reference, and repo.
 * @param destinationExistedBeforeClone - Whether the destination existed before this apply.
 * @returns A promise that resolves to `true` when the fallback clone + checkout succeeded.
 */
async function cloneRepoFallback(
  conn: SshConnection,
  parameters: { reference: string } & GitCloneParameters,
  destinationExistedBeforeClone: boolean
): Promise<boolean> {
  const { destination, reference, repo } = parameters
  // Fallback: clone without --branch then checkout (handles bare commit SHAs).
  const fallback = await conn.exec(
    `git clone -- ${shellQuote(repo)} ${shellQuote(destination)}`,
    EXEC_OPTS
  )
  if (fallback.code !== 0) return false
  const checkout = await conn.exec(
    `git -C ${shellQuote(destination)} checkout ${shellQuote(reference)}`,
    EXEC_OPTS
  )
  if (checkout.code === 0) return true
  // R-0000642: the fallback clone left a worktree on the requested
  // destination at the repository's default branch, but the subsequent
  // checkout to the caller-provided reference failed. Without cleanup the
  // host is left in a state the caller never asked for. Only remove the
  // directory when this apply created it; if the path existed beforehand
  // (e.g. a user staged work in it) the original cleanup guard already
  // skipped removal and we mirror that decision here.
  if (!destinationExistedBeforeClone) {
    await cleanupFailedCloneDestination(conn, destination)
  }
  return false
}

/**
 * Clone a repository into a new directory, optionally at a specific ref.
 *
 * When `reference` is non-empty the implementation first attempts a single
 * `git clone --branch <ref>`. If that fails (e.g. because the ref is a bare
 * commit SHA which `--branch` cannot accept) the destination is removed before
 * falling back to a plain `git clone` + `git checkout <ref>`. R-0000223:
 * without the destination cleanup the fallback clone fails immediately with
 * `destination path … already exists` because the first attempt may have left
 * a partial worktree behind.
 *
 * @param conn - The SSH connection to the remote host.
 * @param parameters - Clone parameters including repo, destination, and optional reference.
 * @returns A promise that resolves to `true` when the clone is complete.
 */
async function cloneRepo(conn: SshConnection, parameters: GitCloneParameters): Promise<boolean> {
  const { destination, reference, repo } = parameters
  if (reference !== undefined && reference !== "") {
    const destinationExistedBeforeClone = await conn.test(`test -e ${shellQuote(destination)}`)
    // Try --branch first (works for branches and tags, not bare SHAs).
    const result = await conn.exec(
      `git clone --branch ${shellQuote(reference)} -- ${shellQuote(repo)} ${shellQuote(destination)}`,
      EXEC_OPTS
    )
    if (result.code === 0) return true
    // R-0000223: remove any partially-populated destination before retrying;
    // a leftover .git or refs/ would cause the fallback clone to abort.
    if (!destinationExistedBeforeClone) {
      await cleanupFailedCloneDestination(conn, destination)
    }
    return cloneRepoFallback(conn, { destination, reference, repo }, destinationExistedBeforeClone)
  }
  const cloneResult = await conn.exec(
    `git clone -- ${shellQuote(repo)} ${shellQuote(destination)}`,
    EXEC_OPTS
  )
  return cloneResult.code === 0
}

/**
 * Probe whether a reference exists as a remote-tracking branch on `origin`.
 *
 * Uses `git for-each-ref` against `refs/remotes/origin/<reference>` to detect
 * a remote-tracking branch deterministically. Returns `true` only when the
 * probe prints a matching ref name.
 *
 * @param conn - The SSH connection to the remote host.
 * @param destination - The repository path on the remote host.
 * @param reference - The branch, tag, or commit SHA to probe.
 * @returns Whether the reference exists as a remote-tracking branch.
 */
async function isRemoteTrackingBranch(
  conn: SshConnection,
  destination: string,
  reference: string
): Promise<boolean> {
  const probe = await conn.exec(
    `git -C ${shellQuote(destination)} for-each-ref --format=%(refname) refs/remotes/origin/${shellQuote(reference)}`,
    EXEC_OPTS
  )
  if (probe.code !== 0) return false
  return probe.stdout.trim() !== ""
}

/**
 * Update an existing repository to a specific ref, or to remote HEAD if no ref is given.
 *
 * When a reference is provided, the function fetches all tags and then checks
 * out the reference. It then probes whether the reference exists as a
 * remote-tracking branch on `origin`. If so, it runs
 * `reset --hard origin/<reference>` to advance to the branch tip. Otherwise it
 * runs `reset --hard <reference>` directly so that tags and bare commit SHAs
 * resolve to the correct commit even when a branch with the same name exists.
 *
 * @param conn - The SSH connection to the remote host.
 * @param parameters - Clone parameters including destination and optional reference.
 * @returns A promise that resolves when the update is complete.
 */
async function updateRepo(conn: SshConnection, parameters: GitCloneParameters): Promise<boolean> {
  const { destination, reference } = parameters
  if (reference !== undefined && reference !== "") {
    const fetchResult = await conn.exec(
      `git -C ${shellQuote(destination)} fetch origin --tags --force`,
      EXEC_OPTS
    )
    if (fetchResult.code !== 0) return false
    const checkout = await conn.exec(
      `git -C ${shellQuote(destination)} checkout ${shellQuote(reference)}`,
      EXEC_OPTS
    )
    if (checkout.code !== 0) return false
    const isBranch = await isRemoteTrackingBranch(conn, destination, reference)
    const resetTarget = isBranch ? `origin/${shellQuote(reference)}` : shellQuote(reference)
    const reset = await conn.exec(
      `git -C ${shellQuote(destination)} reset --hard ${resetTarget}`,
      EXEC_OPTS
    )
    return reset.code === 0
  }
  const fetchHeadResult = await conn.exec(
    `git -C ${shellQuote(destination)} fetch origin HEAD`,
    EXEC_OPTS
  )
  if (fetchHeadResult.code !== 0) return false
  const resetHeadResult = await conn.exec(
    `git -C ${shellQuote(destination)} reset --hard FETCH_HEAD`,
    EXEC_OPTS
  )
  return resetHeadResult.code === 0
}

async function readOriginUrl(conn: SshConnection, destination: string): Promise<null | string> {
  const result = await conn.exec(
    `git -C ${shellQuote(destination)} remote get-url origin`,
    EXEC_OPTS
  )
  if (result.code !== 0) return null
  const remoteUrl = result.stdout.trim()
  return remoteUrl.length === 0 ? null : remoteUrl
}

// R-0000279: read the current worktree HEAD so apply can detect when an
// update would not actually move the checkout. EXEC_OPTS keeps a missing or
// detached HEAD from throwing; we only need the commit hash for the
// idempotency comparison.
async function readWorktreeHead(conn: SshConnection, destination: string): Promise<null | string> {
  const result = await conn.exec(`git -C ${shellQuote(destination)} rev-parse HEAD`, EXEC_OPTS)
  if (result.code !== 0) return null
  const head = result.stdout.trim()
  return head.length === 0 ? null : head
}

async function ensureOriginUrl(
  conn: SshConnection,
  parameters: GitCloneParameters
): Promise<boolean> {
  const { destination, repo } = parameters
  const currentOrigin = await readOriginUrl(conn, destination)
  if (currentOrigin === repo) return true

  const command =
    currentOrigin == null
      ? `git -C ${shellQuote(destination)} remote add origin ${shellQuote(repo)}`
      : `git -C ${shellQuote(destination)} remote set-url origin ${shellQuote(repo)}`
  const result = await conn.exec(command, EXEC_OPTS)
  return result.code === 0
}

/**
 * Resolve a reference to a commit SHA by querying the remote via `git ls-remote`.
 *
 * Remote branches are preferred over same-named tags to match `apply`, which
 * resets branch refs to `origin/<ref>`. For tags, the dereferenced line
 * (`refs/tags/<ref>^{}`) is preferred because it contains the commit SHA rather
 * than the tag object SHA. When `ls-remote` returns no output (e.g. because the
 * reference is already a bare commit SHA), the reference string is returned
 * as-is.
 *
 * @param conn - The SSH connection to the remote host.
 * @param destination - The repository path on the remote host.
 * @param reference - The branch, tag, or commit SHA to resolve.
 * @returns The resolved commit SHA.
 */
async function resolveRemoteReference(
  conn: SshConnection,
  destination: string,
  reference: string
): Promise<string> {
  const result = await conn.exec(
    `git -C ${shellQuote(destination)} ls-remote -- origin ${shellQuote(reference)}`,
    EXEC_OPTS
  )

  const output = result.stdout.trim()
  if (output === "") return reference

  const lines = output.split("\n")
  const branchReference = `refs/heads/${reference}`

  for (const line of lines) {
    const [sha, referenceName] = line.split("\t")
    if (referenceName === branchReference) return sha
  }

  // Prefer the dereferenced tag line (^{}) when present.
  for (const line of lines) {
    if (line.includes("^{}")) {
      return line.split("\t")[0]
    }
  }

  return lines[0].split("\t")[0]
}

/**
 * Resolve the remote default branch HEAD to a commit SHA.
 *
 * @param conn - The SSH connection to the remote host.
 * @param destination - The repository path on the remote host.
 * @returns The remote HEAD SHA, or `null` when it cannot be resolved.
 */
async function resolveRemoteHead(conn: SshConnection, destination: string): Promise<null | string> {
  const result = await conn.exec(
    `git -C ${shellQuote(destination)} ls-remote -- origin HEAD`,
    EXEC_OPTS
  )
  if (result.code !== 0) return null

  const output = result.stdout.trim()
  if (output === "") return null

  return output.split("\n")[0].split("\t")[0]
}

/**
 * Modules for managing Git repositories on the remote host.
 */
export const git = {
  /**
   * Ensure a Git repository is cloned to the given destination and optionally
   * checked out at a specific ref (branch, tag, or commit).
   *
   * If the destination directory does not yet contain a `.git` folder, the
   * repository is cloned from scratch. If it already exists, the repository is
   * updated instead (fetch + checkout + reset). When no `ref` is specified,
   * the existing clone is reset to the current remote default branch HEAD.
   *
   * @param repo - The repository URL to clone.
   * @param destination - The destination path on the remote host.
   * @param options - Optional settings.
   * @param options.ref - A branch, tag, or commit SHA to check out.
   * @returns A Module that manages the cloned repository.
   */
  clone(repo: string, destination: string, options?: { ref?: string }): Module {
    // R-0000730: validate destination first because cleanup paths interpolate
    // it directly into `rm -rf` invocations. Synchronous throw before any
    // async work prevents a malformed path from reaching the SSH layer.
    validateCloneDestination(destination)
    validateCloneRepo(repo)

    const reference = options?.ref
    validateCloneReference(reference)
    const gitDirectory = `${destination}/.git`
    const parameters: GitCloneParameters = { destination, reference, repo }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[git.clone: ${destination}] SSH connection is required`)

        const directoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        if (!directoryExists) {
          const cloned = await cloneRepo(conn, parameters)
          return cloned
            ? { status: "changed" }
            : failed(`[git.clone: ${destination}] git clone or update failed`)
        }

        // R-0000279: differentiate a true update from a no-op rerun. `updateRepo`
        // performs `fetch + reset --hard`, which always succeeds even when the
        // worktree was already at the desired commit. Without a HEAD comparison
        // every apply would announce `changed` and uselessly fire downstream
        // signals (service.reload, ...). compose.up:composeUpReportedChange
        // follows the same pattern.
        const originReady = await ensureOriginUrl(conn, parameters)
        if (!originReady) return failed(`[git.clone: ${destination}] git clone or update failed`)

        const previousHead = await readWorktreeHead(conn, destination)
        const updated = await updateRepo(conn, parameters)
        if (!updated) return failed(`[git.clone: ${destination}] git clone or update failed`)

        const currentHead = await readWorktreeHead(conn, destination)
        if (previousHead !== null && currentHead !== null && previousHead === currentHead) {
          return { status: "ok" }
        }
        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const gitDirectoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        if (!gitDirectoryExists) return NEEDS_APPLY
        const currentOrigin = await readOriginUrl(conn, destination)
        if (currentOrigin !== repo) return NEEDS_APPLY

        const head = await readWorktreeHead(conn, destination)
        if (head === null) return NEEDS_APPLY

        if (reference === undefined || reference === "") {
          const remoteHead = await resolveRemoteHead(conn, destination)
          return remoteHead != null && head === remoteHead ? "ok" : NEEDS_APPLY
        }

        const resolved = await resolveRemoteReference(conn, destination, reference)

        return head === resolved ? "ok" : NEEDS_APPLY
      },
      name: `git.clone: ${destination}`,
    }
  },
}
