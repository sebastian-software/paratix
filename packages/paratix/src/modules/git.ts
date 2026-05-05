import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const

function validateCloneRepo(repo: string): void {
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
 * Clone a repository into a new directory, optionally at a specific ref.
 *
 * @param conn - The SSH connection to the remote host.
 * @param parameters - Clone parameters including repo, destination, and optional reference.
 * @returns A promise that resolves when the clone is complete.
 */
async function cloneRepo(conn: SshConnection, parameters: GitCloneParameters): Promise<boolean> {
  const { destination, reference, repo } = parameters
  if (reference !== undefined && reference !== "") {
    // Try --branch first (works for branches and tags, not bare SHAs).
    const result = await conn.exec(
      `git clone --branch ${shellQuote(reference)} ${shellQuote(repo)} ${shellQuote(destination)}`,
      EXEC_OPTS
    )
    // Fallback: clone without --branch then checkout (handles bare commit SHAs).
    if (result.code !== 0) {
      const fallback = await conn.exec(
        `git clone ${shellQuote(repo)} ${shellQuote(destination)}`,
        EXEC_OPTS
      )
      if (fallback.code !== 0) return false
      const checkout = await conn.exec(
        `git -C ${shellQuote(destination)} checkout ${shellQuote(reference)}`,
        EXEC_OPTS
      )
      return checkout.code === 0
    }
    return true
  }
  const cloneResult = await conn.exec(
    `git clone ${shellQuote(repo)} ${shellQuote(destination)}`,
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
 * Update an existing repository to a specific ref, or pull latest if no ref given.
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
    const fetch = await conn.exec(
      `git -C ${shellQuote(destination)} fetch origin --tags --force`,
      EXEC_OPTS
    )
    if (fetch.code !== 0) return false
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
  const pull = await conn.exec(`git -C ${shellQuote(destination)} pull`, EXEC_OPTS)
  return pull.code === 0
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
    `git -C ${shellQuote(destination)} ls-remote origin ${shellQuote(reference)}`,
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
    `git -C ${shellQuote(destination)} ls-remote origin HEAD`,
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
   * updated instead (fetch + checkout + reset). When no `ref` is specified, a
   * plain `git pull` is performed on an existing clone.
   *
   * @param repo - The repository URL to clone.
   * @param destination - The destination path on the remote host.
   * @param options - Optional settings.
   * @param options.ref - A branch, tag, or commit SHA to check out.
   * @returns A Module that manages the cloned repository.
   */
  clone(repo: string, destination: string, options?: { ref?: string }): Module {
    validateCloneRepo(repo)

    const reference = options?.ref
    const gitDirectory = `${destination}/.git`
    const parameters: GitCloneParameters = { destination, reference, repo }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[git.clone: ${destination}] SSH connection is required`)

        const directoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        const success = await (directoryExists
          ? (await ensureOriginUrl(conn, parameters)) && (await updateRepo(conn, parameters))
          : cloneRepo(conn, parameters))

        return success
          ? { status: "changed" }
          : failed(`[git.clone: ${destination}] git clone or update failed`)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const gitDirectoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        if (!gitDirectoryExists) return NEEDS_APPLY
        const currentOrigin = await readOriginUrl(conn, destination)
        if (currentOrigin !== repo) return NEEDS_APPLY

        const headResult = await conn.exec(
          `git -C ${shellQuote(destination)} rev-parse HEAD`,
          SILENT
        )
        const head = headResult.stdout.trim()

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
