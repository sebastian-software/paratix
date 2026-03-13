import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const

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
 * Update an existing repository to a specific ref, or pull latest if no ref given.
 *
 * When a reference is provided, the function fetches all tags and then checks
 * out the reference. It first attempts `reset --hard origin/<reference>` to
 * handle tracking branches. If that fails (e.g. for tags or bare commit SHAs
 * that have no remote-tracking counterpart), it falls back to
 * `reset --hard <reference>` directly.
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
    const branchReset = await conn.exec(
      `git -C ${shellQuote(destination)} reset --hard origin/${shellQuote(reference)}`,
      EXEC_OPTS
    )
    // Fallback for tags and bare commit SHAs that have no remote-tracking ref.
    if (branchReset.code !== 0) {
      const directReset = await conn.exec(
        `git -C ${shellQuote(destination)} reset --hard ${shellQuote(reference)}`,
        EXEC_OPTS
      )
      return directReset.code === 0
    }
    return true
  }
  const pull = await conn.exec(`git -C ${shellQuote(destination)} pull`, EXEC_OPTS)
  return pull.code === 0
}

/**
 * Resolve a reference to a commit SHA, trying branch first then tag/commit fallback.
 *
 * @param conn - The SSH connection to the remote host.
 * @param destination - The repository path on the remote host.
 * @param reference - The branch, tag, or commit SHA to resolve.
 * @returns The resolved commit SHA.
 */
async function resolveReference(
  conn: SshConnection,
  destination: string,
  reference: string
): Promise<string> {
  const branchResult = await conn.exec(
    `git -C ${shellQuote(destination)} rev-parse origin/${shellQuote(reference)}`,
    EXEC_OPTS
  )

  if (branchResult.code === 0) {
    return branchResult.stdout.trim()
  }

  const commitReference = `${reference}^{commit}`
  const fallbackResult = await conn.exec(
    `git -C ${shellQuote(destination)} rev-parse ${shellQuote(commitReference)}`,
    EXEC_OPTS
  )
  return fallbackResult.stdout.trim()
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
    const reference = options?.ref
    const gitDirectory = `${destination}/.git`
    const parameters: GitCloneParameters = { destination, reference, repo }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return { status: "failed" }

        const directoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        const success = await (directoryExists
          ? updateRepo(conn, parameters)
          : cloneRepo(conn, parameters))

        return { status: success ? "changed" : "failed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const gitDirectoryExists = await conn.test(`test -d ${shellQuote(gitDirectory)}`)
        if (!gitDirectoryExists) return NEEDS_APPLY

        if (reference === undefined || reference === "") return "ok"

        const headResult = await conn.exec(
          `git -C ${shellQuote(destination)} rev-parse HEAD`,
          SILENT
        )
        const head = headResult.stdout.trim()

        await conn.exec(`git -C ${shellQuote(destination)} fetch origin --tags --force`, SILENT)

        const resolved = await resolveReference(conn, destination, reference)

        return head === resolved ? "ok" : NEEDS_APPLY
      },
      name: `git.clone: ${destination}`,
    }
  },
}
